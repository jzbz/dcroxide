// SPDX-License-Identifier: ISC
//! The address manager (dcrd addrmgr `addrmanager.go` and
//! `knownaddress.go`): a pool of known peer addresses spread over
//! new and tried buckets, with viability tracking, local address
//! bookkeeping, and the `peers.json` serialization.
//!
//! dcrd guards the manager with mutexes and saves peers from a
//! ticker goroutine; this port is synchronous with identical state
//! transitions.  The clock and the random source are injectable so
//! every code path is deterministic under test.

// Bounded bookkeeping arithmetic mirrors Go.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use dcroxide_wire::ServiceFlag;
use serde::{Deserialize, Serialize};

use crate::netaddress::{NetAddress, encode_host, new_net_address_from_params};
use crate::network::{
    NetAddressType, NetAddressTypeFilter, is_local, is_rfc3964, is_rfc4380, is_rfc6052, is_rfc6145,
};
use crate::{AddrError, ErrorKind, make_error};

/// The default filename to store serialized peers (dcrd
/// `peersFilename`).
pub const PEERS_FILENAME: &str = "peers.json";

/// The number of addresses under which the manager will claim to
/// need more addresses (dcrd `needAddressThreshold`).
const NEED_ADDRESS_THRESHOLD: usize = 1000;

/// The default maximum number of addresses in each tried bucket
/// (dcrd `defaultTriedBucketSize`).
const DEFAULT_TRIED_BUCKET_SIZE: usize = 256;

/// The number of tried buckets (dcrd `triedBucketCount`).
pub const TRIED_BUCKET_COUNT: usize = 64;

/// The maximum number of addresses in each new bucket (dcrd
/// `newBucketSize`).
const NEW_BUCKET_SIZE: usize = 64;

/// The number of new buckets (dcrd `newBucketCount`).
pub const NEW_BUCKET_COUNT: usize = 1024;

const TRIED_BUCKETS_PER_GROUP: u64 = 8;
const NEW_BUCKETS_PER_GROUP: u64 = 64;
const NEW_BUCKETS_PER_ADDRESS: i32 = 8;
const NUM_MISSING_DAYS: i64 = 30;
const NUM_RETRIES: i32 = 3;
const MAX_FAILURES: i32 = 5;
const MIN_BAD_DAYS: i64 = 7;
const GET_KNOWN_ADDRESS_LIMIT: usize = 2500;
const GET_KNOWN_ADDRESS_PERCENTAGE: usize = 23;
const SERIALIZATION_VERSION: i32 = 1;

const NANOS_PER_SEC: i64 = 1_000_000_000;
const MINUTE_NANOS: i64 = 60 * NANOS_PER_SEC;
const DAY_NANOS: i64 = 24 * 60 * MINUTE_NANOS;

/// The Unix seconds value of Go's zero `time.Time`, which dcrd
/// writes for never-set attempt/success times.
const GO_ZERO_TIME_UNIX: i64 = -62_135_596_800;

/// A clock returning the current time as Unix nanoseconds.  It is
/// `Send + Sync` so the address manager can be shared across the
/// daemon's threads.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// A source of randomness for the address manager (dcrd uses
/// `crypto/rand`); injectable so tests are deterministic.
pub trait AddrRng {
    /// A uniform random integer in `[0, n)`.
    fn int_n(&mut self, n: usize) -> usize;
    /// Fill the buffer with random bytes.
    fn read(&mut self, buf: &mut [u8]);
}

/// A ChaCha20-keyed default randomness source seeded from the system
/// clock; the daemon phase will wire OS entropy.
pub struct SystemRng {
    cipher: chacha20::ChaCha20,
}

impl Default for SystemRng {
    fn default() -> SystemRng {
        use chacha20::cipher::KeyIvInit;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or_default();
        let mut key = [0u8; 32];
        key[..8].copy_from_slice(&nanos.to_le_bytes());
        key[8..16].copy_from_slice(&(nanos ^ 0xa5a5_a5a5_a5a5_a5a5).to_be_bytes());
        let nonce = [0u8; 12];
        SystemRng {
            cipher: chacha20::ChaCha20::new(&key.into(), &nonce.into()),
        }
    }
}

impl AddrRng for SystemRng {
    fn int_n(&mut self, n: usize) -> usize {
        use chacha20::cipher::StreamCipher;
        assert!(n > 0, "int_n of zero");
        // Rejection sampling for a uniform value.
        let bound = u64::MAX - u64::MAX % n as u64;
        loop {
            let mut buf = [0u8; 8];
            self.cipher.apply_keystream(&mut buf);
            let v = u64::from_le_bytes(buf);
            if v < bound {
                return (v % n as u64) as usize;
            }
        }
    }

    fn read(&mut self, buf: &mut [u8]) {
        use chacha20::cipher::StreamCipher;
        for b in buf.iter_mut() {
            *b = 0;
        }
        self.cipher.apply_keystream(buf);
    }
}

/// Information about a known network address used to determine how
/// viable an address is (dcrd `KnownAddress`).
pub struct KnownAddress {
    pub(crate) na: NetAddress,
    pub(crate) src_addr: NetAddress,
    pub(crate) attempts: i32,
    // Unix nanoseconds; `None` is Go's zero time.
    pub(crate) lastattempt: Option<i64>,
    pub(crate) lastsuccess: Option<i64>,
    pub(crate) tried: bool,
    pub(crate) refs: i32,
}

/// A shared handle to a known address.
pub type KnownAddressRef = Arc<Mutex<KnownAddress>>;

impl KnownAddress {
    /// The underlying network address (dcrd `NetAddress`).
    pub fn net_address(&self) -> &NetAddress {
        &self.na
    }

    /// The last time the address was attempted, in Unix nanoseconds
    /// (dcrd `LastAttempt`; `None` is Go's zero time).
    pub fn last_attempt(&self) -> Option<i64> {
        self.lastattempt
    }

    /// The selection probability for the address (dcrd `chance`): the
    /// priority depends on how recently it was attempted and how
    /// often attempts have failed.
    pub fn chance(&self, now: i64) -> f64 {
        // Very recent attempts are less likely to be retried.
        const MIN_CHANCE: f64 = 0.01;
        match self.lastattempt {
            None => return MIN_CHANCE,
            Some(lastattempt) => {
                if now - lastattempt < 10 * MINUTE_NANOS {
                    return MIN_CHANCE;
                }
            }
        }

        // Failed attempts deprioritise.
        let c = 1.0 / 1.5f64.powf(f64::from(self.attempts));
        c.max(MIN_CHANCE)
    }

    /// Whether the address is assumed worthless (dcrd `isBad`): not
    /// tried in the last minute and from the future, unseen for a
    /// month, thrice-failed without success, or five-times failed in
    /// the last week.
    pub fn is_bad(&self, now: i64) -> bool {
        // Wait a minute after the last check.
        if let Some(lastattempt) = self.lastattempt
            && lastattempt > now - MINUTE_NANOS
        {
            return false;
        }

        // From the future?
        if self.na.timestamp > now + 10 * MINUTE_NANOS {
            return true;
        }

        // Over a month old?
        if self.na.timestamp < now - NUM_MISSING_DAYS * DAY_NANOS {
            return true;
        }

        // Never succeeded?
        if self.lastsuccess.is_none() && self.attempts >= NUM_RETRIES {
            return true;
        }

        // Hasn't succeeded in too long?
        let success_cutoff = now - MIN_BAD_DAYS * DAY_NANOS;
        let succeeded_recently = match self.lastsuccess {
            Some(lastsuccess) => lastsuccess > success_cutoff,
            None => false,
        };
        if !succeeded_recently && self.attempts >= MAX_FAILURES {
            return true;
        }

        false
    }
}

/// Network address information for a local address (dcrd
/// `LocalAddr`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalAddr {
    /// The IP address string.
    pub address: String,
    /// The port.
    pub port: u16,
    /// The score (unused by dcrd's summary; kept for shape).
    pub score: i32,
}

/// The hierarchy of local address discovery methods (dcrd
/// `AddressPriority`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AddressPriority {
    /// The address is on a local interface.
    Interface = 0,
    /// The address has been explicitly bound to.
    Bound,
    /// The address was obtained from UPnP.
    Upnp,
    /// The address was obtained from an external HTTP service.
    Http,
    /// The address was provided by --externalip.
    Manual,
}

struct LocalAddress {
    na: NetAddress,
    score: i32,
}

/// The connection state between two addresses (dcrd
/// `NetAddressReach`).  Note that dcrd assigns `Unreachable` the
/// value 0 and starts `Default` from 1 via iota.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NetAddressReach {
    /// A publicly unreachable connection state.
    Unreachable = 0,
    /// The default connection state.
    Default = 1,
    /// A connection state between two RFC4380 addresses.
    Teredo = 2,
    /// A weak IPv6 connection state.
    Ipv6Weak = 3,
    /// A connection state between two IPv4 addresses.
    Ipv4 = 4,
    /// A connection state between two IPv6 addresses.
    Ipv6Strong = 5,
    /// A connection state between two TorV3 addresses.
    Private = 6,
}

/// The serializable state of a known address (dcrd
/// `serializedKnownAddress`); the JSON field names match dcrd's Go
/// struct fields.
#[derive(Serialize, Deserialize)]
struct SerializedKnownAddress {
    #[serde(rename = "Addr")]
    addr: String,
    #[serde(rename = "Src")]
    src: String,
    #[serde(rename = "Attempts")]
    attempts: i32,
    #[serde(rename = "TimeStamp")]
    time_stamp: i64,
    #[serde(rename = "LastAttempt")]
    last_attempt: i64,
    #[serde(rename = "LastSuccess")]
    last_success: i64,
}

/// The serializable state of an address manager (dcrd
/// `serializedAddrManager`); the JSON field names match dcrd's Go
/// struct fields.
#[derive(Serialize, Deserialize)]
struct SerializedAddrManager {
    #[serde(rename = "Version")]
    version: i32,
    #[serde(rename = "Key")]
    key: [u8; 32],
    #[serde(rename = "Addresses")]
    addresses: Vec<SerializedKnownAddress>,
    #[serde(rename = "NewBuckets")]
    new_buckets: Vec<Vec<String>>,
    #[serde(rename = "TriedBuckets")]
    tried_buckets: Vec<Vec<String>>,
}

/// The wanted network address types for an address lookup (dcrd
/// `addrTypeFilter`).
#[derive(Clone, Copy)]
struct AddrTypeFilter {
    want_ipv4: bool,
    want_ipv6: bool,
    want_tor_v3: bool,
}

impl AddrTypeFilter {
    /// Whether the address type matches the filter criteria (dcrd
    /// `addrTypeFilter.matches`).
    fn matches(&self, addr_type: NetAddressType) -> bool {
        (self.want_ipv4 && addr_type == NetAddressType::IPv4)
            || (self.want_ipv6 && addr_type == NetAddressType::IPv6)
            || (self.want_tor_v3 && addr_type == NetAddressType::TorV3)
    }
}

/// The number of addresses by type within a single bucket (dcrd
/// `bucketStats`).  The counters wrap like Go's `uint16` arithmetic.
#[derive(Clone, Copy, Default)]
struct BucketStats {
    num_ipv4: u16,
    num_ipv6: u16,
    num_tor_v3: u16,
}

impl BucketStats {
    /// Increase the count for the given address type (dcrd
    /// `bucketStats.increment`).
    fn increment(&mut self, addr_type: NetAddressType) {
        match addr_type {
            NetAddressType::IPv4 => self.num_ipv4 = self.num_ipv4.wrapping_add(1),
            NetAddressType::IPv6 => self.num_ipv6 = self.num_ipv6.wrapping_add(1),
            NetAddressType::TorV3 => self.num_tor_v3 = self.num_tor_v3.wrapping_add(1),
            NetAddressType::Unknown => {}
        }
    }

    /// Decrease the count for the given address type (dcrd
    /// `bucketStats.decrement`).
    fn decrement(&mut self, addr_type: NetAddressType) {
        match addr_type {
            NetAddressType::IPv4 => self.num_ipv4 = self.num_ipv4.wrapping_sub(1),
            NetAddressType::IPv6 => self.num_ipv6 = self.num_ipv6.wrapping_sub(1),
            NetAddressType::TorV3 => self.num_tor_v3 = self.num_tor_v3.wrapping_sub(1),
            NetAddressType::Unknown => {}
        }
    }

    /// The sum of address counts matching the filter (dcrd
    /// `bucketStats.total`).
    fn total(&self, filter: AddrTypeFilter) -> usize {
        let mut sum = 0usize;
        if filter.want_ipv4 {
            sum = sum.wrapping_add(usize::from(self.num_ipv4));
        }
        if filter.want_ipv6 {
            sum = sum.wrapping_add(usize::from(self.num_ipv6));
        }
        if filter.want_tor_v3 {
            sum = sum.wrapping_add(usize::from(self.num_tor_v3));
        }
        sum
    }

    /// Whether the bucket has any addresses matching the filter (dcrd
    /// `bucketStats.matches`).
    fn matches(&self, filter: AddrTypeFilter) -> bool {
        (filter.want_ipv4 && self.num_ipv4 > 0)
            || (filter.want_ipv6 && self.num_ipv6 > 0)
            || (filter.want_tor_v3 && self.num_tor_v3 > 0)
    }
}

/// A concurrency safe address manager for caching potential peers
/// (dcrd `AddrManager`); this port is synchronous.
pub struct AddrManager {
    peers_file: PathBuf,
    key: [u8; 32],
    addr_index: HashMap<String, KnownAddressRef>,
    addr_new: Vec<HashMap<String, KnownAddressRef>>,
    addr_tried: Vec<Vec<KnownAddressRef>>,
    /// Statistics about the addresses in each new bucket (dcrd
    /// `addrNewStats`).
    addr_new_stats: Vec<BucketStats>,
    /// Statistics about the addresses in each tried bucket (dcrd
    /// `addrTriedStats`).
    addr_tried_stats: Vec<BucketStats>,
    addr_changed: bool,
    n_tried: usize,
    n_new: usize,
    local_addresses: HashMap<String, LocalAddress>,
    tried_bucket_size: usize,

    now_fn: Clock,
    rng: Arc<Mutex<dyn AddrRng + Send>>,
}

/// A pseudorandom new bucket index for the provided addresses (dcrd
/// `getNewBucket`).
fn get_new_bucket(key: &[u8; 32], net_addr: &NetAddress, src_addr: &NetAddress) -> usize {
    let mut data1 = Vec::new();
    data1.extend_from_slice(key);
    data1.extend_from_slice(net_addr.group_key().as_bytes());
    data1.extend_from_slice(src_addr.group_key().as_bytes());
    let hash1 = dcroxide_crypto::blake256::sum256(&data1);
    let mut hash64 = u64::from_le_bytes(hash1[..8].try_into().expect("8 bytes"));
    hash64 %= NEW_BUCKETS_PER_GROUP;
    let mut data2 = Vec::new();
    data2.extend_from_slice(key);
    data2.extend_from_slice(src_addr.group_key().as_bytes());
    data2.extend_from_slice(&hash64.to_le_bytes());

    let hash2 = dcroxide_crypto::blake256::sum256(&data2);
    (u64::from_le_bytes(hash2[..8].try_into().expect("8 bytes")) % NEW_BUCKET_COUNT as u64) as usize
}

/// A pseudorandom tried bucket index for the provided address (dcrd
/// `getTriedBucket`).
fn get_tried_bucket(key: &[u8; 32], net_addr: &NetAddress) -> usize {
    let mut data1 = Vec::new();
    data1.extend_from_slice(key);
    data1.extend_from_slice(net_addr.key().as_bytes());
    let hash1 = dcroxide_crypto::blake256::sum256(&data1);
    let mut hash64 = u64::from_le_bytes(hash1[..8].try_into().expect("8 bytes"));
    hash64 %= TRIED_BUCKETS_PER_GROUP;
    let mut data2 = Vec::new();
    data2.extend_from_slice(key);
    data2.extend_from_slice(net_addr.group_key().as_bytes());
    data2.extend_from_slice(&hash64.to_le_bytes());

    let hash2 = dcroxide_crypto::blake256::sum256(&data2);
    (u64::from_le_bytes(hash2[..8].try_into().expect("8 bytes")) % TRIED_BUCKET_COUNT as u64)
        as usize
}

/// The type of connection reachability from a local address to a
/// remote address (dcrd `getRemoteReachabilityFromLocal`).
fn get_remote_reachability_from_local(
    local_addr: &NetAddress,
    remote_addr: &NetAddress,
) -> NetAddressReach {
    use NetAddressReach::*;
    if !remote_addr.is_routable() {
        return Unreachable;
    }
    if remote_addr.addr_type == NetAddressType::TorV3 {
        return if local_addr.addr_type == NetAddressType::TorV3 {
            Private
        } else if local_addr.is_routable() && local_addr.addr_type == NetAddressType::IPv4 {
            Ipv4
        } else {
            Default
        };
    }
    if is_rfc4380(&remote_addr.ip) {
        return if !local_addr.is_routable() {
            Default
        } else if is_rfc4380(&local_addr.ip) {
            Teredo
        } else if local_addr.addr_type == NetAddressType::IPv4 {
            Ipv4
        } else {
            Ipv6Weak
        };
    }
    if remote_addr.addr_type == NetAddressType::IPv4 {
        // dcrd's routable-IPv4-local and TorV3-local cases both reach
        // the IPv4 remote.
        return if (local_addr.is_routable() && local_addr.addr_type == NetAddressType::IPv4)
            || local_addr.addr_type == NetAddressType::TorV3
        {
            Ipv4
        } else {
            Unreachable
        };
    }
    if remote_addr.addr_type == NetAddressType::IPv6 {
        return if !local_addr.is_routable() {
            Default
        } else if is_rfc4380(&local_addr.ip) {
            Teredo
        } else if local_addr.addr_type == NetAddressType::IPv4 {
            Ipv4
        } else if local_addr.addr_type == NetAddressType::TorV3 {
            Ipv6Strong
        } else if is_rfc3964(&local_addr.ip)
            || is_rfc6052(&local_addr.ip)
            || is_rfc6145(&local_addr.ip)
        {
            // Only prioritize ipv6 if we aren't tunnelling it.
            Ipv6Weak
        } else {
            Ipv6Strong
        };
    }
    Default
}

impl AddrManager {
    /// Construct a new address manager instance storing its peers
    /// file under the given data directory (dcrd `New`).
    pub fn new(data_dir: &std::path::Path) -> AddrManager {
        AddrManager::new_with_hooks(
            data_dir,
            Arc::new(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos() as i64)
                    .unwrap_or_default()
            }),
            Arc::new(Mutex::new(SystemRng::default())),
        )
    }

    /// [`new`](AddrManager::new) with an injectable clock and random
    /// source; exposed so tests are deterministic.
    #[doc(hidden)]
    pub fn new_with_hooks(
        data_dir: &std::path::Path,
        now_fn: Clock,
        rng: Arc<Mutex<dyn AddrRng + Send>>,
    ) -> AddrManager {
        let mut am = AddrManager {
            peers_file: data_dir.join(PEERS_FILENAME),
            key: [0u8; 32],
            addr_index: HashMap::new(),
            addr_new: Vec::new(),
            addr_tried: Vec::new(),
            addr_new_stats: Vec::new(),
            addr_tried_stats: Vec::new(),
            addr_changed: false,
            n_tried: 0,
            n_new: 0,
            local_addresses: HashMap::new(),
            tried_bucket_size: DEFAULT_TRIED_BUCKET_SIZE,
            now_fn,
            rng,
        };
        am.reset();
        am
    }

    /// Reset the manager: reinitialise the random key and allocate
    /// fresh empty bucket storage (dcrd `reset`).
    fn reset(&mut self) {
        self.addr_index = HashMap::new();
        self.rng
            .lock()
            .expect("addrmgr lock poisoned")
            .read(&mut self.key);
        self.addr_new = (0..NEW_BUCKET_COUNT).map(|_| HashMap::new()).collect();
        self.addr_tried = (0..TRIED_BUCKET_COUNT).map(|_| Vec::new()).collect();
        self.addr_new_stats = vec![BucketStats::default(); NEW_BUCKET_COUNT];
        self.addr_tried_stats = vec![BucketStats::default(); TRIED_BUCKET_COUNT];
        self.n_new = 0;
        self.n_tried = 0;
        self.addr_changed = true;
    }

    /// Override the bucket key; exposed so tests can pin the bucket
    /// derivations.
    #[doc(hidden)]
    pub fn set_key(&mut self, key: [u8; 32]) {
        self.key = key;
    }

    /// Override the tried bucket capacity; exposed so tests can
    /// exercise eviction cheaply.
    #[doc(hidden)]
    pub fn set_tried_bucket_size(&mut self, size: usize) {
        self.tried_bucket_size = size;
    }

    /// The new bucket index the manager would use for the address
    /// (dcrd `getNewBucket`).
    #[doc(hidden)]
    pub fn new_bucket_index(&self, net_addr: &NetAddress, src_addr: &NetAddress) -> usize {
        get_new_bucket(&self.key, net_addr, src_addr)
    }

    /// The tried bucket index the manager would use for the address
    /// (dcrd `getTriedBucket`).
    #[doc(hidden)]
    pub fn tried_bucket_index(&self, net_addr: &NetAddress) -> usize {
        get_tried_bucket(&self.key, net_addr)
    }

    /// Update an address already known to the manager or add it when
    /// unknown (dcrd `addOrUpdateAddress`).
    fn add_or_update_address(&mut self, net_addr: &NetAddress, src_addr: &NetAddress) {
        // Filter out non-routable addresses, which also includes
        // invalid and local addresses.
        if !net_addr.is_routable() {
            return;
        }

        let addr_key = net_addr.key();
        let existing = self.addr_index.get(&addr_key).cloned();
        let ka = match existing {
            Some(ka) => {
                {
                    let mut ka_mut = ka.lock().expect("addrmgr lock poisoned");
                    // Update the last seen time and services.  The
                    // stored network addresses are treated as
                    // immutable in dcrd and replaced wholesale.
                    if net_addr.timestamp > ka_mut.na.timestamp
                        || (ka_mut.na.services.0 & net_addr.services.0) != net_addr.services.0
                    {
                        let mut na_copy = ka_mut.na.clone();
                        na_copy.timestamp = net_addr.timestamp;
                        na_copy.add_service(net_addr.services);
                        ka_mut.na = na_copy;
                    }

                    // If already in tried, there is nothing to do.
                    if ka_mut.tried {
                        return;
                    }

                    // Already at the max?
                    if ka_mut.refs == NEW_BUCKETS_PER_ADDRESS {
                        return;
                    }

                    // The more entries we have, the less likely we are
                    // to add more; likelihood is 2N.
                    let factor = (2 * ka_mut.refs) as usize;
                    if self
                        .rng
                        .lock()
                        .expect("addrmgr lock poisoned")
                        .int_n(factor)
                        != 0
                    {
                        return;
                    }
                }
                ka
            }
            None => {
                let ka = Arc::new(Mutex::new(KnownAddress {
                    na: net_addr.clone(),
                    src_addr: src_addr.clone(),
                    attempts: 0,
                    lastattempt: None,
                    lastsuccess: None,
                    tried: false,
                    refs: 0,
                }));
                self.addr_index.insert(addr_key.clone(), ka.clone());
                self.n_new += 1;
                self.addr_changed = true;
                ka
            }
        };

        let bucket = get_new_bucket(&self.key, net_addr, src_addr);

        // If the address already exists in the new bucket, do not
        // replace it.
        if self.addr_new[bucket].contains_key(&addr_key) {
            return;
        }

        // Enforce max addresses.
        if self.addr_new[bucket].len() > NEW_BUCKET_SIZE {
            self.expire_new(bucket);
        }

        // Add to the new bucket.
        ka.lock().expect("addrmgr lock poisoned").refs += 1;
        self.addr_new[bucket].insert(addr_key, ka);
        self.addr_new_stats[bucket].increment(net_addr.addr_type);
        self.addr_changed = true;
    }

    /// Make space in the new buckets by expiring the really bad
    /// entries, or the oldest entry when no bad ones exist (dcrd
    /// `expireNew`).
    fn expire_new(&mut self, bucket: usize) {
        let now = (self.now_fn)();
        let mut oldest: Option<(String, KnownAddressRef)> = None;
        let entries: Vec<(String, KnownAddressRef)> = self.addr_new[bucket]
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (k, v) in entries {
            if v.lock().expect("addrmgr lock poisoned").is_bad(now) {
                self.addr_new[bucket].remove(&k);
                self.addr_new_stats[bucket]
                    .decrement(v.lock().expect("addrmgr lock poisoned").na.addr_type);
                self.addr_changed = true;
                let refs = {
                    let mut v_mut = v.lock().expect("addrmgr lock poisoned");
                    v_mut.refs -= 1;
                    v_mut.refs
                };
                if refs == 0 {
                    self.n_new -= 1;
                    self.addr_index.remove(&k);
                }
                continue;
            }
            oldest = match oldest {
                None => Some((k, v)),
                Some((ok, ov)) => {
                    if v.lock().expect("addrmgr lock poisoned").na.timestamp
                        <= ov.lock().expect("addrmgr lock poisoned").na.timestamp
                    {
                        Some((k, v))
                    } else {
                        Some((ok, ov))
                    }
                }
            };
        }

        if let Some((key, oldest)) = oldest {
            self.addr_new[bucket].remove(&key);
            self.addr_new_stats[bucket]
                .decrement(oldest.lock().expect("addrmgr lock poisoned").na.addr_type);
            self.addr_changed = true;
            let refs = {
                let mut oldest_mut = oldest.lock().expect("addrmgr lock poisoned");
                oldest_mut.refs -= 1;
                oldest_mut.refs
            };
            if refs == 0 {
                self.n_new -= 1;
                self.addr_index.remove(&key);
            }
        }
    }

    /// The index of the oldest address in the tried bucket (dcrd
    /// `getOldestAddressIndex`).
    fn get_oldest_address_index(&self, bucket: usize) -> usize {
        let mut idx = 0;
        let mut oldest_ts = 0i64;
        for (i, ka) in self.addr_tried[bucket].iter().enumerate() {
            let ts = ka.lock().expect("addrmgr lock poisoned").na.timestamp;
            if i == 0 || oldest_ts > ts {
                oldest_ts = ts;
                idx = i;
            }
        }
        idx
    }

    /// Add new addresses to the manager, silently ignoring duplicates
    /// (dcrd `AddAddresses`).
    pub fn add_addresses(&mut self, addrs: &[NetAddress], src_addr: &NetAddress) {
        for na in addrs {
            self.add_or_update_address(na, src_addr);
        }
    }

    fn num_addresses(&self) -> usize {
        self.n_tried + self.n_new
    }

    /// Whether the manager needs more addresses (dcrd
    /// `NeedMoreAddresses`).
    pub fn need_more_addresses(&self) -> bool {
        self.num_addresses() < NEED_ADDRESS_THRESHOLD
    }

    /// A randomized subset of all addresses known to the manager,
    /// filtered to the specified address types (dcrd `AddressCache`).
    pub fn address_cache(&mut self, filter: NetAddressTypeFilter) -> Vec<NetAddress> {
        if self.addr_index.is_empty() {
            return Vec::new();
        }

        let now = (self.now_fn)();
        let mut all_addr: Vec<NetAddress> = Vec::with_capacity(self.addr_index.len());
        for ka in self.addr_index.values() {
            let ka = ka.lock().expect("addrmgr lock poisoned");
            // Skip address types that don't match the filter, low
            // quality addresses, and addresses that never succeeded.
            if !filter(ka.na.addr_type) || ka.is_bad(now) || ka.lastsuccess.is_none() {
                continue;
            }
            all_addr.push(ka.na.clone());
        }

        let addr_len = all_addr.len();

        // A small subset of all known addresses; at least one when
        // available.
        let mut num_addresses = (addr_len * GET_KNOWN_ADDRESS_PERCENTAGE).div_ceil(100);
        if num_addresses > GET_KNOWN_ADDRESS_LIMIT {
            num_addresses = GET_KNOWN_ADDRESS_LIMIT;
        }

        // Fisher-Yates shuffle.
        let mut rng = self.rng.lock().expect("addrmgr lock poisoned");
        for i in (1..all_addr.len()).rev() {
            let j = rng.int_n(i + 1);
            all_addr.swap(i, j);
        }

        all_addr.truncate(num_addresses);
        all_addr
    }

    /// A single address that should be routable and satisfies the
    /// provided filter, picked at random with preference to those not
    /// recently used (dcrd `GetAddress`).
    pub fn get_address<F: Fn(NetAddressType) -> bool>(
        &self,
        filter_fn: F,
    ) -> Option<KnownAddressRef> {
        if self.num_addresses() == 0 {
            return None;
        }

        let filter = AddrTypeFilter {
            want_ipv4: filter_fn(NetAddressType::IPv4),
            want_ipv6: filter_fn(NetAddressType::IPv6),
            want_tor_v3: filter_fn(NetAddressType::TorV3),
        };

        if !filter.want_ipv4 && !filter.want_ipv6 && !filter.want_tor_v3 {
            return None;
        }

        // Collect indices of tried and new buckets that match the
        // filter.
        let tried_bucket_idxs: Vec<usize> = (0..self.addr_tried_stats.len())
            .filter(|&i| self.addr_tried_stats[i].matches(filter))
            .collect();
        let new_bucket_idxs: Vec<usize> = (0..self.addr_new_stats.len())
            .filter(|&i| self.addr_new_stats[i].matches(filter))
            .collect();

        let num_tried = tried_bucket_idxs.len();
        let num_new = new_bucket_idxs.len();

        // Return early if no buckets match the filter.
        if num_tried == 0 && num_new == 0 {
            return None;
        }

        // Use a 50% chance for choosing between tried and new table
        // entries.
        let now = (self.now_fn)();
        let large = 1usize << 30;
        let mut factor = 1.0f64;
        let mut rng = self.rng.lock().expect("addrmgr lock poisoned");
        if num_tried > 0 && (num_new == 0 || rng.int_n(2) == 0) {
            // Tried entry.
            loop {
                // Pick a random bucket from buckets matching the
                // filter.
                let bucket_idx = tried_bucket_idxs[rng.int_n(num_tried)];

                // Calculate total number of tried addresses matching
                // the filter, then pick a random entry.
                let counts = self.addr_tried_stats[bucket_idx];
                let total_matching = counts.total(filter);
                let mut nth = rng.int_n(total_matching);

                // Find the nth address matching the filter.
                let mut picked: Option<&KnownAddressRef> = None;
                for addr in &self.addr_tried[bucket_idx] {
                    if !filter.matches(addr.lock().expect("addrmgr lock poisoned").na.addr_type) {
                        continue;
                    }
                    if nth == 0 {
                        picked = Some(addr);
                        break;
                    }
                    nth -= 1;
                }
                let ka = picked.expect("bucket stats track bucket contents");

                let randval = rng.int_n(large);
                if (randval as f64)
                    < factor * ka.lock().expect("addrmgr lock poisoned").chance(now) * large as f64
                {
                    return Some(ka.clone());
                }
                factor *= 1.2;
            }
        } else {
            // New node.  Note that dcrd walks entries in Go's random
            // map iteration order; entries are walked in an
            // unspecified order here as well.
            loop {
                // Pick a random bucket from the buckets matching the
                // filter.
                let bucket_idx = new_bucket_idxs[rng.int_n(num_new)];

                // Calculate total number of new addresses matching
                // the filter, then pick a random entry.
                let counts = self.addr_new_stats[bucket_idx];
                let total_matching = counts.total(filter);
                let mut nth = rng.int_n(total_matching);

                // Find the nth address matching the filter.
                let mut picked: Option<&KnownAddressRef> = None;
                for addr in self.addr_new[bucket_idx].values() {
                    if !filter.matches(addr.lock().expect("addrmgr lock poisoned").na.addr_type) {
                        continue;
                    }
                    if nth == 0 {
                        picked = Some(addr);
                        break;
                    }
                    nth -= 1;
                }
                let ka = picked.expect("bucket stats track bucket contents");

                let randval = rng.int_n(large);
                if (randval as f64)
                    < factor * ka.lock().expect("addrmgr lock poisoned").chance(now) * large as f64
                {
                    return Some(ka.clone());
                }
                factor *= 1.2;
            }
        }
    }

    fn find(&self, addr: &NetAddress) -> Option<KnownAddressRef> {
        self.addr_index.get(&addr.key()).cloned()
    }

    /// Look up a known address by its key; exposed for tests.
    #[doc(hidden)]
    pub fn known_address(&self, key: &str) -> Option<KnownAddressRef> {
        self.addr_index.get(key).cloned()
    }

    /// Increase the known address' attempt counter and update the
    /// last attempt time (dcrd `Attempt`).
    pub fn attempt(&mut self, addr: &NetAddress) -> Result<(), AddrError> {
        let ka = self.find(addr).ok_or_else(|| {
            make_error(
                ErrorKind::AddressNotFound,
                format!("address {addr} not found"),
            )
        })?;

        let mut ka = ka.lock().expect("addrmgr lock poisoned");
        ka.attempts += 1;
        ka.lastattempt = Some((self.now_fn)());
        Ok(())
    }

    /// Mark the known address as connected and working at the current
    /// time (dcrd `Connected`).
    pub fn connected(&mut self, addr: &NetAddress) -> Result<(), AddrError> {
        let ka = self.find(addr).ok_or_else(|| {
            make_error(
                ErrorKind::AddressNotFound,
                format!("address {addr} not found"),
            )
        })?;

        // Update the time as long as it has been 20 minutes since
        // last time.
        let now = (self.now_fn)();
        let mut ka = ka.lock().expect("addrmgr lock poisoned");
        if now > ka.na.timestamp + 20 * MINUTE_NANOS {
            let mut na_copy = ka.na.clone();
            na_copy.timestamp = now;
            ka.na = na_copy;
        }
        Ok(())
    }

    /// Mark the known address as good after a successful outbound
    /// connection and version exchange (dcrd `Good`).
    pub fn good(&mut self, addr: &NetAddress) -> Result<(), AddrError> {
        let ka = self.find(addr).ok_or_else(|| {
            make_error(
                ErrorKind::AddressNotFound,
                format!("address {addr} not found"),
            )
        })?;

        let now = (self.now_fn)();
        {
            let mut ka_mut = ka.lock().expect("addrmgr lock poisoned");
            // The timestamp is not updated here to avoid leaking
            // information about currently connected peers.
            ka_mut.lastsuccess = Some(now);
            ka_mut.lastattempt = Some(now);
            ka_mut.attempts = 0;

            // If the address is already tried then it's already good.
            if ka_mut.tried {
                return Ok(());
            }
        }

        // Remove from all new buckets, remembering the first bucket
        // it was found in.
        let (addr_key, ka_type) = {
            let ka_ref = ka.lock().expect("addrmgr lock poisoned");
            (ka_ref.na.key(), ka_ref.na.addr_type)
        };
        let mut addr_new_available_index: Option<usize> = None;
        for i in 0..self.addr_new.len() {
            if self.addr_new[i].remove(&addr_key).is_some() {
                self.addr_changed = true;
                ka.lock().expect("addrmgr lock poisoned").refs -= 1;
                self.addr_new_stats[i].decrement(ka_type);
                if addr_new_available_index.is_none() {
                    addr_new_available_index = Some(i);
                }
            }
        }
        self.n_new -= 1;

        let Some(addr_new_available_index) = addr_new_available_index else {
            return Err(make_error(
                ErrorKind::AddressNotFound,
                format!("{addr} is not marked as a new address"),
            ));
        };

        let bucket = get_tried_bucket(&self.key, &ka.lock().expect("addrmgr lock poisoned").na);

        // If this tried bucket has capacity, add the address and flag
        // it as tried.
        if self.addr_tried[bucket].len() < self.tried_bucket_size {
            ka.lock().expect("addrmgr lock poisoned").tried = true;
            self.addr_tried[bucket].push(ka);
            self.addr_tried_stats[bucket].increment(ka_type);
            self.addr_changed = true;
            self.n_tried += 1;
            return Ok(());
        }

        // The tried bucket is at capacity: evict the oldest address
        // in it and move that one to a new bucket.
        let oldest_tried_index = self.get_oldest_address_index(bucket);
        let rmka = self.addr_tried[bucket][oldest_tried_index].clone();

        // First new bucket it would have been put in.
        let mut new_bucket = {
            let rmka_ref = rmka.lock().expect("addrmgr lock poisoned");
            get_new_bucket(&self.key, &rmka_ref.na, &rmka_ref.src_addr)
        };

        // If there is no room there, reuse the new bucket the newly
        // tried address was removed from.
        if self.addr_new[new_bucket].len() >= NEW_BUCKET_SIZE {
            new_bucket = addr_new_available_index;
        }

        // Replace the oldest tried address in the bucket with ka.
        ka.lock().expect("addrmgr lock poisoned").tried = true;
        self.addr_tried[bucket][oldest_tried_index] = ka;
        self.addr_tried_stats[bucket]
            .decrement(rmka.lock().expect("addrmgr lock poisoned").na.addr_type);
        self.addr_tried_stats[bucket].increment(ka_type);

        {
            let mut rmka_mut = rmka.lock().expect("addrmgr lock poisoned");
            rmka_mut.tried = false;
            rmka_mut.refs += 1;
        }

        // The tried count stays the same, but the new count was
        // decremented above and an address is moving back to new.
        self.n_new += 1;

        let (rmkey, rmka_type) = {
            let rmka_ref = rmka.lock().expect("addrmgr lock poisoned");
            (rmka_ref.na.key(), rmka_ref.na.addr_type)
        };
        self.addr_new[new_bucket].insert(rmkey, rmka);
        self.addr_new_stats[new_bucket].increment(rmka_type);
        Ok(())
    }

    /// Set the services for the known address (dcrd `SetServices`).
    pub fn set_services(
        &mut self,
        addr: &NetAddress,
        services: ServiceFlag,
    ) -> Result<(), AddrError> {
        let ka = self.find(addr).ok_or_else(|| {
            make_error(
                ErrorKind::AddressNotFound,
                format!("address {addr} not found"),
            )
        })?;

        let mut ka = ka.lock().expect("addrmgr lock poisoned");
        if ka.na.services != services {
            let mut na_copy = ka.na.clone();
            na_copy.services = services;
            ka.na = na_copy;
        }
        Ok(())
    }

    /// Add a local address to advertise with the given priority (dcrd
    /// `AddLocalAddress`).
    pub fn add_local_address(
        &mut self,
        na: &NetAddress,
        priority: AddressPriority,
    ) -> Result<(), String> {
        if !na.is_routable() {
            return Err(format!("address {na} is not routable"));
        }

        let key = na.key();
        match self.local_addresses.get_mut(&key) {
            Some(la) if la.score < priority as i32 => la.score = priority as i32 + 1,
            Some(_) => {}
            None => {
                self.local_addresses.insert(
                    key,
                    LocalAddress {
                        na: na.clone(),
                        score: priority as i32,
                    },
                );
            }
        }
        Ok(())
    }

    /// Whether the manager has the provided local address (dcrd
    /// `HasLocalAddress`).
    pub fn has_local_address(&self, na: &NetAddress) -> bool {
        self.local_addresses.contains_key(&na.key())
    }

    /// A summary of local addresses information (dcrd
    /// `LocalAddresses`).
    pub fn local_addresses(&self) -> Vec<LocalAddr> {
        self.local_addresses
            .values()
            .map(|addr| LocalAddr {
                address: addr.na.ip_string(),
                port: addr.na.port,
                score: 0,
            })
            .collect()
    }

    /// The most appropriate local address to use for the given remote
    /// address (dcrd `GetBestLocalAddress`).
    pub fn get_best_local_address(
        &self,
        remote_addr: &NetAddress,
        filter: NetAddressTypeFilter,
    ) -> NetAddress {
        let mut bestreach = NetAddressReach::Default;
        let mut bestscore = -1i32;
        let mut best_address: Option<&NetAddress> = None;
        for la in self.local_addresses.values() {
            if !filter(la.na.addr_type) {
                continue;
            }
            let reach = get_remote_reachability_from_local(&la.na, remote_addr);
            if reach > bestreach || (reach == bestreach && la.score > bestscore) {
                bestreach = reach;
                bestscore = la.score;
                best_address = Some(&la.na);
            }
        }

        match best_address {
            Some(best) => best.clone(),
            None => {
                // Send something unroutable if nothing suitable.
                let ip: &[u8] = if remote_addr.addr_type != NetAddressType::IPv4 {
                    &[0u8; 16]
                } else {
                    &[0u8; 4]
                };
                crate::netaddress::new_net_address_from_ip_port(
                    ip,
                    0,
                    ServiceFlag::NODE_NETWORK,
                    (self.now_fn)() / NANOS_PER_SEC * NANOS_PER_SEC,
                )
            }
        }
    }

    /// Whether a suggested address from a remote peer is a good
    /// candidate for this node's public external address, plus the
    /// reachability of the suggestion (dcrd
    /// `IsExternalAddrCandidate`).
    pub fn is_external_addr_candidate(
        &self,
        local_addr: &NetAddress,
        remote_addr: &NetAddress,
    ) -> (bool, NetAddressReach) {
        use NetAddressReach::*;
        let reach = get_remote_reachability_from_local(local_addr, remote_addr);

        // Return early when the remote peer suggested a local
        // address.
        if is_local(&local_addr.ip) {
            return (false, reach);
        }

        let net = local_addr.addr_type;
        let local_ipv4_with_good_reach = net == NetAddressType::IPv4 && reach == Ipv4;
        let local_ipv6_with_good_reach = net == NetAddressType::IPv6
            && (reach == Ipv6Weak || reach == Ipv6Strong || reach == Teredo || reach == Default);

        (
            local_ipv4_with_good_reach || local_ipv6_with_good_reach,
            reach,
        )
    }

    /// Create a network address from a "host:port" string, stamping
    /// it with the current time (dcrd `newNetAddressFromString`).
    fn new_net_address_from_string(&self, addr: &str) -> Result<NetAddress, AddrError> {
        let (host, port_str) = split_host_port(addr).ok_or_else(|| {
            make_error(
                ErrorKind::UnknownAddressType,
                format!("failed to deserialize address {addr}"),
            )
        })?;
        let port: u16 = port_str.parse().map_err(|_| {
            make_error(
                ErrorKind::UnknownAddressType,
                format!("failed to deserialize address {addr}"),
            )
        })?;
        let (addr_type, addr_bytes) = encode_host(&host);
        if addr_type == NetAddressType::Unknown {
            return Err(make_error(
                ErrorKind::UnknownAddressType,
                format!("failed to deserialize address {addr}"),
            ));
        }
        let timestamp = (self.now_fn)() / NANOS_PER_SEC * NANOS_PER_SEC;
        new_net_address_from_params(
            addr_type,
            &addr_bytes,
            port,
            timestamp,
            ServiceFlag::NODE_NETWORK,
        )
    }

    /// Save all known addresses to the peers file (dcrd `savePeers`).
    pub fn save_peers(&mut self) -> Result<(), String> {
        if !self.addr_changed {
            return Ok(());
        }

        let mut sam = SerializedAddrManager {
            version: SERIALIZATION_VERSION,
            key: self.key,
            addresses: Vec::with_capacity(self.addr_index.len()),
            new_buckets: Vec::with_capacity(NEW_BUCKET_COUNT),
            tried_buckets: Vec::with_capacity(TRIED_BUCKET_COUNT),
        };
        for (k, v) in &self.addr_index {
            let v = v.lock().expect("addrmgr lock poisoned");
            sam.addresses.push(SerializedKnownAddress {
                addr: k.clone(),
                src: v.src_addr.key(),
                attempts: v.attempts,
                time_stamp: v.na.timestamp.div_euclid(NANOS_PER_SEC),
                last_attempt: go_unix(v.lastattempt),
                last_success: go_unix(v.lastsuccess),
            });
        }
        for bucket in &self.addr_new {
            sam.new_buckets.push(bucket.keys().cloned().collect());
        }
        for bucket in &self.addr_tried {
            sam.tried_buckets.push(
                bucket
                    .iter()
                    .map(|ka| ka.lock().expect("addrmgr lock poisoned").na.key())
                    .collect(),
            );
        }

        // Write a temporary peers file and then move it into place.
        let tmpfile = self.peers_file.with_extension("json.new");
        let mut encoded = serde_json::to_string(&sam).map_err(|err| err.to_string())?;
        encoded.push('\n');
        std::fs::write(&tmpfile, encoded).map_err(|err| err.to_string())?;
        std::fs::rename(&tmpfile, &self.peers_file).map_err(|err| err.to_string())?;
        self.addr_changed = false;
        Ok(())
    }

    /// Load known addresses from the peers file; an empty, missing,
    /// or malformed file leaves the manager reset (dcrd `loadPeers`).
    pub fn load_peers(&mut self) {
        if let Err(_err) = self.deserialize_peers_path() {
            let _ = std::fs::remove_file(&self.peers_file);
            self.reset();
        }
    }

    fn deserialize_peers_path(&mut self) -> Result<(), String> {
        let path = self.peers_file.clone();
        if !path.exists() {
            return Ok(());
        }
        let contents = std::fs::read_to_string(&path).map_err(|err| err.to_string())?;
        self.deserialize_peers(&contents)
    }

    /// Load the manager state from serialized JSON contents (dcrd
    /// `deserializePeers`).
    pub fn deserialize_peers(&mut self, contents: &str) -> Result<(), String> {
        let sam: SerializedAddrManager =
            serde_json::from_str(contents).map_err(|err| format!("error reading: {err}"))?;

        if sam.version != SERIALIZATION_VERSION {
            return Err(format!(
                "unknown version {} in serialized addrmanager",
                sam.version
            ));
        }
        self.key = sam.key;

        for v in &sam.addresses {
            // NOTE: dcrd never restores the serialized TimeStamp; a
            // loaded address keeps the load-time stamp assigned by
            // the address parser.  Ported bug for bug.  Go's zero
            // time round-trips exactly through its Unix() encoding.
            let net_addr = self
                .new_net_address_from_string(&v.addr)
                .map_err(|err| format!("failed to deserialize netaddress {}: {err}", v.addr))?;
            let src_addr = self
                .new_net_address_from_string(&v.src)
                .map_err(|err| format!("failed to deserialize netaddress {}: {err}", v.src))?;

            let from_go_unix = |secs: i64| -> Option<i64> {
                if secs == GO_ZERO_TIME_UNIX {
                    None
                } else {
                    Some(secs * NANOS_PER_SEC)
                }
            };
            let ka = Arc::new(Mutex::new(KnownAddress {
                na: net_addr,
                src_addr,
                attempts: v.attempts,
                lastattempt: from_go_unix(v.last_attempt),
                lastsuccess: from_go_unix(v.last_success),
                tried: false,
                refs: 0,
            }));
            let key = ka.lock().expect("addrmgr lock poisoned").na.key();
            self.addr_index.insert(key, ka);
        }

        for (i, bucket) in sam.new_buckets.iter().enumerate().take(NEW_BUCKET_COUNT) {
            for val in bucket {
                let Some(ka) = self.addr_index.get(val).cloned() else {
                    return Err(format!(
                        "new buckets contains {val} but none in address list"
                    ));
                };
                let refs = {
                    let mut ka_mut = ka.lock().expect("addrmgr lock poisoned");
                    let prev = ka_mut.refs;
                    ka_mut.refs += 1;
                    prev
                };
                if refs == 0 {
                    self.n_new += 1;
                }
                let ka_type = ka.lock().expect("addrmgr lock poisoned").na.addr_type;
                self.addr_new[i].insert(val.clone(), ka);
                self.addr_new_stats[i].increment(ka_type);
            }
        }
        for (i, bucket) in sam
            .tried_buckets
            .iter()
            .enumerate()
            .take(TRIED_BUCKET_COUNT)
        {
            for val in bucket {
                let Some(ka) = self.addr_index.get(val).cloned() else {
                    return Err(format!(
                        "tried buckets contains {val} but none in address list"
                    ));
                };
                let ka_type = {
                    let mut ka_mut = ka.lock().expect("addrmgr lock poisoned");
                    ka_mut.tried = true;
                    ka_mut.na.addr_type
                };
                self.n_tried += 1;
                self.addr_tried[i].push(ka);
                self.addr_tried_stats[i].increment(ka_type);
            }
        }

        // Sanity checking.
        for (k, v) in &self.addr_index {
            let v = v.lock().expect("addrmgr lock poisoned");
            if v.refs == 0 && !v.tried {
                return Err(format!(
                    "address {k} after serialisation with no references"
                ));
            }
            if v.refs > 0 && v.tried {
                return Err(format!(
                    "address {k} after serialisation which is both new and tried"
                ));
            }
        }

        Ok(())
    }

    /// A snapshot of the internal state; exposed for tests.
    #[doc(hidden)]
    #[allow(clippy::type_complexity)]
    pub fn state_snapshot(
        &self,
    ) -> (
        Vec<(String, String, i32, bool, i32, Vec<usize>, Option<usize>)>,
        usize,
        usize,
        [u8; 32],
    ) {
        let mut addrs = Vec::new();
        for (k, v) in &self.addr_index {
            let v = v.lock().expect("addrmgr lock poisoned");
            let mut new_buckets: Vec<usize> = self
                .addr_new
                .iter()
                .enumerate()
                .filter(|(_, bucket)| bucket.contains_key(k))
                .map(|(i, _)| i)
                .collect();
            new_buckets.sort_unstable();
            let tried_bucket = self
                .addr_tried
                .iter()
                .enumerate()
                .find(|(_, bucket)| {
                    bucket
                        .iter()
                        .any(|ka| Arc::ptr_eq(ka, self.addr_index.get(k).expect("indexed")))
                })
                .map(|(i, _)| i);
            addrs.push((
                k.clone(),
                v.src_addr.key(),
                v.attempts,
                v.tried,
                v.refs,
                new_buckets,
                tried_bucket,
            ));
        }
        addrs.sort();
        (addrs, self.n_new, self.n_tried, self.key)
    }

    /// The new/tried totals plus every non-empty bucket's per-type
    /// statistics as `(bucket, ipv4, ipv6, tor_v3)` rows for the new
    /// then tried tables; exposed so tests replay dcrd's bookkeeping
    /// dumps.
    #[doc(hidden)]
    #[allow(clippy::type_complexity)]
    pub fn bucket_stats_snapshot(
        &self,
    ) -> (
        usize,
        usize,
        Vec<(usize, u16, u16, u16)>,
        Vec<(usize, u16, u16, u16)>,
    ) {
        let nonzero = |stats: &[BucketStats]| {
            stats
                .iter()
                .enumerate()
                .filter(|(_, s)| s.num_ipv4 != 0 || s.num_ipv6 != 0 || s.num_tor_v3 != 0)
                .map(|(i, s)| (i, s.num_ipv4, s.num_ipv6, s.num_tor_v3))
                .collect()
        };
        (
            self.n_new,
            self.n_tried,
            nonzero(&self.addr_new_stats),
            nonzero(&self.addr_tried_stats),
        )
    }
}

/// Go's `Unix()` value for an optional nanosecond timestamp, using
/// the zero-time sentinel when unset.
fn go_unix(t: Option<i64>) -> i64 {
    match t {
        Some(nanos) => nanos.div_euclid(NANOS_PER_SEC),
        None => GO_ZERO_TIME_UNIX,
    }
}

/// Split a "host:port" string, handling bracketed IPv6 hosts (Go
/// `net.SplitHostPort`).
fn split_host_port(addr: &str) -> Option<(String, String)> {
    let idx = addr.rfind(':')?;
    let (host, port) = (&addr[..idx], &addr[idx + 1..]);
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    Some((host.to_string(), port.to_string()))
}
