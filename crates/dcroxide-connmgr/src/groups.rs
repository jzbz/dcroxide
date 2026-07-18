// SPDX-License-Identifier: ISC
//! Outbound network group tracking (dcrd `internal/connmgr`
//! `outboundGroupInfo`, new in dcrd 2.2's connection manager
//! rewrite).
//!
//! Used to strongly prefer outbound connections to different network
//! groups so it is extremely difficult for attackers to gain control
//! of addresses spanning a lot of different groups.  The group of an
//! address is the SipHash-2-4 of the address manager's group key
//! string under a per-instance random key, so distinct connection
//! manager instances produce distinct, externally unpredictable
//! mappings (dcrd hashes with `dchest/siphash`, which the `siphasher`
//! dependency reproduces bit for bit — probed against dcrd's exact
//! keys and preimages).
//!
//! dcrd guards the instance with an embedded mutex and holds it
//! across the whole of `pickOutboundAddr`'s selection loop; the port
//! is a plain single-threaded core and the manager serializes access,
//! preserving that selection-and-add atomicity.

use std::collections::HashMap;
use std::hash::Hasher;

use dcroxide_addrmgr::NetAddress;

use crate::csprng::Csprng;

/// Outbound address group bookkeeping (dcrd `outboundGroupInfo`).
#[derive(Debug)]
pub struct OutboundGroupInfo {
    /// The per-instance SipHash key ensuring unpredictable group
    /// mappings (dcrd `key`).
    key: [u64; 2],
    /// All pending and active addresses (host:port) that have entries
    /// in `counts` (dcrd `addrs`).
    addrs: HashMap<String, u32>,
    /// The number of pending and active outbound addresses per
    /// outbound group (dcrd `counts`).
    counts: HashMap<u64, u32>,
}

impl OutboundGroupInfo {
    /// An initialized instance keyed from the provided CSPRNG (dcrd
    /// `newOutboundGroupInfo`).
    pub fn new(csprng: &mut dyn Csprng) -> OutboundGroupInfo {
        OutboundGroupInfo {
            key: [csprng.uint64(), csprng.uint64()],
            addrs: HashMap::new(),
            counts: HashMap::new(),
        }
    }

    /// An instance with an explicit key, for the differential tests.
    #[doc(hidden)]
    pub fn with_key(key: [u64; 2]) -> OutboundGroupInfo {
        OutboundGroupInfo {
            key,
            addrs: HashMap::new(),
            counts: HashMap::new(),
        }
    }

    /// The key representing the outbound network group for the
    /// address (dcrd `outboundGroupInfo.GroupKey`): the SipHash-2-4
    /// of the address manager group key string under the instance
    /// key.
    pub fn group_key(&self, addr: &NetAddress) -> u64 {
        let mut hasher = siphasher::sip::SipHasher24::new_with_keys(self.key[0], self.key[1]);
        hasher.write(addr.group_key().as_bytes());
        hasher.finish()
    }

    /// Record an address that will be dialed (dcrd `addAddr`).  The
    /// counts wrap like Go's `uint32` increments.
    pub fn add_addr(&mut self, addr: &NetAddress) {
        let addr_count = self.addrs.entry(addr.key()).or_insert(0);
        *addr_count = addr_count.wrapping_add(1);
        let group_key = self.group_key(addr);
        let group_count = self.counts.entry(group_key).or_insert(0);
        *group_count = group_count.wrapping_add(1);
    }

    /// Remove an address no longer in use — a failed dial or a closed
    /// non-persistent connection (dcrd `removeAddr`).  Tolerates
    /// addresses that were already removed by `Disconnect`/`Remove`.
    pub fn remove_addr(&mut self, addr: &NetAddress) {
        let addr_str = addr.key();
        let Some(addr_count) = self.addrs.get_mut(&addr_str) else {
            return;
        };
        *addr_count = addr_count.wrapping_sub(1);
        if *addr_count == 0 {
            self.addrs.remove(&addr_str);
        }
        // dcrd decrements the group entry unconditionally — Go map
        // access materializes a zero for a missing group, which the
        // decrement wraps; the in-sync invariant makes that
        // unreachable, but the port mirrors the arithmetic exactly.
        let group_key = self.group_key(addr);
        let group_count = self.counts.entry(group_key).or_insert(0);
        *group_count = group_count.wrapping_sub(1);
        if *group_count == 0 {
            self.counts.remove(&group_key);
        }
    }

    /// The number of actively tracked addresses in the same outbound
    /// group as the address (dcrd `groupCount`).
    pub fn group_count(&self, addr: &NetAddress) -> u32 {
        self.counts.get(&self.group_key(addr)).copied().unwrap_or(0)
    }

    /// The tracked `(addrs, counts)` state as sorted rows, for the
    /// differential tests.
    #[doc(hidden)]
    #[allow(clippy::type_complexity)]
    pub fn state_snapshot(&self) -> (Vec<(String, u32)>, Vec<(u64, u32)>) {
        let mut addrs: Vec<(String, u32)> =
            self.addrs.iter().map(|(k, v)| (k.clone(), *v)).collect();
        addrs.sort();
        let mut counts: Vec<(u64, u32)> = self.counts.iter().map(|(k, v)| (*k, *v)).collect();
        counts.sort_unstable();
        (addrs, counts)
    }
}
