// SPDX-License-Identifier: ISC
//! The P2P server's address bookkeeping (the first slice of dcrd's
//! `server.go`): the bounded network address submission cache fed by
//! outbound peers, the best-suggestion local address resolution, the
//! host-to-network-address conversion, and the wire/address-manager
//! conversion and service helpers.  The server struct itself, the
//! peer handlers, and the relay machinery arrive with later slices.

// Bounded cache and majority arithmetic mirroring Go.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use dcroxide_addrmgr::{
    AddrManager, AddressPriority, NetAddress, NetAddressReach, NetAddressType, encode_host,
    new_net_address_from_ip_port, new_net_address_from_params,
};
use dcroxide_wire::ServiceFlag;

use crate::gostd::split_host_port;

/// The default number of outbound peers to maintain (dcrd
/// `defaultTargetOutbound`).
pub const DEFAULT_TARGET_OUTBOUND: i64 = 8;

/// The maximum number of cached network address submissions (dcrd
/// `maxCachedNaSubmissions`).
pub const MAX_CACHED_NA_SUBMISSIONS: usize = 20;

/// A DNS resolver like Go's `net.LookupIP`, returning IP addresses.
pub type ResolveIpFn<'a> = dyn Fn(&str) -> Result<Vec<std::net::IpAddr>, String> + 'a;

/// A network address submission from an outbound peer (dcrd
/// `naSubmission`).
#[derive(Debug, Clone)]
pub struct NaSubmission {
    /// The submitted address (dcrd carries the wire form; the
    /// address manager form holds the same bytes).
    pub na: NetAddress,
    /// The network type of the address.
    pub net_type: NetAddressType,
    /// The reachability of the address.
    pub reach: NetAddressReach,
    /// The submission score.
    pub score: u32,
    /// The last access time in Unix seconds.
    pub last_accessed: i64,
}

/// A bounded map for network address submissions (dcrd
/// `naSubmissionCache`).  dcrd guards the map with a mutex; the port
/// is single-threaded.
pub struct NaSubmissionCache {
    /// The submissions keyed by the address's IP string.
    pub cache: BTreeMap<String, NaSubmission>,
    /// The cache limit.
    pub limit: usize,
}

impl NaSubmissionCache {
    /// An empty cache with the given limit.
    pub fn new(limit: usize) -> NaSubmissionCache {
        NaSubmissionCache {
            cache: BTreeMap::new(),
            limit,
        }
    }

    /// Cache the provided address submission (dcrd `add`); the clock
    /// is injected as Unix seconds.
    pub fn add(&mut self, mut sub: NaSubmission, now_unix: i64) -> Result<(), String> {
        let key = sub.na.ip_string();
        if key.is_empty() {
            return Err("submission key cannot be an empty string".to_string());
        }

        // Remove the oldest submission if the cache limit has been
        // reached.  dcrd breaks last-accessed ties by Go's random
        // map iteration; iteration here is in key order.
        if self.cache.len() == self.limit {
            let oldest = self
                .cache
                .values()
                .min_by_key(|sub| sub.last_accessed)
                .map(|sub| sub.na.ip_string());
            if let Some(oldest) = oldest {
                self.cache.remove(&oldest);
            }
        }

        sub.score = 1;
        sub.last_accessed = now_unix;
        self.cache.insert(key, sub);
        Ok(())
    }

    /// Whether the provided key exists in the cache (dcrd `exists`).
    pub fn exists(&self, key: &str) -> bool {
        if key.is_empty() {
            return false;
        }
        self.cache.contains_key(key)
    }

    /// Increase the score of the submission referenced by the key by
    /// one (dcrd `incrementScore`).
    pub fn increment_score(&mut self, key: &str, now_unix: i64) -> Result<(), String> {
        if key.is_empty() {
            return Err("submission key cannot be an empty string".to_string());
        }
        let Some(sub) = self.cache.get_mut(key) else {
            return Err(format!("submission key not found: {key}"));
        };
        sub.score += 1;
        sub.last_accessed = now_unix;
        Ok(())
    }

    /// The best scoring submission of the provided network type
    /// (dcrd `bestSubmission`); dcrd breaks score ties by Go's
    /// random map iteration, while iteration here is in key order.
    pub fn best_submission(&self, net: NetAddressType) -> Option<&NaSubmission> {
        let mut best: Option<&NaSubmission> = None;
        for sub in self.cache.values() {
            if sub.net_type != net {
                continue;
            }
            match best {
                None => best = Some(sub),
                Some(b) if sub.score > b.score => best = Some(sub),
                Some(_) => {}
            }
        }
        best
    }
}

/// Parse and return an address manager network address given a
/// hostname, resolving through the provided DNS resolver when the
/// host is not a recognized address format (dcrd
/// `hostToNetAddress`); the clock is injected as Unix seconds.
pub fn host_to_net_address(
    host: &str,
    port: u16,
    services: ServiceFlag,
    resolver: &ResolveIpFn<'_>,
    now_unix: i64,
) -> Result<NetAddress, String> {
    let (addr_type, addr_bytes) = encode_host(host);
    if addr_type != NetAddressType::Unknown {
        // Since the host type has been successfully recognized and
        // encoded, there is no need to perform a DNS lookup.
        let now_nanos = now_unix * 1_000_000_000;
        return new_net_address_from_params(addr_type, &addr_bytes, port, now_nanos, services)
            .map_err(|e| e.description);
    }
    // Cannot determine the host address type.  Must use DNS.
    let ips = resolver(host)?;
    let Some(first) = ips.first() else {
        return Err(format!("no addresses found for {host}"));
    };
    let ip_bytes: Vec<u8> = match first {
        std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
        std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    Ok(new_net_address_from_ip_port(&ip_bytes, port, services, 0))
}

/// Pick the best suggested network address from the submissions per
/// the provided network type and add it as a local address when the
/// suggestion has a majority and matches a listener (dcrd
/// `peerState.ResolveLocalAddress`); errors are logged by dcrd and
/// abort or skip exactly as the port does.
#[allow(clippy::too_many_arguments)] // Mirrors dcrd's parameter surface.
pub fn resolve_local_address(
    sub_cache: &NaSubmissionCache,
    net_type: NetAddressType,
    addr_mgr: &mut AddrManager,
    services: ServiceFlag,
    listeners: &[String],
    max_peers: i64,
    resolver: &ResolveIpFn<'_>,
    now_unix: i64,
) {
    let Some(best) = sub_cache.best_submission(net_type) else {
        return;
    };

    let mut target_outbound = DEFAULT_TARGET_OUTBOUND;
    if max_peers < target_outbound {
        target_outbound = max_peers;
    }

    // A valid best address suggestion must have a majority (60
    // percent majority) of outbound peers concluding on the same
    // result.
    if (best.score as f64) < (target_outbound as f64 * 0.6).ceil() {
        return;
    }

    let mut add_local_address = |best_suggestion: &str, port: u16| {
        let na = match host_to_net_address(best_suggestion, port, services, resolver, now_unix) {
            Ok(na) => na,
            // dcrd logs the failure and skips the listener.
            Err(_) => return,
        };
        if !addr_mgr.has_local_address(&na) {
            // An add failure is logged and skipped.
            let _ = addr_mgr.add_local_address(&na, AddressPriority::Manual);
        }
    };

    let strip_ipv6_zone = |ip: &str| -> String {
        // Strip the IPv6 zone id if present.
        match ip.rfind('%') {
            Some(idx) if idx > 0 => ip[..idx].to_string(),
            _ => ip.to_string(),
        }
    };

    let best_ip = best.na.ip_string();
    for listener in listeners {
        // dcrd logs and aborts the whole resolution on a listener
        // that fails to split or parse.
        let Ok((host, port_str)) = split_host_port(listener) else {
            return;
        };
        let Ok(port) = port_str.parse::<u16>() else {
            return;
        };
        let host = strip_ipv6_zone(&host);

        // Add a local address if the best suggestion is referenced
        // by a listener.
        if best_ip == host {
            add_local_address(&best_ip, port);
            continue;
        }

        // Add a local address if the listener is generic (applies
        // for both IPv4 and IPv6).
        if host.is_empty() {
            add_local_address(&best_ip, port);
            continue;
        }

        let Ok(listener_ip) = host.parse::<std::net::IpAddr>() else {
            return;
        };

        // Add a local address if the network address is a probable
        // external endpoint of the listener.
        let l_net = match listener_ip {
            std::net::IpAddr::V4(_) => NetAddressType::IPv4,
            std::net::IpAddr::V6(v6) => {
                if v6.to_ipv4_mapped().is_some() {
                    NetAddressType::IPv4
                } else {
                    NetAddressType::IPv6
                }
            }
        };

        let valid_external = (l_net == NetAddressType::IPv4 && best.reach == NetAddressReach::Ipv4)
            || l_net == NetAddressType::IPv6
                && (best.reach == NetAddressReach::Ipv6Weak
                    || best.reach == NetAddressReach::Ipv6Strong
                    || best.reach == NetAddressReach::Teredo);

        if valid_external {
            add_local_address(&best_ip, port);
            continue;
        }
    }
}

/// Convert a wire net address to an address manager net address
/// (dcrd `wireToAddrmgrNetAddress`).
pub fn wire_to_addrmgr_net_address(net_addr: &dcroxide_wire::NetAddress) -> NetAddress {
    let mut new_addr =
        new_net_address_from_ip_port(&net_addr.ip, net_addr.port, net_addr.services, 0);
    new_addr.timestamp = i64::from(net_addr.timestamp) * 1_000_000_000;
    new_addr
}

/// Convert a collection of wire net addresses (dcrd
/// `wireToAddrmgrNetAddresses`).
pub fn wire_to_addrmgr_net_addresses(net_addrs: &[dcroxide_wire::NetAddress]) -> Vec<NetAddress> {
    net_addrs.iter().map(wire_to_addrmgr_net_address).collect()
}

/// Convert an address manager net address to a wire net address
/// (dcrd `addrmgrToWireNetAddress`).
pub fn addrmgr_to_wire_net_address(net_addr: &NetAddress) -> dcroxide_wire::NetAddress {
    let mut ip = [0u8; 16];
    if net_addr.ip.len() == 4 {
        ip[10] = 0xff;
        ip[11] = 0xff;
        ip[12..16].copy_from_slice(&net_addr.ip);
    } else if net_addr.ip.len() == 16 {
        ip.copy_from_slice(&net_addr.ip);
    }
    dcroxide_wire::NetAddress {
        timestamp: (net_addr.timestamp / 1_000_000_000) as u32,
        services: net_addr.services,
        ip,
        port: net_addr.port,
    }
}

/// Whether the advertised services include the desired ones (dcrd
/// `hasServices`).
pub fn has_services(advertised: ServiceFlag, desired: ServiceFlag) -> bool {
    advertised.0 & desired.0 == desired.0
}

/// Whether the network address type is supported by the addr wire
/// message (dcrd `isSupportedNetAddrTypeV1`).
pub fn is_supported_net_addr_type_v1(addr_type: NetAddressType) -> bool {
    addr_type == NetAddressType::IPv4 || addr_type == NetAddressType::IPv6
}

/// The address type filter for the protocol version (dcrd
/// `natfSupported`); every version at the parity tag uses the v1
/// filter.
pub fn natf_supported(_pver: u32) -> fn(NetAddressType) -> bool {
    is_supported_net_addr_type_v1
}

/// The maximum number of known addresses to track per peer (dcrd
/// `maxKnownAddrsPerPeer`).
pub const MAX_KNOWN_ADDRS_PER_PEER: u32 = 10000;

/// The false positive rate for the known-address filter (dcrd
/// `knownAddrsFPRate`).
pub const KNOWN_ADDRS_FP_RATE: f64 = 0.001;

/// The per-peer address relay and banning state (the corresponding
/// `serverPeer` fields).
pub struct ServerPeerAddrState {
    /// The addresses already sent to or received from the peer
    /// (dcrd `knownAddresses`).
    pub known_addresses: dcroxide_containers::apbf::Filter,
    /// Whether the peer already requested addresses (dcrd
    /// `addrsSent`).
    pub addrs_sent: bool,
    /// The dynamic ban score (dcrd `banScore`).
    pub ban_score: dcroxide_connmgr::DynamicBanScore,
    /// Whether the peer is exempt from banning (dcrd
    /// `isWhitelisted`).
    pub is_whitelisted: bool,
}

impl ServerPeerAddrState {
    /// A fresh state as `newServerPeer` builds it.
    pub fn new(is_whitelisted: bool) -> ServerPeerAddrState {
        ServerPeerAddrState {
            known_addresses: dcroxide_containers::apbf::new_filter(
                MAX_KNOWN_ADDRS_PER_PEER,
                KNOWN_ADDRS_FP_RATE,
            ),
            addrs_sent: false,
            ban_score: dcroxide_connmgr::DynamicBanScore::default(),
            is_whitelisted,
        }
    }

    /// Track an address as known to the peer (dcrd
    /// `addKnownAddress`).
    pub fn add_known_address(&mut self, na: &NetAddress) {
        self.known_addresses.add(na.key().as_bytes());
    }

    /// Track a collection of addresses as known to the peer (dcrd
    /// `addKnownAddresses`).
    pub fn add_known_addresses(&mut self, addresses: &[NetAddress]) {
        for na in addresses {
            self.add_known_address(na);
        }
    }

    /// Whether the address is already known to the peer (dcrd
    /// `addressKnown`).
    pub fn address_known(&self, na: &NetAddress) -> bool {
        self.known_addresses.contains(na.key().as_bytes())
    }
}

/// The observable outcome of the server-level addr push (dcrd
/// `serverPeer.pushAddrMsg`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushAddrOutcome {
    /// The addr message to queue to the peer.
    Queued(Box<dcroxide_wire::Message>),
    /// The filtered list was empty; nothing is pushed.  dcrd carries
    /// an error-and-disconnect branch here, but the peer push never
    /// errors at the parity tag, so it is dead code.
    Nothing,
}

/// Push the provided addresses to the peer, filtering the ones it
/// already knows and tracking the ones actually sent (dcrd
/// `serverPeer.pushAddrMsg`).
pub fn push_addr_msg<E: dcroxide_peer::PeerEnv>(
    state: &mut ServerPeerAddrState,
    peer: &mut dcroxide_peer::Peer,
    env: &mut E,
    addresses: &[NetAddress],
) -> PushAddrOutcome {
    // Filter addresses already known to the peer.
    let addrs: Vec<dcroxide_wire::NetAddress> = addresses
        .iter()
        .filter(|addr| !state.address_known(addr))
        .map(addrmgr_to_wire_net_address)
        .collect();
    match peer.push_addr_msg(env, &addrs) {
        Some((msg, known)) => {
            let known_net_addrs = wire_to_addrmgr_net_addresses(&known);
            state.add_known_addresses(&known_net_addrs);
            PushAddrOutcome::Queued(Box::new(msg))
        }
        None => PushAddrOutcome::Nothing,
    }
}

/// Increase the peer's ban score, returning whether the peer is now
/// banned (dcrd `serverPeer.addBanScore`); dcrd's warning logs are
/// daemon output.  The caller performs the ban itself via
/// [`ban_peer`] exactly as dcrd's `BanPeer` does.
#[allow(clippy::too_many_arguments)] // Mirrors dcrd's config surface.
pub fn add_ban_score(
    state: &mut ServerPeerAddrState,
    persistent: u32,
    transient: u32,
    disable_banning: bool,
    ban_threshold: u32,
    now_unix: i64,
) -> bool {
    // No warning is logged and no score is calculated if banning is
    // disabled.
    if disable_banning {
        return false;
    }
    if state.is_whitelisted {
        return false;
    }

    let warn_threshold = ban_threshold >> 1;
    if transient == 0 && persistent == 0 {
        // The score is not being increased, but dcrd still logs a
        // warning when the score is above the warn threshold.
        let _ = state.ban_score.int_at(now_unix) > warn_threshold;
        return false;
    }
    let score = state.ban_score.increase_at(persistent, transient, now_unix);
    if score > warn_threshold && score > ban_threshold {
        return true;
    }
    false
}

/// The observable outcome of banning a peer (dcrd
/// `server.BanPeer`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BanPeerOutcome {
    /// Banning is disabled or the peer is whitelisted; nothing
    /// happens.
    Ignored,
    /// The address could not be split; the peer is disconnected
    /// without a ban entry.
    DisconnectOnly,
    /// The host was banned until the given time and the peer is
    /// disconnected.
    Banned {
        /// The banned host.
        host: String,
        /// The Unix nanosecond time the ban lifts.
        until_nanos: i64,
    },
}

/// Ban the peer at the given address (dcrd `server.BanPeer`); the
/// caller owns the banned-host map until the peer state slice
/// lands.
pub fn ban_peer(
    banned: &mut std::collections::BTreeMap<String, i64>,
    addr: &str,
    is_whitelisted: bool,
    disable_banning: bool,
    ban_duration_nanos: i64,
    now_nanos: i64,
) -> BanPeerOutcome {
    // No warning is logged when banning is disabled.
    if disable_banning {
        return BanPeerOutcome::Ignored;
    }
    if is_whitelisted {
        return BanPeerOutcome::Ignored;
    }

    let Ok((host, _)) = split_host_port(addr) else {
        return BanPeerOutcome::DisconnectOnly;
    };

    let until_nanos = now_nanos + ban_duration_nanos;
    banned.insert(host.clone(), until_nanos);
    BanPeerOutcome::Banned { host, until_nanos }
}

/// The peer facts the getaddr handler consumes.
pub struct GetAddrFacts {
    /// Whether the simulation or regression test network is active.
    pub sim_or_reg_net: bool,
    /// Whether the peer is inbound.
    pub inbound: bool,
}

/// Handle a getaddr message (dcrd `serverPeer.OnGetAddr`): the
/// address cache is the caller's `AddressCache` result over the
/// version-appropriate type filter, and the returned outcome is the
/// push to perform, if any.
pub fn on_get_addr<E: dcroxide_peer::PeerEnv>(
    state: &mut ServerPeerAddrState,
    peer: &mut dcroxide_peer::Peer,
    env: &mut E,
    facts: &GetAddrFacts,
    addr_cache: &[NetAddress],
) -> Option<PushAddrOutcome> {
    // Don't return any addresses when running on the simulation and
    // regression test networks.
    if facts.sim_or_reg_net {
        return None;
    }

    // Do not accept getaddr requests from outbound peers.  This
    // reduces fingerprinting attacks.
    if !facts.inbound {
        return None;
    }

    // Only respond with addresses once per connection.
    if state.addrs_sent {
        return None;
    }
    state.addrs_sent = true;

    // Push the addresses.
    Some(push_addr_msg(state, peer, env, addr_cache))
}

/// The peer facts the addr handler consumes.
pub struct OnAddrFacts {
    /// Whether the simulation or regression test network is active.
    pub sim_or_reg_net: bool,
    /// Whether the peer remains connected (dcrd samples this per
    /// address to stop early on concurrent disconnects; the
    /// synchronous port samples it once).
    pub connected: bool,
    /// The peer's network address (dcrd `sp.NA()`).
    pub peer_na: dcroxide_wire::NetAddress,
}

/// The observable outcome of handling an addr message (dcrd
/// `serverPeer.OnAddr`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnAddrOutcome {
    /// The message was ignored.
    Ignored,
    /// The peer sent an empty address list and the caller bans it
    /// with dcrd's reason string.
    BanEmptyList,
    /// The addresses were tracked and forwarded to the address
    /// manager.
    Processed,
}

/// Handle an addr message (dcrd `serverPeer.OnAddr`); the clock is
/// injected as Unix nanoseconds.
pub fn on_addr(
    state: &mut ServerPeerAddrState,
    addr_mgr: &mut AddrManager,
    facts: &OnAddrFacts,
    addr_list: &[dcroxide_wire::NetAddress],
    now_nanos: i64,
) -> OnAddrOutcome {
    // Ignore addresses when running on the simulation and regression
    // test networks.
    if facts.sim_or_reg_net {
        return OnAddrOutcome::Ignored;
    }

    // A message that has no addresses is invalid; dcrd bans the
    // sender with the reason "sent an empty address list".
    if addr_list.is_empty() {
        return OnAddrOutcome::BanEmptyList;
    }

    let mut addr_list = wire_to_addrmgr_net_addresses(addr_list);
    for na in &mut addr_list {
        // Don't add more addresses when disconnecting.
        if !facts.connected {
            return OnAddrOutcome::Processed;
        }

        // Set the timestamp to 5 days ago if it's more than 24 hours
        // in the future so this address is one of the first to be
        // removed when space is needed.
        if na.timestamp > now_nanos + 10 * 60 * 1_000_000_000 {
            na.timestamp = now_nanos - 24 * 5 * 3600 * 1_000_000_000;
        }

        // Add address to known addresses for this peer.
        state.add_known_address(na);
    }

    // Add addresses to the server address manager, which handles
    // duplicate prevention, limits, and last seen updates.
    let remote_addr = wire_to_addrmgr_net_address(&facts.peer_na);
    addr_mgr.add_addresses(&addr_list, &remote_addr);
    OnAddrOutcome::Processed
}

/// Pick between singular and plural forms (dcrd `pickNoun`).
pub fn pick_noun<'a>(n: u64, singular: &'a str, plural: &'a str) -> &'a str {
    if n == 1 { singular } else { plural }
}

/// The observable outcome of a mempool request (dcrd
/// `serverPeer.OnMemPool`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnMemPoolOutcome {
    /// The flood ban score crossed the threshold; the caller bans
    /// and stops.
    Banned,
    /// The inventory vectors to queue for the pool's transactions.
    Inventory(Vec<dcroxide_wire::InvVect>),
}

/// Handle a mempool request (dcrd `serverPeer.OnMemPool`): a
/// decaying ban score increase prevents flooding, and the pool's
/// transaction hashes become queued inventory.
pub fn on_mem_pool(
    state: &mut ServerPeerAddrState,
    tx_hashes: &[dcroxide_chainhash::Hash],
    disable_banning: bool,
    ban_threshold: u32,
    now_unix: i64,
) -> OnMemPoolOutcome {
    // The score decays each minute to half of its value.
    if add_ban_score(state, 0, 33, disable_banning, ban_threshold, now_unix) {
        return OnMemPoolOutcome::Banned;
    }

    let invs = tx_hashes
        .iter()
        .map(|hash| dcroxide_wire::InvVect {
            inv_type: dcroxide_wire::InvType::TX,
            hash: *hash,
        })
        .collect();
    OnMemPoolOutcome::Inventory(invs)
}

/// The observable outcome of enforcing the node cf service flag
/// (dcrd `serverPeer.enforceNodeCFFlag`); every branch disconnects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfFlagOutcome {
    /// The ban score was applied (crossing recorded) and the peer
    /// disconnects.
    BanAndDisconnect {
        /// Whether the score crossed the ban threshold.
        banned: bool,
    },
    /// The peer disconnects without a score change.
    DisconnectOnly,
}

/// Enforce the node cf service flag for the unsupported version 1
/// committed filter requests (dcrd `serverPeer.enforceNodeCFFlag`,
/// reached from `OnGetCFilter`, `OnGetCFHeaders`, and
/// `OnGetCFTypes`).
pub fn enforce_node_cf_flag(
    state: &mut ServerPeerAddrState,
    protocol_version: u32,
    disable_banning: bool,
    ban_threshold: u32,
    now_unix: i64,
) -> CfFlagOutcome {
    // Ban the peer if the protocol version is high enough that the
    // peer is knowingly violating the protocol and banning is
    // enabled.
    if protocol_version >= dcroxide_wire::NODE_CF_VERSION && !disable_banning {
        let banned = add_ban_score(state, 100, 0, disable_banning, ban_threshold, now_unix);
        return CfFlagOutcome::BanAndDisconnect { banned };
    }

    // Disconnect the peer regardless of protocol version or banning
    // state.
    CfFlagOutcome::DisconnectOnly
}

/// The observable outcome of a notfound message (dcrd
/// `serverPeer.OnNotFound`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnNotFoundOutcome {
    /// The peer is no longer connected; nothing happens.
    Ignored,
    /// An invalid inventory type disconnects the peer.
    DisconnectInvalidType,
    /// A ban score crossing with dcrd's reason string; the caller
    /// bans and stops.
    Banned(String),
    /// The message forwards to the network sync manager.
    Forward,
}

/// Handle a notfound message (dcrd `serverPeer.OnNotFound`).
pub fn on_not_found(
    state: &mut ServerPeerAddrState,
    connected: bool,
    inv_list: &[dcroxide_wire::InvVect],
    disable_banning: bool,
    ban_threshold: u32,
    now_unix: i64,
) -> OnNotFoundOutcome {
    if !connected {
        return OnNotFoundOutcome::Ignored;
    }

    let mut num_blocks: u32 = 0;
    let mut num_txns: u32 = 0;
    let mut num_mix_msgs: u32 = 0;
    for inv in inv_list {
        match inv.inv_type {
            dcroxide_wire::InvType::BLOCK => num_blocks += 1,
            dcroxide_wire::InvType::TX => num_txns += 1,
            dcroxide_wire::InvType::MIX => num_mix_msgs += 1,
            _ => return OnNotFoundOutcome::DisconnectInvalidType,
        }
    }
    if num_blocks > 0 {
        let block_str = pick_noun(u64::from(num_blocks), "block", "blocks");
        let reason = format!("{num_blocks} {block_str} not found");
        if add_ban_score(
            state,
            20 * num_blocks,
            0,
            disable_banning,
            ban_threshold,
            now_unix,
        ) {
            return OnNotFoundOutcome::Banned(reason);
        }
    }
    if num_txns > 0 {
        let tx_str = pick_noun(u64::from(num_txns), "transaction", "transactions");
        let reason = format!("{num_txns} {tx_str} not found");
        if add_ban_score(
            state,
            0,
            10 * num_txns,
            disable_banning,
            ban_threshold,
            now_unix,
        ) {
            return OnNotFoundOutcome::Banned(reason);
        }
    }
    if num_mix_msgs > 0 {
        let mix_str = pick_noun(u64::from(num_mix_msgs), "mix message", "mix messages");
        let reason = format!("{num_mix_msgs} {mix_str} not found");
        if add_ban_score(
            state,
            0,
            10 * num_mix_msgs,
            disable_banning,
            ban_threshold,
            now_unix,
        ) {
            return OnNotFoundOutcome::Banned(reason);
        }
    }
    OnNotFoundOutcome::Forward
}

/// The default number of mix-capable outbound peers to maintain
/// (dcrd `defaultWantMixCapableOutbound`).
const DEFAULT_WANT_MIX_CAPABLE_OUTBOUND: u32 = 3;

/// The early rejections of a version message (dcrd
/// `serverPeer.OnVersion` returns).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionRejection {
    /// The protocol version predates the required minimum.
    OldProtocol,
    /// An outbound peer does not provide the required services.
    MissingServices,
}

/// The peer and configuration facts the version handler consumes.
pub struct OnVersionFacts {
    /// Whether the peer is inbound.
    pub inbound: bool,
    /// Whether the simulation or regression test network is active.
    pub sim_or_reg_net: bool,
    /// Whether listening is disabled.
    pub disable_listen: bool,
    /// Whether the sync manager believes the chain is current.
    pub sync_is_current: bool,
    /// The current outbound peer count (dcrd walks the peer state).
    pub num_outbound: u32,
    /// The mix-capable outbound peer count.
    pub num_mix_capable_outbound: u32,
    /// The configured outbound connection target.
    pub target_outbound: u32,
    /// The peer's network address (dcrd `sp.NA()`).
    pub remote_na: dcroxide_wire::NetAddress,
}

/// The observable outcome of handling a version message (dcrd
/// `serverPeer.OnVersion`); the caller stores the peer address,
/// adds the time sample, and runs the add-peer admission.
#[derive(Debug, PartialEq, Eq)]
pub struct OnVersionOutcome {
    /// Whether the advertised services were forwarded to the
    /// address manager.
    pub set_services: bool,
    /// An early rejection; the peer disconnects and nothing below
    /// applies.
    pub rejected: Option<VersionRejection>,
    /// The peer was disconnected to maintain mix-capable outbound
    /// peers; dcrd deliberately continues processing afterwards.
    pub mix_disconnect: bool,
    /// The local address advertisement pushed to the peer, if any.
    pub pushed_local: Option<PushAddrOutcome>,
    /// Whether a getaddr request was queued for more addresses.
    pub requested_more_addrs: bool,
    /// Whether the peer's address was marked good.
    pub marked_good: bool,
    /// Whether the peer disabled transaction relay.
    pub disable_relay_tx: bool,
}

/// Handle a version message (dcrd `serverPeer.OnVersion`).
#[allow(clippy::too_many_arguments)] // Mirrors dcrd's surface.
pub fn on_version<E: dcroxide_peer::PeerEnv>(
    state: &mut ServerPeerAddrState,
    peer: &mut dcroxide_peer::Peer,
    env: &mut E,
    addr_mgr: &mut AddrManager,
    facts: &OnVersionFacts,
    msg_protocol_version: i32,
    msg_services: ServiceFlag,
    msg_disable_relay_tx: bool,
) -> OnVersionOutcome {
    let mut outcome = OnVersionOutcome {
        set_services: false,
        rejected: None,
        mix_disconnect: false,
        pushed_local: None,
        requested_more_addrs: false,
        marked_good: false,
        disable_relay_tx: false,
    };

    // Update the address manager with the advertised services for
    // outbound connections; skipped for inbound connections and on
    // the simulation and regression test networks.  This happens
    // before rejecting peers that are too old.
    let remote_addr = wire_to_addrmgr_net_address(&facts.remote_na);
    if !facts.sim_or_reg_net && !facts.inbound {
        // A lookup failure is logged and ignored.
        let _ = addr_mgr.set_services(&remote_addr, msg_services);
        outcome.set_services = true;
    }

    // Reject peers that have a protocol version that is too old.
    if msg_protocol_version < dcroxide_wire::REMOVE_REJECT_VERSION as i32 {
        outcome.rejected = Some(VersionRejection::OldProtocol);
        return outcome;
    }

    // Maintain a minimum desired number of outbound peers capable
    // of supporting p2p mixing.  Note that dcrd disconnects here
    // without returning, so processing deliberately continues.
    if !facts.inbound && msg_protocol_version < dcroxide_wire::MIX_VERSION as i32 {
        let mut want_mix_capable = DEFAULT_WANT_MIX_CAPABLE_OUTBOUND;
        if facts.target_outbound < want_mix_capable {
            want_mix_capable = facts.target_outbound;
        }
        let has_min = facts.num_mix_capable_outbound >= want_mix_capable;
        let needs_more = !has_min && facts.num_outbound + want_mix_capable >= facts.target_outbound;
        if needs_more {
            outcome.mix_disconnect = true;
        }
    }

    // Reject outbound peers that are not full nodes.
    let want_services = ServiceFlag::NODE_NETWORK;
    if !facts.inbound && !has_services(msg_services, want_services) {
        outcome.rejected = Some(VersionRejection::MissingServices);
        return outcome;
    }

    // Update the address manager and request known addresses from
    // the remote peer for outbound connections; skipped on the
    // simulation and regression test networks.
    if !facts.sim_or_reg_net && !facts.inbound {
        // Advertise the local address when the server accepts
        // incoming connections and it believes itself to be close
        // to the best known tip.
        if !facts.disable_listen && facts.sync_is_current {
            let filter = natf_supported(msg_protocol_version as u32);
            let lna = addr_mgr.get_best_local_address(&remote_addr, filter);
            if lna.is_routable() {
                outcome.pushed_local = Some(push_addr_msg(state, peer, env, &[lna]));
            }
        }

        // Request known addresses if the server address manager
        // needs more.
        if addr_mgr.need_more_addresses() {
            outcome.requested_more_addrs = true;
        }

        // Mark the address as a known good address; a failure is
        // logged and ignored.
        outcome.marked_good = addr_mgr.good(&remote_addr).is_ok();
    }

    // The caller stores the advertised address and time sample and
    // chooses whether or not to relay transactions.
    outcome.disable_relay_tx = msg_disable_relay_tx;
    outcome
}

/// Handle a verack message (dcrd `serverPeer.OnVerAck`): request
/// all block announcements via full headers.
pub fn on_ver_ack() -> dcroxide_wire::Message {
    dcroxide_wire::Message::SendHeaders
}

/// Whether the 16-byte wire IP is an IPv4-mapped address (Go
/// `na.IP.To4() != nil`).
fn wire_ip_is_v4(ip: &[u8; 16]) -> bool {
    ip[..10] == [0u8; 10] && ip[10] == 0xff && ip[11] == 0xff
}

/// Whether the 16-byte wire IP is a loopback address (Go
/// `net.IP.IsLoopback`).
fn wire_ip_is_loopback(ip: &[u8; 16]) -> bool {
    if wire_ip_is_v4(ip) {
        return ip[12] == 127;
    }
    *ip == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
}

/// A tracked peer in the server peer state maps; the fields are the
/// ones the admission and removal decisions read (dcrd's maps hold
/// the live `*serverPeer`).
#[derive(Debug, Clone)]
pub struct PeerStateEntry {
    /// The peer's network address (dcrd `sp.NA()`).
    pub na: dcroxide_wire::NetAddress,
    /// Whether the peer is inbound.
    pub inbound: bool,
    /// Whether the peer is a persistent outbound peer.
    pub persistent: bool,
}

/// The state of inbound, persistent, and outbound peers as well as
/// banned peers and outbound groups (dcrd `peerState`).  dcrd guards
/// the maps with a mutex; the port is single-threaded.
pub struct PeerState {
    /// The inbound peers by peer ID.
    pub inbound_peers: BTreeMap<i32, PeerStateEntry>,
    /// The non-persistent outbound peers by peer ID.
    pub outbound_peers: BTreeMap<i32, PeerStateEntry>,
    /// The persistent outbound peers by peer ID.
    pub persistent_peers: BTreeMap<i32, PeerStateEntry>,
    /// The banned hosts and the Unix nanosecond times the bans lift.
    pub banned: BTreeMap<String, i64>,
    /// The outbound peer counts by address group key.
    pub outbound_groups: BTreeMap<String, i64>,
    /// The network address submission cache.
    pub sub_cache: NaSubmissionCache,
}

impl Default for PeerState {
    fn default() -> PeerState {
        PeerState::new()
    }
}

impl PeerState {
    /// An empty peer state (dcrd `makePeerState`).
    pub fn new() -> PeerState {
        PeerState {
            inbound_peers: BTreeMap::new(),
            outbound_peers: BTreeMap::new(),
            persistent_peers: BTreeMap::new(),
            banned: BTreeMap::new(),
            outbound_groups: BTreeMap::new(),
            sub_cache: NaSubmissionCache::new(MAX_CACHED_NA_SUBMISSIONS),
        }
    }

    /// The count of all known peers (dcrd `count`).
    pub fn count(&self) -> i64 {
        (self.inbound_peers.len() + self.outbound_peers.len() + self.persistent_peers.len()) as i64
    }

    /// The number of connections with the given wire IP (dcrd
    /// `connectionsWithIP`).
    pub fn connections_with_ip(&self, ip: &[u8; 16]) -> i64 {
        let mut total = 0;
        for entry in self
            .inbound_peers
            .values()
            .chain(self.outbound_peers.values())
            .chain(self.persistent_peers.values())
        {
            if entry.na.ip == *ip {
                total += 1;
            }
        }
        total
    }
}

/// Why the admission handler rejected a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddPeerReject {
    /// The server is shutting down.
    Shutdown,
    /// The peer address could not be split into host and port.
    BadAddress,
    /// The peer's host is banned.
    Banned,
    /// The single-IP connection limit was reached.
    TooManySameIp,
    /// The maximum peer count was reached.
    MaxPeers,
}

/// The peer and configuration facts the admission handler consumes.
pub struct AddPeerFacts {
    /// Whether the server is shutting down.
    pub shutdown: bool,
    /// The peer ID (dcrd `sp.ID()`).
    pub id: i32,
    /// The peer's address string (dcrd `sp.Addr()`).
    pub addr: String,
    /// Whether the peer is inbound.
    pub inbound: bool,
    /// Whether the peer is a persistent outbound peer.
    pub persistent: bool,
    /// Whether the peer is whitelisted.
    pub is_whitelisted: bool,
    /// The peer's network address (dcrd `sp.NA()`).
    pub na: dcroxide_wire::NetAddress,
    /// The remote peer's view of the local address from its version
    /// message, when one was stored (dcrd `sp.peerNa`).
    pub peer_na: Option<dcroxide_wire::NetAddress>,
    /// The single-IP connection limit (dcrd `cfg.MaxSameIP`).
    pub max_same_ip: i64,
    /// The maximum peer count (dcrd `cfg.MaxPeers`).
    pub max_peers: i64,
    /// Whether a proxy or onion proxy is configured.
    pub has_proxy: bool,
    /// Whether automatic network address discovery is disabled.
    pub no_discover_ip: bool,
    /// Whether external IPs are explicitly configured.
    pub has_external_ips: bool,
    /// Whether listening is disabled or no listeners exist.
    pub listen_disabled: bool,
    /// Whether Universal Plug and Play is enabled.
    pub upnp: bool,
    /// Whether the active network is the simulation or regression
    /// test network.
    pub sim_or_reg_net: bool,
    /// The services the server supports.
    pub services: ServiceFlag,
    /// The configured listeners (dcrd `cfg.Listeners`).
    pub listeners: Vec<String>,
}

/// What the admission handler decided and did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AddPeerOutcome {
    /// The rejection when the peer was refused and disconnected;
    /// dcrd returns false from `handleAddPeer`.
    pub rejected: Option<AddPeerReject>,
    /// An expired ban entry for the host was removed.
    pub unbanned: bool,
    /// An inbound peer corroborated an existing address submission.
    pub corroborated: bool,
    /// An outbound peer's suggestion was added as a new submission.
    pub sub_added: bool,
    /// An outbound peer's suggestion incremented an existing
    /// submission.
    pub sub_incremented: bool,
    /// The local address resolution ran after the submission.
    pub resolved_local: bool,
}

/// Deal with adding new peers: categorize the peer, enforce the ban
/// list and the connection limits, track it in the peer state maps,
/// and feed the local external address discovery (dcrd
/// `server.handleAddPeer`).  A rejection in the outcome means dcrd
/// disconnected the peer and returned false.
pub fn handle_add_peer(
    state: &mut PeerState,
    addr_mgr: &mut AddrManager,
    facts: &AddPeerFacts,
    resolver: &ResolveIpFn<'_>,
    now_nanos: i64,
) -> AddPeerOutcome {
    let mut outcome = AddPeerOutcome::default();

    // Ignore new peers when shutting down.
    if facts.shutdown {
        outcome.rejected = Some(AddPeerReject::Shutdown);
        return outcome;
    }

    // Disconnect banned peers.
    let Ok((host, _)) = split_host_port(&facts.addr) else {
        outcome.rejected = Some(AddPeerReject::BadAddress);
        return outcome;
    };
    if let Some(&ban_end) = state.banned.get(&host) {
        if now_nanos < ban_end {
            outcome.rejected = Some(AddPeerReject::Banned);
            return outcome;
        }
        state.banned.remove(&host);
        outcome.unbanned = true;
    }

    // Limit the max number of connections from a single IP, allowing
    // whitelisted inbound peers and localhost connections regardless.
    let is_inbound_whitelisted = facts.is_whitelisted && facts.inbound;
    let peer_ip = facts.na.ip;
    if facts.max_same_ip > 0
        && !is_inbound_whitelisted
        && !wire_ip_is_loopback(&peer_ip)
        && state.connections_with_ip(&peer_ip) + 1 > facts.max_same_ip
    {
        outcome.rejected = Some(AddPeerReject::TooManySameIp);
        return outcome;
    }

    // Limit the max number of total peers, allowing whitelisted
    // inbound peers regardless.
    if state.count() + 1 > facts.max_peers && !is_inbound_whitelisted {
        outcome.rejected = Some(AddPeerReject::MaxPeers);
        return outcome;
    }

    let entry = PeerStateEntry {
        na: facts.na,
        inbound: facts.inbound,
        persistent: facts.persistent,
    };
    let now_unix = now_nanos / 1_000_000_000;

    // Add the new peer.
    if facts.inbound {
        state.inbound_peers.insert(facts.id, entry);

        if let Some(peer_na) = &facts.peer_na {
            let id = wire_to_addrmgr_net_address(peer_na).ip_string();

            // Inbound peers can only corroborate existing address
            // submissions; an increment failure is logged and
            // returns early.
            if state.sub_cache.exists(&id) {
                if state.sub_cache.increment_score(&id, now_unix).is_err() {
                    return outcome;
                }
                outcome.corroborated = true;
            }
        }

        return outcome;
    }

    // The peer is an outbound peer at this point.
    let remote_addr = wire_to_addrmgr_net_address(&facts.na);
    *state
        .outbound_groups
        .entry(remote_addr.group_key())
        .or_insert(0) += 1;
    if facts.persistent {
        state.persistent_peers.insert(facts.id, entry);
    } else {
        state.outbound_peers.insert(facts.id, entry);
    }

    // Fetch the suggested public IP from the outbound peer unless a
    // prevailing condition disables automatic network address
    // discovery: a proxy, explicit disablement, explicit external
    // IPs, disabled listening, UPnP, or the simulation networks.
    if facts.has_proxy
        || facts.no_discover_ip
        || facts.has_external_ips
        || facts.listen_disabled
        || facts.upnp
        || facts.sim_or_reg_net
    {
        return outcome;
    }

    if let Some(peer_na) = &facts.peer_na {
        let net = if wire_ip_is_v4(&peer_na.ip) {
            NetAddressType::IPv4
        } else {
            NetAddressType::IPv6
        };

        let local_addr = wire_to_addrmgr_net_address(peer_na);
        let (good, reach) = addr_mgr.is_external_addr_candidate(&local_addr, &remote_addr);
        if !good {
            return outcome;
        }

        let id = local_addr.ip_string();
        if state.sub_cache.exists(&id) {
            // Increment the submission score if it already exists;
            // a failure is logged and returns early.
            if state.sub_cache.increment_score(&id, now_unix).is_err() {
                return outcome;
            }
            outcome.sub_incremented = true;
        } else {
            // Create a cache entry for a new submission; a failure
            // is logged and returns early.
            let sub = NaSubmission {
                na: local_addr,
                net_type: net,
                reach,
                score: 0,
                last_accessed: 0,
            };
            if state.sub_cache.add(sub, now_unix).is_err() {
                return outcome;
            }
            outcome.sub_added = true;
        }

        // Pick the local address for the provided network based on
        // submission scores.
        resolve_local_address(
            &state.sub_cache,
            net,
            addr_mgr,
            facts.services,
            &facts.listeners,
            facts.max_peers,
            resolver,
            now_unix,
        );
        outcome.resolved_local = true;
    }

    outcome
}

/// The peer and configuration facts the removal handler consumes.
pub struct DonePeerFacts {
    /// The peer ID (dcrd `sp.ID()`).
    pub id: i32,
    /// Whether the peer is inbound.
    pub inbound: bool,
    /// Whether the peer is a persistent outbound peer.
    pub persistent: bool,
    /// Whether the version handshake stored the peer's version.
    pub version_known: bool,
    /// Whether the peer acknowledged the local version.
    pub ver_ack_received: bool,
    /// The peer's network address; dcrd's is always set once the
    /// handshake completed.
    pub na: Option<dcroxide_wire::NetAddress>,
    /// Whether a connection manager request is attached to the peer.
    pub has_conn_req: bool,
    /// Whether the simulation or regression test network is active
    /// (dcrd `cfg.SimNet || cfg.RegNet`).
    pub sim_or_reg_net: bool,
}

/// What the removal handler decided and did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DonePeerOutcome {
    /// The peer was removed from its tracking map.
    pub removed: bool,
    /// The peer's outbound group count was decremented.
    pub group_decremented: bool,
    /// The connection manager was told to disconnect the request.
    pub conn_mgr_disconnect: bool,
    /// The address manager recorded the connection time.
    pub marked_connected: bool,
}

/// Remove a disconnected peer from the server: update the tracking
/// maps and outbound groups, release the connection manager request,
/// and record the last seen time for negotiated untracked peers
/// (dcrd `server.DonePeer`).
pub fn done_peer(
    state: &mut PeerState,
    addr_mgr: &mut AddrManager,
    facts: &DonePeerFacts,
) -> DonePeerOutcome {
    let mut outcome = DonePeerOutcome::default();

    let tracked = if facts.persistent {
        state.persistent_peers.contains_key(&facts.id)
    } else if facts.inbound {
        state.inbound_peers.contains_key(&facts.id)
    } else {
        state.outbound_peers.contains_key(&facts.id)
    };
    if tracked {
        if !facts.inbound && facts.version_known {
            // dcrd reads the address unconditionally; it is always
            // set for peers that completed the handshake.
            if let Some(na) = &facts.na {
                let remote_addr = wire_to_addrmgr_net_address(na);
                *state
                    .outbound_groups
                    .entry(remote_addr.group_key())
                    .or_insert(0) -= 1;
                outcome.group_decremented = true;
            }
        }
        if !facts.inbound && facts.has_conn_req {
            outcome.conn_mgr_disconnect = true;
        }
        if facts.persistent {
            state.persistent_peers.remove(&facts.id);
        } else if facts.inbound {
            state.inbound_peers.remove(&facts.id);
        } else {
            state.outbound_peers.remove(&facts.id);
        }
        outcome.removed = true;
        return outcome;
    }

    if facts.has_conn_req {
        outcome.conn_mgr_disconnect = true;
    }

    // Update the address manager with the last seen time when the
    // peer has acknowledged our version and has sent us its version
    // as well; skipped on the simulation and regression test
    // networks.
    if !facts.sim_or_reg_net && facts.ver_ack_received && facts.version_known {
        if let Some(na) = &facts.na {
            let remote_addr = wire_to_addrmgr_net_address(na);
            // A failure is logged and ignored.
            outcome.marked_connected = addr_mgr.connected(&remote_addr).is_ok();
        }
    }

    outcome
}

/// Disconnect and remove the first peer in the list the comparison
/// selects, returning it for the caller's when-found handling (dcrd
/// `disconnectPeer` with its `whenFound` callback).  dcrd iterates
/// the map in Go's random order; iteration here is in key order.
pub fn disconnect_peer(
    peer_list: &mut BTreeMap<i32, PeerStateEntry>,
    compare: impl Fn(i32, &PeerStateEntry) -> bool,
) -> Option<(i32, PeerStateEntry)> {
    let id = peer_list
        .iter()
        .find(|(id, entry)| compare(**id, entry))
        .map(|(id, _)| *id)?;
    let entry = peer_list.remove(&id)?;
    Some((id, entry))
}

/// Whether the peer address is within a whitelisted network (dcrd
/// `isWhitelisted`); unsplittable addresses and unparseable hosts
/// are logged and not whitelisted.
pub fn is_whitelisted(whitelists: &[crate::config::IpNet], addr: &str) -> bool {
    if whitelists.is_empty() {
        return false;
    }

    let Ok((host, _)) = split_host_port(addr) else {
        return false;
    };
    let Some(ip) = crate::config::parse_ip_go(&host) else {
        return false;
    };

    whitelists.iter().any(|ipnet| ipnet.contains(&ip))
}
