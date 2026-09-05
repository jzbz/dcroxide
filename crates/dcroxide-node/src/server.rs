// SPDX-License-Identifier: ISC
//! The P2P server's decision core (the ported slices of dcrd's
//! `server.go`): the bounded network address submission cache fed by
//! outbound peers, the best-suggestion local address resolution, the
//! host-to-network-address conversion, the wire/address-manager
//! conversion and service helpers, the serverPeer address relay,
//! ban, and abuse-control handlers, the version handshake, the peer
//! state maps and admission, and the relay and broadcast decisions.
//! The chain-backed handlers, the mining and mix handlers, and the
//! server lifecycle arrive with later slices (the rebroadcast
//! machinery lives in the `rebroadcast` module).

// Bounded cache and majority arithmetic mirroring Go.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use dcroxide_addrmgr::{
    AddrManager, AddressPriority, NetAddress, NetAddressReach, NetAddressType, encode_host,
    is_routable, new_net_address_from_ip_port, new_net_address_from_params,
};
use dcroxide_wire::ServiceFlag;

use crate::gostd::{join_host_port, split_host_port};

/// The default number of outbound peers to maintain (dcrd
/// `defaultTargetOutbound`).
pub const DEFAULT_TARGET_OUTBOUND: i64 = 8;

/// dcrd's server-level outbound target: the default, lowered to
/// `--maxpeers` only when that is smaller *as a `uint32`*
/// (`server.go:3927` sets the field, `:4273-4274` lowers it).
///
/// ```text
/// s.targetOutbound = defaultTargetOutbound
/// if uint32(cfg.MaxPeers) < s.targetOutbound {
///     s.targetOutbound = uint32(cfg.MaxPeers)
/// }
/// ```
///
/// The conversion happens BEFORE the comparison, so it truncates to
/// the low 32 bits and a negative `--maxpeers` reads as a huge
/// positive: `-1` leaves the target at 8 rather than lowering it,
/// while `4294967296` truncates to 0 and lowers it to nothing.
///
/// This is NOT the same computation as [`netsync_max_outbound_peers`],
/// which dcrd runs on the same flag 140 lines earlier in signed space
/// and which disagrees with this one in both directions.  Reproducing
/// both, rather than picking whichever looks right, is QK-0014.
pub fn server_target_outbound(max_peers: i64) -> u32 {
    (DEFAULT_TARGET_OUTBOUND as u32).min(max_peers as u32)
}

/// dcrd's netsync outbound target: the default, lowered to `--maxpeers`
/// when that is smaller *as a signed `int`*, and widened only
/// afterwards (`server.go:4132-4142`).
///
/// ```text
/// targetOutbound := defaultTargetOutbound
/// if cfg.MaxPeers < targetOutbound {
///     targetOutbound = cfg.MaxPeers
/// }
/// ...
/// MaxOutboundPeers: uint64(targetOutbound),
/// ```
///
/// The comparison is signed and the widening comes AFTER, so a
/// negative `--maxpeers` becomes an enormous `uint64` instead of a
/// small one: `-1` yields `u64::MAX`, and `4294967296` is not below
/// the default at all so the target stays 8.  Both are the opposite of
/// what [`server_target_outbound`] produces for the same flag; see
/// QK-0014.
pub fn netsync_max_outbound_peers(max_peers: i64) -> u64 {
    DEFAULT_TARGET_OUTBOUND.min(max_peers) as u64
}

/// Whether dcrd's `newServer` can build its relay queues for this
/// `--maxpeers` (`server.go:3931-3932`):
///
/// ```text
/// relayInv:  make(chan relayMsg, cfg.MaxPeers),
/// broadcast: make(chan broadcastMsg, cfg.MaxPeers),
/// ```
///
/// Go takes a channel capacity as a signed `int` and rejects a negative
/// one with `panic: makechan: size out of range`.  Nothing on dcrd's
/// startup path recovers it, and nothing validates the flag beforehand,
/// so `dcrd --maxpeers=-1` dies in `newServer` roughly 200 lines before
/// it reaches either outbound target -- which is why the two targets
/// can disagree there without anyone upstream noticing (QK-0014).
///
/// dcroxide relays synchronously and allocates no such queue, so it
/// would boot where dcrd refuses to, and would do so with
/// `MaxNormalConns` set to `uint32(-1)`: no peer limit at all, from a
/// typo that stops dcrd dead.  Reproducing the refusal is what keeps
/// the port from being the more permissive of the two.
///
/// Only the negative half is deterministic upstream.  A large enough
/// `--maxpeers` also kills dcrd, but as an unrecoverable out-of-memory
/// death whose threshold is the machine's rather than the flag's, so
/// that half is not reproduced; see PARITY.
pub fn max_peers_is_startable(max_peers: i64) -> bool {
    max_peers >= 0
}

/// The maximum number of candidates used for automatic discovery of
/// external addresses to allow (dcrd `maxExternalAddrCandidates`).
pub const MAX_EXTERNAL_ADDR_CANDIDATES: u32 = 20;

/// Render a wire address's 16-byte IP the way Go's `net.IP.String`
/// does.  dcrd reads `candidate.addr.IP.String()` on the RAW WIRE IP
/// throughout this subsystem, never the address manager's
/// `ipString`, which renders an unknown-typed address as the literal
/// `unsupported IP type ...` and a Tor v3 one as a .onion string.
fn wire_ip_string(ip: &[u8; 16]) -> String {
    crate::config::go_ip_string(ip)
}

/// Parse a listener port exactly like Go's `strconv.ParseUint(portStr,
/// 10, 16)`: decimal digits only, no sign, no base prefix, no
/// underscores.  Rust's `str::parse::<u16>` accepts a leading `+`,
/// which Go rejects, and `gostd::go_parse_uint` implements Go's
/// base-0 form, which accepts `0x10` and rejects `08`.
fn go_parse_port(s: &str) -> Option<u16> {
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    s.parse::<u16>().ok()
}

/// An external address candidate (dcrd `externalAddrCandidate`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAddrCandidate {
    /// The reported address in its wire form; dcrd stores the
    /// `*wire.NetAddress` the version message carried, and the
    /// inbound corroboration path reads its port.
    pub addr: dcroxide_wire::NetAddress,
    /// The network type of the address.
    pub net_type: NetAddressType,
    /// The reachability of the address.
    pub reach: NetAddressReach,
    /// The number of times remote peers reported this address.
    pub score: u32,
}

/// Candidates for potentially reachable external addresses (aka
/// local addresses) of the server (dcrd
/// `externalAddrCandidateCache`).
///
/// The overall goal is to automatically discover external addresses
/// for the server that are then advertised to the network.  A
/// variety of heuristics are used including a scoring system that
/// tracks how many times remote peers report a given address as what
/// they see for connections with the local server.  That is, a local
/// address from the perspective of the server.
///
/// Several measures are taken to help prevent malicious behavior.
/// For example, unroutable addresses are ignored and inbound peers
/// can only corroborate addresses that have otherwise already been
/// discovered -- though see [`consider_reported_addr`], where dcrd's
/// inbound corroboration cannot actually fire.
///
/// dcrd embeds a `sync.Mutex` that guards the whole subsystem and is
/// held across the address manager calls in
/// [`resolve_external_address`]; the port passes `&mut` borrows for
/// the same duration.
pub struct ExternalAddrCandidateCache {
    /// The candidates keyed by the wire IP's Go string form.
    pub entries: dcroxide_containers::lru::Map<String, ExternalAddrCandidate>,
}

impl Default for ExternalAddrCandidateCache {
    fn default() -> ExternalAddrCandidateCache {
        ExternalAddrCandidateCache::new()
    }
}

impl ExternalAddrCandidateCache {
    /// A new external address candidate cache that is ready to use
    /// (dcrd `makeExternalAddrCandidateCache`).  It makes use of a
    /// size-limited LRU to protect against malicious behavior.  dcrd
    /// takes no limit here; the constant is baked in.
    pub fn new() -> ExternalAddrCandidateCache {
        const LIMIT: u32 = MAX_EXTERNAL_ADDR_CANDIDATES;
        ExternalAddrCandidateCache {
            entries: dcroxide_containers::lru::Map::new(LIMIT),
        }
    }

    /// The candidate for the given network type with the best score,
    /// or `None` when no suitable candidate exists (dcrd
    /// `bestCandidate`).
    ///
    /// `values` walks the LRU from least to most recently used and
    /// does not promote, and the comparison is strictly `>`, so on a
    /// score tie the LEAST recently used of the tied candidates wins.
    /// This is fully deterministic: there is no Go map iteration
    /// anywhere in this function, so the superseded cache's comment
    /// about random tie-breaking does not apply and must not be
    /// carried forward.
    pub fn best_candidate(&self, net: NetAddressType) -> Option<ExternalAddrCandidate> {
        let mut best: Option<ExternalAddrCandidate> = None;
        for candidate in self.entries.values() {
            if candidate.net_type != net {
                continue;
            }
            match &best {
                None => best = Some(candidate),
                Some(b) if candidate.score > b.score => best = Some(candidate),
                Some(_) => {}
            }
        }
        best
    }
}

/// Apply dcrd's guarded score increment and write the result back
/// into the cache.
///
/// dcrd holds `*externalAddrCandidate` pointers, so `candidate.score++`
/// after a `Get` mutates the entry the map already owns and there is
/// no second `Put`.  `dcroxide_containers::lru::Map` is `V: Clone` and
/// `get` hands back a clone, so the mutated value must be written
/// back explicitly.  A `put` on a key that `get` (or the create path)
/// just promoted replaces the value and re-promotes an already
/// most-recently-used entry: it evicts nothing and leaves the LRU
/// order identical to dcrd's in-place mutation.
fn bump_score(
    entries: &mut dcroxide_containers::lru::Map<String, ExternalAddrCandidate>,
    key: &str,
    mut candidate: ExternalAddrCandidate,
) {
    // Spelled as dcrd spells it -- `if candidate.score <
    // math.MaxUint32 { candidate.score++ }` -- rather than as a
    // `saturating_add`, because this guard is the ported line and a
    // reader comparing the two should see the same shape.
    #[allow(clippy::implicit_saturating_add)]
    if candidate.score < u32::MAX {
        candidate.score += 1;
    }
    let _ = entries.put(key.to_string(), candidate);
}

/// The configuration and server facts the external address
/// subsystem reads; dcrd reaches them through the `cfg` package
/// global and the `server` fields.
pub struct ExternalAddrFacts {
    /// The configured listeners (dcrd `cfg.Listeners`), already
    /// normalized to the `host:port` form.
    pub listeners: Vec<String>,
    /// Whether a proxy or onion proxy is configured (dcrd
    /// `cfg.Proxy != "" || cfg.OnionProxy != ""`).
    pub has_proxy: bool,
    /// Whether automatic network address discovery is disabled (dcrd
    /// `cfg.NoDiscoverIP`).
    pub no_discover_ip: bool,
    /// Whether external IPs are explicitly configured (dcrd
    /// `len(cfg.ExternalIPs) > 0`).
    pub has_external_ips: bool,
    /// Whether listening is disabled OR no listeners exist (dcrd
    /// `cfg.DisableListen || len(cfg.Listeners) == 0`).
    pub listen_disabled: bool,
    /// Whether the active network is simnet or regnet.  dcrd tests
    /// `s.chainParams.Name` against the simnet and regnet params
    /// here, NOT `cfg.SimNet`/`cfg.RegNet`; `handleAddPeer`'s own
    /// advertise block tests the cfg booleans instead, and the two
    /// sources are independent.
    pub sim_or_reg_net: bool,
    /// The services the server supports (dcrd `s.services`, always
    /// `SFNodeNetwork` on this path).
    pub services: ServiceFlag,
    /// The target outbound peer count (dcrd `s.targetOutbound`),
    /// already clamped to `min(DEFAULT_TARGET_OUTBOUND, max_peers)`
    /// at server construction.
    pub target_outbound: u32,
}

/// Potenentially add the provided external address candidate as a
/// known external (aka local) address for the server (dcrd
/// `server.resolveExternalAddress`).
///
/// The address must either match one of the configured listeners or
/// at least possibly be reachable via one of them.  There is no
/// score logic here: the 60% majority gate lives in
/// [`consider_reported_addr_outbound`].
pub fn resolve_external_address(
    candidate: &ExternalAddrCandidate,
    addr_mgr: &mut AddrManager,
    facts: &ExternalAddrFacts,
    resolver: &ResolveIpFn<'_>,
    now_unix: i64,
) {
    let add_local_address =
        |best_suggestion: &str, port: u16, services: ServiceFlag, addr_mgr: &mut AddrManager| {
            let na = match host_to_net_address(best_suggestion, port, services, resolver, now_unix)
            {
                Ok(na) => na,
                // dcrd logs "unable to generate network address using
                // host %v: %v" and returns.  Unreachable in practice:
                // the suggestion is always an IP literal that
                // `encode_host` recognizes, so the resolver is never
                // consulted.
                Err(_) => return,
            };

            if !addr_mgr.has_local_address(&na) {
                // dcrd logs "unable to add local address: %v" and
                // returns.
                let _ = addr_mgr.add_local_address(&na, AddressPriority::Manual);
            }
        };

    let candidate_ip = wire_ip_string(&candidate.addr.ip);
    for listener in &facts.listeners {
        let Ok((host, port_str)) = split_host_port(listener) else {
            // dcrd logs "unable to split network address: %v" and
            // CONTINUES.  One malformed listener must not abort the
            // remaining listeners.
            continue;
        };

        let Some(port) = go_parse_port(&port_str) else {
            // dcrd logs "unable to parse port: %v" and CONTINUES.
            continue;
        };

        // Strip IPv6 zone id if present.  dcrd tests `zoneIndex > 0`
        // strictly, so a host that is exactly "%foo" is left alone.
        let host = match host.rfind('%') {
            Some(idx) if idx > 0 => host[..idx].to_string(),
            _ => host,
        };

        // Add a local address if the candidate matches a listener.
        if candidate_ip == host {
            add_local_address(&candidate_ip, port, facts.services, addr_mgr);
            continue;
        }

        // Add a local address if the listener is generic (applies for
        // both IPv4 and IPv6).  dcrd's condition is
        // `host == "" || (host == "*" && runtime.GOOS == "plan9")`;
        // dcroxide does not target plan9, so the second arm is
        // carried as this comment rather than implemented.
        if host.is_empty() {
            add_local_address(&candidate_ip, port, facts.services, addr_mgr);
            continue;
        }

        let Ok(listener_ip) = host.parse::<std::net::IpAddr>() else {
            // dcrd logs "unable to parse listener: %v" and CONTINUES.
            continue;
        };

        // Add a local address if the network address is a probable
        // external endpoint of the listener.  `To4() != nil` is true
        // only for a 4-byte IP and an IPv4-MAPPED one, so
        // `to_ipv4_mapped` is the match and `to_ipv4` (which also
        // accepts IPv4-compatible `::a.b.c.d`) is not.
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

        // Go's `&&` binds tighter than `||`, so dcrd's missing
        // parentheses around the IPv6 half are harmless; the shape is
        // `(A && B) || (C && (D || E || F))`.  Note this list accepts
        // Ipv6Weak, Ipv6Strong and Teredo but NOT Default, while
        // `is_external_addr_candidate` DOES accept Default on the
        // IPv6 side: an address can be a good candidate and still
        // never match an IPv6 listener.  The two lists are
        // deliberately different; do not harmonize them.
        let valid_external = (l_net == NetAddressType::IPv4
            && candidate.reach == NetAddressReach::Ipv4)
            || l_net == NetAddressType::IPv6
                && (candidate.reach == NetAddressReach::Ipv6Weak
                    || candidate.reach == NetAddressReach::Ipv6Strong
                    || candidate.reach == NetAddressReach::Teredo);

        if valid_external {
            add_local_address(&candidate_ip, port, facts.services, addr_mgr);
            continue;
        }
    }
}

/// Consider the provided address, as reported by an outbound peer,
/// as a potential external address candidate for the server (dcrd
/// `server.considerReportedAddrOutbound`).
///
/// The address is expected to already have passed all checks in
/// [`consider_reported_addr`].
#[allow(clippy::too_many_arguments)] // Mirrors dcrd's parameter surface.
pub fn consider_reported_addr_outbound(
    cache: &mut ExternalAddrCandidateCache,
    addr_mgr: &mut AddrManager,
    addr: &dcroxide_wire::NetAddress,
    remote_addr: &NetAddress,
    facts: &ExternalAddrFacts,
    resolver: &ResolveIpFn<'_>,
    now_unix: i64,
) {
    // Only consider the suggested public IP from the outbound peer if
    // there are no prevailing conditions to disable automatic network
    // address discovery:
    //  - There is a proxy set (--proxy, --onion)
    //  - Automatic network address discovery is explicitly disabled
    //    (--nodiscoverip)
    //  - There is an external IP explicitly set (--externalip)
    //  - Listening has been disabled (--nolisten, listen disabled
    //    because of --connect, etc)
    //  - The active network is simnet or regnet
    if facts.has_proxy
        || facts.no_discover_ip
        || facts.has_external_ips
        || facts.listen_disabled
        || facts.sim_or_reg_net
    {
        return;
    }

    // Determine if the reported address is a candidate for an
    // external address of the server.
    let local_addr = wire_to_addrmgr_net_address(addr);
    let (good, reach) = addr_mgr.is_external_addr_candidate(&local_addr, remote_addr);
    if !good {
        return;
    }

    // dcrd derives this from the wire IP, after the good check, while
    // `is_external_addr_candidate` derived `local_addr.addr_type`
    // through `derive_net_address_type`.  Keep the two derivations
    // separate.
    let net = if wire_ip_is_v4(&addr.ip) {
        NetAddressType::IPv4
    } else {
        NetAddressType::IPv6
    };

    // Increase score for addresses that have already been seen and
    // create a new entry for ones that haven't.  The key is the BARE
    // IP with no port; see [`consider_reported_addr`] for why that
    // matters.  `get` promotes the entry to most recently used and
    // counts a hit or a miss, exactly as dcrd's does.
    let candidate_key = wire_ip_string(&addr.ip);
    let candidate = match cache.entries.get(&candidate_key) {
        Some(existing) => existing,
        None => {
            let fresh = ExternalAddrCandidate {
                addr: *addr,
                net_type: net,
                reach,
                score: 0,
            };
            // May evict the least recently used entry at the limit.
            let _ = cache.entries.put(candidate_key.clone(), fresh.clone());
            fresh
        }
    };
    // Runs for a brand-new candidate too: created at 0, it lands at 1
    // in this same call.
    bump_score(&mut cache.entries, &candidate_key, candidate);

    // Attempt to find the best candidate for the given network type
    // as determined by the one with the best score.
    let Some(best_candidate) = cache.best_candidate(net) else {
        return;
    };

    // The best candidate must have been reported by at least a 60%
    // majority of the target number of outbound peers to be
    // considered valid.  dcrd's expression is unsigned integer
    // arithmetic, not a float ceiling.
    // `div_ceil` would say the same thing, but dcrd's expression is
    // unsigned integer arithmetic written out, and the vector rows
    // pin it in that form.
    #[allow(clippy::manual_div_ceil)]
    if best_candidate.score < ((facts.target_outbound * 60) + 99) / 100 {
        return;
    }

    // Potenentially add the best candidate as a known external (aka
    // local) address for the server.  dcrd still holds the candidate
    // cache mutex here, so the address manager is mutated under it.
    resolve_external_address(&best_candidate, addr_mgr, facts, resolver, now_unix);
}

/// Consider the provided address as a potential external address
/// candidate for the server (dcrd `server.considerReportedAddr`).
#[allow(clippy::too_many_arguments)] // Mirrors dcrd's parameter surface.
pub fn consider_reported_addr(
    cache: &mut ExternalAddrCandidateCache,
    addr_mgr: &mut AddrManager,
    addr: Option<&dcroxide_wire::NetAddress>,
    inbound: bool,
    remote_addr: &NetAddress,
    facts: &ExternalAddrFacts,
    resolver: &ResolveIpFn<'_>,
    now_unix: i64,
) {
    // dcrd's `addr == nil` case: no version message has stored a
    // reported local address yet.  The routability test is the
    // PACKAGE-level `addrmgr.IsRoutable` on the raw IP, not the
    // `NetAddress` method, which returns true unconditionally for Tor
    // v3.  It applies to inbound and outbound alike.
    let Some(addr) = addr else {
        return;
    };
    if !is_routable(&addr.ip) {
        return;
    }

    // Inbound peers can only corroborate existing external address
    // candidates.
    //
    // DELIBERATE UPSTREAM DEFECT -- DO NOT "FIX" THIS (QK-0013).
    // dcrd builds the lookup key here with `net.JoinHostPort`, so it
    // is `8.8.8.8:9108` or `[2001:db8::1]:9108`, while
    // `consider_reported_addr_outbound` stores under the BARE
    // `addr.IP.String()`, e.g. `8.8.8.8`.  The two key spaces are
    // disjoint -- the joined form always carries `:<port>` and
    // brackets IPv6, the bare form never does -- so this lookup
    // ALWAYS misses and an inbound peer can NEVER bump a score,
    // notwithstanding the cache's own doc comment.  Rewriting this to
    // key on the bare IP would make dcroxide stronger than dcrd and
    // would lower the number of reports an attacker needs to push an
    // address over the 60% majority, since inbound peers are the
    // cheap ones to supply in bulk.  The miss is also not invisible:
    // `get` ticks the LRU's miss counter and moves its hit ratio, so
    // `exists` or `peek` would diverge here too.  Pinned by the
    // `ecra|beforeinbound`, `ecra|afterinbound`, `ecrakey|*` and
    // `ecra|inboundhitjoinedkey` vector rows.
    if inbound {
        let port_str = addr.port.to_string();
        let candidate_key = join_host_port(&wire_ip_string(&addr.ip), &port_str);
        if let Some(candidate) = cache.entries.get(&candidate_key) {
            bump_score(&mut cache.entries, &candidate_key, candidate);
        }
        return;
    }

    consider_reported_addr_outbound(
        cache,
        addr_mgr,
        addr,
        remote_addr,
        facts,
        resolver,
        now_unix,
    );
}

/// A DNS resolver like Go's `net.LookupIP`, returning IP addresses.
pub type ResolveIpFn<'a> = dyn Fn(&str) -> Result<Vec<std::net::IpAddr>, String> + 'a;

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

/// Convert a wire v2 network address type to an address manager type
/// (dcrd `wireToAddrmgrNetAddressType`).
pub fn wire_v2_to_addrmgr_net_address_type(
    addr_type: dcroxide_wire::NetAddressType,
) -> dcroxide_addrmgr::NetAddressType {
    match addr_type {
        dcroxide_wire::NetAddressType::IPV4 => dcroxide_addrmgr::NetAddressType::IPv4,
        dcroxide_wire::NetAddressType::IPV6 => dcroxide_addrmgr::NetAddressType::IPv6,
        dcroxide_wire::NetAddressType::TOR_V3 => dcroxide_addrmgr::NetAddressType::TorV3,
        _ => dcroxide_addrmgr::NetAddressType::Unknown,
    }
}

/// Convert an address manager network address type to a wire v2 type
/// (dcrd `addrmgrToWireNetAddressType`).
pub fn addrmgr_to_wire_v2_net_address_type(
    addr_type: dcroxide_addrmgr::NetAddressType,
) -> dcroxide_wire::NetAddressType {
    match addr_type {
        dcroxide_addrmgr::NetAddressType::IPv4 => dcroxide_wire::NetAddressType::IPV4,
        dcroxide_addrmgr::NetAddressType::IPv6 => dcroxide_wire::NetAddressType::IPV6,
        dcroxide_addrmgr::NetAddressType::TorV3 => dcroxide_wire::NetAddressType::TOR_V3,
        _ => dcroxide_wire::NetAddressType::UNKNOWN,
    }
}

/// Convert a wire v2 network address to an address manager net
/// address (one element of dcrd `wireToAddrmgrNetAddressesV2`); fails
/// when the encoded bytes do not fit the claimed type.
pub fn wire_v2_to_addrmgr_net_address(
    net_addr: &dcroxide_wire::NetAddressV2,
) -> Result<NetAddress, String> {
    let addr_type = wire_v2_to_addrmgr_net_address_type(net_addr.addr_type);
    dcroxide_addrmgr::new_net_address_from_params(
        addr_type,
        &net_addr.encoded_addr,
        net_addr.port,
        (net_addr.timestamp as i64).saturating_mul(1_000_000_000),
        net_addr.services,
    )
    .map_err(|e| e.description)
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

/// Convert an address manager net address to a wire v2 net address
/// (dcrd `addrmgrToWireNetAddressV2`).
pub fn addrmgr_to_wire_net_address_v2(net_addr: &NetAddress) -> dcroxide_wire::NetAddressV2 {
    dcroxide_wire::NetAddressV2::new(
        addrmgr_to_wire_v2_net_address_type(net_addr.addr_type),
        net_addr.ip.clone(),
        net_addr.port,
        net_addr.timestamp.div_euclid(1_000_000_000) as u64,
        net_addr.services,
    )
}

/// Convert a collection of wire v2 net addresses, failing when any
/// address cannot form a valid manager address (dcrd
/// `wireToAddrmgrNetAddressesV2`).
pub fn wire_v2_to_addrmgr_net_addresses(
    net_addrs: &[dcroxide_wire::NetAddressV2],
) -> Result<Vec<NetAddress>, String> {
    net_addrs
        .iter()
        .map(wire_v2_to_addrmgr_net_address)
        .collect()
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

/// Whether the address manager address type is supported by the v2
/// address message (dcrd `isSupportedNetAddressTypeV2`).
pub fn is_supported_net_address_type_v2(addr_type: NetAddressType) -> bool {
    addr_type == NetAddressType::IPv4
        || addr_type == NetAddressType::IPv6
        || addr_type == NetAddressType::TorV3
}

/// The address type filter for the protocol version (dcrd
/// `natfSupported`): the v1 types below the addrv2 version and the
/// v2 types from it on.
pub fn natf_supported(pver: u32) -> fn(NetAddressType) -> bool {
    if pver < dcroxide_wire::ADDR_V2_VERSION {
        return is_supported_net_addr_type_v1;
    }
    is_supported_net_address_type_v2
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
    /// The dynamic ban score (dcrd `banScore`), shared so the peer
    /// registry can report the live decaying value for `getpeerinfo`
    /// exactly as dcrd's RPC adaptor reads `sp.banScore.Int()` off the
    /// same object the abuse handlers bump.
    pub ban_score: std::sync::Arc<std::sync::Mutex<dcroxide_connmgr::DynamicBanScore>>,
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
            ban_score: std::sync::Arc::default(),
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

/// Push the provided addresses to the peer as a legacy addr message,
/// filtering the ones it already knows and tracking the ones actually
/// sent (dcrd `serverPeer.pushAddrV1Msg`).
pub fn push_addr_v1_msg<E: dcroxide_peer::PeerEnv>(
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

/// Push the provided addresses to the peer as an addrv2 message,
/// filtering the ones it already knows and tracking the ones actually
/// sent (dcrd `serverPeer.pushAddrV2Msg`).
pub fn push_addr_v2_msg<E: dcroxide_peer::PeerEnv>(
    state: &mut ServerPeerAddrState,
    peer: &mut dcroxide_peer::Peer,
    env: &mut E,
    addresses: &[NetAddress],
) -> PushAddrOutcome {
    // Filter addresses already known to the peer.
    let addrs: Vec<dcroxide_wire::NetAddressV2> = addresses
        .iter()
        .filter(|addr| !state.address_known(addr))
        .map(addrmgr_to_wire_net_address_v2)
        .collect();
    match peer.push_addr_v2_msg(env, &addrs) {
        Some((msg, known)) => {
            // A conversion failure only skips the known-address
            // bookkeeping; the message is already queued (dcrd logs
            // the error and returns after `PushAddrV2Msg` sent).
            if let Ok(known_net_addrs) = wire_v2_to_addrmgr_net_addresses(&known) {
                state.add_known_addresses(&known_net_addrs);
            }
            PushAddrOutcome::Queued(Box::new(msg))
        }
        None => PushAddrOutcome::Nothing,
    }
}

/// Send the address message form the negotiated protocol version
/// calls for (dcrd `serverPeer.pushAddrMsg`).
pub fn push_addr_msg<E: dcroxide_peer::PeerEnv>(
    state: &mut ServerPeerAddrState,
    peer: &mut dcroxide_peer::Peer,
    env: &mut E,
    pver: u32,
    addresses: &[NetAddress],
) -> PushAddrOutcome {
    if pver >= dcroxide_wire::ADDR_V2_VERSION {
        return push_addr_v2_msg(state, peer, env, addresses);
    }
    push_addr_v1_msg(state, peer, env, addresses)
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

    // dcrd 2.2 increments whitelisted peers' scores (visible through
    // getpeerinfo) and only skips the ban itself; the zero-increase
    // warning branch is gone.
    let warn_threshold = ban_threshold >> 1;
    let score = state
        .ban_score
        .lock()
        .expect("ban score poisoned")
        .increase_at(persistent, transient, now_unix);
    if score > warn_threshold && score > ban_threshold && !state.is_whitelisted {
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
    let pver = peer.protocol_version();
    Some(push_addr_msg(state, peer, env, pver, addr_cache))
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
    pub peer_na: NetAddress,
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
    addr_mgr.add_addresses(&addr_list, &facts.peer_na);
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
    /// The peer is banned directly with the carried reason (dcrd 2.2
    /// replaced the ban-score increase) and disconnects.
    BanAndDisconnect {
        /// dcrd's ban reason.
        reason: String,
    },
    /// The peer disconnects without a ban.
    DisconnectOnly,
}

/// Enforce the node cf service flag for the unsupported version 1
/// committed filter requests (dcrd `serverPeer.enforceNodeCFFlag`,
/// reached from `OnGetCFilter`, `OnGetCFHeaders`, and
/// `OnGetCFTypes`).
pub fn enforce_node_cf_flag(
    protocol_version: u32,
    disable_banning: bool,
    cmd: &str,
) -> CfFlagOutcome {
    // Ban the peer directly if the protocol version is high enough
    // that the peer is knowingly violating the protocol and banning
    // is enabled (dcrd 2.2 replaced the ban-score increase); the peer
    // disconnects regardless.
    if protocol_version >= dcroxide_wire::NODE_CF_VERSION && !disable_banning {
        return CfFlagOutcome::BanAndDisconnect {
            reason: format!(
                "sent {cmd} request with protocol version {protocol_version} >= {}",
                dcroxide_wire::NODE_CF_VERSION
            ),
        };
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
    /// An outbound peer was rejected in favor of a mix-capable one
    /// (dcrd 2.2; pre-2.2 this disconnected without rejecting).
    MixCapableWanted,
    /// An outbound peer does not provide the required services.
    MissingServices,
}

/// The peer and configuration facts the version handler consumes.
pub struct OnVersionFacts {
    /// Whether the peer is inbound.
    pub inbound: bool,
    /// Whether the simulation or regression test network is active.
    pub sim_or_reg_net: bool,
    /// The current outbound peer count (dcrd walks the peer state).
    pub num_outbound: u32,
    /// The mix-capable outbound peer count.
    pub num_mix_capable_outbound: u32,
    /// The configured outbound connection target.
    pub target_outbound: u32,
    /// The peer's network address (dcrd `sp.remoteAddr`).
    pub remote_na: NetAddress,
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
    /// Whether the peer disabled transaction relay.
    pub disable_relay_tx: bool,
}

/// Handle a version message (dcrd `serverPeer.OnVersion`, the
/// callback dcrd 2.2 fires from inside the handshake; the address
/// advertisement that used to follow moved to the post-handshake
/// add-peer admission).
pub fn on_version(
    addr_mgr: &mut AddrManager,
    facts: &OnVersionFacts,
    msg_protocol_version: i32,
    msg_services: ServiceFlag,
    msg_disable_relay_tx: bool,
) -> OnVersionOutcome {
    let mut outcome = OnVersionOutcome {
        set_services: false,
        rejected: None,
        disable_relay_tx: false,
    };

    // Update the address manager with the advertised services for
    // outbound connections; skipped for inbound connections and on
    // the simulation and regression test networks.  This happens
    // before rejecting peers that are too old.
    if !facts.sim_or_reg_net && !facts.inbound {
        // A lookup failure is logged and ignored.
        let _ = addr_mgr.set_services(&facts.remote_na, msg_services);
        outcome.set_services = true;
    }

    // Reject peers that have a protocol version that is too old.
    if msg_protocol_version < dcroxide_wire::REMOVE_REJECT_VERSION as i32 {
        outcome.rejected = Some(VersionRejection::OldProtocol);
        return outcome;
    }

    // Maintain a minimum desired number of outbound peers capable
    // of supporting p2p mixing.  dcrd 2.2 rejects here (aborting the
    // handshake); pre-2.2 it disconnected without returning.
    if !facts.inbound && msg_protocol_version < dcroxide_wire::MIX_VERSION as i32 {
        let mut want_mix_capable = DEFAULT_WANT_MIX_CAPABLE_OUTBOUND;
        if facts.target_outbound < want_mix_capable {
            want_mix_capable = facts.target_outbound;
        }
        let has_min = facts.num_mix_capable_outbound >= want_mix_capable;
        let needs_more = !has_min && facts.num_outbound + want_mix_capable >= facts.target_outbound;
        if needs_more {
            outcome.rejected = Some(VersionRejection::MixCapableWanted);
            return outcome;
        }
    }

    // Reject outbound peers that are not full nodes.
    let want_services = ServiceFlag::NODE_NETWORK;
    if !facts.inbound && !has_services(msg_services, want_services) {
        outcome.rejected = Some(VersionRejection::MissingServices);
        return outcome;
    }

    // The address advertisement, getaddr request, and good marking
    // moved to the post-handshake add-peer admission in dcrd 2.2
    // (`handleAddPeer`); the caller stores the advertised address and
    // time sample and chooses whether or not to relay transactions.
    outcome.disable_relay_tx = msg_disable_relay_tx;
    outcome
}

/// The observable outcome of handling an addrv2 message (dcrd
/// `serverPeer.OnAddrV2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnAddrV2Outcome {
    /// The message was ignored (simulation or regression network).
    Ignored,
    /// An address failed conversion; the peer is banned (dcrd's
    /// "sent invalid addrv2 message" ban).
    BanInvalid,
    /// The addresses were forwarded to the address manager.
    Processed,
}

/// Handle an addrv2 message (dcrd `serverPeer.OnAddrV2`).  Unlike the
/// legacy handler an empty list is NOT banned, and a conversion
/// failure is.
pub fn on_addr_v2(
    state: &mut ServerPeerAddrState,
    addr_mgr: &mut AddrManager,
    facts: &OnAddrFacts,
    addr_list: &[dcroxide_wire::NetAddressV2],
    now_nanos: i64,
) -> OnAddrV2Outcome {
    // Ignore addresses when running on the simulation and regression
    // test networks.
    if facts.sim_or_reg_net {
        return OnAddrV2Outcome::Ignored;
    }

    // Do not add more addresses if the peer is disconnecting.
    if !facts.connected {
        return OnAddrV2Outcome::Ignored;
    }

    // A claimed type that does not match the canonical form of the
    // address bans the peer.
    let Ok(mut addr_list) = wire_v2_to_addrmgr_net_addresses(addr_list) else {
        return OnAddrV2Outcome::BanInvalid;
    };

    for na in &mut addr_list {
        if !facts.connected {
            return OnAddrV2Outcome::Processed;
        }

        // Set the timestamp to 5 days ago if it's more than 10
        // minutes in the future so this address is one of the first
        // to be removed when space is needed.
        if na.timestamp > now_nanos + 10 * 60 * 1_000_000_000 {
            na.timestamp = now_nanos - 5 * 24 * 60 * 60 * 1_000_000_000;
        }

        // Add address to known addresses for this peer.
        state.add_known_addresses(core::slice::from_ref(na));
    }

    // Add addresses to the server address manager, which handles
    // duplicate prevention, limits, and last seen updates.
    addr_mgr.add_addresses(&addr_list, &facts.peer_na);
    OnAddrV2Outcome::Processed
}

/// dcrd's exact error text for a version rejection (the `fmt.Errorf`
/// strings `serverPeer.OnVersion` returns).
pub fn version_rejection_text(
    facts: &OnVersionFacts,
    msg: &dcroxide_wire::MsgVersion,
    rejection: VersionRejection,
) -> String {
    match rejection {
        VersionRejection::OldProtocol => format!(
            "rejecting protocol version {} prior to the required version {}",
            msg.protocol_version,
            dcroxide_wire::REMOVE_REJECT_VERSION,
        ),
        VersionRejection::MixCapableWanted => {
            let mut want_mix_capable = DEFAULT_WANT_MIX_CAPABLE_OUTBOUND;
            if facts.target_outbound < want_mix_capable {
                want_mix_capable = facts.target_outbound;
            }
            format!(
                "rejecting outbound peer with protocol version {} in favor of \
                 a peer with minimum version {} (have: {}, target: {})",
                msg.protocol_version,
                dcroxide_wire::MIX_VERSION,
                facts.num_mix_capable_outbound,
                want_mix_capable,
            )
        }
        VersionRejection::MissingServices => {
            let want_services = ServiceFlag::NODE_NETWORK;
            let missing = ServiceFlag(want_services.0 & !msg.services.0);
            format!(
                "rejecting peer with services {} due to not providing desired services {}",
                msg.services, missing,
            )
        }
    }
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

/// Why the admission handler rejected a peer.  dcrd 2.2 rejects
/// banned connections before the handshake and enforces the
/// connection limits in the connection manager, leaving shutdown as
/// the only add-time rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddPeerReject {
    /// The server is shutting down.
    Shutdown,
}

/// The outcome of the pre-handshake banned-host check.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BannedConnOutcome {
    /// The host is banned and the connection must be closed.
    pub banned: bool,
    /// An expired ban was lifted (dcrd logs "no longer banned").
    pub unbanned: bool,
}

/// Reject a connection from a banned host before the handshake (dcrd
/// 2.2 `handleBannedConn`); an expired ban is lifted.  The host key
/// is the bare IP rendering (dcrd `net.IP(remoteAddr.IP).String()`),
/// not the host:port form.
pub fn handle_banned_conn(
    banned: &mut std::collections::BTreeMap<String, i64>,
    host: &str,
    now_nanos: i64,
) -> BannedConnOutcome {
    let mut outcome = BannedConnOutcome::default();
    if let Some(&ban_end) = banned.get(host) {
        if now_nanos < ban_end {
            outcome.banned = true;
            return outcome;
        }
        banned.remove(host);
        outcome.unbanned = true;
    }
    outcome
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
    /// The peer's network address (dcrd `sp.NA()`); the address
    /// manager form of it is dcrd's `sp.remoteAddr`.
    pub na: dcroxide_wire::NetAddress,
    /// The remote peer's view of the local address from its version
    /// message, when one was stored (dcrd
    /// `sp.reportedLocalAddr.Load()`).
    pub peer_na: Option<dcroxide_wire::NetAddress>,
    /// The single-IP connection limit (dcrd `cfg.MaxSameIP`).
    pub max_same_ip: i64,
    /// The configuration the external address subsystem reads.
    pub external: ExternalAddrFacts,
}
/// What the admission handler decided and did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AddPeerOutcome {
    /// The rejection when the peer was refused and disconnected;
    /// dcrd returns false from `handleAddPeer`.
    pub rejected: Option<AddPeerReject>,
    /// An expired ban entry for the host was removed.
    pub unbanned: bool,
}
/// Add a peer to the server's state, categorising it, enforcing the
/// connection limits, and considering the address it reported for the
/// local connection as an external address candidate (dcrd
/// `server.handleAddPeer`, `server.go:2625`).
///
/// Returns what was decided; dcrd returns a bool and disconnects the
/// peer itself on a rejection.
pub fn handle_add_peer(
    state: &mut PeerState,
    cache: &mut ExternalAddrCandidateCache,
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

    // dcrd updates the address manager and requests known addresses
    // from the remote peer for outbound connections here, gated on
    // `!cfg.SimNet && !cfg.RegNet && !sp.Inbound()`.  That block
    // needs the sync manager and the local-address advertisement and
    // arrives with the daemon wiring; note its gate reads the cfg
    // booleans, while the discovery gate below reads the chain params
    // name, and the two are independent.

    // Consider the address the remote peer reported for the local
    // connection as a potential external address candidate for the
    // server.  Called once, unconditionally, before the peer state
    // lock and before the peer is inserted into any map.
    let now_unix = now_nanos / 1_000_000_000;
    let remote_addr = wire_to_addrmgr_net_address(&facts.na);
    consider_reported_addr(
        cache,
        addr_mgr,
        facts.peer_na.as_ref(),
        facts.inbound,
        &remote_addr,
        &facts.external,
        resolver,
        now_unix,
    );

    // dcrd 2.2 rejects banned connections before the handshake
    // ([`handle_banned_conn`]) and enforces the connection limits in
    // the connection manager, so the only add-time gate left is the
    // shutdown check above.
    let entry = PeerStateEntry {
        na: facts.na,
        inbound: facts.inbound,
        persistent: facts.persistent,
    };

    // Add the new peer.
    if facts.inbound {
        state.inbound_peers.insert(facts.id, entry);
        return outcome;
    }

    // The peer is an outbound peer at this point.
    if facts.persistent {
        state.persistent_peers.insert(facts.id, entry);
    } else {
        state.outbound_peers.insert(facts.id, entry);
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
    if !facts.sim_or_reg_net
        && facts.ver_ack_received
        && facts.version_known
        && let Some(na) = &facts.na
    {
        let remote_addr = wire_to_addrmgr_net_address(na);
        // A failure is logged and ignored.
        outcome.marked_connected = addr_mgr.connected(&remote_addr).is_ok();
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
/// `connmgr.IsWhitelisted`); unsplittable addresses and unparseable
/// hosts are not whitelisted.  The candidate is parsed through the
/// `To4`-normalized form the address manager canonicalizes remote
/// addresses into before dcrd hands them to the connection manager.
pub fn is_whitelisted(whitelists: &[crate::config::IpPrefix], addr: &str) -> bool {
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

/// The negotiated peer facts the relay handler consumes (dcrd reads
/// them off the live `serverPeer`).
pub struct RelayPeerFacts {
    /// Whether the peer is connected (dcrd `sp.Connected()`).
    pub connected: bool,
    /// The services the peer advertised (dcrd `sp.Services()`).
    pub services: ServiceFlag,
    /// Whether the peer prefers headers over inventory for block
    /// announcements (dcrd `sp.WantsHeaders()`).
    pub wants_headers: bool,
    /// Whether the peer disabled transaction relaying (dcrd
    /// `sp.disableRelayTx`).
    pub disable_relay_tx: bool,
    /// The negotiated protocol version (dcrd `sp.ProtocolVersion()`).
    pub protocol_version: u32,
}

/// The relay message facts the handler consumes (dcrd `relayMsg`).
pub struct RelayInvFacts {
    /// The inventory type.
    pub inv_type: dcroxide_wire::InvType,
    /// The inventory hash.
    pub inv_hash: dcroxide_chainhash::Hash,
    /// The services required to receive the announcement.
    pub req_services: ServiceFlag,
    /// Whether to relay immediately rather than with the next batch.
    pub immediate: bool,
    /// Whether the message data is a usable block header (dcrd's type
    /// assertion of `msg.data.(wire.BlockHeader)`).
    pub data_is_block_header: bool,
    /// Whether the message data is a usable transaction (dcrd's type
    /// assertion of `msg.data.(*dcrutil.Tx)`).
    pub data_is_tx: bool,
}

/// What the relay handler decided to do with the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayPeerAction {
    /// Nothing is relayed to the peer.
    Ignore,
    /// A headers message carrying the announced block header is
    /// queued.
    QueueHeaders,
    /// The inventory is queued to be relayed immediately.
    QueueInventoryImmediate,
    /// The inventory is queued to be relayed with the next batch.
    QueueInventory,
}

/// The outcome of the relay handler: the queue action plus the
/// transaction hash the peer qualified to be advertised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayPeerOutcome {
    /// The queue action.
    pub action: RelayPeerAction,
    /// The transaction hash the caller records as recently advertised,
    /// set only for a transaction inventory that cleared this peer's
    /// relay gate (dcrd's per-peer `recentlyAdvertisedTxns.Put`).
    pub advertised_tx: Option<dcroxide_chainhash::Hash>,
}

/// Relay an inventory announcement to a specific peer, applying the
/// service filter, the block-announcement de-duplication, the
/// headers preference, and the transaction and mix relay gates
/// (dcrd `server.handleRelayPeerInvMsg`).  The peer's last announced
/// block is updated in place.
pub fn handle_relay_peer_inv(
    announced_block: &mut Option<dcroxide_chainhash::Hash>,
    facts: &RelayPeerFacts,
    msg: &RelayInvFacts,
) -> RelayPeerOutcome {
    let ignore = RelayPeerOutcome {
        action: RelayPeerAction::Ignore,
        advertised_tx: None,
    };

    if !facts.connected {
        return ignore;
    }

    // Ignore peers that do not have the required service flags.
    if !has_services(facts.services, msg.req_services) {
        return ignore;
    }

    // Filter duplicate block announcements.
    let is_block_announcement = msg.inv_type == dcroxide_wire::InvType::BLOCK;
    if is_block_announcement {
        if *announced_block == Some(msg.inv_hash) {
            *announced_block = None;
            return ignore;
        }
        *announced_block = Some(msg.inv_hash);
    }

    // Generate and send a headers message instead of an inventory
    // message for block announcements when the peer prefers headers.
    if is_block_announcement && facts.wants_headers {
        if !msg.data_is_block_header {
            // dcrd warns and drops the announcement.
            return ignore;
        }
        return RelayPeerOutcome {
            action: RelayPeerAction::QueueHeaders,
            advertised_tx: None,
        };
    }

    let mut advertised_tx = None;
    if msg.inv_type == dcroxide_wire::InvType::TX {
        // Don't relay the transaction to the peer when it has
        // transaction relaying disabled.
        if facts.disable_relay_tx {
            return ignore;
        }
        if !msg.data_is_tx {
            // dcrd warns and drops the announcement.
            return ignore;
        }
        // Track advertised transactions so they can be served even
        // after leaving the mempool.
        advertised_tx = Some(msg.inv_hash);
    }

    if msg.inv_type == dcroxide_wire::InvType::MIX {
        // Don't relay the mixing message to the peer when it has
        // transaction relaying disabled.
        if facts.disable_relay_tx {
            return ignore;
        }
        // Don't relay mix message inventory when unsupported by the
        // negotiated protocol version.
        if facts.protocol_version < dcroxide_wire::MIX_VERSION {
            return ignore;
        }
    }

    // Either queue the inventory to be relayed immediately or with
    // the next batch depending on the immediate flag.
    let action = if msg.immediate {
        RelayPeerAction::QueueInventoryImmediate
    } else {
        RelayPeerAction::QueueInventory
    };
    RelayPeerOutcome {
        action,
        advertised_tx,
    }
}

/// Whether the broadcast message should be queued to a given peer:
/// the peer must be connected and not in the exclusion set (dcrd's
/// per-peer body of `server.handleBroadcastMsg`).
pub fn should_broadcast_to_peer(connected: bool, is_excluded: bool) -> bool {
    connected && !is_excluded
}

/// The maximum number of inventory vectors per message (dcrd
/// `wire.MaxInvPerMsg`).
pub const MAX_INV_PER_MSG: u32 = 50000;

/// The maximum number of concurrent pending getdata request batches
/// before a peer is disconnected (dcrd `maxConcurrentGetDataReqs`).
pub const MAX_CONCURRENT_GETDATA_REQS: usize = 1000;

/// The maximum number of pending individual getdata item requests
/// before a peer is disconnected (dcrd `maxPendingGetDataItemReqs`,
/// two full inventory messages).
pub const MAX_PENDING_GETDATA_ITEM_REQS: u32 = 2 * MAX_INV_PER_MSG;

/// The ban score charged for requesting one full inventory message
/// worth of getdata items (dcrd's `numNewReqs*99/wire.MaxInvPerMsg`
/// rate: 99 points, one short of the default ban threshold, so a
/// single maximal query warns and a second one bans).
pub const GETDATA_SCORE_PER_FULL_INV: u32 = 99;

/// The ban score a `getdata` costs its sender (dcrd's
/// `numNewReqs*99/wire.MaxInvPerMsg` in `OnGetData`).
///
/// This is Go integer division, so any request below
/// `MAX_INV_PER_MSG / GETDATA_SCORE_PER_FULL_INV` items — 506 — costs
/// nothing at all, and only the size of each individual request is
/// charged, never the total across requests.
///
/// The truncation is deliberate parity, and an earlier version of this
/// port "fixed" it by carrying the remainder into the next request so
/// repeated 505-item batches were no longer free.  That is a regression,
/// not an improvement: at 99 points per full inventory message the rate
/// is 0.00198 points per item, and against dcrd's 60-second ban-score
/// half-life and threshold of 100 the equilibrium is reached at ~583
/// items per second sustained.  Both dcrd and this port request blocks
/// in batches of `maxInFlightBlocks` (16), which truncates to zero, so
/// dcrd charges an honestly syncing peer nothing — while a carry would
/// charge it at the full per-item rate.  Early-chain blocks are ~1 KiB,
/// so 583 blocks/s is only ~0.6 MB/s of upload: an ordinary peer
/// bootstrapping from us over a fast link would be banned partway
/// through the small-block window.
///
/// What actually bounds the getdata path is the machinery
/// [`MAX_CONCURRENT_GETDATA_REQS`], [`MAX_PENDING_GETDATA_ITEM_REQS`]
/// and [`MAX_PENDING_SEND`] provide; the audit finding here was that
/// those counters were being passed as literal zeroes, not that the
/// rate was wrong.
pub fn getdata_ban_score_increase(num_new_reqs: u32) -> u32 {
    let scaled = u64::from(num_new_reqs).saturating_mul(u64::from(GETDATA_SCORE_PER_FULL_INV));
    u32::try_from(scaled / u64::from(MAX_INV_PER_MSG)).unwrap_or(u32::MAX)
}

/// The number of getdata response messages that may be loaded from
/// the database and queued for send at once (dcrd `maxPendingSend` in
/// `serveGetData`, "keeping the memory usage bounded to reasonable
/// limits").
pub const MAX_PENDING_SEND: usize = 3;

/// The wire message header overhead added to each queued payload when
/// tracking send progress (dcrd `wire.MessageHeaderSize`).
pub const MESSAGE_HEADER_SIZE: u64 = 24;

/// The send-pipeline bound for one peer's getdata serve: the port of
/// dcrd's `maxPendingSend` semaphore and its `sendDoneChan`.
///
/// dcrd releases a semaphore slot when the output goroutine reports a
/// completed write on the per-message done channel.  This port's
/// output loop does not carry a per-message completion signal, so the
/// pipeline derives one from the peer's cumulative send accounting
/// (`Peer::record_send`, which the output loop updates after every
/// write): a queued message is treated as written once the peer's
/// sent-byte counter has advanced past the cumulative byte mark
/// recorded when it was queued.
///
/// Bytes written for messages from other producers (relay inventory,
/// pings, handshake traffic) also advance that counter, so a mark can
/// retire slightly early; the resulting slack is bounded by whatever
/// those producers wrote concurrently and never lets more than
/// [`MAX_PENDING_SEND`] getdata payloads plus that slack sit unsent.
/// The remaining hard bound is the outbound queue's own depth.
#[derive(Debug, Clone, Default)]
pub struct SendPipeline {
    marks: std::collections::VecDeque<u64>,
    queued: u64,
    sent: u64,
}

impl SendPipeline {
    /// A pipeline with nothing queued.
    pub fn new() -> SendPipeline {
        SendPipeline::default()
    }

    /// The number of queued data messages not yet known to have been
    /// written (dcrd's occupied semaphore slots).
    pub fn pending(&self) -> usize {
        self.marks.len()
    }

    /// Whether another data message may be queued without exceeding
    /// `capacity` outstanding sends (dcrd's semaphore acquisition).
    pub fn has_room(&self, capacity: usize) -> bool {
        self.marks.len() < capacity
    }

    /// Record that a data message of `bytes` payload was queued.
    pub fn record_queued(&mut self, bytes: u64) {
        self.queued = self
            .queued
            .saturating_add(bytes)
            .saturating_add(MESSAGE_HEADER_SIZE);
        self.marks.push_back(self.queued);
    }

    /// Fold in `bytes` newly written by the peer's output loop,
    /// retiring every queued message the counter has passed (dcrd
    /// draining `sendDoneChan` to release semaphore slots).
    pub fn record_sent(&mut self, bytes: u64) {
        self.sent = self.sent.saturating_add(bytes);
        while self.marks.front().is_some_and(|mark| *mark <= self.sent) {
            self.marks.pop_front();
        }
    }
}

/// What the getdata handler decided to do with the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnGetDataOutcome {
    /// The empty request is banned with dcrd's reason.
    BanEmpty,
    /// The decaying request ban score crossed the threshold, so dcrd
    /// bans with the "ban score exceeds threshold" reason.
    BanScore,
    /// Too many concurrent pending request batches; the peer is
    /// disconnected.
    DisconnectConcurrent,
    /// Too many pending individual item requests; the peer is
    /// disconnected.
    DisconnectPendingItems,
    /// The request is queued to be served asynchronously; the field
    /// is the new pending item count.
    Enqueue {
        /// The pending individual item request count after the
        /// enqueue.
        new_pending_items: u32,
    },
}

/// Apply the getdata intake gates: ban empty requests, apply the
/// decaying ban score that penalizes oversized inventory queries,
/// enforce the concurrent-request and pending-item limits, and
/// otherwise queue the request to be served (dcrd
/// `serverPeer.OnGetData` up to the point the serve queue takes
/// over).  The serving itself is chain-backed and lands with a later
/// slice.
#[allow(clippy::too_many_arguments)] // Mirrors dcrd's fact surface.
pub fn on_get_data(
    state: &mut ServerPeerAddrState,
    inv_len: u32,
    pending_getdata_reqs: usize,
    pending_item_reqs: u32,
    disable_banning: bool,
    ban_threshold: u32,
    now_unix: i64,
) -> OnGetDataOutcome {
    // Ban peers sending empty getdata requests.
    if inv_len == 0 {
        return OnGetDataOutcome::BanEmpty;
    }

    // A decaying ban score increase is applied to prevent exhausting
    // resources with unusually large inventory queries.  Requesting
    // more than the maximum inventory vector length within a short
    // period of time yields a score above the default ban threshold.
    //
    // dcrd truncates the per-request rate to zero for any batch of 505
    // items or fewer, and that truncation is reproduced exactly; see
    // [`getdata_ban_score_increase`] for why charging the remainder
    // instead would ban honest peers doing ordinary early-chain sync.
    let num_new_reqs = inv_len;
    let transient = getdata_ban_score_increase(num_new_reqs);
    if add_ban_score(
        state,
        0,
        transient,
        disable_banning,
        ban_threshold,
        now_unix,
    ) {
        return OnGetDataOutcome::BanScore;
    }

    // Prevent too many outstanding request batches while still
    // allowing multiple simultaneous getdata requests to be served
    // asynchronously.
    if pending_getdata_reqs + 1 > MAX_CONCURRENT_GETDATA_REQS {
        return OnGetDataOutcome::DisconnectConcurrent;
    }

    // Prevent too many outstanding individual item requests.
    if pending_item_reqs + num_new_reqs > MAX_PENDING_GETDATA_ITEM_REQS {
        return OnGetDataOutcome::DisconnectPendingItems;
    }

    // Queue the data requests to be served asynchronously.
    OnGetDataOutcome::Enqueue {
        new_pending_items: pending_item_reqs + num_new_reqs,
    }
}

/// What the inventory handler decided to do with the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnInvOutcome {
    /// The empty announcement is banned with dcrd's reason.
    BanEmpty,
    /// A blocks-only peer announced the given noun (transactions or
    /// mix messages) and is disconnected.
    DisconnectAnnouncement(&'static str),
    /// The announcement is forwarded to the sync manager (ported
    /// netsync machinery).
    Forward,
}

/// Classify an inventory announcement: ban empty announcements, and
/// in blocks-only mode disconnect peers that announce transactions
/// or mix messages, otherwise forward to the sync manager (dcrd
/// `serverPeer.OnInv`).  The forward is ported netsync machinery.
///
/// The whole vectors are taken rather than their types alone because
/// dcrd reads `invVect.Type` straight off `msg.InvList`
/// (`server.go:1390`) and materializes nothing; a caller holding a
/// `MsgInv` passes `&inv.inv_list` with no intermediate list.
pub fn on_inv_classify(inv_list: &[dcroxide_wire::InvVect], blocks_only: bool) -> OnInvOutcome {
    // Ban peers sending empty inventory announcements.
    if inv_list.is_empty() {
        return OnInvOutcome::BanEmpty;
    }

    if !blocks_only {
        return OnInvOutcome::Forward;
    }

    for iv in inv_list {
        if iv.inv_type == dcroxide_wire::InvType::TX {
            return OnInvOutcome::DisconnectAnnouncement("transactions");
        }
        if iv.inv_type == dcroxide_wire::InvType::MIX {
            return OnInvOutcome::DisconnectAnnouncement("mix messages");
        }
    }

    OnInvOutcome::Forward
}

/// Whether an announced inventory vector enters the peer's known
/// inventory (dcrd `SyncManager.OnInv`).  dcrd's switch handles the
/// block, transaction and mixing cases and has no default arm
/// (`internal/netsync/manager.go:1894-1961`, with `AddKnownInventory`
/// at `:1908`, `:1917` and `:1942`), so an error, filtered-block or
/// unknown vector is forwarded without ever entering the set.  That
/// matters beyond bookkeeping: the set holds only
/// `dcroxide_peer::MAX_KNOWN_INVENTORY` entries, so a type dcrd
/// ignores must not evict a block or transaction dcrd would still
/// remember.
///
/// The getdata path matches the same three types elsewhere in the
/// daemon; that one tracks dcrd's `OnGetData` switch, which is a
/// different switch, and the two must not be unified.
pub fn inv_is_marked_known(inv_type: dcroxide_wire::InvType) -> bool {
    matches!(
        inv_type,
        dcroxide_wire::InvType::BLOCK | dcroxide_wire::InvType::TX | dcroxide_wire::InvType::MIX
    )
}

/// The maximum number of block inventory vectors per message (dcrd
/// `wire.MaxBlocksPerMsg`).
pub const MAX_BLOCKS_PER_MSG: usize = 500;

/// The response the getblocks handler builds from the located block
/// hashes (dcrd `serverPeer.OnGetBlocks` after `LocateBlocks`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetBlocksResponse {
    /// The block inventory vectors to send; an empty list means no
    /// message is sent.
    pub inv: Vec<dcroxide_wire::InvVect>,
    /// The continue hash to store when the inventory message is full,
    /// so the next getblocks can be triggered by the corresponding
    /// block request.
    pub continue_hash: Option<dcroxide_chainhash::Hash>,
}

/// Build the getblocks inventory response from the located block
/// hashes: skip inventory the peer is already known to have, and set
/// the continue hash when the response fills an entire message (dcrd
/// `serverPeer.OnGetBlocks`).  The `LocateBlocks` walk itself is the
/// ported chain query, pinned separately.
pub fn build_get_blocks_response(
    located: &[dcroxide_chainhash::Hash],
    known: impl Fn(&dcroxide_wire::InvVect) -> bool,
) -> GetBlocksResponse {
    let mut inv = Vec::new();
    for hash in located {
        let iv = dcroxide_wire::InvVect {
            inv_type: dcroxide_wire::InvType::BLOCK,
            hash: *hash,
        };
        // Skip inventory the peer is already known to have.  dcrd
        // notes a TODO to increase the ban score here.
        if known(&iv) {
            continue;
        }
        inv.push(iv);
    }

    // Set the continue hash when the response fills an entire message
    // so the peer requesting the final block triggers the next batch.
    let mut continue_hash = None;
    if !inv.is_empty() && inv.len() == MAX_BLOCKS_PER_MSG {
        continue_hash = Some(inv[inv.len() - 1].hash);
    }

    GetBlocksResponse { inv, continue_hash }
}

/// The response the getheaders handler builds (dcrd
/// `serverPeer.OnGetHeaders`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetHeadersResponse {
    /// An empty headers message signalling that the local best known
    /// tip has too little work for the located headers to be
    /// interesting, sent without appearing unresponsive.
    Empty,
    /// The located headers (possibly empty when the locator is
    /// already at the tip).
    Headers(Vec<dcroxide_wire::BlockHeader>),
}

/// Decide the getheaders response: send an empty headers message when
/// the local best known tip's cumulative work is below the minimum
/// known work already achieved on the network, otherwise send the
/// located headers (dcrd `serverPeer.OnGetHeaders`).  The tip work is
/// compared against the minimum known work by the ported uint256
/// ordering; a chain work lookup error skips the empty-response gate.
/// The `LocateHeaders` walk is the ported chain query, pinned
/// separately.
pub fn build_get_headers_response(
    chain_work_errored: bool,
    tip_work_below_min: bool,
    located: Vec<dcroxide_wire::BlockHeader>,
) -> GetHeadersResponse {
    if !chain_work_errored && tip_work_below_min {
        return GetHeadersResponse::Empty;
    }
    GetHeadersResponse::Headers(located)
}

/// The outcome of resolving a single getdata inventory item against
/// the advertised-transaction cache, mempool, chain, or mix pool
/// (the fetch seams dcrd's `handleServeGetData` consults).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetDataResolution {
    /// The requested item was fetched; its data message is queued.
    Found,
    /// The requested item could not be found; it is accumulated into
    /// the consolidated notfound response.
    NotFound,
    /// The inventory type is unknown; the item is skipped entirely
    /// (dcrd neither serves it, records it as not found, nor
    /// decrements the pending counter).
    UnknownType,
}

/// A single action the getdata server takes, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeGetDataAction {
    /// Queue the resolved data message for the given inventory item.
    QueueData(dcroxide_wire::InvVect),
    /// Queue a single-item inventory of the current best tip to
    /// trigger the peer to request the next getblocks batch, sent
    /// after the block that was the advertised continuation.
    QueueContinueInv(dcroxide_chainhash::Hash),
    /// Queue the consolidated notfound message at the end of the
    /// batch.
    QueueNotFound(Vec<dcroxide_wire::InvVect>),
}

/// What the getdata server decided over a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeGetDataOutcome {
    /// The actions in the exact order they are queued to the peer.
    pub actions: Vec<ServeGetDataAction>,
    /// Whether the stored continuation hash was cleared (after
    /// serving the block it referenced).
    pub cleared_continue_hash: bool,
    /// The number of pending data item requests to decrement (dcrd
    /// decrements for served and not-found items, but not for unknown
    /// types).
    pub pending_decrements: u32,
}

/// A single action the getdata server takes for one inventory item,
/// the per-item decomposition of [`ServeGetDataAction`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeGetDataItemAction {
    /// Queue the resolved data message for the item.  This is the
    /// only action dcrd gates behind its send semaphore.
    QueueData(dcroxide_wire::InvVect),
    /// Queue a single-item inventory of the current best tip after
    /// the data message, triggering the peer's next getblocks batch.
    QueueContinueInv(dcroxide_chainhash::Hash),
    /// Accumulate the item into the batch's consolidated notfound,
    /// which is queued once the whole batch has been walked.
    AccumulateNotFound(dcroxide_wire::InvVect),
}

/// What the getdata server decided for one inventory item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeGetDataItemOutcome {
    /// The actions in the exact order they are taken.
    pub actions: Vec<ServeGetDataItemAction>,
    /// Whether the stored continuation hash was cleared by this item.
    pub cleared_continue_hash: bool,
    /// The pending data item request decrement: one for served and
    /// not-found items, zero for unknown types (dcrd skips those
    /// without touching `numPendingGetDataItemReqs`).
    pub pending_decrement: u32,
}

/// Decide what to do with one resolved getdata inventory item (one
/// iteration of dcrd `serverPeer.handleServeGetData`'s loop).
///
/// Serving item by item is what lets the caller hold the chain lock
/// for a single fetch instead of the whole batch and keep at most
/// [`MAX_PENDING_SEND`] payloads in flight; [`serve_get_data`] is the
/// batch fold over this and stays byte-for-byte identical.
pub fn serve_get_data_item(
    iv: dcroxide_wire::InvVect,
    resolution: GetDataResolution,
    continue_hash: Option<dcroxide_chainhash::Hash>,
    best_hash: dcroxide_chainhash::Hash,
) -> ServeGetDataItemOutcome {
    let mut actions = Vec::new();
    let mut cleared_continue_hash = false;
    let mut pending_decrement = 0;

    match resolution {
        GetDataResolution::UnknownType => {
            // Unknown inventory types are skipped without a notfound
            // entry or a pending decrement.
        }
        GetDataResolution::NotFound => {
            actions.push(ServeGetDataItemAction::AccumulateNotFound(iv));
            pending_decrement = 1;
        }
        GetDataResolution::Found => {
            actions.push(ServeGetDataItemAction::QueueData(iv));
            pending_decrement = 1;

            // When the served block was the advertised continuation,
            // trigger the next getblocks batch — and clear the
            // continuation so a getdata that lists the same block
            // twice emits exactly one continue inv (dcrd
            // `handleServeGetData` reloading `continueHash` each
            // iteration and `Store(nil)` after the first match).
            if iv.inv_type == dcroxide_wire::InvType::BLOCK && continue_hash == Some(iv.hash) {
                actions.push(ServeGetDataItemAction::QueueContinueInv(best_hash));
                cleared_continue_hash = true;
            }
        }
    }

    ServeGetDataItemOutcome {
        actions,
        cleared_continue_hash,
        pending_decrement,
    }
}

/// Serve a batch of getdata inventory items: queue each resolved data
/// message in request order, accumulate the misses into a single
/// notfound message sent last, and — when a served block was the
/// advertised continuation — queue a best-tip inventory afterward and
/// clear the continuation (dcrd `serverPeer.handleServeGetData`).
/// The item fetches are the caller's seams; dcrd's send semaphore is
/// ported as [`SendPipeline`], which the caller drives around the
/// per-item [`serve_get_data_item`] this folds over.
pub fn serve_get_data(
    items: &[(dcroxide_wire::InvVect, GetDataResolution)],
    mut continue_hash: Option<dcroxide_chainhash::Hash>,
    best_hash: dcroxide_chainhash::Hash,
) -> ServeGetDataOutcome {
    let mut actions = Vec::new();
    let mut not_found = Vec::new();
    let mut cleared_continue_hash = false;
    let mut pending_decrements = 0;

    for (iv, resolution) in items {
        let item = serve_get_data_item(*iv, *resolution, continue_hash, best_hash);
        for action in item.actions {
            match action {
                ServeGetDataItemAction::QueueData(iv) => {
                    actions.push(ServeGetDataAction::QueueData(iv));
                }
                ServeGetDataItemAction::QueueContinueInv(best) => {
                    actions.push(ServeGetDataAction::QueueContinueInv(best));
                }
                ServeGetDataItemAction::AccumulateNotFound(iv) => not_found.push(iv),
            }
        }
        if item.cleared_continue_hash {
            cleared_continue_hash = true;
            continue_hash = None;
        }
        pending_decrements += item.pending_decrement;
    }

    if !not_found.is_empty() {
        actions.push(ServeGetDataAction::QueueNotFound(not_found));
    }

    ServeGetDataOutcome {
        actions,
        cleared_continue_hash,
        pending_decrements,
    }
}

/// The maximum number of head block hashes per init state message
/// (dcrd `wire.MaxISBlocksAtHeadPerMsg`).
pub const MAX_IS_BLOCKS_AT_HEAD: usize = 8;

/// The maximum number of vote hashes per init state message (dcrd
/// `wire.MaxISVotesAtHeadPerMsg`).
pub const MAX_IS_VOTES_AT_HEAD: usize = 40;

/// The maximum number of treasury spend hashes per init state message
/// (dcrd `wire.MaxISTSpendsAtHeadPerMsg`).
pub const MAX_IS_TSPENDS_AT_HEAD: usize = 7;

/// What the init state handler decided to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnGetInitStateOutcome {
    /// A repeated request on the connection; dcrd 2.2 bans the peer
    /// with the carried reason and disconnects (older versions
    /// ignored it).
    Ban(String),
    /// An empty init state message, sent when the chain has not yet
    /// reached stake validation so there is nothing interesting to
    /// advertise.
    Blank,
    /// The filled init state response with the requested hashes.
    Filled {
        /// Head block hashes (at most eight).
        block_hashes: Vec<dcroxide_chainhash::Hash>,
        /// Vote hashes for the head blocks.
        vote_hashes: Vec<dcroxide_chainhash::Hash>,
        /// Mempool treasury spend hashes.
        tspend_hashes: Vec<dcroxide_chainhash::Hash>,
    },
    /// The filled message exceeded a wire limit, so dcrd logs the
    /// error and sends nothing.
    BuildError,
}

/// The requested-type flags parsed from a getinitstate message.
#[derive(Debug, Clone, Copy, Default)]
pub struct InitStateWants {
    /// Whether head block hashes were requested.
    pub blocks: bool,
    /// Whether head block vote hashes were requested.
    pub votes: bool,
    /// Whether mempool treasury spend hashes were requested.
    pub tspends: bool,
}

/// Assemble the init state response: ignore duplicate requests on a
/// connection, send an empty message before stake validation, and
/// otherwise fill the requested head blocks (capped), their votes,
/// and the mempool treasury spends, clearing the head blocks when
/// only votes were requested and reporting the over-limit build
/// failure dcrd swallows (dcrd `serverPeer.OnGetInitState`).  The
/// eligible blocks come from the ported `SortParentsByVotes`, the
/// votes from the mempool's `VoteHashesForBlock`, and the treasury
/// spends from `TSpendHashes` — all seams supplied by the caller.
pub fn on_get_init_state(
    init_state_sent: bool,
    best_height: i64,
    stake_validation_height: i64,
    wants: InitStateWants,
    eligible_blocks: &[dcroxide_chainhash::Hash],
    votes_for: impl Fn(&dcroxide_chainhash::Hash) -> Vec<dcroxide_chainhash::Hash>,
    tspends: &[dcroxide_chainhash::Hash],
) -> OnGetInitStateOutcome {
    if init_state_sent {
        return OnGetInitStateOutcome::Ban("sent more than one getinitstate".to_string());
    }

    // Send an empty init state message early in the chain.
    if best_height < stake_validation_height - 1 {
        return OnGetInitStateOutcome::Blank;
    }

    // Fetch head block hashes if either they or their votes are
    // wanted, capping the list.
    let mut block_hashes = Vec::new();
    if wants.blocks || wants.votes {
        block_hashes = eligible_blocks.to_vec();
        if block_hashes.len() > MAX_IS_BLOCKS_AT_HEAD {
            block_hashes.truncate(MAX_IS_BLOCKS_AT_HEAD);
        }
    }

    // Construct the votes for the head blocks.
    let mut vote_hashes = Vec::new();
    if wants.votes {
        for bh in &block_hashes {
            vote_hashes.extend(votes_for(bh));
        }
    }

    // Construct the treasury spends.
    let tspend_hashes = if wants.tspends {
        tspends.to_vec()
    } else {
        Vec::new()
    };

    // Clear the head blocks when they were not themselves requested.
    if !wants.blocks {
        block_hashes.clear();
    }

    // dcrd builds the message with per-list limits and logs and drops
    // the response when any is exceeded.
    if block_hashes.len() > MAX_IS_BLOCKS_AT_HEAD
        || vote_hashes.len() > MAX_IS_VOTES_AT_HEAD
        || tspend_hashes.len() > MAX_IS_TSPENDS_AT_HEAD
    {
        return OnGetInitStateOutcome::BuildError;
    }

    OnGetInitStateOutcome::Filled {
        block_hashes,
        vote_hashes,
        tspend_hashes,
    }
}

/// The maximum block hashes a mining state message carries (dcrd wire
/// `MaxMSBlocksAtHeadPerMsg`).
const MAX_MS_BLOCKS_AT_HEAD: usize = dcroxide_wire::MAX_MS_BLOCKS_AT_HEAD_PER_MSG as usize;

/// The outcome of the getminingstate handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnGetMiningStateOutcome {
    /// The peer is banned with the carried reason and disconnected:
    /// dcrd 2.2 rejects requests from peers whose protocol version
    /// makes the legacy message a knowing violation, and repeated
    /// requests on a connection (older versions ignored repeats).
    Ban(String),
    /// Send nothing: the chain is early (dcrd's blank
    /// `pushMiningStateMsg` aborts on zero blocks), there are no
    /// eligible blocks, or an eligible block has no vote metadata
    /// (dcrd warns and returns).
    Nothing,
    /// Send the mining state.
    Filled {
        /// The best height (dcrd's `uint32(best.Height)`).
        height: u32,
        /// The eligible head block hashes, capped at the message
        /// maximum.
        block_hashes: Vec<dcroxide_chainhash::Hash>,
        /// Their vote hashes — capped at `MaxMSBlocksAtHeadPerMsg`,
        /// dcrd's `pushMiningStateMsg` comparing its vote index
        /// against the BLOCK limit (kept bug for bug; the wire cap of
        /// forty is never reached).
        vote_hashes: Vec<dcroxide_chainhash::Hash>,
    },
}

/// Assemble the mining state response, the legacy sibling of the init
/// state exchange (dcrd `serverPeer.OnGetMiningState` +
/// `pushMiningStateMsg`): ignore duplicate requests on a connection,
/// send nothing early in the chain (the blank push aborts on zero
/// blocks) or when no block is eligible, and otherwise fill the capped
/// head blocks and their votes — bailing out entirely when any
/// eligible block is missing vote metadata, exactly as dcrd returns
/// without pushing.  The eligible blocks come from the ported
/// `SortParentsByVotes` and the votes from the mempool's
/// `VoteHashesForBlock`, both seams supplied by the caller.
pub fn on_get_mining_state(
    protocol_version: u32,
    mining_state_sent: bool,
    best_height: i64,
    stake_validation_height: i64,
    eligible_blocks: &[dcroxide_chainhash::Hash],
    votes_for: impl Fn(&dcroxide_chainhash::Hash) -> Vec<dcroxide_chainhash::Hash>,
) -> OnGetMiningStateOutcome {
    // Ban peers requesting the initial state via the legacy message
    // once the protocol version makes it a knowing violation, and
    // peers repeating the request (both new in dcrd 2.2).
    if protocol_version >= dcroxide_wire::INIT_STATE_VERSION {
        return OnGetMiningStateOutcome::Ban(format!(
            "sent getminings request with protocol version {protocol_version} >= {}",
            dcroxide_wire::INIT_STATE_VERSION
        ));
    }
    if mining_state_sent {
        return OnGetMiningStateOutcome::Ban("sent more than one getminings".to_string());
    }

    // Early in the chain dcrd pushes a blank state, and the push
    // aborts on an empty block list — so nothing is sent.
    if best_height < stake_validation_height - 1 {
        return OnGetMiningStateOutcome::Nothing;
    }

    // Cap the eligible list to the message maximum; nothing is sent
    // when no block is eligible.
    let mut block_hashes = eligible_blocks.to_vec();
    if block_hashes.is_empty() {
        return OnGetMiningStateOutcome::Nothing;
    }
    if block_hashes.len() > MAX_MS_BLOCKS_AT_HEAD {
        block_hashes.truncate(MAX_MS_BLOCKS_AT_HEAD);
    }

    // Construct the votes; an eligible block without vote metadata
    // aborts the whole response (dcrd warns and returns).
    let mut vote_hashes = Vec::new();
    for bh in &block_hashes {
        let vhs = votes_for(bh);
        if vhs.is_empty() {
            return OnGetMiningStateOutcome::Nothing;
        }
        vote_hashes.extend(vhs);
    }
    // dcrd's push truncates the votes against the BLOCK limit (kept
    // bug for bug).
    if vote_hashes.len() > MAX_MS_BLOCKS_AT_HEAD {
        vote_hashes.truncate(MAX_MS_BLOCKS_AT_HEAD);
    }

    OnGetMiningStateOutcome::Filled {
        height: best_height as u32,
        block_hashes,
        vote_hashes,
    }
}

#[cfg(test)]
mod mining_state_tests {
    use super::*;
    use dcroxide_chainhash::Hash;

    fn h(byte: u8) -> Hash {
        Hash([byte; 32])
    }

    /// The latch, the early-chain no-op, the empty-eligible no-op, the
    /// missing-votes bail-out, and the block and vote caps (the vote
    /// cap being dcrd's block-limit quirk).
    #[test]
    fn get_mining_state_outcomes_match_dcrd() {
        let svh = 100i64;
        let votes = |bh: &Hash| vec![Hash([bh.0[0]; 32]), Hash([bh.0[0] ^ 0xff; 32])];

        // Peers whose protocol version covers getinitstate are banned
        // for using the legacy message (dcrd 2.2).
        assert_eq!(
            on_get_mining_state(
                dcroxide_wire::INIT_STATE_VERSION,
                false,
                200,
                svh,
                &[h(1)],
                votes
            ),
            OnGetMiningStateOutcome::Ban(format!(
                "sent getminings request with protocol version {} >= {}",
                dcroxide_wire::INIT_STATE_VERSION,
                dcroxide_wire::INIT_STATE_VERSION
            ))
        );
        // Duplicate requests ban (dcrd 2.2; older versions ignored).
        assert_eq!(
            on_get_mining_state(7, true, 200, svh, &[h(1)], votes),
            OnGetMiningStateOutcome::Ban("sent more than one getminings".to_string())
        );
        // Early chain: dcrd's blank push sends nothing.
        assert_eq!(
            on_get_mining_state(7, false, svh - 2, svh, &[h(1)], votes),
            OnGetMiningStateOutcome::Nothing
        );
        // No eligible blocks: nothing.
        assert_eq!(
            on_get_mining_state(7, false, 200, svh, &[], votes),
            OnGetMiningStateOutcome::Nothing
        );
        // An eligible block without vote metadata aborts the response.
        assert_eq!(
            on_get_mining_state(7, false, 200, svh, &[h(1), h(2)], |bh: &Hash| {
                if bh.0[0] == 2 {
                    Vec::new()
                } else {
                    vec![h(0xaa)]
                }
            }),
            OnGetMiningStateOutcome::Nothing
        );

        // Blocks cap at eight, and the votes cap at the BLOCK limit
        // (dcrd's pushMiningStateMsg quirk): nine eligible blocks with
        // two votes each fill eight blocks and eight (not sixteen or
        // forty) votes.
        let blocks: Vec<Hash> = (1..=9).map(h).collect();
        match on_get_mining_state(7, false, 200, svh, &blocks, votes) {
            OnGetMiningStateOutcome::Filled {
                height,
                block_hashes,
                vote_hashes,
            } => {
                assert_eq!(height, 200);
                assert_eq!(block_hashes.len(), 8, "blocks cap at the message max");
                assert_eq!(block_hashes[0], h(1), "order preserved");
                assert_eq!(vote_hashes.len(), 8, "votes cap at the BLOCK limit");
            }
            other => panic!("expected filled, got {other:?}"),
        }
    }
}
