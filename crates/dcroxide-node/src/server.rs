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
