// SPDX-License-Identifier: ISC
//! What dcrd's `initListeners` (`server.go`) does with the peer-to-peer
//! listeners once they are bound: the bound-address rendering its
//! `--boundaddrevents` pipe messages carry, and the registration of the
//! node's own addresses with the address manager, so the handshake can
//! advertise one to outbound peers (`GetBestLocalAddress`) and
//! `getnetworkinfo` can list them (`LocalAddresses`).
//!
//! Every `--externalip` is added at manual priority; without one, each
//! bound listener is added at bound priority through `addLocalAddress`,
//! which expands an unspecified bind to the host's interface addresses
//! of the same family.

use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;

use dcroxide_addrmgr::{AddrManager, AddressPriority, new_net_address_from_ip_port};
use dcroxide_wire::ServiceFlag;

use crate::gostd::split_host_port;
use crate::outbound::go_parse_uint16;
use crate::server::{ResolveIpFn, host_to_net_address};

/// Render a bound TCP address the way Go's `net.TCPAddr.String` does
/// (`listener.Addr().String()`): `JoinHostPort` over `IP.String`, which
/// prints an IPv4-mapped IPv6 address in dotted IPv4 form, unbracketed.
/// A zoned link-local address keeps Rust's numeric scope where Go would
/// print the interface name.
pub fn go_tcp_addr_string(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V6(v6) if v6.scope_id() == 0 => match v6.ip().to_ipv4_mapped() {
            Some(v4) => format!("{v4}:{}", v6.port()),
            None => format!("[{}]:{}", v6.ip(), v6.port()),
        },
        other => other.to_string(),
    }
}

/// Whether Go's `IP.To4` is non-nil: an IPv4 address or the
/// IPv4-mapped IPv6 form of one.
fn is_ipv4_like(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => true,
        IpAddr::V6(v6) => v6.to_ipv4_mapped().is_some(),
    }
}

/// The raw address bytes Go's `net.IP` would carry.
fn ip_bytes(ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

/// The address manager, locked only around each addition: a host name
/// resolves outside it, as dcrd's `hostToNetAddress` runs outside the
/// manager's local-address mutex.
fn lock(amgr: &Mutex<AddrManager>) -> std::sync::MutexGuard<'_, AddrManager> {
    amgr.lock().expect("addrmgr mutex poisoned")
}

/// Add an address this node is listening on to the address manager so
/// it may be relayed to peers (dcrd `addLocalAddress`).  A bind to the
/// unspecified address advertises every interface address of the same
/// family instead; the address manager's own refusals (an unroutable
/// address) are ignored, as dcrd ignores them.
fn add_local_address(
    amgr: &Mutex<AddrManager>,
    addr: &str,
    services: ServiceFlag,
    resolver: &ResolveIpFn<'_>,
    interface_addrs: &dyn Fn() -> Result<Vec<String>, String>,
    now_unix: i64,
) -> Result<(), String> {
    let (host, port_str) = split_host_port(addr)?;
    let port = go_parse_uint16(&port_str)?;

    if let Some(ip) = host.parse::<IpAddr>().ok().filter(IpAddr::is_unspecified) {
        // If bound to unspecified address, advertise all local interfaces.
        for iface in interface_addrs()? {
            // Go's `net.ParseCIDR`: an address and a prefix length.
            let Some((iface_ip, prefix)) = iface.split_once('/') else {
                continue;
            };
            let Ok(iface_ip) = iface_ip.parse::<IpAddr>() else {
                continue;
            };
            if prefix.parse::<u8>().is_err() {
                continue;
            }

            // If bound to 0.0.0.0, do not add IPv6 interfaces and if
            // bound to ::, do not add IPv4 interfaces.
            if is_ipv4_like(&ip) != is_ipv4_like(&iface_ip) {
                continue;
            }

            // dcrd's `NewNetAddressFromIPPort` stamps `time.Now()` to the
            // second; the address manager keeps Unix nanoseconds.
            let net_addr = new_net_address_from_ip_port(
                &ip_bytes(&iface_ip),
                port,
                services,
                now_unix.saturating_mul(1_000_000_000),
            );
            let _ = lock(amgr).add_local_address(&net_addr, AddressPriority::Bound);
        }
    } else {
        let net_addr = host_to_net_address(&host, port, services, resolver, now_unix)?;
        let _ = lock(amgr).add_local_address(&net_addr, AddressPriority::Bound);
    }

    Ok(())
}

/// Register the node's own addresses with the address manager once the
/// peer-to-peer listeners are bound (the tail of dcrd's
/// `initListeners`): every `--externalip` at manual priority, its port
/// defaulting to the network's, or, when none is configured, every
/// bound listener (`bound`, rendered by [`go_tcp_addr_string`]) at bound
/// priority.  Each address that cannot be added is logged and skipped,
/// with dcrd's texts and subsystems; the only error returned is an
/// unparsable default port, which fails dcrd's server construction.
// The seams are dcrd's: the listener addresses, its lookup, the
// interface enumeration and the clock.
#[allow(clippy::too_many_arguments)]
pub fn add_listener_local_addresses(
    amgr: &Mutex<AddrManager>,
    external_ips: &[String],
    default_port: &str,
    bound: &[String],
    services: ServiceFlag,
    resolver: &ResolveIpFn<'_>,
    interface_addrs: &dyn Fn() -> Result<Vec<String>, String>,
    now_unix: i64,
) -> Result<(), String> {
    if !external_ips.is_empty() {
        let default_port = go_parse_uint16(default_port).map_err(|e| {
            crate::logging::error(
                "SRVR",
                &format!("Can not parse default port {default_port} for active chain: {e}"),
            );
            e
        })?;

        for sip in external_ips {
            let mut eport = default_port;
            let host = match split_host_port(sip) {
                // No port, use default.
                Err(_) => sip.clone(),
                Ok((host, port_str)) => match go_parse_uint16(&port_str) {
                    Ok(port) => {
                        eport = port;
                        host
                    }
                    Err(e) => {
                        crate::logging::warn(
                            "SRVR",
                            &format!("Can not parse port from {sip} for externalip: {e}"),
                        );
                        continue;
                    }
                },
            };

            let na = match host_to_net_address(&host, eport, services, resolver, now_unix) {
                Ok(na) => na,
                Err(e) => {
                    crate::logging::warn("SRVR", &format!("Not adding {sip} as externalip: {e}"));
                    continue;
                }
            };

            if let Err(e) = lock(amgr).add_local_address(&na, AddressPriority::Manual) {
                crate::logging::warn("AMGR", &format!("Skipping specified external IP: {e}"));
            }
        }
    } else {
        // Add bound addresses to address manager to be advertised to
        // peers.
        for addr in bound {
            if let Err(e) =
                add_local_address(amgr, addr, services, resolver, interface_addrs, now_unix)
            {
                crate::logging::warn("AMGR", &format!("Skipping bound address {addr}: {e}"));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcroxide_addrmgr::NetAddress;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV6};

    fn manager() -> (tempfile::TempDir, Mutex<AddrManager>) {
        let dir = tempfile::tempdir().expect("temp dir");
        let amgr = AddrManager::new(dir.path());
        (dir, Mutex::new(amgr))
    }

    /// The local addresses as `host:port` strings, sorted.
    fn locals(amgr: &Mutex<AddrManager>) -> Vec<String> {
        let mut out: Vec<String> = lock(amgr)
            .local_addresses()
            .into_iter()
            .map(|la| format!("{}:{}", la.address, la.port))
            .collect();
        out.sort();
        out
    }

    fn no_lookup(host: &str) -> Result<Vec<IpAddr>, String> {
        Err(format!("lookup {host}: no such host"))
    }

    #[test]
    fn bound_addresses_render_as_go_prints_them() {
        let v4: SocketAddr = "0.0.0.0:9108".parse().expect("v4");
        assert_eq!(go_tcp_addr_string(&v4), "0.0.0.0:9108");
        let v6: SocketAddr = "[::]:9108".parse().expect("v6");
        assert_eq!(go_tcp_addr_string(&v6), "[::]:9108");
        // Go's IP.String prints the mapped form as IPv4.
        let mapped = SocketAddr::V6(SocketAddrV6::new(
            Ipv4Addr::new(1, 2, 3, 4).to_ipv6_mapped(),
            9108,
            0,
            0,
        ));
        assert_eq!(go_tcp_addr_string(&mapped), "1.2.3.4:9108");
    }

    /// Each `--externalip` is advertised, its port defaulting to the
    /// network's, and one that cannot be parsed or is not routable is
    /// skipped -- while the bound listeners are ignored, as dcrd's
    /// `else` branch only runs without an external address.
    #[test]
    fn external_ips_are_added_at_manual_priority() {
        let (_dir, amgr) = manager();
        let external = vec![
            "1.2.3.4".to_string(),
            "5.6.7.8:18555".to_string(),
            "[2001:4860::8888]:9000".to_string(),
            "9.9.9.9:notaport".to_string(),
            "192.168.1.10".to_string(),
        ];
        add_listener_local_addresses(
            &amgr,
            &external,
            "9108",
            &["8.8.8.8:9108".to_string()],
            ServiceFlag::NODE_NETWORK,
            &no_lookup,
            &|| Ok(Vec::new()),
            0,
        )
        .expect("register");
        assert_eq!(
            locals(&amgr),
            vec![
                "1.2.3.4:9108".to_string(),
                "2001:4860::8888:9000".to_string(),
                "5.6.7.8:18555".to_string(),
            ]
        );
    }

    /// Without `--externalip`, a specific bind is advertised as is and
    /// an unspecified one expands to the routable interface addresses of
    /// its own family only.
    #[test]
    fn bound_listeners_are_added_at_bound_priority() {
        let (_dir, amgr) = manager();
        let interfaces = || {
            Ok(vec![
                "127.0.0.1/32".to_string(),
                "203.0.113.9/24".to_string(),
                "11.22.33.44/32".to_string(),
                "2001:4860::1/64".to_string(),
                "fe80::1/64".to_string(),
                "not-an-address".to_string(),
            ])
        };
        add_listener_local_addresses(
            &amgr,
            &[],
            "9108",
            &["0.0.0.0:9108".to_string(), "8.8.4.4:9109".to_string()],
            ServiceFlag::NODE_NETWORK,
            &no_lookup,
            &interfaces,
            0,
        )
        .expect("register");
        assert_eq!(
            locals(&amgr),
            vec!["11.22.33.44:9108".to_string(), "8.8.4.4:9109".to_string()]
        );

        let (_dir, amgr) = manager();
        add_listener_local_addresses(
            &amgr,
            &[],
            "9108",
            &[go_tcp_addr_string(&SocketAddr::new(
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                9108,
            ))],
            ServiceFlag::NODE_NETWORK,
            &no_lookup,
            &interfaces,
            0,
        )
        .expect("register");
        assert_eq!(locals(&amgr), vec!["2001:4860::1:9108".to_string()]);
    }

    /// The address the handshake would advertise to an IPv4 peer, as
    /// stored and as its wire `addr` and `addrv2` timestamps.
    fn advertised(amgr: &Mutex<AddrManager>) -> (NetAddress, u32, u64) {
        let remote =
            new_net_address_from_ip_port(&[8, 8, 8, 8], 9108, ServiceFlag::NODE_NETWORK, 0);
        let best = lock(amgr).get_best_local_address(&remote, |_| true);
        let v1 = crate::server::addrmgr_to_wire_net_address(&best).timestamp;
        let v2 = crate::server::addrmgr_to_wire_net_address_v2(&best).timestamp;
        (best, v1, v2)
    }

    /// Every registered address carries the startup time, as dcrd's
    /// `NewNetAddressFromIPPort` and `hostToNetAddress` stamp
    /// `time.Now()`: an interface address an unspecified bind expands
    /// to, and an `--externalip` host name the resolver answers.  A
    /// 1970 stamp would make every receiving node treat the
    /// advertisement as over a month old.
    #[test]
    fn registered_addresses_carry_the_clock() {
        const NOW_UNIX: i64 = 1_758_800_000;

        let (_dir, amgr) = manager();
        add_listener_local_addresses(
            &amgr,
            &[],
            "9108",
            &["0.0.0.0:9108".to_string()],
            ServiceFlag::NODE_NETWORK,
            &no_lookup,
            &|| Ok(vec!["11.22.33.44/32".to_string()]),
            NOW_UNIX,
        )
        .expect("register");
        let (best, v1, v2) = advertised(&amgr);
        assert_eq!(best.key(), "11.22.33.44:9108");
        assert_eq!(best.timestamp, NOW_UNIX * 1_000_000_000);
        assert_eq!(i64::from(v1), NOW_UNIX);
        assert_eq!(v2, NOW_UNIX as u64);

        let (_dir, amgr) = manager();
        let resolver = |host: &str| -> Result<Vec<IpAddr>, String> {
            match host {
                "node.example.com" => Ok(vec!["5.6.7.8".parse().expect("literal IP")]),
                _ => no_lookup(host),
            }
        };
        add_listener_local_addresses(
            &amgr,
            &["node.example.com".to_string()],
            "9108",
            &[],
            ServiceFlag::NODE_NETWORK,
            &resolver,
            &|| Ok(Vec::new()),
            NOW_UNIX,
        )
        .expect("register");
        let (best, v1, v2) = advertised(&amgr);
        assert_eq!(best.key(), "5.6.7.8:9108");
        assert_eq!(best.timestamp, NOW_UNIX * 1_000_000_000);
        assert_eq!(i64::from(v1), NOW_UNIX);
        assert_eq!(v2, NOW_UNIX as u64);
    }

    /// The `--externalip` port warning carries Go's `NumError` text,
    /// and Go's `ParseUint` scans left to right: a port that overflows
    /// before a stray byte is out of range, not invalid syntax.
    #[test]
    fn ports_parse_as_go_base_ten() {
        assert_eq!(go_parse_uint16("9108"), Ok(9108));
        assert_eq!(
            go_parse_uint16("99999x"),
            Err(r#"strconv.ParseUint: parsing "99999x": value out of range"#.to_string())
        );
        assert_eq!(
            go_parse_uint16("+9108"),
            Err(r#"strconv.ParseUint: parsing "+9108": invalid syntax"#.to_string())
        );
        assert_eq!(
            go_parse_uint16("0x10"),
            Err(r#"strconv.ParseUint: parsing "0x10": invalid syntax"#.to_string())
        );
        assert_eq!(
            go_parse_uint16("65536"),
            Err(r#"strconv.ParseUint: parsing "65536": value out of range"#.to_string())
        );
    }
}
