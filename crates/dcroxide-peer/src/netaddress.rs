// SPDX-License-Identifier: ISC
//! Conversion of connection addresses to wire network addresses
//! (dcrd peer `newNetAddress`).

use dcroxide_wire::{NetAddress, ServiceFlag};

/// The kinds of connection address dcrd's peer sees: a TCP address, a
/// SOCKS-proxied address, or an arbitrary `net.Addr` whose string
/// form is parsed as a last resort.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerAddr {
    /// A `net.TCPAddr`: raw IP bytes (4 or 16) and port.
    Tcp {
        /// The IP bytes.
        ip: Vec<u8>,
        /// The port.
        port: u16,
    },
    /// A `socks.ProxiedAddr`: a host name that may or may not be an
    /// IP literal, and a port.
    Proxied {
        /// The host.
        host: String,
        /// The port.
        port: u16,
    },
    /// Any other address, carried as its `String()` form.
    Other {
        /// The address string, expected to be host:port.
        addr: String,
    },
}

/// Parse an IP like Go's `net.ParseIP`, normalized to the 16-byte
/// form; `None` mirrors a nil `net.IP`.
fn parse_ip(host: &str) -> Option<[u8; 16]> {
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => Some(map_v4(&v4.octets())),
        Ok(std::net::IpAddr::V6(v6)) => Some(v6.octets()),
        Err(_) => None,
    }
}

fn map_v4(octets: &[u8; 4]) -> [u8; 16] {
    let mut ip = [0u8; 16];
    ip[10] = 0xff;
    ip[11] = 0xff;
    ip[12..16].copy_from_slice(octets);
    ip
}

/// Normalize raw IP bytes to the wire 16-byte form (Go
/// `NewNetAddressIPPort` stores `ip.To16()`; nil stays all zero).
fn to16(ip: &[u8]) -> [u8; 16] {
    match ip.len() {
        4 => map_v4(&[ip[0], ip[1], ip[2], ip[3]]),
        16 => {
            let mut out = [0u8; 16];
            out.copy_from_slice(ip);
            out
        }
        _ => [0u8; 16],
    }
}

/// Create a wire network address from a connection address (dcrd
/// `newNetAddress`), mirroring the TCP, proxied, and string-parse
/// fallback branches.
pub fn new_net_address(addr: &PeerAddr, services: ServiceFlag) -> Result<NetAddress, String> {
    match addr {
        PeerAddr::Tcp { ip, port } => Ok(NetAddress {
            timestamp: 0,
            services,
            ip: to16(ip),
            port: *port,
        }),
        PeerAddr::Proxied { host, port } => {
            // An unparseable proxied host falls back to 0.0.0.0.
            let ip = parse_ip(host).unwrap_or_else(|| map_v4(&[0, 0, 0, 0]));
            Ok(NetAddress {
                timestamp: 0,
                services,
                ip,
                port: *port,
            })
        }
        PeerAddr::Other { addr } => {
            let (host, port_str) = split_host_port(addr)?;
            let port: u16 = if port_str.is_empty() || !port_str.bytes().all(|c| c.is_ascii_digit())
            {
                return Err(format!(
                    "strconv.ParseUint: parsing \"{port_str}\": invalid syntax"
                ));
            } else {
                port_str.parse().map_err(|_| {
                    format!("strconv.ParseUint: parsing \"{port_str}\": value out of range")
                })?
            };
            // A nil parsed IP stays the zero address.
            let ip = parse_ip(&host).unwrap_or([0u8; 16]);
            Ok(NetAddress {
                timestamp: 0,
                services,
                ip,
                port,
            })
        }
    }
}

/// Split host and port like Go's `net.SplitHostPort`, with dcrd's
/// observable error text.
pub(crate) fn split_host_port(hostport: &str) -> Result<(String, String), String> {
    let missing_port = || format!("address {hostport}: missing port in address");
    let too_many_colons = || format!("address {hostport}: too many colons in address");
    if let Some(stripped) = hostport.strip_prefix('[') {
        let Some(end) = stripped.find(']') else {
            return Err(format!("address {hostport}: missing ']' in address"));
        };
        let host = &stripped[..end];
        let rest = &stripped[end.saturating_add(1)..];
        let Some(port) = rest.strip_prefix(':') else {
            if rest.is_empty() {
                return Err(missing_port());
            }
            return Err(format!(
                "address {hostport}: unexpected '{}' after address",
                &rest[..1]
            ));
        };
        if port.contains(':') {
            return Err(too_many_colons());
        }
        return Ok((host.to_string(), port.to_string()));
    }
    let Some(colon) = hostport.rfind(':') else {
        return Err(missing_port());
    };
    let host = &hostport[..colon];
    let port = &hostport[colon.saturating_add(1)..];
    if host.contains(':') {
        return Err(too_many_colons());
    }
    if hostport.contains('[') || hostport.contains(']') {
        return Err(format!("address {hostport}: unexpected '[' in address"));
    }
    Ok((host.to_string(), port.to_string()))
}
