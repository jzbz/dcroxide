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
    const MISSING_PORT: &str = "missing port in address";
    const TOO_MANY_COLONS: &str = "too many colons in address";
    // `AddrError.Error` prefixes the address unless it is empty.
    let addr_err = |why: &str| -> Result<(String, String), String> {
        if hostport.is_empty() {
            Err(why.to_string())
        } else {
            Err(format!("address {hostport}: {why}"))
        }
    };
    let b = hostport.as_bytes();
    let (mut j, mut k) = (0, 0);

    // The port starts after the last colon.
    let Some(i) = hostport.rfind(':') else {
        return addr_err(MISSING_PORT);
    };

    let host;
    if b[0] == b'[' {
        // Expect the first ']' just before the last ':'.
        let Some(end) = hostport.find(']') else {
            return addr_err("missing ']' in address");
        };
        match end.saturating_add(1) {
            // There can't be a ':' behind the ']' now.
            n if n == b.len() => return addr_err(MISSING_PORT),
            // The expected result.
            n if n == i => {}
            // Either ']' isn't followed by a colon, or it is followed
            // by a colon that is not the last one.
            n if b[n] == b':' => return addr_err(TOO_MANY_COLONS),
            _ => return addr_err(MISSING_PORT),
        }
        host = &hostport[1..end];
        // There can't be a '[' resp. ']' before these positions.
        (j, k) = (1, end.saturating_add(1));
    } else {
        host = &hostport[..i];
        if host.contains(':') {
            return addr_err(TOO_MANY_COLONS);
        }
    }
    if hostport[j..].contains('[') {
        return addr_err("unexpected '[' in address");
    }
    if hostport[k..].contains(']') {
        return addr_err("unexpected ']' in address");
    }

    Ok((
        host.to_string(),
        hostport[i.saturating_add(1)..].to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `split_host_port` matches Go's `net.SplitHostPort`, reporting a
    /// missing port (never panicking) when a bracketed host is followed
    /// by a trailing character — including a multibyte one.
    #[test]
    fn split_host_port_matches_go() {
        assert_eq!(
            split_host_port("[::1]:80").unwrap(),
            ("::1".to_string(), "80".to_string())
        );
        for missing in ["[::1]", "[::1]x", "[::1]\u{20ac}"] {
            assert_eq!(
                split_host_port(missing).unwrap_err(),
                format!("address {missing}: missing port in address"),
                "{missing}"
            );
        }
        assert_eq!(
            split_host_port("[::1]::80").unwrap_err(),
            "address [::1]::80: too many colons in address"
        );
    }

    /// The bracket checks run over the whole address, as Go's
    /// `SplitHostPort` does after its bracket switch, and each stray
    /// bracket and the empty address get Go's own text.
    #[test]
    fn split_host_port_rejects_stray_brackets() {
        for (input, want) in [
            ("[a[b]:80", "address [a[b]:80: unexpected '[' in address"),
            ("[::1]:80]", "address [::1]:80]: unexpected ']' in address"),
            ("[abc", "address [abc: missing port in address"),
            ("a]:80", "address a]:80: unexpected ']' in address"),
            ("a[b:80", "address a[b:80: unexpected '[' in address"),
            ("[a]b]:80", "address [a]b]:80: missing port in address"),
            ("", "missing port in address"),
        ] {
            assert_eq!(split_host_port(input).unwrap_err(), want, "{input}");
        }
        assert_eq!(
            split_host_port("[]:80").unwrap(),
            (String::new(), "80".to_string())
        );
    }
}
