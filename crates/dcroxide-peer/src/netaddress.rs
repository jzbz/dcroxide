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
            let port = parse_port(&port_str)?;
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

/// Parse a port like Go's `strconv.ParseUint(s, 10, 16)`, with its
/// error text.
///
/// Go checks the bytes as it accumulates them, left to right, so the
/// first digit that takes the value past 65535 is a range error even
/// when an invalid byte follows it: `"99999x"` is out of range, where
/// `"6553x"` is invalid syntax.  Checking every byte for syntax first
/// got the former wrong.  The input is quoted as Go's `NumError` quotes
/// it ([`go_quote`]).
pub(crate) fn parse_port(s: &str) -> Result<u16, String> {
    let err = |why: &str| format!("strconv.ParseUint: parsing {}: {why}", go_quote(s));
    if s.is_empty() {
        return Err(err("invalid syntax"));
    }
    let mut n: u32 = 0;
    for c in s.bytes() {
        if !c.is_ascii_digit() {
            return Err(err("invalid syntax"));
        }
        // `c` is a digit and `n` at most 65535 here, so nothing wraps or
        // saturates.
        n = n
            .saturating_mul(10)
            .saturating_add(u32::from(c.wrapping_sub(b'0')));
        if n > u32::from(u16::MAX) {
            return Err(err("value out of range"));
        }
    }
    u16::try_from(n).map_err(|_| err("value out of range"))
}

/// Go's `strconv.Quote` for a valid UTF-8 string, as `NumError.Error`
/// renders the text it failed to parse.
///
/// Exact below U+0100, where Go's `IsPrint` is a range check: printable
/// ASCII and U+00A1..=U+00FF but the soft hyphen are kept, `"` and `\`
/// are backslashed, the seven C escapes are named, the other ASCII
/// controls and DEL are `\xNN`, and the rest are `\u00NN`.  Beyond it Go
/// keeps a rune only when its Unicode tables call it printable; this
/// escapes the control and space characters and keeps the rest, so a
/// format, private-use or unassigned rune is kept where Go writes a
/// `\u` escape.  Only a caller's own address string reaches this, never
/// the daemon's.
fn go_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len().saturating_add(2));
    out.push('"');
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            ' '..='~' | '\u{a1}'..='\u{ac}' | '\u{ae}'..='\u{ff}' => out.push(c),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            '\0'..='\u{1f}' | '\u{7f}' => out.push_str(&format!("\\x{:02x}", u32::from(c))),
            '\u{80}'..='\u{a0}' | '\u{ad}' => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            _ if c.is_control() || c.is_whitespace() => {
                if u32::from(c) < 0x1_0000 {
                    out.push_str(&format!("\\u{:04x}", u32::from(c)));
                } else {
                    out.push_str(&format!("\\U{:08x}", u32::from(c)));
                }
            }
            _ => out.push(c),
        }
    }
    out.push('"');
    out
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

    /// Go's `strconv.ParseUint(s, 10, 16)`, over the order of its checks:
    /// a digit that overflows is reported before a bad byte after it.
    #[test]
    fn parse_port_matches_go_parse_uint() {
        for (input, want) in [
            ("0", Ok(0)),
            ("8333", Ok(8333)),
            ("065535", Ok(65535)),
            ("65535", Ok(65535)),
            ("65536", Err("value out of range")),
            ("99999x", Err("value out of range")),
            ("65536a", Err("value out of range")),
            ("6553x", Err("invalid syntax")),
            ("x", Err("invalid syntax")),
            ("+1", Err("invalid syntax")),
            ("1_0", Err("invalid syntax")),
            ("", Err("invalid syntax")),
        ] {
            let want = want.map_err(|why| format!("strconv.ParseUint: parsing \"{input}\": {why}"));
            assert_eq!(parse_port(input), want, "{input}");
        }
        // `NumError` quotes the input with `strconv.Quote`.
        for (input, quoted) in [
            ("8\"3", r#""8\"3""#),
            ("8\\3", r#""8\\3""#),
            ("8\t3", r#""8\t3""#),
            ("8\u{1}3", r#""8\x013""#),
            ("8\u{7f}3", r#""8\x7f3""#),
            ("8\u{85}3", r#""8\u00853""#),
            ("8\u{a0}3", "\"8\\u00a03\""),
            ("8\u{ad}3", "\"8\\u00ad3\""),
            ("8\u{e9}3", "\"8\u{e9}3\""),
            ("8\u{3000}3", "\"8\\u30003\""),
            ("8\u{4e2d}3", "\"8\u{4e2d}3\""),
        ] {
            assert_eq!(
                parse_port(input),
                Err(format!(
                    "strconv.ParseUint: parsing {quoted}: invalid syntax"
                )),
                "{input:?}"
            );
        }
        assert_eq!(
            new_net_address(
                &PeerAddr::Other {
                    addr: "1.2.3.4:99999x".to_string()
                },
                ServiceFlag(0)
            ),
            Err("strconv.ParseUint: parsing \"99999x\": value out of range".to_string())
        );
        assert_eq!(
            crate::Peer::new_outbound(crate::Config::default(), "1.2.3.4:99999x").err(),
            Some("strconv.ParseUint: parsing \"99999x\": value out of range".to_string())
        );
    }

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
