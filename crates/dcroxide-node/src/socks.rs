// SPDX-License-Identifier: ISC
//! The SOCKS5 proxy dial and the Tor DNS resolution the daemon's
//! --proxy/--onion wiring uses: a port of `decred/go-socks`'s
//! `Proxy.DialContext` (version 5 only — the greeting with optional
//! RFC 1929 username/password authentication, the TCP CONNECT
//! command over a domain address, the reply status table, and Tor
//! isolation drawing random credentials per connection) and of dcrd
//! `connmgr.TorLookupIP` (Tor's SOCKS RESOLVE extension with its own
//! error table).
//!
//! go-socks wraps the stream in a `proxiedConn` that reports the
//! proxy's bound address; the daemon's peer runtime keys everything
//! on the dialed address, so the port returns the raw stream and the
//! bound address is read and discarded.

// The handshake mirrors Go's bounded buffer arithmetic.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// A SOCKS5 proxy client (go-socks `socks.Proxy`).
#[derive(Clone, Debug, Default)]
pub struct Proxy {
    /// The proxy address (host:port).
    pub addr: String,
    /// The RFC 1929 username, when authenticating.
    pub username: String,
    /// The RFC 1929 password, when authenticating.
    pub password: String,
    /// Draw random credentials per connection so Tor isolates the
    /// circuits (go-socks `TorIsolation`).
    pub tor_isolation: bool,
}

const PROTOCOL_VERSION: u8 = 5;
const AUTH_NONE: u8 = 0;
const AUTH_GSSAPI: u8 = 1;
const AUTH_USERNAME_PASSWORD: u8 = 2;
const AUTH_UNAVAILABLE: u8 = 0xff;
const COMMAND_TCP_CONNECT: u8 = 1;
const ADDRESS_TYPE_IPV4: u8 = 1;
const ADDRESS_TYPE_DOMAIN: u8 = 3;
const ADDRESS_TYPE_IPV6: u8 = 4;

/// go-socks' reply status error texts.
fn status_error(status: u8) -> Option<&'static str> {
    Some(match status {
        1 => "general failure",
        2 => "connection not allowed by ruleset",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused by destination host",
        6 => "TTL expired",
        7 => "command not supported / protocol error",
        8 => "address type not supported",
        _ => return None,
    })
}

const ERR_INVALID_PROXY_RESPONSE: &str = "invalid proxy response";
const ERR_NO_ACCEPTABLE_AUTH: &str = "no acceptable authentication method";
const ERR_AUTH_FAILED: &str = "authentication failed";

/// The instant the exchange must be finished by.
///
/// go-socks takes the context deadline once, applies it to the
/// connection as an absolute instant (`dial.go:115-117`), and clears
/// it before handing the connection back (`:271`), so every read and
/// write of the handshake shares one budget.  Rust's socket timeouts
/// are per-operation instead: arming each one with the full dial
/// timeout would let a proxy that answers just inside it stretch the
/// exchange to that timeout *per operation*.  Carrying the deadline
/// and arming each operation with what is left of it restores the
/// single budget.
#[derive(Clone, Copy)]
struct Deadline(Instant);

impl Deadline {
    fn after(timeout: Duration) -> Self {
        Deadline(Instant::now() + timeout)
    }

    /// Arm both socket timeouts with the remaining budget, or report
    /// Go's timeout text once it is spent.  A zero `Duration` means
    /// "no timeout" to the socket API, so an expired deadline has to
    /// be caught here rather than passed down.
    fn arm(&self, conn: &TcpStream) -> Result<(), String> {
        let left = self.0.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("i/o timeout".to_string());
        }
        conn.set_read_timeout(Some(left))
            .map_err(|e| e.to_string())?;
        conn.set_write_timeout(Some(left))
            .map_err(|e| e.to_string())
    }
}

/// Fill `buf` within the deadline (Go `io.ReadFull` over a connection
/// carrying one): re-armed per syscall, because a peer trickling a
/// byte at a time would otherwise restart a per-operation timeout on
/// every one of them.  Go's zero-bytes/partial split is preserved.
fn read_full(conn: &mut TcpStream, buf: &mut [u8], deadline: Deadline) -> Result<(), String> {
    let mut filled = 0;
    while filled < buf.len() {
        deadline.arm(conn)?;
        match conn.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(if filled == 0 { "EOF" } else { "unexpected EOF" }.to_string());
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

/// Write all of `buf` within the deadline, re-armed per syscall for
/// the same reason as `read_full`.
fn write_full(conn: &mut TcpStream, buf: &[u8], deadline: Deadline) -> Result<(), String> {
    let mut written = 0;
    while written < buf.len() {
        deadline.arm(conn)?;
        match conn.write(&buf[written..]) {
            Ok(0) => return Err("write: connection closed".to_string()),
            Ok(n) => written += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

/// Connect to a `host:port` proxy address like Go's `net.Dialer`:
/// resolve the name (a hostname proxy such as Tor's default
/// `localhost:9050` is common) and connect to the resolved addresses
/// in order until one succeeds.
fn connect_proxy(addr: &str, deadline: Deadline) -> Result<TcpStream, String> {
    use std::net::ToSocketAddrs;
    let resolved: Vec<std::net::SocketAddr> = addr
        .to_socket_addrs()
        .map_err(|e| format!("invalid proxy address {addr}: {e}"))?
        .collect();
    let mut last_err = format!("no addresses found for proxy {addr}");
    for socket in resolved {
        // Go's dialer draws each attempt's timeout from the same
        // deadline, so a name resolving to several addresses cannot
        // spend the budget more than once.
        let left = deadline.0.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("i/o timeout".to_string());
        }
        match TcpStream::connect_timeout(&socket, left) {
            Ok(conn) => return Ok(conn),
            Err(e) => last_err = e.to_string(),
        }
    }
    Err(last_err)
}

impl Proxy {
    /// Connect to `addr` (host:port) through the proxy (go-socks
    /// `Proxy.DialContext`).  `timeout` is the whole exchange's
    /// budget, connect included, the way the context deadline dcrd
    /// passes is (`connmgr/connmanager.go:902`).
    pub fn dial(&self, addr: &str, timeout: Duration) -> Result<TcpStream, String> {
        let (host, port_str) = crate::gostd::split_host_port(addr)?;
        let port: u16 = port_str
            .parse::<u16>()
            .map_err(|e| format!("strconv.Atoi: parsing \"{port_str}\": {e}"))?;

        // The deadline is taken before the connect, because Go's is:
        // `dialer.DialContext` and the handshake that follows share
        // the one the caller's context carries.
        let deadline = Deadline::after(timeout);
        let mut conn = connect_proxy(&self.addr, deadline)?;

        // Tor isolation overrides the credentials with random ones.
        let (user, pass) = if self.tor_isolation {
            let mut b = [0u8; 16];
            getrandom::fill(&mut b).map_err(|e| e.to_string())?;
            (hex(&b[0..8]), hex(&b[8..16]))
        } else {
            (self.username.clone(), self.password.clone())
        };

        // Initial greeting: authNone always, plus username/password
        // when credentials are present.
        let greeting: Vec<u8> = if user.is_empty() {
            vec![PROTOCOL_VERSION, 1, AUTH_NONE]
        } else {
            vec![PROTOCOL_VERSION, 2, AUTH_NONE, AUTH_USERNAME_PASSWORD]
        };
        write_full(&mut conn, &greeting, deadline)?;

        // The server's auth choice.
        let mut reply = [0u8; 2];
        read_full(&mut conn, &mut reply, deadline)?;
        if reply[0] != PROTOCOL_VERSION {
            return Err(ERR_INVALID_PROXY_RESPONSE.to_string());
        }
        match reply[1] {
            AUTH_NONE => {}
            AUTH_USERNAME_PASSWORD => {
                // RFC 1929 sub-negotiation.
                let mut auth = Vec::with_capacity(3 + user.len() + pass.len());
                auth.push(1);
                auth.push(user.len() as u8);
                auth.extend_from_slice(user.as_bytes());
                auth.push(pass.len() as u8);
                auth.extend_from_slice(pass.as_bytes());
                write_full(&mut conn, &auth, deadline)?;
                let mut status = [0u8; 2];
                read_full(&mut conn, &mut status, deadline)?;
                if status[0] != 1 {
                    return Err(ERR_INVALID_PROXY_RESPONSE.to_string());
                }
                if status[1] != 0 {
                    return Err(ERR_AUTH_FAILED.to_string());
                }
            }
            AUTH_UNAVAILABLE | AUTH_GSSAPI => {
                return Err(ERR_NO_ACCEPTABLE_AUTH.to_string());
            }
            _ => return Err(ERR_INVALID_PROXY_RESPONSE.to_string()),
        }

        // The connect command, always over a domain address like
        // go-socks (the proxy resolves the name).
        let mut request = Vec::with_capacity(7 + host.len());
        request.push(PROTOCOL_VERSION);
        request.push(COMMAND_TCP_CONNECT);
        request.push(0); // reserved
        request.push(ADDRESS_TYPE_DOMAIN);
        request.push(host.len() as u8);
        request.extend_from_slice(host.as_bytes());
        request.push((port >> 8) as u8);
        request.push((port & 0xff) as u8);
        write_full(&mut conn, &request, deadline)?;

        // The reply header, then the bound address it describes (read
        // and discarded; the runtime keys the peer on the dialed
        // address).
        let mut header = [0u8; 4];
        read_full(&mut conn, &mut header, deadline)?;
        if header[0] != PROTOCOL_VERSION {
            return Err(ERR_INVALID_PROXY_RESPONSE.to_string());
        }
        if header[1] != 0 {
            return Err(status_error(header[1])
                .unwrap_or(ERR_INVALID_PROXY_RESPONSE)
                .to_string());
        }
        match header[3] {
            ADDRESS_TYPE_IPV4 => {
                let mut bound = [0u8; 4];
                read_full(&mut conn, &mut bound, deadline)?;
            }
            ADDRESS_TYPE_IPV6 => {
                let mut bound = [0u8; 16];
                read_full(&mut conn, &mut bound, deadline)?;
            }
            ADDRESS_TYPE_DOMAIN => {
                let mut len = [0u8; 1];
                read_full(&mut conn, &mut len, deadline)?;
                let mut bound = vec![0u8; len[0] as usize];
                read_full(&mut conn, &mut bound, deadline)?;
            }
            _ => return Err(ERR_INVALID_PROXY_RESPONSE.to_string()),
        }
        let mut bound_port = [0u8; 2];
        read_full(&mut conn, &mut bound_port, deadline)?;

        // go-socks clears the handshake deadline before returning;
        // the caller applies the peer read deadline itself.
        let _ = conn.set_read_timeout(None);
        let _ = conn.set_write_timeout(None);
        Ok(conn)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Resolve a hostname through Tor's SOCKS RESOLVE extension (dcrd
/// `connmgr.TorLookupIP`), with dcrd's error texts.
pub fn tor_lookup_ip(
    host: &str,
    proxy: &str,
    timeout: Duration,
) -> Result<Vec<std::net::IpAddr>, String> {
    let deadline = Deadline::after(timeout);
    let mut conn = connect_proxy(proxy, deadline)?;

    // The greeting offers only authNone.
    write_full(&mut conn, &[0x05, 0x01, 0x00], deadline)?;
    let mut reply = [0u8; 2];
    read_full(&mut conn, &mut reply, deadline)?;
    if reply[0] != 0x05 {
        return Err("invalid SOCKS proxy version".to_string());
    }
    if reply[1] != 0x00 {
        return Err("invalid proxy authentication method".to_string());
    }

    // The RESOLVE command (0xF0) over the domain address with port 0.
    let mut request = Vec::with_capacity(7 + host.len());
    request.push(5);
    request.push(240); // torCmdResolve
    request.push(0); // reserved
    request.push(3); // torATypeDomainName
    request.push(host.len() as u8);
    request.extend_from_slice(host.as_bytes());
    request.push(0); // port 0 high
    request.push(0); // port 0 low (Go writes one zero into a zeroed buffer)
    write_full(&mut conn, &request, deadline)?;

    let mut header = [0u8; 4];
    read_full(&mut conn, &mut header, deadline)?;
    if header[0] != 5 {
        return Err("invalid SOCKS proxy version".to_string());
    }
    if header[1] != 0 {
        return Err(match header[1] {
            0x01 => "tor general error",
            0x02 => "tor not allowed",
            0x03 => "tor network is unreachable",
            0x04 => "tor host is unreachable",
            0x05 => "tor connection refused",
            0x06 => "tor TTL expired",
            0x07 => "tor command not supported",
            0x08 => "tor address type not supported",
            _ => "invalid SOCKS proxy version",
        }
        .to_string());
    }
    if header[3] != 1 && header[3] != 4 {
        return Err("invalid IP address".to_string());
    }

    // dcrd reads the address and port in one raw read and validates
    // the length against the announced type.
    let mut reply = [0u8; 32 + 2];
    deadline.arm(&conn)?;
    let reply_len = conn.read(&mut reply).map_err(|e| e.to_string())?;
    match header[3] {
        1 => {
            if reply_len != 4 + 2 {
                return Err("invalid IPV4 address".to_string());
            }
            let ip = std::net::Ipv4Addr::new(reply[0], reply[1], reply[2], reply[3]);
            Ok(vec![std::net::IpAddr::V4(ip)])
        }
        4 => {
            if reply_len <= 4 + 2 {
                return Err("invalid IPV6 address".to_string());
            }
            let mut octets = [0u8; 16];
            let addr_len = reply_len - 2;
            if addr_len != 16 {
                return Err("invalid IPV6 address".to_string());
            }
            octets.copy_from_slice(&reply[..16]);
            Ok(vec![std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))])
        }
        _ => Err("unknown address type".to_string()),
    }
}

/// How onion addresses route (the concrete form of the config's
/// `OnionSelection`).
#[derive(Clone, Debug)]
enum OnionRoute {
    /// The ordinary dial and lookup functions.
    SameAsMain,
    /// A dedicated onion proxy (dcrd builds the `socks.Proxy` per
    /// dial inside the closure; the captured fields are identical).
    Proxy(Proxy),
    /// --noonion: onion dials and lookups fail.
    Disabled,
}

/// The daemon's dial and lookup routing (dcrd's `cfg.dial`,
/// `cfg.lookup`, `cfg.oniondial`, and `cfg.onionlookup` closures with
/// the `dcrdDial`/`dcrdLookup` dispatchers over them).
#[derive(Clone, Debug)]
pub struct NodeDialer {
    /// The ordinary dialer: direct, or through the SOCKS5 proxy.
    main_proxy: Option<Proxy>,
    /// The ordinary lookup: the system resolver, or Tor resolution
    /// through the given proxy address.
    lookup_proxy: Option<String>,
    /// The onion routing.
    onion: OnionRoute,
}

/// dcrd's `--noonion` error text for both the dial and the lookup.
const ERR_TOR_DISABLED: &str = "tor has been disabled";

impl NodeDialer {
    /// The default routing: direct dials and the system resolver.
    pub fn direct() -> NodeDialer {
        NodeDialer {
            main_proxy: None,
            lookup_proxy: None,
            onion: OnionRoute::SameAsMain,
        }
    }

    /// Build the routing the configuration selected (the closure
    /// assembly at the end of dcrd's `loadConfig`, over the pinned
    /// selection enums).
    pub fn from_config(cfg: &crate::config::Config) -> NodeDialer {
        let main_proxy = match cfg.dial {
            crate::config::DialSelection::Direct => None,
            crate::config::DialSelection::SocksProxy => Some(Proxy {
                addr: cfg.proxy.clone(),
                username: cfg.proxy_user.clone(),
                password: cfg.proxy_pass.clone(),
                tor_isolation: cfg.tor_isolation,
            }),
        };
        let lookup_proxy = match cfg.lookup {
            crate::config::LookupSelection::System => None,
            crate::config::LookupSelection::TorViaProxy => Some(cfg.proxy.clone()),
        };
        let onion = match cfg.onion {
            crate::config::OnionSelection::SameAsMain => OnionRoute::SameAsMain,
            crate::config::OnionSelection::OnionProxy => OnionRoute::Proxy(Proxy {
                addr: cfg.onion_proxy.clone(),
                username: cfg.onion_proxy_user.clone(),
                password: cfg.onion_proxy_pass.clone(),
                tor_isolation: cfg.tor_isolation,
            }),
            crate::config::OnionSelection::Disabled => OnionRoute::Disabled,
        };
        NodeDialer {
            main_proxy,
            lookup_proxy,
            onion,
        }
    }

    /// Dial a host:port with dcrd's routing (`dcrdDial`): an address
    /// containing `.onion:` takes the onion route, everything else the
    /// ordinary one.
    pub fn dial(&self, addr: &str, timeout: Duration) -> Result<TcpStream, String> {
        if addr.contains(".onion:") {
            return match &self.onion {
                OnionRoute::SameAsMain => self.dial_main(addr, timeout),
                OnionRoute::Proxy(proxy) => proxy.dial(addr, timeout),
                OnionRoute::Disabled => Err(ERR_TOR_DISABLED.to_string()),
            };
        }
        self.dial_main(addr, timeout)
    }

    fn dial_main(&self, addr: &str, timeout: Duration) -> Result<TcpStream, String> {
        match &self.main_proxy {
            Some(proxy) => proxy.dial(addr, timeout),
            None => {
                let socket: std::net::SocketAddr = addr
                    .parse()
                    .map_err(|e| format!("invalid dial address {addr}: {e}"))?;
                TcpStream::connect_timeout(&socket, timeout).map_err(|e| e.to_string())
            }
        }
    }

    /// Resolve a host with dcrd's routing (`dcrdLookup`): a `.onion`
    /// suffix takes the onion route, everything else the ordinary one.
    pub fn lookup(&self, host: &str, timeout: Duration) -> Result<Vec<std::net::IpAddr>, String> {
        if host.ends_with(".onion") {
            return match &self.onion {
                OnionRoute::SameAsMain => self.lookup_main(host, timeout),
                OnionRoute::Proxy(proxy) => tor_lookup_ip(host, &proxy.addr, timeout),
                OnionRoute::Disabled => Err(ERR_TOR_DISABLED.to_string()),
            };
        }
        self.lookup_main(host, timeout)
    }

    fn lookup_main(&self, host: &str, timeout: Duration) -> Result<Vec<std::net::IpAddr>, String> {
        match &self.lookup_proxy {
            Some(proxy) => tor_lookup_ip(host, proxy, timeout),
            None => {
                // Go `net.LookupIP` via the system resolver.
                use std::net::ToSocketAddrs;
                Ok((host, 0u16)
                    .to_socket_addrs()
                    .map_err(|e| e.to_string())?
                    .map(|addr| addr.ip())
                    .collect())
            }
        }
    }
}
