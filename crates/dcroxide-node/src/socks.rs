// SPDX-License-Identifier: ISC
//! The SOCKS5 proxy dial and the Tor DNS resolution the daemon's
//! --proxy/--onion wiring uses: a port of `decred/go-socks`'s
//! `Proxy.DialContext` (version 5 only — the greeting with optional
//! RFC 1929 username/password authentication, the TCP CONNECT
//! command over a domain address, the reply status table, and Tor
//! isolation drawing random credentials per connection) and of dcrd
//! `addrmgr.TorLookupIP` (Tor's SOCKS RESOLVE extension with its own
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

/// std's text for a TCP connect that ran out its timeout
/// (`TcpStream::connect_timeout`'s `TimedOut`), and the text the proxy
/// connect reports when the dial's deadline passes before an address's
/// turn: in both cases Go's dialer fails with an error that `errors.Is`
/// `context.DeadlineExceeded`, which the outbound driver turns into the
/// connect handlers' timeout.
pub(crate) const CONNECT_TIMED_OUT: &str = "connection timed out";

/// Go's head start for the first address family (`net/dial.go`
/// `fallbackDelay`, the zero `net.Dialer`'s 300 ms).
const FALLBACK_DELAY: Duration = Duration::from_millis(300);

/// Connect to a `host:port` proxy address like the zero `net.Dialer`
/// go-socks and `TorLookupIP` dial with: resolve the name (a hostname
/// proxy such as Tor's default `localhost:9050` is common), split the
/// addresses by the family of the first as `Dialer.DialContext` does for
/// a dual-stack dialer, and race the two families ([`dial_parallel`]).
/// The error reported is Go's, which go-socks and `TorLookupIP` return
/// as it is.
///
/// Go splits the time among the addresses only when the context has a
/// deadline ([`dial_serial`]).  go-socks's does: connmgr's dial timeout,
/// or the seeder's minute.  dcrd runs `TorLookupIP` under
/// `context.Background()` (`config.go:1270`, `:1310`), so there each
/// address's connect runs until the kernel gives up, and no deadline
/// error exists.  For a Tor lookup, `deadline` is the port's own bound
/// (see [`tor_lookup_ip`]), and it is split the same way.
fn connect_proxy(addr: &str, deadline: Deadline) -> Result<TcpStream, String> {
    use std::net::ToSocketAddrs;
    let resolved: Vec<std::net::SocketAddr> = addr
        .to_socket_addrs()
        .map_err(|e| format!("invalid proxy address {addr}: {e}"))?
        .collect();
    if resolved.is_empty() {
        return Err(format!("no addresses found for proxy {addr}"));
    }
    let (primaries, fallbacks) = partition_by_family(resolved);
    dial_parallel(primaries, fallbacks, deadline, TcpStream::connect_timeout)
}

/// Go's `addrList.partition(isIPv4)`: the addresses of the first
/// address's family, then the rest, each in order.  An IPv4-mapped IPv6
/// address counts as IPv4, as `IP.To4` has it.
fn partition_by_family(
    addrs: Vec<std::net::SocketAddr>,
) -> (Vec<std::net::SocketAddr>, Vec<std::net::SocketAddr>) {
    let is_ipv4 = |addr: &std::net::SocketAddr| match addr.ip() {
        std::net::IpAddr::V4(_) => true,
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().is_some(),
    };
    let Some(primary_label) = addrs.first().map(is_ipv4) else {
        return (Vec::new(), Vec::new());
    };
    addrs
        .into_iter()
        .partition(|addr| is_ipv4(addr) == primary_label)
}

/// Go's `partialDeadline` (`net/dial.go`): how long the next of
/// `addrs_remaining` addresses may take out of the `left` before the
/// deadline — an equal share, at least two seconds, or all of `left`
/// when less than that remains.  `None` once the deadline has passed.
fn partial_timeout(left: Duration, addrs_remaining: usize) -> Option<Duration> {
    const SANE_MINIMUM: Duration = Duration::from_secs(2);
    if left.is_zero() {
        return None;
    }
    let share = left / u32::try_from(addrs_remaining.max(1)).unwrap_or(u32::MAX);
    Some(if share < SANE_MINIMUM {
        left.min(SANE_MINIMUM)
    } else {
        share
    })
}

/// Go's `dialSerial` (`net/dial.go`): the addresses in turn, each given
/// its [`partial_timeout`] share of the time left, until one connects.
/// The first address's error is the one reported ("The error from the
/// first address is most relevant"), except that once the deadline has
/// passed before an address's turn Go's context is done and the dial
/// fails with its deadline error instead ([`CONNECT_TIMED_OUT`]).  Go
/// computes the shares only under a context with a deadline, as
/// go-socks's dial has.  Under `TorLookupIP`'s background context each
/// address takes as long as the kernel's connect does, so for a Tor
/// lookup both the shares and the timeout error come from the port's
/// own bound.
fn dial_serial<C>(
    ras: &[std::net::SocketAddr],
    deadline: Deadline,
    connect: &C,
) -> Result<TcpStream, String>
where
    C: Fn(&std::net::SocketAddr, Duration) -> std::io::Result<TcpStream>,
{
    let mut first_err = None;
    for (i, ra) in ras.iter().enumerate() {
        let left = deadline.0.saturating_duration_since(Instant::now());
        let Some(timeout) = partial_timeout(left, ras.len() - i) else {
            return Err(CONNECT_TIMED_OUT.to_string());
        };
        match connect(ra, timeout) {
            Ok(conn) => {
                // Go's dialer sets TCP_NODELAY on every connection it
                // makes, ignoring a failure (`newTCPConn`,
                // `net/tcpsock.go`).
                let _ = conn.set_nodelay(true);
                return Ok(conn);
            }
            Err(e) => {
                first_err.get_or_insert_with(|| go_connect_error(&ra.to_string(), &e));
            }
        }
    }
    // Go's `errMissingAddress`, for an empty list.
    Err(first_err.unwrap_or_else(|| "dial tcp: missing address".to_string()))
}

/// Go's `dialParallel` (`net/dial.go`): with no fallback family, the
/// primaries in turn.  Otherwise the primary family dials at once and the
/// fallback family after [`FALLBACK_DELAY`], or as soon as the primary
/// family has failed, and the first connection wins; when both fail the
/// primary family's error is reported.  Each family races on its own
/// thread.  Go cancels the loser; here a loser still connecting runs out
/// its share of the deadline and its connection, if it makes one, is
/// dropped.
fn dial_parallel<C>(
    primaries: Vec<std::net::SocketAddr>,
    fallbacks: Vec<std::net::SocketAddr>,
    deadline: Deadline,
    connect: C,
) -> Result<TcpStream, String>
where
    C: Fn(&std::net::SocketAddr, Duration) -> std::io::Result<TcpStream> + Clone + Send + 'static,
{
    if fallbacks.is_empty() {
        return dial_serial(&primaries, deadline, &connect);
    }

    let (results, raced) = std::sync::mpsc::channel();
    // Start one family's `dialSerial`.  Refused a thread, the family
    // dials in line instead, which only costs the race its overlap.
    let start_racer = |primary: bool, ras: Vec<std::net::SocketAddr>| {
        let (inline_ras, inline_connect, inline_results) =
            (ras.clone(), connect.clone(), results.clone());
        let (connect, results) = (connect.clone(), results.clone());
        let spawned = crate::runtime::spawn_conn_thread("proxy-dial", move || {
            let _ = results.send((primary, dial_serial(&ras, deadline, &connect)));
        });
        if spawned.is_err() {
            let _ =
                inline_results.send((primary, dial_serial(&inline_ras, deadline, &inline_connect)));
        }
    };

    start_racer(true, primaries);
    let fallback_at = Instant::now() + FALLBACK_DELAY;
    let mut fallbacks = Some(fallbacks);
    let mut primary_err: Option<String> = None;
    let mut fallback_failed = false;
    loop {
        // `results` stays alive here, so the channel never disconnects
        // while a racer owes its outcome.
        let outcome = if fallbacks.is_some() {
            match raced.recv_timeout(fallback_at.saturating_duration_since(Instant::now())) {
                Ok(outcome) => outcome,
                Err(_) => {
                    // The head start ran out.
                    if let Some(ras) = fallbacks.take() {
                        start_racer(false, ras);
                    }
                    continue;
                }
            }
        } else {
            match raced.recv() {
                Ok(outcome) => outcome,
                Err(_) => {
                    return Err(primary_err.unwrap_or_else(|| CONNECT_TIMED_OUT.to_string()));
                }
            }
        };
        match outcome {
            (_, Ok(conn)) => return Ok(conn),
            (true, Err(e)) => {
                if fallback_failed {
                    return Err(e);
                }
                primary_err = Some(e);
                // Go resets the fallback timer to zero when the primary
                // fails inside its head start.
                if let Some(ras) = fallbacks.take() {
                    start_racer(false, ras);
                }
            }
            (false, Err(_)) => {
                if let Some(e) = primary_err.take() {
                    return Err(e);
                }
                fallback_failed = true;
            }
        }
    }
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
/// `addrmgr.TorLookupIP`, `addrmgr/tordns.go`), with dcrd's error texts.
///
/// `timeout` is the port's own bound.  dcrd calls `TorLookupIP` with
/// `context.Background()` (`config.go:1270`, `:1310`), so neither its
/// proxy connect nor its exchange has a deadline, and a proxy that stops
/// answering holds the lookup indefinitely.  The port's callers pass a
/// bound instead: a minute for connect targets and seeder sources, or
/// the dial timeout when marking a dial attempt, for example.  The
/// connect splits that bound among the proxy's addresses as Go's
/// `dialSerial` would under a deadline, and the exchange uses what is
/// left.  When it
/// runs out, the lookup fails with the dial timeout text or Go's `i/o
/// timeout`, which dcrd, having no deadline here, never reports.
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

/// Go's `avoidDNS` (`net/dnsclient_unix.go`): a `.onion` name, matched
/// ASCII-case-insensitively after one trailing dot is dropped, is never
/// sent to DNS.  Go's resolver still answers such a name from
/// `/etc/hosts`, and still queries the `resolv.conf` search-list forms
/// of an unrooted one (`<name>.onion.<suffix>.`), failing with `lookup
/// <name> on <server>: no such host` when a search domain is set; the
/// port skips the name altogether, which is Go's answer for a rooted
/// name or a resolver without search domains.
fn avoid_dns(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name).as_bytes();
    name.len() >= 6 && name[name.len() - 6..].eq_ignore_ascii_case(b".onion")
}

/// A failed direct connect as Go's dialer reports it, the
/// `*net.OpError` text `dial tcp <addr>: connect: <errno text>`.  On
/// unix Go's errno texts are the C library's with the first letter
/// lowered.  std's own timeout carries no OS error and keeps its text,
/// which the outbound driver reads as the dial deadline running out, and
/// other platforms keep std's rendering (Go's Windows text is
/// `connectex: <message>`).
fn go_connect_error(addr: &str, e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(code) if cfg!(unix) => {
            let text = e.to_string();
            let text = text
                .strip_suffix(&format!(" (os error {code})"))
                .unwrap_or(&text);
            let mut chars = text.chars();
            let errno_text: String = match chars.next() {
                Some(first) => first.to_lowercase().chain(chars).collect(),
                None => String::new(),
            };
            format!("dial tcp {addr}: connect: {errno_text}")
        }
        _ => e.to_string(),
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
                // A Tor v3 key under the default onion routing is the one
                // host that reaches here unresolved.  Go's dialer resolves
                // it first, and its resolver answers a `.onion` name with
                // no addresses without asking DNS (see `avoid_dns`), which
                // the dial reports as `filterAddrList`'s error inside its
                // `OpError` (`net/ipsock.go`, `net/dial.go`).
                if let Ok((host, _)) = crate::gostd::split_host_port(addr)
                    && avoid_dns(&host)
                {
                    return Err(format!(
                        "dial tcp: address {host}: no suitable address found"
                    ));
                }
                let socket: std::net::SocketAddr = addr
                    .parse()
                    .map_err(|e| format!("invalid dial address {addr}: {e}"))?;
                let conn = TcpStream::connect_timeout(&socket, timeout)
                    .map_err(|e| go_connect_error(addr, &e))?;
                // Go's dialer sets TCP_NODELAY on every connection it
                // makes, ignoring a failure (`newTCPConn`,
                // `net/tcpsock.go`).
                let _ = conn.set_nodelay(true);
                Ok(conn)
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
                // Go `net.LookupIP` via the system resolver.  Go's own
                // resolver never asks DNS for a `.onion` name (RFC 7686),
                // which comes back with no addresses; the system resolver
                // would send the query, so the name never reaches it.
                if avoid_dns(host) {
                    return Ok(Vec::new());
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    /// A stand-in connect that fails at once with a text naming the
    /// address, recording each attempt's address and timeout.
    fn refusing(
        attempts: &Arc<Mutex<Vec<(SocketAddr, Duration)>>>,
    ) -> impl Fn(&SocketAddr, Duration) -> std::io::Result<TcpStream> + Clone + Send + 'static {
        let attempts = Arc::clone(attempts);
        move |addr: &SocketAddr, timeout: Duration| {
            attempts.lock().expect("attempts").push((*addr, timeout));
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("refused {addr}"),
            ))
        }
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("socket address")
    }

    /// Go's `partialDeadline`: equal shares with a two-second floor, all
    /// of what is left below that, and nothing once it is spent.
    #[test]
    fn partial_timeout_matches_gos_partial_deadline() {
        let secs = Duration::from_secs;
        assert_eq!(partial_timeout(secs(30), 1), Some(secs(30)));
        assert_eq!(partial_timeout(secs(30), 2), Some(secs(15)));
        assert_eq!(partial_timeout(secs(30), 3), Some(secs(10)));
        assert_eq!(partial_timeout(secs(3), 2), Some(secs(2)));
        assert_eq!(
            partial_timeout(Duration::from_millis(1500), 3),
            Some(Duration::from_millis(1500))
        );
        assert_eq!(partial_timeout(Duration::ZERO, 1), None);
    }

    /// Go's dialer splits the addresses by the first one's family.
    #[test]
    fn the_first_address_picks_the_primary_family() {
        let (v6a, v4a, v6b, mapped) = (
            addr("[2001:db8::1]:9050"),
            addr("192.0.2.1:9050"),
            addr("[2001:db8::2]:9050"),
            addr("[::ffff:192.0.2.2]:9050"),
        );
        assert_eq!(
            partition_by_family(vec![v6a, v4a, v6b, mapped]),
            (vec![v6a, v6b], vec![v4a, mapped])
        );
        assert_eq!(
            partition_by_family(vec![mapped, v6a, v4a]),
            (vec![mapped, v4a], vec![v6a])
        );
    }

    /// Go's `dialSerial` gives each address its `partialDeadline` share
    /// of the time left and reports the first address's error.  The
    /// port gave every address all of the time left, so a first address
    /// that black-holes spent the whole dial timeout and the next never
    /// had a turn.
    #[test]
    fn each_address_gets_its_share_of_the_deadline() {
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let ras = [
            addr("192.0.2.1:9050"),
            addr("192.0.2.2:9050"),
            addr("192.0.2.3:9050"),
        ];
        let result = dial_serial(
            &ras,
            Deadline::after(Duration::from_secs(30)),
            &refusing(&attempts),
        );
        assert_eq!(
            result.map(|_| ()),
            Err("refused 192.0.2.1:9050".to_string())
        );
        let attempts = attempts.lock().expect("attempts").clone();
        let near = |got: Duration, want: u64| {
            let want = Duration::from_secs(want);
            got <= want && got + Duration::from_secs(1) > want
        };
        assert_eq!(attempts.len(), 3);
        assert!(near(attempts[0].1, 10), "{attempts:?}");
        assert!(near(attempts[1].1, 15), "{attempts:?}");
        assert!(near(attempts[2].1, 30), "{attempts:?}");
    }

    /// Once the deadline has passed before an address's turn, Go's
    /// `dialSerial` returns its done context's deadline error, whatever
    /// the earlier addresses failed with; the driver maps that text to
    /// the connect handlers' timeout.  The port returned a bare "i/o
    /// timeout", which no caller recognised as the deadline.
    #[test]
    fn a_spent_deadline_fails_as_the_dial_timeout() {
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&attempts);
        // The first address uses up all it is given (under the two-second
        // floor, the whole budget), then fails.
        let slow = move |addr: &SocketAddr, timeout: Duration| {
            recorded.lock().expect("attempts").push((*addr, timeout));
            std::thread::sleep(timeout);
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("refused {addr}"),
            ))
        };
        let result = dial_serial(
            &[addr("192.0.2.1:9050"), addr("192.0.2.2:9050")],
            Deadline::after(Duration::from_millis(200)),
            &slow,
        );
        assert_eq!(result.map(|_| ()), Err(CONNECT_TIMED_OUT.to_string()));
        assert_eq!(
            attempts.lock().expect("attempts").len(),
            1,
            "no attempt starts past the deadline"
        );
    }

    /// The zero `net.Dialer` that go-socks and `TorLookupIP` dial with is
    /// dual-stack: the second family starts 300 ms after the first unless
    /// the first has connected, and the first connection wins.  The port
    /// tried the addresses in order with the whole budget each, so a
    /// proxy name whose first address black-holes (`localhost` resolving
    /// to `::1` first on a host that drops it) spent the dial timeout
    /// there and never reached `127.0.0.1`.
    #[test]
    fn a_black_holed_family_falls_back_after_the_head_start() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let live = listener.local_addr().expect("listener address");
        let started = Instant::now();
        let v4_started = Arc::new(Mutex::new(None));
        let v4_mark = Arc::clone(&v4_started);
        let connect = move |addr: &SocketAddr, timeout: Duration| {
            if addr.is_ipv6() {
                // Black-holed: nothing answers until the attempt's time
                // is up.
                std::thread::sleep(timeout);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    CONNECT_TIMED_OUT,
                ));
            }
            *v4_mark.lock().expect("mark") = Some(started.elapsed());
            TcpStream::connect_timeout(&live, timeout)
        };
        let conn = dial_parallel(
            vec![addr("[2001:db8::1]:9050")],
            vec![live],
            Deadline::after(Duration::from_secs(20)),
            connect,
        )
        .expect("the fallback family connects");
        assert_eq!(conn.peer_addr().expect("peer"), live);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the black-holed family must not hold the dial: {:?}",
            started.elapsed()
        );
        let v4_at = v4_started
            .lock()
            .expect("mark")
            .expect("the fallback family was dialed");
        assert!(v4_at >= FALLBACK_DELAY, "the head start is kept: {v4_at:?}");
    }

    /// When both families fail, Go reports the primary family's first
    /// error, and a primary that fails inside its head start starts the
    /// fallback at once.
    #[test]
    fn both_families_failing_report_the_primarys_error() {
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let result = dial_parallel(
            vec![addr("[2001:db8::1]:9050"), addr("[2001:db8::2]:9050")],
            vec![addr("192.0.2.1:9050")],
            Deadline::after(Duration::from_secs(30)),
            refusing(&attempts),
        );
        assert_eq!(
            result.map(|_| ()),
            Err("refused [2001:db8::1]:9050".to_string())
        );
        let mut tried: Vec<SocketAddr> = attempts
            .lock()
            .expect("attempts")
            .iter()
            .map(|(addr, _)| *addr)
            .collect();
        tried.sort();
        assert_eq!(
            tried,
            vec![
                addr("192.0.2.1:9050"),
                addr("[2001:db8::1]:9050"),
                addr("[2001:db8::2]:9050"),
            ]
        );
    }
}
