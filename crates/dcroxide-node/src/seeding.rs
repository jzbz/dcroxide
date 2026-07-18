// SPDX-License-Identifier: ISC
//! Seeder bootstrap — the daemon driver for the ported HTTPS seeder
//! (dcrd `server.querySeeders` over `connmgr.SeedAddrs`).
//!
//! Each configured seeder is queried on its own thread through a
//! TLS-capable HTTP transport, and the discovered addresses land in the
//! shared address manager with the seeder's resolved IP as their
//! source, giving the automatic dialer its bootstrap candidates.  When
//! every seeder fails and the manager still needs addresses, the round
//! is retried with dcrd's one-to-ten-second backoff until shutdown.

use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dcroxide_addrmgr::AddrManager;
use std::io::{Read, Write};

use dcroxide_addrmgr::{HttpsSeederFilters, MAX_RESP_SIZE, SeedEnv, SeederTransport, seed_addrs};

/// The TLS-capable seeder transport over `ureq` (dcrd's `dcrdDial`
/// behind Go's `http.Client`; the proxy configuration plugs in with the
/// Tor/proxy piece).
pub struct UreqTransport {
    agent: ureq::Agent,
}

impl UreqTransport {
    /// A transport with dcrd's one-minute per-seeder timeout.
    pub fn new() -> UreqTransport {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(60)))
            // The seeder logic inspects the status itself.
            .http_status_as_error(false)
            .build();
        UreqTransport {
            agent: config.new_agent(),
        }
    }
}

impl Default for UreqTransport {
    fn default() -> Self {
        UreqTransport::new()
    }
}

impl SeederTransport for UreqTransport {
    fn get(&mut self, url: &str) -> Result<(u32, Vec<u8>), String> {
        let mut response = self
            .agent
            .get(url)
            .call()
            .map_err(|e| format!("seeder request failed: {e}"))?;
        let status = u32::from(response.status().as_u16());
        // Read at most the connmgr's response cap off the wire from an
        // untrusted seeder (dcrd's `io.LimitReader(resp.Body,
        // maxNodes*maxAddrLen)`), rather than ureq's 10 MiB default; a
        // larger body is truncated to the cap, not rejected.  `seed_addrs`
        // truncates to the same cap again as a safety net.
        let mut body = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(MAX_RESP_SIZE as u64)
            .read_to_end(&mut body)
            .map_err(|e| format!("seeder response read failed: {e}"))?;
        Ok((status, body))
    }
}

/// A seeder transport that dials through the configured proxy routing
/// (dcrd routes its seeder HTTP transport through `dcrdDial`, so a
/// `--proxy` operator's seeder traffic rides the SOCKS proxy rather
/// than leaking directly).  The connection is established through the
/// [`NodeDialer`](crate::socks::NodeDialer) — SOCKS5 or direct — then
/// wrapped in TLS validated against the public web PKI roots, and a
/// minimal HTTP/1.1 GET reads the seeder's JSON response.
///
/// The client is deliberately small: it sends one `Connection: close`
/// GET and reads the body to end of stream, capped at the connmgr's
/// response limit and bounded by an absolute deadline (dcrd's
/// one-minute request timeout).  It follows no redirects and decodes
/// no chunked transfer encoding — the Decred seeders answer 200 with
/// the JSON body directly — a documented simplification from Go's
/// `http.Client`.
pub struct ProxySeederTransport {
    dialer: crate::socks::NodeDialer,
    timeout: Duration,
}

impl ProxySeederTransport {
    /// A transport over the given dial routing with dcrd's one-minute
    /// per-seeder request deadline.
    pub fn new(dialer: crate::socks::NodeDialer) -> ProxySeederTransport {
        ProxySeederTransport {
            dialer,
            timeout: Duration::from_secs(60),
        }
    }
}

/// A URL split into the parts the transport dials and requests.
struct SeederUrl {
    host: String,
    port: u16,
    path_and_query: String,
    tls: bool,
}

fn parse_seeder_url(url: &str) -> Result<SeederUrl, String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("invalid seeder url: {url}"))?;
    let tls = match scheme {
        "https" => true,
        "http" => false,
        other => return Err(format!("unsupported seeder scheme: {other}")),
    };
    let (authority, path_and_query) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host.to_string(),
            port.parse::<u16>()
                .map_err(|e| format!("invalid seeder port {port}: {e}"))?,
        ),
        None => (authority.to_string(), if tls { 443 } else { 80 }),
    };
    if host.is_empty() {
        return Err(format!("invalid seeder url: {url}"));
    }
    Ok(SeederUrl {
        host,
        port,
        path_and_query: path_and_query.to_string(),
        tls,
    })
}

/// The shared TLS client configuration over the public web PKI roots
/// (built once; rustls' config is meant to be reused).
fn seeder_tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("rustls default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

/// Read the HTTP response off a stream: the status line's code and the
/// body after the header block, capped at the connmgr's limit and
/// bounded by an absolute deadline.
fn read_http_response(mut read: impl Read, deadline: Instant) -> Result<(u32, Vec<u8>), String> {
    // Cap the whole response (header + body) at the connmgr limit plus
    // a small header allowance, so an untrusted seeder cannot force an
    // unbounded read, and stop at the deadline so a slow-trickle seeder
    // cannot pin the seeding round (a true absolute bound, not just a
    // per-read idle timeout).
    let cap = (MAX_RESP_SIZE as u64).saturating_add(8192) as usize;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    while raw.len() < cap {
        if Instant::now() >= deadline {
            return Err("seeder response timed out".to_string());
        }
        match read.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            // rustls surfaces an unclean TLS close (a peer that shuts
            // the TCP connection without close_notify, common behind
            // CDNs and load balancers) as UnexpectedEof; the
            // Connection: close body framing treats it as end of stream
            // and keeps the bytes already received, as Go's http.Client
            // does.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(format!("seeder response read failed: {e}")),
        }
    }
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "seeder response missing header terminator".to_string())?;
    let header = &raw[..split];
    let body_start = split.saturating_add(4);
    let status_line = header
        .split(|b| *b == b'\r' || *b == b'\n')
        .next()
        .unwrap_or_default();
    let status = std::str::from_utf8(status_line)
        .ok()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u32>().ok())
        .ok_or_else(|| "seeder response missing status code".to_string())?;
    let mut body = raw[body_start..].to_vec();
    body.truncate(MAX_RESP_SIZE);
    Ok((status, body))
}

impl SeederTransport for ProxySeederTransport {
    fn get(&mut self, url: &str) -> Result<(u32, Vec<u8>), String> {
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .unwrap_or_else(Instant::now);
        let parsed = parse_seeder_url(url)?;
        let stream = self
            .dialer
            .dial(&format!("{}:{}", parsed.host, parsed.port), self.timeout)?;
        let _ = stream.set_read_timeout(Some(self.timeout));
        let _ = stream.set_write_timeout(Some(self.timeout));

        // The Host header carries the port unless it is the scheme
        // default (Go's http.Client and RFC 7230 both do this).
        let default_port = if parsed.tls { 443 } else { 80 };
        let host_header = if parsed.port == default_port {
            parsed.host.clone()
        } else {
            format!("{}:{}", parsed.host, parsed.port)
        };
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: dcroxide\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            parsed.path_and_query
        );

        if parsed.tls {
            let server_name = rustls::pki_types::ServerName::try_from(parsed.host.clone())
                .map_err(|e| format!("invalid seeder host {}: {e}", parsed.host))?;
            let conn = rustls::ClientConnection::new(seeder_tls_config(), server_name)
                .map_err(|e| format!("seeder tls setup failed: {e}"))?;
            let mut tls = rustls::StreamOwned::new(conn, stream);
            tls.write_all(request.as_bytes())
                .map_err(|e| format!("seeder request failed: {e}"))?;
            read_http_response(tls, deadline)
        } else {
            let mut stream = stream;
            stream
                .write_all(request.as_bytes())
                .map_err(|e| format!("seeder request failed: {e}"))?;
            read_http_response(stream, deadline)
        }
    }
}
/// The system clock and randomness stamping discovered addresses (the
/// seeder backdates each between three and seven days).
pub struct SystemSeedEnv;

impl SeedEnv for SystemSeedEnv {
    fn now_nanos(&mut self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0)
    }

    fn rand_duration(&mut self, max_nanos: i64) -> i64 {
        let mut buf = [0u8; 8];
        getrandom::fill(&mut buf).expect("system random source");
        u64::from_le_bytes(buf)
            .checked_rem(max_nanos.max(1) as u64)
            .unwrap_or(0) as i64
    }
}

/// The running seeder bootstrap; dropping it (or calling
/// [`SeederBoot::shutdown`]) stops the retry loop.
pub struct SeederBoot {
    stop: mpsc::Sender<()>,
    thread: Option<JoinHandle<()>>,
}

impl SeederBoot {
    /// Stop the bootstrap; an in-flight seeder round is abandoned
    /// rather than waited out (its request threads end at the
    /// transport timeout at most).
    pub fn shutdown(mut self) {
        self.stop_thread();
    }

    fn stop_thread(&mut self) {
        let (closed, _) = mpsc::channel();
        self.stop = closed;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for SeederBoot {
    fn drop(&mut self) {
        self.stop_thread();
    }
}

/// Query the network's seeders and feed the discovered addresses into
/// the address manager (dcrd `querySeeders` launched from `Run` when
/// seeding is enabled).  `transport_factory` builds the per-seeder
/// transport, letting tests script the responses.
pub fn start_seeding<T, F>(
    seeders: Vec<String>,
    addr_manager: Arc<Mutex<AddrManager>>,
    required_services: u64,
    transport_factory: F,
) -> SeederBoot
where
    T: SeederTransport,
    F: Fn() -> T + Send + Sync + 'static,
{
    let (stop, stopped) = mpsc::channel::<()>();
    let thread = thread::spawn(move || {
        let filters = HttpsSeederFilters::default().services(required_services);
        let factory = Arc::new(transport_factory);
        // dcrd retries the whole round with a growing backoff while
        // every seeder fails and the manager still needs addresses.
        let mut backoff = Duration::from_secs(1);
        loop {
            // Each seeder reports its result over a channel rather than
            // being joined, so a shutdown does not wait out an in-flight
            // request (dcrd cancels the requests through the daemon
            // context; the port cannot abort its transports, so the
            // round threads are abandoned instead — their requests run
            // to the transport timeout at most and die with the
            // process).
            let mut err_count = 0usize;
            let (results, resulted) = mpsc::channel();
            for seeder in &seeders {
                let seeder = seeder.clone();
                let filters = filters.clone();
                let factory = Arc::clone(&factory);
                let results = results.clone();
                thread::spawn(move || {
                    let mut transport = factory();
                    let mut env = SystemSeedEnv;
                    let outcome = seed_addrs(&seeder, &mut transport, &mut env, &filters)
                        .map(|addrs| (seeder, addrs));
                    let _ = results.send(outcome);
                });
            }
            drop(results);
            let mut outstanding = seeders.len();
            while outstanding > 0 {
                // A stop request or a dropped stop sender abandons the
                // round immediately.
                if let Ok(()) | Err(mpsc::TryRecvError::Disconnected) = stopped.try_recv() {
                    return;
                }
                match resulted.recv_timeout(Duration::from_millis(200)) {
                    Ok(Ok((seeder, addrs))) => {
                        outstanding = outstanding.saturating_sub(1);
                        if addrs.is_empty() {
                            continue;
                        }
                        add_seeded(&addr_manager, &seeder, addrs);
                    }
                    Ok(Err(_)) => {
                        outstanding = outstanding.saturating_sub(1);
                        err_count = err_count.saturating_add(1);
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    // Every round sender is gone: whatever did not
                    // report counts as failed.
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        err_count = err_count.saturating_add(outstanding);
                        break;
                    }
                }
            }

            let need_more = addr_manager
                .lock()
                .expect("addrmgr mutex poisoned")
                .need_more_addresses();
            if err_count < seeders.len() || !need_more {
                return;
            }

            // Wait out the backoff unless shutdown arrives first.
            match stopped.recv_timeout(backoff) {
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
            }
            if backoff < Duration::from_secs(10) {
                backoff = backoff.saturating_add(Duration::from_secs(1));
            }
        }
    });
    SeederBoot {
        stop,
        thread: Some(thread),
    }
}

/// Add a seeder's discovered addresses with the seeder's resolved IP
/// as their source, falling back to the first returned address when
/// the lookup fails right after succeeding (dcrd `querySeeders`'s
/// source selection).
fn add_seeded(
    addr_manager: &Arc<Mutex<AddrManager>>,
    seeder: &str,
    addrs: Vec<dcroxide_wire::NetAddress>,
) {
    const HTTPS_PORT: u16 = 443;
    let addresses = crate::server::wire_to_addrmgr_net_addresses(&addrs);
    let src = (seeder, HTTPS_PORT)
        .to_socket_addrs()
        .ok()
        .and_then(|mut ips| ips.next())
        .and_then(|socket| {
            crate::peerconn::net_address_from_socket(socket, Default::default()).ok()
        })
        .map(|wire| crate::server::wire_to_addrmgr_net_address(&wire))
        .unwrap_or_else(|| addresses[0].clone());
    addr_manager
        .lock()
        .expect("addrmgr mutex poisoned")
        .add_addresses(&addresses, &src);
}

/// The interval between periodic address-book dumps (dcrd addrmgr
/// `dumpAddressInterval`).
pub const DUMP_ADDRESS_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// The running address-book dump ticker; dropping the stop sender
/// through [`AddressDump::shutdown`] ends the loop.
pub struct AddressDump {
    stop: mpsc::Sender<()>,
    join: Option<JoinHandle<()>>,
}

impl AddressDump {
    /// Stop the ticker and wait for it (the daemon's final `savePeers`
    /// runs separately at shutdown, like dcrd's address handler saving
    /// once more after its loop breaks).
    pub fn shutdown(mut self) {
        let _ = self.stop.send(());
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Start the periodic address-book dump (the ticker half of dcrd
/// addrmgr's `addressHandler`): every interval the shared manager
/// saves its peers file — a no-op when nothing changed, exactly
/// dcrd's `savePeers` dirty gate.
pub fn start_address_dump(
    addr_manager: Arc<Mutex<AddrManager>>,
    interval: Duration,
) -> AddressDump {
    let (stop, stopped) = mpsc::channel::<()>();
    let join = thread::spawn(move || {
        // A stop signal or a dropped sender ends the loop; a timeout
        // is the tick.
        while let Err(mpsc::RecvTimeoutError::Timeout) = stopped.recv_timeout(interval) {
            if let Err(e) = addr_manager
                .lock()
                .expect("addr manager mutex poisoned")
                .save_peers()
            {
                // dcrd's savePeers logs and carries on.
                crate::logging::error("AMGR", &format!("Unable to save peers: {e}"));
            }
        }
    });
    AddressDump {
        stop,
        join: Some(join),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deadline far enough out that the parse tests never hit it.
    fn far_deadline() -> Instant {
        Instant::now()
            .checked_add(Duration::from_secs(60))
            .expect("deadline")
    }

    #[test]
    fn seeder_url_splits_scheme_host_port_path() {
        let u = parse_seeder_url("https://dnsseed.decred.org/api/addrs?services=1").expect("url");
        assert!(u.tls);
        assert_eq!(u.host, "dnsseed.decred.org");
        assert_eq!(u.port, 443, "https defaults to 443");
        assert_eq!(u.path_and_query, "/api/addrs?services=1");

        let u = parse_seeder_url("http://seed.example:8080/x").expect("url");
        assert!(!u.tls);
        assert_eq!(u.host, "seed.example");
        assert_eq!(u.port, 8080);

        // No path defaults to "/", and http defaults to 80.
        let u = parse_seeder_url("http://seed.example").expect("url");
        assert_eq!(u.port, 80);
        assert_eq!(u.path_and_query, "/");

        assert!(parse_seeder_url("ftp://seed.example/").is_err());
        assert!(parse_seeder_url("no-scheme").is_err());
    }

    #[test]
    fn http_response_reads_status_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"a\":1}";
        let (status, body) = read_http_response(&raw[..], far_deadline()).expect("parse");
        assert_eq!(status, 200);
        assert_eq!(body, b"{\"a\":1}");

        // A non-200 status is surfaced (the seeder logic inspects it).
        let raw = b"HTTP/1.1 503 Service Unavailable\r\n\r\n";
        let (status, body) = read_http_response(&raw[..], far_deadline()).expect("parse");
        assert_eq!(status, 503);
        assert!(body.is_empty());

        // A response with no header terminator is an error, not a panic.
        assert!(read_http_response(&b"garbage"[..], far_deadline()).is_err());
    }
}
