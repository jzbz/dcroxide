// SPDX-License-Identifier: ISC
//! Checks for the seeder bootstrap driver: a scripted seeder response
//! lands its discovered addresses in the address manager, and a failing
//! seeder round retries with backoff until shutdown.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dcroxide_addrmgr::{AddrManager, NetAddressType};
use dcroxide_connmgr::SeederTransport;
use dcroxide_node::seeding::start_seeding;

/// A transport answering every request with the scripted body.
struct ScriptedTransport {
    status: u32,
    body: Vec<u8>,
    calls: Arc<AtomicUsize>,
}

impl SeederTransport for ScriptedTransport {
    fn get(&mut self, _url: &str) -> Result<(u32, Vec<u8>), String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok((self.status, self.body.clone()))
    }
}

#[test]
fn seeded_addresses_land_in_the_manager() {
    let dir = tempfile::tempdir().expect("temp dir");
    let addr_manager = Arc::new(Mutex::new(AddrManager::new(dir.path())));

    // Two routable nodes in the seeder's JSON stream shape.
    let body = br#"{"host":"8.8.8.5:19108","services":1,"pver":6}
{"host":"8.8.7.5:19108","services":1,"pver":6}"#
        .to_vec();
    let calls = Arc::new(AtomicUsize::new(0));
    let transport_calls = Arc::clone(&calls);

    let boot = start_seeding(
        vec!["192.0.2.10".to_string()],
        Arc::clone(&addr_manager),
        1,
        move || ScriptedTransport {
            status: 200,
            body: body.clone(),
            calls: Arc::clone(&transport_calls),
        },
    );

    // The discovered addresses appear in the manager and the round
    // finishes without retrying.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut known = 0;
    while known < 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
        // One lock per statement: both guards alive in one expression
        // would self-deadlock on the non-reentrant mutex.
        let mgr = addr_manager.lock().expect("addrmgr");
        known = mgr.known_address("8.8.8.5:19108").is_some() as usize
            + mgr.known_address("8.8.7.5:19108").is_some() as usize;
    }
    assert_eq!(known, 2, "both seeded addresses should be known");

    boot.shutdown();
    assert_eq!(calls.load(Ordering::SeqCst), 1, "one successful round");
    let _ = NetAddressType::IPv4;
}

#[test]
fn failing_seeders_retry_until_shutdown() {
    let dir = tempfile::tempdir().expect("temp dir");
    let addr_manager = Arc::new(Mutex::new(AddrManager::new(dir.path())));

    let calls = Arc::new(AtomicUsize::new(0));
    let transport_calls = Arc::clone(&calls);
    let boot = start_seeding(
        vec!["192.0.2.10".to_string()],
        Arc::clone(&addr_manager),
        1,
        move || ScriptedTransport {
            status: 500,
            body: Vec::new(),
            calls: Arc::clone(&transport_calls),
        },
    );

    // The failing round retries on the backoff; after a bit more than
    // a second at least a second attempt has run.
    let deadline = Instant::now() + Duration::from_secs(5);
    while calls.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(calls.load(Ordering::SeqCst) >= 2, "the round should retry");

    // Shutdown interrupts the backoff wait promptly.
    let start = Instant::now();
    boot.shutdown();
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "shutdown should interrupt the backoff"
    );
}

/// The periodic address-book dump: the ticker saves a changed manager
/// to peers.json without waiting for shutdown, and the handle stops
/// the loop cleanly.
#[test]
fn periodic_dump_writes_the_peers_file() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut mgr = dcroxide_addrmgr::AddrManager::new(dir.path());
    // A routable address marks the book dirty so the dirty gate lets
    // the save through.
    let na = dcroxide_addrmgr::new_net_address_from_ip_port(
        &[8, 8, 8, 8],
        9108,
        dcroxide_wire::ServiceFlag(0),
        2_000_000_000,
    );
    mgr.add_addresses(core::slice::from_ref(&na), &na);
    let mgr = std::sync::Arc::new(std::sync::Mutex::new(mgr));

    let dump = dcroxide_node::seeding::start_address_dump(
        std::sync::Arc::clone(&mgr),
        std::time::Duration::from_millis(50),
    );
    let peers = dir.path().join("peers.json");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !peers.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(peers.exists(), "the ticker must dump the address book");
    dump.shutdown();
}

/// A one-shot plain-HTTP server that records the request line and Host
/// header and answers with the given status and body.  Returns its
/// bound address and an observation channel.
fn fake_http_server(
    status_line: &'static str,
    body: &'static str,
) -> (String, std::sync::mpsc::Receiver<String>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind http");
    let addr = listener.local_addr().expect("addr").to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept");
        conn.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        // Read the request head up to the blank line.
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while conn.read(&mut byte).map(|n| n == 1).unwrap_or(false) {
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let _ = tx.send(String::from_utf8_lossy(&buf).into_owned());
        let response = format!(
            "{status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = conn.write_all(response.as_bytes());
    });
    (addr, rx)
}

/// A one-shot anonymous fake SOCKS5 proxy that bridges to the CONNECT
/// target.  Returns the bound address.
fn fake_socks5_bridge() -> String {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let addr = listener.local_addr().expect("addr").to_string();
    std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept");
        // Greeting.
        let mut head = [0u8; 2];
        conn.read_exact(&mut head).expect("greeting");
        let mut methods = vec![0u8; head[1] as usize];
        conn.read_exact(&mut methods).expect("methods");
        conn.write_all(&[5, 0]).expect("auth none");
        // CONNECT over a domain address.
        let mut req = [0u8; 5];
        conn.read_exact(&mut req).expect("request");
        assert_eq!(&req[..4], &[5, 1, 0, 3], "domain connect");
        let mut host = vec![0u8; req[4] as usize];
        conn.read_exact(&mut host).expect("host");
        let mut port = [0u8; 2];
        conn.read_exact(&mut port).expect("port");
        let dest = format!(
            "{}:{}",
            String::from_utf8_lossy(&host),
            u16::from_be_bytes(port)
        );
        conn.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
            .expect("reply");
        // Bridge, propagating each side's EOF as a write shutdown so a
        // read-to-EOF client (the seeder transport) unblocks.
        let upstream = std::net::TcpStream::connect(dest).expect("connect upstream");
        let mut up_read = upstream.try_clone().expect("clone");
        let mut down_write = conn.try_clone().expect("clone");
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut up_read, &mut down_write);
            let _ = down_write.shutdown(std::net::Shutdown::Write);
        });
        let mut up_write = upstream.try_clone().expect("clone");
        let _ = std::io::copy(&mut conn, &mut up_write);
        let _ = up_write.shutdown(std::net::Shutdown::Write);
    });
    addr
}

/// The proxy seeder transport dials directly, formats the GET, and
/// parses the response over plain HTTP.
#[test]
fn proxy_transport_direct_http_round_trip() {
    let (server, requests) = fake_http_server("HTTP/1.1 200 OK", "{\"seed\":true}");
    let mut transport = dcroxide_node::seeding::ProxySeederTransport::new(
        dcroxide_node::socks::NodeDialer::direct(),
    );
    let (status, body) = transport
        .get(&format!("http://{server}/api/addrs?services=1"))
        .expect("seeder request");
    assert_eq!(status, 200);
    assert_eq!(body, b"{\"seed\":true}");
    let req = requests.recv().expect("request");
    assert!(
        req.starts_with("GET /api/addrs?services=1 HTTP/1.1"),
        "req: {req}"
    );
    assert!(req.contains(&format!("Host: {server}")), "req: {req}");
}

/// With a proxy configured, the seeder transport routes its HTTP
/// request through the SOCKS proxy rather than dialing the seeder
/// directly (dcrd's seeder-over-dcrdDial behavior).
#[test]
fn proxy_transport_routes_through_the_socks_proxy() {
    let (server, requests) = fake_http_server("HTTP/1.1 200 OK", "[]");
    let proxy = fake_socks5_bridge();

    let mut cfg = dcroxide_node::config::Config::defaults("/tmp/dcrd-home");
    cfg.dial = dcroxide_node::config::DialSelection::SocksProxy;
    cfg.proxy = proxy;
    let dialer = dcroxide_node::socks::NodeDialer::from_config(&cfg);

    let mut transport = dcroxide_node::seeding::ProxySeederTransport::new(dialer);
    let (status, body) = transport
        .get(&format!("http://{server}/addrs"))
        .expect("seeder request through the proxy");
    assert_eq!(status, 200);
    assert_eq!(body, b"[]");
    // The request reached the origin server through the proxy bridge.
    let req = requests.recv().expect("request via proxy");
    assert!(req.starts_with("GET /addrs HTTP/1.1"), "req: {req}");
}
