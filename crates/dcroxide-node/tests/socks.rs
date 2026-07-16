// SPDX-License-Identifier: ISC
//! Checks for the SOCKS5 dial and Tor resolution over in-process fake
//! proxies: the handshake forms (anonymous, username/password, and
//! Tor isolation's per-connection random credentials), go-socks'
//! error texts, the Tor RESOLVE exchange with dcrd's error table, and
//! the dcrdDial/dcrdLookup routing rules including --noonion.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::Duration;

use dcroxide_node::socks::{NodeDialer, Proxy, tor_lookup_ip};

const TIMEOUT: Duration = Duration::from_secs(5);

/// What one fake SOCKS5 session observed.
#[derive(Debug, Default)]
struct Observed {
    methods: Vec<u8>,
    username: String,
    password: String,
    host: String,
    port: u16,
}

/// A single-connection fake SOCKS5 proxy: negotiates with the given
/// auth method, optionally records credentials, replies with the
/// given status, and on success bridges the stream to the requested
/// destination.  Returns the bound proxy address and the observation
/// channel.
fn fake_socks5(auth_reply: u8, status: u8) -> (String, mpsc::Receiver<Observed>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
    let addr = listener.local_addr().expect("addr").to_string();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept");
        conn.set_read_timeout(Some(TIMEOUT)).expect("timeout");
        let mut observed = Observed::default();

        // Greeting: version, method count, methods.
        let mut head = [0u8; 2];
        conn.read_exact(&mut head).expect("greeting head");
        assert_eq!(head[0], 5, "socks version");
        let mut methods = vec![0u8; head[1] as usize];
        conn.read_exact(&mut methods).expect("methods");
        observed.methods = methods;
        conn.write_all(&[5, auth_reply]).expect("auth choice");

        if auth_reply == 2 {
            // RFC 1929 username/password sub-negotiation.
            let mut head = [0u8; 2];
            conn.read_exact(&mut head).expect("auth head");
            assert_eq!(head[0], 1, "auth version");
            let mut user = vec![0u8; head[1] as usize];
            conn.read_exact(&mut user).expect("user");
            let mut plen = [0u8; 1];
            conn.read_exact(&mut plen).expect("plen");
            let mut pass = vec![0u8; plen[0] as usize];
            conn.read_exact(&mut pass).expect("pass");
            observed.username = String::from_utf8_lossy(&user).into_owned();
            observed.password = String::from_utf8_lossy(&pass).into_owned();
            // Reject the fixed credentials "bad"/"bad".
            let ok = observed.username != "bad";
            conn.write_all(&[1, if ok { 0 } else { 1 }])
                .expect("auth status");
            if !ok {
                let _ = tx.send(observed);
                return;
            }
        }
        if auth_reply == 0xff {
            let _ = tx.send(observed);
            return;
        }

        // The connect request over a domain address.
        let mut head = [0u8; 5];
        conn.read_exact(&mut head).expect("request head");
        assert_eq!(&head[..4], &[5, 1, 0, 3], "domain connect");
        let mut host = vec![0u8; head[4] as usize];
        conn.read_exact(&mut host).expect("host");
        let mut port = [0u8; 2];
        conn.read_exact(&mut port).expect("port");
        observed.host = String::from_utf8_lossy(&host).into_owned();
        observed.port = u16::from_be_bytes(port);

        // The reply with an IPv4 bound address.
        conn.write_all(&[5, status, 0, 1, 127, 0, 0, 1, 0, 0])
            .expect("reply");
        let dest = format!("{}:{}", observed.host, observed.port);
        let _ = tx.send(observed);
        if status != 0 {
            return;
        }

        // Bridge to the destination.
        let upstream = TcpStream::connect(dest).expect("connect upstream");
        let mut up_read = upstream.try_clone().expect("clone");
        let mut down_write = conn.try_clone().expect("clone");
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut up_read, &mut down_write);
        });
        let mut up_write = upstream;
        let _ = std::io::copy(&mut conn, &mut up_write);
    });
    (addr, rx)
}

/// An echo listener: accepts one connection and echoes what arrives.
fn echo_listener() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
    let addr = listener.local_addr().expect("addr").to_string();
    std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 16];
        let n = conn.read(&mut buf).expect("read");
        conn.write_all(&buf[..n]).expect("echo");
    });
    addr
}

/// An anonymous dial completes the handshake, carries the destination
/// as a domain request, and the stream reaches the target.
#[test]
fn anonymous_proxy_dial_bridges_to_the_destination() {
    let echo = echo_listener();
    let (proxy_addr, observed) = fake_socks5(0, 0);
    let proxy = Proxy {
        addr: proxy_addr,
        ..Proxy::default()
    };
    let mut conn = proxy.dial(&echo, TIMEOUT).expect("proxied dial");
    conn.write_all(b"ping").expect("write");
    let mut reply = [0u8; 4];
    conn.read_exact(&mut reply).expect("read");
    assert_eq!(&reply, b"ping", "the bridge must reach the echo target");

    let seen = observed.recv().expect("observation");
    assert_eq!(seen.methods, vec![0], "anonymous offers authNone only");
    let (host, port) = echo.rsplit_once(':').expect("addr");
    assert_eq!(seen.host, host);
    assert_eq!(seen.port, port.parse::<u16>().expect("port"));
}

/// A proxy given by hostname resolves like Go's net.Dialer (Tor's
/// default `localhost:9050` form), not only as a numeric address.
#[test]
fn hostname_proxy_resolves() {
    let echo = echo_listener();
    let (proxy_addr, observed) = fake_socks5(0, 0);
    // Swap the numeric host for "localhost" on the same port.
    let port = proxy_addr.rsplit_once(':').expect("addr").1;
    let named = format!("localhost:{port}");
    let proxy = Proxy {
        addr: named,
        ..Proxy::default()
    };
    let mut conn = proxy.dial(&echo, TIMEOUT).expect("named proxy dial");
    conn.write_all(b"hi").expect("write");
    let mut reply = [0u8; 2];
    conn.read_exact(&mut reply).expect("read");
    assert_eq!(&reply, b"hi");
    assert!(
        observed.recv().is_ok(),
        "the named proxy handled the session"
    );
}

/// Credentials negotiate RFC 1929 and reach the proxy; Tor isolation
/// replaces them with fresh 16-hex-character pairs per connection.
#[test]
fn credentials_and_tor_isolation() {
    // Fixed credentials.
    let echo = echo_listener();
    let (proxy_addr, observed) = fake_socks5(2, 0);
    let proxy = Proxy {
        addr: proxy_addr,
        username: "user".to_string(),
        password: "pass".to_string(),
        tor_isolation: false,
    };
    proxy.dial(&echo, TIMEOUT).expect("authenticated dial");
    let seen = observed.recv().expect("observation");
    assert_eq!(seen.methods, vec![0, 2], "credentials offer both methods");
    assert_eq!(
        (seen.username.as_str(), seen.password.as_str()),
        ("user", "pass")
    );

    // Tor isolation: two dials draw two distinct random pairs.
    let mut pairs = Vec::new();
    for _ in 0..2 {
        let echo = echo_listener();
        let (proxy_addr, observed) = fake_socks5(2, 0);
        let proxy = Proxy {
            addr: proxy_addr,
            username: "ignored".to_string(),
            password: "ignored".to_string(),
            tor_isolation: true,
        };
        proxy.dial(&echo, TIMEOUT).expect("isolated dial");
        let seen = observed.recv().expect("observation");
        assert_eq!(seen.username.len(), 16, "8 random bytes as hex");
        assert_eq!(seen.password.len(), 16);
        assert_ne!(seen.username, "ignored", "isolation overrides credentials");
        pairs.push((seen.username, seen.password));
    }
    assert_ne!(
        pairs[0], pairs[1],
        "isolation draws per-connection credentials"
    );
}

/// go-socks' error texts: a rejected authentication, an unacceptable
/// method, and a refused connection status.
#[test]
fn proxy_error_texts() {
    let (proxy_addr, _observed) = fake_socks5(2, 0);
    let proxy = Proxy {
        addr: proxy_addr,
        username: "bad".to_string(),
        password: "bad".to_string(),
        tor_isolation: false,
    };
    assert_eq!(
        proxy.dial("127.0.0.1:1", TIMEOUT).err(),
        Some("authentication failed".to_string())
    );

    let (proxy_addr, _observed) = fake_socks5(0xff, 0);
    let proxy = Proxy {
        addr: proxy_addr,
        ..Proxy::default()
    };
    assert_eq!(
        proxy.dial("127.0.0.1:1", TIMEOUT).err(),
        Some("no acceptable authentication method".to_string())
    );

    let (proxy_addr, _observed) = fake_socks5(0, 5);
    let proxy = Proxy {
        addr: proxy_addr,
        ..Proxy::default()
    };
    assert_eq!(
        proxy.dial("127.0.0.1:1", TIMEOUT).err(),
        Some("connection refused by destination host".to_string())
    );
}

/// A fake Tor RESOLVE responder: verifies the RESOLVE request shape
/// and replies with the given status and IPv4 address.
fn fake_tor_resolver(status: u8, ip: [u8; 4]) -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind resolver");
    let addr = listener.local_addr().expect("addr").to_string();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept");
        conn.set_read_timeout(Some(TIMEOUT)).expect("timeout");
        let mut greeting = [0u8; 3];
        conn.read_exact(&mut greeting).expect("greeting");
        assert_eq!(greeting, [5, 1, 0]);
        conn.write_all(&[5, 0]).expect("auth choice");

        let mut head = [0u8; 5];
        conn.read_exact(&mut head).expect("request head");
        assert_eq!(head[0], 5);
        assert_eq!(head[1], 240, "the Tor RESOLVE command");
        assert_eq!(head[3], 3, "domain address type");
        let mut host = vec![0u8; head[4] as usize];
        conn.read_exact(&mut host).expect("host");
        let mut port = [0u8; 2];
        conn.read_exact(&mut port).expect("port");
        let _ = tx.send(String::from_utf8_lossy(&host).into_owned());

        conn.write_all(&[5, status, 0, 1]).expect("reply head");
        if status == 0 {
            // The address and port arrive as one read in dcrd.
            let mut payload = ip.to_vec();
            payload.extend_from_slice(&[0, 0]);
            conn.write_all(&payload).expect("address");
        }
    });
    (addr, rx)
}

/// Tor resolution round-trips an IPv4 answer and surfaces dcrd's
/// error table.
#[test]
fn tor_lookup_resolves_and_errors() {
    let (resolver, hosts) = fake_tor_resolver(0, [93, 184, 216, 34]);
    let ips = tor_lookup_ip("example.com", &resolver, TIMEOUT).expect("resolve");
    assert_eq!(
        ips,
        vec!["93.184.216.34".parse::<std::net::IpAddr>().expect("ip")]
    );
    assert_eq!(hosts.recv().expect("host"), "example.com");

    let (resolver, _hosts) = fake_tor_resolver(0x04, [0; 4]);
    assert_eq!(
        tor_lookup_ip("example.com", &resolver, TIMEOUT).err(),
        Some("tor host is unreachable".to_string())
    );
}

/// The dcrdDial/dcrdLookup routing: --noonion errors both onion
/// paths with dcrd's text, and an onion-specific proxy takes only the
/// .onion traffic while ordinary dials stay direct.
#[test]
fn onion_routing_rules() {
    // --noonion.
    let disabled = NodeDialer::from_config(&{
        let mut cfg = dcroxide_node::config::Config::defaults("/tmp/dcrd-home");
        cfg.onion = dcroxide_node::config::OnionSelection::Disabled;
        cfg
    });
    assert_eq!(
        disabled.dial("abcdef.onion:9108", TIMEOUT).err(),
        Some("tor has been disabled".to_string())
    );
    assert_eq!(
        disabled.lookup("abcdef.onion", TIMEOUT).err(),
        Some("tor has been disabled".to_string())
    );

    // An onion proxy takes .onion dials; ordinary dials stay direct.
    let echo = echo_listener();
    let (onion_proxy, observed) = fake_socks5(0, 0);
    let dialer = NodeDialer::from_config(&{
        let mut cfg = dcroxide_node::config::Config::defaults("/tmp/dcrd-home");
        cfg.onion = dcroxide_node::config::OnionSelection::OnionProxy;
        cfg.onion_proxy = onion_proxy;
        cfg
    });
    // The SOCKS handshake completes before any bridging, so the dial
    // succeeds and the routing shows in what the proxy observed: the
    // .onion name reaches the onion proxy verbatim (the proxy would
    // resolve it; the fake's bridge to a nonexistent name just dies
    // after the granted reply).
    let _conn = dialer
        .dial("expectedfailure.onion:9108", TIMEOUT)
        .expect("the onion dial routes through the onion proxy");
    let seen = observed.recv().expect("observation");
    assert_eq!(seen.host, "expectedfailure.onion");
    assert_eq!(seen.port, 9108);

    // Ordinary dials bypass the onion proxy entirely.
    let mut conn = dialer.dial(&echo, TIMEOUT).expect("direct dial");
    conn.write_all(b"ok").expect("write");
    let mut reply = [0u8; 2];
    conn.read_exact(&mut reply).expect("read");
    assert_eq!(&reply, b"ok");
}
