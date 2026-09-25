// SPDX-License-Identifier: ISC
//! The RPC server's HTTP framing against dcrd's, end to end over a
//! real listener: what Go's connection loop does before any handler
//! runs (`Expect`), how the mux's own answers close, how dcrd's hijacked
//! writer frames the JSON-RPC reply, how a malformed chunked body is
//! answered, and how a TLS session ends.
//!
//! - A non-empty `Expect` other than `100-continue` is refused 417
//!   before routing, and `100-continue` is answered with the interim
//!   response when the handler reads the body -- which the 401 and 503
//!   never do.  The port ignored the header.
//! - The mux's 307, the asterisk answers, the CONNECT 404 and the `/ws`
//!   401 discard the declared body before closing, as the handlers'
//!   own errors already did, so the close does not reset the answer.
//! - The JSON-RPC reply mirrors the request's protocol and carries only
//!   `Connection` and `Content-Type`, running to the close.
//! - A chunked body Go's reader refuses is answered with its error.
//! - Every answer written through Go's `ResponseWriter` mirrors an
//!   HTTP/1.0 request's protocol, and a HEAD gets no body -- nor, when
//!   the answer has none, a `Content-Length`.
//! - A TLS session ends with `close_notify`, so a reply framed by the
//!   close reads as complete.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};
use dcroxide_node::rpcrun::{
    NodeRpcChain, NodeRpcConnManager, NodeRpcSyncManager, RpcListener, RpcTransport,
    load_or_generate_cert_pair, reloadable_tls_config, start_rpc_listener,
};
use dcroxide_node::runtime::ConnectedPeers;
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::server::{Config, Server};
use dcroxide_standalone::SubsidyCache;
use dcroxide_wire::PROTOCOL_VERSION;

/// A server over a fresh genesis testnet chain.
fn server() -> (tempfile::TempDir, Arc<Server<NodeRpcChain>>) {
    let params = dcroxide_chaincfg::testnet3_params();
    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    );
    let sync_manager = Arc::new(Mutex::new(dcroxide_node::sync::new_sync_manager(
        Arc::clone(&chain),
        &params,
        false,
        8,
        1000,
        Arc::clone(&tx_pool),
        dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone(), &tx_pool),
    )));
    let server = Arc::new(Server::new(Config {
        chain: NodeRpcChain::new(chain, params.clone()),
        chain_params: params.clone(),
        subsidy_cache: std::sync::Mutex::new(SubsidyCache::new(params.clone())),
        min_relay_tx_fee: 10000,
        max_protocol_version: PROTOCOL_VERSION,
        sync_mgr: Box::new(NodeRpcSyncManager::new(sync_manager, Arc::clone(&tx_pool))),
        conn_mgr: Box::new(NodeRpcConnManager::new(
            ConnectedPeers::new(),
            Arc::new(dcroxide_node::transport::NetByteTotals::new()),
        )),
        client_cert_auth: false,
        tx_mempooler: Box::new(dcroxide_node::txmempool::NodeRpcTxMempooler::new(tx_pool)),
        clock: Box::new(dcroxide_node::rpcrun::SystemClock),
        interfaces: Box::new(NoInterfaces),
        rand_u64: Box::new(|| 7),
        tx_indexer: None,
        db: Box::new(()),
        filterer_v2: Box::new(()),
        exists_addresser: None,
        log_manager: Box::new(()),
        fee_estimator: Box::new(()),
        block_templater: None,
        sanity_checker: Box::new(()),
        time_source: Box::new(dcroxide_node::rpcrun::SystemTimeSource),
        proxy: String::new(),
        test_net: true,
        runtime_version: String::new(),
        cpu_miner: Box::new(()),
        mix_pooler: Box::new(()),
        profiler_mgr: Box::new(()),
        addr_manager: Box::new(()),
        mining_addrs: Vec::new(),
        user_agent_version: "0.1.0".to_string(),
        net_info: Vec::new(),
        services: 0,
        request_shutdown: Box::new(|| {}),
        allow_unsynced_mining: false,
        rpc_user: "user".to_string(),
        rpc_pass: "pass".to_string(),
        rpc_limit_user: String::new(),
        rpc_limit_pass: String::new(),
    }));
    (dir, server)
}

/// Start a listener on loopback over the given transport, returning it
/// with its port.
fn listen(server: &Arc<Server<NodeRpcChain>>, transport: RpcTransport) -> (RpcListener, u16) {
    let listener = start_rpc_listener(
        &["127.0.0.1:0".to_string()],
        Arc::clone(server),
        transport,
        dcroxide_node::websocket::NodeNtfnMgr::new(),
        128,
    )
    .expect("listen");
    let port = listener.bound_addrs()[0].port();
    (listener, port)
}

/// The Basic credentials the test server accepts.
fn auth() -> String {
    dcroxide_rpc::http::base64_std_encode(b"user:pass")
}

/// A `getblockcount` request body.
const BODY: &str = r#"{"jsonrpc":"1.0","id":1,"method":"getblockcount","params":[]}"#;

/// Send the raw request and read the reply to its end, with how the
/// connection ended: `Ok` for a clean close, an error for a reset.
fn exchange(port: u16, request: &[u8]) -> (String, std::io::Result<usize>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.write_all(request).expect("write");
    let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
    let mut response = Vec::new();
    let ended = stream.read_to_end(&mut response);
    (String::from_utf8_lossy(&response).into_owned(), ended)
}

/// Read until the blank line that ends a response head, or the timeout.
fn read_head(stream: &mut TcpStream) -> String {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// Go answers a non-empty expectation other than `100-continue` with a
/// 417 before any routing -- on `/`, `/ws` and `OPTIONS *` alike, with
/// the request's protocol in the status line -- and consults only the
/// first `Expect` copy.  Each answer is a real server's.
#[test]
fn an_unmet_expectation_is_refused_before_routing() {
    let (_dir, server) = server();
    let (listener, port) = listen(&server, RpcTransport::Plain);
    let expect_417 = |request: String, proto: &str| {
        let (response, ended) = exchange(port, request.as_bytes());
        assert!(
            response.starts_with(&format!(
                "{proto} 417 Expectation Failed\r\nConnection: close\r\nDate: "
            )),
            "{request:?}: {response:?}"
        );
        assert!(
            response.ends_with("\r\nContent-Length: 0\r\n\r\n"),
            "{response:?}"
        );
        assert!(ended.is_ok(), "{request:?} closed cleanly: {ended:?}");
    };
    let auth = auth();
    expect_417(
        format!(
            "POST / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {auth}\r\nExpect: foo\r\nContent-Length: {}\r\n\r\n{BODY}",
            BODY.len()
        ),
        "HTTP/1.1",
    );
    expect_417(
        format!(
            "POST / HTTP/1.0\r\nAuthorization: Basic {auth}\r\nExpect: foo\r\nContent-Length: {}\r\n\r\n{BODY}",
            BODY.len()
        ),
        "HTTP/1.0",
    );
    expect_417(
        "GET /ws HTTP/1.1\r\nHost: x\r\nExpect: foo\r\n\r\n".to_string(),
        "HTTP/1.1",
    );
    expect_417(
        "OPTIONS * HTTP/1.1\r\nHost: x\r\nExpect: foo\r\n\r\n".to_string(),
        "HTTP/1.1",
    );

    // Only the first copy counts, and an empty one expects nothing.
    let (response, _) = exchange(
        port,
        format!(
            "POST / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {auth}\r\nExpect:\r\nExpect: foo\r\nContent-Length: {}\r\n\r\n{BODY}",
            BODY.len()
        )
        .as_bytes(),
    );
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response:?}");
    listener.shutdown();
}

/// `Expect: 100-continue` gets the interim response once the handler
/// goes to read the body, so a client holding its body back until then
/// (curl above its threshold, .NET's `HttpWebRequest`) sends it at once
/// rather than after its own timeout -- in either framing.  An answer
/// that never reads the body never sends it.
#[test]
fn continue_is_sent_when_the_body_is_read() {
    let (_dir, server) = server();
    let (listener, port) = listen(&server, RpcTransport::Plain);
    let auth = auth();
    let chunked = format!("{:x}\r\n{BODY}\r\n0\r\n\r\n", BODY.len());
    for (framing, body) in [
        (format!("Content-Length: {}", BODY.len()), BODY.to_string()),
        ("Transfer-Encoding: chunked".to_string(), chunked),
    ] {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        write!(
            stream,
            "POST / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {auth}\r\nExpect: 100-continue\r\n{framing}\r\n\r\n"
        )
        .expect("write the head");
        assert_eq!(
            read_head(&mut stream),
            "HTTP/1.1 100 Continue\r\n\r\n",
            "{framing}: the interim response comes before the body is sent"
        );
        stream.write_all(body.as_bytes()).expect("write the body");
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "{framing}: {response:?}"
        );
        assert!(response.contains(r#""result":0"#), "{response:?}");
    }

    // The 401 answers without reading, so no interim response precedes it.
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    write!(
        stream,
        "POST / HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: {}\r\n\r\n",
        BODY.len()
    )
    .expect("write the head");
    assert!(
        read_head(&mut stream).starts_with("HTTP/1.1 401 Unauthorized\r\n"),
        "the 401 comes first"
    );
    listener.shutdown();
}

/// Every answer the mux gives itself discards the declared body before
/// the close, so a body that arrived with the head does not turn the
/// close into a reset that takes the answer with it.  The 307 is the
/// realistic case: a client whose base URL ends in `/` posting to `//`.
#[test]
fn mux_answers_discard_the_declared_body() {
    let (_dir, server) = server();
    let (listener, port) = listen(&server, RpcTransport::Plain);
    let bad_auth = dcroxide_rpc::http::base64_std_encode(b"foo:bar");
    for (request_line, extra, status) in [
        ("POST // HTTP/1.1", "", "307 Temporary Redirect"),
        ("OPTIONS * HTTP/1.1", "", "200 OK"),
        ("GET * HTTP/1.1", "", "400 Bad Request"),
        ("CONNECT h:443 HTTP/1.1", "", "404 Not Found"),
        (
            "GET /ws HTTP/1.1",
            &*format!("Authorization: Basic {bad_auth}\r\n"),
            "401 Unauthorized",
        ),
    ] {
        let request = format!(
            "{request_line}\r\nHost: localhost\r\n{extra}Content-Length: {}\r\n\r\n{BODY}",
            BODY.len()
        );
        let (response, ended) = exchange(port, request.as_bytes());
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status}\r\n")),
            "{request_line}: {response:?}"
        );
        assert!(
            ended.is_ok(),
            "{request_line}: the body was left unread and the close reset: {ended:?}"
        );
    }
    listener.shutdown();
}

/// dcrd writes the JSON-RPC reply by hand on the hijacked connection:
/// the request's protocol in the status line, the handler's
/// `Connection` and `Content-Type`, and the body to the close -- no
/// `Date`, no `Content-Length`.
#[test]
fn the_json_reply_is_framed_as_dcrds_hijacked_writer_frames_it() {
    let (_dir, server) = server();
    let (listener, port) = listen(&server, RpcTransport::Plain);
    let auth = auth();
    for (proto, host) in [("HTTP/1.1", "Host: x\r\n"), ("HTTP/1.0", "")] {
        let (response, _) = exchange(
            port,
            format!(
                "POST / {proto}\r\n{host}Authorization: Basic {auth}\r\nContent-Length: {}\r\n\r\n{BODY}",
                BODY.len()
            )
            .as_bytes(),
        );
        let expected = format!(
            "{proto} 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n{{"
        );
        assert!(response.starts_with(&expected), "{response:?}");
        assert!(response.ends_with("}\n"), "{response:?}");
    }
    listener.shutdown();
}

/// A chunked body Go's reader refuses is answered with that reader's
/// error, as dcrd answers any failed body read.  It was a generic
/// "invalid chunked body", or no refusal at all for a bare-LF line.
#[test]
fn a_refused_chunked_body_is_answered_with_gos_error() {
    let (_dir, server) = server();
    let (listener, port) = listen(&server, RpcTransport::Plain);
    let (response, _) = exchange(
        port,
        format!(
            "POST / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {}\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\n{BODY}\r\n0\r\n\r\n",
            auth(),
            BODY.len()
        )
        .as_bytes(),
    );
    assert!(
        response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
        "{response:?}"
    );
    assert!(
        response
            .ends_with("\r\n\r\n400 error reading JSON message: chunked line ends with bare LF\n"),
        "{response:?}"
    );
    listener.shutdown();
}

/// The answers Go writes through its `ResponseWriter` follow the
/// request: an HTTP/1.0 request's status line says `HTTP/1.0`, a HEAD
/// keeps `http.Error`'s `Content-Length` but gets nothing after the
/// head, and a HEAD answered with no body at all -- the 417, the
/// asterisk 400 -- gets no `Content-Length` either.  Each shape is a
/// real server's.  The port said `HTTP/1.1` to everyone and sent a HEAD
/// the body.
#[test]
fn head_and_http_1_0_answers_are_shaped_as_gos() {
    let (_dir, server) = server();
    let (listener, port) = listen(&server, RpcTransport::Plain);
    let bad_auth = dcroxide_rpc::http::base64_std_encode(b"foo:bar");
    let head_only = |request: &str, status: &str, length: Option<&str>| {
        let (response, ended) = exchange(port, request.as_bytes());
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status}\r\n")),
            "{request:?}: {response:?}"
        );
        assert!(response.ends_with("\r\n\r\n"), "no body: {response:?}");
        match length {
            Some(length) => assert!(
                response.contains(&format!("\r\nContent-Length: {length}\r\n")),
                "{response:?}"
            ),
            None => assert!(!response.contains("Content-Length"), "{response:?}"),
        }
        assert!(ended.is_ok(), "{request:?}: {ended:?}");
    };
    head_only(
        "HEAD / HTTP/1.1\r\nHost: x\r\n\r\n",
        "401 Unauthorized",
        Some("18"),
    );
    head_only(
        &format!("HEAD /ws HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {bad_auth}\r\n\r\n"),
        "401 Unauthorized",
        Some("18"),
    );
    head_only(
        "HEAD / HTTP/1.1\r\nHost: x\r\nExpect: foo\r\n\r\n",
        "417 Expectation Failed",
        None,
    );
    head_only(
        "HEAD * HTTP/1.1\r\nHost: x\r\n\r\n",
        "400 Bad Request",
        None,
    );

    for (request, status) in [
        ("GET / HTTP/1.0\r\n\r\n".to_string(), "401 Unauthorized"),
        (
            format!("GET /ws HTTP/1.0\r\nAuthorization: Basic {bad_auth}\r\n\r\n"),
            "401 Unauthorized",
        ),
        (
            "GET // HTTP/1.0\r\n\r\n".to_string(),
            "307 Temporary Redirect",
        ),
        ("OPTIONS * HTTP/1.0\r\n\r\n".to_string(), "200 OK"),
        ("GET * HTTP/1.0\r\n\r\n".to_string(), "400 Bad Request"),
        (
            "CONNECT h:443 HTTP/1.0\r\n\r\n".to_string(),
            "404 Not Found",
        ),
    ] {
        let (response, _) = exchange(port, request.as_bytes());
        assert!(
            response.starts_with(&format!("HTTP/1.0 {status}\r\n")),
            "{request:?}: {response:?}"
        );
    }
    // The connection loop's own errors say HTTP/1.1 whatever was asked.
    let (response, _) = exchange(port, b"GET / HTTP/1.0\r\nFoo\r\n\r\n");
    assert!(
        response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
        "{response:?}"
    );
    listener.shutdown();
}

/// Any certificate will do: the test is about how the session ends.
#[derive(Debug)]
struct AnyCertificate;

impl rustls::client::danger::ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Over TLS every reply ends with a `close_notify`, as Go's
/// `tls.Conn.Close` ends it -- the JSON-RPC reply and the connection
/// loop's errors, both framed by the close.  A strict TLS client (rustls
/// here, OpenSSL in curl) read the bare FIN it got instead as a
/// truncated body.
#[test]
fn tls_replies_end_with_close_notify() {
    let (_dir, server) = server();
    let certs = tempfile::tempdir().expect("temp dir");
    let cert = certs.path().join("rpc.cert");
    let key = certs.path().join("rpc.key");
    load_or_generate_cert_pair(&cert, &key, &[], dcroxide_certgen::Curve::P256)
        .expect("a cert pair");
    let tls = reloadable_tls_config(&cert, &key, None, Duration::ZERO).expect("a TLS config");
    let (listener, port) = listen(&server, RpcTransport::Tls(tls));
    let client_config = Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCertificate))
        .with_no_client_auth(),
    );
    let auth = auth();
    for (request, status) in [
        (
            format!(
                "POST / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {auth}\r\nContent-Length: {}\r\n\r\n{BODY}",
                BODY.len()
            ),
            "HTTP/1.1 200 OK\r\n",
        ),
        (
            "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n".to_string(),
            "HTTP/1.1 501 Not Implemented\r\n",
        ),
    ] {
        let sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let _ = sock.set_read_timeout(Some(Duration::from_secs(20)));
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
        let session =
            rustls::ClientConnection::new(Arc::clone(&client_config), name).expect("a session");
        let mut tls = rustls::StreamOwned::new(session, sock);
        tls.write_all(request.as_bytes()).expect("write");
        let mut response = Vec::new();
        let ended = tls.read_to_end(&mut response);
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with(status), "{response:?}");
        assert!(ended.is_ok(), "the reply was cut off: {ended:?}");
    }
    listener.shutdown();
}
