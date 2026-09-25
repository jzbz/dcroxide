// SPDX-License-Identifier: ISC
//! The RPC listener's binding, accept latency and body reading, against
//! dcrd's `setupRPCListeners`, Go's blocking accept and `jsonRPCRead`.
//!
//! - rpclisten addresses run through dcrd's `parseListeners`: an empty
//!   host listens on both families, a non-IP host is refused, a `tcp6`
//!   wildcard binds IPv6-only beside the `tcp4` one, and an address that
//!   cannot be bound is skipped with a warning -- startup fails only when
//!   none bound.  The listener used to bind each raw string with `?`.
//!   A `tcp6` listener carries `SO_REUSEADDR` as Go's does, so a restart
//!   rebinds over the TIME_WAIT its served connections leave.
//! - The accept loop wakes for an arrival instead of sleeping out a
//!   fixed 50 ms, which charged every sequential HTTP call that much.
//! - An authenticated body is cut at dcrd's 8 MiB limit and parsed, not
//!   refused with a plain-text 400, and one that is not UTF-8 is parsed
//!   the way Go's `encoding/json` parses the raw bytes.  What lies past
//!   the limit is then read, or left, as Go's `body.Close` reads it.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};
use dcroxide_node::rpcrun::{
    NodeRpcChain, NodeRpcConnManager, NodeRpcSyncManager, RpcListener, start_rpc_listener,
};
use dcroxide_node::runtime::ConnectedPeers;
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::server::{Config, Server};
use dcroxide_standalone::SubsidyCache;
use dcroxide_wire::PROTOCOL_VERSION;

/// dcrd `rpcReadLimitAuthenticated`.
const READ_LIMIT: usize = 1 << 23;

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

/// Start a plain-HTTP listener on the given addresses.
fn listen(server: &Arc<Server<NodeRpcChain>>, addrs: &[&str]) -> std::io::Result<RpcListener> {
    let addrs: Vec<String> = addrs.iter().map(|addr| addr.to_string()).collect();
    start_rpc_listener(
        &addrs,
        Arc::clone(server),
        dcroxide_node::rpcrun::RpcTransport::Plain,
        dcroxide_node::websocket::NodeNtfnMgr::new(),
        128,
    )
}

/// Send the raw request bytes and return the whole response.
fn exchange(port: u16, request: &[u8]) -> String {
    exchange_at(SocketAddr::from(([127, 0, 0, 1], port)), request)
}

/// Send the raw request bytes to `addr` and return the whole response.
fn exchange_at(addr: SocketAddr, request: &[u8]) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.write_all(request).expect("write");
    read_response(&mut stream).0
}

/// Read the response to its end, and how the connection ended: `Ok`
/// for the server's clean close, an error for a reset -- which is what
/// closing over unread request bytes sends.
fn read_response(stream: &mut TcpStream) -> (String, std::io::Result<usize>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
    let mut response = Vec::new();
    let ended = stream.read_to_end(&mut response);
    (String::from_utf8_lossy(&response).into_owned(), ended)
}

/// The request head for an authenticated POST with the given framing
/// header.
fn head(framing: &str) -> String {
    format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {}\r\n\
         Content-Type: application/json\r\n{framing}\r\nConnection: close\r\n\r\n",
        dcroxide_rpc::http::base64_std_encode(b"user:pass")
    )
}

/// As [`head`], without `Connection: close`: an HTTP/1.1 request that
/// leaves the connection open, as Go's `http.Client` sends by default.
fn keep_alive_head(framing: &str) -> String {
    head(framing).replace("Connection: close\r\n", "")
}

/// A `getblockcount` request padded with whitespace to exactly `len`
/// bytes, which is still one valid JSON document.
fn padded_request(len: usize) -> Vec<u8> {
    let mut body = br#"{"jsonrpc":"1.0","id":1,"method":"getblockcount","params":[]}"#.to_vec();
    body.resize(len, b' ');
    body
}

/// Whether this host can bind an IPv6 loopback socket at all.
fn have_ipv6() -> bool {
    TcpListener::bind("[::1]:0").is_ok()
}

/// A port nothing is listening on right now.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("ephemeral port")
        .port()
}

/// An empty host is dcrd's "all interfaces": `tcp4` and `tcp6` both
/// listen (the sample config documents `rpclisten=` and
/// `rpclisten=:9109`), where binding the raw `:port` string failed to
/// resolve and aborted startup.
#[test]
fn an_empty_host_listens_on_both_families() {
    let (_dir, server) = server();
    let listener = listen(&server, &[":0"]).expect("the wildcard listens");
    let bound = listener.bound_addrs().to_vec();
    assert!(
        bound
            .iter()
            .any(|addr| addr.ip().is_unspecified() && addr.is_ipv4()),
        "the tcp4 wildcard is bound: {bound:?}"
    );
    if have_ipv6() {
        assert!(
            bound
                .iter()
                .any(|addr| addr.ip().is_unspecified() && addr.is_ipv6()),
            "the tcp6 wildcard is bound: {bound:?}"
        );
    }
    listener.shutdown();
}

/// The two wildcards on one port coexist, because the `tcp6` one is
/// bound IPv6-only as Go's `net.Listen("tcp6", ...)` binds it.
#[test]
fn the_v4_and_v6_wildcards_share_a_port() {
    if !have_ipv6() {
        return;
    }
    let (_dir, server) = server();
    let port = free_port();
    let listener = listen(
        &server,
        &[&format!("0.0.0.0:{port}"), &format!("[::]:{port}")],
    )
    .expect("both wildcards listen");
    assert_eq!(
        listener.bound_addrs().len(),
        2,
        "{:?}",
        listener.bound_addrs()
    );
    listener.shutdown();
}

/// An IPv6 listener rebinds its port at once after a restart, while the
/// connections it served still sit in TIME_WAIT.  The server closes
/// first under `Connection: close`, so every call leaves one, and Go's
/// listeners (`setDefaultListenerSockopts`) and std's `TcpListener::bind`
/// set `SO_REUSEADDR` so it does not block the bind.  The `tcp6` bind
/// did not, so a quick restart lost the `::1` listener -- or failed to
/// start, when that was the only address.
#[cfg(not(windows))]
#[test]
fn a_restarted_v6_listener_rebinds_over_time_wait() {
    if !have_ipv6() {
        return;
    }
    let (_dir, server) = server();
    let listener = listen(&server, &["[::1]:0"]).expect("listen");
    let addr = listener.bound_addrs()[0];
    let response = exchange_at(
        addr,
        [head("Content-Length: 61").as_bytes(), &padded_request(61)]
            .concat()
            .as_slice(),
    );
    assert!(response.contains(r#""result":0"#), "{response}");
    listener.shutdown();

    let listener = listen(&server, &[&addr.to_string()]).expect("the port rebinds");
    assert_eq!(listener.bound_addrs(), [addr]);
    listener.shutdown();
}

/// One address that cannot be bound is skipped, as dcrd's
/// `setupRPCListeners` warns and continues; startup fails only when no
/// address bound, with dcrd's `no usable rpc listen addresses`.
#[test]
fn an_unbindable_address_is_skipped_unless_it_is_the_only_one() {
    let (_dir, server) = server();
    let busy = TcpListener::bind("127.0.0.1:0").expect("occupy a port");
    let busy_addr = busy.local_addr().expect("busy addr").to_string();

    let listener = listen(&server, &[&busy_addr, "127.0.0.1:0"]).expect("the free one listens");
    assert_eq!(
        listener.bound_addrs().len(),
        1,
        "{:?}",
        listener.bound_addrs()
    );
    let port = listener.bound_addrs()[0].port();
    let response = exchange(
        port,
        [head("Content-Length: 61").as_bytes(), &padded_request(61)]
            .concat()
            .as_slice(),
    );
    assert!(response.contains(r#""result":0"#), "{response}");
    listener.shutdown();

    let err = listen(&server, &[&busy_addr])
        .err()
        .expect("nothing usable to listen on");
    assert_eq!(err.to_string(), "no usable rpc listen addresses");
}

/// A host that is not an IP literal is refused, as dcrd's
/// `parseListeners` refuses it.
#[test]
fn a_hostname_is_not_a_listen_address() {
    let (_dir, server) = server();
    let err = listen(&server, &["localhost:0"])
        .err()
        .expect("a hostname is refused");
    assert_eq!(err.to_string(), "'localhost' is not a valid IP address");
}

/// Sequential HTTP calls, each on a fresh connection as dcrd's
/// `Connection: close` forces, are accepted as they arrive.  With the
/// accept loop sleeping 50 ms whenever nothing was pending, every call
/// after the first waited out most of that sleep.
#[test]
fn sequential_requests_are_accepted_without_a_poll_delay() {
    let (_dir, server) = server();
    let listener = listen(&server, &["127.0.0.1:0"]).expect("listen");
    let port = listener.bound_addrs()[0].port();
    let request = [head("Content-Length: 61").as_bytes(), &padded_request(61)].concat();

    let mut latencies: Vec<Duration> = (0..21)
        .map(|_| {
            let started = Instant::now();
            let response = exchange(port, &request);
            assert!(response.contains(r#""result":0"#), "{response}");
            started.elapsed()
        })
        .collect();
    latencies.sort();
    let median = latencies[latencies.len() / 2];
    assert!(
        median < Duration::from_millis(25),
        "a sequential call waited on the accept loop: median {median:?} of {latencies:?}"
    );
    listener.shutdown();
}

/// A declared body over the authenticated limit is read up to the limit
/// and parsed (dcrd's `io.LimitReader`, with no length check): a valid
/// request padded past 8 MiB is served.  Only the first 8 MiB is sent,
/// which is all dcrd reads before answering.
#[test]
fn an_oversized_content_length_is_truncated_and_served() {
    let (_dir, server) = server();
    let listener = listen(&server, &["127.0.0.1:0"]).expect("listen");
    let port = listener.bound_addrs()[0].port();

    let declared = READ_LIMIT + 1;
    let request = [
        head(&format!("Content-Length: {declared}")).as_bytes(),
        &padded_request(READ_LIMIT),
    ]
    .concat();
    let response = exchange(port, &request);
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "{}",
        &response[..response.len().min(200)]
    );
    assert!(response.contains(r#""result":0"#), "{response}");

    // A document the limit cuts short is dcrd's -32700, still a 200.
    let mut cut = br#"{"jsonrpc":"1.0","id":1,"method":"getblockcount","params":["#.to_vec();
    cut.resize(READ_LIMIT, b' ');
    let request = [
        head(&format!("Content-Length: {declared}")).as_bytes(),
        &cut,
    ]
    .concat();
    let response = exchange(port, &request);
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(
        response.contains(r#""code":-32700,"message":"Failed to parse request: "#),
        "{response}"
    );
    listener.shutdown();
}

/// A chunked body over the limit is cut at the limit the same way, and
/// the rest of it is read before the answer, as Go's `body.Close`
/// reads on through a chunked body (`transfer.go:999-1019`), so the
/// connection closes cleanly instead of resetting over unread bytes.
#[test]
fn an_oversized_chunked_body_is_truncated_and_served() {
    let (_dir, server) = server();
    let listener = listen(&server, &["127.0.0.1:0"]).expect("listen");
    let port = listener.bound_addrs()[0].port();

    // One chunk declared larger than the limit, then the last chunk.
    let chunk_size = READ_LIMIT + 1000;
    let request = [
        head("Transfer-Encoding: chunked").as_bytes(),
        format!("{chunk_size:x}\r\n").as_bytes(),
        &padded_request(chunk_size),
        b"\r\n0\r\n\r\n",
    ]
    .concat();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.write_all(&request).expect("write");
    let (response, ended) = read_response(&mut stream);
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "{}",
        &response[..response.len().min(200)]
    );
    assert!(response.contains(r#""result":0"#), "{response}");
    assert!(
        ended.is_ok(),
        "the rest of the body was left unread: {ended:?}"
    );
    listener.shutdown();
}

/// A `Content-Length` body whose remainder past the limit is at most
/// `maxPostHandlerReadBytes`, on a request that did not ask to close,
/// is read to its end before the answer, as Go's `body.Close` reads it
/// (`transfer.go:1002-1019`).  With `Connection: close`, or a larger
/// remainder, Go reads nothing more; the test above covers that.
#[test]
fn a_keep_alive_body_just_past_the_limit_is_read_to_its_end() {
    let (_dir, server) = server();
    let listener = listen(&server, &["127.0.0.1:0"]).expect("listen");
    let port = listener.bound_addrs()[0].port();

    let declared = READ_LIMIT + 1000;
    let request = [
        keep_alive_head(&format!("Content-Length: {declared}")).as_bytes(),
        &padded_request(declared),
    ]
    .concat();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.write_all(&request).expect("write");
    let (response, ended) = read_response(&mut stream);
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "{}",
        &response[..response.len().min(200)]
    );
    assert!(response.contains(r#""result":0"#), "{response}");
    assert!(
        ended.is_ok(),
        "the rest of the body was left unread: {ended:?}"
    );
    listener.shutdown();
}

/// A chunk that ends exactly at the limit is where dcrd's limited read
/// stops: the next size line is `body.Close`'s to read, and its error
/// is dropped, so a malformed line there is still answered from the
/// 8 MiB prefix.  The port read that line as part of the body and
/// answered 400.  The line arrives after a pause, so Go's reader cannot
/// have it buffered when the limit is reached.
#[test]
fn a_chunk_ending_at_the_limit_is_served_whatever_follows() {
    let (_dir, server) = server();
    let listener = listen(&server, &["127.0.0.1:0"]).expect("listen");
    let port = listener.bound_addrs()[0].port();

    let request = [
        head("Transfer-Encoding: chunked").as_bytes(),
        format!("{READ_LIMIT:x}\r\n").as_bytes(),
        &padded_request(READ_LIMIT),
    ]
    .concat();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.write_all(&request).expect("write");
    std::thread::sleep(Duration::from_millis(300));
    stream.write_all(b"\r\nzz\r\n").expect("write");
    let (response, _) = read_response(&mut stream);
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "{}",
        &response[..response.len().min(200)]
    );
    assert!(response.contains(r#""result":0"#), "{response}");
    listener.shutdown();
}

/// When the rest of a truncated chunked body never comes, dcrd's
/// `body.Close` waits for it until the server's read deadline, drops
/// the timeout, and still answers from the prefix.  The port read the
/// next size line as part of the body and, timing out there, closed
/// without an answer.
#[test]
fn a_stalled_body_past_the_limit_is_answered_at_the_read_deadline() {
    let (_dir, server) = server();
    let listener = listen(&server, &["127.0.0.1:0"]).expect("listen");
    let port = listener.bound_addrs()[0].port();

    let started = Instant::now();
    let request = [
        head("Transfer-Encoding: chunked").as_bytes(),
        format!("{READ_LIMIT:x}\r\n").as_bytes(),
        &padded_request(READ_LIMIT),
    ]
    .concat();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.write_all(&request).expect("write");
    let (response, _) = read_response(&mut stream);
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "{}",
        &response[..response.len().min(200)]
    );
    assert!(response.contains(r#""result":0"#), "{response}");
    // dcrd's `rpcAuthTimeoutSeconds` read deadline, from the accept.
    assert!(
        started.elapsed() >= Duration::from_secs(9),
        "answered after {:?}, before the read deadline",
        started.elapsed()
    );
    listener.shutdown();
}

/// A body that is not UTF-8 is parsed the way Go's `encoding/json`
/// parses the raw bytes: an invalid byte inside a string decodes to
/// U+FFFD and the request is served, and one outside a string is the
/// -32700 parse error inside a 200 -- never the plain-text 400 the
/// listener answered before.
#[test]
fn a_non_utf8_body_is_parsed_like_go() {
    let (_dir, server) = server();
    let listener = listen(&server, &["127.0.0.1:0"]).expect("listen");
    let port = listener.bound_addrs()[0].port();

    let body =
        b"{\"jsonrpc\":\"1.0\",\"id\":\"a\xffb\",\"method\":\"getblockcount\",\"params\":[]}";
    let request = [
        head(&format!("Content-Length: {}", body.len())).as_bytes(),
        body.as_slice(),
    ]
    .concat();
    let response = exchange(port, &request);
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.contains(r#""result":0"#), "{response}");
    assert!(response.contains("\"id\":\"a\u{fffd}b\""), "{response}");

    let body = b"\xff";
    let request = [head("Content-Length: 1").as_bytes(), body.as_slice()].concat();
    let response = exchange(port, &request);
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(
        response
            .contains(r#""code":-32700,"message":"Failed to parse request: invalid character "#),
        "{response}"
    );
    listener.shutdown();
}

/// An accepted RPC connection carries TCP keepalive with Go's 15 second
/// idle time, as every connection Go's `TCPListener.Accept` returns
/// does, so a client whose host vanished is reaped instead of holding
/// its slot forever.  Read back from the kernel's socket table: the
/// server side of an idle connection runs the keepalive timer (`tr` 2)
/// due within the idle time.
#[cfg(target_os = "linux")]
#[test]
fn accepted_connections_carry_gos_keepalive() {
    let (_dir, server) = server();
    let listener = listen(&server, &["127.0.0.1:0"]).expect("listen");
    let port = listener.bound_addrs()[0].port();

    // Connect and send nothing, so the server side sits idle in its
    // request read.
    let client = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let client_port = client.local_addr().expect("client addr").port();
    let local = format!("0100007F:{port:04X}");
    let remote = format!("0100007F:{client_port:04X}");

    // The server's end: local is the listener port, remote the client's.
    let deadline = Instant::now() + Duration::from_secs(5);
    let timer = loop {
        let table = std::fs::read_to_string("/proc/net/tcp").expect("/proc/net/tcp");
        let row = table.lines().find_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            (fields.get(1) == Some(&local.as_str()) && fields.get(2) == Some(&remote.as_str()))
                .then(|| fields.get(5).map(|timer| timer.to_string()))
                .flatten()
        });
        if let Some(timer) = row.as_ref().filter(|timer| timer.starts_with("02:")) {
            break timer.clone();
        }
        assert!(
            Instant::now() < deadline,
            "the accepted socket never armed a keepalive timer (last: {row:?})"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    // `tm->when` counts clock ticks (USER_HZ, 100 on Linux) until the
    // first probe, which the 15 second idle time bounds.
    let ticks = u64::from_str_radix(timer.trim_start_matches("02:"), 16).expect("timer ticks");
    assert!(
        ticks <= 15 * 100,
        "keepalive due in {ticks} ticks, past Go's 15 s idle time"
    );
    drop(client);
    listener.shutdown();
}
