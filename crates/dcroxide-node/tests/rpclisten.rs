// SPDX-License-Identifier: ISC
//! End-to-end checks for the RPC listener: raw HTTP requests against a
//! genesis chain hit the ported JSON-RPC pipeline — authenticated
//! queries answer, bad credentials get dcrd's 401, and a handler whose
//! daemon seam is not wired yet answers an internal error without
//! killing the server.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};
use dcroxide_node::rpcrun::{
    NodeRpcChain, NodeRpcConnManager, NodeRpcSyncManager, start_rpc_listener,
};
use dcroxide_node::runtime::ConnectedPeers;
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::server::{Config, RpcSubsidyParams, Server};
use dcroxide_standalone::SubsidyCache;
use dcroxide_wire::PROTOCOL_VERSION;

/// Start an RPC listener over a fresh genesis testnet chain, also
/// handing back the shared chain so tests can seed its state.
fn serve_rpc() -> (
    tempfile::TempDir,
    dcroxide_node::rpcrun::RpcListener,
    u16,
    dcroxide_chainhash::Hash,
    Arc<Mutex<Chain>>,
) {
    // A cap comfortably above any test's connection concurrency, so the
    // standard-client limit never trips for the functional tests.
    serve_rpc_capped(128)
}

fn serve_rpc_capped(
    max_clients: usize,
) -> (
    tempfile::TempDir,
    dcroxide_node::rpcrun::RpcListener,
    u16,
    dcroxide_chainhash::Hash,
    Arc<Mutex<Chain>>,
) {
    let (dir, listener, ports, hash, chain) =
        serve_rpc_capped_on(&["127.0.0.1:0".to_string()], max_clients);
    let port = ports[0];
    (dir, listener, port, hash, chain)
}

/// As [`serve_rpc_capped`], but over an explicit set of listen
/// addresses, so the tests can exercise the several accept loops the
/// default `rpclisten` expands to (typically 127.0.0.1 and ::1).
fn serve_rpc_capped_on(
    listen: &[String],
    max_clients: usize,
) -> (
    tempfile::TempDir,
    dcroxide_node::rpcrun::RpcListener,
    Vec<u16>,
    dcroxide_chainhash::Hash,
    Arc<Mutex<Chain>>,
) {
    let params = dcroxide_chaincfg::testnet3_params();
    let genesis_hash = params.genesis_hash;

    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    let shared_chain = Arc::clone(&chain);
    let connected = ConnectedPeers::new();
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
    // A real (but empty and never-enabled) fee estimator, exactly as
    // the daemon wires it: estimatesmartfee reads it and, with no
    // transactions ever seen, answers dcrd's estimation error.
    let fee_estimator = dcroxide_node::fees::new_shared_estimator(10000).expect("fee estimator");

    let server = Arc::new(Server::new(Config {
        chain: NodeRpcChain::new(chain, params.clone()),
        chain_params: params.clone(),
        subsidy_cache: std::sync::Mutex::new(SubsidyCache::new(RpcSubsidyParams(params.clone()))),
        min_relay_tx_fee: 10000,
        max_protocol_version: PROTOCOL_VERSION,
        sync_mgr: Box::new(NodeRpcSyncManager::new(sync_manager, Arc::clone(&tx_pool))),
        conn_mgr: Box::new(NodeRpcConnManager::new(
            connected,
            Arc::new(dcroxide_node::transport::NetByteTotals::new()),
        )),
        client_cert_auth: false,
        tx_mempooler: Box::new(dcroxide_node::txmempool::NodeRpcTxMempooler::new(
            Arc::clone(&tx_pool),
        )),
        clock: Box::new(dcroxide_node::rpcrun::SystemClock),
        interfaces: Box::new(NoInterfaces),
        rand_u64: Box::new(|| 7),
        tx_indexer: None,
        db: Box::new(()),
        filterer_v2: Box::new(()),
        exists_addresser: None,
        log_manager: Box::new(()),
        fee_estimator: Box::new(dcroxide_node::fees::NodeRpcFeeEstimator::new(fee_estimator)),
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

    let listener = start_rpc_listener(
        listen,
        server,
        dcroxide_node::rpcrun::RpcTransport::Plain,
        dcroxide_node::websocket::NodeNtfnMgr::new(),
        max_clients,
    )
    .expect("start rpc listener");
    let ports = listener
        .bound_addrs()
        .iter()
        .map(|addr| addr.port())
        .collect();
    (dir, listener, ports, genesis_hash, shared_chain)
}

/// Send one raw HTTP POST and return the full response text.
fn post(port: u16, auth: Option<&str>, body: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let auth_header = auth
        .map(|creds| {
            format!(
                "Authorization: Basic {}\r\n",
                dcroxide_rpc::http::base64_std_encode(creds.as_bytes())
            )
        })
        .unwrap_or_default();
    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\n{auth_header}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    response
}

/// As [`post`], but tolerating a connection the server drops without a
/// reply: a refused connection surfaces as a failed connect, a failed
/// write, a clean end of stream, or a reset depending on timing, and all
/// four mean the same thing — no HTTP response came back.
fn try_post(port: u16, auth: Option<&str>, body: &str) -> String {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return String::new();
    };
    let auth_header = auth
        .map(|creds| {
            format!(
                "Authorization: Basic {}\r\n",
                dcroxide_rpc::http::base64_std_encode(creds.as_bytes())
            )
        })
        .unwrap_or_default();
    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\n{auth_header}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return String::new();
    }
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response).into_owned()
}

#[test]
fn answers_chain_queries_over_http() {
    let (_dir, listener, port, genesis_hash, _chain) = serve_rpc();

    // getbestblockhash answers the genesis hash.
    let response = post(
        port,
        Some("user:pass"),
        r#"{"jsonrpc":"1.0","method":"getbestblockhash","params":[],"id":1}"#,
    );
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(
        response.contains(&format!("\"result\":\"{genesis_hash}\"")),
        "{response}"
    );

    // getblockcount answers zero.
    let response = post(
        port,
        Some("user:pass"),
        r#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":2}"#,
    );
    assert!(response.contains("\"result\":0"), "{response}");

    // getblockhash 0 answers the genesis hash through the chain adapter.
    let response = post(
        port,
        Some("user:pass"),
        r#"{"jsonrpc":"1.0","method":"getblockhash","params":[0],"id":5}"#,
    );
    assert!(
        response.contains(&format!("\"result\":\"{genesis_hash}\"")),
        "{response}"
    );

    // getblock (non-verbose) returns the serialized genesis block hex.
    let response = post(
        port,
        Some("user:pass"),
        &format!(
            r#"{{"jsonrpc":"1.0","method":"getblock","params":["{genesis_hash}",false],"id":6}}"#
        ),
    );
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.contains("\"result\":\""), "{response}");

    // getbestblock returns the genesis hash and height zero.
    let response = post(
        port,
        Some("user:pass"),
        r#"{"jsonrpc":"1.0","method":"getbestblock","params":[],"id":7}"#,
    );
    assert!(response.contains(&genesis_hash.to_string()), "{response}");
    assert!(response.contains("\"height\":0"), "{response}");

    // getconnectioncount answers zero through the connection-manager
    // adapter over the empty registry.
    let response = post(
        port,
        Some("user:pass"),
        r#"{"jsonrpc":"1.0","method":"getconnectioncount","params":[],"id":8}"#,
    );
    assert!(response.contains("\"result\":0"), "{response}");

    // getinfo answers the full node-info result (the zero-offset time
    // source matches a sample-less dcrd).
    let response = post(
        port,
        Some("user:pass"),
        r#"{"jsonrpc":"1.0","method":"getinfo","params":[],"id":9}"#,
    );
    assert!(response.contains("\"blocks\":0"), "{response}");
    assert!(response.contains("\"timeoffset\":0"), "{response}");
    assert!(response.contains("\"testnet\":true"), "{response}");
    assert!(response.contains("\"txindex\":false"), "{response}");

    // getblockchaininfo answers with the genesis chain state and the
    // agenda statuses through the threshold-state conversion.
    let response = post(
        port,
        Some("user:pass"),
        r#"{"jsonrpc":"1.0","method":"getblockchaininfo","params":[],"id":10}"#,
    );
    assert!(response.contains("\"chain\":\"testnet3\""), "{response}");
    assert!(response.contains("\"blocks\":0"), "{response}");
    assert!(
        response.contains("\"initialblockdownload\":true"),
        "{response}"
    );
    assert!(response.contains("\"deployments\":{"), "{response}");
    assert!(response.contains("\"status\":\"defined\""), "{response}");

    // getnettotals answers through the byte-totals pair and the system
    // clock (no peers have exchanged bytes in this fixture).
    let response = post(
        port,
        Some("user:pass"),
        r#"{"jsonrpc":"1.0","method":"getnettotals","params":[],"id":11}"#,
    );
    assert!(response.contains("\"totalbytesrecv\":0"), "{response}");
    assert!(response.contains("\"totalbytessent\":0"), "{response}");
    assert!(response.contains("\"timemillis\":"), "{response}");

    // The mempool now answers over the wired pool: empty for a fresh
    // chain.
    let response = post(
        port,
        Some("user:pass"),
        r#"{"jsonrpc":"1.0","method":"getrawmempool","params":[],"id":12}"#,
    );
    assert!(response.contains("\"result\":[]"), "{response}");

    // A garbage sendrawtransaction draws dcrd's deserialization error.
    let response = post(
        port,
        Some("user:pass"),
        r#"{"jsonrpc":"1.0","method":"sendrawtransaction","params":["zz"],"id":13}"#,
    );
    assert!(response.contains("-22"), "{response}");

    // A well-formed transaction spending unknown outputs is refused as
    // an orphan (rule error), since submission disallows orphans.
    let orphan_tx = {
        use dcroxide_wire::{MsgTx, OutPoint, TxIn, TxOut};
        let tx = MsgTx {
            tx_in: vec![TxIn {
                previous_out_point: OutPoint {
                    hash: dcroxide_chainhash::Hash([0x77; 32]),
                    index: 0,
                    tree: 0,
                },
                sequence: u32::MAX,
                value_in: 0,
                block_height: 0,
                block_index: 0,
                signature_script: vec![0x51],
            }],
            tx_out: vec![TxOut {
                value: 1,
                version: 0,
                pk_script: vec![0x51],
            }],
            ..MsgTx::default()
        };
        tx.serialize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let response = post(
        port,
        Some("user:pass"),
        &format!(
            r#"{{"jsonrpc":"1.0","method":"sendrawtransaction","params":["{orphan_tx}"],"id":14}}"#
        ),
    );
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(!response.contains("-32603"), "{response}");
    assert!(response.contains("\"error\":{"), "{response}");

    // estimatesmartfee reads the wired fee estimator; with no
    // transactions ever seen it answers dcrd's estimation error as an
    // internal error (-32603) rather than killing the server.
    let response = post(
        port,
        Some("user:pass"),
        r#"{"jsonrpc":"1.0","method":"estimatesmartfee","params":[10],"id":3}"#,
    );
    assert!(response.contains("-32603"), "{response}");
    assert!(
        response.contains("not enough transactions seen for estimation"),
        "{response}"
    );

    // An unsupported estimation mode is rejected before the estimator
    // is even consulted (dcrd's rpc_invalid_error, -8).
    let response = post(
        port,
        Some("user:pass"),
        r#"{"jsonrpc":"1.0","method":"estimatesmartfee","params":[10,"economical"],"id":31}"#,
    );
    assert!(response.contains("-8"), "{response}");

    // ...and the server still answers afterwards.
    let response = post(
        port,
        Some("user:pass"),
        r#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":4}"#,
    );
    assert!(response.contains("\"result\":0"), "{response}");

    listener.shutdown();
}

#[test]
fn rejects_bad_credentials_with_dcrds_401() {
    let (_dir, listener, port, _genesis_hash, _chain) = serve_rpc();

    let response = post(
        port,
        Some("user:wrong"),
        r#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":1}"#,
    );
    assert!(response.starts_with("HTTP/1.1 401"), "{response}");
    assert!(
        response.contains("WWW-Authenticate: Basic realm=\"dcrd RPC\""),
        "{response}"
    );

    let response = post(
        port,
        None,
        r#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":2}"#,
    );
    assert!(response.starts_with("HTTP/1.1 401"), "{response}");

    listener.shutdown();
}

#[test]
fn unauthenticated_post_is_rejected_before_reading_the_body() {
    let (_dir, listener, port, _genesis_hash, _chain) = serve_rpc();

    // An unauthenticated POST declares a multi-megabyte body but sends
    // none, then half-closes its write side.  The server must
    // authenticate before allocating or reading the body (dcrd's
    // checkAuth-before-jsonRPCRead order), so it still answers 401
    // instead of blocking on a body that never arrives.  Before the fix
    // the body was read first, and this connection got no response.
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let request = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 4000000\r\nConnection: close\r\n\r\n";
    stream.write_all(request.as_bytes()).expect("write");
    stream
        .shutdown(std::net::Shutdown::Write)
        .expect("half close");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .expect("read timeout");
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    assert!(
        response.starts_with("HTTP/1.1 401"),
        "an unauthenticated request must be rejected without its body: {response:?}"
    );

    listener.shutdown();
}

#[test]
fn a_zero_client_cap_sheds_every_standard_request_with_503() {
    // dcrd's RPCMaxClients == 0 makes numClients+1 > 0 always true, so
    // every standard RPC connection is shed with 503.  The cap is checked
    // before authentication, so even a valid request is refused.
    let (_dir, listener, port, _genesis_hash, _chain) = serve_rpc_capped(0);

    let response = post(
        port,
        Some("user:pass"),
        r#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":1}"#,
    );
    assert!(
        response.starts_with("HTTP/1.1 503"),
        "a zero client cap must shed every request: {response}"
    );

    listener.shutdown();
}

/// The UTXO seams: gettxout resolves a seeded entry through the chain
/// adapter (falling through the empty mempool with dcrd's default
/// includemempool), misses answer JSON null, and gettxoutsetinfo
/// reports the seeded set's statistics.
#[test]
fn answers_utxo_queries_over_http() {
    let (_dir, listener, port, genesis_hash, chain) = serve_rpc();

    // Seed one unspent regular output at a known outpoint the way a
    // connected block would leave it in the flushed set.
    let tx_hash = dcroxide_chainhash::Hash([0xab; 32]);
    let entry = dcroxide_blockchain::UtxoEntry::new(
        123456789,
        vec![0x51], // OP_TRUE
        0,
        0,
        0,
        false,
        false,
        dcroxide_stake::TxType::Regular,
        None,
    );
    chain
        .lock()
        .expect("chain mutex")
        .db
        .as_ref()
        .expect("db")
        .update(|tx| {
            dcroxide_blockchain::chaindb::db_put_utxo(
                tx,
                &dcroxide_wire::OutPoint {
                    hash: tx_hash,
                    index: 0,
                    tree: 0,
                },
                Some(&entry),
            )
            .expect("write utxo row");
            Ok(())
        })
        .expect("seed the flushed set");

    // gettxout with dcrd's default includemempool probes the empty
    // mempool, misses, and resolves the entry from the UTXO set.
    let response = post(
        port,
        Some("user:pass"),
        &format!(r#"{{"jsonrpc":"1.0","method":"gettxout","params":["{tx_hash}",0,0],"id":1}}"#),
    );
    assert!(response.contains("\"value\":1.23456789"), "{response}");
    assert!(response.contains("\"confirmations\":1"), "{response}");
    assert!(response.contains("\"coinbase\":false"), "{response}");
    assert!(
        response.contains(&format!("\"bestblock\":\"{genesis_hash}\"")),
        "{response}"
    );

    // An unknown outpoint answers JSON null with no error.
    let unknown = dcroxide_chainhash::Hash([0xcd; 32]);
    let response = post(
        port,
        Some("user:pass"),
        &format!(r#"{{"jsonrpc":"1.0","method":"gettxout","params":["{unknown}",0,0],"id":2}}"#),
    );
    assert!(response.contains("\"result\":null"), "{response}");
    assert!(response.contains("\"error\":null"), "{response}");

    // gettxoutsetinfo reports the seeded set over the stats seam.
    let response = post(
        port,
        Some("user:pass"),
        r#"{"jsonrpc":"1.0","method":"gettxoutsetinfo","params":[],"id":3}"#,
    );
    assert!(response.contains("\"height\":0"), "{response}");
    assert!(
        response.contains(&format!("\"bestblock\":\"{genesis_hash}\"")),
        "{response}"
    );
    assert!(response.contains("\"transactions\":1"), "{response}");
    assert!(response.contains("\"txouts\":1"), "{response}");
    assert!(response.contains("\"totalamount\":123456789"), "{response}");

    listener.shutdown();
}

/// The TLS transport: a generated certificate pair serves HTTPS, and a
/// rustls client trusting that certificate completes the query
/// (dcrd's default RPC mode over its autogenerated rpc.cert).
#[test]
fn serves_tls_with_a_generated_certificate() {
    use std::io::{Read, Write};

    let params = dcroxide_chaincfg::testnet3_params();
    let dir = tempfile::tempdir().expect("temp dir");

    // Generate the certificate pair like the daemon's first start.
    let cert_path = dir.path().join("rpc.cert");
    let key_path = dir.path().join("rpc.key");
    let (cert_pem, key_pem) = dcroxide_node::rpcrun::load_or_generate_cert_pair(
        &cert_path,
        &key_path,
        &[],
        dcroxide_certgen::Curve::P256,
    )
    .expect("generate cert pair");
    assert!(cert_path.exists() && key_path.exists());
    // A second load reuses the written pair.
    let (cert_again, _) = dcroxide_node::rpcrun::load_or_generate_cert_pair(
        &cert_path,
        &key_path,
        &[],
        dcroxide_certgen::Curve::P256,
    )
    .expect("reload cert pair");
    assert_eq!(cert_pem, cert_again);

    let tls = dcroxide_node::rpcrun::tls_server_config(&cert_pem, &key_pem, None)
        .expect("build tls config");

    // A chain-backed server exactly like the plain-HTTP fixture.
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    let server = Arc::new(Server::new(Config {
        chain: NodeRpcChain::new(chain, params.clone()),
        chain_params: params.clone(),
        subsidy_cache: std::sync::Mutex::new(SubsidyCache::new(RpcSubsidyParams(params.clone()))),
        min_relay_tx_fee: 10000,
        max_protocol_version: PROTOCOL_VERSION,
        sync_mgr: Box::new(()),
        conn_mgr: Box::new(()),
        client_cert_auth: false,
        tx_mempooler: Box::new(()),
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
    let listener = start_rpc_listener(
        &["127.0.0.1:0".to_string()],
        server,
        dcroxide_node::rpcrun::RpcTransport::Tls(tls),
        dcroxide_node::websocket::NodeNtfnMgr::new(),
        128,
    )
    .expect("start tls listener");
    let port = listener.bound_addrs()[0].port();

    // A rustls client pinning the generated certificate.  dcrd's
    // autogenerated certificate is a self-signed CA served directly as
    // the end-entity certificate; Go clients accept that shape but
    // webpki refuses it, so Decred tooling pins rpc.cert — this
    // verifier does the same.
    #[derive(Debug)]
    struct PinnedCert(Vec<u8>);
    impl rustls::client::danger::ServerCertVerifier for PinnedCert {
        fn verify_server_cert(
            &self,
            end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            if end_entity.as_ref() == self.0.as_slice() {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            } else {
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ))
            }
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
    use rustls::pki_types::pem::PemObject;
    let pinned_der = rustls::pki_types::CertificateDer::pem_slice_iter(&cert_pem)
        .next()
        .expect("one cert")
        .expect("parse cert")
        .as_ref()
        .to_vec();
    let client_config = Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedCert(pinned_der)))
            .with_no_client_auth(),
    );
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
    let session = rustls::ClientConnection::new(client_config, name).expect("client");
    let tcp = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let mut tls_stream = rustls::StreamOwned::new(session, tcp);

    let body = r#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":1}"#;
    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        dcroxide_rpc::http::base64_std_encode(b"user:pass"),
        body.len()
    );
    tls_stream.write_all(request.as_bytes()).expect("write");
    let mut response = String::new();
    let _ = tls_stream.read_to_string(&mut response);
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.contains("\"result\":0"), "{response}");

    listener.shutdown();
}

/// A chunked-transfer POST decodes to the same request the
/// Content-Length path serves (Go's net/http decodes chunked
/// transparently; the RPC pipeline sees only the body).
#[test]
fn answers_a_chunked_transfer_request() {
    let (_dir, listener, port, genesis_hash, _chain) = serve_rpc();

    let body = r#"{"jsonrpc":"1.0","method":"getbestblockhash","params":[],"id":1}"#;
    let auth = dcroxide_rpc::http::base64_std_encode(b"user:pass");
    // Split the body across two chunks with an extension on the first
    // size line and a trailer header, all of which the decoder must
    // accept and discard.
    let (first, second) = body.split_at(10);
    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {auth}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x};ext=1\r\n{first}\r\n{:x}\r\n{second}\r\n0\r\nX-Trailer: ignored\r\n\r\n",
        first.len(),
        second.len(),
    );
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.write_all(request.as_bytes()).expect("write");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(
        response.contains(&format!("\"result\":\"{genesis_hash}\"")),
        "{response}"
    );

    // Bare-LF size and trailer lines are tolerated exactly as Go's
    // readChunkLine tolerates them (the after-data CRLF stays strict).
    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {auth}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\n{body}\r\n0\n\n",
        body.len(),
    );
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.write_all(request.as_bytes()).expect("write");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");

    listener.shutdown();
}

/// A transfer encoding the server cannot read is answered 501 before
/// any routing (Go's server answers Unsupported Transfer-Encoding),
/// and malformed chunk framing is a 400.
#[test]
fn rejects_bad_transfer_encodings() {
    let (_dir, listener, port, _genesis_hash, _chain) = serve_rpc();
    let auth = dcroxide_rpc::http::base64_std_encode(b"user:pass");

    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {auth}\r\nTransfer-Encoding: gzip\r\nConnection: close\r\n\r\n"
    );
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.write_all(request.as_bytes()).expect("write");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    assert!(response.starts_with("HTTP/1.1 501"), "{response}");

    // A size line that is not hex fails the chunk framing.
    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {auth}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nzz\r\n"
    );
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.write_all(request.as_bytes()).expect("write");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert!(response.contains("invalid chunked body"), "{response}");

    listener.shutdown();
}

/// Shutdown waits for the per-connection handler threads (dcrd
/// `rpcServer.Stop`'s wait group): with a live websocket client
/// connected, `shutdown()` must both wait for it and terminate,
/// because the serving loop observes the shutdown flag within a poll
/// interval.
#[test]
fn shutdown_drains_a_live_websocket_handler() {
    let (_dir, listener, port, _genesis_hash, _chain) = serve_rpc();

    // Open a websocket and complete the upgrade so the serving loop is
    // live, then leave the connection idle.
    let auth = dcroxide_rpc::http::base64_std_encode(b"user:pass");
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let request = format!(
        "GET /ws HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {auth}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).expect("write");
    let mut head = [0u8; 12];
    stream.read_exact(&mut head).expect("read upgrade status");
    assert_eq!(&head, b"HTTP/1.1 101", "upgrade must be accepted");

    // Shutdown must return: it waits for the ws handler, and the
    // handler exits once it observes the flag.  Run it on a helper
    // thread so a regression (a hang) fails the join below rather than
    // wedging the test forever.
    let done = std::thread::spawn(move || {
        listener.shutdown();
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !done.is_finished() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        done.is_finished(),
        "shutdown must drain the websocket handler within the deadline"
    );
    done.join().expect("shutdown thread");
}

/// A websocket client that stalls mid-frame (one frame-header byte,
/// then silence) wedges its read past the poll interval; shutdown must
/// still return, because the drain force-closes the socket after the
/// grace period (dcrd's context watcher calling `Disconnect`).
#[test]
fn shutdown_force_closes_a_mid_frame_websocket_stall() {
    let (_dir, listener, port, _genesis_hash, _chain) = serve_rpc();

    let auth = dcroxide_rpc::http::base64_std_encode(b"user:pass");
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let request = format!(
        "GET /ws HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {auth}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).expect("write");
    let mut head = [0u8; 12];
    stream.read_exact(&mut head).expect("read upgrade status");
    assert_eq!(&head, b"HTTP/1.1 101", "upgrade must be accepted");
    // The first byte of a text frame header, then nothing: the serving
    // loop is now blocked inside the frame read, past the idle poll.
    stream.write_all(&[0x81]).expect("write partial frame");
    std::thread::sleep(std::time::Duration::from_millis(200));

    let done = std::thread::spawn(move || {
        listener.shutdown();
    });
    // The grace period is one second; the force-close must unblock the
    // handler well before this deadline.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while !done.is_finished() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        done.is_finished(),
        "shutdown must force-close a wedged websocket handler"
    );
    done.join().expect("shutdown thread");
}

/// `--authtype=clientcert` must produce a listener that actually
/// demands a verified client certificate: a CA file holding no usable
/// certificate is a startup error, never a silently open endpoint
/// (dcrd `newTLSConfig` returns "no certificates found in %q").
#[test]
fn client_cert_auth_requires_usable_certificate_authorities() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let cert_path = dir.path().join("rpc.cert");
    let key_path = dir.path().join("rpc.key");
    let (cert_pem, key_pem) = dcroxide_node::rpcrun::load_or_generate_cert_pair(
        &cert_path,
        &key_path,
        &[],
        dcroxide_certgen::Curve::P256,
    )
    .expect("generate cert pair");

    // Empty and garbage CA material both fail closed.
    for cas in [&b""[..], &b"not a certificate at all"[..]] {
        let err = dcroxide_node::rpcrun::tls_server_config(&cert_pem, &key_pem, Some(cas))
            .expect_err("a CA file without certificates must not build a listener");
        assert!(
            err.contains("no certificates found") || err.contains("client certificate"),
            "unexpected error: {err}"
        );
    }

    // A real certificate as the CA root builds a verifying listener
    // (rustls keeps the verifier private, so the observable assertion
    // here is that the CA material is required and parsed; the
    // fail-closed half of the control is pinned by
    // `zero_credentials_deny_without_client_certificate_auth`).
    dcroxide_node::rpcrun::tls_server_config(&cert_pem, &key_pem, Some(&cert_pem))
        .expect("build tls config with client CAs");
    dcroxide_node::rpcrun::tls_server_config(&cert_pem, &key_pem, None).expect("build tls config");
}

/// A half-present pair must not be regenerated over the file that is
/// still there.
///
/// dcrd guards `genCertPair` with `!keyFileExists && !certFileExists`
/// (`server.go` 3846), so with one file present it generates nothing,
/// falls through to `tls.LoadX509KeyPair`, and fails startup on the
/// missing one. The port used to regenerate whenever EITHER file was
/// missing, which silently destroyed a private key an operator may have
/// placed deliberately — a lost key, on a path where nothing in the
/// request said "replace it". Matching dcrd here is also the
/// non-destructive choice, so this pins both halves: the error, and the
/// key surviving byte for byte.
#[test]
fn a_half_present_pair_is_not_regenerated_over_the_surviving_file() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cert_path = dir.path().join("rpc.cert");
    let key_path = dir.path().join("rpc.key");

    // The operator's key, with the certificate gone.
    let provisioned = b"-----BEGIN EC PRIVATE KEY-----\nthe operator's key\n";
    std::fs::write(&key_path, provisioned).expect("seed the key");

    let err = dcroxide_node::rpcrun::load_or_generate_cert_pair(
        &cert_path,
        &key_path,
        &[],
        dcroxide_certgen::Curve::P256,
    )
    .expect_err("a missing certificate beside a present key must not regenerate");
    assert!(
        err.contains("rpc.cert") && err.contains("is missing"),
        "the error must name the missing file: {err}"
    );
    assert_eq!(
        std::fs::read(&key_path).expect("read the key back"),
        provisioned,
        "the existing private key must survive untouched"
    );
    assert!(
        !cert_path.exists(),
        "nothing must have been written for the missing half either"
    );

    // And symmetrically, with the certificate present and the key gone.
    std::fs::remove_file(&key_path).expect("remove the key");
    std::fs::write(&cert_path, b"the operator's cert").expect("seed the cert");
    let err = dcroxide_node::rpcrun::load_or_generate_cert_pair(
        &cert_path,
        &key_path,
        &[],
        dcroxide_certgen::Curve::P256,
    )
    .expect_err("a missing key beside a present certificate must not regenerate");
    assert!(
        err.contains("rpc.key") && err.contains("is missing"),
        "the error must name the missing file: {err}"
    );
    assert_eq!(
        std::fs::read(&cert_path).expect("read the cert back"),
        b"the operator's cert",
        "the existing certificate must survive untouched"
    );
    assert!(!key_path.exists(), "no key must have been conjured up");
}

/// The autogenerated RPC private key must be owner-only from the
/// moment it exists — dcrd writes it with `os.WriteFile(keyFile, key,
/// 0600)`.  Writing it world-readable and chmod'ing afterwards leaves
/// a window in which any local user can copy it, so the mode is
/// asserted here; the certificate stays world-readable like dcrd's.
#[cfg(unix)]
#[test]
fn generated_rpc_key_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("temp dir");
    let cert_path = dir.path().join("rpc.cert");
    let key_path = dir.path().join("rpc.key");

    // Neither file exists, which is the only condition under which
    // anything is generated (dcrd's `!keyFileExists && !certFileExists`).
    dcroxide_node::rpcrun::load_or_generate_cert_pair(
        &cert_path,
        &key_path,
        &[],
        dcroxide_certgen::Curve::P256,
    )
    .expect("generate cert pair");

    let mode = std::fs::metadata(&key_path)
        .expect("key metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o600,
        "the RPC private key must not be group/world readable"
    );
}

/// When the private key cannot be placed, startup must fail rather
/// than continue with a half-written pair.  The old code discarded the
/// result of the permission call, so a key it could not protect was
/// still handed to the listener.  dcrd also removes the certificate on
/// this path so the next start regenerates a matching pair.
#[cfg(unix)]
#[test]
fn an_unplaceable_rpc_key_fails_startup_and_removes_the_certificate() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("temp dir");
    let cert_path = dir.path().join("rpc.cert");

    // The key goes in a directory that cannot be written to, so BOTH
    // paths are absent — generation therefore runs — but placing the key
    // fails.  Occupying the key path itself would make it "exist", and
    // the both-absent guard would refuse before writing anything, which
    // is a different behaviour from the one under test here.
    let locked = dir.path().join("locked");
    std::fs::create_dir(&locked).expect("create the locked directory");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500))
        .expect("lock the directory");
    let key_path = locked.join("rpc.key");

    // Root ignores the mode bits, so the premise cannot be set up there.
    if std::fs::write(locked.join("canary"), b"x").is_ok() {
        return;
    }

    let err = dcroxide_node::rpcrun::load_or_generate_cert_pair(
        &cert_path,
        &key_path,
        &[],
        dcroxide_certgen::Curve::P256,
    )
    .expect_err("an unwritable key must not be ignored");
    assert!(
        err.contains("unable to write the RPC key"),
        "unexpected error: {err}"
    );
    assert!(
        !cert_path.exists(),
        "the certificate must not outlive the key it was generated with"
    );
}

/// A client that pauses mid-request longer than one receive slice must
/// still be served.
///
/// The RPC read loop issues its receives in slices so a handler whose
/// socket has been shut down under it (pre-authentication eviction) comes
/// back up promptly instead of sleeping out the authentication timeout.
/// That introduced a new way for a receive to return nothing which has
/// nothing to do with the deadline being spent, and treating it as a
/// timeout would cut off any client that paused — a `dcrctl` on a slow
/// link, a submitblock arriving in pieces. The old loop could not get
/// this wrong because its socket timeout *was* the deadline.
///
/// So: send the head, wait past a slice, then send the body, and require
/// the answer. The pause is comfortably inside the ten-second
/// authentication timeout, so only the slice handling can fail this.
#[test]
fn a_client_that_pauses_mid_request_is_still_served() {
    let (_dir, listener, port, _genesis_hash, _chain) = serve_rpc();

    let body = r#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":1}"#;
    let auth = dcroxide_rpc::http::base64_std_encode(b"user:pass");
    let head = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {auth}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.write_all(head.as_bytes()).expect("write head");
    stream.flush().expect("flush head");

    // Longer than one receive slice, so the server's read genuinely comes
    // back around with nothing to show for it.
    std::thread::sleep(std::time::Duration::from_millis(2500));

    stream.write_all(body.as_bytes()).expect("write body");
    stream.flush().expect("flush body");

    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read the response");
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "a pause longer than one receive slice must not lose the request: {response:?}"
    );
    assert!(response.contains("\"result\":0"), "{response}");
    listener.shutdown();
}

/// Open `count` connections that say nothing at all, each parking a
/// handler in the request read for the full authentication timeout, and
/// hand the sockets back so the caller holds the flood open.
fn stall_connections(port: u16, count: usize) -> Vec<TcpStream> {
    let mut stalled = Vec::with_capacity(count);
    for _ in 0..count {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(sock) => stalled.push(sock),
            // The kernel refusing this early is itself a shed; nothing
            // more can be opened, so the flood is as large as it gets.
            Err(_) => break,
        }
    }
    stalled
}

/// Block until the pre-authentication pool is actually saturated.
///
/// Opening the sockets is far cheaper than accepting them — each
/// admission spawns two threads — so a test that dialled a flood and
/// immediately probed the server would be racing the accept loop
/// draining the listen backlog, and could observe an idle pool. Waiting
/// on the invariant (rather than sleeping a guessed interval) makes the
/// flood real before the assertion that depends on it.
fn wait_for_pre_auth_saturation(listener: &dcroxide_node::rpcrun::RpcListener) {
    let (soft, _hard) = listener.pre_auth_budget();
    let deadline = std::time::Instant::now()
        .checked_add(std::time::Duration::from_secs(30))
        .expect("deadline");
    while listener.pre_auth_connections() < soft && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        listener.pre_auth_connections() >= soft,
        "the flood must fill the nominal pre-authentication budget {soft} before the \
         assertions that depend on it (live: {})",
        listener.pre_auth_connections(),
    );
}

/// A pre-authentication flood must not take the RPC server off the air.
///
/// dcrd sheds an over-limit client with 503 from inside the handler,
/// which is safe there because the handler is a goroutine and the check
/// runs per request. Here a handler is an OS thread with a
/// multi-megabyte stack, so admission has to be bounded before the
/// spawn — and a single bounded pool shared by unauthenticated and
/// legitimate connections turns a thread flood into a total
/// availability outage: an attacker opening the whole pool and sending
/// nothing holds it for the ten-second authentication timeout, and every
/// other connection (the operator's `dcrctl`, every websocket
/// subscriber) is dropped on the accept thread with no reply.
///
/// The budget is therefore split — a connection leaves the
/// pre-authentication pool the moment it authenticates — and within the
/// pool admission disconnects the *oldest* pre-authentication
/// connection rather than the arriving one. So with a flood many times
/// the pool's size in progress, an authenticated request still gets its
/// answer.
#[test]
fn an_authenticated_request_is_served_during_a_pre_auth_flood() {
    let (_dir, listener, port, _genesis_hash, _chain) = serve_rpc_capped(10);
    let (soft, hard) = listener.pre_auth_budget();

    // A flood well past the whole budget, held open for the test.
    let stalled = stall_connections(port, hard.saturating_mul(2));
    assert!(
        stalled.len() > hard,
        "the flood must exceed the budget it is testing ({} opened, budget {soft}/{hard})",
        stalled.len()
    );
    wait_for_pre_auth_saturation(&listener);

    // The pool is bounded no matter how large the flood is.
    assert!(
        listener.pre_auth_connections() <= hard,
        "a flood of {} connections must not exceed the pre-authentication ceiling {hard} \
         (live: {})",
        stalled.len(),
        listener.pre_auth_connections(),
    );

    // ...and an authenticated client is still served.  Retries cover a
    // loaded machine, inside a window far shorter than the ten-second
    // authentication timeout a stalled connection would hold a shared
    // slot for, so a regression cannot pass by simply waiting the flood
    // out.
    let deadline = std::time::Instant::now()
        .checked_add(std::time::Duration::from_secs(5))
        .expect("deadline");
    let mut attempts = 0usize;
    let last = loop {
        attempts += 1;
        let last = try_post(
            port,
            Some("user:pass"),
            r#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":1}"#,
        );
        if last.starts_with("HTTP/1.1 200 OK") {
            break last;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "an authenticated request must be answered during a pre-authentication flood \
             ({attempts} attempts, last response: {last:?})"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    assert!(last.contains("\"result\":0"), "{last}");

    drop(stalled);
    listener.shutdown();
}

/// Read the bytes of an HTTP response head, stopping at the blank line
/// so the frames that follow an upgrade stay in the socket.
fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).expect("read response head");
        head.push(byte[0]);
    }
    String::from_utf8(head).expect("utf8 head")
}

/// Write a masked client text frame (every client frame must be masked).
fn write_client_frame(stream: &mut TcpStream, payload: &[u8]) {
    let mut frame = vec![0x81]; // FIN + text.
    assert!(payload.len() < 126, "test payloads stay small");
    frame.push(0x80 | payload.len() as u8); // MASK + length.
    let mask = [0x12u8, 0x34, 0x56, 0x78];
    frame.extend_from_slice(&mask);
    for (i, byte) in payload.iter().enumerate() {
        frame.push(byte ^ mask[i & 3]);
    }
    stream.write_all(&frame).expect("write frame");
}

/// Read one unmasked server text frame's payload.
fn read_server_frame(stream: &mut TcpStream) -> String {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).expect("read frame header");
    let len = match header[1] & 0x7F {
        126 => {
            let mut ext = [0u8; 2];
            stream.read_exact(&mut ext).expect("read extended length");
            u16::from_be_bytes(ext) as usize
        }
        127 => {
            let mut ext = [0u8; 8];
            stream.read_exact(&mut ext).expect("read extended length");
            u64::from_be_bytes(ext) as usize
        }
        n => n as usize,
    };
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).expect("read frame payload");
    String::from_utf8(payload).expect("utf8 payload")
}

/// An established websocket subscriber must survive a pre-authentication
/// flood.
///
/// This is the half of the split budget that the eviction rule alone
/// cannot provide: if a connection kept its pre-authentication slot for
/// its whole session, a long-lived subscriber would be the *oldest*
/// entry in the pool and therefore the first thing an arriving flood
/// disconnects — the fix for the attacker would have broken the
/// legitimate user outright. A connection therefore leaves the pool the
/// moment it completes its handshake, after which dcrd's own
/// `rpcmaxwebsockets` governs it.
#[test]
fn an_established_websocket_survives_a_pre_auth_flood() {
    let (_dir, listener, port, _genesis_hash, _chain) = serve_rpc_capped(10);
    let (_soft, hard) = listener.pre_auth_budget();

    // Complete the upgrade, so this connection is an established client.
    let auth = dcroxide_rpc::http::base64_std_encode(b"user:pass");
    let mut ws = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let request = format!(
        "GET /ws HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {auth}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n\r\n"
    );
    ws.write_all(request.as_bytes()).expect("write");
    let head = read_head(&mut ws);
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");

    // It answers before the flood...
    write_client_frame(
        &mut ws,
        br#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":1}"#,
    );
    ws.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .expect("read timeout");
    let before = read_server_frame(&mut ws);
    assert!(before.contains("\"result\":0"), "{before}");

    // ...and after a flood that churns the whole pre-authentication pool
    // many times over.
    let stalled = stall_connections(port, hard.saturating_mul(2));
    assert!(
        stalled.len() > hard,
        "the flood must exceed the pre-authentication ceiling {hard}"
    );
    wait_for_pre_auth_saturation(&listener);
    write_client_frame(
        &mut ws,
        br#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":2}"#,
    );
    let after = read_server_frame(&mut ws);
    assert!(
        after.contains("\"result\":0"),
        "an established websocket must stay serviceable through a pre-authentication \
         flood: {after}"
    );

    drop(stalled);
    listener.shutdown();
}

/// The pre-authentication budget is one process-wide pool, not one per
/// accept loop: `num_clients` is deliberately shared across the accept
/// loops for exactly this reason, and the default `rpclisten` expands to
/// every localhost lookup result (typically 127.0.0.1 and ::1), so a
/// per-loop pool would silently multiply the documented bound by the
/// number of listen addresses.
///
/// Each listen address must register its connections in the shared pool,
/// so flooding any one of them alone moves the listener-wide count.
#[test]
fn the_pre_auth_budget_is_shared_across_listen_addresses() {
    let listen = vec!["127.0.0.1:0".to_string(), "127.0.0.1:0".to_string()];
    for which in 0..listen.len() {
        let (_dir, listener, ports, _genesis_hash, _chain) = serve_rpc_capped_on(&listen, 10);
        assert_eq!(ports.len(), 2, "both addresses must bind");
        let (soft, hard) = listener.pre_auth_budget();
        assert_eq!(
            listener.pre_auth_connections(),
            0,
            "a fresh listener has nothing in the pre-authentication pool"
        );

        // Flood exactly one of the two addresses.
        let stalled = stall_connections(ports[which], soft.saturating_add(4));
        // The count is polled: the accept loop registers connections as
        // it drains the backlog, which is not instantaneous.
        let deadline = std::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(10))
            .expect("deadline");
        while listener.pre_auth_connections() == 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            listener.pre_auth_connections() > 0,
            "the flood on listen address {which} must register in the process-wide \
             pre-authentication pool, not in a pool private to its accept loop"
        );
        assert!(
            listener.pre_auth_connections() <= hard,
            "listen address {which} must share the ceiling {hard}, not have its own \
             (live: {})",
            listener.pre_auth_connections(),
        );

        drop(stalled);
        listener.shutdown();
    }
}

/// Two `Authorization` headers on one request: dcrd's header map keeps
/// every occurrence in arrival order and it authenticates against
/// `authhdr[0]` (`rpcserver.go:5525-5536`), so the first one decides.
/// The concrete case is a reverse proxy that injects its own header:
/// with last-wins the client's copy overrides the proxy's, which is the
/// opposite of dcrd's answer in both directions.
#[test]
fn the_first_authorization_header_decides() {
    let (_dir, listener, port, _genesis_hash, _chain) = serve_rpc();

    let send = |first: &str, second: &str| -> String {
        let body = r#"{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":1}"#;
        let request = format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {}\r\nAuthorization: Basic {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            dcroxide_rpc::http::base64_std_encode(first.as_bytes()),
            dcroxide_rpc::http::base64_std_encode(second.as_bytes()),
            body.len()
        );
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream.write_all(request.as_bytes()).expect("write");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read");
        response
    };

    // Valid first, garbage second: the request is served.
    let response = send("user:pass", "user:wrong");
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "the first header authenticates: {response}"
    );

    // Garbage first, valid second: the request is refused.  A
    // last-wins reader answers 200 here.
    let response = send("user:wrong", "user:pass");
    assert!(
        response.starts_with("HTTP/1.1 401"),
        "a later header cannot rescue the first: {response}"
    );

    listener.shutdown();
}
