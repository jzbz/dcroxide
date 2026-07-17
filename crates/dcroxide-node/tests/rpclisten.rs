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
        dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone()),
    )));
    // A real (but empty and never-enabled) fee estimator, exactly as
    // the daemon wires it: estimatesmartfee reads it and, with no
    // transactions ever seen, answers dcrd's estimation error.
    let fee_estimator = dcroxide_node::fees::new_shared_estimator(10000).expect("fee estimator");

    let server = Arc::new(Mutex::new(Server::new(Config {
        chain: NodeRpcChain::new(chain, params.clone()),
        chain_params: params.clone(),
        subsidy_cache: SubsidyCache::new(RpcSubsidyParams(params.clone())),
        min_relay_tx_fee: 10000,
        max_protocol_version: PROTOCOL_VERSION,
        sync_mgr: Box::new(NodeRpcSyncManager::new(sync_manager, Arc::clone(&tx_pool))),
        conn_mgr: Box::new(NodeRpcConnManager::new(
            connected,
            Arc::new(dcroxide_node::transport::NetByteTotals::new()),
        )),
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
    })));

    let listener = start_rpc_listener(
        &["127.0.0.1:0".to_string()],
        server,
        dcroxide_node::rpcrun::RpcTransport::Plain,
        dcroxide_node::websocket::NodeNtfnMgr::new(),
        max_clients,
    )
    .expect("start rpc listener");
    let port = listener.bound_addrs()[0].port();
    (dir, listener, port, genesis_hash, shared_chain)
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
    let (cert_pem, key_pem) =
        dcroxide_node::rpcrun::load_or_generate_cert_pair(&cert_path, &key_path, &[])
            .expect("generate cert pair");
    assert!(cert_path.exists() && key_path.exists());
    // A second load reuses the written pair.
    let (cert_again, _) =
        dcroxide_node::rpcrun::load_or_generate_cert_pair(&cert_path, &key_path, &[])
            .expect("reload cert pair");
    assert_eq!(cert_pem, cert_again);

    let tls =
        dcroxide_node::rpcrun::tls_server_config(&cert_pem, &key_pem).expect("build tls config");

    // A chain-backed server exactly like the plain-HTTP fixture.
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    let server = Arc::new(Mutex::new(Server::new(Config {
        chain: NodeRpcChain::new(chain, params.clone()),
        chain_params: params.clone(),
        subsidy_cache: SubsidyCache::new(RpcSubsidyParams(params.clone())),
        min_relay_tx_fee: 10000,
        max_protocol_version: PROTOCOL_VERSION,
        sync_mgr: Box::new(()),
        conn_mgr: Box::new(()),
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
    })));
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
