// SPDX-License-Identifier: ISC
//! The node's half of the Go interop matrix ADR-0015 holds the switch to
//! (T10): Go's `crypto/tls`, through the oracle's TLS commands, against
//! the node's production TLS code alone, the RPC listener as
//! `start_rpc_listener` serves it over `reloadable_tls_config` and the
//! seeder transports `UreqTransport` and `ProxySeederTransport` over the
//! direct dialer, so that the same file runs before the switch, on ring's
//! provider, and after it, on `dcroxide-tlscrypto`'s.  The provider's own
//! half is that crate's `tests/go_interop.rs`.  The oracle runs under
//! dcrd's `GODEBUG` (`dcroxide_testutil::tls_interop::DCRD_TLS_GODEBUG`),
//! so Go's default client and server are dcrd's at the parity pin, the
//! three hybrids first.
//!
//! - **Go's client against the RPC listener.**  Each server key, P-256
//!   and P-521 from certgen, as the daemon's first start makes them,
//!   P-384 and Ed25519 from the gencerts machinery, and RSA-2048 from the
//!   test-key fixture certified by `tls_pki`, by each client profile: Go's
//!   default; TLS 1.2 alone; each group alone in TLS 1.3 and in TLS 1.2;
//!   each ECDHE suite of the key's kind alone in TLS 1.2; and a share for
//!   a group the listener lacks, SecP384r1MLKEM1024 offered with P-256
//!   and without P-384, so that its share has no classical fallback
//!   (`crypto/tls/handshake_client.go:145-159`).  Each is a `getblockcount`
//!   POST answered 200, and the version, suite, group and
//!   HelloRetryRequest the same Go client negotiates with Go's server
//!   holding the same pair: a server cut to the listener's classical
//!   groups, X25519, P-256, P-384 and P-521, agrees on every cell, and
//!   one on Go's default list on every cell but those of the two profiles
//!   the hybrids decide ([`HYBRID_GAP`]), whose differences are asserted.
//!   So Go's AES-GCM preference is compared on this machine, not assumed.
//! - **The RSA `rpc.key` cells.**  ring serves an RSA key its signer
//!   loads, 2048 to 4096 bits with an exponent of at least 65537, today;
//!   the switch refuses one (ADR-0015, T6), and the RSA-2048 cell, the one
//!   the switch flips, then expects the refusal ([`RSA_RPC_KEY_SERVED`]).
//!   The fixture's RSA-1024, RSA-8192 and e = 3 keys, which ring's signer
//!   does not load, the listener refuses at startup today, in ring's words
//!   ([`RSA_KEY_REFUSAL`]), where dcrd serves them ([`RSA_BOUNDS_GAP`]);
//!   the switch, refusing every RSA key, changes only those words.  Go's
//!   server serves each pair the listener refuses, so that the refusal is
//!   the listener's policy and not a pair no stack serves.
//! - **`--authtype=clientcert`.**  The client certificates of the
//!   provider's matrix (`dcroxide_testutil::tls_interop::ClientCerts`),
//!   each key alone and under each kind of CA, in each version, through
//!   `GoClientCertVerifier`: every cell the provider's matrix completes is
//!   accepted by the listener and by Go's server, and the three refused
//!   today, a P-521 client key, an issuer signing with ECDSA-SHA512 and an
//!   RSA-1024 client key, are refused by the listener in its handshake,
//!   with the alert Go's client reports for each and no HTTP answer, where
//!   the reference Go's server accepts them ([`CLIENTCERT_GAP`]).  The
//!   count of cells the listener accepts is asserted, and under the
//!   reference Go the count Go's server accepts, so a `tls_pki` chain
//!   every verifier refused would fail the test rather than pass each
//!   cell.
//! - **The seeder clients against Go's HTTPS server**, serving seeder
//!   JSON under a chain from `tls_pki` whose root the transports' test
//!   constructors take in place of `webpki-roots`, the provider hand-off
//!   being the daemon's: server keys P-256, P-384 and Ed25519, and an
//!   RSA-4096 root over an RSA-2048 intermediate over a P-256 leaf, the
//!   seeders' shape; TLS 1.3 and TLS 1.2; each group alone on the server,
//!   P-521 refused, since the seeders offer ring's three groups, which
//!   the switch keeps (`dcroxide_tlscrypto::DEFAULT_KX_GROUPS`).  The
//!   addresses are read through `seed_addrs`.  In each version the
//!   daemon's own constructors, `UreqTransport::new()` and
//!   `ProxySeederTransport::new()`, and the test constructors given a root
//!   that did not issue the chain refuse it as an unknown issuer, which
//!   Go's server reads as [`refused_chain`] says.  Each ClientHello, as
//!   Go's server saw it, equals
//!   `tests/data/seeder-client-hello.json`, which
//!   `regenerate_seeder_client_hello` wrote from a run on ring's provider
//!   and the switch must reproduce: the same suites, groups, signature
//!   schemes and versions, each in order, and the same extensions, as a
//!   set, since rustls orders them at random for each ClientHello
//!   (`rustls-0.23.46/src/msgs/handshake.rs:1063-1093`).  The description
//!   is of a ClientHello to a seeder named by its address, as these cells
//!   name Go's server, so it has no server_name extension; a seeder named
//!   by a DNS name, as every seeder the daemon queries is, gets one, which
//!   a cell naming ureq's seeder `localhost` checks; the proxy's client
//!   reaches a name only through a proxy.  So the daemon's constructors'
//!   hand-off, which no local chain gets through, is compared too.
//!
//! The oracle, the certificates, the client-certificate cells and Go's
//! report of a connection are `dcroxide_testutil::tls_interop`'s, shared
//! with the provider's matrix.  Each test starts one oracle, runs its
//! cells in turn and prints the handshakes they made, its wall time and
//! the Go that answered.  Without an oracle, or with one whose Go is older
//! than 1.26, the tests skip, unless `DCROXIDE_REQUIRE_ORACLE` is set, as
//! in CI, where they also require the reference Go, whose words for each
//! refusal the cells compare ([`assert_refused_by_the_node`] says where a
//! reset may stand in for them).  Nothing leaves loopback, and each of
//! Go's connections has a deadline.

// Test-harness arithmetic: counts of cells and fixed times.
#![allow(clippy::arithmetic_side_effects)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use dcroxide_addrmgr::{HttpsSeederFilters, SeedEnv, SeederTransport, seed_addrs};
use dcroxide_blockchain::process::Chain;
use dcroxide_certgen::Curve;
use dcroxide_certgen::gentool;
use dcroxide_database::{Database, Options};
use dcroxide_node::rpcrun::{NodeRpcChain, RpcListener, start_rpc_listener};
use dcroxide_node::seeding::{ProxySeederTransport, UreqTransport};
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::server::{Config, Server};
use dcroxide_standalone::SubsidyCache;
use dcroxide_testutil::tls_interop::{ClientCerts, Issued, Negotiated, TlsOracle, spec};
use dcroxide_testutil::{REFERENCE_GO, hex};
use dcroxide_wire::PROTOCOL_VERSION;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};

/// Whether the listener serves an RSA `rpc.key` ring's signer loads, 2048
/// to 4096 bits with an exponent of at least 65537.  ring signs with one
/// today; the switch refuses it at startup and on rotation (ADR-0015,
/// T6), and with it this, the one cell of the matrix the switch flips.
/// The refusal's branch shows Go's server serving the pair, and the switch
/// also pins T6's refusal text there, which only it can write.
const RSA_RPC_KEY_SERVED: bool = true;

/// The fixture's RSA keys ring's signer does not load: under 2048 bits,
/// over 4096, and with an exponent under 65537
/// (`ring-0.17.14/src/rsa/keypair.rs:268-285`,
/// `ring-0.17.14/src/rsa.rs:35`).  Go's server, as dcrd's, serves each to
/// Go's client, which takes a server key of up to 8192 bits
/// (`crypto/tls/handshake_client.go:1085-1112`).
const RSA_KEYS_RING_REFUSES: [&str; 3] = ["rsa1024", "rsa8192", "rsa2048-e3"];

/// What the listener refuses [`RSA_KEYS_RING_REFUSES`] with today: ring's
/// key loader's words for a key none of its signers takes
/// (`rustls-0.23.46/src/crypto/ring/sign.rs:21-40`).  The switch refuses
/// every RSA key with T6's words, which take these words' place, so for
/// these keys it changes only the text.
const RSA_KEY_REFUSAL: &str = "failed to parse private key as RSA, ECDSA, or EdDSA";

/// The PARITY.md entry the listener's refusal of RSA keys dcrd serves
/// belongs to.
const RSA_BOUNDS_GAP: &str = "PARITY.md, \"The RPC listener refuses an RSA `rpc.key` that ring \
                              cannot sign with\"";

/// The PARITY.md entry the listener's differences from Go's default
/// server belong to: Go's server takes a hybrid post-quantum group the
/// client supports ahead of any group the client sent a share for
/// (`crypto/tls/handshake_server_tls13.go:201-246`), and the listener has
/// none until ADR-0015's T3.
const HYBRID_GAP: &str = "PARITY.md, \"The RPC listener's TLS key exchange is classical where \
                          dcrd's is hybrid post-quantum\"";

/// The PARITY.md entry the listener's refusals of client certificates Go
/// accepts belong to: P-521 keys, ECDSA with SHA-512 and RSA keys under
/// 2048 bits, which ring's verification set lacks and Go's
/// client-certificate set (ADR-0015, T4) adds.
const CLIENTCERT_GAP: &str = "PARITY.md, \"Under `--authtype=clientcert` webpki and ring still \
                              decide part of a client chain\"";

/// The listener's classical groups, Go's default list less the hybrids
/// (`rpctls.rs`'s `RPC_KX_GROUP_IDS`), by Go's names.
const CLASSICAL: [&str; 4] = ["X25519", "CurveP256", "CurveP384", "CurveP521"];

/// Go's client dialing `addr` with `fields`, naming localhost, trusting
/// `root`, and sending `request`: the `tls_dial` detail.
fn dial(go: &mut TlsOracle, addr: &str, root: &[u8], fields: &Value, request: &Value) -> Value {
    let mut fields = fields.clone();
    fields["addr"] = json!(addr);
    fields["server_name"] = json!("localhost");
    fields["roots"] = json!([hex(root)]);
    fields["request"] = request.clone();
    go.dial(fields)
}

/// Go's server listening with `fields`, answering a JSON-RPC result when
/// they name no response body: its address and its id.
fn listen(go: &mut TlsOracle, mut fields: Value) -> (String, Value) {
    if fields.get("response_body").is_none() {
        fields["response_body"] = json!("{\"result\":0,\"error\":null,\"id\":1}");
    }
    go.listen(fields)
}

/// Go's client with `fields` and `request` against Go's server holding
/// `pair`, its groups cut to `groups` or Go's default list for none: what
/// the two negotiated, which each must report alike.
fn reference(
    go: &mut TlsOracle,
    pair: &Pair,
    groups: Option<&[&str]>,
    fields: &Value,
    request: &Value,
) -> Negotiated {
    let (addr, id) = listen(
        go,
        json!({
            "chain": [hex(&pair.cert)],
            "key_pkcs8": hex(&pair.key_pkcs8),
            "curve_preferences": groups,
        }),
    );
    let detail = dial(go, &addr, &pair.cert, fields, request);
    let served = go.served(&id);
    let what = format!("{}, Go's server on {groups:?}", pair.name);
    assert_eq!(detail["ok"], true, "{what}: Go's client {detail}");
    assert_eq!(served["ok"], true, "{what}: Go's server {served}");
    let negotiated = Negotiated::of_go(&detail).expect("a completed handshake");
    assert_eq!(
        Negotiated::of_go(&served).as_ref(),
        Some(&negotiated),
        "{what}"
    );
    negotiated
}

/// [`TlsOracle::assert_refused`] for a refusal the node makes of Go's end,
/// which Go may see as a reset in place of the node's alert.  The node
/// closes a failed connection at once, as Go's own server does, and when
/// Go's bytes are still unread there, its system sends a reset; a system
/// that throws away what it has received when a reset arrives, as Go's
/// `net/http` says of BSD systems and suspects of Windows
/// (`net/http/server.go:1759-1764`), then shows Go the reset and not the
/// alert.  On Linux, where these tests have run, the alert arrives, and
/// Go's words are held to the reference Go's; elsewhere a reset passes
/// too.
fn assert_refused_by_the_node(go: &TlsOracle, what: &str, detail: &Value, error: &str) {
    let text = detail["error"].as_str().unwrap_or_default();
    let reset = text.ends_with("connection reset by peer")
        || text.contains("forcibly closed by the remote host");
    if cfg!(target_os = "linux") || !reset {
        go.assert_refused(what, detail, error);
    } else {
        assert_eq!(detail["ok"], false, "{what}: Go's end {detail}");
    }
}

/// The TLS 1.2 suites of an ECDSA or Ed25519 key, by Go's names.
const ECDSA_SUITES: [&str; 3] = [
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
];

/// The TLS 1.2 suites of an RSA key, by Go's names.
const RSA_SUITES: [&str; 3] = [
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
];

/// A certificate and key the listener serves as `rpc.cert` and `rpc.key`
/// and Go's reference server holds alike.
struct Pair {
    name: &'static str,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    /// The certificate: what Go's clients trust, and what Go's server
    /// sends.
    cert: Vec<u8>,
    /// The key, PKCS#8, for Go's server.
    key_pkcs8: Vec<u8>,
    /// The TLS 1.2 suites of the key's kind.
    tls12_suites: [&'static str; 3],
}

/// The scripted gencerts environment: a fixed time and counted serials.
struct GenEnvAt(i64, u8);

impl gentool::GenEnv for GenEnvAt {
    fn now_unix(&mut self) -> i64 {
        self.0
    }

    fn serial_bytes(&mut self) -> Vec<u8> {
        self.1 = self.1.wrapping_add(1);
        vec![self.1]
    }
}

impl Pair {
    /// A pair as the daemon's first start generates one on `curve`, by
    /// certgen, written in `dir`.
    fn certgen(name: &'static str, dir: &tempfile::TempDir, curve: Curve) -> Pair {
        let (cert_pem, key_pem) = dcroxide_node::rpcrun::load_or_generate_cert_pair(
            &dir.path().join(format!("{curve:?}.cert")),
            &dir.path().join(format!("{curve:?}.key")),
            &[],
            curve,
        )
        .expect("a certgen pair");
        Pair::of_pem(name, cert_pem, key_pem, ECDSA_SUITES)
    }

    /// A pair as gencerts makes one on `algo`: a self-signed authority
    /// for localhost.
    fn gencerts(name: &'static str, algo: &str) -> Pair {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock")
            .as_secs();
        let key = gentool::generate_key(algo).expect("a gencerts key");
        let cert = gentool::generate_authority(
            &mut GenEnvAt(i64::try_from(now).expect("a time"), 0),
            &key,
            &["localhost".to_owned()],
            "gencerts",
            1,
            false,
        )
        .expect("a gencerts authority");
        let key_pem = gentool::pem_private_key(&key.marshal_pkcs8().expect("PKCS#8"));
        Pair::of_pem(name, cert.pem, key_pem, ECDSA_SUITES)
    }

    /// The pair `tls_pki` made.
    fn issued(name: &'static str, issued: &Issued, tls12_suites: [&'static str; 3]) -> Pair {
        Pair {
            name,
            cert_pem: issued.cert_pem.clone(),
            key_pem: issued.key_pem.clone(),
            cert: issued.cert.clone(),
            key_pkcs8: issued.key_pkcs8.clone(),
            tls12_suites,
        }
    }

    /// The pair in `cert_pem` and `key_pem`, its key read by gencerts'
    /// parser under its PEM label and given to Go's server in PKCS#8.
    fn of_pem(
        name: &'static str,
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
        tls12_suites: [&'static str; 3],
    ) -> Pair {
        let cert = CertificateDer::from_pem_slice(&cert_pem)
            .expect("a certificate")
            .as_ref()
            .to_vec();
        let key = PrivateKeyDer::from_pem_slice(&key_pem).expect("a key");
        let label = match key {
            PrivateKeyDer::Sec1(_) => "EC PRIVATE KEY",
            _ => "PRIVATE KEY",
        };
        let key_pkcs8 = gentool::parse_private_key(label, key.secret_der())
            .and_then(|key| key.marshal_pkcs8())
            .expect("a key gencerts reads");
        Pair {
            name,
            cert_pem,
            key_pem,
            cert,
            key_pkcs8,
            tls12_suites,
        }
    }
}

/// The RPC listener as the daemon starts it.
struct Listening {
    /// Where `rpc.cert`, `rpc.key`, `clients.pem` and the chain live.
    _dir: tempfile::TempDir,
    listener: RpcListener,
    /// Its loopback address.
    addr: String,
}

/// Start the RPC listener as the daemon does, over `pair` written to
/// `rpc.cert` and `rpc.key`, and under `--authtype=clientcert` when
/// `client_cas` is given, written to `clients.pem`, with no Basic
/// credentials, which dcrd refuses under that auth type; a genesis testnet
/// chain answers `getblockcount`.  A configuration the files do not build
/// is the error.
fn listen_rpc(pair: &Pair, client_cas: Option<&[u8]>) -> Result<Listening, String> {
    let params = dcroxide_chaincfg::testnet3_params();
    let dir = tempfile::tempdir().expect("a temp dir");
    let cert_path = dir.path().join("rpc.cert");
    let key_path = dir.path().join("rpc.key");
    std::fs::write(&cert_path, &pair.cert_pem).expect("rpc.cert written");
    std::fs::write(&key_path, &pair.key_pem).expect("rpc.key written");
    let client_cas_path = client_cas.map(|pem| {
        let path = dir.path().join("clients.pem");
        std::fs::write(&path, pem).expect("clients.pem written");
        path
    });
    let tls = dcroxide_node::rpcrun::reloadable_tls_config(
        &cert_path,
        &key_path,
        client_cas_path.as_deref(),
        dcroxide_node::rpcrun::RPC_TLS_MIN_RELOAD_CHECK_DELAY,
    )?;
    let (rpc_user, rpc_pass) = match client_cas {
        Some(_) => (String::new(), String::new()),
        None => ("user".to_owned(), "pass".to_owned()),
    };
    let db = Database::create(&Options::new(dir.path().join("blocks"), params.net.0))
        .expect("a database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("a chain"),
    ));
    let server = Arc::new(Server::new(Config {
        chain: NodeRpcChain::new(chain, params.clone()),
        chain_params: params.clone(),
        subsidy_cache: Mutex::new(SubsidyCache::new(params.clone())),
        min_relay_tx_fee: 10000,
        max_protocol_version: PROTOCOL_VERSION,
        sync_mgr: Box::new(()),
        conn_mgr: Box::new(()),
        client_cert_auth: client_cas.is_some(),
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
        user_agent_version: "0.1.0".to_owned(),
        net_info: Vec::new(),
        services: 0,
        request_shutdown: Box::new(|| {}),
        allow_unsynced_mining: false,
        rpc_user,
        rpc_pass,
        rpc_limit_user: String::new(),
        rpc_limit_pass: String::new(),
    }));
    let listener = start_rpc_listener(
        &["127.0.0.1:0".to_owned()],
        server,
        dcroxide_node::rpcrun::RpcTransport::Tls(tls),
        dcroxide_node::websocket::NodeNtfnMgr::new(),
        128,
    )
    .expect("the listener");
    let addr = listener.bound_addrs()[0].to_string();
    Ok(Listening {
        _dir: dir,
        listener,
        addr,
    })
}

/// A `getblockcount` POST, with the listener's Basic credentials when
/// `credentials`.
fn getblockcount(credentials: bool) -> Value {
    let mut headers = json!({ "Content-Type": "application/json" });
    if credentials {
        let basic = dcroxide_rpc::http::base64_std_encode(b"user:pass");
        headers["Authorization"] = json!(format!("Basic {basic}"));
    }
    json!({
        "method": "POST",
        "path": "/",
        "headers": headers,
        "body": "{\"jsonrpc\":\"1.0\",\"method\":\"getblockcount\",\"params\":[],\"id\":1}",
    })
}

/// Whether the listener answered `detail`'s request: 200, with the
/// genesis chain's block count.
fn answered(detail: &Value) -> bool {
    detail["ok"] == true
        && detail["http_status"] == 200
        && detail["http_body"]
            .as_str()
            .is_some_and(|body| body.contains("\"result\":0"))
}

/// A Go client profile: its name, its `tls_dial` fields, and, where Go's
/// default server takes a hybrid with it that the listener lacks, the
/// group and HelloRetryRequest the listener gives it and those Go's
/// server gives it instead ([`HYBRID_GAP`]).
struct Profile {
    name: String,
    dial: Value,
    hybrid: Option<[(&'static str, bool); 2]>,
}

/// The client profiles for `pair`.
fn profiles(pair: &Pair) -> Vec<Profile> {
    let profile = |name: String, dial: Value| Profile {
        name,
        dial,
        hybrid: None,
    };
    let mut profiles = vec![
        // Go's default client offers the three hybrids with an
        // X25519MLKEM768 share and an X25519 one.
        Profile {
            name: "Go's default".to_owned(),
            dial: json!({}),
            hybrid: Some([("X25519", false), ("X25519MLKEM768", false)]),
        },
        profile("TLS 1.2".to_owned(), json!({ "max_version": "TLS 1.2" })),
    ];
    for group in CLASSICAL {
        profiles.push(profile(
            format!("TLS 1.3, {group} alone"),
            json!({ "min_version": "TLS 1.3", "curve_preferences": [group] }),
        ));
        profiles.push(profile(
            format!("TLS 1.2, {group} alone"),
            json!({ "max_version": "TLS 1.2", "curve_preferences": [group] }),
        ));
    }
    for suite in pair.tls12_suites {
        profiles.push(profile(
            format!("TLS 1.2, {suite} alone"),
            json!({ "max_version": "TLS 1.2", "cipher_suites": [suite] }),
        ));
    }
    // A share for SecP384r1MLKEM1024 alone: the listener asks for P-256
    // with a HelloRetryRequest, and Go's default server takes the hybrid.
    profiles.push(Profile {
        name: "a SecP384r1MLKEM1024 share, with P-256".to_owned(),
        dial: json!({ "curve_preferences": ["SecP384r1MLKEM1024", "CurveP256"] }),
        hybrid: Some([("CurveP256", true), ("SecP384r1MLKEM1024", false)]),
    });
    profiles
}

/// Go's client against the RPC listener, by server key and client
/// profile, each cell compared with Go's server cut to the listener's
/// classical groups and with Go's default server; and the RSA `rpc.key`
/// cells.
#[test]
fn go_clients_handshake_with_the_rpc_listener() {
    let Some(mut go) = TlsOracle::start() else {
        return;
    };
    let dir = tempfile::tempdir().expect("a temp dir");
    let mut specs = vec![spec("RSA-2048", "rsa2048", None, "server")];
    specs.extend(RSA_KEYS_RING_REFUSES.map(|key| spec(key, key, None, "server")));
    let rsa = go.pki(&specs);
    let pairs = [
        Pair::certgen("P-256 from certgen", &dir, Curve::P256),
        Pair::certgen("P-521 from certgen", &dir, Curve::P521),
        Pair::gencerts("P-384 from gencerts", "P-384"),
        Pair::gencerts("Ed25519 from gencerts", "Ed25519"),
        Pair::issued("RSA-2048 from tls_pki", &rsa["RSA-2048"], RSA_SUITES),
    ];
    let request = getblockcount(true);
    let mut compared = 0;
    for pair in &pairs {
        let rsa = pair.name.starts_with("RSA");
        let listening = match listen_rpc(pair, None) {
            Ok(listening) => {
                assert!(!rsa || RSA_RPC_KEY_SERVED, "{}: served", pair.name);
                listening
            }
            Err(e) => {
                assert!(rsa && !RSA_RPC_KEY_SERVED, "{}: refused: {e}", pair.name);
                // Go's server serves the pair the listener refuses.
                reference(&mut go, pair, Some(&CLASSICAL), &json!({}), &request);
                continue;
            }
        };
        for profile in profiles(pair) {
            let what = format!("{}, {}", pair.name, profile.name);
            let detail = dial(
                &mut go,
                &listening.addr,
                &pair.cert,
                &profile.dial,
                &request,
            );
            assert!(answered(&detail), "{what}: the listener {detail}");
            let ours = Negotiated::of_go(&detail).expect("a completed handshake");
            let classical = reference(&mut go, pair, Some(&CLASSICAL), &profile.dial, &request);
            let default = reference(&mut go, pair, None, &profile.dial, &request);
            assert_like_go(&what, &ours, &classical, &default, profile.hybrid);
            compared += 1;
        }
        listening.listener.shutdown();
    }
    // The RSA keys ring's signer does not load: refused at startup, where
    // Go's server serves each.
    for key in RSA_KEYS_RING_REFUSES {
        let pair = Pair::issued(key, &rsa[key], RSA_SUITES);
        match listen_rpc(&pair, None) {
            Ok(listening) => {
                listening.listener.shutdown();
                panic!("{key}: served, where {RSA_BOUNDS_GAP} records a refusal");
            }
            Err(e) => assert!(e.contains(RSA_KEY_REFUSAL), "{key}: refused: {e}"),
        }
        reference(&mut go, &pair, Some(&CLASSICAL), &json!({}), &request);
    }
    go.report("go_clients_handshake_with_the_rpc_listener");
    let profiles = 1 + 1 + 2 * CLASSICAL.len() + 3 + 1;
    let keys = if RSA_RPC_KEY_SERVED { 5 } else { 4 };
    assert_eq!(compared, keys * profiles, "every key by every profile");
    assert_eq!(
        go.handshakes(),
        keys * profiles * 3 + (5 - keys) + RSA_KEYS_RING_REFUSES.len(),
        "every cell with the listener and Go's two servers, and Go's server serving each pair \
         the listener refuses"
    );
}

/// What the listener negotiated with a Go client, `ours`, against what the
/// same client negotiated with Go's server holding the same pair, cut to
/// the listener's classical groups, `classical`, and on Go's default list,
/// `default`: equal to the first, and to the second but where the
/// profile's `hybrid` entry names the listener's group and
/// HelloRetryRequest and the hybrid Go's default server takes in their
/// place ([`HYBRID_GAP`]).
fn assert_like_go(
    what: &str,
    ours: &Negotiated,
    classical: &Negotiated,
    default: &Negotiated,
    hybrid: Option<[(&str, bool); 2]>,
) {
    assert_eq!(
        ours, classical,
        "{what}: Go's server on the classical groups"
    );
    match hybrid {
        None => assert_eq!(ours, default, "{what}: Go's default server"),
        Some([(our_group, our_retry), (go_group, go_retry)]) => {
            assert_eq!(
                (ours.group.as_str(), ours.hello_retry_request),
                (our_group, our_retry),
                "{what}: the listener"
            );
            let differs = Negotiated {
                group: go_group.to_owned(),
                hello_retry_request: go_retry,
                ..ours.clone()
            };
            assert_eq!(
                *default, differs,
                "{what}: Go's default server, which differs as {HYBRID_GAP} records"
            );
        }
    }
}

/// `--authtype=clientcert`: each client certificate cell, in each version,
/// presented by Go's client to the listener, through
/// `GoClientCertVerifier`, and to Go's server requiring and verifying
/// client certificates under the same roots.
#[test]
fn go_client_certificates_under_clientcert_auth() {
    let Some(mut go) = TlsOracle::start() else {
        return;
    };
    let dir = tempfile::tempdir().expect("a temp dir");
    let server = Pair::certgen("P-256 from certgen", &dir, Curve::P256);
    let clients = ClientCerts::make(&mut go);
    let clients_pem: Vec<u8> = clients
        .trusted
        .iter()
        .flat_map(|ca| ca.cert_pem.clone())
        .collect();
    let client_cas: Vec<String> = clients.trusted.iter().map(|ca| hex(&ca.cert)).collect();
    let listening = listen_rpc(&server, Some(&clients_pem)).expect("a clientcert listener");
    let request = getblockcount(false);
    let (mut ours_accepted, mut theirs_accepted) = (0, 0);
    for (version, fields) in [
        ("TLS 1.3", json!({ "min_version": "TLS 1.3" })),
        ("TLS 1.2", json!({ "max_version": "TLS 1.2" })),
    ] {
        for (name, client, refusal) in &clients.cells {
            let what = format!("{version}, {name}");
            let mut fields = fields.clone();
            fields["client_cert"] = client.identity(&[]);
            let detail = dial(&mut go, &listening.addr, &server.cert, &fields, &request);
            let ours = answered(&detail);
            let (addr, id) = listen(
                &mut go,
                json!({
                    "chain": [hex(&server.cert)],
                    "key_pkcs8": hex(&server.key_pkcs8),
                    "client_auth": "RequireAndVerifyClientCert",
                    "client_cas": client_cas,
                }),
            );
            dial(&mut go, &addr, &server.cert, &fields, &request);
            let served = go.served(&id);
            let theirs = served["ok"] == true;
            if theirs {
                assert_eq!(
                    served["peer_certificates"],
                    json!([hex(&client.cert)]),
                    "{what}: Go's server"
                );
            }
            match refusal {
                None => {
                    assert!(ours, "{what}: the listener {detail}");
                    assert!(theirs, "{what}: Go's server {served}");
                }
                Some(refusal) => {
                    // The listener refuses the certificate in its
                    // handshake, with the alert that names why, and
                    // answers nothing.
                    assert_refused_by_the_node(&go, &what, &detail, refusal.go_error(version));
                    assert_eq!(detail["http_status"], 0, "{what}: the listener {detail}");
                    // The reference Go's server accepts it, the difference
                    // the PARITY entry records; another Go may refuse it
                    // too.
                    assert!(
                        theirs || go.go_version() != REFERENCE_GO,
                        "{what}: Go's server, which accepts it as {CLIENTCERT_GAP} records: \
                         {served}"
                    );
                }
            }
            ours_accepted += usize::from(ours);
            theirs_accepted += usize::from(theirs);
        }
    }
    listening.listener.shutdown();
    go.report("go_client_certificates_under_clientcert_auth");
    assert_eq!(
        ours_accepted, 48,
        "four keys alone and under five authorities in two versions, accepted by the listener"
    );
    if go.go_version() == REFERENCE_GO {
        assert_eq!(
            theirs_accepted, 54,
            "those and the three refused today, in two versions, accepted by Go's server"
        );
    }
    assert_eq!(
        go.handshakes(),
        2 * clients.cells.len() * 2,
        "every cell in two versions, with the listener and with Go's server"
    );
}

/// The seeder JSON Go's server answers with: two loopback addresses,
/// one a line, as the seeders stream them.
const SEEDER_BODY: &str = "{\"host\":\"127.0.0.1:9108\",\"services\":1,\"pver\":11}\n\
                           {\"host\":\"[::1]:19108\",\"services\":5,\"pver\":11}\n";

/// The seeding environment: a fixed time and no randomness.
struct FixedEnv;

impl SeedEnv for FixedEnv {
    fn now_nanos(&mut self) -> i64 {
        1_800_000_000_000_000_000
    }

    fn rand_duration(&mut self, _max_nanos: i64) -> i64 {
        0
    }
}

/// The seeder transports, by name.
const TRANSPORTS: [&str; 2] = ["ureq", "proxy"];

/// The addresses the seeder at `addr` gives `transport`, the one named,
/// as the port and services of each: verifying the seeder's chain to
/// `root` alone, through the transport's test constructor, or, for none,
/// to `webpki-roots`, through the daemon's.
fn seed(transport: &str, addr: &str, root: Option<&[u8]>) -> Result<Vec<(u16, u64)>, String> {
    let roots: Vec<CertificateDer<'_>> = root.into_iter().map(CertificateDer::from).collect();
    let direct = dcroxide_node::socks::NodeDialer::direct;
    let found = match (transport, root) {
        ("ureq", Some(_)) => seed_with(addr, UreqTransport::with_root_certs(&roots)),
        ("ureq", None) => seed_with(addr, UreqTransport::new()),
        (_, Some(_)) => seed_with(
            addr,
            ProxySeederTransport::with_root_certs(direct(), &roots),
        ),
        (_, None) => seed_with(addr, ProxySeederTransport::new(direct())),
    }?;
    Ok(found
        .iter()
        .map(|addr| (addr.port, addr.services.0))
        .collect())
}

/// `seed_addrs` over `transport`.
fn seed_with(
    addr: &str,
    mut transport: impl SeederTransport,
) -> Result<Vec<dcroxide_wire::NetAddress>, String> {
    seed_addrs(
        addr,
        &mut transport,
        &mut FixedEnv,
        &HttpsSeederFilters::default(),
    )
}

/// Go's HTTPS seeder: a server with `fields` answering [`SEEDER_BODY`].
fn seeder(go: &mut TlsOracle, mut fields: Value) -> (String, Value) {
    fields["response_body"] = json!(SEEDER_BODY);
    go.listen(fields)
}

/// What Go's server reads when a seeder transport refuses its chain in
/// `version`: the unknown_ca alert in TLS 1.2, and in TLS 1.3 the
/// connection's end, with no alert.  rustls makes one write after a
/// failed handshake (`rustls-0.23.46/src/conn.rs:697-700`) and hands it
/// its queue in one `write_vectored` call
/// (`rustls-0.23.46/src/vecbuf.rs:207`), and in TLS 1.3 its client queued
/// the middlebox-compatibility ChangeCipherSpec at the ServerHello
/// (`rustls-0.23.46/src/client/tls13.rs:233`), ahead of the alert.  Both
/// transports' connections write one buffer a call, the proxy's
/// `DeadlineStream` and ureq's `TransportAdapter` having no
/// `write_vectored` of their own, so the ChangeCipherSpec goes and the
/// alert does not.  Go's client sends its alert.
fn refused_chain(version: &str) -> &'static str {
    match version {
        "TLS 1.3" => "EOF",
        _ => "remote error: tls: unknown certificate authority",
    }
}

/// The error each transport gives up on a seeder's chain with when none of
/// its roots issued it.
fn unknown_issuer(transport: &str) -> String {
    match transport {
        "ureq" => "seeder request failed: io: invalid peer certificate: UnknownIssuer",
        _ => "seeder request failed: invalid peer certificate: UnknownIssuer",
    }
    .to_owned()
}

/// A ClientHello as Go's server saw it, its extensions sorted.
fn described(hello: &Value) -> Value {
    let mut hello = hello.clone();
    let mut extensions: Vec<u64> = hello["extensions"]
        .as_array()
        .expect("a ClientHello's extensions")
        .iter()
        .map(|extension| extension.as_u64().expect("an extension"))
        .collect();
    extensions.sort_unstable();
    hello["extensions"] = json!(extensions);
    hello
}

/// Assert that `hello`, a ClientHello as Go's server saw it, is `want`, a
/// description: its suites, groups, signature schemes and versions in
/// order, and its extensions as a set.
fn assert_hello(what: &str, hello: &Value, want: &Value) {
    assert_eq!(
        &described(hello),
        want,
        "{what}: the ClientHello, against {}",
        seeder_client_hello_path().display()
    );
}

/// Where the seeders' recorded ClientHello lives.
fn seeder_client_hello_path() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("seeder-client-hello.json")
}

/// The seeders' recorded ClientHello, each transport's.
fn recorded_client_hello() -> Value {
    let path = seeder_client_hello_path();
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// The seeder clients against Go's HTTPS server: each transport, by
/// server chain, by version, by the group the server takes, the
/// addresses read; the daemon's constructors and a root that did not issue
/// the chain refused, in each version; a seeder named by a DNS name; and
/// each ClientHello the recorded one.
#[test]
fn seeder_clients_handshake_with_go_servers() {
    let Some(mut go) = TlsOracle::start() else {
        return;
    };
    let recorded = recorded_client_hello();
    let pki = go.pki(&[
        spec("P-256", "P-256", None, "server"),
        spec("P-384", "P-384", None, "server"),
        spec("Ed25519", "Ed25519", None, "server"),
        spec("RSA-4096 root", "rsa4096", None, "ca"),
        spec(
            "RSA-2048 intermediate",
            "rsa2048",
            Some(("RSA-4096 root", "SHA256-RSA")),
            "ca",
        ),
        spec(
            "P-256 under RSA-2048",
            "P-256",
            Some(("RSA-2048 intermediate", "SHA256-RSA")),
            "server",
        ),
    ]);
    // Each chain: its name, the certificates the server sends, and the
    // root the transports trust.
    let chains = [
        ("P-256", vec!["P-256"], "P-256"),
        ("P-384", vec!["P-384"], "P-384"),
        ("Ed25519", vec!["Ed25519"], "Ed25519"),
        (
            "RSA-4096, RSA-2048, P-256",
            vec!["P-256 under RSA-2048", "RSA-2048 intermediate"],
            "RSA-4096 root",
        ),
    ];
    let versions = [
        ("TLS 1.3", json!({ "min_version": "TLS 1.3" })),
        ("TLS 1.2", json!({ "max_version": "TLS 1.2" })),
    ];
    let p256 = &pki["P-256"];
    let mut seeded = 0;
    for transport in TRANSPORTS {
        let want_hello = &recorded[transport];
        assert!(
            want_hello.is_object(),
            "{}: no {transport}",
            seeder_client_hello_path().display()
        );
        for (chain, sent, root) in &chains {
            let server = pki[sent[0]]
                .identity(&sent[1..].iter().map(|name| &pki[*name]).collect::<Vec<_>>());
            for (version, listen) in &versions {
                for group in CLASSICAL {
                    let what = format!("{transport}, {chain}, {version}, {group}");
                    let mut listen = listen.clone();
                    listen["chain"] = server["chain"].clone();
                    listen["key_pkcs8"] = server["key_pkcs8"].clone();
                    listen["curve_preferences"] = json!([group]);
                    let (addr, id) = seeder(&mut go, listen);
                    let found = seed(transport, &addr, Some(&pki[*root].cert));
                    let served = go.served(&id);
                    assert_hello(&what, &served["client_hello"], want_hello);
                    if group == "CurveP521" {
                        // The seeders offer X25519, P-256 and P-384, so Go's
                        // server finds no group in common, or in TLS 1.2 no
                        // ECDHE suite, and says so with a handshake_failure
                        // alert.
                        let alert = match transport {
                            "ureq" => {
                                "seeder request failed: io: received fatal alert: \
                                       HandshakeFailure"
                            }
                            _ => "seeder request failed: received fatal alert: HandshakeFailure",
                        };
                        assert_eq!(found, Err(alert.to_owned()), "{what}");
                        assert_eq!(served["ok"], false, "{what}: Go's server {served}");
                        let error = served["error"].as_str().unwrap_or_default();
                        let refusal = match *version {
                            "TLS 1.3" => {
                                "tls: no key exchanges supported by both client and server"
                            }
                            _ => "tls: no cipher suite supported by both client and server",
                        };
                        assert!(
                            error.starts_with(refusal) || go.go_version() != REFERENCE_GO,
                            "{what}: Go's server {served}"
                        );
                        continue;
                    }
                    assert_eq!(found, Ok(vec![(9108, 1), (19108, 5)]), "{what}");
                    assert_eq!(served["ok"], true, "{what}: Go's server {served}");
                    let negotiated = Negotiated::of_go(&served).expect("a completed handshake");
                    // The seeders send an X25519 share, so a server that
                    // takes another group asks for its share in TLS 1.3.
                    let retried = *version == "TLS 1.3" && group != "X25519";
                    assert_eq!(
                        (negotiated.version.as_str(), negotiated.group.as_str()),
                        (*version, group),
                        "{what}"
                    );
                    assert_eq!(negotiated.hello_retry_request, retried, "{what}");
                    seeded += 1;
                }
            }
        }
        // A chain none of the transport's roots issued: the daemon's own
        // constructor, on `webpki-roots`, and the test constructor given
        // another root.  rustls refuses it with an unknown_ca alert
        // (`rustls-0.23.46/src/error.rs:642-645`), which Go's server reads
        // in TLS 1.2 ([`refused_chain`] says what it reads in TLS 1.3).
        for (version, listen) in &versions {
            for (roots, root) in [
                ("webpki-roots", None),
                ("another root", Some(&pki["P-384"])),
            ] {
                let what = format!("{transport}, {roots}, {version}");
                let mut listen = listen.clone();
                listen["chain"] = json!([hex(&p256.cert)]);
                listen["key_pkcs8"] = json!(hex(&p256.key_pkcs8));
                let (addr, id) = seeder(&mut go, listen);
                let found = seed(transport, &addr, root.map(|issued| issued.cert.as_slice()));
                let served = go.served(&id);
                assert_hello(&what, &served["client_hello"], want_hello);
                assert_eq!(found, Err(unknown_issuer(transport)), "{what}");
                assert_refused_by_the_node(&go, &what, &served, refused_chain(version));
            }
        }
        // A seeder named by a DNS name, as the daemon's are: the same
        // ClientHello with a server_name extension, 0.  The proxy's
        // client dials an address alone over the direct dialer, and a name
        // only through a proxy, so the cell is ureq's.
        if transport != "ureq" {
            continue;
        }
        let what = format!("{transport}, a seeder named localhost");
        let mut named = want_hello.clone();
        let mut extensions = named["extensions"].as_array().cloned().unwrap_or_default();
        extensions.insert(0, json!(0));
        named["extensions"] = json!(extensions);
        let (addr, id) = seeder(&mut go, p256.identity(&[]));
        let (_, port) = addr.rsplit_once(':').expect("a port");
        let found = seed(transport, &format!("localhost:{port}"), Some(&p256.cert));
        let served = go.served(&id);
        assert_hello(&what, &served["client_hello"], &named);
        assert_eq!(found, Ok(vec![(9108, 1), (19108, 5)]), "{what}");
        assert_eq!(served["ok"], true, "{what}: Go's server {served}");
    }
    go.report("seeder_clients_handshake_with_go_servers");
    assert_eq!(
        seeded,
        2 * 4 * 2 * 3,
        "two transports, four chains, two versions, three groups"
    );
    assert_eq!(
        go.handshakes(),
        2 * (4 * 2 * 4 + 2 * 2) + 1,
        "two transports, each four chains in two versions under four groups and two refused \
         roots in two versions, and ureq's seeder named localhost"
    );
}

/// Go's names for what ring's provider, the seeders' before ADR-0015's
/// switch, offers: its suites (`tls.CipherSuiteName`), groups
/// (`tls.CurveID`'s String) and verification schemes
/// (`tls.SignatureScheme`'s String).
const RING_SUITES: [(rustls::CipherSuite, &str); 9] = [
    (
        rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
        "TLS_AES_256_GCM_SHA384",
    ),
    (
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        "TLS_AES_128_GCM_SHA256",
    ),
    (
        rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        "TLS_CHACHA20_POLY1305_SHA256",
    ),
    (
        rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    ),
    (
        rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    ),
    (
        rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    ),
    (
        rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    ),
    (
        rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    ),
    (
        rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    ),
];

/// See [`RING_SUITES`].
const RING_GROUPS: [(rustls::NamedGroup, &str); 3] = [
    (rustls::NamedGroup::X25519, "X25519"),
    (rustls::NamedGroup::secp256r1, "CurveP256"),
    (rustls::NamedGroup::secp384r1, "CurveP384"),
];

/// See [`RING_SUITES`].
const RING_SCHEMES: [(rustls::SignatureScheme, &str); 9] = [
    (
        rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
        "ECDSAWithP384AndSHA384",
    ),
    (
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        "ECDSAWithP256AndSHA256",
    ),
    (rustls::SignatureScheme::ED25519, "Ed25519"),
    (rustls::SignatureScheme::RSA_PSS_SHA512, "PSSWithSHA512"),
    (rustls::SignatureScheme::RSA_PSS_SHA384, "PSSWithSHA384"),
    (rustls::SignatureScheme::RSA_PSS_SHA256, "PSSWithSHA256"),
    (rustls::SignatureScheme::RSA_PKCS1_SHA512, "PKCS1WithSHA512"),
    (rustls::SignatureScheme::RSA_PKCS1_SHA384, "PKCS1WithSHA384"),
    (rustls::SignatureScheme::RSA_PKCS1_SHA256, "PKCS1WithSHA256"),
];

/// Go's name for each of `items`, from `names`.
fn go_names<T: PartialEq + std::fmt::Debug>(
    items: impl IntoIterator<Item = T>,
    names: &[(T, &'static str)],
) -> Vec<&'static str> {
    items
        .into_iter()
        .map(|item| {
            names
                .iter()
                .find(|(known, _)| *known == item)
                .map_or_else(|| panic!("no Go name for {item:?}"), |(_, name)| *name)
        })
        .collect()
}

/// Writes `tests/data/seeder-client-hello.json`: the ClientHello each
/// seeder transport sends to a seeder named by its address, as Go's server
/// sees it, with its extensions sorted.  Ignored, since the description is
/// recorded once, from a run on ring's provider before ADR-0015's switch,
/// which must reproduce it; run it alone, under the reference Go, with
/// `cargo test -p dcroxide-node --test tls_interop -- --ignored regenerate_seeder_client_hello`.
/// It holds what it records to ring's provider's suites, groups and
/// verification schemes, named here, so it records ring's ClientHello or
/// nothing: the switch, which takes ring out, deletes this test, and the
/// description stays ring's.
#[test]
#[ignore = "regenerates the committed seeder ClientHello fixture"]
fn regenerate_seeder_client_hello() {
    let mut go = TlsOracle::start().expect("the oracle");
    let server = go.pki(&[spec("P-256", "P-256", None, "server")])["P-256"].clone();
    let ring = rustls::crypto::ring::default_provider();
    // rustls ends its suites with the renegotiation SCSV, 0x00ff, in a
    // ClientHello that offers TLS 1.2.
    let mut suites = go_names(ring.cipher_suites.iter().map(|s| s.suite()), &RING_SUITES);
    suites.push("0x00FF");
    let ring_offers = json!({
        "cipher_suites": suites,
        "supported_curves": go_names(ring.kx_groups.iter().map(|g| g.name()), &RING_GROUPS),
        "signature_schemes": go_names(
            ring.signature_verification_algorithms.supported_schemes(),
            &RING_SCHEMES,
        ),
        "supported_versions": ["TLS 1.3", "TLS 1.2"],
    });
    let mut fixture = json!({
        "about": "The ClientHello each seeder transport of dcroxide-node sends to a seeder named \
                  by its address, so without the server_name extension a seeder named by a DNS \
                  name gets, as Go's crypto/tls server sees it (ClientHelloInfo), its extensions \
                  sorted, since rustls orders them at random for each ClientHello: recorded by \
                  tests/tls_interop.rs's regenerate_seeder_client_hello under the reference Go, \
                  from a run on the provider below, before ADR-0015's switch, which must \
                  reproduce it, and read by seeder_clients_handshake_with_go_servers.",
        "provider": "ring 0.17.14 through rustls 0.23.46",
    });
    for transport in TRANSPORTS {
        let (addr, id) = seeder(&mut go, server.identity(&[]));
        let found = seed(transport, &addr, Some(&server.cert));
        let served = go.served(&id);
        assert_eq!(found, Ok(vec![(9108, 1), (19108, 5)]), "{transport}");
        let hello = described(&served["client_hello"]);
        for (field, offered) in ring_offers.as_object().expect("an object") {
            assert_eq!(
                &hello[field], offered,
                "{transport}: {field}, against ring's provider"
            );
        }
        fixture[transport] = hello;
    }
    assert_eq!(
        go.go_version(),
        REFERENCE_GO,
        "the description is the reference Go's"
    );
    fixture["go_version"] = json!(go.go_version());
    let mut text = serde_json::to_string_pretty(&fixture).expect("the fixture");
    text.push('\n');
    let path = seeder_client_hello_path();
    std::fs::write(&path, text).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

/// [`assert_like_go`] holds the listener to Go's server on the classical
/// groups on every cell, and to Go's default server but where the
/// profile names the hybrid it takes: the check every RPC cell rests on,
/// run without the oracle.
#[test]
fn the_listener_is_held_to_both_go_servers() {
    let ours = Negotiated::new("TLS 1.3", "TLS_AES_128_GCM_SHA256", "X25519", false);
    let other_suite = Negotiated {
        suite: "TLS_AES_256_GCM_SHA384".to_owned(),
        ..ours.clone()
    };
    let hybrid = Negotiated {
        group: "X25519MLKEM768".to_owned(),
        ..ours.clone()
    };
    let gap = Some([("X25519", false), ("X25519MLKEM768", false)]);
    let holds = |classical: &Negotiated, default: &Negotiated, entry| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_like_go("a cell", &ours, classical, default, entry);
        }))
        .is_ok()
    };
    assert!(holds(&ours, &ours, None));
    assert!(holds(&ours, &hybrid, gap));
    let elsewhere = Some([("CurveP256", true), ("X25519MLKEM768", false)]);
    for (what, classical, default, entry) in [
        (
            "another suite on the classical groups",
            &other_suite,
            &ours,
            None,
        ),
        (
            "another suite on the default list",
            &ours,
            &other_suite,
            None,
        ),
        ("a hybrid where none is listed", &ours, &hybrid, None),
        ("no hybrid where one is listed", &ours, &ours, gap),
        (
            "another suite beside the hybrid",
            &other_suite,
            &hybrid,
            gap,
        ),
        (
            "the listener's group not the one listed",
            &ours,
            &hybrid,
            elsewhere,
        ),
    ] {
        assert!(!holds(classical, default, entry), "{what}");
    }
}

/// [`assert_hello`] holds a ClientHello to its description list by list,
/// in order, and its extensions as a set: the check the seeder cells rest
/// on, run without the oracle.
#[test]
fn a_client_hello_is_held_to_its_description() {
    let hello = json!({
        "cipher_suites": ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"],
        "supported_curves": ["X25519", "CurveP256"],
        "signature_schemes": ["ECDSAWithP384AndSHA384", "ECDSAWithP256AndSHA256"],
        "supported_versions": ["TLS 1.3", "TLS 1.2"],
        "extensions": [43, 10, 51, 13],
    });
    let want = described(&hello);
    assert_eq!(want["extensions"], json!([10, 13, 43, 51]));
    let with = |field: &str, value: Value| {
        let mut changed = hello.clone();
        changed[field] = value;
        changed
    };
    let matches = |hello: &Value| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_hello("a cell", hello, &want);
        }))
        .is_ok()
    };
    assert!(matches(&hello));
    assert!(matches(&with("extensions", json!([51, 13, 10, 43]))));
    for (what, changed) in [
        (
            "suites in another order",
            with(
                "cipher_suites",
                json!(["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"]),
            ),
        ),
        (
            "groups in another order",
            with("supported_curves", json!(["CurveP256", "X25519"])),
        ),
        (
            "schemes in another order",
            with(
                "signature_schemes",
                json!(["ECDSAWithP256AndSHA256", "ECDSAWithP384AndSHA384"]),
            ),
        ),
        (
            "versions in another order",
            with("supported_versions", json!(["TLS 1.2", "TLS 1.3"])),
        ),
        (
            "an extension more",
            with("extensions", json!([43, 10, 51, 13, 0])),
        ),
        ("a group fewer", with("supported_curves", json!(["X25519"]))),
    ] {
        assert!(!matches(&changed), "{what}");
    }
}
