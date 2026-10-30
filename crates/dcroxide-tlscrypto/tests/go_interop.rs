// SPDX-License-Identifier: ISC
//! Go's `crypto/tls` against this crate's provider over loopback, through
//! the oracle's TLS commands: the provider's half of the Go interop matrix
//! ADR-0015 holds the switch to (T10), the node's being `dcroxide-node`'s
//! `tests/tls_interop.rs`.  Every rustls configuration here is built from
//! [`default_provider`] alone, cut to the suites, groups or signature
//! schemes a cell names, and every certificate is made by Go's
//! `x509.CreateCertificate` through `tls_pki`, its RSA keys taken from the
//! test-key fixture, never generated.  The oracle runs under dcrd's
//! `GODEBUG` (`dcroxide_testutil::tls_interop::DCRD_TLS_GODEBUG`).
//!
//! Go's client against the provider's server:
//!
//! - TLS 1.3, each of the three suites, forced on the server, since a Go
//!   client always offers all three in its own order
//!   (`crypto/tls/handshake_client.go:128-139`), by each of the four
//!   groups, the client's `curve_preferences` cut to it, by each server
//!   key, P-256, P-384, P-521 and Ed25519: 48 cells.  TLS 1.2, each
//!   ECDHE-ECDSA suite, both sides cut to it, by the same groups and keys:
//!   48.  A HelloRetryRequest: the client's X25519 share for a server
//!   that takes P-256 alone.
//! - Client certificates, the server requiring them through
//!   `WebPkiClientVerifier::builder_with_provider`: client keys P-256,
//!   P-384, Ed25519 and RSA-2048, each a self-signed leaf the server
//!   trusts and a leaf under each kind of CA, P-256, P-384 signing with
//!   ECDSA-SHA384, RSA-4096 signing with SHA256-RSA and with
//!   SHA256-RSAPSS, and Ed25519, in each version: 48 cells.  Three are
//!   refused today, as ring refuses them, and Go's client-certificate set
//!   (ADR-0015, T4) is what makes them complete: a P-521 client key, an
//!   issuer signing with ECDSA-SHA512 and an RSA-1024 client key, in each
//!   version.
//! - Refused by rustls itself, whatever the provider: ECDHE-RSA suites
//!   alone against an ECDSA key and a CBC suite alone, in TLS 1.2, and no
//!   group in common, in each version.
//!
//! The provider's client against Go's server:
//!
//! - TLS 1.3, each suite, forced on the client, by each group by each
//!   server key, P-256, P-384, Ed25519, RSA-2048, RSA-3072 and RSA-4096:
//!   72 cells.  A P-521 server key is refused in each version, since the
//!   provider verifies no P-521 signature until T4, where Go would serve
//!   it.  TLS 1.2, each ECDHE-ECDSA suite by each group by the three EC
//!   and Edwards keys, and each ECDHE-RSA suite by each group by the three
//!   RSA keys: 72.
//! - Each RSA signature scheme alone, the client's verifier offering only
//!   it: TLS 1.2's three PKCS#1 v1.5 and three PSS schemes and TLS 1.3's
//!   three PSS schemes, the scheme Go's server signed with checked.
//! - Chains: an RSA-4096 root over an RSA-2048 intermediate over a P-256
//!   leaf, the shape the seeders serve, signed with SHA256-, SHA384- and
//!   SHA512-RSA and with SHA256-RSAPSS; a P-384 root over a P-256 leaf;
//!   an Ed25519 root and leaf; and refused today, a P-521 root signing
//!   with ECDSA-SHA512, an RSA-1024 intermediate and an RSA-8193 one, the
//!   last two outside ring's RSA bounds, which the provider keeps; each in
//!   both versions.
//! - Client certificates from the provider's client, its keys loaded by
//!   `sign::KEY_PROVIDER`, P-256, P-384, P-521 and Ed25519, to a Go server
//!   requiring and verifying them, in both versions.
//!
//! A completed cell asserts that both ends report one version, suite,
//! group and HelloRetryRequest, the cell's version and, where it names
//! them, its suite, group and HelloRetryRequest, and an HTTP request
//! answered over it; a refused one asserts the refusing end's rustls error,
//! and that Go's end refused, with the reference Go's words for it when the
//! oracle runs that Go (`TlsOracle::assert_refused`).  Each refused cell's
//! rustls error was checked once against ring's: a run of these tests with
//! ring's provider put in for this one, while ring is in the tree, gave the
//! same error in every refused cell it can run (all but those whose keys
//! are P-521, which ring cannot load).  The oracle, the certificates, the
//! client-certificate cells and Go's report of a connection are
//! `dcroxide_testutil::tls_interop`'s, shared with the node's matrix.  Each
//! matrix is one test with one oracle, which prints the handshakes it
//! made, one a cell, its wall time and the Go that answered.  Without an
//! oracle, or with one whose Go is older than 1.26, the tests skip, unless
//! `DCROXIDE_REQUIRE_ORACLE` is set, as in CI, where they also require the
//! reference Go.  Nothing leaves loopback, every accept, handshake, read
//! and write on either side has a deadline, and the rustls end of a failed
//! connection closes it only once its peer has, so that its alert is not
//! lost to a reset.

// Test-harness arithmetic: a deadline and counts of cells.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use dcroxide_testutil::hex;
use dcroxide_testutil::tls_interop::{
    ClientCertRefusal, ClientCerts, Issued, Negotiated, TlsOracle, spec,
};
use dcroxide_tlscrypto::{SUPPORTED_SIG_ALGS, cipher_suite, default_provider, kx_group};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, SupportedKxGroup, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    AlertDescription, CertificateError, ClientConfig, ClientConnection, ConnectionCommon,
    DigitallySignedStruct, Error, HandshakeKind, PeerIncompatible, ProtocolVersion, RootCertStore,
    ServerConfig, ServerConnection, SignatureScheme, SupportedCipherSuite,
    SupportedProtocolVersion,
};
use serde_json::{Value, json};

/// How long any connection may take on the rustls side: its accept, its
/// handshake, its request and its response, as long as Go's side
/// (`dcroxide_testutil::tls_interop::TIMEOUT_MS`).
const TIMEOUT: Duration = Duration::from_secs(10);

/// How long the rustls end of a failed connection waits for its peer to
/// close ([`linger`]).
const LINGER: Duration = Duration::from_secs(1);

/// The body each server answers its one request with.
const BODY: &str = "{\"result\":0}";

/// A protocol version, with Go's name for it (`tls.VersionName`).
type Version = (&'static SupportedProtocolVersion, &'static str);

/// TLS 1.3.
const TLS13: Version = (&rustls::version::TLS13, "TLS 1.3");

/// TLS 1.2.
const TLS12: Version = (&rustls::version::TLS12, "TLS 1.2");

/// A cipher suite, with Go's name for it (`tls.CipherSuiteName`).
type Suite = (SupportedCipherSuite, &'static str);

/// TLS 1.3's suites.
fn tls13_suites() -> [Suite; 3] {
    [
        (
            cipher_suite::TLS13_AES_128_GCM_SHA256,
            "TLS_AES_128_GCM_SHA256",
        ),
        (
            cipher_suite::TLS13_AES_256_GCM_SHA384,
            "TLS_AES_256_GCM_SHA384",
        ),
        (
            cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            "TLS_CHACHA20_POLY1305_SHA256",
        ),
    ]
}

/// TLS 1.2's ECDHE-ECDSA suites.
fn ecdsa_suites() -> [Suite; 3] {
    [
        (
            cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        ),
        (
            cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        ),
        (
            cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        ),
    ]
}

/// TLS 1.2's ECDHE-RSA suites.
fn rsa_suites() -> [Suite; 3] {
    [
        (
            cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        ),
        (
            cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        ),
        (
            cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        ),
    ]
}

/// A key exchange group, with Go's name for it (`tls.CurveID`'s String).
type Group = (&'static dyn SupportedKxGroup, &'static str);

/// The four groups.
fn groups() -> [Group; 4] {
    [
        (kx_group::X25519, "X25519"),
        (kx_group::SECP256R1, "CurveP256"),
        (kx_group::SECP384R1, "CurveP384"),
        (kx_group::SECP521R1, "CurveP521"),
    ]
}

/// Go's name for whatever of the version, suite and group lists has `want`,
/// or the item itself, debug-printed, for one none has.
fn go_name<T: PartialEq + std::fmt::Debug>(want: T, known: &[(T, &'static str)]) -> String {
    known
        .iter()
        .find(|(item, _)| *item == want)
        .map_or_else(|| format!("{want:?}"), |(_, name)| (*name).to_owned())
}

/// What a cell expects: `version`, Go's suite and group names, and whether
/// there was a HelloRetryRequest.
fn expected(version: Version, suite: &str, group: &str, hello_retry_request: bool) -> Negotiated {
    Negotiated::new(version.1, suite, group, hello_retry_request)
}

/// What a rustls connection negotiated, by Go's names, once its handshake
/// is done.
fn negotiated<D>(conn: &ConnectionCommon<D>) -> Option<Negotiated> {
    if conn.is_handshaking() {
        return None;
    }
    let suites: Vec<_> = [tls13_suites(), ecdsa_suites(), rsa_suites()]
        .concat()
        .into_iter()
        .map(|(suite, name)| (suite.suite(), name))
        .collect();
    let group_names: Vec<_> = groups()
        .into_iter()
        .map(|(group, name)| (group.name(), name))
        .collect();
    Some(Negotiated {
        version: go_name(
            conn.protocol_version()?,
            &[
                (ProtocolVersion::TLSv1_3, TLS13.1),
                (ProtocolVersion::TLSv1_2, TLS12.1),
            ],
        ),
        suite: go_name(conn.negotiated_cipher_suite()?.suite(), &suites),
        group: go_name(conn.negotiated_key_exchange_group()?.name(), &group_names),
        hello_retry_request: conn.handshake_kind()
            == Some(HandshakeKind::FullWithHelloRetryRequest),
    })
}

/// Why one end gave a connection up: rustls's error, or the I/O's.
#[derive(Debug, PartialEq)]
enum Failure {
    /// rustls refused, or was refused by the peer's alert.
    Tls(Error),
    /// The connection failed otherwise.
    Io(String),
}

/// The failure an I/O error from rustls's stream carries.
fn failure(e: io::Error) -> Failure {
    match e.get_ref().and_then(|inner| inner.downcast_ref::<Error>()) {
        Some(tls) => Failure::Tls(tls.clone()),
        None => Failure::Io(e.to_string()),
    }
}

/// What the rustls end saw of a connection.
#[derive(Debug)]
struct Seen {
    /// The handshake and the request's outcome.
    outcome: Result<(), Failure>,
    /// What the handshake negotiated, once done.
    negotiated: Option<Negotiated>,
    /// The peer's certificates.
    peer_certificates: Vec<Vec<u8>>,
}

impl Seen {
    /// What `conn` saw, with `outcome`.
    fn of<D>(conn: &ConnectionCommon<D>, outcome: Result<(), Failure>) -> Seen {
        Seen {
            outcome,
            negotiated: negotiated(conn),
            peer_certificates: conn
                .peer_certificates()
                .unwrap_or_default()
                .iter()
                .map(|cert| cert.as_ref().to_vec())
                .collect(),
        }
    }
}

/// Drive `conn`'s handshake over `tcp` to its end.
fn handshake<D>(conn: &mut ConnectionCommon<D>, tcp: &mut TcpStream) -> Result<(), Failure> {
    while conn.is_handshaking() {
        conn.complete_io(tcp).map_err(failure)?;
    }
    Ok(())
}

/// Set `tcp`'s read and write timeouts to [`TIMEOUT`].
fn bounded(tcp: &TcpStream) -> io::Result<()> {
    tcp.set_read_timeout(Some(TIMEOUT))?;
    tcp.set_write_timeout(Some(TIMEOUT))
}

/// Close the write side of a failed connection, after the alert rustls
/// wrote as it failed, and read and drop what the peer still sends until
/// it closes, for about [`LINGER`].  A socket closed with data it has not
/// read sends a reset, and a stack that throws away what it has received
/// when a reset arrives, as Go's `net/http` says of BSD systems and
/// suspects of Windows (`net/http/server.go:1759-1764`), would show the
/// peer the reset in place of the alert, which the refused cells compare.
/// Go's client writes its request as soon as its TLS 1.3 handshake is
/// done, before a server refuses its certificate.
fn linger(tcp: &mut TcpStream) {
    let _ = tcp.shutdown(Shutdown::Write);
    let _ = tcp.set_read_timeout(Some(LINGER));
    let deadline = Instant::now() + LINGER;
    let mut sink = [0; 4096];
    while Instant::now() < deadline && matches!(tcp.read(&mut sink), Ok(n) if n > 0) {}
}

/// Read one HTTP request's head off `stream`, through its blank line.
fn read_head(stream: &mut impl Read) -> Result<String, Failure> {
    let mut head = Vec::new();
    let mut byte = [0];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 16 * 1024 {
            return Err(Failure::Io("an HTTP head over 16 KiB".to_owned()));
        }
        match stream.read(&mut byte).map_err(failure)? {
            0 => {
                return Err(Failure::Io(
                    "the peer closed inside the HTTP head".to_owned(),
                ));
            }
            _ => head.push(byte[0]),
        }
    }
    String::from_utf8(head).map_err(|e| Failure::Io(e.to_string()))
}

/// Serve one connection with `config` on a loopback port the system picks,
/// on a thread: the handshake, then one HTTP request read, its body by its
/// `Content-Length`, and answered 200 with [`BODY`], then a
/// `close_notify`.  The thread gives up when no client comes within
/// [`TIMEOUT`], and closes a connection that failed with [`linger`].
fn serve_one(config: Arc<ServerConfig>) -> (String, JoinHandle<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
    let addr = listener.local_addr().expect("its address").to_string();
    listener
        .set_nonblocking(true)
        .expect("a listener that does not block");
    let server = thread::spawn(move || {
        let deadline = Instant::now() + TIMEOUT;
        let mut tcp = loop {
            match listener.accept() {
                Ok((tcp, _)) => break tcp,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(e) => {
                    return Seen {
                        outcome: Err(Failure::Io(format!("accept: {e}"))),
                        negotiated: None,
                        peer_certificates: Vec::new(),
                    };
                }
            }
        };
        let mut conn = ServerConnection::new(config).expect("a server connection");
        let outcome = tcp
            .set_nonblocking(false)
            .and_then(|()| bounded(&tcp))
            .map_err(failure)
            .and_then(|()| handshake(&mut conn, &mut tcp))
            .and_then(|()| answer(&mut conn, &mut tcp));
        if outcome.is_err() {
            linger(&mut tcp);
        }
        Seen::of(&conn, outcome)
    });
    (addr, server)
}

/// Read one HTTP request on the server's side and answer it.
fn answer(conn: &mut ServerConnection, tcp: &mut TcpStream) -> Result<(), Failure> {
    let mut stream = rustls::Stream::new(conn, tcp);
    let head = read_head(&mut stream)?;
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).map_err(failure)?;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{BODY}",
        BODY.len()
    );
    stream.write_all(response.as_bytes()).map_err(failure)?;
    stream.conn.send_close_notify();
    stream.flush().map_err(failure)
}

/// Dial `addr` with `config`, naming `localhost`, and send one HTTP request,
/// reading the response to the server's `close_notify`; it must be 200
/// with [`BODY`].  A connection that failed is closed with [`linger`].
fn dial(addr: &str, config: Arc<ClientConfig>) -> Seen {
    let name = ServerName::try_from("localhost").expect("a server name");
    let mut conn = ClientConnection::new(config, name).expect("a client connection");
    let addr: SocketAddr = addr.parse().expect("a socket address");
    let mut tcp = match TcpStream::connect_timeout(&addr, TIMEOUT) {
        Ok(tcp) => tcp,
        Err(e) => return Seen::of(&conn, Err(failure(e))),
    };
    let outcome = bounded(&tcp)
        .map_err(failure)
        .and_then(|()| handshake(&mut conn, &mut tcp))
        .and_then(|()| {
            let mut stream = rustls::Stream::new(&mut conn, &mut tcp);
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .map_err(failure)?;
            let mut response = Vec::new();
            stream.read_to_end(&mut response).map_err(failure)?;
            let response = String::from_utf8_lossy(&response);
            if response.starts_with("HTTP/1.1 200 OK\r\n") && response.ends_with(BODY) {
                Ok(())
            } else {
                Err(Failure::Io(format!("the response {response:?}")))
            }
        });
    if outcome.is_err() {
        linger(&mut tcp);
    }
    Seen::of(&conn, outcome)
}

/// A `tls_pki` certificate and key as rustls takes them.
trait AsRustls {
    /// The certificate.
    fn der(&self) -> CertificateDer<'static>;
    /// The key.
    fn private_key(&self) -> PrivateKeyDer<'static>;
}

impl AsRustls for Issued {
    fn der(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.cert.clone())
    }

    fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_pkcs8.clone()))
    }
}

/// Go's client dialing `server` with `dial`'s fields, the address, server
/// name and one GET request added: Go's `tls_dial` detail, and what the
/// server saw.
fn client_to(go: &mut TlsOracle, server: Arc<ServerConfig>, mut dial: Value) -> (Value, Seen) {
    let (addr, served) = serve_one(server);
    dial["addr"] = json!(addr);
    dial["server_name"] = json!("localhost");
    dial["request"] = json!({ "method": "GET", "path": "/" });
    let detail = go.dial(dial);
    (detail, served.join().expect("the server's thread"))
}

/// Go's server listening with `listen`'s fields, its response body added,
/// dialed by `client`: what the client saw, and Go's `tls_listen_result`
/// detail.
fn server_for(go: &mut TlsOracle, mut listen: Value, client: Arc<ClientConfig>) -> (Seen, Value) {
    listen["response_body"] = json!(BODY);
    let (addr, id) = go.listen(listen);
    let seen = dial(&addr, client);
    (seen, go.served(&id))
}

/// The provider offering `suites` and `groups` alone.
fn offering(
    suites: &[SupportedCipherSuite],
    groups: &[&'static dyn SupportedKxGroup],
) -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider {
        cipher_suites: suites.to_vec(),
        kx_groups: groups.to_vec(),
        ..default_provider()
    })
}

/// The provider whole.
fn whole() -> Arc<CryptoProvider> {
    Arc::new(default_provider())
}

/// A root store of `certs`.
fn roots(certs: &[&Issued]) -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for issued in certs {
        roots.add(issued.der()).expect("a root");
    }
    Arc::new(roots)
}

/// A server on `provider` in `version`, serving `identity`, and requiring
/// a client certificate under `client_roots` when there are any.
fn server_config(
    provider: Arc<CryptoProvider>,
    version: Version,
    identity: &Issued,
    client_roots: &[&Issued],
) -> Arc<ServerConfig> {
    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[version.0])
        .expect("the server's version");
    let builder = if client_roots.is_empty() {
        builder.with_no_client_auth()
    } else {
        let verifier = WebPkiClientVerifier::builder_with_provider(roots(client_roots), provider)
            .build()
            .expect("the client verifier");
        builder.with_client_cert_verifier(verifier)
    };
    Arc::new(
        builder
            .with_single_cert(vec![identity.der()], identity.private_key())
            .expect("the server's key"),
    )
}

/// A server certificate verifier over webpki's on the provider that
/// records the signature scheme of each handshake signature it checks.
#[derive(Debug)]
struct Recording {
    inner: Arc<WebPkiServerVerifier>,
    schemes: Mutex<Vec<SignatureScheme>>,
}

impl Recording {
    /// The verifier over `roots`, with the provider's algorithms `algs`.
    fn over(roots: Arc<RootCertStore>, algs: WebPkiSupportedAlgorithms) -> Arc<Recording> {
        let provider = CryptoProvider {
            signature_verification_algorithms: algs,
            ..default_provider()
        };
        Arc::new(Recording {
            inner: WebPkiServerVerifier::builder_with_provider(roots, Arc::new(provider))
                .build()
                .expect("the server verifier"),
            schemes: Mutex::new(Vec::new()),
        })
    }

    /// The schemes of the signatures checked so far.
    fn schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.lock().expect("the schemes").clone()
    }

    /// Record `dss`'s scheme.
    fn record(&self, dss: &DigitallySignedStruct) {
        self.schemes.lock().expect("the schemes").push(dss.scheme);
    }
}

impl ServerCertVerifier for Recording {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.record(dss);
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.record(dss);
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// A client on `provider` in `version`, verifying the server with
/// `verifier`, presenting `identity` when given.
fn client_config(
    provider: Arc<CryptoProvider>,
    version: Version,
    verifier: Arc<Recording>,
    identity: Option<&Issued>,
) -> Arc<ClientConfig> {
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version.0])
        .expect("the client's version")
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    Arc::new(match identity {
        Some(identity) => builder
            .with_client_auth_cert(vec![identity.der()], identity.private_key())
            .expect("the client's key"),
        None => builder.with_no_client_auth(),
    })
}

/// The rustls error the provider's server refuses a client certificate
/// with in `version` for `refusal`, which ring's provider gives too.
fn refusal_error(refusal: ClientCertRefusal, version: Version) -> Error {
    match (refusal, version.1) {
        // Go's client sends no certificate it cannot sign with under a
        // scheme the CertificateRequest lists, and in TLS 1.3 a P-521 key
        // signs with ecdsa_secp521r1_sha512 alone, which the provider's
        // list lacks (`ClientCertRefusal::go_error`).
        (ClientCertRefusal::P521Key, "TLS 1.3") => Error::NoCertificatesPresented,
        // In TLS 1.2 an ECDSA scheme names no curve
        // (`crypto/tls/auth.go:194-200`) and Go signs with the first the
        // server lists (`:261-267`), ECDSA with SHA-384, which the
        // provider takes from a P-256 or P-384 key alone.
        (ClientCertRefusal::P521Key, _) => Error::InvalidCertificate(
            CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext {
                signature_algorithm_id: ECDSA_SHA384.to_vec(),
                public_key_algorithm_id: EC_P521_KEY.to_vec(),
            },
        ),
        (ClientCertRefusal::Sha512Issuer, _) => unsupported(ECDSA_SHA512),
        (ClientCertRefusal::Rsa1024Key, _) => {
            Error::InvalidCertificate(CertificateError::BadSignature)
        }
    }
}

/// ecdsa-with-SHA384's identifier, as webpki names it in an error.
const ECDSA_SHA384: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];

/// ecdsa-with-SHA512's identifier, as webpki names it in an error.
const ECDSA_SHA512: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];

/// id-ecPublicKey on secp521r1, as webpki names it in an error.
const EC_P521_KEY: &[u8] = &[
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23,
];

/// The error webpki refuses a certificate signed under the algorithm
/// `signature_algorithm_id` with, which the provider does not verify: the
/// identifier and every algorithm identifier the provider has, in its
/// order, which are ring's.
fn unsupported(signature_algorithm_id: &[u8]) -> Error {
    Error::InvalidCertificate(CertificateError::UnsupportedSignatureAlgorithmContext {
        signature_algorithm_id: signature_algorithm_id.to_vec(),
        supported_algorithms: SUPPORTED_SIG_ALGS
            .all
            .iter()
            .map(|alg| alg.signature_alg_id())
            .collect(),
    })
}

/// Go's client against the provider's server: every suite of each version
/// by every group by every key the provider serves, a HelloRetryRequest,
/// client certificates, and the refusals rustls makes itself.
#[test]
fn go_clients_handshake_with_the_provider_server() {
    let Some(mut go) = TlsOracle::start() else {
        return;
    };
    let keys = ["P-256", "P-384", "P-521", "Ed25519"];
    let specs: Vec<Value> = keys
        .iter()
        .map(|key| spec(key, key, None, "server"))
        .collect();
    let servers = go.pki(&specs);

    // Every suite by every group by every key, in each version.
    for key in keys {
        let identity = &servers[key];
        let go_roots = json!([hex(&identity.cert)]);
        for (group, group_name) in groups() {
            for (suite, suite_name) in tls13_suites() {
                let what = format!("TLS 1.3, {suite_name}, {group_name}, {key}");
                let server = server_config(offering(&[suite], &[group]), TLS13, identity, &[]);
                let (detail, seen) = client_to(
                    &mut go,
                    server,
                    json!({ "roots": go_roots, "curve_preferences": [group_name] }),
                );
                let want = expected(TLS13, suite_name, group_name, false);
                assert_completed(&what, &detail, &seen, &want);
            }
            for (suite, suite_name) in ecdsa_suites() {
                let what = format!("TLS 1.2, {suite_name}, {group_name}, {key}");
                let server = server_config(offering(&[suite], &[group]), TLS12, identity, &[]);
                let (detail, seen) = client_to(
                    &mut go,
                    server,
                    json!({
                        "roots": go_roots, "max_version": TLS12.1,
                        "cipher_suites": [suite_name], "curve_preferences": [group_name],
                    }),
                );
                let want = expected(TLS12, suite_name, group_name, false);
                assert_completed(&what, &detail, &seen, &want);
            }
        }
    }

    // The client's share is X25519's, and the server takes P-256 alone.
    let p256 = &servers["P-256"];
    let go_roots = json!([hex(&p256.cert)]);
    let (suite, suite_name) = tls13_suites()[0];
    let server = server_config(offering(&[suite], &[kx_group::SECP256R1]), TLS13, p256, &[]);
    let (detail, seen) = client_to(
        &mut go,
        server,
        json!({ "roots": go_roots, "curve_preferences": ["X25519", "CurveP256"] }),
    );
    let want = expected(TLS13, suite_name, "CurveP256", true);
    assert_completed("a HelloRetryRequest", &detail, &seen, &want);

    // Client certificates, in each version.
    let clients = ClientCerts::make(&mut go);
    let trusted: Vec<&Issued> = clients.trusted.iter().collect();
    let mut accepted = 0;
    for version in [TLS13, TLS12] {
        let server = server_config(whole(), version, p256, &trusted);
        for (name, client, refusal) in &clients.cells {
            let what = format!("{}, {name}", version.1);
            let (detail, seen) = client_to(
                &mut go,
                Arc::clone(&server),
                json!({ "roots": go_roots, "client_cert": client.identity(&[]) }),
            );
            if let Some(refusal) = *refusal {
                let error = refusal_error(refusal, version);
                assert_eq!(seen.outcome, Err(Failure::Tls(error)), "{what}");
                go.assert_refused(&what, &detail, refusal.go_error(version.1));
                continue;
            }
            // Go's client offers X25519 first among the provider's groups,
            // with a share for it, and picks the suite in its own order.
            let suite = detail["cipher_suite"].as_str().unwrap_or_default();
            assert_completed(
                &what,
                &detail,
                &seen,
                &expected(version, suite, "X25519", false),
            );
            assert_eq!(
                seen.peer_certificates,
                std::slice::from_ref(&client.cert),
                "{what}"
            );
            accepted += 1;
        }
    }
    assert_eq!(accepted, 48, "four keys, six chains, two versions");

    // What ring's provider refuses too: rustls's own errors.
    let refusals = [
        (
            "ECDHE-RSA suites against an ECDSA key",
            TLS12,
            offering(&rsa_suites().map(|(suite, _)| suite), &[kx_group::X25519]),
            json!({ "max_version": TLS12.1 }),
            Error::PeerIncompatible(PeerIncompatible::NoCipherSuitesInCommon),
        ),
        (
            "a CBC suite",
            TLS12,
            whole(),
            json!({
                "max_version": TLS12.1,
                "cipher_suites": ["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"],
            }),
            Error::PeerIncompatible(PeerIncompatible::NoCipherSuitesInCommon),
        ),
        (
            "no group in common",
            TLS13,
            offering(&[suite], &[kx_group::X25519]),
            json!({ "curve_preferences": ["CurveP521"] }),
            Error::PeerIncompatible(PeerIncompatible::NoKxGroupsInCommon),
        ),
        (
            "no group in common",
            TLS12,
            offering(&[ecdsa_suites()[0].0], &[kx_group::X25519]),
            json!({ "max_version": TLS12.1, "curve_preferences": ["CurveP521"] }),
            Error::PeerIncompatible(PeerIncompatible::NoKxGroupsInCommon),
        ),
    ];
    for (what, version, provider, mut dial, want) in refusals {
        let what = format!("{}, {what}", version.1);
        dial["roots"] = go_roots.clone();
        let server = server_config(provider, version, p256, &[]);
        let (detail, seen) = client_to(&mut go, server, dial);
        go.assert_refused(&what, &detail, "remote error: tls: handshake failure");
        assert_eq!(seen.outcome, Err(Failure::Tls(want)), "{what}");
    }

    go.report("go_clients_handshake_with_the_provider_server");
    assert_eq!(
        go.handshakes(),
        48 + 48 + 1 + 48 + 6 + 4,
        "the suites by the groups by the keys in each version, the HelloRetryRequest, the \
         client certificates and the refusals"
    );
}

/// A completed cell: Go's client or server and the provider's end both
/// report `want`, and the request went through.
fn assert_completed(what: &str, detail: &Value, seen: &Seen, want: &Negotiated) {
    assert_eq!(detail["ok"], true, "{what}: Go's end {detail}");
    assert_eq!(seen.outcome, Ok(()), "{what}: the provider's end");
    assert_eq!(
        Negotiated::of_go(detail).as_ref(),
        Some(want),
        "{what}: Go's end"
    );
    assert_eq!(
        seen.negotiated.as_ref(),
        Some(want),
        "{what}: the provider's end"
    );
}

/// A completed cell that leaves the suite and group to the two ends: Go's
/// end negotiated `version`, and [`assert_completed`] holds the provider's
/// end to what Go's reports.
fn assert_agreed(what: &str, detail: &Value, seen: &Seen, version: Version) {
    let go = Negotiated::of_go(detail)
        .filter(|go| go.version == version.1)
        .unwrap_or_else(|| panic!("{what}: Go's end in {} {detail}", version.1));
    assert_completed(what, detail, seen, &go);
}

/// The provider's client against Go's server: every suite of each version
/// by every group by every key Go serves the provider verifies, each RSA
/// signature scheme alone, chains, and client certificates.
#[test]
fn the_provider_client_handshakes_with_go_servers() {
    let Some(mut go) = TlsOracle::start() else {
        return;
    };
    let rsa_keys = ["rsa2048", "rsa3072", "rsa4096"];
    let ec_keys = ["P-256", "P-384", "Ed25519"];
    let mut specs: Vec<Value> = ec_keys
        .iter()
        .chain(&rsa_keys)
        .chain(&["P-521"])
        .map(|key| spec(key, key, None, "server"))
        .collect();
    // The chains: a root, an intermediate when there is one, and a leaf,
    // and the error the provider refuses one with, if it does.  An RSA
    // key outside ring's bounds, which the provider keeps, verifies no
    // signature, and P-521 and SHA-512 ECDSA are not verified at all.
    let bad_signature = || Some(Error::InvalidCertificate(CertificateError::BadSignature));
    let mut chains: Vec<(String, [String; 3], Option<Error>)> = Vec::new();
    specs.push(spec("rsa4096 root", "rsa4096", None, "ca"));
    for sig_alg in ["SHA256-RSA", "SHA384-RSA", "SHA512-RSA", "SHA256-RSAPSS"] {
        let inter = format!("rsa2048 intermediate, {sig_alg}");
        let leaf = format!("P-256 leaf under rsa2048, {sig_alg}");
        specs.push(spec(
            &inter,
            "rsa2048",
            Some(("rsa4096 root", sig_alg)),
            "ca",
        ));
        specs.push(spec(&leaf, "P-256", Some((&inter, sig_alg)), "server"));
        chains.push((
            format!("RSA-4096, RSA-2048, P-256, {sig_alg}"),
            ["rsa4096 root".to_owned(), inter, leaf],
            None,
        ));
    }
    for inter_key in ["rsa1024", "rsa8193"] {
        let inter = format!("{inter_key} intermediate");
        let leaf = format!("P-256 leaf under {inter_key}");
        specs.push(spec(
            &inter,
            inter_key,
            Some(("rsa4096 root", "SHA256-RSA")),
            "ca",
        ));
        specs.push(spec(&leaf, "P-256", Some((&inter, "SHA256-RSA")), "server"));
        chains.push((
            format!("RSA-4096, {inter_key}, P-256"),
            ["rsa4096 root".to_owned(), inter, leaf],
            bad_signature(),
        ));
    }
    for (root_key, leaf_key, sig_alg, refused) in [
        ("P-384", "P-256", "ECDSA-SHA384", None),
        ("Ed25519", "Ed25519", "Ed25519", None),
        (
            "P-521",
            "P-256",
            "ECDSA-SHA512",
            Some(unsupported(ECDSA_SHA512)),
        ),
    ] {
        let root = format!("{root_key} root");
        let leaf = format!("{leaf_key} leaf under {root_key}");
        specs.push(spec(&root, root_key, None, "ca"));
        specs.push(spec(&leaf, leaf_key, Some((&root, sig_alg)), "server"));
        chains.push((
            format!("{root_key}, {leaf_key}, {sig_alg}"),
            [root, String::new(), leaf],
            refused,
        ));
    }
    for key in ["P-256", "P-384", "P-521", "Ed25519"] {
        specs.push(spec(&format!("client {key}"), key, None, "client"));
    }
    let pki = go.pki(&specs);
    let listening = |identity: &Issued, chain: &[&Issued]| identity.identity(chain);

    // Every suite by every group by every key Go serves the provider
    // verifies: TLS 1.3's three with each key, TLS 1.2's ECDSA suites
    // with the EC and Edwards keys and its RSA suites with the RSA keys.
    let cells: [(Version, Vec<Suite>, Vec<&str>); 3] = [
        (TLS13, tls13_suites().to_vec(), [ec_keys, rsa_keys].concat()),
        (TLS12, ecdsa_suites().to_vec(), ec_keys.to_vec()),
        (TLS12, rsa_suites().to_vec(), rsa_keys.to_vec()),
    ];
    for (version, suites, keys) in cells {
        for key in keys {
            let identity = &pki[key];
            for (group, group_name) in groups() {
                for &(suite, suite_name) in &suites {
                    let what = format!("{}, {suite_name}, {group_name}, {key}", version.1);
                    let verifier = Recording::over(roots(&[identity]), SUPPORTED_SIG_ALGS);
                    let client =
                        client_config(offering(&[suite], &[group]), version, verifier, None);
                    let (seen, detail) = server_for(&mut go, listening(identity, &[]), client);
                    let want = expected(version, suite_name, group_name, false);
                    assert_completed(&what, &detail, &seen, &want);
                    assert_eq!(
                        seen.peer_certificates,
                        std::slice::from_ref(&identity.cert),
                        "{what}"
                    );
                }
            }
        }
    }

    // A P-521 server key, whose signature the provider cannot check.
    for version in [TLS13, TLS12] {
        let what = format!("{}, a P-521 server key", version.1);
        let identity = &pki["P-521"];
        let verifier = Recording::over(roots(&[identity]), SUPPORTED_SIG_ALGS);
        let client = client_config(whole(), version, verifier, None);
        let (seen, detail) = server_for(&mut go, listening(identity, &[]), client);
        // In TLS 1.3 Go's server finds no scheme of the client's for its
        // key and says so; in TLS 1.2 the provider refuses the
        // certificate's own ECDSA-SHA512 signature first.
        let (error, go_error) = match version.1 {
            "TLS 1.3" => (
                Error::AlertReceived(AlertDescription::HandshakeFailure),
                "tls: peer doesn't support any of the certificate's signature algorithms",
            ),
            _ => (
                unsupported(ECDSA_SHA512),
                "remote error: tls: error decrypting message",
            ),
        };
        assert_eq!(seen.outcome, Err(Failure::Tls(error)), "{what}");
        go.assert_refused(&what, &detail, go_error);
    }

    // Each RSA signature scheme alone.
    let rsa2048 = &pki["rsa2048"];
    let schemes = [
        (TLS12, SignatureScheme::RSA_PKCS1_SHA256),
        (TLS12, SignatureScheme::RSA_PKCS1_SHA384),
        (TLS12, SignatureScheme::RSA_PKCS1_SHA512),
        (TLS12, SignatureScheme::RSA_PSS_SHA256),
        (TLS12, SignatureScheme::RSA_PSS_SHA384),
        (TLS12, SignatureScheme::RSA_PSS_SHA512),
        (TLS13, SignatureScheme::RSA_PSS_SHA256),
        (TLS13, SignatureScheme::RSA_PSS_SHA384),
        (TLS13, SignatureScheme::RSA_PSS_SHA512),
    ];
    for (version, scheme) in schemes {
        let what = format!("{}, {scheme:?} alone", version.1);
        let entry = SUPPORTED_SIG_ALGS
            .mapping
            .iter()
            .find(|(mapped, _)| *mapped == scheme)
            .expect("a scheme the provider verifies");
        let algs = WebPkiSupportedAlgorithms {
            all: SUPPORTED_SIG_ALGS.all,
            mapping: std::slice::from_ref(entry),
        };
        let verifier = Recording::over(roots(&[rsa2048]), algs);
        let client = client_config(whole(), version, Arc::clone(&verifier), None);
        let (seen, detail) = server_for(&mut go, listening(rsa2048, &[]), client);
        assert_agreed(&what, &detail, &seen, version);
        assert_eq!(
            verifier.schemes(),
            [scheme],
            "{what}: the scheme Go signed with"
        );
    }

    // Chains, the root trusted and the rest sent.
    for (what, [root, inter, leaf], refused) in &chains {
        for version in [TLS13, TLS12] {
            let what = format!("{}, {what}", version.1);
            let leaf = &pki[leaf];
            let sent: Vec<&Issued> = pki.get(inter).into_iter().collect();
            let verifier = Recording::over(roots(&[&pki[root]]), SUPPORTED_SIG_ALGS);
            let client = client_config(whole(), version, verifier, None);
            let (seen, detail) = server_for(&mut go, listening(leaf, &sent), client);
            match refused {
                None => {
                    assert_agreed(&what, &detail, &seen, version);
                    let mut chain = vec![leaf.cert.clone()];
                    chain.extend(sent.iter().map(|issued| issued.cert.clone()));
                    assert_eq!(seen.peer_certificates, chain, "{what}");
                }
                Some(error) => {
                    assert_eq!(seen.outcome, Err(Failure::Tls(error.clone())), "{what}");
                    go.assert_refused(
                        &what,
                        &detail,
                        "remote error: tls: error decrypting message",
                    );
                }
            }
        }
    }

    // The provider's client presenting each key it loads to a Go server
    // that requires and verifies it.
    let server = &pki["P-256"];
    for key in ["P-256", "P-384", "P-521", "Ed25519"] {
        for version in [TLS13, TLS12] {
            let what = format!("{}, a {key} client certificate", version.1);
            let client_cert = &pki[&format!("client {key}")];
            let verifier = Recording::over(roots(&[server]), SUPPORTED_SIG_ALGS);
            let client = client_config(whole(), version, verifier, Some(client_cert));
            let mut listen = listening(server, &[]);
            listen["client_auth"] = json!("RequireAndVerifyClientCert");
            listen["client_cas"] = json!([hex(&client_cert.cert)]);
            let (seen, detail) = server_for(&mut go, listen, client);
            assert_agreed(&what, &detail, &seen, version);
            assert_eq!(
                detail["peer_certificates"],
                json!([hex(&client_cert.cert)]),
                "{what}"
            );
            assert_eq!(
                detail["verified_chains"],
                json!([[hex(&client_cert.cert)]]),
                "{what}"
            );
        }
    }

    go.report("the_provider_client_handshakes_with_go_servers");
    assert_eq!(
        go.handshakes(),
        72 + 2 + 72 + 9 + 18 + 8,
        "the suites by the groups by the keys in each version, the P-521 key, the RSA schemes, \
         the chains and the client certificates"
    );
}

/// [`assert_completed`] holds each end to the cell's version, suite, group
/// and HelloRetryRequest, not only to having completed, and
/// [`assert_agreed`] holds the two ends to one another in the cell's
/// version: the checks every completed cell of both matrices here rests
/// on, run without the oracle.
#[test]
fn a_completed_cell_is_held_to_what_it_negotiated() {
    let want = expected(TLS13, "TLS_AES_128_GCM_SHA256", "X25519", false);
    let go = |negotiated: &Negotiated, ok: bool| {
        json!({
            "ok": ok, "version": negotiated.version, "cipher_suite": negotiated.suite,
            "curve_id": negotiated.group, "hello_retry_request": negotiated.hello_retry_request,
        })
    };
    let rustls = |outcome: Result<(), Failure>, negotiated: &Negotiated| Seen {
        outcome,
        negotiated: Some(negotiated.clone()),
        peer_certificates: Vec::new(),
    };
    let completes = |detail: Value, seen: Seen| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_completed("a cell", &detail, &seen, &want);
        }))
        .is_ok()
    };
    let other_group = Negotiated {
        group: "CurveP256".to_owned(),
        ..want.clone()
    };
    let retried = Negotiated {
        hello_retry_request: true,
        ..want.clone()
    };
    let reset = || Err(Failure::Io("reset".to_owned()));
    assert!(completes(go(&want, true), rustls(Ok(()), &want)));
    for (what, detail, seen) in [
        (
            "Go's end on another group",
            go(&other_group, true),
            rustls(Ok(()), &want),
        ),
        (
            "the provider's end retried",
            go(&want, true),
            rustls(Ok(()), &retried),
        ),
        ("Go's end failed", go(&want, false), rustls(Ok(()), &want)),
        (
            "the provider's end failed",
            go(&want, true),
            rustls(reset(), &want),
        ),
    ] {
        assert!(!completes(detail, seen), "{what}");
    }
    let agrees = |detail: Value, seen: Seen, version: Version| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_agreed("a cell", &detail, &seen, version);
        }))
        .is_ok()
    };
    assert!(agrees(go(&want, true), rustls(Ok(()), &want), TLS13));
    assert!(
        !agrees(go(&want, true), rustls(Ok(()), &want), TLS12),
        "both ends in another version"
    );
    assert!(
        !agrees(go(&other_group, true), rustls(Ok(()), &want), TLS13),
        "the two ends on two groups"
    );
}
