// SPDX-License-Identifier: ISC
//! The node's TLS runs with no process-wide rustls provider (ADR-0015):
//! every configuration it builds names `dcroxide-tlscrypto`'s, rustls
//! takes `custom-provider`, which leaves it no provider to pick from its
//! crate features, and nothing installs a default.  A configuration built
//! on the process default, `ClientConfig::builder`,
//! `WebPkiClientVerifier::builder` and their kin, panics without one
//! (`rustls-0.23.46/src/crypto/mod.rs:243-257`), and so does a ureq agent
//! whose `TlsConfig` names no provider, at its first TLS connection
//! (`ureq-3.5.1/src/tls/rustls.rs:153-159`): ureq picks its provider
//! lazily, so building an agent shows nothing.
//!
//! So this, a test binary of its own, that no other test may install a
//! default first, drives each of the daemon's TLS paths and then finds
//! the default still unset: both seeder transports from the daemon's own
//! constructors (`bin/dcroxide.rs`), `UreqTransport::new()` and
//! `ProxySeederTransport::new` over the direct dialer, each fetching from
//! a local TLS server whose certificate chains to no `webpki-roots` root,
//! which each must refuse as an unknown issuer, the provider having
//! verified it; and the RPC listener's configuration set, built without
//! and with a client CA file, which brings in `GoClientCertVerifier`,
//! each through one handshake.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use dcroxide_addrmgr::SeederTransport;
use dcroxide_node::rpcrun::{load_or_generate_cert_pair, tls_server_config};
use dcroxide_node::seeding::{ProxySeederTransport, UreqTransport};
use dcroxide_node::socks::NodeDialer;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

/// A certgen P-256 pair as the daemon makes one, under `dir` as `name`:
/// the certificate's and key's PEM.
fn pair(dir: &std::path::Path, name: &str) -> (Vec<u8>, Vec<u8>) {
    load_or_generate_cert_pair(
        &dir.join(format!("{name}.cert")),
        &dir.join(format!("{name}.key")),
        &[],
        dcroxide_certgen::Curve::P256,
    )
    .expect("a cert pair")
}

/// `gencerts`' environment at the current time, with serials counted from
/// one.
struct Now(u8);

impl dcroxide_certgen::gentool::GenEnv for Now {
    fn now_unix(&mut self) -> i64 {
        let since = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock");
        i64::try_from(since.as_secs()).expect("the time")
    }

    fn serial_bytes(&mut self) -> Vec<u8> {
        self.0 = self.0.wrapping_add(1);
        vec![self.0]
    }
}

/// A seeder's certificate and key: a leaf for the loopback address,
/// issued by a local authority of `gencerts`' making, so that the chain
/// ends at a root `webpki-roots` lacks.
fn seeder_identity() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    use dcroxide_certgen::gentool;
    let ca_key = gentool::generate_key("P-256").expect("a key");
    let ca = gentool::generate_authority(&mut Now(0), &ca_key, &[], "seeder CA", 1, true)
        .expect("an authority");
    let ca_key_pem = gentool::pem_private_key(&ca_key.marshal_pkcs8().expect("PKCS#8"));
    let (ca, ca_key) = gentool::load_ca_pair(&ca.pem, &ca_key_pem).expect("the authority");
    let key = gentool::generate_key("P-256").expect("a key");
    let leaf = gentool::create_issued_cert(
        &mut Now(100),
        &key,
        &ca,
        &ca_key,
        &["127.0.0.1".to_owned()],
        "seeder",
        1,
        false,
    )
    .expect("a leaf");
    let key = PrivateKeyDer::Pkcs8(key.marshal_pkcs8().expect("PKCS#8").into());
    (vec![CertificateDer::from(leaf.der)], key)
}

/// The provider every configuration here is built on.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(dcroxide_tlscrypto::default_provider())
}

/// A server certificate verifier that takes any chain and checks the
/// handshake signature with the provider's algorithms: the RPC
/// certificate is its own authority, which webpki will not take as an end
/// entity.
#[derive(Debug)]
struct AnyServerCert;

impl ServerCertVerifier for AnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &dcroxide_tlscrypto::SUPPORTED_SIG_ALGS,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &dcroxide_tlscrypto::SUPPORTED_SIG_ALGS,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        dcroxide_tlscrypto::SUPPORTED_SIG_ALGS.supported_schemes()
    }
}

/// One handshake in memory between `server` and a client on the provider
/// presenting `client`, a certificate and its key, when given, and one
/// application record each way: the client's certificates the server
/// took.
fn handshake(
    server: &Arc<rustls::ServerConfig>,
    client: Option<(CertificateDer<'static>, PrivateKeyDer<'static>)>,
) -> Vec<CertificateDer<'static>> {
    let builder = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("the provider's versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyServerCert));
    let config = match client {
        Some((cert, key)) => builder
            .with_client_auth_cert(vec![cert], key)
            .expect("the client's certificate"),
        None => builder.with_no_client_auth(),
    };
    let name = ServerName::try_from("localhost").expect("a name");
    let mut client = rustls::ClientConnection::new(Arc::new(config), name).expect("a client");
    let mut server = rustls::ServerConnection::new(Arc::clone(server)).expect("a server");
    /// Every record `from` has to send, read and processed by `to`.
    fn deliver<A, B>(from: &mut rustls::ConnectionCommon<A>, to: &mut rustls::ConnectionCommon<B>) {
        let mut wire = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut wire).expect("write the records");
        }
        let mut rest = wire.as_slice();
        while !rest.is_empty() {
            to.read_tls(&mut rest).expect("read the records");
            to.process_new_packets().expect("take the records");
        }
    }
    client
        .writer()
        .write_all(b"ping")
        .expect("the client writes");
    for _ in 0..8 {
        deliver(&mut client, &mut server);
        deliver(&mut server, &mut client);
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
    }
    deliver(&mut client, &mut server);
    assert!(!server.is_handshaking(), "the handshake completed");
    let mut ping = [0u8; 4];
    server
        .reader()
        .read_exact(&mut ping)
        .expect("the server reads");
    assert_eq!(&ping, b"ping");
    server
        .peer_certificates()
        .map(<[_]>::to_vec)
        .unwrap_or_default()
}

#[test]
fn the_daemons_tls_runs_with_no_process_provider() {
    assert!(
        CryptoProvider::get_default().is_none(),
        "nothing has installed a default yet"
    );
    let dir = tempfile::tempdir().expect("a temp dir");

    // A seeder whose chain no `webpki-roots` root issued, serving each
    // connection's handshake until the client refuses the chain.
    let (certs, key) = seeder_identity();
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .expect("the provider's versions")
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("the seeder's configuration"),
    );
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("an address").port();
    let seeder = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("a timeout");
            let mut conn = rustls::ServerConnection::new(Arc::clone(&config)).expect("a server");
            let refused = conn.complete_io(&mut stream);
            assert!(refused.is_err(), "the client took the chain: {refused:?}");
        }
    });

    let url = format!("https://127.0.0.1:{port}/");
    let refused = |what: &str, got: Result<(u32, Vec<u8>), String>| match got {
        Err(e) => assert!(
            e.contains("invalid peer certificate: UnknownIssuer"),
            "{what}: refused otherwise: {e}"
        ),
        Ok((status, _)) => panic!("{what}: answered {status} over a chain no root issued"),
    };
    refused("ureq", UreqTransport::new().get(&url));
    refused(
        "the proxy's client",
        ProxySeederTransport::new(NodeDialer::direct()).get(&url),
    );
    seeder.join().expect("the seeder saw both refusals");

    // The RPC listener's set, without and with a client CA file; the
    // client's certificate is the file's one.
    let (rpc_cert, rpc_key) = pair(dir.path(), "rpc");
    let (client_cert_pem, client_key_pem) = pair(dir.path(), "client");
    let client_cert = CertificateDer::from_pem_slice(&client_cert_pem).expect("the certificate");
    let client_key = PrivateKeyDer::from_pem_slice(&client_key_pem).expect("the key");
    let plain = tls_server_config(&rpc_cert, &rpc_key, None).expect("the RPC configurations");
    let server = plain.configs().next().expect("a configuration");
    assert!(handshake(server, None).is_empty(), "no client certificate");
    let clientcert = tls_server_config(&rpc_cert, &rpc_key, Some(&client_cert_pem))
        .expect("the clientcert configurations");
    let server = clientcert.configs().next().expect("a configuration");
    assert_eq!(
        handshake(server, Some((client_cert.clone(), client_key))),
        [client_cert],
        "the client's certificate, through GoClientCertVerifier"
    );

    assert!(
        CryptoProvider::get_default().is_none(),
        "the daemon's TLS installed a process default"
    );
}
