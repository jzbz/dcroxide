// SPDX-License-Identifier: ISC
//! A refused TLS handshake on the RPC listener is logged as dcrd logs it,
//! over a running node.
//!
//! dcrd serves RPC through net/http, whose connection loop logs every
//! failed handshake as `http: TLS handshake error from <addr>: <err>`
//! (`net/http/server.go:2005`) to the server's `ErrorLog`, which dcrd
//! forwards to the RPCS logger at error level (`logForwarder`,
//! `internal/rpcserver/rpcserver.go:5885-5892`).  The port logged nothing
//! for any of them.  The `<err>` is Go's own text for each failure here:
//! a client that closes without a word, one that speaks plain HTTP (which
//! net/http also answers with a 400), one that rejects the certificate,
//! one with no key exchange in common, and two offering only TLS 1.1: a
//! TLS 1.2 ClientHello rewritten to offer TLS 1.1, and one as a real TLS
//! 1.1 client sends it, without signature_algorithms.

#![cfg(target_os = "linux")]
// Test-harness arithmetic over a fixed deadline.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Kills the daemon however the test ends.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Wait until the collected stdout contains `needle`, returning it.
fn wait_for(collected: &Mutex<String>, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let out = collected.lock().expect("sink").clone();
        if out.contains(needle) {
            return out;
        }
        assert!(Instant::now() < deadline, "no {needle:?} in: {out}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The handshake error line dcrd logs for a client at `client`.
fn handshake_error(client: &str, reason: &str) -> String {
    format!("[ERR] RPCS: http: TLS handshake error from {client}: {reason}\n")
}

/// A server certificate verifier that accepts the certificate, or
/// refuses it as signed by an unknown authority, which a rustls client
/// answers with an `unknown_ca` alert.
#[derive(Debug)]
struct Verifier {
    accept: bool,
}

impl rustls::client::danger::ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if self.accept {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
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
        dcroxide_tlscrypto::SUPPORTED_SIG_ALGS.supported_schemes()
    }
}

/// A key exchange the listener does not implement (x448), offered alone;
/// it is never completed.
#[derive(Debug)]
struct OnlyX448;

/// An [`OnlyX448`] share: 56 bytes the server never reads.
struct OnlyX448Exchange([u8; 56]);

impl rustls::crypto::SupportedKxGroup for OnlyX448 {
    fn start(&self) -> Result<Box<dyn rustls::crypto::ActiveKeyExchange>, rustls::Error> {
        Ok(Box::new(OnlyX448Exchange([9; 56])))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X448
    }
}

impl rustls::crypto::ActiveKeyExchange for OnlyX448Exchange {
    fn complete(
        self: Box<Self>,
        _peer: &[u8],
    ) -> Result<rustls::crypto::SharedSecret, rustls::Error> {
        Err(rustls::Error::General("x448 is never negotiated".into()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.0
    }

    fn group(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X448
    }
}

/// A rustls client over `provider` and `versions`, verifying with
/// `verifier`.
fn client(
    provider: rustls::crypto::CryptoProvider,
    versions: &[&'static rustls::SupportedProtocolVersion],
    verifier: Verifier,
) -> rustls::ClientConnection {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    rustls::ClientConnection::new(
        Arc::new(config),
        rustls::pki_types::ServerName::try_from("localhost").expect("name"),
    )
    .expect("client")
}

/// Run `conn`'s handshake against the listener until it ends, returning
/// the client's address as the server sees it.
fn attempt(addr: &str, mut conn: rustls::ClientConnection) -> String {
    let mut tcp = TcpStream::connect(addr).expect("connect to the RPC server");
    tcp.set_read_timeout(Some(Duration::from_secs(30)))
        .expect("timeout");
    let local = tcp.local_addr().expect("local addr").to_string();
    let _ = conn.complete_io(&mut tcp);
    local
}

#[test]
fn refused_tls_handshakes_are_logged_as_dcrd_logs_them() {
    let appdata = tempfile::tempdir().expect("appdata");
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcroxide"))
        .args([
            "--simnet",
            "--noseeders",
            "--nolisten",
            "--rpclisten=127.0.0.1:0",
            "--rpcuser=user",
            "--rpcpass=pass",
        ])
        .arg(format!("--appdata={}", appdata.path().display()))
        .env_remove("DCROXIDE_APPDATA")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dcroxide");
    let mut out = child.stdout.take().expect("stdout pipe");
    let _daemon = Daemon(child);
    let collected = Arc::new(Mutex::new(String::new()));
    let sink = Arc::clone(&collected);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = out.read(&mut buf) {
            if n == 0 {
                break;
            }
            sink.lock()
                .expect("sink")
                .push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    });
    let listening = wait_for(&collected, "RPC server listening on ");
    let addr = listening
        .split("RPC server listening on ")
        .nth(1)
        .and_then(|rest| rest.lines().next())
        .expect("the listener address")
        .trim()
        .to_string();

    // A client that connects and closes without a byte: Go's bare `EOF`,
    // the line a port scanner or a TCP health check leaves.
    let silent = TcpStream::connect(&addr).expect("connect");
    let client_addr = silent.local_addr().expect("local addr").to_string();
    drop(silent);
    wait_for(&collected, &handshake_error(&client_addr, "EOF"));

    // Plain HTTP: net/http answers on the bare connection, then logs.
    let mut http = TcpStream::connect(&addr).expect("connect");
    http.set_read_timeout(Some(Duration::from_secs(30)))
        .expect("timeout");
    let client_addr = http.local_addr().expect("local addr").to_string();
    http.write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}")
        .expect("send");
    let mut answer = String::new();
    let _ = http.read_to_string(&mut answer);
    assert_eq!(
        answer,
        "HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n"
    );
    wait_for(
        &collected,
        &handshake_error(
            &client_addr,
            "client sent an HTTP request to an HTTPS server",
        ),
    );

    // A client that refuses the certificate sends an alert, which Go
    // reports as a remote error.
    let refusing = client(
        dcroxide_tlscrypto::default_provider(),
        rustls::DEFAULT_VERSIONS,
        Verifier { accept: false },
    );
    let client_addr = attempt(&addr, refusing);
    wait_for(
        &collected,
        &handshake_error(
            &client_addr,
            "remote error: tls: unknown certificate authority",
        ),
    );

    // No key exchange in common over TLS 1.3.
    let mut provider = dcroxide_tlscrypto::default_provider();
    provider.kx_groups = vec![&OnlyX448];
    let client_addr = attempt(
        &addr,
        client(
            provider,
            &[&rustls::version::TLS13],
            Verifier { accept: true },
        ),
    );
    wait_for(
        &collected,
        &handshake_error(
            &client_addr,
            "tls: no key exchanges supported by both client and server",
        ),
    );

    // A ClientHello offering only TLS 1.1: a rustls TLS 1.2 ClientHello
    // whose `supported_versions` entry is rewritten to 0x0302.
    let mut hello_conn = client(
        dcroxide_tlscrypto::default_provider(),
        &[&rustls::version::TLS12],
        Verifier { accept: true },
    );
    let mut hello = Vec::new();
    while hello_conn.wants_write() {
        hello_conn.write_tls(&mut hello).expect("the ClientHello");
    }
    let versions_ext = [0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x03];
    let at = hello
        .windows(versions_ext.len())
        .position(|window| window == versions_ext)
        .expect("a supported_versions extension offering TLS 1.2");
    hello[at + 6] = 0x02;
    let mut tls11 = TcpStream::connect(&addr).expect("connect");
    tls11
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("timeout");
    let client_addr = tls11.local_addr().expect("local addr").to_string();
    tls11.write_all(&hello).expect("send the ClientHello");
    let mut alert = Vec::new();
    let _ = tls11.read_to_end(&mut alert);
    // A fatal `protocol_version` alert, as Go sends.
    assert!(alert.ends_with(&[0x02, 0x46]), "{alert:x?}");
    wait_for(
        &collected,
        &handshake_error(
            &client_addr,
            "tls: client offered only unsupported versions: [302]",
        ),
    );

    // A ClientHello as a real TLS 1.1 client sends it, Go's with
    // `MaxVersion` TLS 1.1 or OpenSSL's `-tls1_1`: `legacy_version`
    // 0x0302 and neither supported_versions nor signature_algorithms,
    // which rustls alone refuses with `handshake_failure` before it looks
    // at the versions.  Go refuses the versions first, in a TLS 1.0
    // record.
    let tls11_hello = {
        let suites: [u8; 6] = [0xc0, 0x13, 0xc0, 0x14, 0x00, 0x2f];
        // supported_groups (X25519, P-256) and ec_point_formats
        // (uncompressed).
        let extensions: [u8; 16] = [
            0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x0b, 0x00, 0x02,
            0x01, 0x00,
        ];
        let mut body = vec![0x03, 0x02];
        body.extend_from_slice(&[0x5a; 32]);
        body.push(0);
        body.extend_from_slice(&u16::try_from(suites.len()).expect("short").to_be_bytes());
        body.extend_from_slice(&suites);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(
            &u16::try_from(extensions.len())
                .expect("short")
                .to_be_bytes(),
        );
        body.extend_from_slice(&extensions);
        let body_len = u32::try_from(body.len()).expect("short").to_be_bytes();
        let mut message = vec![1];
        message.extend_from_slice(&body_len[1..]);
        message.extend_from_slice(&body);
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&u16::try_from(message.len()).expect("short").to_be_bytes());
        record.extend_from_slice(&message);
        record
    };
    let mut tls11 = TcpStream::connect(&addr).expect("connect");
    tls11
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("timeout");
    let client_addr = tls11.local_addr().expect("local addr").to_string();
    tls11.write_all(&tls11_hello).expect("send the ClientHello");
    let mut alert = Vec::new();
    let _ = tls11.read_to_end(&mut alert);
    assert_eq!(alert, [0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x46]);
    wait_for(
        &collected,
        &handshake_error(
            &client_addr,
            "tls: client offered only unsupported versions: [302 301]",
        ),
    );

    // And a client that completes its handshake is not logged at all,
    // even when it then leaves without a request, which Go passes over in
    // silence too.
    attempt(
        &addr,
        client(
            dcroxide_tlscrypto::default_provider(),
            rustls::DEFAULT_VERSIONS,
            Verifier { accept: true },
        ),
    );
    std::thread::sleep(Duration::from_millis(500));
    let out = collected.lock().expect("sink").clone();
    assert_eq!(
        out.matches("TLS handshake error").count(),
        6,
        "one line per refused handshake: {out}"
    );
}
