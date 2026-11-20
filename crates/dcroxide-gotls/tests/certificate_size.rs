// SPDX-License-Identifier: ISC
//! Client certificate messages of the sizes a client keeping to the
//! protocol sends, through [`handshake`] under client-certificate
//! authentication, held to Go's server requiring and verifying client
//! certificates under the same roots, through the oracle's TLS commands
//! (`dcroxide_testutil::tls_interop`) under dcrd's `GODEBUG`, with Go's
//! client on both.
//!
//! [`handshake`] reads the client's bytes itself after the ClientHello and
//! gives them to rustls, whose buffer holds one record (`MAX_WIRE_SIZE`,
//! 18,437 bytes) until the records it has processed start a longer
//! handshake message, and 64 KiB less one byte then
//! (`rustls-0.23.46/src/msgs/deframer/buffers.rs:218-236`).  A read given
//! to rustls whole before it processed any of it filled the one record's
//! room once a Certificate message passed some 16 KiB, and the client was
//! refused with rustls's `message buffer full` before a certificate was
//! looked at, which neither Go nor the node's listener before the crate
//! did.  These tests hold that messages from some 50 KiB to within 600
//! bytes of rustls's own limit reach the verifier and are accepted when
//! their chain is valid, in TLS 1.3 and TLS 1.2.
//!
//! The chains are real ones: ML-DSA-87 authorities, whose certificates
//! are some 7.5 KB each, six of them between the leaf and the trusted
//! root, the most webpki builds through
//! (`rustls-webpki-0.103.17/src/verify_cert.rs:873`).  For the sizes near
//! the limits the client sends further valid certificates after that
//! chain, self-signed authorities Go's server takes as intermediates it
//! does not need.  Between rustls's limit and Go's, a Certificate message
//! Go reads is refused, as PARITY.md's ML-DSA entry records; the cells
//! there pin that difference and Go's own refusal past 256 KiB.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use dcroxide_gotls::{
    ClientAuth, GoClientCertVerifier, GoServerConfigs, GoServerOptions, KeyPair, handshake,
};
use dcroxide_testutil::hex;
use dcroxide_testutil::tls_interop::{Issued, TlsOracle, reads_as_reset, spec};
use serde_json::{Value, json};

/// The request each cell's client sends, which a TLS 1.3 server's refusal
/// of its certificate arrives in answer to.
fn request() -> Value {
    json!({ "method": "POST", "path": "/", "headers": {}, "body": "ping" })
}

/// The ML-DSA-87 authorities between the leaf and the root, the root's
/// child first: six, the most webpki builds through.
const AUTHORITIES: [&str; 6] = ["ca 1", "ca 2", "ca 3", "ca 4", "ca 5", "ca 6"];

/// The largest Certificate message Go's server reads
/// (`maxHandshakeCertificateMsg`, `crypto/tls/common.go:72`).
const GO_CERTIFICATE_MAX: usize = 262_144;

/// The largest handshake message rustls reads
/// (`MAX_HANDSHAKE_SIZE`, `rustls-0.23.46/src/msgs/deframer/handshake.rs:376`).
const RUSTLS_HANDSHAKE_MAX: usize = 0xffff;

/// What a handshake through [`handshake`] gave: the client's certificates
/// as the server received them, or the handshake's error text.
type Served = Result<Vec<Vec<u8>>, String>;

/// Serve one connection on loopback with `configs` through [`handshake`],
/// answering a completed handshake's request with a 200: the address, and
/// what the handshake gave, once the client is done.
fn serve_once(configs: Arc<GoServerConfigs>) -> (String, thread::JoinHandle<Served>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("the address").to_string();
    let serving = thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(10))
            .expect("a deadline");
        let mut tls = handshake(sock, deadline, Duration::from_millis(50), || configs)?;
        let peer: Vec<Vec<u8>> = tls
            .conn
            .peer_certificates()
            .unwrap_or_default()
            .iter()
            .map(|cert| cert.to_vec())
            .collect();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if tls.read(&mut byte).unwrap_or(0) == 0 {
                return Ok(peer);
            }
            head.push(byte[0]);
        }
        let _ =
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        tls.conn.send_close_notify();
        let _ = tls.flush();
        Ok(peer)
    });
    (addr, serving)
}

/// What one cell gave: Go's client's answer from the crate's server, what
/// the crate's server gave, Go's client's answer from Go's server, and
/// Go's server's answer.
struct Outcome {
    ours: Value,
    ours_served: Served,
    theirs: Value,
    served: Value,
}

/// One cell: Go's client in `version`'s `fields`, presenting `chain`,
/// leaf first, with `key`'s key, to the crate's server trusting `root`
/// under `RequireAndVerifyClientCert`, and to Go's server trusting the
/// same, each holding `server`'s pair.
fn cell(
    go: &mut TlsOracle,
    server: &Issued,
    root: &Issued,
    fields: &Value,
    chain: &[&Issued],
) -> Outcome {
    let key_pair = KeyPair::from_pem(&server.cert_pem, &server.key_pem).expect("the pair");
    let verifier = GoClientCertVerifier::from_pem(&root.cert_pem).expect("the verifier");
    let options = GoServerOptions {
        client_auth: ClientAuth::RequireAndVerifyClientCert(Arc::new(verifier)),
        ..GoServerOptions::default()
    };
    let configs = Arc::new(GoServerConfigs::new(&key_pair, &options).expect("the set"));
    let (leaf, rest) = chain.split_first().expect("a leaf");
    let dial = |go: &mut TlsOracle, addr: &str| {
        let mut fields = fields.clone();
        fields["addr"] = json!(addr);
        fields["server_name"] = json!("localhost");
        fields["roots"] = json!([hex(&server.cert)]);
        fields["client_cert"] = leaf.identity(rest);
        fields["request"] = request();
        go.dial(fields)
    };
    let (addr, serving) = serve_once(configs);
    let ours = dial(go, &addr);
    let ours_served = serving.join().expect("the server thread");

    let (addr, id) = go.listen(json!({
        "chain": [hex(&server.cert)],
        "key_pkcs8": hex(&server.key_pkcs8),
        "client_auth": "RequireAndVerifyClientCert",
        "client_cas": [hex(&root.cert)],
        "min_version": "TLS 1.2",
        "response_body": "ok",
    }));
    let theirs = dial(go, &addr);
    let served = go.served(&id);
    Outcome {
        ours,
        ours_served,
        theirs,
        served,
    }
}

/// The length of the body of the Certificate message carrying `chain` in
/// `version`: in TLS 1.2 the list's three-byte length and each
/// certificate's (RFC 5246 §7.4.2), and in TLS 1.3 an empty request
/// context besides and each entry's empty extensions, which Go's client
/// sends (RFC 8446 §4.4.2).
fn certificate_message_len(version: &str, chain: &[&Issued]) -> usize {
    let per_entry = if version == "TLS 1.3" { 5 } else { 3 };
    let context = usize::from(version == "TLS 1.3");
    chain
        .iter()
        .map(|cert| cert.cert.len().saturating_add(per_entry))
        .sum::<usize>()
        .saturating_add(3)
        .saturating_add(context)
}

/// The two versions each cell runs in, as Go's client is cut to them.
fn versions() -> [(&'static str, Value); 2] {
    [
        ("TLS 1.3", json!({ "min_version": "TLS 1.3" })),
        ("TLS 1.2", json!({ "max_version": "TLS 1.2" })),
    ]
}

/// The specs of the chains: the server's pair, the trusted ML-DSA-87
/// root, [`AUTHORITIES`] below it, and under the last of them an
/// ML-DSA-87 and a P-256 client leaf, and the same two for servers alone,
/// whose extended key usage leaves out client authentication.
fn chain_specs() -> Vec<Value> {
    let mut specs = vec![
        spec("server", "P-256", None, "server"),
        spec("root", "ML-DSA-87", None, "ca"),
    ];
    let mut issuer = "root";
    for name in AUTHORITIES {
        specs.push(spec(name, "ML-DSA-87", Some((issuer, "ML-DSA-87")), "ca"));
        issuer = name;
    }
    specs.push(spec(
        "leaf ML-DSA-87",
        "ML-DSA-87",
        Some((issuer, "ML-DSA-87")),
        "client",
    ));
    specs.push(spec(
        "leaf P-256",
        "P-256",
        Some((issuer, "ML-DSA-87")),
        "client",
    ));
    for key in ["ML-DSA-87", "P-256"] {
        specs.push(spec(
            &format!("leaf {key} for servers"),
            key,
            Some((issuer, "ML-DSA-87")),
            "server",
        ));
    }
    specs
}

/// A valid client chain of over 32 KiB, an ML-DSA-87 or a P-256 leaf and
/// the six ML-DSA-87 authorities above it, is verified and accepted by
/// the crate's server, which receives every certificate, as Go's server
/// accepts it and verifies it to the root, in TLS 1.3 and, for the P-256
/// leaf (Go's client sends no ML-DSA certificate in TLS 1.2), in TLS 1.2;
/// and the same chains with a leaf for servers alone are refused by the
/// verifier for its key usage, in Go's words, by both, so the refusal
/// comes from the certificates, not their size.  (A chain under a root the
/// server does not trust is no test of that with Go's client, which sends
/// no certificate whose issuers the CertificateRequest's authorities leave
/// out.)  Before the fix the crate refused each of these with rustls's
/// `message buffer full`, the refused ones included.
#[test]
fn a_client_chain_over_32_kib_is_verified_and_accepted_as_go_accepts_it() {
    let Some(mut go) = TlsOracle::start_ml_dsa() else {
        return;
    };
    let pki = go.pki(&chain_specs());
    let server = &pki["server"];
    let usage = "tls: failed to verify certificate: x509: certificate specifies an incompatible \
                 key usage";
    let mut cells = 0usize;
    for (version, fields) in versions() {
        for leaf in ["leaf ML-DSA-87", "leaf P-256"] {
            if version == "TLS 1.2" && leaf == "leaf ML-DSA-87" {
                continue;
            }
            let mut chain = vec![&pki[leaf]];
            chain.extend(AUTHORITIES.iter().rev().map(|name| &pki[*name]));
            let sent: usize = chain.iter().map(|cert| cert.cert.len()).sum();
            let message = certificate_message_len(version, &chain);
            assert!(sent > 32 * 1024 + 2048, "{leaf}: {sent} bytes of chain");
            assert!(message < RUSTLS_HANDSHAKE_MAX, "{leaf}: {message}");

            let what =
                format!("{version}, {leaf}, {sent} bytes of chain, a {message}-byte message");
            let outcome = cell(&mut go, server, &pki["root"], &fields, &chain);
            assert_eq!(outcome.ours["ok"], true, "{what}: ours {}", outcome.ours);
            assert_eq!(outcome.ours["http_status"], 200, "{what}: ours");
            let received = outcome.ours_served.expect("the crate's server accepts");
            let want: Vec<Vec<u8>> = chain.iter().map(|cert| cert.cert.clone()).collect();
            assert_eq!(
                received, want,
                "{what}: the certificates the server received"
            );
            assert_eq!(
                outcome.theirs["ok"], true,
                "{what}: Go's {}",
                outcome.theirs
            );
            assert_eq!(outcome.served["ok"], true, "{what}: Go's server");
            let verified = outcome.served["verified_chains"][0]
                .as_array()
                .map_or(0, Vec::len);
            assert_eq!(
                verified,
                chain.len().saturating_add(1),
                "{what}: to the root"
            );
            cells = cells.saturating_add(1);

            // Go's alert for the usage is `bad_certificate` and rustls's
            // `unsupported_certificate`, as PARITY.md's clientcert entry
            // records, so Go's client's errors are not compared.
            chain[0] = &pki[&format!("{leaf} for servers")];
            let what = format!("{what}, for servers alone");
            let outcome = cell(&mut go, server, &pki["root"], &fields, &chain);
            assert_eq!(outcome.ours["ok"], false, "{what}: ours {}", outcome.ours);
            assert_eq!(
                outcome.theirs["ok"], false,
                "{what}: Go's {}",
                outcome.theirs
            );
            assert_eq!(
                outcome.ours_served.as_ref().map(Vec::len),
                Err(&usage.to_owned()),
                "{what}: the verifier's refusal"
            );
            go.assert_refused(&what, &outcome.served, usage);
            cells = cells.saturating_add(1);
        }
    }
    assert_eq!(
        cells, 6,
        "three chains, each with a client's leaf and a server's"
    );
    go.report("a_client_chain_over_32_kib_is_verified_and_accepted_as_go_accepts_it");
}

/// Assert that Go's client, whose Certificate message a server refused
/// with most of it still to come, read `alert` or a reset: the server
/// closes once it refuses, and the client's bytes still unread there, or
/// arriving after the close, draw a reset from its system, which may
/// reach the client before the alert does.  Windows names the reset
/// "forcibly closed by the remote host" (WSAECONNRESET) or "aborted by
/// the software in your host machine" (WSAECONNABORTED).
fn assert_alert_or_reset(what: &str, detail: &Value, alert: &str) {
    assert_eq!(detail["ok"], false, "{what}: Go's client {detail}");
    let error = detail["error"].as_str().unwrap_or_default();
    assert!(
        error == alert || reads_as_reset(error) || error.ends_with("broken pipe"),
        "{what}: Go's client read {error}, not {alert} or a reset"
    );
}

/// How many of the certificates sent after the chain to bring a
/// Certificate message near a limit are self-signed ML-DSA-87 authorities,
/// of some 7.5 KB each, enough to pass Go's limit.
const PADS_LARGE: usize = 36;

/// How many are self-signed P-256 authorities, of some 400 bytes each,
/// which bring the message within 600 bytes of a limit.
const PADS_SMALL: usize = 24;

/// The chain `base` followed by pads from `pads`, the large ones first,
/// whose Certificate message in `version` is the longest at or under
/// `at_most`.
fn padded<'a>(
    version: &str,
    base: &[&'a Issued],
    pads: &[&'a Issued],
    at_most: usize,
) -> Vec<&'a Issued> {
    let mut chain = base.to_vec();
    for pad in pads {
        chain.push(pad);
        if certificate_message_len(version, &chain) > at_most {
            chain.pop();
        }
    }
    chain
}

/// Certificate messages near the two limits, a valid chain (the P-256
/// leaf under the six ML-DSA-87 authorities) with further valid
/// certificates after it, in TLS 1.3 and TLS 1.2, each to the crate's
/// server and to Go's:
///
/// - at most 600 bytes under rustls's 64 KiB, both accept, and the
///   crate's server receives every certificate;
/// - over rustls's limit and at most 600 bytes under Go's 256 KiB, Go's
///   server accepts and the crate's refuses, before its verifier runs,
///   with `decode_error` and Go's words for a message it cannot decode,
///   the difference PARITY.md's ML-DSA entry records, which the node had
///   before the crate as well;
/// - over Go's 256 KiB by at most 600 bytes, both refuse, Go's server with
///   `internal_error` and its words for the length.
#[test]
fn client_certificate_messages_near_the_limits_against_gos() {
    let Some(mut go) = TlsOracle::start_ml_dsa() else {
        return;
    };
    let mut specs = chain_specs();
    for i in 0..PADS_LARGE {
        specs.push(spec(&format!("pad {i}"), "ML-DSA-87", None, "ca"));
    }
    for i in 0..PADS_SMALL {
        specs.push(spec(&format!("small pad {i}"), "P-256", None, "ca"));
    }
    let pki = go.pki(&specs);
    let server = &pki["server"];
    let mut base = vec![&pki["leaf P-256"]];
    base.extend(AUTHORITIES.iter().rev().map(|name| &pki[*name]));
    let pads: Vec<&Issued> = (0..PADS_LARGE)
        .map(|i| &pki[&format!("pad {i}")])
        .chain((0..PADS_SMALL).map(|i| &pki[&format!("small pad {i}")]))
        .collect();
    let mut cells = 0usize;
    for (version, fields) in versions() {
        let under_rustls = padded(version, &base, &pads, RUSTLS_HANDSHAKE_MAX);
        let under_go = padded(version, &base, &pads, GO_CERTIFICATE_MAX);
        let over_go = padded(
            version,
            &base,
            &pads,
            GO_CERTIFICATE_MAX.saturating_add(600),
        );
        for (what, chain, low, high) in [
            (
                "under rustls's limit",
                &under_rustls,
                RUSTLS_HANDSHAKE_MAX.saturating_sub(600),
                RUSTLS_HANDSHAKE_MAX,
            ),
            (
                "under Go's limit",
                &under_go,
                GO_CERTIFICATE_MAX.saturating_sub(600),
                GO_CERTIFICATE_MAX,
            ),
            (
                "over Go's limit",
                &over_go,
                GO_CERTIFICATE_MAX.saturating_add(1),
                GO_CERTIFICATE_MAX.saturating_add(600),
            ),
        ] {
            let message = certificate_message_len(version, chain);
            let what = format!(
                "{version}, {what}, {} certificates, a {message}-byte message",
                chain.len()
            );
            assert!(
                (low..=high).contains(&message),
                "{what}: not in {low}..={high}"
            );
            let outcome = cell(&mut go, server, &pki["root"], &fields, chain);
            if message <= RUSTLS_HANDSHAKE_MAX {
                assert_eq!(outcome.ours["ok"], true, "{what}: ours {}", outcome.ours);
                let received = outcome.ours_served.expect("the crate's server accepts");
                assert_eq!(received.len(), chain.len(), "{what}: every certificate");
            } else {
                assert_eq!(outcome.ours["ok"], false, "{what}: ours {}", outcome.ours);
                let text = outcome.ours_served.expect_err("the crate's server refuses");
                assert_eq!(
                    text, "local error: tls: error decoding message",
                    "{what}: rustls's refusal in Go's words"
                );
                assert_alert_or_reset(
                    &what,
                    &outcome.ours,
                    "remote error: tls: error decoding message",
                );
            }
            if message <= GO_CERTIFICATE_MAX {
                assert_eq!(
                    outcome.theirs["ok"], true,
                    "{what}: Go's {}",
                    outcome.theirs
                );
                assert_eq!(outcome.served["ok"], true, "{what}: Go's server");
                assert_eq!(
                    outcome.served["peer_certificates"]
                        .as_array()
                        .map_or(0, Vec::len),
                    chain.len(),
                    "{what}: Go's server"
                );
            } else {
                assert_alert_or_reset(&what, &outcome.theirs, "remote error: tls: internal error");
                go.assert_refused(
                    &what,
                    &outcome.served,
                    &format!(
                        "tls: handshake message of length {message} bytes exceeds maximum of \
                         {GO_CERTIFICATE_MAX} bytes"
                    ),
                );
            }
            cells = cells.saturating_add(1);
        }
    }
    assert_eq!(cells, 6, "three sizes in two versions");
    assert_eq!(
        go.handshakes(),
        cells.saturating_mul(2),
        "each with both servers"
    );
    go.report("client_certificate_messages_near_the_limits_against_gos");
}
