// SPDX-License-Identifier: ISC
//! dcrwallet's two TLS listeners, as the crate's public API expresses them
//! for a wallet ([`GoServerOptions::dcrwallet_jsonrpc`],
//! [`GoServerOptions::dcrwallet_grpc`]), against Go's `crypto/tls`
//! configured as dcrwallet configures it, through the oracle's TLS
//! commands, the harness the node's and the provider's matrices share
//! (`dcroxide_testutil::tls_interop`), run under dcrwallet's `GODEBUG`
//! ([`TlsOracle::start_dcrwallet`]).
//!
//! dcrwallet's `tls.Config` (`startRPCServers`, `rpcserver.go:252-330` at
//! the wallet's pin) keeps a `ClientCAs` pool that may be empty: a
//! `--clientcafile` that adds nothing only warns, and the gRPC listener
//! then requires a client certificate all the same.  Under
//! `--issueclientcert` it adds the authority it generates with
//! `CertPool.AddCert`, on `--tlscurve`'s curve, Ed25519 by default, and
//! issues a client certificate under it; the oracle makes both from
//! dcrwallet's own templates (`tls_pki`'s `dcrwallet`).  Its JSON-RPC
//! listener asks for no certificate under basic authentication, though
//! the pool is set, and requires one under clientcert.  Its gRPC listener
//! passes the configuration to grpc-go's `credentials.NewTLS`, which adds
//! `h2` and sets the suites, and grpc-go closes a handshake that
//! negotiated no protocol (the oracle's `grpc`).
//!
//! Each cell is served once by a [`GoServerConfigs`] through [`handshake`]
//! and once by Go's server, to the same Go client, in TLS 1.3 and in TLS
//! 1.2, and the two are held to one verdict, to the same error at Go's
//! client (unless Go's client, refused by Go's server, met a reset when it
//! wrote its request, a race [`assert_agree`] describes), to the same
//! protocol and, where a cell says so, the same
//! version, suite and group, and, when the oracle runs the reference Go,
//! to Go's server's words in the crate's handshake error.  The signature
//! schemes of the crate's CertificateRequest differ from Go's as
//! PARITY.md's ML-DSA entry records (PKCS#1 v1.5 in TLS 1.3), so an empty
//! pool's are held to those of a pool with an authority in it, the list
//! dcrd's port sends.  The cells of a client that breaks
//! the protocol after its first ClientHello send hand-written records in
//! place of Go's client and compare the server's answer record by record.
//!
//! The bytes after a handshake are the harness's HTTP/1.1 exchange on both
//! sides, whatever protocol was negotiated: grpc-go would speak HTTP/2
//! there, and the wallet's gRPC server is not built here.  No cell
//! compares a hybrid group, which the crate does not offer (ADR-0015, T3):
//! each cell that compares the group cuts Go's client to classical ones.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use dcroxide_gotls::{
    ClientCaPool, GRPC_MISSING_ALPN, GoClientCertVerifier, GoServerConfigs, GoServerOptions,
    KeyPair, handshake,
};
use dcroxide_testutil::REFERENCE_GO;
use dcroxide_testutil::hex;
use dcroxide_testutil::tls_interop::{Issued, Negotiated, TlsOracle, reads_as_reset, spec};
use serde_json::{Value, json};

/// The request each cell's client sends, which a TLS 1.3 server's refusal
/// of its certificate arrives in answer to.
fn request() -> Value {
    json!({ "method": "POST", "path": "/", "headers": {}, "body": "ping" })
}

/// Serve one connection on loopback with `configs` through [`handshake`],
/// answering a completed handshake's request with a 200: the address, and
/// the handshake's error text, if it failed, once the client is done.
fn serve_once(configs: Arc<GoServerConfigs>) -> (String, thread::JoinHandle<Option<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("the address").to_string();
    let serving = thread::spawn(move || {
        let (sock, _) = listener.accept().expect("accept");
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(10))
            .expect("a deadline");
        let mut tls = match handshake(sock, deadline, Duration::from_millis(50), || configs) {
            Ok(tls) => tls,
            Err(text) => return Some(text),
        };
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if tls.read(&mut byte).unwrap_or(0) == 0 {
                return None;
            }
            head.push(byte[0]);
        }
        let _ =
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        tls.conn.send_close_notify();
        let _ = tls.flush();
        None
    });
    (addr, serving)
}

/// What one cell gave: Go's client's answer from the crate's server, the
/// crate's handshake error, Go's client's answer from Go's server, and
/// Go's server's answer.
struct Outcome {
    ours: Value,
    ours_error: Option<String>,
    theirs: Value,
    served: Value,
}

/// One cell: Go's client dialing with `fields` the crate's server built
/// with `options`, and Go's server listening with `go_fields`, with
/// `server`'s pair on both.
fn cell(
    go: &mut TlsOracle,
    server: &Issued,
    options: &GoServerOptions,
    go_fields: &Value,
    fields: &Value,
) -> Outcome {
    let key_pair = KeyPair::from_pem(&server.cert_pem, &server.key_pem).expect("the pair");
    let configs = Arc::new(GoServerConfigs::new(&key_pair, options).expect("the set"));
    let dial = |go: &mut TlsOracle, addr: &str| {
        let mut fields = fields.clone();
        fields["addr"] = json!(addr);
        fields["server_name"] = json!("localhost");
        fields["roots"] = json!([hex(&server.cert)]);
        fields["request"] = request();
        go.dial(fields)
    };
    let (addr, serving) = serve_once(configs);
    let ours = dial(go, &addr);
    let ours_error = serving.join().expect("the server thread");

    let mut go_fields = go_fields.clone();
    go_fields["chain"] = json!([hex(&server.cert)]);
    go_fields["key_pkcs8"] = json!(hex(&server.key_pkcs8));
    go_fields["response_body"] = json!("ok");
    // dcrwallet's `MinVersion` (`rpcserver.go:274`), Go's server default
    // since Go 1.22 anyway.
    go_fields["min_version"] = json!("TLS 1.2");
    let (addr, id) = go.listen(go_fields);
    let theirs = dial(go, &addr);
    let served = go.served(&id);
    Outcome {
        ours,
        ours_error,
        theirs,
        served,
    }
}

/// The two versions each cell runs in, as Go's client is cut to them.
fn versions() -> [(&'static str, Value); 2] {
    [
        ("TLS 1.3", json!({ "min_version": "TLS 1.3" })),
        ("TLS 1.2", json!({ "max_version": "TLS 1.2" })),
    ]
}

/// Whether Go's client, as `detail` reports it, read a reset of the
/// connection ([`reads_as_reset`]) off Linux, where a refusing server's
/// alert was due.  A server that refuses closes with Go's bytes still
/// unread or still to come, which draws a reset from its system.  Linux
/// delivers the alert all the same; a system that throws away what it
/// has received when a reset arrives, as Windows does, may show Go's
/// client the reset instead.
fn reset_in_place_of_the_alert(detail: &Value) -> bool {
    !cfg!(target_os = "linux") && reads_as_reset(detail["error"].as_str().unwrap_or_default())
}

/// [`TlsOracle::assert_refused`] for what Go's client read: off Linux a
/// reset may reach it before the alert does
/// ([`reset_in_place_of_the_alert`]), and then only the refusal is held.
fn assert_client_refused(go: &TlsOracle, what: &str, detail: &Value, alert: &str) {
    if reset_in_place_of_the_alert(detail) {
        assert_eq!(detail["ok"], false, "{what}: Go's client {detail}");
    } else {
        go.assert_refused(what, detail, alert);
    }
}

/// Assert that Go's client was refused and read `alert`, under any Go.
/// Off Linux a reset may reach it before the alert does (see
/// [`assert_agree`]), and then only the refusal is held.
fn assert_hears(go: &TlsOracle, what: &str, detail: &Value, alert: &str) {
    assert_client_refused(go, what, detail, alert);
    if !reset_in_place_of_the_alert(detail) {
        assert_eq!(detail["error"], alert, "{what}");
    }
}

/// Hold the crate's server to Go's: one verdict, the same error at Go's
/// client, the same protocol at both of Go's ends, and under the reference
/// Go the crate's handshake error in Go's server's words.
fn assert_agree(go: &TlsOracle, what: &str, outcome: &Outcome) {
    let Outcome {
        ours,
        ours_error,
        theirs,
        served,
    } = outcome;
    assert_eq!(
        ours["ok"], theirs["ok"],
        "{what}: ours {ours}, Go's {theirs}"
    );
    // A TLS 1.2 client that sends no certificate hears rustls's
    // `certificate_required` where Go sends `handshake_failure`, as
    // PARITY.md's clientcert entry records; Go's own client sends none
    // when the CertificateRequest names no authority that issued its own.
    let tls12_without_a_certificate = ours["error"] == "remote error: tls: certificate required"
        && theirs["error"] == "remote error: tls: handshake failure"
        && ours_error.as_deref() == Some("tls: client didn't provide a certificate");
    // A client certificate Go's parser refuses is refused here with
    // rustls's bad encoding, `bad_certificate`, where Go sends
    // `decode_error`, which no error a rustls verifier returns is answered
    // with, as PARITY.md's clientcert entry records; the words are Go's.
    let unparsable_certificate = ours["error"] == "remote error: tls: bad certificate"
        && theirs["error"] == "remote error: tls: error decoding message"
        && ours_error
            .as_deref()
            .is_some_and(|text| text.starts_with("tls: failed to parse client certificate: "));
    // grpc-go closes a completed handshake that negotiated no protocol;
    // what Go's client then reads, a close_notify or a reset after its
    // request crossed the close, is the race of two sockets, not the
    // servers', so only the verdict is compared.
    let closed_after_the_handshake = ours_error.as_deref() == Some(GRPC_MISSING_ALPN);
    // A server that refuses closes with Go's bytes still unread or still
    // to come, which draws a reset from its system.  Linux delivers the
    // alert all the same; a system that throws away what it has received
    // when a reset arrives, as Windows does, may show Go's client the
    // reset instead, so there only the verdict is compared.
    let reset_before_the_alert =
        reset_in_place_of_the_alert(ours) || reset_in_place_of_the_alert(theirs);
    // Go's client writes its request as soon as its TLS 1.3 handshake
    // returns, before the server has judged its certificate
    // (`tools/oracle/tls.go`'s `tlsDialOnce`), and Go's server closes a
    // refused handshake at once (`serveOne`'s deferred `Close`), with what
    // is left of the client's flight possibly unread, so its system may
    // answer with a reset that reaches the client before it writes: the
    // write fails and the alert goes unread.  That is the race of two
    // sockets, not Go's server's verdict, so the crate's side is held to
    // an alert, but for a reset in its place off Linux (above), and Go's
    // server's words are compared below as ever.
    let gos_request_met_a_reset = request_met_a_reset(theirs);
    if gos_request_met_a_reset {
        assert_eq!(theirs["ok"], false, "{what}: Go's {theirs}");
        assert!(
            reset_in_place_of_the_alert(ours)
                || ours["error"]
                    .as_str()
                    .is_some_and(|error| error.starts_with("remote error: tls: ")),
            "{what}: the crate's server's alert, ours {ours}"
        );
    }
    if !tls12_without_a_certificate
        && !closed_after_the_handshake
        && !reset_before_the_alert
        && !gos_request_met_a_reset
        && !unparsable_certificate
    {
        assert_eq!(
            ours["error"], theirs["error"],
            "{what}: Go's client's error"
        );
    }
    assert_eq!(
        ours.get("negotiated_protocol"),
        theirs.get("negotiated_protocol"),
        "{what}: the protocol, ours {ours}, Go's {theirs}"
    );
    assert_eq!(
        ours_error.is_none(),
        served["ok"] == true,
        "{what}: ours {ours_error:?}, Go's server {served}"
    );
    if go.go_version() == REFERENCE_GO
        && let Some(text) = ours_error
    {
        assert_eq!(served["error"], json!(text), "{what}: Go's server's words");
    }
}

/// Whether Go's client, as `detail` reports it, was refused at the write
/// of its request by a reset ([`reads_as_reset`]) or, the reset already
/// taken, a broken pipe: Go names the failed operation first, `write`.
fn request_met_a_reset(detail: &Value) -> bool {
    let error = detail["error"].as_str().unwrap_or_default();
    detail["ok"] == false
        && error.starts_with("write ")
        && (reads_as_reset(error) || error.ends_with("broken pipe"))
}

/// [`request_met_a_reset`] takes Go's words for a request written into a
/// reset, on Linux and on Windows, and nothing a refusal's alert or a
/// reset read during the handshake shows, run without the oracle.
#[test]
fn a_request_written_into_a_reset_is_told_from_an_alert() {
    for (error, met) in [
        (
            "write tcp 127.0.0.1:50650->127.0.0.1:42553: write: connection reset by peer",
            true,
        ),
        (
            "write tcp 127.0.0.1:50650->127.0.0.1:42553: write: broken pipe",
            true,
        ),
        (
            "write tcp 127.0.0.1:50650->127.0.0.1:42553: wsasend: An existing connection was \
             forcibly closed by the remote host.",
            true,
        ),
        ("remote error: tls: error decrypting message", false),
        ("remote error: tls: illegal parameter", false),
        (
            "read tcp 127.0.0.1:50650->127.0.0.1:42553: read: connection reset by peer",
            false,
        ),
        ("EOF", false),
    ] {
        assert_eq!(
            request_met_a_reset(&json!({ "ok": false, "error": error })),
            met,
            "{error}"
        );
    }
    assert!(!request_met_a_reset(&json!({ "ok": true, "error": "" })));
}

/// The `tls_pki` specs of dcrwallet's `--issueclientcert` pair on `curve`:
/// the authority `<prefix>-ca` and the client `<prefix>-client` under it,
/// each from dcrwallet's template.
fn issued_specs(prefix: &str, curve: &str) -> [Value; 2] {
    [
        json!({ "name": format!("{prefix}-ca"), "key": curve, "dcrwallet": "ca" }),
        json!({
            "name": format!("{prefix}-client"), "key": curve,
            "issuer": format!("{prefix}-ca"), "dcrwallet": "client",
        }),
    ]
}

/// An empty pool under `RequireAndVerifyClientCert`, dcrwallet's gRPC
/// listener when its client CA file adds nothing: a certificate is asked
/// for, a client without one is refused, and every certificate a client
/// sends is refused, as Go refuses it.
#[test]
fn an_empty_client_ca_pool_refuses_every_client_as_go_does() {
    let Some(mut go) = TlsOracle::start_dcrwallet() else {
        return;
    };
    let pki = go.pki(&[
        spec("server", "P-256", None, "server"),
        spec("client", "P-256", None, "client"),
        spec("ca", "P-256", None, "ca"),
    ]);
    let (server, client) = (&pki["server"], &pki["client"]);
    let mut pool = ClientCaPool::new();
    assert!(!pool.append_certs_from_pem(b"no certificate here"));
    assert!(pool.is_empty());
    let verifier = Arc::new(GoClientCertVerifier::new(pool).expect("an empty pool's verifier"));
    // The JSON-RPC listener under clientcert, ALPN out of the way.
    let options = GoServerOptions::dcrwallet_jsonrpc(&verifier, true);
    let go_server = json!({ "client_auth": "RequireAndVerifyClientCert", "client_cas": [] });
    // The same listener with an authority in its pool, which did not
    // issue the client's certificate either.
    let mut one = ClientCaPool::new();
    assert!(one.append_certs_from_pem(&pki["ca"].cert_pem));
    let with_one = GoServerOptions::dcrwallet_jsonrpc(
        &Arc::new(GoClientCertVerifier::new(one).expect("the verifier")),
        true,
    );
    for (version, fields) in versions() {
        for with_cert in [true, false] {
            let what = format!("{version}, client certificate {with_cert}");
            let mut fields = fields.clone();
            if with_cert {
                fields["client_cert"] = client.identity(&[]);
            }
            let outcome = cell(&mut go, server, &options, &go_server, &fields);
            assert_eq!(
                outcome.ours["ok"], false,
                "{what}: refused {}",
                outcome.ours
            );
            assert_agree(&go, &what, &outcome);
            let pooled = cell(&mut go, server, &with_one, &go_server, &fields).ours;
            assert_eq!(pooled["ok"], false, "{what}: refused with a pool {pooled}");
            assert_ne!(outcome.ours["certificate_request"], Value::Null, "{what}");
            assert_eq!(
                outcome.ours["certificate_request"], pooled["certificate_request"],
                "{what}: the CertificateRequest's schemes"
            );
        }
    }
    go.report("an_empty_client_ca_pool_refuses_every_client_as_go_does");
}

/// A pool filled from a client CA file and then by `AddCert`, as
/// dcrwallet fills it under `--issueclientcert`: a client certificate
/// issued by the added authority is accepted, one issued by neither is
/// refused, as Go accepts and refuses them.
#[test]
fn a_pool_with_an_added_authority_verifies_as_go_does() {
    let Some(mut go) = TlsOracle::start_dcrwallet() else {
        return;
    };
    let pki = go.pki(&[
        spec("server", "P-256", None, "server"),
        spec("file-ca", "P-256", None, "ca"),
        spec("issued-ca", "P-256", None, "ca"),
        spec("other-ca", "P-256", None, "ca"),
        spec(
            "issued",
            "P-256",
            Some(("issued-ca", "ECDSA-SHA256")),
            "client",
        ),
        spec(
            "stranger",
            "P-256",
            Some(("other-ca", "ECDSA-SHA256")),
            "client",
        ),
    ]);
    let server = &pki["server"];
    let mut pool = ClientCaPool::new();
    assert!(pool.append_certs_from_pem(&pki["file-ca"].cert_pem));
    assert!(pool.add_cert(pki["issued-ca"].cert.clone()));
    assert!(
        pool.add_cert(pki["issued-ca"].cert.clone()),
        "a second copy"
    );
    assert_eq!(pool.len(), 2, "one copy of each");
    let verifier = Arc::new(GoClientCertVerifier::new(pool).expect("the verifier"));
    let options = GoServerOptions::dcrwallet_jsonrpc(&verifier, true);
    let go_server = json!({
        "client_auth": "RequireAndVerifyClientCert",
        "client_cas": [hex(&pki["file-ca"].cert), hex(&pki["issued-ca"].cert)],
    });
    for (version, fields) in versions() {
        for (name, accepted) in [("issued", true), ("stranger", false)] {
            let what = format!("{version}, {name}");
            let mut fields = fields.clone();
            fields["client_cert"] = pki[name].identity(&[]);
            let outcome = cell(&mut go, server, &options, &go_server, &fields);
            assert_eq!(outcome.ours["ok"], accepted, "{what}: {}", outcome.ours);
            assert_agree(&go, &what, &outcome);
        }
    }
    go.report("a_pool_with_an_added_authority_verifies_as_go_does");
}

/// `NoClientCert` with a pool set, dcrwallet's JSON-RPC listener under
/// basic authentication: no certificate is asked for, a client that has
/// one completes as one without does, and a client's ALPN is ignored, as
/// a `tls.Config` without `NextProtos` ignores it.
#[test]
fn no_client_cert_asks_for_none_as_go_does() {
    let Some(mut go) = TlsOracle::start_dcrwallet() else {
        return;
    };
    let pki = go.pki(&[
        spec("server", "P-256", None, "server"),
        spec("ca", "P-256", None, "ca"),
        spec("client", "P-256", Some(("ca", "ECDSA-SHA256")), "client"),
    ]);
    let server = &pki["server"];
    let mut pool = ClientCaPool::new();
    assert!(pool.append_certs_from_pem(&pki["ca"].cert_pem));
    let verifier = Arc::new(GoClientCertVerifier::new(pool).expect("the verifier"));
    let options = GoServerOptions::dcrwallet_jsonrpc(&verifier, false);
    let go_server = json!({ "client_cas": [hex(&pki["ca"].cert)] });
    for (version, fields) in versions() {
        for (with_cert, alpn) in [(true, None), (false, None), (false, Some("h2"))] {
            let what = format!("{version}, client certificate {with_cert}, ALPN {alpn:?}");
            let mut fields = fields.clone();
            if with_cert {
                fields["client_cert"] = pki["client"].identity(&[]);
            }
            if let Some(alpn) = alpn {
                fields["next_protos"] = json!([alpn]);
            }
            let outcome = cell(&mut go, server, &options, &go_server, &fields);
            assert_eq!(outcome.ours["ok"], true, "{what}: {}", outcome.ours);
            assert_eq!(outcome.ours["certificate_request"], Value::Null, "{what}");
            assert_eq!(outcome.ours.get("negotiated_protocol"), None, "{what}");
            assert_agree(&go, &what, &outcome);
        }
    }
    go.report("no_client_cert_asks_for_none_as_go_does");
}

/// dcrwallet's `--issueclientcert` pair on each `--tlscurve`, made from
/// dcrwallet's templates, trusted by `AddCert` alone, on the gRPC listener
/// and on the JSON-RPC listener under clientcert: the client is accepted,
/// as Go accepts it, on Ed25519, dcrwallet's default, on P-256, on P-384
/// and on P-521, whose authority signs with ECDSA-SHA512 and whose client
/// key signs its CertificateVerify with `ecdsa_secp521r1_sha512` in TLS
/// 1.3 and, in TLS 1.2, with the first ECDSA scheme the server lists,
/// `ecdsa_secp256r1_sha256`, which Go's server and the crate both take
/// from a P-521 key (ADR-0015, T4).  Go's client is cut to classical
/// groups, so the version, suite and group are compared too.
#[test]
fn issued_client_certificates_verify_as_go_does() {
    let Some(mut go) = TlsOracle::start_dcrwallet() else {
        return;
    };
    let curves = ["Ed25519", "P-256", "P-384", "P-521"];
    let mut specs = vec![spec("server", "Ed25519", None, "server")];
    for curve in curves {
        specs.extend(issued_specs(curve, curve));
    }
    let pki = go.pki(&specs);
    let server = &pki["server"];
    for curve in curves {
        let ca = &pki[&format!("{curve}-ca")];
        let client = &pki[&format!("{curve}-client")];
        let mut pool = ClientCaPool::new();
        assert!(pool.add_cert(ca.cert.clone()));
        let verifier = Arc::new(GoClientCertVerifier::new(pool).expect("the verifier"));
        let listeners = [
            (
                "gRPC",
                GoServerOptions::dcrwallet_grpc(&verifier),
                json!({ "client_auth": "RequireAndVerifyClientCert",
                        "client_cas": [hex(&ca.cert)], "grpc": true }),
                json!(["h2"]),
            ),
            (
                "JSON-RPC",
                GoServerOptions::dcrwallet_jsonrpc(&verifier, true),
                json!({ "client_auth": "RequireAndVerifyClientCert",
                        "client_cas": [hex(&ca.cert)] }),
                json!([]),
            ),
        ];
        for (listener, options, go_server, alpn) in &listeners {
            for (version, fields) in versions() {
                let what = format!("{curve}, {listener}, {version}");
                let mut fields = fields.clone();
                fields["client_cert"] = client.identity(&[]);
                fields["next_protos"] = alpn.clone();
                fields["curve_preferences"] = json!(["X25519", "CurveP256"]);
                let outcome = cell(&mut go, server, options, go_server, &fields);
                assert_eq!(
                    outcome.theirs["ok"], true,
                    "{what}: Go's {}",
                    outcome.theirs
                );
                assert_agree(&go, &what, &outcome);
                assert_eq!(
                    Negotiated::of_go(&outcome.ours),
                    Negotiated::of_go(&outcome.theirs),
                    "{what}: what was negotiated"
                );
            }
        }
    }
    go.report("issued_client_certificates_verify_as_go_does");
}

/// dcrwallet's `--issueclientcert` client on each `--tlscurve` with its
/// key written as Go's `crypto/x509` refuses to parse it (the oracle's
/// `tls_pki` `spki`): an ECDSA point compressed, in the hybrid form or off
/// its curve, an Ed25519 key with NULL parameters or of 31 bytes; such a
/// certificate sent after the client's own, which no chain uses; a leaf
/// on an X25519 or a DSA key, which Go parses and its TLS takes no
/// signature from; and an RSA key of 8200 bits sent after the client's
/// own.  Go's client sends each as it is (`client_unchecked`), to
/// dcrwallet's JSON-RPC listener under clientcert, in TLS 1.3 and 1.2,
/// and both servers refuse it, in Go's words: `tls: failed to parse
/// client certificate: ` and the parser's error, `tls: client certificate
/// contains an unsupported public key of type ` and the key's, or `tls:
/// client sent certificate containing RSA key larger than 8192 bits`.
/// The alerts are Go's, `unsupported_certificate` and `bad_certificate`,
/// but for a certificate that does not parse, which the crate answers
/// with `bad_certificate` and Go with `decode_error` ([`assert_agree`]).
#[test]
fn client_keys_go_does_not_parse_or_take_are_refused_as_go_does() {
    let Some(mut go) = TlsOracle::start_dcrwallet() else {
        return;
    };
    let curves = ["Ed25519", "P-256", "P-384", "P-521"];
    let mut specs = vec![spec("server", "Ed25519", None, "server")];
    let mut cells: Vec<(&str, String, Vec<String>, &str)> = Vec::new();
    let parse = "tls: failed to parse client certificate: ";
    for curve in curves {
        specs.extend(issued_specs(curve, curve));
        let broken: &[(&str, &str)] = if curve == "Ed25519" {
            &[
                (
                    "ed25519_params",
                    "x509: Ed25519 key encoded with illegal parameters",
                ),
                ("ed25519_short", "x509: wrong Ed25519 public key size"),
            ]
        } else {
            &[
                ("compressed", "ecdsa: invalid uncompressed public key"),
                ("hybrid", "ecdsa: invalid uncompressed public key"),
                ("off_curve", ""),
            ]
        };
        for &(mode, words) in broken {
            let name = format!("{curve}-{mode}");
            let mut client = issued_specs(curve, curve)[1].clone();
            client["name"] = json!(name);
            client["spki"] = json!(mode);
            specs.push(client);
            let words = if mode == "off_curve" {
                format!("{parse}{} point not on curve", curve.replace('-', ""))
            } else {
                format!("{parse}{words}")
            };
            cells.push((curve, words.clone(), vec![name.clone()], "leaf"));
            cells.push((
                curve,
                words,
                vec![format!("{curve}-client"), name],
                "unused",
            ));
        }
    }
    for (mode, words) in [
        (
            "x25519",
            "tls: client certificate contains an unsupported public key of type <nil>",
        ),
        (
            "dsa",
            "tls: client certificate contains an unsupported public key of type *dsa.PublicKey",
        ),
    ] {
        let name = format!("P-256-{mode}");
        let mut client = issued_specs("P-256", "P-256")[1].clone();
        client["name"] = json!(name);
        client["spki"] = json!(mode);
        specs.push(client);
        cells.push(("P-256", words.to_string(), vec![name], "leaf"));
    }
    let mut rsa = issued_specs("P-256", "P-256")[1].clone();
    rsa["name"] = json!("P-256-rsa_8200");
    rsa["spki"] = json!("rsa_8200");
    specs.push(rsa);
    cells.push((
        "P-256",
        "tls: client sent certificate containing RSA key larger than 8192 bits".to_string(),
        vec!["P-256-client".to_string(), "P-256-rsa_8200".to_string()],
        "unused",
    ));
    let pki = go.pki(&specs);
    let server = &pki["server"];
    for (curve, words, chain, role) in &cells {
        let (options, go_server) = clientcert_listener(&pki[&format!("{curve}-ca")]);
        for (version, fields) in versions() {
            let what = format!("{chain:?} ({role}), {version}");
            let mut fields = fields.clone();
            fields["client_cert"] = json!({
                "chain": chain.iter().map(|name| hex(&pki[name].cert)).collect::<Vec<_>>(),
                "key_pkcs8": hex(&pki[&chain[0]].key_pkcs8),
            });
            fields["client_unchecked"] = json!(true);
            fields["curve_preferences"] = json!(["X25519", "CurveP256"]);
            let outcome = cell(&mut go, server, &options, &go_server, &fields);
            assert_eq!(outcome.ours["ok"], false, "{what}: ours {}", outcome.ours);
            assert_eq!(
                outcome.ours_error.as_deref(),
                Some(words.as_str()),
                "{what}: the crate's words"
            );
            assert_agree(&go, &what, &outcome);
        }
    }
    go.report("client_keys_go_does_not_parse_or_take_are_refused_as_go_does");
}

/// Go's words for a client CertificateVerify under a scheme its server
/// refuses before it verifies anything: one its list lacks, or in TLS 1.3
/// one that does not fit the leaf's key (`handshake_server.go:779-782`,
/// `handshake_server_tls13.go:1086-1092`), sent with `illegal_parameter`.
const SCHEME_REFUSED: &str = "tls: client certificate used with invalid signature algorithm";

/// The start of Go's words for a client CertificateVerify whose signature
/// does not verify (`handshake_server.go:796-797`,
/// `handshake_server_tls13.go:1101-1104`), sent with `decrypt_error`.
const SIGNATURE_FAILED: &str = "tls: invalid signature by the client certificate: ";

/// dcrwallet's JSON-RPC listener under clientcert, its pool holding
/// `ca` alone, as the crate's options and as Go's server's fields.
fn clientcert_listener(ca: &Issued) -> (GoServerOptions, Value) {
    let mut pool = ClientCaPool::new();
    assert!(pool.add_cert(ca.cert.clone()));
    let verifier = Arc::new(GoClientCertVerifier::new(pool).expect("the verifier"));
    (
        GoServerOptions::dcrwallet_jsonrpc(&verifier, true),
        json!({ "client_auth": "RequireAndVerifyClientCert", "client_cas": [hex(&ca.cert)] }),
    )
}

/// dcrwallet's `--issueclientcert` client on each `--tlscurve`, signing
/// its CertificateVerify as the oracle's `client_signer` breaks it, against
/// dcrwallet's JSON-RPC listener under clientcert, in TLS 1.3 and 1.2: a
/// signature with a bit flipped, a byte short, a byte long, empty, or made
/// by another key of the same curve, and, for an ECDSA key, re-encoded
/// with r zero or the order, with a needless leading zero on r, with the
/// SEQUENCE's length in a longer form than DER's, or as r and s side by
/// side without DER, is refused by both servers with `decrypt_error` and
/// Go's words, `ECDSA verification failure` or `Ed25519 verification
/// failure`; a signature whose s is replaced by n-s is accepted by both,
/// as Go's `ecdsa.VerifyASN1` accepts it.  The handshake's version, suite
/// and group are compared where it completes.
#[test]
fn broken_client_signatures_are_refused_as_go_does() {
    let Some(mut go) = TlsOracle::start_dcrwallet() else {
        return;
    };
    let curves = ["Ed25519", "P-256", "P-384", "P-521"];
    let mut specs = vec![spec("server", "Ed25519", None, "server")];
    for curve in curves {
        specs.extend(issued_specs(curve, curve));
    }
    let pki = go.pki(&specs);
    let server = &pki["server"];
    let any_key = ["flip", "truncate", "trailing_byte", "empty", "other_key"];
    let ecdsa_only = [
        "zero_r",
        "r_is_n",
        "leading_zero",
        "long_length",
        "raw",
        "high_s",
    ];
    let mut compared = 0;
    for curve in curves {
        let (options, go_server) = clientcert_listener(&pki[&format!("{curve}-ca")]);
        let client = &pki[&format!("{curve}-client")];
        let (modes, failure) = if curve == "Ed25519" {
            (any_key.to_vec(), "Ed25519 verification failure")
        } else {
            (
                [&any_key[..], &ecdsa_only[..]].concat(),
                "ECDSA verification failure",
            )
        };
        for mode in modes {
            for (version, fields) in versions() {
                let what = format!("{curve}, {mode}, {version}");
                let mut fields = fields.clone();
                fields["client_cert"] = client.identity(&[]);
                fields["client_signer"] = json!(mode);
                fields["curve_preferences"] = json!(["X25519", "CurveP256"]);
                let outcome = cell(&mut go, server, &options, &go_server, &fields);
                assert_agree(&go, &what, &outcome);
                if mode == "high_s" {
                    assert_eq!(outcome.ours["ok"], true, "{what}: {}", outcome.ours);
                    assert_eq!(
                        Negotiated::of_go(&outcome.ours),
                        Negotiated::of_go(&outcome.theirs),
                        "{what}: what was negotiated"
                    );
                } else {
                    assert_client_refused(
                        &go,
                        &what,
                        &outcome.ours,
                        "remote error: tls: error decrypting message",
                    );
                    assert_eq!(
                        outcome.ours_error,
                        Some(format!("{SIGNATURE_FAILED}{failure}")),
                        "{what}: the crate's words"
                    );
                }
                compared += 1;
            }
        }
    }
    go.report("broken_client_signatures_are_refused_as_go_does");
    assert_eq!(compared, 2 * (5 + 3 * 11), "every mode on each curve");
}

/// One row of [`client_schemes_for_another_key_are_judged_as_go_does`]:
/// what the client is told, the version, and Go's refusal, the alert at
/// Go's client and Go's server's words, or none for an acceptance.
type SchemeRow<'a> = (Value, &'a str, Option<(&'a str, String)>);

/// dcrwallet's `--issueclientcert` client on each `--tlscurve`, signing
/// its CertificateVerify under a scheme for another key than its own
/// (the oracle's `client_public`, the public key Go's client chooses the
/// scheme by) or under a scheme it is held to (`client_sig_algs`),
/// against dcrwallet's JSON-RPC listener under clientcert.  In TLS 1.3 a
/// scheme of another curve or kind than the leaf's key, a P-521 key's
/// signature under ecdsa_secp256r1_sha256 or ecdsa_secp384r1_sha384 among
/// them, is refused by both with `illegal_parameter` and Go's words, the
/// crate's verifier making Go's check of the key (ADR-0015, T4).  In TLS
/// 1.2, where Go does not tie an ECDSA scheme to a curve, an ECDSA key
/// signing under the first ECDSA scheme listed, or held to any one of the
/// three, is accepted by both, P-256 with SHA-512 and P-521 with SHA-256
/// among them; and a scheme of another kind than the key is refused by
/// both with `decrypt_error` and Go's words naming the key's type.
#[test]
fn client_schemes_for_another_key_are_judged_as_go_does() {
    let Some(mut go) = TlsOracle::start_dcrwallet() else {
        return;
    };
    let curves = ["Ed25519", "P-256", "P-384", "P-521"];
    let mut specs = vec![spec("server", "Ed25519", None, "server")];
    for curve in curves {
        specs.extend(issued_specs(curve, curve));
    }
    let pki = go.pki(&specs);
    let server = &pki["server"];
    let ecdsa_schemes = [
        "ECDSAWithP256AndSHA256",
        "ECDSAWithP384AndSHA384",
        "ECDSAWithP521AndSHA512",
    ];
    let mut compared = 0;
    for curve in curves {
        let (options, go_server) = clientcert_listener(&pki[&format!("{curve}-ca")]);
        let client = &pki[&format!("{curve}-client")];
        // Each row: what the client is told, the version, and Go's
        // refusal, the alert at Go's client and Go's server's words, or
        // none for an acceptance.
        let mut rows: Vec<SchemeRow<'_>> = Vec::new();
        for public in curves.iter().filter(|&&public| public != curve) {
            rows.push((
                json!({ "client_public": public }),
                "TLS 1.3",
                Some((
                    "remote error: tls: illegal parameter",
                    SCHEME_REFUSED.into(),
                )),
            ));
            let kind = |key: &str| if key == "Ed25519" { "Ed25519" } else { "ECDSA" };
            let tls12 = (kind(public) != kind(curve)).then(|| {
                let got = if curve == "Ed25519" {
                    "ed25519.PublicKey"
                } else {
                    "*ecdsa.PublicKey"
                };
                (
                    "remote error: tls: error decrypting message",
                    format!(
                        "{SIGNATURE_FAILED}expected an {} public key, got {got}",
                        kind(public)
                    ),
                )
            });
            rows.push((json!({ "client_public": public }), "TLS 1.2", tls12));
        }
        if curve != "Ed25519" {
            for scheme in ecdsa_schemes {
                rows.push((json!({ "client_sig_algs": [scheme] }), "TLS 1.2", None));
            }
        }
        for (extra, version, refusal) in rows {
            let what = format!("{curve}, {extra}, {version}");
            let mut fields = if version == "TLS 1.3" {
                json!({ "min_version": "TLS 1.3" })
            } else {
                json!({ "max_version": "TLS 1.2" })
            };
            for (key, value) in extra.as_object().expect("fields") {
                fields[key] = value.clone();
            }
            fields["client_cert"] = client.identity(&[]);
            fields["curve_preferences"] = json!(["X25519", "CurveP256"]);
            let outcome = cell(&mut go, server, &options, &go_server, &fields);
            assert_agree(&go, &what, &outcome);
            match refusal {
                Some((alert, words)) => {
                    assert_client_refused(&go, &what, &outcome.ours, alert);
                    assert_eq!(outcome.ours_error, Some(words.clone()), "{what}");
                    go.assert_refused(&what, &outcome.served, &words);
                }
                None => {
                    assert_eq!(outcome.ours["ok"], true, "{what}: {}", outcome.ours);
                    assert_eq!(
                        Negotiated::of_go(&outcome.ours),
                        Negotiated::of_go(&outcome.theirs),
                        "{what}: what was negotiated"
                    );
                }
            }
            compared += 1;
        }
    }
    go.report("client_schemes_for_another_key_are_judged_as_go_does");
    assert_eq!(compared, 4 * 3 * 2 + 3 * 3, "every row on each curve");
}

/// What the crate's handshake reports for a TLS 1.2 client whose P-224
/// key signed its CertificateVerify under ecdsa_secp256r1_sha256: rustls's
/// words for a signature algorithm, ecdsa-with-SHA256, the provider has
/// none of for that key, id-ecPublicKey on secp224r1, since Go, which
/// verifies the signature, has none to give (PARITY.md, the clientcert
/// entry).
const P224_REFUSED: &str = "invalid peer certificate: \
     UnsupportedSignatureAlgorithmForPublicKeyContext { signature_algorithm_id: [6, 8, 42, 134, \
     72, 206, 61, 4, 3, 2], public_key_algorithm_id: [6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, \
     43, 129, 4, 0, 33] }";

/// A client certificate on a P-224 key, which no `--tlscurve` offers and
/// Go's `x509` reads, issued by a P-256 authority dcrwallet's JSON-RPC
/// listener trusts under clientcert.  In TLS 1.2 Go's server verifies the
/// client's ECDSA signature with it and accepts the client, and the
/// crate's refuses it with `decrypt_error`, the provider having no P-224
/// algorithm: the divergence PARITY.md's clientcert entry records, in
/// rustls's words ([`P224_REFUSED`]), not words Go never prints.  In TLS
/// 1.3, where Go's client has no scheme for the key and sends no
/// certificate, both refuse it alike.
#[test]
fn a_p224_client_key_is_judged_as_recorded() {
    let Some(mut go) = TlsOracle::start_dcrwallet() else {
        return;
    };
    let pki = go.pki(&[
        spec("server", "Ed25519", None, "server"),
        spec("ca", "P-256", None, "ca"),
        spec("client", "P-224", Some(("ca", "ECDSA-SHA256")), "client"),
    ]);
    let (options, go_server) = clientcert_listener(&pki["ca"]);
    for (version, fields) in versions() {
        let what = format!("P-224, {version}");
        let mut fields = fields.clone();
        fields["client_cert"] = pki["client"].identity(&[]);
        fields["curve_preferences"] = json!(["X25519", "CurveP256"]);
        let outcome = cell(&mut go, &pki["server"], &options, &go_server, &fields);
        if version == "TLS 1.3" {
            assert_agree(&go, &what, &outcome);
            assert_eq!(
                outcome.ours_error.as_deref(),
                Some("tls: client didn't provide a certificate"),
                "{what}"
            );
            continue;
        }
        assert_eq!(
            outcome.theirs["ok"], true,
            "{what}: Go's {}",
            outcome.theirs
        );
        assert_eq!(
            outcome.served["ok"], true,
            "{what}: Go's server {}",
            outcome.served
        );
        assert_client_refused(
            &go,
            &what,
            &outcome.ours,
            "remote error: tls: error decrypting message",
        );
        assert_eq!(outcome.ours_error.as_deref(), Some(P224_REFUSED), "{what}");
    }
    go.report("a_p224_client_key_is_judged_as_recorded");
}

/// dcrwallet's `--issueclientcert` client on each `--tlscurve` whose
/// certificate's signature, its authority's, was tampered with, its last
/// byte flipped, against dcrwallet's JSON-RPC listener under clientcert,
/// in TLS 1.3 and 1.2: refused by both with `unknown_ca`, Go's search
/// building no chain, in Go's words, which Go's server follows with the
/// hint naming the signature's failure that the crate does not render
/// (PARITY.md, the clientcert entry).
#[test]
fn tampered_client_chains_are_refused_as_go_does() {
    let Some(mut go) = TlsOracle::start_dcrwallet() else {
        return;
    };
    let curves = ["Ed25519", "P-256", "P-384", "P-521"];
    let mut specs = vec![spec("server", "Ed25519", None, "server")];
    for curve in curves {
        specs.extend(issued_specs(curve, curve));
    }
    let pki = go.pki(&specs);
    let server = &pki["server"];
    let unknown =
        "tls: failed to verify certificate: x509: certificate signed by unknown authority";
    for curve in curves {
        let (options, go_server) = clientcert_listener(&pki[&format!("{curve}-ca")]);
        let client = &pki[&format!("{curve}-client")];
        let mut tampered = client.cert.clone();
        if let Some(last) = tampered.last_mut() {
            *last ^= 1;
        }
        for (version, fields) in versions() {
            let what = format!("{curve}, {version}");
            let mut fields = fields.clone();
            fields["client_cert"] =
                json!({ "chain": [hex(&tampered)], "key_pkcs8": hex(&client.key_pkcs8) });
            let outcome = cell(&mut go, server, &options, &go_server, &fields);
            let alert = "remote error: tls: unknown certificate authority";
            assert_client_refused(&go, &what, &outcome.ours, alert);
            assert_client_refused(&go, &what, &outcome.theirs, alert);
            if !reset_in_place_of_the_alert(&outcome.ours)
                && !reset_in_place_of_the_alert(&outcome.theirs)
            {
                assert_eq!(outcome.ours["error"], outcome.theirs["error"], "{what}");
            }
            assert_eq!(outcome.ours_error.as_deref(), Some(unknown), "{what}");
            assert_eq!(outcome.served["ok"], false, "{what}: Go's server");
            if go.go_version() == REFERENCE_GO {
                let served = outcome.served["error"].as_str().unwrap_or_default();
                assert!(
                    served.starts_with(&format!("{unknown} (possibly because of ")),
                    "{what}: Go's words {served}"
                );
            }
        }
    }
    go.report("tampered_client_chains_are_refused_as_go_does");
}

/// A client certificate on P-256 or P-521 issued by an authority on each
/// of P-256, P-384 and P-521 signing with each of ECDSA-SHA256, -SHA384
/// and -SHA512, against dcrwallet's JSON-RPC listener under clientcert,
/// in TLS 1.3 and 1.2: every chain is accepted by both, as Go's
/// `crypto/x509` verifies an ECDSA signature with any of the three hashes
/// on any of the three curves (ADR-0015, T4), and the version, suite and
/// group are compared.
#[test]
fn issuers_on_each_curve_and_hash_verify_as_go_does() {
    let Some(mut go) = TlsOracle::start_dcrwallet() else {
        return;
    };
    let curves = ["P-256", "P-384", "P-521"];
    let hashes = ["ECDSA-SHA256", "ECDSA-SHA384", "ECDSA-SHA512"];
    let leaves = ["P-256", "P-521"];
    let mut specs = vec![spec("server", "Ed25519", None, "server")];
    for ca in curves {
        specs.push(spec(&format!("{ca}-ca"), ca, None, "ca"));
        for hash in hashes {
            for leaf in leaves {
                specs.push(spec(
                    &format!("{leaf} under {ca} {hash}"),
                    leaf,
                    Some((&format!("{ca}-ca"), hash)),
                    "client",
                ));
            }
        }
    }
    let pki = go.pki(&specs);
    let server = &pki["server"];
    let mut compared = 0;
    for ca in curves {
        let (options, go_server) = clientcert_listener(&pki[&format!("{ca}-ca")]);
        for hash in hashes {
            for leaf in leaves {
                let client = &pki[&format!("{leaf} under {ca} {hash}")];
                for (version, fields) in versions() {
                    let what = format!("{leaf} under {ca} {hash}, {version}");
                    let mut fields = fields.clone();
                    fields["client_cert"] = client.identity(&[]);
                    fields["curve_preferences"] = json!(["X25519", "CurveP256"]);
                    let outcome = cell(&mut go, server, &options, &go_server, &fields);
                    assert_eq!(
                        outcome.theirs["ok"], true,
                        "{what}: Go's {}",
                        outcome.theirs
                    );
                    assert_agree(&go, &what, &outcome);
                    assert_eq!(
                        Negotiated::of_go(&outcome.ours),
                        Negotiated::of_go(&outcome.theirs),
                        "{what}: what was negotiated"
                    );
                    compared += 1;
                }
            }
        }
    }
    go.report("issuers_on_each_curve_and_hash_verify_as_go_does");
    assert_eq!(compared, 3 * 3 * 2 * 2, "every chain in two versions");
}

/// The `tls_pki` spec of an authority `name` on P-256 valid from
/// `not_before` to `not_after`, Unix seconds, or for `eku` alone.
fn authority_spec(name: &str, window: Option<(i64, i64)>, eku: Option<&str>) -> Value {
    let mut ca = spec(name, "P-256", None, "ca");
    if let Some((not_before, not_after)) = window {
        ca["not_before"] = json!(not_before);
        ca["not_after"] = json!(not_after);
    }
    if let Some(eku) = eku {
        ca["eku"] = json!([eku]);
    }
    ca
}

/// Client certificates Go's search refuses for an authority it passes
/// over or a usage it lacks, on dcrwallet's gRPC listener and on its
/// JSON-RPC listener under clientcert, with a pool holding a valid
/// authority, an expired one, one not yet valid and a server-only one:
/// refused by both servers, and for the same reason as far as rustls can
/// say it.  A leaf whose only issuer in the pool is outside its validity
/// hears `certificate_expired` from both, Go's search ending on that
/// authority's `isValid` refusal (`crypto/x509/verify.go:764`), where the
/// crate used to pass the authority over and send `unknown_ca`; the
/// crate's words are rustls's, Go's printing the time in the server's
/// zone.  A server-only leaf under the valid authority, and a client leaf
/// under the server-only one, are Go's `IncompatibleUsage`, in Go's words,
/// with `unsupported_certificate` where Go sends `bad_certificate`, as
/// PARITY.md's clientcert entry records.  And a server-only leaf whose
/// issuer is in no pool, over this pool and over an empty one, hears
/// `unknown_ca` and Go's words from both, Go building no chain and so
/// never reaching its usage, where the crate used to refuse its usage
/// first.  Go's client presents that leaf only where the
/// CertificateRequest names no authority, so only to the empty pool.
#[test]
fn authorities_and_usages_gos_search_refuses_are_refused_as_go_does() {
    let Some(mut go) = TlsOracle::start_dcrwallet() else {
        return;
    };
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock")
            .as_secs(),
    )
    .expect("a time");
    let day = 86_400;
    let leaf = |name: &str, issuer: Option<&str>, eku: &str| {
        let mut leaf = spec(
            name,
            "P-256",
            issuer.map(|ca| (ca, "ECDSA-SHA256")),
            "client",
        );
        leaf["eku"] = json!([eku]);
        leaf
    };
    let pki = go.pki(&[
        spec("server", "Ed25519", None, "server"),
        authority_spec("ca", None, None),
        authority_spec("expired-ca", Some((now - 10 * day, now - day)), None),
        authority_spec("future-ca", Some((now + day, now + 10 * day)), None),
        authority_spec("server-ca", None, Some("server_auth")),
        authority_spec("other-ca", None, None),
        leaf("under-expired-ca", Some("expired-ca"), "client_auth"),
        leaf("under-future-ca", Some("future-ca"), "client_auth"),
        leaf("server-leaf", Some("ca"), "server_auth"),
        leaf("under-server-ca", Some("server-ca"), "client_auth"),
        leaf("server-stranger", Some("other-ca"), "server_auth"),
    ]);
    let server = &pki["server"];
    let cas = ["ca", "expired-ca", "future-ca", "server-ca"];
    let mut pool = ClientCaPool::new();
    for ca in cas {
        assert!(pool.add_cert(pki[ca].cert.clone()), "{ca}");
    }
    let verifier = Arc::new(GoClientCertVerifier::new(pool).expect("the verifier"));
    let empty = Arc::new(GoClientCertVerifier::new(ClientCaPool::new()).expect("an empty pool"));
    let go_cas: Vec<String> = cas.iter().map(|ca| hex(&pki[*ca].cert)).collect();
    let listeners = [
        (
            "gRPC",
            GoServerOptions::dcrwallet_grpc(&verifier),
            json!({ "client_auth": "RequireAndVerifyClientCert", "client_cas": go_cas,
                    "grpc": true }),
            json!(["h2"]),
        ),
        (
            "JSON-RPC",
            GoServerOptions::dcrwallet_jsonrpc(&verifier, true),
            json!({ "client_auth": "RequireAndVerifyClientCert", "client_cas": go_cas }),
            json!([]),
        ),
        (
            "JSON-RPC, an empty pool",
            GoServerOptions::dcrwallet_jsonrpc(&empty, true),
            json!({ "client_auth": "RequireAndVerifyClientCert", "client_cas": [] }),
            json!([]),
        ),
    ];
    let expired = "remote error: tls: expired certificate";
    let has_expired = "tls: failed to verify certificate: x509: certificate has expired or is \
                       not yet valid: current time ";
    let usage = "tls: failed to verify certificate: x509: certificate specifies an incompatible \
                 key usage";
    let unknown =
        "tls: failed to verify certificate: x509: certificate signed by unknown authority";
    // Each cell: the client, the error Go's client hears from the crate
    // and from Go, and the start of Go's server's words and of the
    // crate's, and whether the two are the same.
    let cells = [
        (
            "under-expired-ca",
            expired,
            expired,
            has_expired,
            "invalid peer certificate: certificate expired: ",
        ),
        (
            "under-future-ca",
            expired,
            expired,
            has_expired,
            "invalid peer certificate: certificate not valid yet: ",
        ),
        (
            "server-leaf",
            "remote error: tls: unsupported certificate",
            "remote error: tls: bad certificate",
            usage,
            usage,
        ),
        (
            "under-server-ca",
            "remote error: tls: unsupported certificate",
            "remote error: tls: bad certificate",
            usage,
            usage,
        ),
        (
            "server-stranger",
            "remote error: tls: unknown certificate authority",
            "remote error: tls: unknown certificate authority",
            unknown,
            unknown,
        ),
    ];
    let mut compared = 0;
    for (listener, options, go_server, alpn) in &listeners {
        for (version, fields) in versions() {
            for (name, ours_hears, theirs_hears, go_words, our_words) in cells {
                // Over an empty pool every client chains to nothing, and
                // Go's client sends its certificate though no authority is
                // named; over a full pool it sends none whose issuer the
                // CertificateRequest does not name, so the stranger is
                // presented to the empty pool alone.
                let empty_pool = listener.contains("empty");
                let presented = if empty_pool {
                    name == "server-stranger" || name == "server-leaf"
                } else {
                    name != "server-stranger"
                };
                if !presented {
                    continue;
                }
                let what = format!("{listener}, {version}, {name}");
                let mut fields = fields.clone();
                fields["client_cert"] = pki[name].identity(&[]);
                fields["next_protos"] = alpn.clone();
                let outcome = cell(&mut go, server, options, go_server, &fields);
                let (ours_hears, theirs_hears, go_words, our_words) = if empty_pool {
                    (
                        "remote error: tls: unknown certificate authority",
                        "remote error: tls: unknown certificate authority",
                        unknown,
                        unknown,
                    )
                } else {
                    (ours_hears, theirs_hears, go_words, our_words)
                };
                // The alerts are compared under any Go, which sends them
                // as the reference does.
                assert_hears(
                    &go,
                    &format!("{what}: the crate"),
                    &outcome.ours,
                    ours_hears,
                );
                assert_hears(&go, &format!("{what}: Go"), &outcome.theirs, theirs_hears);
                let text = outcome.ours_error.clone().unwrap_or_default();
                assert!(
                    text.starts_with(our_words),
                    "{what}: the crate's words {text}"
                );
                assert_eq!(outcome.served["ok"], false, "{what}: Go's server");
                if go.go_version() == REFERENCE_GO {
                    let served = outcome.served["error"].as_str().unwrap_or_default();
                    assert!(served.starts_with(go_words), "{what}: Go's words {served}");
                }
                compared += 1;
            }
        }
    }
    go.report("authorities_and_usages_gos_search_refuses_are_refused_as_go_does");
    assert_eq!(
        compared,
        2 * 2 * 4 + 2 * 2,
        "every cell on each listener in two versions"
    );
}

/// Go's client held to TLS 1.0 and 1.1, and to TLS 1.0 alone, against each
/// of dcrwallet's listeners on each `--tlscurve`'s key: refused by both
/// servers first of all, with `protocol_version` and Go's text naming the
/// versions it read (`readClientHello`,
/// `crypto/tls/handshake_server.go:178-194`).  Such a client sends no
/// signature_algorithms, which rustls refuses a ClientHello for before it
/// looks at the versions, so the crate refuses it ahead of rustls
/// (`HelloFacts::go_version_refusal`).
#[test]
fn a_tls10_or_tls11_client_is_refused_as_go_does() {
    let Some(mut go) = TlsOracle::start_dcrwallet() else {
        return;
    };
    let curves = ["Ed25519", "P-256", "P-384", "P-521"];
    let mut specs: Vec<Value> = curves
        .iter()
        .map(|curve| spec(&format!("server-{curve}"), curve, None, "server"))
        .collect();
    specs.extend(issued_specs("wallet", "Ed25519"));
    let pki = go.pki(&specs);
    let (ca, client) = (&pki["wallet-ca"], &pki["wallet-client"]);
    let mut pool = ClientCaPool::new();
    assert!(pool.add_cert(ca.cert.clone()));
    let verifier = Arc::new(GoClientCertVerifier::new(pool).expect("the verifier"));
    let listeners = [
        (
            "gRPC",
            GoServerOptions::dcrwallet_grpc(&verifier),
            json!({ "client_auth": "RequireAndVerifyClientCert",
                    "client_cas": [hex(&ca.cert)], "grpc": true }),
            json!(["h2"]),
        ),
        (
            "JSON-RPC, basic",
            GoServerOptions::dcrwallet_jsonrpc(&verifier, false),
            json!({ "client_cas": [hex(&ca.cert)] }),
            json!([]),
        ),
        (
            "JSON-RPC, clientcert",
            GoServerOptions::dcrwallet_jsonrpc(&verifier, true),
            json!({ "client_auth": "RequireAndVerifyClientCert",
                    "client_cas": [hex(&ca.cert)] }),
            json!([]),
        ),
    ];
    let clients = [
        (
            "TLS 1.0 and 1.1",
            json!({ "min_version": "TLS 1.0", "max_version": "TLS 1.1" }),
            "[302 301]",
        ),
        (
            "TLS 1.0",
            json!({ "min_version": "TLS 1.0", "max_version": "TLS 1.0" }),
            "[301]",
        ),
    ];
    for curve in curves {
        let server = &pki[&format!("server-{curve}")];
        for (listener, options, go_server, alpn) in &listeners {
            for (version, fields, versions) in &clients {
                let what = format!("{curve}, {listener}, {version}");
                let mut fields = fields.clone();
                fields["client_cert"] = client.identity(&[]);
                fields["next_protos"] = alpn.clone();
                let outcome = cell(&mut go, server, options, go_server, &fields);
                go.assert_refused(
                    &what,
                    &outcome.ours,
                    "remote error: tls: protocol version not supported",
                );
                assert_eq!(
                    outcome.ours_error,
                    Some(format!(
                        "tls: client offered only unsupported versions: {versions}"
                    )),
                    "{what}"
                );
                assert_agree(&go, &what, &outcome);
            }
        }
    }
    go.report("a_tls10_or_tls11_client_is_refused_as_go_does");
}

/// dcrwallet's gRPC listener with its issued client, by the protocols a
/// client offers: `h2` is negotiated; a client offering none, or
/// `http/1.1` alone, completes its handshake and is then closed, as
/// grpc-go closes it; a client sharing no protocol is refused with
/// `no_application_protocol`, in TLS 1.2 ahead of a suite the server
/// lacks, where Go's `negotiateALPN` falls; and in TLS 1.2 the suites are
/// grpc-go's, Go's ECDHE CBC suites refused and the rest chosen in Go's
/// order, the version, suite and group held to Go's in every cell that
/// completes, with Go's client cut to classical groups.
#[test]
fn the_grpc_listener_negotiates_as_grpc_go_does() {
    let Some(mut go) = TlsOracle::start_dcrwallet() else {
        return;
    };
    let mut specs = vec![spec("server", "Ed25519", None, "server")];
    specs.extend(issued_specs("wallet", "Ed25519"));
    let pki = go.pki(&specs);
    let (server, ca, client) = (&pki["server"], &pki["wallet-ca"], &pki["wallet-client"]);
    let mut pool = ClientCaPool::new();
    assert!(pool.add_cert(ca.cert.clone()));
    let options =
        GoServerOptions::dcrwallet_grpc(&Arc::new(GoClientCertVerifier::new(pool).expect("pool")));
    let go_server = json!({
        "client_auth": "RequireAndVerifyClientCert", "client_cas": [hex(&ca.cert)], "grpc": true,
    });
    let classical = json!(["X25519", "CurveP256", "CurveP384", "CurveP521"]);
    let cbc = json!([
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
    ]);
    // Each profile: its name, the fields beside the version's, whether the
    // two servers keep the connection, and whether it is closed after a
    // completed handshake.
    let profiles = [
        ("h2", json!({ "next_protos": ["h2"] }), true, false),
        (
            "h2 after another",
            json!({ "next_protos": ["spdy/3", "h2"] }),
            true,
            false,
        ),
        ("no ALPN", json!({}), false, true),
        (
            "http/1.1 alone",
            json!({ "next_protos": ["http/1.1"] }),
            false,
            true,
        ),
        (
            "no protocol in common",
            json!({ "next_protos": ["spdy/3", "h3"] }),
            false,
            false,
        ),
    ];
    for (version, version_fields) in versions() {
        for (name, extra, kept, closed) in &profiles {
            let what = format!("{version}, {name}");
            let mut fields = version_fields.clone();
            for (key, value) in extra.as_object().expect("fields") {
                fields[key] = value.clone();
            }
            fields["client_cert"] = client.identity(&[]);
            fields["curve_preferences"] = classical.clone();
            let outcome = cell(&mut go, server, &options, &go_server, &fields);
            assert_eq!(outcome.ours["ok"], *kept, "{what}: {}", outcome.ours);
            assert_eq!(
                outcome.ours_error.as_deref() == Some(GRPC_MISSING_ALPN),
                *closed,
                "{what}: {:?}",
                outcome.ours_error
            );
            assert_agree(&go, &what, &outcome);
            assert_eq!(
                Negotiated::of_go(&outcome.ours),
                Negotiated::of_go(&outcome.theirs),
                "{what}: what was negotiated"
            );
        }
    }
    // TLS 1.2 suites: the CBC pair alone, refused by both, with ALPN as a
    // gRPC client sends it, and with no protocol in common, which Go
    // refuses first; and the AEAD suites in an order of the client's that
    // Go's server overrides.
    let tls12 = |suites: &Value, alpn: Value| {
        json!({ "max_version": "TLS 1.2", "cipher_suites": suites, "next_protos": alpn,
                "curve_preferences": classical })
    };
    let aead = json!([
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
    ]);
    for (what, mut fields, kept, words) in [
        (
            "the CBC suites",
            tls12(&cbc, json!(["h2"])),
            false,
            "tls: no cipher suite supported by both client and server; client offered: [c009 c00a]",
        ),
        (
            "the CBC suites, no protocol in common",
            tls12(&cbc, json!(["spdy/3"])),
            false,
            "tls: client requested unsupported application protocols ([\"spdy/3\"])",
        ),
        ("the AEAD suites", tls12(&aead, json!(["h2"])), true, ""),
    ] {
        fields["client_cert"] = client.identity(&[]);
        let outcome = cell(&mut go, server, &options, &go_server, &fields);
        assert_eq!(outcome.ours["ok"], kept, "{what}: {}", outcome.ours);
        if !kept {
            assert_eq!(outcome.ours_error.as_deref(), Some(words), "{what}");
        }
        assert_agree(&go, what, &outcome);
        assert_eq!(
            Negotiated::of_go(&outcome.ours),
            Negotiated::of_go(&outcome.theirs),
            "{what}: what was negotiated"
        );
    }
    go.report("the_grpc_listener_negotiates_as_grpc_go_does");
}

/// `bytes` behind a one-byte length.
fn len8(bytes: &[u8]) -> Vec<u8> {
    [&[u8::try_from(bytes.len()).expect("short")][..], bytes].concat()
}

/// `bytes` behind a two-byte length.
fn len16(bytes: &[u8]) -> Vec<u8> {
    let len = u16::try_from(bytes.len()).expect("short").to_be_bytes();
    [&len[..], bytes].concat()
}

/// A ClientHello extension.
fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
    [&kind.to_be_bytes()[..], &len16(data)].concat()
}

/// A record of `content_type` in `version` around `body`.
fn record(content_type: u8, version: u16, body: &[u8]) -> Vec<u8> {
    [&[content_type][..], &version.to_be_bytes(), &len16(body)].concat()
}

/// What a hand-written ClientHello holds besides its suites, groups and
/// signature algorithms ([`client_hello`]).
#[derive(Clone, Copy)]
struct HelloFields<'a> {
    /// `random`, every byte this one.
    random: u8,
    /// supported_versions, when sent.
    versions: Option<&'a [u16]>,
    /// The groups of the key shares, when key_share is sent, each share
    /// 32 bytes of 9s.
    shares: Option<&'a [u16]>,
    /// The ALPN protocols, when the extension is sent.
    alpn: &'a [&'a [u8]],
    /// Whether early_data is sent.
    early_data: bool,
}

/// A ClientHello record in `record_version`, written by hand so that a
/// second one can change what Go compares: X25519 alone among the groups,
/// a TLS 1.3 suite and Go's six TLS 1.2 ECDHE AEAD suites, the Ed25519,
/// ECDSA P-256 and RSA-PSS schemes, uncompressed points, and `fields`.
fn client_hello(fields: &HelloFields<'_>, record_version: u16) -> Vec<u8> {
    let mut extensions = vec![
        extension(0, &len16(&[&[0][..], &len16(b"localhost")].concat())),
        extension(10, &len16(&[0x00, 0x1d])),
        extension(11, &len8(&[0])),
        extension(13, &len16(&[0x08, 0x07, 0x04, 0x03, 0x08, 0x04])),
    ];
    if let Some(versions) = fields.versions {
        let list: Vec<u8> = versions.iter().flat_map(|v| v.to_be_bytes()).collect();
        extensions.push(extension(43, &len8(&list)));
    }
    if let Some(shares) = fields.shares {
        let list: Vec<u8> = shares
            .iter()
            .flat_map(|group| [&group.to_be_bytes()[..], &len16(&[9; 32])].concat())
            .collect();
        extensions.push(extension(51, &len16(&list)));
    }
    if !fields.alpn.is_empty() {
        let names: Vec<u8> = fields.alpn.iter().flat_map(|name| len8(name)).collect();
        extensions.push(extension(16, &len16(&names)));
    }
    if fields.early_data {
        extensions.push(extension(42, &[]));
    }
    let suites = [
        0x13, 0x01, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8,
    ];
    let body = [
        &[0x03, 0x03][..],
        &[fields.random; 32],
        &len8(&[]),
        &len16(&suites),
        &len8(&[0]),
        &len16(&extensions.concat()),
    ]
    .concat();
    let len = u32::try_from(body.len()).expect("short").to_be_bytes();
    record(22, record_version, &[&[1][..], &len[1..], &body].concat())
}

/// The records a server sends, read until `done` says they are enough,
/// the server closes, or three seconds pass: each named, ChangeCipherSpec
/// records left out, since both servers send one after a
/// HelloRetryRequest, Go's in a write of its own and rustls's in the
/// HelloRetryRequest's, so that it arrives in a different read.  A handshake
/// record is named by its first message, `HelloRetryRequest` or
/// `ServerHello`, and `ServerHelloDone` when it holds one; an alert by
/// its bytes.
#[allow(clippy::arithmetic_side_effects)]
fn records_until(sock: &mut std::net::TcpStream, done: impl Fn(&[String]) -> bool) -> Vec<String> {
    const HRR_RANDOM_HEAD: [u8; 4] = [0xcf, 0x21, 0xad, 0x74];
    sock.set_read_timeout(Some(Duration::from_secs(3)))
        .expect("a timeout");
    let mut seen: Vec<String> = Vec::new();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        while buf.len() >= 5 {
            let len = usize::from(u16::from_be_bytes([buf[3], buf[4]]));
            if buf.len() < 5 + len {
                break;
            }
            let body: Vec<u8> = buf[5..5 + len].to_vec();
            match buf[0] {
                20 => {}
                21 => seen.push(format!("alert {body:?}")),
                22 if body.first() == Some(&2) && body.len() >= 10 => {
                    seen.push(if body[6..10] == HRR_RANDOM_HEAD {
                        "HelloRetryRequest".to_string()
                    } else {
                        "ServerHello".to_string()
                    });
                }
                22 => {}
                other => seen.push(format!("record type {other}")),
            }
            // A TLS 1.2 server's flight ends with ServerHelloDone, a
            // four-byte message at the end of its handshake records.
            if buf[0] == 22 && body.ends_with(&[14, 0, 0, 0]) {
                seen.push("ServerHelloDone".to_string());
            }
            buf.drain(..5 + len);
        }
        if done(&seen) {
            return seen;
        }
        match sock.read(&mut chunk) {
            Ok(0) | Err(_) => {
                seen.push("closed".to_string());
                return seen;
            }
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// Whether `seen` holds what answers a ClientHello: an alert, a
/// ServerHello, or a TLS 1.2 server's whole first flight.
fn answered(seen: &[String]) -> bool {
    seen.iter().any(|record| {
        record.starts_with("alert") || record == "ServerHello" || record == "ServerHelloDone"
    })
}

/// Go's alert and text for a refusal, or none for a ServerHello.
type Refusal<'a> = Option<(u8, &'a str)>;

/// One exchange of [`a_client_breaking_the_protocol_after_its_hello_is_refused_as_go_does`].
type Case<'a> = (String, Vec<u8>, Vec<u8>, bool, Refusal<'a>);

/// A client that breaks the protocol after its first ClientHello, against
/// the crate's server and Go's, each configured as one of dcrwallet's
/// listeners, under dcrwallet's `GODEBUG`: after a HelloRetryRequest
/// (forced by a TLS 1.3 ClientHello offering X25519 alone without a key
/// share for it), a second ClientHello that changes a field Go compares,
/// its random or its ALPN, that sends no key share, two, or one for
/// another group, that offers early data, or that comes in a TLS 1.0
/// record or behind a ChangeCipherSpec in one; and, in TLS 1.2, a record
/// in TLS 1.0's version after the server's first flight.  Each is refused
/// by both with Go's alert in a TLS 1.2 record, and the crate's handshake
/// error is Go's text, which Go's server is held to under the reference
/// Go; an unchanged second ClientHello is answered with a ServerHello by
/// both.  The node's listener runs the same handshake.
#[test]
fn a_client_breaking_the_protocol_after_its_hello_is_refused_as_go_does() {
    let Some(mut go) = TlsOracle::start_dcrwallet() else {
        return;
    };
    let mut specs = vec![spec("server", "Ed25519", None, "server")];
    specs.extend(issued_specs("wallet", "Ed25519"));
    let pki = go.pki(&specs);
    let (server, ca) = (&pki["server"], &pki["wallet-ca"]);
    let mut pool = ClientCaPool::new();
    assert!(pool.add_cert(ca.cert.clone()));
    let verifier = Arc::new(GoClientCertVerifier::new(pool).expect("the verifier"));
    let key_pair = KeyPair::from_pem(&server.cert_pem, &server.key_pem).expect("the pair");
    let listeners = [
        (
            "gRPC",
            GoServerOptions::dcrwallet_grpc(&verifier),
            json!({ "client_auth": "RequireAndVerifyClientCert",
                    "client_cas": [hex(&ca.cert)], "grpc": true }),
        ),
        (
            "JSON-RPC, basic",
            GoServerOptions::dcrwallet_jsonrpc(&verifier, false),
            json!({ "client_cas": [hex(&ca.cert)] }),
        ),
    ];
    let first = HelloFields {
        random: 1,
        versions: Some(&[0x0304, 0x0303]),
        shares: Some(&[]),
        alpn: &[b"h2"],
        early_data: false,
    };
    let unchanged = HelloFields {
        shares: Some(&[0x001d]),
        ..first
    };
    let ccs = record(20, 0x0303, &[1]);
    let modified = "tls: client illegally modified second ClientHello";
    let tls10_record = "tls: received record with version 301 when expecting version 303";
    let alert = |code: u8| format!("alert {:?}", [2u8, code]);
    // Each row: what it is, the bytes after the HelloRetryRequest, and
    // Go's alert and text, or none for a ServerHello.
    let rows: Vec<(&str, Vec<u8>, Refusal<'_>)> = vec![
        (
            "unchanged",
            [ccs.clone(), client_hello(&unchanged, 0x0303)].concat(),
            None,
        ),
        (
            "ALPN changed",
            client_hello(
                &HelloFields {
                    alpn: &[b"h2", b"spdy/3"],
                    ..unchanged
                },
                0x0303,
            ),
            Some((47, modified)),
        ),
        (
            "random changed",
            client_hello(
                &HelloFields {
                    random: 2,
                    ..unchanged
                },
                0x0303,
            ),
            Some((47, modified)),
        ),
        (
            "no key share",
            client_hello(&first, 0x0303),
            Some((
                47,
                "tls: client didn't send one key share in second ClientHello",
            )),
        ),
        (
            "two key shares",
            client_hello(
                &HelloFields {
                    shares: Some(&[0x001d, 0x001d]),
                    ..unchanged
                },
                0x0303,
            ),
            Some((
                47,
                "tls: client didn't send one key share in second ClientHello",
            )),
        ),
        (
            "a P-256 key share",
            client_hello(
                &HelloFields {
                    shares: Some(&[0x0017]),
                    ..unchanged
                },
                0x0303,
            ),
            Some((
                47,
                "tls: client sent unexpected key share in second ClientHello",
            )),
        ),
        (
            "early data",
            client_hello(
                &HelloFields {
                    early_data: true,
                    ..unchanged
                },
                0x0303,
            ),
            Some((47, "tls: client indicated early data in second ClientHello")),
        ),
        (
            "in a TLS 1.0 record",
            client_hello(&unchanged, 0x0301),
            Some((70, tls10_record)),
        ),
        (
            "behind a ChangeCipherSpec in a TLS 1.0 record",
            [record(20, 0x0301, &[1]), client_hello(&unchanged, 0x0303)].concat(),
            Some((70, tls10_record)),
        ),
    ];
    // One exchange: the first ClientHello, which both answer with a
    // HelloRetryRequest, then `then`; what the server sent after it.
    let exchange = |addr: &str, opening: &[u8], then: &[u8], wait_for_retry: bool| {
        let mut sock = std::net::TcpStream::connect(addr).expect("connect");
        sock.write_all(opening).expect("the first ClientHello");
        if wait_for_retry {
            let retry = records_until(&mut sock, |seen| !seen.is_empty());
            assert_eq!(retry, ["HelloRetryRequest"], "the first answer");
        } else {
            let flight = records_until(&mut sock, |seen| {
                seen.iter()
                    .any(|record| record == "ServerHelloDone" || record.starts_with("alert"))
            });
            assert!(
                flight.iter().any(|record| record == "ServerHelloDone"),
                "the TLS 1.2 flight: {flight:?}"
            );
        }
        sock.write_all(then).expect("the next records");
        records_until(&mut sock, answered)
    };
    // Each case: what it is, the opening bytes, the bytes after the
    // server's first answer, whether that answer is a HelloRetryRequest,
    // and Go's refusal.
    let mut cases: Vec<Case<'_>> = Vec::new();
    for (what, then, refusal) in rows {
        cases.push((
            format!("second ClientHello {what}"),
            client_hello(&first, 0x0301),
            then,
            true,
            refusal,
        ));
    }
    // TLS 1.2: a ClientKeyExchange-sized record in TLS 1.0's version after
    // the server's flight, refused on its header.
    let tls12 = HelloFields {
        versions: None,
        shares: None,
        ..first
    };
    cases.push((
        "TLS 1.2, a record in TLS 1.0's version".to_string(),
        client_hello(&tls12, 0x0301),
        record(22, 0x0301, &[16, 0, 0, 33, 32, 9, 9, 9]),
        false,
        Some((70, tls10_record)),
    ));
    for (listener, options, go_server) in &listeners {
        let configs = Arc::new(GoServerConfigs::new(&key_pair, options).expect("the set"));
        for (what, opening, then, retry, refusal) in &cases {
            let what = format!("{listener}, {what}");
            let (addr, serving) = serve_once(Arc::clone(&configs));
            let ours = exchange(&addr, opening, then, *retry);
            let ours_error = serving.join().expect("the server thread");

            let mut go_fields = go_server.clone();
            go_fields["chain"] = json!([hex(&server.cert)]);
            go_fields["key_pkcs8"] = json!(hex(&server.key_pkcs8));
            go_fields["response_body"] = json!("ok");
            go_fields["min_version"] = json!("TLS 1.2");
            let (addr, id) = go.listen(go_fields);
            let theirs = exchange(&addr, opening, then, *retry);
            let served = go.served(&id);

            assert_eq!(
                ours.first(),
                theirs.first(),
                "{what}: ours {ours:?}, Go's {theirs:?}"
            );
            match refusal {
                Some((code, text)) => {
                    assert_eq!(ours.first(), Some(&alert(*code)), "{what}: {ours:?}");
                    assert_eq!(ours_error.as_deref(), Some(*text), "{what}");
                    go.assert_refused(&what, &served, text);
                }
                None => assert_eq!(
                    ours.first().map(String::as_str),
                    Some("ServerHello"),
                    "{what}"
                ),
            }
        }
    }
    go.report("a_client_breaking_the_protocol_after_its_hello_is_refused_as_go_does");
}
