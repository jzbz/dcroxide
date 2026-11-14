// SPDX-License-Identifier: ISC
//! The RPC server reloads its TLS material when the files change, the
//! way dcrd's `reloadableTLSConfig` does (`server.go:3639-3736`,
//! constructed at `:3796`).
//!
//! dcrd hangs `configFileClient` off `tls.Config.GetConfigForClient`, so
//! the check runs on an arriving connection rather than on a timer. The
//! port has the same hook: its handshake reads the ClientHello before it
//! chooses a configuration, and `config_for_client` stands there, where
//! Go calls dcrd's callback.
//!
//! Every rotation below changes the SIZE of both files, by generating a
//! genuinely different pair and then padding each with trailing
//! newlines. That is not decoration. `watchedFile.updated` compares size
//! OR mtime, and two writes on a fast filesystem can land in the same
//! mtime tick, so driving the size is what makes these tests
//! deterministic rather than dependent on timestamp granularity. PEM
//! parsers ignore trailing whitespace, so the padded files stay valid.
//!
//! The curve stays P-256 throughout. A P-521 pair builds the same
//! configuration (pinned below), and serving one is pinned end to end in
//! `rpclisten.rs`.  The key file is read as Go's `tls.X509KeyPair` reads
//! it, which the key cases below hold to Go's own reading through the
//! oracle when it is present, an RSA key, refused (ADR-0015, T6), among
//! them.  That a rotation to an RSA key fails with the same words is
//! pinned beside the reloader, in `rpcrun.rs`'s tests, which can read the
//! reload's error.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use dcroxide_certgen::Curve;
use dcroxide_node::rpcrun::{
    RSA_RPC_KEY_REFUSED, ReloadableTlsConfig, load_or_generate_cert_pair, reloadable_tls_config,
};
use dcroxide_node::{ConfigEnv, load_config_from_argv};
use dcroxide_testutil::REFERENCE_GO;
use dcroxide_testutil::tls_interop::{TlsOracle, spec};
use serde_json::json;

/// Write a fresh self-signed pair at the two paths, replacing whatever
/// is there, and pad both files with `pad` trailing newlines so their
/// sizes differ from any previous generation. PEM ignores the padding;
/// the watcher does not.
fn write_pair(cert: &Path, key: &Path, pad: usize) {
    let _ = std::fs::remove_file(cert);
    let _ = std::fs::remove_file(key);
    load_or_generate_cert_pair(cert, key, &[], Curve::P256).expect("generate a cert pair");
    for path in [cert, key] {
        let mut bytes = std::fs::read(path).expect("read the generated file");
        bytes.extend(std::iter::repeat_n(b'\n', pad));
        std::fs::write(path, &bytes).expect("pad the generated file");
    }
}

/// A reloader over a fresh P-256 pair in a temporary directory, with no
/// rate limit so each call checks the files.
fn reloader(delay: Duration) -> (tempfile::TempDir, Arc<ReloadableTlsConfig>) {
    let dir = tempfile::tempdir().expect("temp dir");
    let cert = dir.path().join("rpc.cert");
    let key = dir.path().join("rpc.key");
    write_pair(&cert, &key, 0);
    let reloadable =
        reloadable_tls_config(&cert, &key, None, delay).expect("build the reloadable config");
    (dir, reloadable)
}

/// A rotated certificate is served without a restart -- the gap this
/// closes. Also pins dcrd's short-circuit in `needsReload`, which is a
/// wart rather than an accident: `c.cert.updated() || c.key.updated() ||
/// c.clientCAs.updated()` stops at the first true, so rotating a cert
/// and key together leaves the key's remembered details stale and
/// reloads a second time on the next check.
#[test]
fn a_rotated_pair_reloads_twice_because_the_check_short_circuits() {
    let (dir, reloadable) = reloader(Duration::ZERO);
    let cert = dir.path().join("rpc.cert");
    let key = dir.path().join("rpc.key");

    // Nothing has changed since construction primed the details.
    let first = reloadable.config_for_client();
    let again = reloadable.config_for_client();
    assert!(
        Arc::ptr_eq(&first, &again),
        "an unchanged pair must not rebuild the configuration"
    );

    write_pair(&cert, &key, 7);

    // The certificate is noticed, and the key is never stat'd on this
    // pass because `||` short-circuited.
    let after_cert = reloadable.config_for_client();
    assert!(
        !Arc::ptr_eq(&first, &after_cert),
        "a rotated certificate must be reloaded"
    );

    // So the key reports changed on the NEXT check, against details
    // that were primed before the rotation, and the same material is
    // loaded a second time. dcrd does exactly this.
    let after_key = reloadable.config_for_client();
    assert!(
        !Arc::ptr_eq(&after_cert, &after_key),
        "the stale key details must force dcrd's second reload"
    );

    // And then it settles: all three are current, so nothing reloads.
    let settled = reloadable.config_for_client();
    assert!(
        Arc::ptr_eq(&after_key, &settled),
        "once every watched file is current the config stops rebuilding"
    );
}

/// dcrd checks at most once every `minReloadCheckDelay`
/// (`server.go:3665-3668`), and starts the clock a full delay out
/// (`:3806`), so a rotation inside that window is not seen yet.
#[test]
fn a_rotation_inside_the_check_interval_is_not_seen_yet() {
    let (dir, reloadable) = reloader(Duration::from_secs(3600));
    let cert = dir.path().join("rpc.cert");
    let key = dir.path().join("rpc.key");

    let before = reloadable.config_for_client();
    write_pair(&cert, &key, 7);
    let after = reloadable.config_for_client();
    assert!(
        Arc::ptr_eq(&before, &after),
        "the rate limit must hold the old configuration until the delay elapses"
    );
}

/// A replacement that will not parse leaves the working configuration
/// in place (dcrd `configFileClient`, which only assigns `cachedConfig`
/// on success). Replacing the files with malformed data must not take
/// the RPC server down.
#[test]
fn a_broken_replacement_preserves_the_working_configuration() {
    let (dir, reloadable) = reloader(Duration::ZERO);
    let cert = dir.path().join("rpc.cert");
    let key = dir.path().join("rpc.key");

    let before = reloadable.config_for_client();
    std::fs::write(&cert, b"-----BEGIN CERTIFICATE-----\nnot a certificate\n").expect("write");

    let after = reloadable.config_for_client();
    assert!(
        Arc::ptr_eq(&before, &after),
        "a malformed certificate must not replace the working configuration"
    );

    // And the server keeps serving: repeated connections keep getting
    // the last good configuration rather than failing.
    let later = reloadable.config_for_client();
    assert!(
        Arc::ptr_eq(&before, &later),
        "the working configuration survives repeated failed reloads"
    );

    // Recovery matters as much as preservation: a failed reload must
    // not leave the watcher unable to notice the fix. dcrd keeps
    // checking on the same schedule and clears `prevAttemptErr` on the
    // next success (`server.go:3731`).
    write_pair(&cert, &key, 11);
    let fixed = reloadable.config_for_client();
    assert!(
        !Arc::ptr_eq(&before, &fixed),
        "a repaired certificate must be picked up after a failed reload"
    );
}

/// A deleted certificate is the same story, and dcrd's `updated`
/// deliberately does not refresh its remembered details for a missing
/// file, so it keeps reporting changed rather than latching. The
/// observable consequence is that restoring the file is picked up.
#[test]
fn a_deleted_certificate_preserves_the_config_and_recovers() {
    let (dir, reloadable) = reloader(Duration::ZERO);
    let cert = dir.path().join("rpc.cert");
    let key = dir.path().join("rpc.key");

    let before = reloadable.config_for_client();
    std::fs::remove_file(&cert).expect("delete the certificate");

    let gone = reloadable.config_for_client();
    assert!(
        Arc::ptr_eq(&before, &gone),
        "a deleted certificate must not take down the working configuration"
    );

    // Restoring a valid pair is noticed, which it would not be if the
    // deleted file had latched its details as unchanged.
    write_pair(&cert, &key, 7);
    let restored = reloadable.config_for_client();
    assert!(
        !Arc::ptr_eq(&before, &restored),
        "a restored certificate must be reloaded"
    );
}

/// The port does not resume statefully, because Go's server does not.
/// Go's TLS1.2 `checkForResumption` reads only `clientHello.sessionTicket`
/// (`crypto/tls/handshake_server.go:450-465`) and merely echoes the
/// session id (`:565`), while rustls would look that id up in
/// `session_storage` and restore the stored client certificate chain
/// without re-verifying it or checking its expiry
/// (`server/tls12.rs:146-160`, `:289`, `server/hs.rs:39-58`).
///
/// `can_cache` is the switch rustls itself consults before offering a
/// session id at all (`server/tls12.rs:177-178`), so asserting on it
/// asserts on the thing that decides the behaviour.  It holds for every
/// configuration in the set, whichever one a ClientHello is served by.
#[test]
fn stateful_resumption_is_disabled() {
    let (_dir, reloadable) = reloader(Duration::ZERO);
    let configs = reloadable.config_for_client();
    assert_eq!(
        configs.configs().count(),
        10,
        "two suite orders, five key exchange sets"
    );
    for config in configs.configs() {
        assert!(
            !config.session_storage.can_cache(),
            "a session cache would resume clients dcrd would make handshake again"
        );
    }
}

/// And a reload does not quietly restore it: every rebuilt configuration
/// goes through the same builder, so the property holds for the life of
/// the process rather than only at startup.
#[test]
fn a_reload_does_not_restore_stateful_resumption() {
    let (dir, reloadable) = reloader(Duration::ZERO);
    let cert = dir.path().join("rpc.cert");
    let key = dir.path().join("rpc.key");

    let before = reloadable.config_for_client();
    write_pair(&cert, &key, 5);
    let after = reloadable.config_for_client();
    assert!(
        !Arc::ptr_eq(&before, &after),
        "the rotation must actually have reloaded, or this proves nothing"
    );
    for config in after.configs() {
        assert!(
            !config.session_storage.can_cache(),
            "the rebuilt configuration must not resume statefully either"
        );
    }
}

/// dcrd accepts `--tlscurve=P-521` and serves TLS with the resulting
/// certificate, and so does the port. The pair builds a configuration,
/// and so does the reloader, which shares the builder. The key is SEC1
/// PEM, the form dcrd's `certgen` writes.
#[test]
fn a_p521_pair_builds_a_configuration() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cert = dir.path().join("rpc.cert");
    let key = dir.path().join("rpc.key");
    let (cert_pem, key_pem) =
        load_or_generate_cert_pair(&cert, &key, &[], Curve::P521).expect("generate a P-521 pair");
    assert!(
        key_pem.starts_with(b"-----BEGIN EC PRIVATE KEY-----"),
        "the key is SEC1 PEM"
    );

    dcroxide_node::rpcrun::tls_server_config(&cert_pem, &key_pem, None)
        .expect("a P-521 pair builds a configuration");
    if let Err(err) = reloadable_tls_config(&cert, &key, None, Duration::ZERO) {
        panic!("and so does the reloader: {err}");
    }
}

/// The hand-built P-521 path keeps the check `with_single_cert` makes for
/// every other key: a key that does not belong to the certificate is
/// refused at startup, rather than serving handshakes no client can verify.
#[test]
fn a_p521_key_for_another_certificate_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (cert_a, _) = load_or_generate_cert_pair(
        &dir.path().join("a.cert"),
        &dir.path().join("a.key"),
        &[],
        Curve::P521,
    )
    .expect("pair a");
    let (_, key_b) = load_or_generate_cert_pair(
        &dir.path().join("b.cert"),
        &dir.path().join("b.key"),
        &[],
        Curve::P521,
    )
    .expect("pair b");
    let err = dcroxide_node::rpcrun::tls_server_config(&cert_a, &key_b, None)
        .expect_err("a key for another certificate must not build");
    assert!(
        err.contains("unable to build the RPC TLS configuration"),
        "got: {err}"
    );
}

/// The pair the port generates on `curve`: the certificate's PEM, and the
/// DER of the SEC 1 key it writes under `EC PRIVATE KEY`.
fn generated_pair(curve: Curve) -> (Vec<u8>, Vec<u8>) {
    use rustls::pki_types::pem::PemObject;
    let dir = tempfile::tempdir().expect("temp dir");
    let (cert_pem, key_pem) = load_or_generate_cert_pair(
        &dir.path().join("rpc.cert"),
        &dir.path().join("rpc.key"),
        &[],
        curve,
    )
    .expect("generate a pair");
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(&key_pem).expect("parse key");
    (cert_pem, key.secret_der().to_vec())
}

/// `der` as a PEM block of type `label`.
fn pem(label: &str, der: &[u8]) -> Vec<u8> {
    let b64 = dcroxide_rpc::http::base64_std_encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem.into_bytes()
}

/// The pair the port generates on `curve`, its SEC 1 key rewritten by
/// `edit` before it is re-encoded as an `EC PRIVATE KEY` block.
fn pair_with_edited_key(curve: Curve, edit: impl Fn(&[u8]) -> Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let (cert_pem, der) = generated_pair(curve);
    (cert_pem, pem("EC PRIVATE KEY", &edit(&der)))
}

/// A SEC1 private key rewritten by `edit`, as PEM: the P-521 pair the port
/// generates, its `ECPrivateKey` bytes changed before re-encoding.
fn p521_pair_with_edited_key(edit: impl Fn(&[u8]) -> Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    pair_with_edited_key(Curve::P521, |der| {
        // SEQUENCE (long form, one length byte), INTEGER 1, OCTET STRING of 66.
        assert_eq!(&der[..2], &[0x30, 0x81], "a long-form SEQUENCE");
        assert_eq!(
            &der[3..8],
            &[0x02, 0x01, 0x01, 0x04, 0x42],
            "version 1, a 66-byte scalar"
        );
        edit(der)
    })
}

/// Go drops zero padding in front of a private scalar
/// (`crypto/x509/sec1.go:115-122`), so dcrd serves a P-521 key whose scalar
/// is 67 bytes with a leading zero, and so does the port.
#[test]
fn a_zero_padded_p521_key_serves_as_it_does_in_dcrd() {
    let (cert_pem, key_pem) = p521_pair_with_edited_key(|der| {
        let len = der[2]
            .checked_add(1)
            .expect("the key stays under 256 bytes");
        let mut out = vec![0x30, 0x81, len, 0x02, 0x01, 0x01, 0x04, 0x43, 0x00];
        out.extend_from_slice(&der[8..]);
        out
    });
    dcroxide_node::rpcrun::tls_server_config(&cert_pem, &key_pem, None)
        .expect("a zero-padded P-521 scalar serves");
}

/// Go refuses an `ECPrivateKey` whose version is not 1
/// (`crypto/x509/sec1.go:98-100`), so dcrd will not load the pair, and
/// neither does the port.
#[test]
fn a_p521_key_with_an_unknown_version_is_refused_as_in_dcrd() {
    let (cert_pem, key_pem) = p521_pair_with_edited_key(|der| {
        let mut out = der.to_vec();
        out[5] = 0x02;
        out
    });
    let err = dcroxide_node::rpcrun::tls_server_config(&cert_pem, &key_pem, None)
        .expect_err("a version 2 key must not load");
    assert!(
        err.contains("unable to build the RPC TLS configuration"),
        "got: {err}"
    );
}

/// The fields of a SEC 1 key the port generated: the length of its
/// SEQUENCE's header, and where each field starts, every header in the
/// short or the one-byte long form.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "offsets into a key of under 256 bytes the port generated"
)]
fn sec1_fields(der: &[u8]) -> (usize, Vec<usize>) {
    let header = |at: usize| match der[at + 1] {
        0x81 => (3, usize::from(der[at + 2])),
        len => (2, usize::from(len)),
    };
    let mut fields = Vec::new();
    let mut at = header(0).0;
    while at < der.len() {
        fields.push(at);
        let (size, len) = header(at);
        at += size + len;
    }
    (header(0).0, fields)
}

/// A DER element of `tag` holding `content`, under 256 bytes, its length
/// in the short or the one-byte long form.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match u8::try_from(content.len()).expect("a short key") {
        len @ 0..0x80 => out.push(len),
        len => out.extend([0x81, len]),
    }
    out.extend_from_slice(content);
    out
}

/// A SEC 1 key the port generated, without the `[1]` public key that
/// ends it.
fn without_public_key(der: &[u8]) -> Vec<u8> {
    let (start, fields) = sec1_fields(der);
    assert_eq!(fields.len(), 4, "version, scalar, curve and public key");
    let public = fields[3];
    assert_eq!(der[public], 0xa1, "the public key last");
    tlv(0x30, &der[start..public])
}

/// A SEC 1 key the port generated on `curve`, in PKCS#8: version 0, the
/// `id-ecPublicKey` algorithm with the curve's OID, and the key, which
/// names its curve inside too, as Go reads either way.
fn as_pkcs8(curve: Curve, sec1: &[u8]) -> Vec<u8> {
    let named: &[u8] = match curve {
        Curve::P256 => &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        Curve::P521 => &[0x2b, 0x81, 0x04, 0x00, 0x23],
    };
    let ec_public_key = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    let algorithm = tlv(
        0x30,
        &[tlv(0x06, &ec_public_key), tlv(0x06, named)].concat(),
    );
    tlv(
        0x30,
        &[tlv(0x02, &[0]), algorithm, tlv(0x04, sec1)].concat(),
    )
}

/// Hold a pair to Go's `tls.X509KeyPair` through the oracle's
/// `x509_key_pair`, when the oracle is present: `want` is its answer
/// under the reference Go, `ok` and the key's type or `refused: ` and
/// Go's error, compared whole there, and as a verdict alone under another
/// Go or where `want` is `refused: ` alone.
fn assert_go_reads(
    go: Option<&mut TlsOracle>,
    what: &str,
    cert_pem: &[u8],
    key_pem: &[u8],
    want: &str,
) {
    let Some(go) = go else {
        return;
    };
    let answer = go.call(
        "x509_key_pair",
        &json!({
            "cert_pem": String::from_utf8_lossy(cert_pem),
            "key_pem": String::from_utf8_lossy(key_pem),
        }),
    );
    let answer = answer["result"].as_str().expect("x509_key_pair's verdict");
    if go.go_version() == REFERENCE_GO && want != "refused: " {
        assert_eq!(answer, want, "{what}: Go");
    } else {
        assert_eq!(
            answer.starts_with("ok "),
            want.starts_with("ok "),
            "{what}: Go answered {answer}"
        );
    }
}

/// What the oracle's `x509_key_pair` answers for a pair the port generated
/// on `curve`, its key read whole.
fn go_reads_ecdsa(curve: Curve) -> &'static str {
    match curve {
        Curve::P256 => "ok ECDSA P-256",
        Curve::P521 => "ok ECDSA P-521",
    }
}

/// Every key is read by `dcroxide-tlscrypto`'s loader, by Go's
/// `tls.X509KeyPair` rules, so a SEC 1 key without its public key, which
/// Go loads, since it never reads that key (`crypto/x509/sec1.go:87-130`),
/// builds a configuration on either curve, as in dcrd, and Go's own
/// reading agrees through the oracle when it is present.
#[test]
fn a_key_without_its_public_key_builds_on_either_curve() {
    let mut go = TlsOracle::start();
    for curve in [Curve::P521, Curve::P256] {
        let (cert_pem, key_pem) = pair_with_edited_key(curve, without_public_key);
        if let Err(err) = dcroxide_node::rpcrun::tls_server_config(&cert_pem, &key_pem, None) {
            panic!("{curve:?}: {err}");
        }
        let what = format!("{curve:?}");
        let want = go_reads_ecdsa(curve);
        assert_go_reads(go.as_mut(), &what, &cert_pem, &key_pem, want);
    }
}

/// The RPC server takes the key block by Go's rule, the first whose type
/// is `PRIVATE KEY` or ends in ` PRIVATE KEY` (`crypto/tls/tls.go:286-303`),
/// and reads its DER whatever the label, as Go's `parsePrivateKey` does
/// (`:361-379`), so a pair builds with its SEC 1 key under `EC PRIVATE KEY`,
/// `RSA PRIVATE KEY` or a label of its own, and with its PKCS#8 form under
/// `PRIVATE KEY` or a label of its own, on either curve, as in dcrd, and
/// Go's own reading agrees through the oracle when it is present.
#[test]
fn a_key_builds_under_every_label_go_takes() {
    let mut go = TlsOracle::start();
    for curve in [Curve::P521, Curve::P256] {
        let (cert_pem, sec1) = generated_pair(curve);
        let pkcs8 = as_pkcs8(curve, &sec1);
        for (label, der) in [
            ("EC PRIVATE KEY", &sec1),
            ("RSA PRIVATE KEY", &sec1),
            ("TEST PRIVATE KEY", &sec1),
            ("PRIVATE KEY", &pkcs8),
            ("TEST PRIVATE KEY", &pkcs8),
        ] {
            let key_pem = pem(label, der);
            let built = dcroxide_node::rpcrun::tls_server_config(&cert_pem, &key_pem, None);
            if let Err(err) = built {
                panic!("{curve:?} under {label}: {err}");
            }
            let what = format!("{curve:?} under {label}");
            let want = go_reads_ecdsa(curve);
            assert_go_reads(go.as_mut(), &what, &cert_pem, &key_pem, want);
        }
    }
}

/// A DER element of `tag` holding `content`, its length in the fewest
/// bytes.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len().to_be_bytes();
    let digits = &len[len.iter().position(|&b| b != 0).unwrap_or(len.len())..];
    let mut out = vec![tag];
    match digits {
        [] => out.push(0),
        [short] if *short < 0x80 => out.push(*short),
        _ => {
            out.push(0x80 | u8::try_from(digits.len()).expect("at most eight length bytes"));
            out.extend_from_slice(digits);
        }
    }
    out.extend_from_slice(content);
    out
}

/// A DER INTEGER of the unsigned big-endian `value`.
fn der_integer(value: &[u8]) -> Vec<u8> {
    let sign = value.first().is_none_or(|first| first & 0x80 != 0);
    der(0x02, &[if sign { &[0][..] } else { &[] }, value].concat())
}

/// The fields of a SEC 1 key the port generated, each a whole element.
fn sec1_elements(der: &[u8]) -> Vec<&[u8]> {
    let (_, mut bounds) = sec1_fields(der);
    bounds.push(der.len());
    bounds
        .windows(2)
        .map(|field| &der[field[0]..field[1]])
        .collect()
}

/// An RSA private key of the test-key fixture in PKCS#1 (RFC 8017 §A.1.2),
/// version 0 and its five values, followed by `crt`, which stand in the
/// places of the two CRT exponents and the coefficient when given.
fn pkcs1(key: &dcroxide_testutil::RsaTestKey, crt: &[&[u8]]) -> Vec<u8> {
    let values = [&key.n, &key.e, &key.d, &key.p, &key.q];
    let fields: Vec<Vec<u8>> = std::iter::once(der_integer(&[0]))
        .chain(values.iter().map(|value| der_integer(value)))
        .chain(crt.iter().map(|value| der_integer(value)))
        .collect();
    der(0x30, &fields.concat())
}

/// What one key file comes to: the port's verdict and Go's.
struct KeyCase {
    what: &'static str,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    /// The text the port's error ends with, or `None` where the pair
    /// builds.
    refused: Option<&'static str>,
    /// `x509_key_pair`'s answer under the reference Go: `ok` and the key's
    /// type, or `refused: ` and Go's error, or `refused: ` alone where only
    /// the verdict is compared.
    go: &'static str,
}

/// The RPC key is read as Go's `tls.X509KeyPair` reads it, and each case
/// is held to Go's own reading through the oracle's `x509_key_pair` when
/// the oracle is present: Go's words under the reference Go, else its
/// verdict alone.
///
/// - P-256 keys ring refused and Go serves: a scalar with a leading zero
///   byte, which Go strips (`crypto/x509/sec1.go:115-122`); no public key;
///   and another key's public key, which Go never compares with the
///   scalar, with the certificate the scalar's.
/// - An RSA key, which Go serves and the port refuses with T6's text
///   (ADR-0015): PKCS#1 without its CRT values, which Go computes, and in
///   PKCS#8, each for its certificate from `tls_pki` (the oracle's alone);
///   and a PKCS#1 structure with CRT values made up, which Go's `Validate`
///   refuses too, since the port reads the structure alone.
/// - A P-224 key, which Go loads and serves over TLS 1.2 only, and the
///   port refuses at load: against a P-256 certificate, so that Go reads
///   it as an ECDSA key and refuses it only as not the certificate's.
/// - The block by Go's rule: a PKCS#8 key under `TEST PRIVATE KEY` serves;
///   under `TESTPRIVATE KEY`, which runs into `PRIVATE KEY` with no space,
///   it is skipped, refused alone with Go's text and served from a plain
///   block after it; an `ENCRYPTED PRIVATE KEY` block ahead of a plain key
///   is the block read, which does not parse, refused with the PKCS#8
///   parser's error for a first element that is not the version; and a
///   file of a certificate alone, of no PEM, and of other blocks, each
///   with Go's text.
#[test]
fn an_rpc_key_is_read_as_x509_key_pair_reads_it() {
    let (p256_cert, p256_sec1) = generated_pair(Curve::P256);
    let (_, other_sec1) = generated_pair(Curve::P256);
    let fields = sec1_elements(&p256_sec1);
    let other_fields = sec1_elements(&other_sec1);
    assert_eq!(fields.len(), 4, "version, scalar, curve and public key");
    let sec1_of = |fields: &[&[u8]]| pem("EC PRIVATE KEY", &der(0x30, &fields.concat()));
    let padded_scalar = der(0x04, &[&[0][..], &fields[1][2..]].concat());
    let rsa_key = dcroxide_testutil::rsa_test_key("rsa2048");
    // A P-224 scalar of 1, the curve named inside (1.3.132.0.33).
    let p224 = der(
        0x30,
        &[
            der_integer(&[1]),
            der(0x04, &[&[0; 27][..], &[1]].concat()),
            der(0xa0, &der(0x06, &[0x2b, 0x81, 0x04, 0x00, 0x21])),
        ]
        .concat(),
    );
    // An EncryptedPrivateKeyInfo's shape: PBES2's OID and no key.
    let encrypted = der(
        0x30,
        &[
            der(
                0x30,
                &der(
                    0x06,
                    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d],
                ),
            ),
            der(0x04, &[0x55; 16]),
        ]
        .concat(),
    );
    let pkcs8 = pem("PRIVATE KEY", &as_pkcs8(Curve::P256, &p256_sec1));
    let p256_cert_der = {
        use rustls::pki_types::pem::PemObject;
        rustls::pki_types::CertificateDer::from_pem_slice(&p256_cert).expect("the certificate")
    };
    let case = |what, key_pem, refused, go| KeyCase {
        what,
        cert_pem: p256_cert.clone(),
        key_pem,
        refused,
        go,
    };
    let mut cases = vec![
        case(
            "a P-256 scalar with a leading zero byte",
            sec1_of(&[fields[0], &padded_scalar, fields[2], fields[3]]),
            None,
            "ok ECDSA P-256",
        ),
        case(
            "a P-256 key without its public key",
            sec1_of(&fields[..3]),
            None,
            "ok ECDSA P-256",
        ),
        case(
            "a P-256 key with another key's public key",
            sec1_of(&[fields[0], fields[1], fields[2], other_fields[3]]),
            None,
            "ok ECDSA P-256",
        ),
        case(
            "an RSA key, PKCS#1 with CRT values made up",
            pem("RSA PRIVATE KEY", &pkcs1(&rsa_key, &[&[1], &[1], &[1]])),
            Some(RSA_RPC_KEY_REFUSED),
            "refused: ",
        ),
        case(
            "a P-224 key",
            pem("EC PRIVATE KEY", &p224),
            Some("unsupported private key: ECDSA P-224"),
            "refused: tls: private key does not match public key",
        ),
        case(
            "a PKCS#8 key under TEST PRIVATE KEY",
            pem("TEST PRIVATE KEY", &as_pkcs8(Curve::P256, &p256_sec1)),
            None,
            "ok ECDSA P-256",
        ),
        case(
            "a PKCS#8 key under TESTPRIVATE KEY",
            pem("TESTPRIVATE KEY", &as_pkcs8(Curve::P256, &p256_sec1)),
            Some(
                "tls: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input \
                 after skipping PEM blocks of the following types: [TESTPRIVATE KEY]",
            ),
            "refused: tls: failed to find PEM block with type ending in \"PRIVATE KEY\" in key \
             input after skipping PEM blocks of the following types: [TESTPRIVATE KEY]",
        ),
        case(
            "a TESTPRIVATE KEY block ahead of a plain key",
            [
                pem("TESTPRIVATE KEY", &as_pkcs8(Curve::P256, &p256_sec1)),
                pkcs8.clone(),
            ]
            .concat(),
            None,
            "ok ECDSA P-256",
        ),
        case(
            "an ENCRYPTED PRIVATE KEY block ahead of a plain key",
            [pem("ENCRYPTED PRIVATE KEY", &encrypted), pkcs8.clone()].concat(),
            Some(
                "tls: failed to parse private key: asn1: structure error: tags don't match (2 vs \
                 {class:0 tag:16 length:11 isCompound:true}) {optional:false explicit:false \
                 application:false private:false defaultValue:<nil> tag:<nil> stringType:0 \
                 timeType:0 set:false omitEmpty:false} int @2",
            ),
            "refused: tls: failed to parse private key: asn1: structure error: tags don't match \
             (2 vs {class:0 tag:16 length:11 isCompound:true}) {optional:false explicit:false \
             application:false private:false defaultValue:<nil> tag:<nil> stringType:0 \
             timeType:0 set:false omitEmpty:false} int @2",
        ),
        case(
            "a certificate alone",
            pem("CERTIFICATE", &p256_cert_der),
            Some("tls: found a certificate rather than a key in the PEM for the private key"),
            "refused: tls: found a certificate rather than a key in the PEM for the private key",
        ),
        case(
            "no PEM",
            b"not a key\n".to_vec(),
            Some("tls: failed to find any PEM data in key input"),
            "refused: tls: failed to find any PEM data in key input",
        ),
        case(
            "a certificate and parameters",
            [
                pem("CERTIFICATE", &p256_cert_der),
                pem("EC PARAMETERS", &fields[2][2..]),
            ]
            .concat(),
            Some(
                "tls: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input \
                 after skipping PEM blocks of the following types: [CERTIFICATE EC PARAMETERS]",
            ),
            "refused: tls: failed to find PEM block with type ending in \"PRIVATE KEY\" in key \
             input after skipping PEM blocks of the following types: [CERTIFICATE EC PARAMETERS]",
        ),
    ];
    let mut go = TlsOracle::start();
    if let Some(go) = go.as_mut() {
        let rsa = go
            .pki(&[spec("RSA-2048", "rsa2048", None, "server")])
            .remove("RSA-2048")
            .expect("the RSA pair");
        cases.push(KeyCase {
            what: "an RSA key, PKCS#1 without its CRT values, for its certificate",
            cert_pem: rsa.cert_pem.clone(),
            key_pem: pem("RSA PRIVATE KEY", &pkcs1(&rsa_key, &[])),
            refused: Some(RSA_RPC_KEY_REFUSED),
            go: "ok RSA 2048",
        });
        cases.push(KeyCase {
            what: "an RSA key, PKCS#8, for its certificate",
            cert_pem: rsa.cert_pem.clone(),
            key_pem: rsa.key_pem.clone(),
            refused: Some(RSA_RPC_KEY_REFUSED),
            go: "ok RSA 2048",
        });
    }
    for case in &cases {
        let built = dcroxide_node::rpcrun::tls_server_config(&case.cert_pem, &case.key_pem, None);
        match (built, case.refused) {
            (Ok(_), None) => {}
            (Err(err), Some(text)) => assert!(err.ends_with(text), "{}: refused: {err}", case.what),
            (Ok(_), Some(text)) => panic!("{}: built, where {text} was expected", case.what),
            (Err(err), None) => panic!("{}: refused: {err}", case.what),
        }
        assert_go_reads(
            go.as_mut(),
            case.what,
            &case.cert_pem,
            &case.key_pem,
            case.go,
        );
    }
    let expected = if go.is_some() { 14 } else { 12 };
    assert_eq!(cases.len(), expected, "every case ran");
}

/// And P-256, the default, builds.
#[test]
fn a_p256_key_still_builds() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cert = dir.path().join("rpc.cert");
    let key = dir.path().join("rpc.key");
    let (cert_pem, key_pem) =
        load_or_generate_cert_pair(&cert, &key, &[], Curve::P256).expect("generate a P-256 pair");
    dcroxide_node::rpcrun::tls_server_config(&cert_pem, &key_pem, None)
        .expect("a P-256 pair serves");
}

/// `tls_curve` stays a faithful port of dcrd's `tlsCurve`, which knows
/// both curves.
#[test]
fn the_curve_mapping_still_matches_dcrd() {
    assert_eq!(
        dcroxide_node::config::tls_curve("P-521").expect("dcrd's mapping accepts P-521"),
        dcroxide_node::config::TlsCurve::P521,
    );
    assert_eq!(
        dcroxide_node::config::tls_curve("P-256").expect("and P-256"),
        dcroxide_node::config::TlsCurve::P256,
    );
    assert!(dcroxide_node::config::tls_curve("P-384").is_err());
}

/// Loading a configuration with `--tlscurve=P-521` succeeds, as it does in
/// dcrd, whose `loadConfig` accepts every curve `tlsCurve` maps
/// (`config.go:1344`).
#[test]
fn loading_a_p521_configuration_succeeds() {
    let home = tempfile::tempdir().expect("temp home");
    let env = ConfigEnv {
        default_home_dir: home.path().to_string_lossy().into_owned(),
        lookup_localhost: Box::new(|| Ok(vec!["::1".to_string(), "127.0.0.1".to_string()])),
        interface_by_name: Box::new(|_| None),
        getenv: Box::new(|_: &str| None),
        user_home: Box::new(|_| None),
        rand_bytes: Box::new(|b: &mut [u8]| b.fill(0x42)),
    };

    let args = vec!["dcroxide".to_string(), "--tlscurve=P-521".to_string()];
    if let Err(e) = load_config_from_argv(&args, &env) {
        panic!("--tlscurve=P-521 loads in dcrd and must load here: {e}");
    }
}
