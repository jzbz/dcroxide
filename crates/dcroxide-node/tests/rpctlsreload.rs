// SPDX-License-Identifier: ISC
//! The RPC server reloads its TLS material when the files change, the
//! way dcrd's `reloadableTLSConfig` does (`server.go:3639-3736`,
//! constructed at `:3796`).
//!
//! dcrd hangs `configFileClient` off `tls.Config.GetConfigForClient`, so
//! the check runs on an arriving connection rather than on a timer. The
//! port has the same hook because it builds a `rustls::ServerConnection`
//! per accepted connection, and `config_for_client` stands where dcrd's
//! callback does.
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
//! `rpclisten.rs`.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use dcroxide_certgen::Curve;
use dcroxide_node::rpcrun::{
    ReloadableTlsConfig, load_or_generate_cert_pair, reloadable_tls_config,
};
use dcroxide_node::{ConfigEnv, load_config_from_argv};

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
/// asserts on the thing that decides the behaviour.
#[test]
fn stateful_resumption_is_disabled() {
    let (_dir, reloadable) = reloader(Duration::ZERO);
    let config = reloadable.config_for_client();
    assert!(
        !config.session_storage.can_cache(),
        "a session cache would resume clients dcrd would make handshake again"
    );
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
    assert!(
        !after.session_storage.can_cache(),
        "the rebuilt configuration must not resume statefully either"
    );
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

/// A SEC1 private key rewritten by `edit`, as PEM: the P-521 pair the port
/// generates, its `ECPrivateKey` bytes changed before re-encoding.
fn p521_pair_with_edited_key(edit: impl Fn(&[u8]) -> Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    use rustls::pki_types::pem::PemObject;
    let dir = tempfile::tempdir().expect("temp dir");
    let (cert_pem, key_pem) = load_or_generate_cert_pair(
        &dir.path().join("rpc.cert"),
        &dir.path().join("rpc.key"),
        &[],
        Curve::P521,
    )
    .expect("generate a P-521 pair");
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(&key_pem).expect("parse key");
    let der = key.secret_der();
    // SEQUENCE (long form, one length byte), INTEGER 1, OCTET STRING of 66.
    assert_eq!(&der[..2], &[0x30, 0x81], "a long-form SEQUENCE");
    assert_eq!(
        &der[3..8],
        &[0x02, 0x01, 0x01, 0x04, 0x42],
        "version 1, a 66-byte scalar"
    );
    let edited = edit(der);
    let b64 = dcroxide_rpc::http::base64_std_encode(&edited);
    let mut pem = String::from("-----BEGIN EC PRIVATE KEY-----\n");
    for line in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END EC PRIVATE KEY-----\n");
    (cert_pem, pem.into_bytes())
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

/// And P-256, the default, is unaffected.
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
