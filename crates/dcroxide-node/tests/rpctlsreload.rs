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
//! The curve stays P-256 throughout: P-521 pairs are generated fine but
//! cannot be loaded by the RPC TLS setup at all, which is a separate
//! defect and not this file's subject.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use dcroxide_certgen::Curve;
use dcroxide_node::rpcrun::{
    ReloadableTlsConfig, load_or_generate_cert_pair, reloadable_tls_config,
};

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

/// Resumption state survives a certificate rotation, because dcrd's
/// does. Go resolves ticket keys with
/// `originalConfig.ticketKeys(configForClient)`
/// (`handshake_server.go:177`) and falls through to the long-lived
/// outer config when the reloaded one sets none -- which dcrd's never
/// does -- so a client resuming across a rotation is not forced into a
/// full handshake upstream, and must not be here.
#[test]
fn a_rotation_carries_the_resumption_state_over() {
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
        Arc::ptr_eq(&before.session_storage, &after.session_storage),
        "a rotated certificate must not throw away resumption state"
    );
    assert!(
        Arc::ptr_eq(&before.ticketer, &after.ticketer),
        "nor the ticketer"
    );
}

/// But a changed client CA bundle drops it, which is the one place
/// keeping it would be weaker than dcrd. Go re-verifies a resumed
/// session's stored client chain against the reloaded roots and
/// declines to resume when it no longer chains
/// (`handshake_server_tls13.go:373-381`); rustls restores
/// `peer_certificates` with no verifier call (`server/tls12.rs:289`),
/// so a cache that outlived its issuer would keep admitting a revoked
/// client.
#[test]
fn a_changed_client_ca_bundle_drops_the_resumption_state() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cert = dir.path().join("rpc.cert");
    let key = dir.path().join("rpc.key");
    let cas = dir.path().join("clients.pem");
    write_pair(&cert, &key, 0);

    // A bundle holding one self-signed authority, then two.
    let ca_one = dir.path().join("ca1.cert");
    let ca_one_key = dir.path().join("ca1.key");
    write_pair(&ca_one, &ca_one_key, 0);
    let first = std::fs::read(&ca_one).expect("read ca1");
    std::fs::write(&cas, &first).expect("write bundle");

    let reloadable = reloadable_tls_config(&cert, &key, Some(&cas), Duration::ZERO)
        .expect("build with a client CA bundle");
    let before = reloadable.config_for_client();

    let ca_two = dir.path().join("ca2.cert");
    let ca_two_key = dir.path().join("ca2.key");
    write_pair(&ca_two, &ca_two_key, 0);
    let mut both = first.clone();
    both.extend_from_slice(&std::fs::read(&ca_two).expect("read ca2"));
    std::fs::write(&cas, &both).expect("rewrite bundle");

    let after = reloadable.config_for_client();
    assert!(
        !Arc::ptr_eq(&before, &after),
        "the bundle change must actually have reloaded"
    );
    assert!(
        !Arc::ptr_eq(&before.session_storage, &after.session_storage),
        "a changed trust bundle must not leave sessions resumable on the old roots"
    );
}
