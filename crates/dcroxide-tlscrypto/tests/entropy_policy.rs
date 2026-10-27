// SPDX-License-Identifier: ISC
//! Where the TLS provider reads kernel entropy, and where it draws from the
//! process-wide generator instead, each in one place.
//!
//! `dcroxide-node`'s `tests/entropy_policy.rs` accounts for every kernel
//! read in the daemon's own source and leaves its dependencies' draws out
//! of scope.  This crate is the dependency that draws for TLS, so it keeps
//! the same account of itself, in the same style.
//!
//! Every byte the provider draws but one comes from `rand::kernel_fill`:
//! the bytes rustls asks its `SecureRandom` for, and the ephemeral key of
//! each key exchange, which the RPC server draws once per TLS handshake a
//! client steers to P-521 today and, from the switch (ADR-0015), once per
//! TLS handshake the node serves or dials.  A peer paces those draws, and
//! they stay on the kernel deliberately, on two grounds: Go's `crypto/tls`
//! draws the same bytes from its standard-library `crypto/rand`, not from
//! dcrd's package generator, and a failed read returns `GetRandomFailed`,
//! which fails the one handshake rather than aborting the process.  An
//! ephemeral scalar has a third: it is the session's whole secret, and the
//! process generator, which keeps its key for 4 MiB of draws, would let a
//! later read of the process's memory recover it, where the kernel's
//! generator erases its key as it goes.
//!
//! The one that is not the kernel's is the additional data each ECDSA
//! handshake signature mixes into its RFC 6979 nonce, which comes from the
//! process-wide generator of `dcroxide_crypto::rand`, through
//! `rand::ProcessRng`.  RFC 6979 keeps the nonce safe should that draw be
//! weak, so it needs neither the kernel's freshness nor its fallibility,
//! and that generator, seeded at startup, cannot fail after it.  The RPC
//! server makes it once per TLS handshake it signs with a P-521 key today
//! and, from the switch, once per handshake signed with any ECDSA key.
//!
//! The scans match literal text: `getrandom::`, so `use getrandom::fill;`
//! followed by a bare `fill(..)`, or another entropy crate, walks straight
//! past them; and `dcroxide_crypto`, likewise.  The counts of the lines
//! that name `kernel_fill` and `ProcessRng` below are the second line of
//! defence: each source is drawn from where its reason holds and nowhere
//! else, so a key exchange or the `SecureRandom` drawing from the process
//! generator fails here, as does a signature drawing from the kernel.

use std::collections::BTreeMap;
use std::path::Path;

/// How many lines of each source file under `src` contain `needle`, for
/// the files where it appears at all.
fn lines_containing(needle: &str) -> BTreeMap<String, usize> {
    lines_where(|line| line.contains(needle))
}

/// How many lines of each source file under `src` `counts` picks, for the
/// files where it picks one at all.
fn lines_where(counts: impl Fn(&str) -> bool) -> BTreeMap<String, usize> {
    per_file(|text| text.lines().filter(|line| counts(line)).count())
}

/// [`lines_where`] over the lines of each file ahead of its unit tests,
/// the `mod tests` the crate's files end with.
fn code_lines_where(counts: impl Fn(&str) -> bool) -> BTreeMap<String, usize> {
    per_file(|text| {
        text.lines()
            .take_while(|line| !line.trim_start().starts_with("mod tests"))
            .filter(|line| counts(line))
            .count()
    })
}

/// What `count` gives for each source file under `src`, for the files
/// where it gives more than zero.
fn per_file(count: impl Fn(&str) -> usize) -> BTreeMap<String, usize> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut observed = BTreeMap::new();
    let mut stack = vec![src.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if entry.file_type().expect("file type").is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read source");
            let count = count(&text);
            if count > 0 {
                let rel = path.strip_prefix(&src).expect("under src");
                observed.insert(rel.to_string_lossy().replace('\\', "/"), count);
            }
        }
    }
    observed
}

/// Every kernel-entropy read in this crate, with the reason it is allowed
/// to stay; each reason begins `per-event` or `one-shot`, as the node's
/// ledger's do.
#[test]
fn every_kernel_entropy_read_in_the_provider_is_accounted_for() {
    let expected: BTreeMap<&str, (usize, &str)> = [(
        "rand.rs",
        (
            1,
            "per-event but correct: kernel_fill, the provider's one read, behind its \
             SecureRandom and every key exchange's ephemeral key, once or more per TLS \
             handshake; Go's crypto/tls draws these bytes from its standard-library \
             crypto/rand rather than dcrd's package generator, a failure fails only that \
             handshake rather than aborting, and the process generator keeps its ChaCha20 \
             key across draws, so drawing a session's whole secret from it would let a \
             later memory read recover past sessions' keys",
        ),
    )]
    .into_iter()
    .collect();
    for (file, (_, reason)) in &expected {
        assert!(
            reason.starts_with("per-event") || reason.starts_with("one-shot"),
            "{file}: every reason begins `per-event` or `one-shot`"
        );
    }

    let expected_counts: BTreeMap<String, usize> = expected
        .iter()
        .map(|(file, (count, _))| ((*file).to_owned(), *count))
        .collect();
    assert_eq!(
        lines_containing("getrandom::"),
        expected_counts,
        "the kernel-entropy sites in this crate changed; update the ledger in \
         this test with the reason each one is allowed to stay"
    );
}

/// The key exchanges draw only through `kernel_fill`, which X25519's start
/// and the NIST curves' hand to their draws, and nothing else in the crate
/// names it but its `SecureRandom`: the lines that name it, less comments
/// and `use` declarations, so a draw that passes it on by name is counted
/// as well as one that calls it.
#[test]
fn the_key_exchanges_draw_through_kernel_fill() {
    let uses: BTreeMap<String, usize> = lines_where(|line| {
        let line = line.trim_start();
        line.contains("kernel_fill") && !line.starts_with("//") && !line.starts_with("use ")
    })
    .into_iter()
    .filter(|(file, _)| file != "rand.rs")
    .collect();
    assert_eq!(uses, BTreeMap::from([("kx.rs".to_owned(), 2)]));
}

/// Every draw from the process-wide generator in this crate, with the
/// reason it is allowed to stay: the lines of code, comments aside, that
/// name `dcroxide_crypto`.
#[test]
fn every_draw_from_the_process_generator_is_accounted_for() {
    let expected: BTreeMap<&str, (usize, &str)> = [(
        "rand.rs",
        (
            1,
            "per-event but correct: ProcessRng, the hedge of every ECDSA handshake \
             signature, once per TLS handshake signed with an ECDSA key; RFC 6979 derives \
             the nonce from the key and the transcript, so a weak draw leaves the signature \
             safe and only makes two signatures of one transcript differ, and the generator, \
             seeded at startup, cannot fail after it, where a kernel read on a peer-paced path \
             can; Go hedges from its standard-library crypto/rand, which a failure there \
             aborts",
        ),
    )]
    .into_iter()
    .collect();
    for (file, (_, reason)) in &expected {
        assert!(
            reason.starts_with("per-event") || reason.starts_with("one-shot"),
            "{file}: every reason begins `per-event` or `one-shot`"
        );
    }

    let expected_counts: BTreeMap<String, usize> = expected
        .iter()
        .map(|(file, (count, _))| ((*file).to_owned(), *count))
        .collect();
    let named = lines_where(|line| {
        line.contains("dcroxide_crypto") && !line.trim_start().starts_with("//")
    });
    assert_eq!(
        named, expected_counts,
        "a source file names dcroxide_crypto where the ledger in this test does \
         not; the provider's random bytes and ephemeral keys come from the kernel, \
         so account here for what that crate is used for"
    );
}

/// The process generator is drawn only through `ProcessRng`, which only
/// the ECDSA signer uses: the lines of code outside the unit tests that
/// name it, less comments and `use` declarations, are its definition in
/// `rand.rs` and the signer's one draw in `sign.rs`.  So the
/// `SecureRandom`, a key exchange or the Ed25519 signer drawing from it
/// fails here.
#[test]
fn only_the_ecdsa_signer_draws_from_the_process_generator() {
    let uses = code_lines_where(|line| {
        let line = line.trim_start();
        line.contains("ProcessRng") && !line.starts_with("//") && !line.starts_with("use ")
    });
    assert_eq!(
        uses,
        BTreeMap::from([("rand.rs".to_owned(), 2), ("sign.rs".to_owned(), 1)])
    );
}
