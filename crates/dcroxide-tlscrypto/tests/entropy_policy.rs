// SPDX-License-Identifier: ISC
//! Where the TLS provider reads kernel entropy, and that it reads it in one
//! place.
//!
//! `dcroxide-node`'s `tests/entropy_policy.rs` accounts for every kernel
//! read in the daemon's own source and leaves its dependencies' draws out
//! of scope.  This crate is the dependency that draws for TLS, so it keeps
//! the same account of itself, in the same style.
//!
//! Every byte the provider draws comes from `rand::kernel_fill`: the bytes
//! rustls asks its `SecureRandom` for, and the ephemeral key of each key
//! exchange, which the RPC server draws once per TLS handshake a client
//! steers to P-521 today and, from the switch (ADR-0015), once per TLS
//! handshake the node serves or dials.  A peer paces those draws, and they
//! stay on the kernel deliberately, on two grounds: Go's `crypto/tls`
//! draws the same bytes from its standard-library `crypto/rand`, not from
//! dcrd's package generator, and a failed read returns `GetRandomFailed`,
//! which fails the one handshake rather than aborting the process.  An
//! ephemeral scalar has a third: it is the session's whole secret, and the
//! process generator, which keeps its key for 4 MiB of draws, would let a
//! later read of the process's memory recover it, where the kernel's
//! generator erases its key as it goes.
//!
//! The scan matches the literal text `getrandom::`, so `use getrandom::fill;`
//! followed by a bare `fill(..)`, or another entropy crate, walks straight
//! past it; the count of the lines that name `kernel_fill` below is the
//! second line of defence for the key exchanges.  The process-wide
//! generator of `dcroxide-crypto` is kept out by the last test, which
//! finds no line of the crate's code, its comments aside, naming that
//! crate.

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
            let count = text.lines().filter(|line| counts(line)).count();
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

/// No line of the crate's code, its comments aside, names
/// `dcroxide_crypto`, so nothing here draws from its process-wide
/// generator: not the bytes rustls asks the `SecureRandom` for, and not an
/// ephemeral key, for the reasons the module doc gives.  A use of that
/// generator added later, such as the hedge of an ECDSA signature, which
/// RFC 6979 keeps safe should the draw be weak, comes here with its
/// reason.
#[test]
fn nothing_draws_from_the_process_generator() {
    let named = lines_where(|line| {
        line.contains("dcroxide_crypto") && !line.trim_start().starts_with("//")
    });
    assert_eq!(
        named,
        BTreeMap::new(),
        "a source file names dcroxide_crypto; the provider's random bytes and \
         ephemeral keys come from the kernel alone, so account here for what \
         that crate is used for"
    );
}
