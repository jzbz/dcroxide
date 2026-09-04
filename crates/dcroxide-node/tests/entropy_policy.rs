// SPDX-License-Identifier: ISC
//! Where the daemon reads kernel entropy, and where it must not.
//!
//! dcrd reads the kernel fatally exactly once, in `crypto/rand`'s package
//! `init` (`crypto/rand/prng.go:116-122`), and never again: its PRNG
//! keeps reading on each rekey but discards a failure (`prng.go:68-70`,
//! `:101`), which is what lets the package document that "The default
//! global PRNG will never panic after package init"
//! (`crypto/rand/README.md:18`).
//!
//! This port has no process-wide init seam, so the same policy has to be
//! kept site by site: seed a stream at construction, where an abort is
//! the right answer, and stream from it afterwards on any path an
//! outsider can pace. The mempool's orphan-eviction draw was the case
//! that mattered — a peer pushing orphans past `max_orphan_txs` reaches
//! it, and under `panic = "abort"` a failed read there is an outage.
//!
//! What these tests pin is the mechanism: no kernel read on the
//! peer-paced path, a stream that is seeded once from the OS, and an
//! explicit account of every remaining `getrandom` call in the crate.
//! They do not pin the failure itself. Proving that a `getrandom` error
//! used to abort and now cannot would need an injection seam inside
//! `getrandom::fill`, which is a larger change than the fix.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use dcroxide_blockchain::process::Chain;
use dcroxide_connmgr::SystemCsprng;
use dcroxide_database::{Database, Options};
use dcroxide_mempool::PoolChain;
use dcroxide_node::txmempool::NodePoolChain;

/// An empty regnet chain. `random_u64` never touches the chain, so no
/// blocks are connected — this is only the backend the pool adapter
/// needs to exist.
fn empty_chain() -> (tempfile::TempDir, Arc<Mutex<Chain>>) {
    let params = dcroxide_chaincfg::regnet_params();
    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    (dir, chain)
}

fn draws(pool_chain: &NodePoolChain, n: usize) -> Vec<u64> {
    (0..n).map(|_| pool_chain.random_u64()).collect()
}

/// The draw streams from a seed fixed at construction.
///
/// This is the assertion a per-draw kernel read cannot satisfy: handed
/// the same seed twice, the source must produce the same sequence twice.
#[test]
fn the_pool_draw_streams_from_a_seed_fixed_at_construction() {
    let params = dcroxide_chaincfg::regnet_params();
    let (_dir_a, chain_a) = empty_chain();
    let (_dir_b, chain_b) = empty_chain();

    let a = NodePoolChain::with_rng(chain_a, params.clone(), SystemCsprng::from_seed([9u8; 32]));
    let b = NodePoolChain::with_rng(chain_b, params, SystemCsprng::from_seed([9u8; 32]));

    let seq_a = draws(&a, 256);
    let seq_b = draws(&b, 256);

    assert_eq!(
        seq_a, seq_b,
        "the same seed must yield the same sequence: the source is seeded once, not read per draw"
    );

    let distinct: std::collections::HashSet<u64> = seq_a.iter().copied().collect();
    assert!(
        distinct.len() > 1,
        "the source must stream rather than return a constant"
    );

    // The value feeds `draw % len` at `dcroxide-mempool/src/pool.rs:636`,
    // so it has to be spread rather than cornered. A given residue is
    // missing from 256 draws with probability (7/8)^256, about 1e-15.
    let residues: std::collections::HashSet<u64> = seq_a.iter().map(|v| v % 8).collect();
    assert!(
        residues.len() >= 6,
        "draws must spread across the eviction index space, saw {} of 8 residues",
        residues.len()
    );
}

/// The daemon's own constructor seeds from the OS, not from a constant.
///
/// Separates "streams" from "streams unpredictably": the test above
/// would still pass if `new` hard-coded a seed.
#[test]
fn the_pool_seed_comes_from_the_os_not_a_constant() {
    let params = dcroxide_chaincfg::regnet_params();
    let (_dir_a, chain_a) = empty_chain();
    let (_dir_b, chain_b) = empty_chain();

    let a = NodePoolChain::new(chain_a, params.clone());
    let b = NodePoolChain::new(chain_b, params);

    assert_ne!(
        draws(&a, 8),
        draws(&b, 8),
        "two pools built by the daemon constructor must not share a seed"
    );
}

/// Every kernel-entropy read left in this crate, with the reason it is
/// allowed to stay.
///
/// Three limits, stated rather than implied. The scan matches the
/// literal text `getrandom::`, so `use getrandom::fill;` followed by a
/// bare `fill(..)`, or any other entropy crate, walks straight past it.
/// It covers this crate only. Outside it, `certgen/src/gentool.rs` is
/// a one-shot tool construction where an abort is the right answer,
/// and every other workspace read now lives in one place:
/// `dcroxide-crypto/src/rand.rs`, the port of dcrd's `crypto/rand`,
/// which the address manager and the connection manager both draw
/// from. That module holds two reads — the fatal one in `Prng::new`,
/// which runs at construction, and the one in `Prng::reseed`, which
/// recurs every 4 MiB and deliberately ignores a failure. That last
/// one follows dcrd's structure rather than its behaviour: dcrd's own
/// guard for it is dead code, because `crypto/rand.Read` kills the
/// process rather than returning an error on any toolchain dcrd builds
/// with. The divergence is recorded in PARITY.md. And the reasons
/// below are a debt
/// ledger, not a permission list — entries marked `debt` may be
/// removed as they are converted, never added to.
#[test]
fn every_kernel_entropy_read_in_the_daemon_crate_is_accounted_for() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    let expected: BTreeMap<&str, (usize, &str)> = [
        ("bgtemplate.rs", (2, "debt: mining-address pick and extra nonce, once per template build; dcrd draws both from its never-failing crypto/rand")),
        ("bin/dcroxide.rs", (2, "one startup, one debt: the rand_bytes closure writes the RPC credential file before any listener opens; the rand_u64 closure is per-request through handle_ping")),
        ("bin/gencerts.rs", (1, "tool: a standalone binary with no peers; refusing to emit a key beats emitting a weak one")),
        ("cpuminer.rs", (1, "debt: per-worker extra-nonce offset, CPU miner only")),
        ("peerconn.rs", (1, "debt, highest rate: the handshake nonce plus the Fisher-Yates address shuffles, up to one read per swap on an unauthenticated getaddr")),
        ("rebroadcast.rs", (1, "debt: node-paced rebroadcast jitter, a rejection loop so one call can read several times")),
        ("rpcrun.rs", (3, "startup: the self-signed TLS ed25519 seed, EC scalar and certificate serial, generated at boot")),
        ("seeding.rs", (1, "debt: seeder retry jitter, node-paced")),
        ("socks.rs", (1, "already correct: the surrounding SOCKS exchange is fallible for a dozen other reasons, so the failure is returned rather than aborting")),
        ("websocket.rs", (1, "debt: new_session_id, drawn after the 101 and before authentication is required")),
    ]
    .into_iter()
    .collect();

    let mut observed: BTreeMap<String, usize> = BTreeMap::new();
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
            let count = text
                .lines()
                .filter(|line| line.contains("getrandom::"))
                .count();
            if count > 0 {
                let rel = path.strip_prefix(&src).expect("under src");
                observed.insert(rel.to_string_lossy().replace('\\', "/"), count);
            }
        }
    }

    // The mempool's orphan-eviction draw is the one this file exists for:
    // a peer paces it, so it must not read the kernel at all.
    assert!(
        !observed.contains_key("txmempool.rs"),
        "txmempool.rs must not read kernel entropy: a peer paces the \
         orphan-eviction draw, so a failed read there aborts the daemon"
    );

    let expected_counts: BTreeMap<String, usize> = expected
        .iter()
        .map(|(file, (count, _))| ((*file).to_string(), *count))
        .collect();

    assert_eq!(
        observed, expected_counts,
        "the kernel-entropy sites in this crate changed; update the \
         ledger in this test with the reason each one is allowed to stay"
    );
}
