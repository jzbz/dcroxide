// SPDX-License-Identifier: ISC
//! Signature pre-verification (`dcroxide_blockchain::preverify`) held
//! against the vectors: whatever it puts in the signature cache, every
//! verdict is the one given without it.
//!
//! - dcrd's script corpus (`script_tests.json`, through the script
//!   crate's own harness): each vector run without a cache, then with a
//!   cache the pre-verification of its spend filled, and with one filled
//!   by its own public key script run under the flags pre-verification
//!   uses, which stands for a guess that was right whatever the vector's
//!   script.
//! - The block script rows of the connect battery (`cbs`), checked
//!   without a cache and after pre-verifying each block.
//! - dcrd's full block battery on three chains: one without
//!   pre-verification, one whose blocks are each pre-verified before
//!   they are processed, and one beside a pre-verifier its blocks are
//!   offered to as they are processed: every row gives the same outcome
//!   and the same tip.  The battery holds no input of the guessed shape,
//!   so the pre-verifier is handed no block, and the rows show only that
//!   nothing changes.
//! - Block 432,100 of mainnet, whose pay-to-pubkey-hash inputs the guess
//!   gets right.
//! - The headers-first battery: the floor below which the chain checks
//!   no script agrees with `is_assume_valid_ancestor` along the best
//!   header's branch.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

// The script crate's own harness for the corpus.
#[path = "../../dcroxide-txscript/tests/common/mod.rs"]
mod common;

use std::sync::Arc;

#[cfg(feature = "std")]
use dcroxide_blockchain::preverify::Preverifier;
use dcroxide_blockchain::preverify::{preverify_block, preverify_input};
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_blockchain::validate::check_block_scripts;
use dcroxide_blockchain::{BlockTxHashes, HashedBlock, RuleError, RuleErrorKind, UtxoEntry};
use dcroxide_chaincfg::{regnet_params, simnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_stake::TxType;
use dcroxide_testutil::unhex;
use dcroxide_txscript::{Engine, ScriptError, ScriptFlags, SigCache};
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint};

/// The flags pre-verification runs its guesses under.
const LANE_FLAGS: ScriptFlags = ScriptFlags(
    ScriptFlags::VERIFY_CLEAN_STACK.0
        | ScriptFlags::VERIFY_CHECK_LOCK_TIME_VERIFY.0
        | ScriptFlags::VERIFY_CHECK_SEQUENCE_VERIFY.0
        | ScriptFlags::VERIFY_SHA256.0
        | ScriptFlags::VERIFY_TREASURY.0,
);

fn parse_hash(s: &str) -> Hash {
    let bytes = unhex(s);
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Hash(h)
}

/// The arrays of strings of a JSON file that holds nothing else, as
/// `script_tests.json` does: no escapes, no other values.
fn string_arrays(json: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row: Option<Vec<String>> = None;
    let mut chars = json.chars();
    let mut depth = 0;
    while let Some(c) = chars.next() {
        match c {
            '[' => {
                depth += 1;
                if depth == 2 {
                    row = Some(Vec::new());
                }
            }
            ']' => {
                if depth == 2 {
                    rows.push(row.take().expect("a row"));
                }
                depth -= 1;
            }
            '"' => {
                let mut text = String::new();
                for c in chars.by_ref() {
                    assert_ne!(c, '\\', "an escape");
                    if c == '"' {
                        break;
                    }
                    text.push(c);
                }
                row.as_mut().expect("a string inside a row").push(text);
            }
            ',' | ' ' | '\n' | '\r' | '\t' => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    rows
}

/// Run input 0 of `tx` against `pk_script`, with `cache` attached when
/// given.
fn run(
    pk_script: &[u8],
    tx: &MsgTx,
    flags: ScriptFlags,
    cache: Option<&SigCache>,
) -> Result<(), ScriptError> {
    let mut engine = Engine::new(pk_script, tx, 0, flags, 0)?;
    if let Some(cache) = cache {
        engine.set_sig_cache(cache);
    }
    engine.execute()
}

/// Every vector of dcrd's script corpus gives the result it gives
/// without a cache, error text included, after its spend was
/// pre-verified, and after its own script ran under pre-verification's
/// flags into the cache.
#[test]
fn script_vectors_give_their_results_after_preverification() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcroxide-txscript/testdata/script_tests.json"
    );
    let corpus = std::fs::read_to_string(path).expect("the corpus");
    let (mut vectors, mut guessed, mut guessed_verified, mut own_verified) = (0, 0, 0, 0);
    for (i, test) in string_arrays(&corpus).iter().enumerate() {
        if test.len() == 1 {
            continue;
        }
        let sig_script = common::parse_short_form_v0(&test[0]).expect("signature script");
        let pk_script = common::parse_short_form_v0(&test[1]).expect("public key script");
        let flags = common::parse_script_flags(&test[2]).expect("flags");
        let allowed = common::parse_expected_result(&test[3]).expect("expected result");
        let tx = common::create_spending_tx(&sig_script, &pk_script);
        let tx_hash = tx.tx_hash();

        let bare = run(&pk_script, &tx, flags, None);
        match (&allowed, &bare) {
            (None, Ok(())) => {}
            (Some(kinds), Err(err)) if kinds.contains(&err.kind) => {}
            _ => panic!("#{i}: {bare:?} against {allowed:?}"),
        }

        let cache = SigCache::new(100);
        if let Some(verified) = preverify_input(&tx, 0, &tx_hash, false, &cache) {
            guessed += 1;
            guessed_verified += usize::from(verified);
        }
        assert_eq!(
            run(&pk_script, &tx, flags, Some(&cache)),
            bare,
            "#{i}: after pre-verification"
        );

        let cache = SigCache::new(100);
        own_verified += usize::from(run(&pk_script, &tx, LANE_FLAGS, Some(&cache)).is_ok());
        assert_eq!(
            run(&pk_script, &tx, flags, Some(&cache)),
            bare,
            "#{i}: after its own script under the lane's flags"
        );
        vectors += 1;
    }
    assert!(vectors > 2000, "{vectors} vectors");
    assert_eq!(
        (guessed, guessed_verified, own_verified),
        (GUESSED, GUESSED_VERIFIED, OWN_VERIFIED),
        "what the corpus gave the guess"
    );
}

/// The corpus's vectors whose spend gets a guess, those of them whose
/// guess verifies, and those whose own script runs to success under
/// pre-verification's flags.  Few vectors spend pay-to-pubkey-hash, so
/// the third is what puts entries the vectors' own checks then find in
/// most caches.
const GUESSED: usize = 4;
const GUESSED_VERIFIED: usize = 3;
const OWN_VERIFIED: usize = 1176;

/// A spent output as a `cbsu` row of the connect battery gives it.
fn parse_entry(f: &[&str]) -> (OutPoint, UtxoEntry) {
    let outpoint = OutPoint {
        hash: parse_hash(f[1]),
        index: f[2].parse().expect("idx"),
        tree: f[3].parse().expect("tree"),
    };
    let mut entry = UtxoEntry::new(
        f[4].parse().expect("amt"),
        unhex(f[10]),
        f[5].parse().expect("h"),
        f[6].parse().expect("bi"),
        f[7].parse().expect("sv"),
        false,
        false,
        TxType::Regular,
        if f[11] == "-" {
            None
        } else {
            Some(unhex(f[11]))
        },
    );
    entry.set_state_bits(f[8].parse().expect("st"));
    entry.set_packed_flags_bits(f[9].parse().expect("fl"));
    (outpoint, entry)
}

/// The block script rows of the connect battery get their verdicts
/// after pre-verification, as without it.
#[test]
fn connect_battery_script_rows_give_their_verdicts_after_preverification() {
    let data = include_str!("data/connectblock_vectors.txt");
    let mut view = UtxoView::new();
    let (mut rows, mut checked, mut verified) = (0, 0, 0);
    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "cbsu" => {
                let (outpoint, entry) = parse_entry(&f);
                view.insert_entry(&outpoint, entry);
            }
            "cbs" => {
                let regular = f[1] == "r";
                let flags = ScriptFlags(f[2].parse().expect("flags"));
                let autorev: bool = f[3].parse().expect("autorev");
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                let bare = check_block_scripts(&block, &view, regular, flags, None, autorev);
                let cache = SigCache::new(1_000);
                let done = preverify_block(&block, &BlockTxHashes::compute(&block), &cache);
                checked += done.checked;
                verified += done.verified;
                let warm =
                    check_block_scripts(&block, &view, regular, flags, Some(&cache), autorev);
                assert_eq!(warm, bare, "{}", &line[..60]);
                let verdict = match &bare {
                    Ok(()) => "ok",
                    Err(err) => err.kind.kind_name(),
                };
                assert_eq!(verdict, f[5], "{}", &line[..60]);
                rows += 1;
            }
            _ => {}
        }
    }
    assert_eq!(rows, 5);
    assert_eq!((checked, verified), (CBS_CHECKED, CBS_VERIFIED));
}

/// The inputs of the five `cbs` blocks that get a guess, and those whose
/// guess verifies: none, the battery's spends paying to script hashes.
/// Pinned so that a battery that gains some is noticed.
const CBS_CHECKED: u64 = 0;
const CBS_VERIFIED: u64 = 0;

/// The battery's blocks in order, each with its row name and the
/// current time the row is replayed at.
fn battery_blocks() -> Vec<(String, i64, MsgBlock)> {
    let mut now = 0;
    let mut blocks = Vec::new();
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let hex = match f[0] {
            "now" => {
                now = f[1].parse().expect("now");
                continue;
            }
            "accept" => f[4],
            "reject" => f[3],
            "orphanorreject" => f[2],
            _ => continue,
        };
        let (block, _) = MsgBlock::from_bytes(&unhex(hex)).expect("block");
        blocks.push((f[1].to_string(), now, block));
    }
    blocks
}

/// What a processing call reported, in a form that compares.
fn outcome(result: &(i64, Vec<RuleError>)) -> (i64, Vec<(RuleErrorKind, String)>) {
    (
        result.0,
        result
            .1
            .iter()
            .map(|err| (err.kind, err.description.clone()))
            .collect(),
    )
}

fn tip_hash(chain: &Chain) -> Hash {
    chain.store.node(chain.best_chain.tip().expect("tip")).hash
}

/// Every row of dcrd's full block battery gives the same outcome and
/// leaves the same tip on a chain without pre-verification, on one
/// whose blocks were each pre-verified into its cache before they were
/// processed, and, where the crate has threads, on one whose blocks were
/// offered to a pre-verifier as they were processed.  None has an input
/// of the guessed shape, so the pre-verifier takes none of them (pinned
/// below); the race of a lane with the chain's checks is held in
/// `preverify::tests`, on signed blocks.
#[test]
fn the_full_block_battery_gives_the_same_outcomes_after_preverification() {
    let params = regnet_params();
    let mut plain = Chain::new(&params, Hash::ZERO, false);
    let mut before = Chain::new(&params, Hash::ZERO, false);
    let mut racing = Chain::new(&params, Hash::ZERO, false);
    #[cfg(feature = "std")]
    let preverifier = Preverifier::new(
        Arc::clone(racing.sig_cache.as_ref().expect("the default cache")),
        4,
        usize::MAX,
    );
    #[cfg(feature = "std")]
    if let Some(preverifier) = &preverifier {
        preverifier.set_floor(-1);
    }
    let before_cache = Arc::clone(before.sig_cache.as_ref().expect("the default cache"));

    let (mut rows, mut checked, mut verified) = (0usize, 0, 0);
    for (name, now, block) in battery_blocks() {
        let expected = outcome(&plain.process_block(&block, now, &params));

        let done = preverify_block(&block, &BlockTxHashes::compute(&block), &before_cache);
        checked += done.checked;
        verified += done.verified;
        assert_eq!(
            outcome(&before.process_block(&block, now, &params)),
            expected,
            "{name}: pre-verified before"
        );

        let hashed = HashedBlock::new(Arc::new(block));
        #[cfg(feature = "std")]
        let ticket = preverifier
            .as_ref()
            .and_then(|preverifier| preverifier.submit(&hashed));
        assert_eq!(
            outcome(&racing.process_hashed_block(&hashed, now, &params)),
            expected,
            "{name}: pre-verified alongside"
        );
        #[cfg(feature = "std")]
        if let (Some(preverifier), Some(ticket)) = (&preverifier, ticket) {
            preverifier.withdraw_through(ticket);
        }

        assert_eq!(tip_hash(&before), tip_hash(&plain), "{name}");
        assert_eq!(tip_hash(&racing), tip_hash(&plain), "{name}");
        rows += 1;
    }
    assert_eq!(rows, 561);
    assert_eq!((checked, verified), (BATTERY_CHECKED, BATTERY_VERIFIED));
    #[cfg(feature = "std")]
    if let Some(preverifier) = &preverifier {
        preverifier.shutdown();
        let counts = preverifier.counts();
        assert_eq!(counts.inputs, BATTERY_CHECKED);
        assert!(counts.checked <= counts.inputs);
    }
}

/// The inputs of the battery's blocks that get a guess, and those whose
/// guess verifies: none.  dcrd's generator pays to script hashes of
/// `OP_TRUE` and its tickets and votes spend those, so the battery shows
/// only that pre-verification takes nothing away; the signed blocks of
/// the crate's own tests (`preverify::tests`) and block 432,100 below
/// carry the signatures.  Pinned so that a battery that gains some is
/// noticed.
const BATTERY_CHECKED: u64 = 0;
const BATTERY_VERIFIED: u64 = 0;

/// Block 432,100's pay-to-pubkey-hash inputs, two in its regular tree
/// (one spending a vote's payout) and one in its stake tree (a ticket
/// purchase's), get their scripts guessed right: each verifies, and then
/// verifies against the script rebuilt for it as without a cache.  Its
/// four votes spend tickets paying to a script hash and get no guess.
#[test]
fn mainnet_block_432100_is_preverified_where_the_guess_reaches() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcroxide-txscript/testdata/block432100.hex"
    );
    let hex = std::fs::read_to_string(path).expect("the block");
    let (block, _) = MsgBlock::from_bytes(&unhex(hex.trim())).expect("decodes");
    assert_eq!(block.header.height, 432_100);
    let cache = SigCache::new(100);
    let tx_hashes = BlockTxHashes::compute(&block);
    let done = preverify_block(&block, &tx_hashes, &cache);
    assert_eq!((done.checked, done.verified), (3, 3));

    // Input by input, for each tree.
    let mut verified = 0;
    for (stake, txs, hashes) in [
        (true, &block.stransactions, tx_hashes.stake()),
        (false, &block.transactions, tx_hashes.regular()),
    ] {
        for (tx, tx_hash) in txs.iter().zip(hashes) {
            for idx in 0..tx.tx_in.len() {
                if let Some(ok) = preverify_input(tx, idx, tx_hash, stake, &cache) {
                    assert!(ok, "{tx_hash}:{idx}");
                    verified += 1;
                }
            }
        }
    }
    assert_eq!(verified, 3);
}

/// Along the best header's branch, at every step of the headers-first
/// battery, a block is at or below the chain's script floor exactly when
/// the chain skips its scripts as an ancestor of the assumed valid
/// block; and the floor is -1 whenever the assumed valid node is not on
/// that branch, or the chain has none.
#[test]
fn the_script_floor_follows_the_assumed_valid_ancestry() {
    let mut params = simnet_params();
    let data = include_str!("data/processheaders_vectors.txt");
    let mut now: i64 = 0;
    let mut chain: Option<Chain> = None;
    let (mut steps, mut on_branch_steps, mut skipped, mut checked) = (0, 0, 0, 0);
    let mut headers = Vec::new();
    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("now"),
            "cfg" => {
                params.assume_valid = parse_hash(f[1]);
                let mut c = Chain::new(&params, parse_hash(f[2]), false);
                c.expected_blocks_in_two_weeks = f[4].parse().expect("e2w");
                chain = Some(c);
            }
            "hdr" => {
                let chain = chain.as_mut().expect("cfg first");
                let (header, _) = BlockHeader::from_bytes(&unhex(f[1])).expect("header");
                let _ = chain.maybe_accept_block_header(&header, now, &params);
                headers.push(header.block_hash());
            }
            "mark" => {
                let chain = chain.as_mut().expect("cfg first");
                let node = chain
                    .index
                    .lookup_node(&parse_hash(f[1]))
                    .expect("marked node");
                chain
                    .index
                    .mark_block_failed_validation(&mut chain.store, node);
            }
            _ => continue,
        }
        let Some(chain) = chain.as_ref() else {
            continue;
        };
        let floor = chain.script_skip_floor();
        let on_branch = match (chain.assume_valid_node, chain.index.best_header()) {
            (Some(av), Some(best)) => chain.store.is_ancestor_of(av, best),
            _ => false,
        };
        on_branch_steps += usize::from(on_branch);
        let mut node = chain.index.best_header();
        while let Some(id) = node {
            let skips = chain.is_assume_valid_ancestor(id);
            if on_branch {
                let height = chain.store.node(id).height;
                assert_eq!(
                    height <= floor,
                    skips,
                    "{line}: height {height}, floor {floor}"
                );
            } else {
                assert_eq!(floor, -1, "{line}");
            }
            if on_branch {
                skipped += usize::from(skips);
                checked += usize::from(!skips);
            }
            node = chain.store.node(id).parent;
        }
        steps += 1;
    }
    assert_eq!(steps, 45);
    // The floor is exercised on both sides along the branch.
    assert!(
        on_branch_steps > 0 && skipped > 0 && checked > 0,
        "{on_branch_steps} steps on the branch, {skipped} skipped, {checked} checked"
    );

    // An assumed valid node off the best header's branch gives no floor,
    // and one on it the lower of its height and two weeks below the best
    // header.
    let mut chain = chain.expect("a chain");
    let best = chain.index.best_header().expect("a best header");
    let best_height = chain.store.node(best).height;
    let nodes: Vec<_> = headers
        .iter()
        .filter_map(|hash| chain.index.lookup_node(hash))
        .collect();
    let off_branch = nodes
        .iter()
        .copied()
        .find(|node| !chain.store.is_ancestor_of(*node, best))
        .expect("the battery has a header off the best header's branch");
    chain.assume_valid_node = Some(off_branch);
    assert_eq!(chain.script_skip_floor(), -1, "off the branch");
    chain.expected_blocks_in_two_weeks = 4;
    for node in nodes
        .iter()
        .copied()
        .filter(|node| chain.store.is_ancestor_of(*node, best))
    {
        chain.assume_valid_node = Some(node);
        let height = chain.store.node(node).height;
        assert_eq!(chain.script_skip_floor(), height.min(best_height - 4));
    }

    // In bulk import every block skips its scripts.
    chain.bulk_import_mode = true;
    assert_eq!(chain.script_skip_floor(), i64::MAX);
}
