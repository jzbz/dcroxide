// SPDX-License-Identifier: ISC
//! Replay of dcrd's stake transaction pool behavior generated with
//! dcrd's own mempool test harness (`data/txstake_vectors.txt`), over a
//! mirrored fake chain, section by section, each on a harness of its own:
//!
//! - `votes`: the vote orphan flow, a second vote by a ticket on a block,
//!   the five-vote limit across blocks with recovery after a removal, the
//!   height policy refusing an old vote ahead of the five-vote limit, the
//!   vote and revocation stake validation height gates, revocation
//!   acceptance with the one-revocation rule, a disapproval tally over
//!   no-votes, and the pruning of the votes with their metadata at the
//!   ten-block boundary.
//! - `dupvote`, `voteheight`, `votevalidity` and `votepruning`: dcrd's
//!   `TestDuplicateVoteRejection`, `TestVoteHeightPolicy`,
//!   `TestVoteValidity` and `TestVotePruning`
//!   (`internal/mempool/mempool_test.go:2314-2408`, `:1954-2070`,
//!   `:2072-2177`, `:2410-2564`): the
//!   height policy's both boundaries, votes on an unknown block, with a
//!   wrong height or with an ineligible ticket, and the pruning of two
//!   blocks' votes and metadata.  A `vhb` row follows every step where dcrd
//!   asserts a vote's metadata membership (`5a6f22f0`).
//! - `voteclocks`: a vote accepted three blocks after the block it votes
//!   on outlives its metadata, and a second vote by its ticket on the
//!   block is accepted once the metadata is pruned (`d54099ad`'s two
//!   clocks).
//! - `voteorder`: where the new checks sit among the others.  A vote too
//!   old for the tip is refused as old although its block is unknown, one
//!   claiming a height past the future limit as a future vote although its
//!   block's height differs, both by the stake validation height gate
//!   before that height, one with an ineligible ticket and a signature
//!   that does not verify by the script check, and an old vote with an
//!   ineligible ticket is accepted once old votes are allowed (the
//!   `oldvotes` row), the winners never read.
//! - `treasury`: concurrent tspend limits, mined-on-ancestor, the expiry
//!   policy in all directions, the chain-level Pi key and signature
//!   rejections, treasury adds under the fee policy, and standalone
//!   treasurybase rejection, with a replaced Pi key set.
//!
//! Every section also compares the lines the pool logs for each call
//! with the lines dcrd's pool logged for it (the `log` rows).
//!
//! The blocks votes vote on are the harness's mock blocks, whose headers
//! carry the height the votes claim, and the tickets that may vote on
//! each are registered as its winners (`b443b0b3`, `023c42ff`).  The file
//! is written by `tools/mempoolvectors`, run inside dcrd's
//! `internal/mempool`; the treasury section is unchanged by the vote
//! commits, and the tool reproduces it byte for byte.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::{
    LogRows, apply_block_row, chain_from_init, error_kind, harness_policy, hash_csv, parse_hash,
    parse_tx, raw_hex,
};
use dcroxide_chaincfg::{Params, mainnet_params};
use dcroxide_mempool::TxPool;
use dcroxide_testutil::unhex;
use dcroxide_txscript::ScriptFlags;

/// Records every treasury spend the pool announces (dcrd's mempool
/// `OnTSpendReceived`).
#[derive(Clone, Default)]
struct TSpendRecorder(std::sync::Arc<std::sync::Mutex<Vec<dcroxide_chainhash::Hash>>>);

impl dcroxide_mempool::TSpendReceiver for TSpendRecorder {
    fn tspend_received(&mut self, tspend: &dcroxide_wire::MsgTx) {
        self.0.lock().expect("recorder").push(tspend.tx_hash());
    }
}

/// The battery's sections, in file order: each name and the rows from the
/// one after its `net` row up to the next `net` row.
fn sections(data: &str) -> Vec<(&str, Vec<&str>)> {
    let mut sections: Vec<(&str, Vec<&str>)> = Vec::new();
    for line in data.lines() {
        if let Some(name) = line.strip_prefix("net ") {
            sections.push((name, Vec::new()));
        } else {
            sections.last_mut().expect("a net row first").1.push(line);
        }
    }
    sections
}

/// The rows of the named section.
fn section<'a>(data: &'a str, name: &str) -> Vec<&'a str> {
    sections(data)
        .into_iter()
        .find(|(n, _)| *n == name)
        .unwrap_or_else(|| panic!("section {name}"))
        .1
}

/// The per-kind row counts of a replay: process-transaction rows, state
/// checks, vote hash lists, disapproval checks, tspend hash lists,
/// sections, and `log` rows.
type Counts = [usize; 7];

/// Run one section's rows against a fresh pool, adding to the counts.
fn run_section(params: &Params, lines: &[&str], counts: &mut Counts) {
    let init: Vec<&str> = lines[0].split(' ').collect();
    let chain = chain_from_init(&init);
    let policy = harness_policy(params.coinbase_maturity);
    let mut pool = TxPool::new(chain, policy, params);
    // Every treasury spend the pool accepts must also be announced:
    // dcrd fires `OnTSpendReceived` inside the policy block that admits
    // it (`mempool.go:1926-1929`), and that is the only path to a
    // websocket client's `tspendnew`.
    let announced = TSpendRecorder::default();
    pool.set_tspend_receiver(Box::new(announced.clone()));
    let mut log_rows = LogRows::new();
    pool.set_logger(log_rows.logger());

    let mut last = lines[0];
    for line in &lines[1..] {
        if log_rows.take_row(line) {
            continue;
        }
        log_rows.check(last);
        last = line;
        let f: Vec<&str> = line.split(' ').collect();
        if apply_block_row(&mut pool.chain, &f) {
            continue;
        }
        match f[0] {
            "treasury" => {
                // The harness activates the treasury agenda and adds
                // the treasury script verification flag.
                pool.chain.treasury_active = f[1] == "1";
                if pool.chain.treasury_active {
                    pool.chain.script_flags =
                        ScriptFlags(pool.chain.script_flags.0 | ScriptFlags::VERIFY_TREASURY.0);
                }
            }
            "sethgt" => {
                pool.chain.best_height = f[1].parse().expect("height");
            }
            "oldvotes" => {
                // dcrd's `Policy.AllowOldVotes`.
                pool.policy.allow_old_votes = f[1] == "1";
            }
            "utxo" => {
                let tx = parse_tx(f[1]);
                let height: i64 = f[2].parse().expect("height");
                let block_index: u32 = f[3].parse().expect("block index");
                pool.chain
                    .utxos
                    .add_tx_outs(&tx, height, block_index, false);
            }
            "tspendmined" => {
                pool.chain.tspend_mined.insert(parse_hash(f[1]).0);
            }
            "pt" => {
                // pt <txhex> <alloworphan> <allowhighfees> <tag>
                //    (ok <acceptedcsv> | <kind> -)
                let tx = parse_tx(f[1]);
                let allow_orphan = f[2] == "true";
                let allow_high_fees = f[3] == "true";
                let tag: u64 = f[4].parse().expect("tag");
                match pool.process_transaction(&tx, allow_orphan, allow_high_fees, tag) {
                    Ok(accepted) => {
                        assert_eq!("ok", f[5], "{line}: unexpected acceptance");
                        assert_eq!(hash_csv(&accepted), f[6], "{line}: accepted list");
                    }
                    Err(err) => {
                        assert_eq!(error_kind(&err), f[5], "{line}: kind ({err:?})");
                    }
                }
                counts[0] += 1;
            }
            "rmtx" => {
                let tx = parse_tx(f[1]);
                pool.remove_transaction(&tx, &tx.tx_hash(), f[2] == "true");
            }
            "prune" => {
                pool.prune_stake_tx(f[1].parse().expect("sdiff"), f[2].parse().expect("height"));
            }
            "state" => {
                // state <count> <pool> <orphans> <staged> <tspends>
                assert_eq!(pool.count().to_string(), f[1], "{line}: count");
                assert_eq!(hash_csv(&pool.tx_hashes()), f[2], "{line}: pool");
                assert_eq!(hash_csv(&pool.orphan_hashes()), f[3], "{line}: orphans");
                assert_eq!(hash_csv(&pool.staged_hashes()), f[4], "{line}: staged");
                assert_eq!(hash_csv(&pool.tspend_hashes()), f[5], "{line}: tspends");
                counts[1] += 1;
            }
            "vhb" => {
                // vhb <blockhash> <sorted vote hash csv>
                let mut hashes: Vec<String> = pool
                    .vote_hashes_for_block(&parse_hash(f[1]))
                    .iter()
                    .map(|h| raw_hex(&h.0))
                    .collect();
                hashes.sort();
                let csv = if hashes.is_empty() {
                    "-".to_string()
                } else {
                    hashes.join(",")
                };
                assert_eq!(csv, f[2], "{line}");
                counts[2] += 1;
            }
            "disap" => {
                let disapproved = pool.is_reg_tx_tree_known_disapproved(&parse_hash(f[1]));
                assert_eq!(disapproved.to_string(), f[2], "{line}");
                counts[3] += 1;
            }
            "tsh" => {
                // tsh <sorted tspend hash csv>
                assert_eq!(hash_csv(&pool.tspend_hashes()), f[1], "{line}");
                counts[4] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    log_rows.check(last);
    counts[5] += 1;
    counts[6] += log_rows.checked();

    // The pool tracks a treasury spend the moment it is added; the
    // announcement fires a few checks earlier, so every tracked hash
    // must appear among the announced ones.  A superset check rather
    // than equality, because a rejection announces nothing -- and not
    // vacuous, since the treasury section tracks seven.
    let announced = announced.0.lock().expect("recorder");
    for tracked in pool.tspend_hashes() {
        assert!(
            announced.contains(&tracked),
            "tspend {tracked} entered the pool without being announced, so a client \
             subscribed to tspendnew never hears about it",
        );
    }
}

/// The vote-received hook fires for every accepted vote (dcrd
/// `addTransaction`'s `OnVoteReceived` firing `s.bg.VoteReceived`):
/// replaying the votes battery with a recording receiver installed
/// sees the first accepted SSGen delivered to the hook, and it is a
/// vote whose hash the pool tracks for the block it votes on.
#[test]
fn the_vote_receiver_hook_records_accepted_votes() {
    use std::sync::{Arc, Mutex};

    use dcroxide_stake::{TxType, determine_tx_type, ssgen_block_voted_on};
    use dcroxide_wire::MsgTx;

    struct Recorder(Arc<Mutex<Vec<MsgTx>>>);
    impl dcroxide_mempool::VoteReceiver for Recorder {
        fn vote_received(&mut self, vote: &MsgTx) {
            self.0.lock().expect("recorder").push(vote.clone());
        }
    }

    let data = include_str!("data/txstake_vectors.txt");
    let votes_rows = section(data, "votes");

    let params = mainnet_params();
    let init: Vec<&str> = votes_rows[0].split(' ').collect();
    let chain = chain_from_init(&init);
    let policy = harness_policy(params.coinbase_maturity);
    let mut pool = TxPool::new(chain, policy, &params);
    let recorded = Arc::new(Mutex::new(Vec::new()));
    pool.set_vote_receiver(Box::new(Recorder(Arc::clone(&recorded))));

    // Replay the setup and process-transaction rows, stopping the
    // moment the receiver first fires so the vote is still tracked.
    let mut first_vote: Option<MsgTx> = None;
    'rows: for line in &votes_rows[1..] {
        let f: Vec<&str> = line.split(' ').collect();
        if apply_block_row(&mut pool.chain, &f) {
            continue;
        }
        match f[0] {
            "sethgt" => pool.chain.best_height = f[1].parse().expect("height"),
            "utxo" => {
                let tx = parse_tx(f[1]);
                let height: i64 = f[2].parse().expect("height");
                let block_index: u32 = f[3].parse().expect("block index");
                pool.chain
                    .utxos
                    .add_tx_outs(&tx, height, block_index, false);
            }
            "pt" => {
                let tx = parse_tx(f[1]);
                let _ = pool.process_transaction(
                    &tx,
                    f[2] == "true",
                    f[3] == "true",
                    f[4].parse().expect("tag"),
                );
                let recorded = recorded.lock().expect("recorder");
                if let Some(vote) = recorded.first() {
                    first_vote = Some(vote.clone());
                    break 'rows;
                }
            }
            _ => {}
        }
    }

    let vote = first_vote.expect("the battery accepts at least one vote");
    assert_eq!(
        determine_tx_type(&vote),
        TxType::SSGen,
        "the hook fires with an SSGen vote"
    );
    let (block_hash, _) = ssgen_block_voted_on(&vote);
    assert!(
        pool.vote_hashes_for_block(&block_hash)
            .contains(&vote.tx_hash()),
        "the recorded vote is tracked for the block it votes on"
    );
}

#[test]
fn txstake_vectors() {
    let data = include_str!("data/txstake_vectors.txt");
    let sections = sections(data);
    let names: Vec<&str> = sections.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        names,
        [
            "votes",
            "dupvote",
            "voteheight",
            "votevalidity",
            "votepruning",
            "voteclocks",
            "voteorder",
            "treasury"
        ]
    );

    let mut counts = [0usize; 7];
    for (name, rows) in &sections {
        if *name == "treasury" {
            // The treasury harness replaces the network Pi keys with a
            // test key.
            let pikeys: Vec<&str> = rows[0].split(' ').collect();
            assert_eq!(pikeys[0], "pikeys");
            let pi_pub_key = unhex(pikeys[1]);
            let mut params = mainnet_params();
            params.pi_keys = vec![pi_pub_key.clone(), pi_pub_key];
            run_section(&params, &rows[1..], &mut counts);
        } else {
            run_section(&mainnet_params(), rows, &mut counts);
        }
    }

    assert_eq!(counts, [70, 86, 50, 2, 4, 8, 139], "row counts");
}

/// Every vote error kind the pool raises is reached by the battery, so
/// none of the vote checks can be lost without a vector failing.
#[test]
fn every_vote_rejection_kind_is_exercised() {
    let data = include_str!("data/txstake_vectors.txt");
    for kind in [
        "ErrOrphan",
        "ErrorAlreadyVoted",
        "ErrTooManyVotes",
        "ErrOldVote",
        "ErrFutureVote",
        "ErrVoteBlockUnknown",
        "ErrVoteBlockHeight",
        "ErrIneligibleTicketVote",
        "ErrDuplicateRevocation",
    ] {
        assert!(
            data.lines()
                .any(|l| l.starts_with("pt ") && l.split(' ').nth(5) == Some(kind)),
            "no row expects {kind}"
        );
    }
}
