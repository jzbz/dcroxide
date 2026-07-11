// SPDX-License-Identifier: ISC
//! Replay of dcrd's stake transaction pool behavior generated with
//! dcrd's own mempool test harness (`data/txstake_vectors.txt`): the
//! vote orphan flow, duplicate-vote and max-vote-double-spend
//! rejection across blocks, old vote policy, the stake validation
//! height gates, revocation acceptance with the one-revocation rule,
//! disapproval tallies over no-votes, the votes-map retention quirk
//! after pruning, and the treasury battery — concurrent tspend
//! limits, mined-on-ancestor, the expiry policy in all directions,
//! the chain-level Pi key and signature rejections, treasury adds
//! under the fee policy, and standalone treasurybase rejection — over
//! a mirrored fake chain with a replaced Pi key set.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::{
    chain_from_init, error_kind, harness_policy, hash_csv, parse_hash, parse_tx, raw_hex,
};
use dcroxide_chaincfg::{Params, mainnet_params};
use dcroxide_mempool::TxPool;
use dcroxide_testutil::unhex;
use dcroxide_txscript::ScriptFlags;
use dcroxide_wire::BlockHeader;

/// Run one harness section's rows against a fresh pool, returning the
/// per-row-kind counts.
fn run_section(params: &Params, lines: &[&str], counts: &mut [usize; 6]) {
    let init: Vec<&str> = lines[0].split(' ').collect();
    let chain = chain_from_init(&init);
    let policy = harness_policy(params.coinbase_maturity);
    let mut pool = TxPool::new(chain, policy, params);

    for line in &lines[1..] {
        let f: Vec<&str> = line.split(' ').collect();
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
            "besthash" => {
                // besthash <hash> <headerhex>
                let hash = parse_hash(f[1]);
                let (header, _) = BlockHeader::from_bytes(&unhex(f[2])).expect("header");
                pool.chain.headers.insert(hash.0, header);
                pool.chain.best_hash = hash;
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
                        assert_eq!(error_kind(&err), f[5], "{line}: kind");
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
    counts[5] += 1;
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
    let lines: Vec<&str> = data.lines().collect();
    let treasury_at = lines
        .iter()
        .position(|l| *l == "net treasury")
        .expect("treasury section");
    assert_eq!(lines[0], "net votes");
    let votes_rows = &lines[1..treasury_at];

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
        match f[0] {
            "sethgt" => pool.chain.best_height = f[1].parse().expect("height"),
            "besthash" => {
                let hash = parse_hash(f[1]);
                let (header, _) = BlockHeader::from_bytes(&unhex(f[2])).expect("header");
                pool.chain.headers.insert(hash.0, header);
                pool.chain.best_hash = hash;
            }
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
    let lines: Vec<&str> = data.lines().collect();

    // Split the file into the two harness sections.
    let treasury_at = lines
        .iter()
        .position(|l| *l == "net treasury")
        .expect("treasury section");
    assert_eq!(lines[0], "net votes");
    let votes_rows = &lines[1..treasury_at];
    let mut treasury_rows = &lines[treasury_at + 1..];

    // The treasury harness replaces the network Pi keys with a test
    // key.
    let pikeys: Vec<&str> = treasury_rows[0].split(' ').collect();
    assert_eq!(pikeys[0], "pikeys");
    let pi_pub_key = unhex(pikeys[1]);
    treasury_rows = &treasury_rows[1..];

    let mut counts = [0usize; 6];

    let params = mainnet_params();
    run_section(&params, votes_rows, &mut counts);

    let mut treasury_params = mainnet_params();
    treasury_params.pi_keys = vec![pi_pub_key.clone(), pi_pub_key];
    run_section(&treasury_params, treasury_rows, &mut counts);

    assert_eq!(counts, [45, 49, 3, 2, 4, 2], "row counts");
}
