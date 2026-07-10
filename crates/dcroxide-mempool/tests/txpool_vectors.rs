// SPDX-License-Identifier: ISC
//! Replay of dcrd's transaction pool behavior generated with dcrd's
//! own mempool test harness (`data/txpool_vectors.txt`): the full
//! acceptance gauntlet driven through `ProcessTransaction`,
//! `MaybeAcceptTransaction(s)`, and `MaybeAcceptDependents` over a
//! mirrored fake chain — chained acceptance, orphan cascades and
//! policy, duplicates and double spends, the already-exists check,
//! fee policy in both directions, block- and time-based sequence
//! locks, expiry with pruning, ticket staging with unstaging on
//! parent confirmation, stake difficulty gates and pruning, batch
//! acceptance through the transient pool, and double spend removal —
//! comparing every verdict, accepted-transaction list, and the full
//! pool/orphan/stage/tspend state after every operation.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

mod common;

use common::{
    chain_from_init, error_kind, harness_policy, hash_csv, parse_hash, parse_tx, raw_hex,
};
use dcroxide_chaincfg::mainnet_params;
use dcroxide_mempool::TxPool;
use dcroxide_wire::{MsgTx, TX_TREE_REGULAR};

#[test]
fn txpool_vectors() {
    let params = mainnet_params();
    let data = include_str!("data/txpool_vectors.txt");
    let mut lines = data.lines();

    // The init row builds the harness: the fake chain state and the
    // pool policy dcrd's newPoolHarness configures.
    let init: Vec<&str> = lines.next().expect("init row").split(' ').collect();
    let chain = chain_from_init(&init);
    let policy = harness_policy(params.coinbase_maturity);
    let mut pool = TxPool::new(chain, policy, &params);
    let mut counts = [0usize; 8];

    for line in lines {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "utxo" => {
                // utxo <txhex> <height> <blockindex>
                let tx = parse_tx(f[1]);
                let height: i64 = f[2].parse().expect("height");
                let block_index: u32 = f[3].parse().expect("block index");
                pool.chain
                    .utxos
                    .add_tx_outs(&tx, height, block_index, false);
            }
            "utxotime" => {
                // utxotime <hash> <idx> <unix>
                let key = (
                    parse_hash(f[1]).0,
                    f[2].parse().expect("idx"),
                    TX_TREE_REGULAR,
                );
                pool.chain
                    .utxo_times
                    .insert(key, f[3].parse().expect("time"));
            }
            "setsdiff" => {
                pool.chain.next_stake_diff = f[1].parse().expect("sdiff");
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
            "mat" => {
                // mat <txhex> <isnew> (ok <missingcsv|-> | <kind> -)
                let tx = parse_tx(f[1]);
                let is_new = f[2] == "true";
                match pool.maybe_accept_transaction_pub(&tx, is_new) {
                    Ok(missing) => {
                        assert_eq!("ok", f[3], "{line}: unexpected acceptance");
                        let csv = if missing.is_empty() {
                            "-".to_string()
                        } else {
                            missing
                                .iter()
                                .map(|op| {
                                    format!("{}:{}:{}", raw_hex(&op.hash.0), op.index, op.tree)
                                })
                                .collect::<Vec<_>>()
                                .join(",")
                        };
                        assert_eq!(csv, f[4], "{line}: missing parents");
                    }
                    Err(err) => {
                        assert_eq!(error_kind(&err), f[3], "{line}: kind");
                    }
                }
                counts[1] += 1;
            }
            "mats" => {
                // mats <txhexcsv> <verdict>
                let txns: Vec<MsgTx> = f[1].split(',').map(parse_tx).collect();
                let errors = pool.maybe_accept_transactions(&txns);
                let verdict = match errors.len() {
                    0 => "ok".to_string(),
                    1 => error_kind(&errors[0]),
                    _ => "multi".to_string(),
                };
                assert_eq!(verdict, f[2], "{line}");
                counts[2] += 1;
            }
            "mad" => {
                // mad <txhex> <treasury> <acceptedcsv|->
                let tx = parse_tx(f[1]);
                let treasury = f[2] == "true";
                let accepted = pool.maybe_accept_dependents(&tx, &tx.tx_hash(), treasury);
                assert_eq!(hash_csv(&accepted), f[3], "{line}");
                counts[3] += 1;
            }
            "rmtx" => {
                let tx = parse_tx(f[1]);
                pool.remove_transaction(&tx, &tx.tx_hash(), f[2] == "true");
            }
            "rmds" => {
                let tx = parse_tx(f[1]);
                pool.remove_double_spends(&tx, &tx.tx_hash());
            }
            "rmorph" => {
                let tx = parse_tx(f[1]);
                pool.remove_orphan_pub(&tx.tx_hash());
            }
            "rmtag" => {
                // rmtag <tag> <count>
                let evicted = pool.remove_orphans_by_tag(f[1].parse().expect("tag"));
                assert_eq!(evicted.to_string(), f[2], "{line}");
                counts[4] += 1;
            }
            "prune" => {
                // prune <sdiff> <height>
                pool.prune_stake_tx(f[1].parse().expect("sdiff"), f[2].parse().expect("height"));
            }
            "pruneexp" => {
                pool.prune_expired_tx(f[1].parse().expect("height"));
            }
            "state" => {
                // state <count> <pool> <orphans> <staged> <tspends>
                assert_eq!(pool.count().to_string(), f[1], "{line}: count");
                assert_eq!(hash_csv(&pool.tx_hashes()), f[2], "{line}: pool");
                assert_eq!(hash_csv(&pool.orphan_hashes()), f[3], "{line}: orphans");
                assert_eq!(hash_csv(&pool.staged_hashes()), f[4], "{line}: staged");
                assert_eq!(hash_csv(&pool.tspend_hashes()), f[5], "{line}: tspends");
                counts[5] += 1;
            }
            "have" => {
                let have = pool.have_transaction(&parse_hash(f[1]));
                assert_eq!(have.to_string(), f[2], "{line}");
                counts[6] += 1;
            }
            "spent" => {
                // spent <hash> <idx> <tree> <bool>
                let outpoint = dcroxide_wire::OutPoint {
                    hash: parse_hash(f[1]),
                    index: f[2].parse().expect("idx"),
                    tree: f[3].parse().expect("tree"),
                };
                assert_eq!(pool.is_spent(&outpoint).to_string(), f[4], "{line}");
                counts[7] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [29, 1, 2, 1, 1, 40, 1, 1], "row counts");
}

/// The exists-address hook fires for every transaction added to the
/// pool (dcrd `addTransaction` calling `AddUnconfirmedTx` when the
/// index is enabled): replaying the battery's first acceptance with a
/// recording index installed sees exactly the accepted transactions.
#[test]
fn the_exists_addr_hook_records_added_transactions() {
    use std::sync::{Arc, Mutex};

    struct Recorder(Arc<Mutex<Vec<dcroxide_chainhash::Hash>>>);
    impl dcroxide_mempool::UnconfirmedAddrIndexer for Recorder {
        fn add_unconfirmed_tx(&mut self, tx: &MsgTx) {
            self.0.lock().expect("recorder").push(tx.tx_hash());
        }
    }

    let params = mainnet_params();
    let data = include_str!("data/txpool_vectors.txt");
    let mut lines = data.lines();
    let init: Vec<&str> = lines.next().expect("init row").split(' ').collect();
    let chain = chain_from_init(&init);
    let policy = harness_policy(params.coinbase_maturity);
    let mut pool = TxPool::new(chain, policy, &params);
    let recorded = Arc::new(Mutex::new(Vec::new()));
    pool.set_exists_addr_index(Box::new(Recorder(Arc::clone(&recorded))));

    // The battery's first operation accepts a transaction spending
    // the harness coinbase.
    let f: Vec<&str> = lines.next().expect("first op").split(' ').collect();
    assert_eq!(f[0], "pt", "battery starts with a process-transaction row");
    assert_eq!(f[5], "ok", "battery's first row accepts");
    let tx = parse_tx(f[1]);
    let accepted = pool
        .process_transaction(
            &tx,
            f[2] == "true",
            f[3] == "true",
            f[4].parse().expect("tag"),
        )
        .expect("scripted acceptance");
    assert!(!accepted.is_empty());
    let recorded = recorded.lock().expect("recorder");
    assert_eq!(
        accepted, *recorded,
        "every accepted transaction must reach the index hook"
    );
}
