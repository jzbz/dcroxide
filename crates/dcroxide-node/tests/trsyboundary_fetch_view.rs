// SPDX-License-Identifier: ISC
//! The mempool's view of the chain without the tip's regular tree, on
//! either side of the treasury agenda's activation boundary, replayed from
//! the `fetchview` case of `trsyboundary_vectors.txt`, which
//! `tools/trsyboundarygen` writes inside dcrd's `internal/blockchain` at
//! the parity pin.
//!
//! dcrd's `FetchUtxoView` disconnects the tip's regular tree for a caller
//! that leaves it out, as the mempool does once the votes it holds for the
//! tip disapprove that tree.  Since `37fd3a3e` it does so with the tip's own
//! treasury flag, `isTreasuryAgendaActive(tip.parent)`
//! (`utxoviewpoint.go:1352-1359`), where it took the flag of the block
//! after the tip.  The two differ only while H_act-1, the last block before
//! the agenda, is the tip: read with H_act's flag, its spend journal comes
//! up one spent output short, as if its first stake transaction were a
//! treasurybase.  The port's `FetchUtxoView` is the node's
//! `chain_fetch_utxo_view` (`txmempool.rs`), so the case is replayed here,
//! through the pool's own chain adapter, rather than beside the other cases
//! in `dcroxide-blockchain`'s `tests/trsyboundary_vectors.rs`.
//!
//! The case asks for the view on the tip H_act-1, bva19 at height 69, for
//! h70's regular spend, and on the tip h70 for h71's, where both flags are
//! active, so a flag taken a block too far back fails as well.  Every
//! `viewentry` row is the view's entry for an output the tip's regular
//! tree or the transaction creates or spends, written as the blockchain
//! replay reads them: `missing`, `spent`, or the unspent entry's amount,
//! height, block index, transaction type, coinbase and expiry flags,
//! script version and script.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use dcroxide_blockchain::UtxoEntry;
use dcroxide_blockchain::chaindb::db_fetch_utxo_set_state;
use dcroxide_blockchain::process::{Chain, OpenConfig};
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_chaincfg::{Params, regnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_mempool::PoolChain;
use dcroxide_node::txmempool::NodePoolChain;
use dcroxide_testutil::{hex, unhex};
use dcroxide_wire::{MsgBlock, OutPoint, TX_TREE_REGULAR};

/// The maximum size of the UTXO cache of dcrd's test chain
/// (`common_test.go:154`).
const TEST_CACHE_MAX_BYTES: u64 = 100 * 1024;

/// dcrd's `quickVoteActivationParams` (`validate_test.go:239-263`), as
/// `dcroxide-blockchain`'s `tests/trsyboundary_vectors.rs` builds them.
fn quick_vote_activation_params() -> Params {
    let mut p = regnet_params();
    p.work_diff_window_size = 200_000;
    p.work_diff_windows = 1;
    p.target_timespan_secs = p.target_time_per_block_secs * p.work_diff_window_size;
    p.coinbase_maturity = 2;
    p.block_enforce_num_required = 5;
    p.block_reject_num_required = 7;
    p.block_upgrade_num_to_check = 10;
    p.ticket_maturity = 2;
    p.ticket_pool_size = 4;
    p.ticket_expiry = 6 * u32::from(p.ticket_pool_size);
    p.stake_enabled_height = i64::from(p.coinbase_maturity) + i64::from(p.ticket_maturity);
    p.stake_validation_height = i64::from(p.coinbase_maturity) + i64::from(p.ticket_pool_size) * 2;
    p.stake_version_interval = 10;
    p.rule_change_activation_interval =
        u32::from(p.ticket_pool_size) * u32::from(p.tickets_per_block);
    p.rule_change_activation_quorum =
        p.rule_change_activation_interval * u32::from(p.tickets_per_block * 100) / 1000;
    p
}

fn vector_rows() -> Vec<Vec<String>> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcroxide-blockchain/tests/data/trsyboundary_vectors.txt"
    );
    std::fs::read_to_string(path)
        .expect("trsyboundary vectors")
        .lines()
        .map(|line| line.split(' ').map(str::to_string).collect())
        .collect()
}

fn outpoint(f: &[String]) -> OutPoint {
    OutPoint {
        hash: f[1].parse().expect("hash"),
        index: f[2].parse().expect("index"),
        tree: f[3].parse().expect("tree"),
    }
}

/// An entry as the generator writes it (its `exportEntry`).
fn entry_text(entry: Option<&UtxoEntry>) -> String {
    match entry {
        None => "missing".to_string(),
        Some(entry) if entry.is_spent() => "spent".to_string(),
        Some(entry) => format!(
            "{} {} {} {} {} {} {} {}",
            entry.amount(),
            entry.block_height(),
            entry.block_index(),
            entry.transaction_type(),
            entry.is_coin_base(),
            entry.has_expiry(),
            entry.script_version(),
            hex(entry.pk_script()),
        ),
    }
}

/// A clock that does not move, for [`Chain::set_periodic_clock`]: the
/// periodic flush never comes due, as the generator's caches never flush
/// on their own.
fn fixed_clock() -> Option<i64> {
    Some(0)
}

/// What the case checked or did, by row kind.
#[derive(Debug, Default, PartialEq)]
struct Tally {
    processed: usize,
    states: usize,
    treasury: usize,
    tips: usize,
    disapprovals: usize,
    views: usize,
    view_entries: usize,
}

/// The `fetchview` case: the chain and the pool's adapter over it, fed
/// the case's blocks, and every view and entry checked against dcrd's.
#[test]
fn the_pool_view_disconnects_the_tip_with_its_own_treasury_flag() {
    let rows = vector_rows();
    let blocks: BTreeMap<&str, MsgBlock> = rows
        .iter()
        .filter(|f| f[0] == "block")
        .map(|f| {
            let (block, _) = MsgBlock::from_bytes(&unhex(&f[2])).expect("block");
            (f[1].as_str(), block)
        })
        .collect();
    let mut section = Vec::new();
    let mut inside = false;
    for f in &rows {
        if f[0] == "test" {
            inside = f[1] == "fetchview";
        } else if inside {
            section.push(f);
        }
    }
    assert!(
        !section.is_empty(),
        "no fetchview section in the vector file"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let mut pool_chain: Option<(Params, Arc<Mutex<Chain>>, NodePoolChain)> = None;
    let mut now = None;
    let mut tally = Tally::default();
    // The view of the last `fetchview` row, which its `viewentry` rows
    // read.
    let mut view: Option<UtxoView> = None;

    for f in section {
        let line = f.join(" ");
        if f[0] == "params" {
            assert_eq!(f[1], "quickvote", "{line}");
            let params = quick_vote_activation_params();
            let opts = Options::new(dir.path().join("chain"), params.net.0);
            let db = Database::create(&opts).expect("create database");
            let mut config = OpenConfig::new(Hash::ZERO, false, 0);
            config.utxo_cache_max_bytes = TEST_CACHE_MAX_BYTES;
            let mut chain = Chain::open_with_config(db, &params, config).expect("open chain");
            chain.set_periodic_clock(fixed_clock);
            let chain = Arc::new(Mutex::new(chain));
            let adapter = NodePoolChain::new(Arc::clone(&chain), params.clone());
            pool_chain = Some((params, chain, adapter));
            continue;
        }
        let (params, chain, adapter) = pool_chain.as_ref().expect("a params row first");
        if f[0] != "viewentry" {
            view = None;
        }
        match f[0].as_str() {
            "now" => now = Some(f[1].parse::<i64>().expect("now")),
            "process" => {
                let (fork_len, errs) = chain.lock().expect("chain").process_block(
                    &blocks[f[1].as_str()],
                    now.expect("now row"),
                    params,
                );
                assert!(errs.is_empty(), "{line}: {errs:?}");
                assert_eq!(fork_len.to_string(), f[2], "{line}: fork length");
                tally.processed += 1;
            }
            "state" => {
                let chain = chain.lock().expect("chain");
                let db = chain.db.as_ref().expect("database-backed chain");
                let mut state = None;
                db.view(|tx| {
                    state = db_fetch_utxo_set_state(tx).expect("utxo set state");
                    Ok(())
                })
                .expect("read the utxo set state");
                let state = state.expect("a recorded utxo set state");
                assert_eq!(
                    (
                        state.last_flush_hash.to_string(),
                        state.last_flush_height.to_string()
                    ),
                    (f[1].clone(), f[2].clone()),
                    "{line}: the backend's utxo set state"
                );
                tally.states += 1;
            }
            "treasury" => {
                let hash = blocks[f[1].as_str()].header.block_hash();
                let active = chain
                    .lock()
                    .expect("chain")
                    .is_treasury_agenda_active(&hash, params)
                    .unwrap_or_else(|e| panic!("{line}: {e:?}"));
                assert_eq!(active.to_string(), f[2], "{line}");
                tally.treasury += 1;
            }
            "tip" => {
                assert_eq!(
                    adapter.best_hash(),
                    blocks[f[1].as_str()].header.block_hash(),
                    "{line}"
                );
                tally.tips += 1;
            }
            "disapproves" => {
                // dcrd asserts this of the generator's tip, the named
                // block, which the chain has not seen yet.
                assert_eq!(blocks[f[1].as_str()].header.vote_bits & 1, 0, "{line}");
                tally.disapprovals += 1;
            }
            "fetchview" => {
                let index: usize = f[2].parse().expect("transaction index");
                let tx = &blocks[f[1].as_str()].transactions[index];
                let fetched = adapter
                    .fetch_utxo_view(tx, &tx.tx_hash(), TX_TREE_REGULAR, false)
                    .unwrap_or_else(|e| panic!("{line}: {e}"));
                view = Some(fetched);
                tally.views += 1;
            }
            "viewentry" => {
                let view = view.as_ref().expect("a fetchview row first");
                assert_eq!(
                    entry_text(view.lookup_entry(&outpoint(f))),
                    f[4..].join(" "),
                    "{line}"
                );
                tally.view_entries += 1;
            }
            other => panic!("unknown row kind {other}: {line}"),
        }
    }

    assert_eq!(
        tally,
        Tally {
            processed: 70,
            states: 2,
            treasury: 3,
            tips: 3,
            disapprovals: 1,
            views: 2,
            view_entries: 19,
        }
    );
}
