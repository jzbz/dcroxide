// SPDX-License-Identifier: ISC
//! The persistence restart round trip: the chain reorganization
//! vectors (`data/reorg_vectors.txt`, dcrd ground truth from a
//! complete real `BlockChain`) replayed over a database-backed
//! chain with every write persisted, then the chain is flushed,
//! dropped, and reopened from the database — the frozen final
//! section must hold against the reopened chain, along with the
//! block index statuses, stake state, and chain data maps matching
//! the pre-restart chain exactly.  Restarting mid-scenario is
//! deliberately not exercised against the frozen fields because the
//! utxo cache tombstones do not survive restarts, so continued
//! reorganizations legitimately resurrect entries from the journal
//! fraud proofs instead — a timing divergence dcrd itself exhibits
//! across restarts.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::UtxoEntry;
use dcroxide_blockchain::blockindex::BlockStatus;
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_chaincfg::{Params, simnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_stake::TxType;
use dcroxide_testutil::unhex;
use dcroxide_wire::{MsgBlock, OutPoint};
use tempfile::TempDir;

/// Read the persisted utxo set state marker straight off the database.
fn read_set_state(chain: &Chain) -> dcroxide_blockchain::UtxoSetState {
    let mut state = None;
    chain
        .db
        .as_ref()
        .expect("db")
        .view(|tx| {
            state = dcroxide_blockchain::chaindb::db_fetch_utxo_set_state(tx)
                .expect("read utxo set state");
            Ok(())
        })
        .expect("view");
    state.expect("a utxo set state marker")
}

fn parse_hash(s: &str) -> Hash {
    let bytes = unhex(s);
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Hash(h)
}

fn raw_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn check_state(chain: &Chain, f: &[&str], line: &str, phase: &str) {
    let st = &chain.state_snapshot;
    assert_eq!(st.hash, parse_hash(f[1]), "{phase} {line}: hash");
    assert_eq!(st.prev_hash, parse_hash(f[2]), "{phase} {line}: prev");
    assert_eq!(st.height.to_string(), f[3], "{phase} {line}: height");
    assert_eq!(st.bits.to_string(), f[4], "{phase} {line}: bits");
    assert_eq!(st.block_size.to_string(), f[5], "{phase} {line}: size");
    if phase == "live" {
        assert_eq!(st.num_txns.to_string(), f[6], "{phase} {line}: numtxns");
    } else {
        // dcrd's initChainState recomputes NumTxns from the regular
        // transaction tree only while connectBlock counts both
        // trees, so dcrd itself diverges on this cosmetic field
        // across restarts; the port mirrors that behavior.
        let (block, _) =
            MsgBlock::from_bytes(&chain.blocks[&st.hash.0].serialize()).expect("tip block");
        assert_eq!(
            st.num_txns,
            block.transactions.len() as u64,
            "{phase} {line}: regular-only numtxns"
        );
    }
    assert_eq!(st.total_txns.to_string(), f[7], "{phase} {line}: totaltxns");
    assert_eq!(
        st.median_time.to_string(),
        f[8],
        "{phase} {line}: mediantime"
    );
    assert_eq!(
        st.total_subsidy.to_string(),
        f[9],
        "{phase} {line}: subsidy"
    );
    assert_eq!(st.next_pool_size.to_string(), f[10], "{phase} {line}: pool");
    assert_eq!(
        st.next_stake_diff.to_string(),
        f[11],
        "{phase} {line}: sdiff"
    );
    assert_eq!(raw_hex(&st.next_final_state), f[12], "{phase} {line}: fs");
}

fn check_utxo(chain: &Chain, f: &[&str], line: &str, phase: &str) {
    let op = OutPoint {
        hash: parse_hash(f[1]),
        index: f[2].parse().expect("idx"),
        tree: f[3].parse().expect("tree"),
    };
    let entry = chain.fetch_utxo_entry(&op);
    if f[4] == "0" {
        assert!(
            entry.is_none() || entry.expect("checked").is_spent(),
            "{phase} {line}: expected absent"
        );
    } else {
        let entry = entry.unwrap_or_else(|| panic!("{phase} {line}: expected present"));
        assert!(!entry.is_spent(), "{phase} {line}: unexpectedly spent");
        assert_eq!(entry.amount().to_string(), f[5], "{phase} {line}: amount");
        assert_eq!(
            entry.block_height().to_string(),
            f[6],
            "{phase} {line}: height"
        );
        assert_eq!(
            entry.block_index().to_string(),
            f[7],
            "{phase} {line}: bindex"
        );
        assert_eq!(
            entry.script_version().to_string(),
            f[8],
            "{phase} {line}: sver"
        );
        assert_eq!(
            entry.packed_flags_bits().to_string(),
            f[9],
            "{phase} {line}: flags"
        );
        assert_eq!(raw_hex(entry.pk_script()), f[10], "{phase} {line}: script");
    }
}

/// Reopen the chain from the database and restore the test-harness
/// candidate registrations the protocol relies on.
fn reopen(chain: Chain, opts: &Options, params: &Params, known_blocks: &[Hash]) -> Chain {
    drop(chain);
    let db = Database::open(opts).expect("reopen database");
    let mut chain = Chain::open(db, params, Hash::ZERO, false, 0).expect("reopen chain");
    for hash in known_blocks {
        if let Some(node) = chain.index.lookup_node(hash) {
            chain.index.add_best_chain_candidate(node);
        }
    }
    chain
}

#[test]
fn persistence_vectors() {
    let params = simnet_params();
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), 0x12141c16);
    let db = Database::create(&opts).expect("create database");
    let mut chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("open chain");

    let data = include_str!("data/reorg_vectors.txt");
    let now: i64 = 2_000_000_000;
    let mut known_blocks: Vec<Hash> = Vec::new();
    // The state/uc rows of the current section, replayed again after
    // the restart.
    let mut section: Vec<String> = Vec::new();
    let mut counts = [0usize; 3];

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "u" => {
                let op = OutPoint {
                    hash: parse_hash(f[1]),
                    index: f[2].parse().expect("idx"),
                    tree: f[3].parse().expect("tree"),
                };
                let mut entry = UtxoEntry::new(
                    f[4].parse().expect("amt"),
                    unhex(f[9]),
                    f[5].parse().expect("h"),
                    f[6].parse().expect("bi"),
                    f[7].parse().expect("sv"),
                    false,
                    false,
                    TxType::Regular,
                    None,
                );
                entry.set_packed_flags_bits(f[8].parse().expect("fl"));
                entry.set_state_bits(1);
                let mut seed_view = UtxoView::new();
                seed_view.insert_entry(&op, entry);
                chain.commit_view(&mut seed_view);
                counts[0] += 1;
            }
            "blk" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[1])).expect("block");
                let hash = block.header.block_hash();
                let prev = chain
                    .index
                    .lookup_node(&block.header.prev_block)
                    .expect("previous node");
                let id = chain.store.new_node(&block.header, Some(prev));
                chain.store.node_mut(id).is_fully_linked = true;
                chain.index.add_node(&chain.store, id);
                chain.index.set_status_flags(
                    &mut chain.store,
                    id,
                    BlockStatus(BlockStatus::DATA_STORED.0 | BlockStatus::VALIDATED.0),
                );
                chain.index.add_best_chain_candidate(id);
                chain.blocks.insert(hash.0, block.clone());
                chain
                    .db
                    .as_ref()
                    .expect("db")
                    .update(|tx| tx.store_block(&block))
                    .expect("store block");
                known_blocks.push(hash);
                counts[1] += 1;
            }
            "reorg" => {
                let target = chain
                    .index
                    .lookup_node(&parse_hash(f[1]))
                    .expect("target node");
                let errs = chain.reorganize_chain(Some(target), now, &params);
                assert!(errs.is_empty(), "{line}: {errs:?}");
                assert_eq!(f[2], "ok", "{line}");
                section.clear();
                counts[2] += 1;
            }
            "state" => {
                check_state(&chain, &f, line, "live");
                section.push(line.to_string());
            }
            "uc" => {
                check_utxo(&chain, &f, line, "live");
                section.push(line.to_string());
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [12, 19, 4], "row counts");

    // Every reorg's disconnects flushed the cache with the new tip of
    // each step recorded ATOMICALLY alongside the entry writes (dcrd's
    // backend `PutUtxos`), so the persisted marker has moved off its
    // initial value and sits on the main chain (the fork point of the
    // last reorganization; connects do not flush).
    let mid_state = read_set_state(&chain);
    assert_ne!(
        mid_state.last_flush_hash, params.genesis_hash,
        "the disconnect flushes must have recorded a utxo set state"
    );
    let marker = chain
        .index
        .lookup_node(&mid_state.last_flush_hash)
        .expect("the marker block is known");
    let tip = chain.best_chain.tip().expect("tip");
    assert!(
        marker == tip || chain.store.is_ancestor_of(marker, tip),
        "the flush marker must sit on the main chain"
    );

    // Snapshot the pre-restart observables.
    let statuses_of = |chain: &Chain| -> Vec<String> {
        known_blocks
            .iter()
            .map(|h| {
                chain
                    .index
                    .lookup_node(h)
                    .map(|n| chain.store.node(n).status.0.to_string())
                    .unwrap_or_else(|| "-".to_string())
            })
            .collect()
    };
    let pre_statuses = statuses_of(&chain);
    let pre_journals = chain.spend_journal.clone();
    let pre_filters: Vec<[u8; 32]> = chain.filters.keys().copied().collect();
    let pre_tip = {
        let tip = chain.best_chain.tip().expect("tip");
        chain.store.node(tip).hash
    };
    let pre_stake = {
        let tip = chain.best_chain.tip().expect("tip");
        chain
            .store
            .node(tip)
            .stake_node
            .clone()
            .expect("tip stake node")
    };

    // Flush, restart, and verify the final section against the
    // reopened chain along with the deeper observables.
    chain.flush(&params).expect("flush");
    // The shutdown flush lands the utxo set state and the best state
    // in the same transaction as the entries: both markers now agree
    // on the tip.
    let flushed_state = read_set_state(&chain);
    assert_eq!(
        flushed_state.last_flush_hash, pre_tip,
        "flushed marker hash"
    );
    assert_eq!(
        flushed_state.last_flush_height, chain.state_snapshot.height as u32,
        "flushed marker height"
    );
    chain = reopen(chain, &opts, &params, &known_blocks);
    for row in &section {
        let rf: Vec<&str> = row.split(' ').collect();
        match rf[0] {
            "state" => check_state(&chain, &rf, row, "reopened"),
            "uc" => check_utxo(&chain, &rf, row, "reopened"),
            _ => {}
        }
    }
    assert_eq!(statuses_of(&chain), pre_statuses, "reopened statuses");
    assert_eq!(chain.spend_journal, pre_journals, "reopened journals");
    let mut reopened_filters: Vec<[u8; 32]> = chain.filters.keys().copied().collect();
    reopened_filters.sort_unstable();
    let mut pre_filters = pre_filters;
    pre_filters.sort_unstable();
    assert_eq!(reopened_filters, pre_filters, "reopened filters");
    let tip = chain.best_chain.tip().expect("tip");
    assert_eq!(chain.store.node(tip).hash, pre_tip, "reopened tip");
    let stake = chain
        .store
        .node(tip)
        .stake_node
        .clone()
        .expect("reopened stake node");
    assert_eq!(stake.pool_size(), pre_stake.pool_size(), "reopened pool");
    assert_eq!(
        stake.final_state(),
        pre_stake.final_state(),
        "reopened final state"
    );
    assert_eq!(stake.winners(), pre_stake.winners(), "reopened winners");
}
