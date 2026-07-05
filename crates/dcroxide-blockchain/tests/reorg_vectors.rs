// SPDX-License-Identifier: ISC
//! Replay of dcrd's chain reorganization machinery generated against
//! a complete real `BlockChain` instance inside dcrd's
//! internal/blockchain package (`data/reorg_vectors.txt`): two
//! competing simnet branches of pre-validated skeleton blocks
//! (coinbases, treasurybases from height 2, regular spends, and
//! ticket purchases over seeded utxos) driven through
//! `reorganizeChain` — the initial attach, a reorganization to a
//! longer competing branch, the reorganization back, and a tip
//! extension — comparing the best state snapshot and the presence and
//! fields of every outpoint in the utxo universe after each step.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::UtxoEntry;
use dcroxide_blockchain::blockindex::BlockStatus;
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_chaincfg::simnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_stake::TxType;
use dcroxide_testutil::unhex;
use dcroxide_wire::{MsgBlock, OutPoint};

fn parse_hash(s: &str) -> Hash {
    let bytes = unhex(s);
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Hash(h)
}

fn raw_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn reorg_vectors() {
    let params = simnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    let data = include_str!("data/reorg_vectors.txt");
    // A fixed present time; the crafted chain timestamps are far in
    // the past so the is-current latch stays off like dcrd's run.
    let now: i64 = 2_000_000_000;
    let mut counts = [0usize; 5];

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "u" => {
                // u <hash> <idx> <tree> <amount> <height> <bindex>
                //   <sver> <flags> <script>
                let key = (
                    parse_hash(f[1]).0,
                    f[2].parse::<u32>().expect("idx"),
                    f[3].parse::<i8>().expect("tree"),
                );
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
                let mut seed_view = UtxoView::new();
                let op = OutPoint {
                    hash: Hash(key.0),
                    index: key.1,
                    tree: key.2,
                };
                entry.set_state_bits(1); // modified, like the dump's seeds
                seed_view.insert_entry(&op, entry);
                chain.commit_view(&mut seed_view);
                counts[0] += 1;
            }
            "blk" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[1])).expect("block");
                let prev = chain
                    .index
                    .lookup_node(&block.header.prev_block)
                    .expect("previous node");
                let id = chain.store.new_node(&block.header, Some(prev));
                {
                    let node = chain.store.node_mut(id);
                    node.status =
                        BlockStatus(BlockStatus::DATA_STORED.0 | BlockStatus::VALIDATED.0);
                    node.is_fully_linked = true;
                }
                chain.index.add_node(&chain.store, id);
                chain.index.add_best_chain_candidate(id);
                chain.blocks.insert(block.header.block_hash().0, block);
                counts[1] += 1;
            }
            "reorg" => {
                // reorg <target hash> <verdict>
                let target = chain
                    .index
                    .lookup_node(&parse_hash(f[1]))
                    .expect("target node");
                let errs = chain.reorganize_chain(Some(target), now, &params);
                let kind = if errs.is_empty() {
                    "ok".to_string()
                } else {
                    errs[0].kind.kind_name().to_string()
                };
                assert_eq!(kind, f[2], "{line}");
                counts[2] += 1;
            }
            "state" => {
                // state <hash> <prevhash> <height> <bits> <blocksize>
                //   <numtxns> <totaltxns> <mediantime> <totalsubsidy>
                //   <nextpoolsize> <nextstakediff> <finalstate>
                let st = &chain.state_snapshot;
                assert_eq!(st.hash, parse_hash(f[1]), "{line}: hash");
                assert_eq!(st.prev_hash, parse_hash(f[2]), "{line}: prev");
                assert_eq!(st.height.to_string(), f[3], "{line}: height");
                assert_eq!(st.bits.to_string(), f[4], "{line}: bits");
                assert_eq!(st.block_size.to_string(), f[5], "{line}: size");
                assert_eq!(st.num_txns.to_string(), f[6], "{line}: numtxns");
                assert_eq!(st.total_txns.to_string(), f[7], "{line}: totaltxns");
                assert_eq!(st.median_time.to_string(), f[8], "{line}: mediantime");
                assert_eq!(st.total_subsidy.to_string(), f[9], "{line}: subsidy");
                assert_eq!(st.next_pool_size.to_string(), f[10], "{line}: pool");
                assert_eq!(st.next_stake_diff.to_string(), f[11], "{line}: sdiff");
                assert_eq!(raw_hex(&st.next_final_state), f[12], "{line}: fs");
                counts[3] += 1;
            }
            "uc" => {
                // uc <hash> <idx> <tree> <present>
                //   [amount height bindex sver flags script]
                let key = (
                    parse_hash(f[1]).0,
                    f[2].parse::<u32>().expect("idx"),
                    f[3].parse::<i8>().expect("tree"),
                );
                let op = OutPoint {
                    hash: Hash(key.0),
                    index: key.1,
                    tree: key.2,
                };
                let entry = chain.fetch_utxo_entry(&op);
                if f[4] == "0" {
                    assert!(
                        entry.is_none() || entry.expect("checked").is_spent(),
                        "{line}: expected absent"
                    );
                } else {
                    let entry = entry.unwrap_or_else(|| panic!("{line}: expected present"));
                    assert!(!entry.is_spent(), "{line}: unexpectedly spent");
                    assert_eq!(entry.amount().to_string(), f[5], "{line}: amount");
                    assert_eq!(entry.block_height().to_string(), f[6], "{line}: height");
                    assert_eq!(entry.block_index().to_string(), f[7], "{line}: bindex");
                    assert_eq!(entry.script_version().to_string(), f[8], "{line}: sver");
                    assert_eq!(entry.packed_flags_bits().to_string(), f[9], "{line}: flags");
                    assert_eq!(raw_hex(entry.pk_script()), f[10], "{line}: script");
                }
                counts[4] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [12, 19, 4, 4, 732], "row counts");
}
