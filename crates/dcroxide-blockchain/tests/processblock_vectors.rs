// SPDX-License-Identifier: ISC
//! Replay of dcrd's full block processing generated against a
//! complete real `BlockChain` instance inside dcrd's
//! internal/blockchain package (`data/processblock_vectors.txt`):
//! ground proof-of-work simnet blocks driven through `ProcessBlock` —
//! sequential intake under bulk import mode, a duplicate, an orphan,
//! a headers-first delivery whose data arrives out of order, a
//! reorganization to a longer competing branch mid-processing, sanity
//! and positional rejections, a full-validation connect failure with
//! its known-invalid and invalid-ancestor short circuits, and a
//! losing-branch extension — comparing verdicts, fork lengths, node
//! status bytes, the best state, and the final utxo universe.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::UtxoEntry;
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_chaincfg::simnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_stake::TxType;
use dcroxide_testutil::unhex;
use dcroxide_wire::{BlockHeader, MsgBlock, OutPoint};

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
fn processblock_vectors() {
    let params = simnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    let data = include_str!("data/processblock_vectors.txt");
    // A fixed present time far after the crafted chain timestamps.
    let now: i64 = 2_000_000_000;
    let mut counts = [0usize; 5];

    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "u" => {
                // u <hash> <idx> <tree> <amount> <height> <bindex>
                //   <sver> <flags> <script>
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
                entry.set_state_bits(1); // modified, like the dump's seeds
                let mut seed_view = UtxoView::new();
                seed_view.insert_entry(&op, entry);
                chain.commit_view(&mut seed_view);
                counts[0] += 1;
            }
            "bulk" => {
                chain.bulk_import_mode = f[1] == "1";
                counts[1] += 1;
            }
            "hdr" => {
                // hdr <headerhex> <kind>
                let (header, _) = BlockHeader::from_bytes(&unhex(f[1])).expect("header");
                let kind = match chain.process_block_header(&header, now, &params) {
                    Ok(()) => "ok".to_string(),
                    Err(e) => e.kind.kind_name().to_string(),
                };
                assert_eq!(kind, f[2], "{line}");
                counts[2] += 1;
            }
            "pb" => {
                // pb <blockhex> <kind> <forklen> <status|-> <statehash>
                //   <stateheight> <numtxns> <totaltxns> <subsidy>
                let (block, _) = MsgBlock::from_bytes(&unhex(f[1])).expect("block");
                let (fork_len, errs) = chain.process_block(&block, now, &params);
                let kind = if errs.is_empty() {
                    "ok".to_string()
                } else {
                    errs[0].kind.kind_name().to_string()
                };
                assert_eq!(kind, f[2], "{line}");
                assert_eq!(fork_len.to_string(), f[3], "{line}: fork length");
                let status = chain
                    .index
                    .lookup_node(&block.header.block_hash())
                    .map(|n| chain.store.node(n).status.0.to_string())
                    .unwrap_or_else(|| "-".to_string());
                assert_eq!(status, f[4], "{line}: status");
                let st = &chain.state_snapshot;
                assert_eq!(st.hash, parse_hash(f[5]), "{line}: state hash");
                assert_eq!(st.height.to_string(), f[6], "{line}: state height");
                assert_eq!(st.num_txns.to_string(), f[7], "{line}: numtxns");
                assert_eq!(st.total_txns.to_string(), f[8], "{line}: totaltxns");
                assert_eq!(st.total_subsidy.to_string(), f[9], "{line}: subsidy");
                counts[3] += 1;
            }
            "uc" => {
                // uc <hash> <idx> <tree> <present>
                //   [amount height bindex sver flags script]
                let op = OutPoint {
                    hash: parse_hash(f[1]),
                    index: f[2].parse().expect("idx"),
                    tree: f[3].parse().expect("tree"),
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
    assert_eq!(counts, [12, 3, 1, 26, 219], "row counts");
}
