// SPDX-License-Identifier: ISC
//! Replay of dcrd's manual chain manipulation generated against a
//! complete real `BlockChain` instance inside dcrd's
//! internal/blockchain package (`data/invalidate_vectors.txt`):
//! `ForceHeadReorganization` between tip siblings with every error
//! case, and `InvalidateBlock`/`ReconsiderBlock` across side chain
//! marking round trips, best chain rollbacks with fallback
//! reorganizations (including one whose best candidate needs
//! revalidation the skeleton blocks cannot pass), the no-op repeat,
//! the genesis and unknown block rejections, and a deep invalidation
//! taking every branch with it — comparing verdicts, the best chain
//! tip, the status byte of every block after each operation, and the
//! final utxo universe.

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
fn invalidate_vectors() {
    let params = simnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    let data = include_str!("data/invalidate_vectors.txt");
    let now: i64 = 2_000_000_000;
    // Every block seen, in file order, for the status table.
    let mut all_blocks: Vec<Hash> = Vec::new();
    let mut counts = [0usize; 6];

    let check_op = |chain: &Chain, all_blocks: &[Hash], f: &[&str], line: &str| {
        // ... <kind> <tiphash> <tipheight> <statusCSV>
        let tip = chain.best_chain.tip().expect("tip");
        assert_eq!(
            chain.store.node(tip).hash,
            parse_hash(f[3]),
            "{line}: tip hash"
        );
        assert_eq!(
            chain.store.node(tip).height.to_string(),
            f[4],
            "{line}: tip height"
        );
        let statuses: Vec<String> = all_blocks
            .iter()
            .map(|h| {
                chain
                    .index
                    .lookup_node(h)
                    .map(|n| chain.store.node(n).status.0.to_string())
                    .unwrap_or_else(|| "-".to_string())
            })
            .collect();
        assert_eq!(statuses.join(","), f[5], "{line}: statuses");
    };

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
            "bulk" => {
                chain.bulk_import_mode = f[1] == "1";
            }
            "hdr" => {
                let (header, _) = BlockHeader::from_bytes(&unhex(f[1])).expect("header");
                let kind = match chain.process_block_header(&header, now, &params) {
                    Ok(()) => "ok".to_string(),
                    Err(e) => e.kind.kind_name().to_string(),
                };
                assert_eq!(kind, f[2], "{line}");
                all_blocks.push(header.block_hash());
            }
            "pb" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[1])).expect("block");
                let (fork_len, errs) = chain.process_block(&block, now, &params);
                let kind = if errs.is_empty() {
                    "ok".to_string()
                } else {
                    errs[0].kind.kind_name().to_string()
                };
                assert_eq!(kind, f[2], "{line}");
                assert_eq!(fork_len.to_string(), f[3], "{line}: fork length");
                if kind == "ok" {
                    all_blocks.push(block.header.block_hash());
                }
                counts[1] += 1;
            }
            "inv" => {
                // inv <hash> <kind> <tiphash> <tipheight> <statusCSV>
                let errs = chain.invalidate_block(&parse_hash(f[1]), now, &params);
                let kind = if errs.is_empty() {
                    "ok".to_string()
                } else {
                    errs[0].kind.kind_name().to_string()
                };
                assert_eq!(kind, f[2], "{line}");
                check_op(&chain, &all_blocks, &f, line);
                counts[2] += 1;
            }
            "rec" => {
                let errs = chain.reconsider_block(&parse_hash(f[1]), now, &params);
                let kind = if errs.is_empty() {
                    "ok".to_string()
                } else {
                    errs[0].kind.kind_name().to_string()
                };
                assert_eq!(kind, f[2], "{line}");
                check_op(&chain, &all_blocks, &f, line);
                counts[3] += 1;
            }
            "frg" => {
                // frg <former/new> <kind> <tiphash> <tipheight> <statusCSV>
                let (former, new) = f[1].split_once('/').expect("hash pair");
                let errs = chain.force_head_reorganization(
                    parse_hash(former),
                    parse_hash(new),
                    now,
                    &params,
                );
                let kind = if errs.is_empty() {
                    "ok".to_string()
                } else {
                    errs[0].kind.kind_name().to_string()
                };
                assert_eq!(kind, f[2], "{line}");
                check_op(&chain, &all_blocks, &f, line);
                counts[4] += 1;
            }
            "uc" => {
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
                counts[5] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [12, 21, 6, 4, 6, 201], "row counts");
}
