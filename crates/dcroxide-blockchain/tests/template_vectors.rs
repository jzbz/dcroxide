// SPDX-License-Identifier: ISC
//! Replay of dcrd's block template validation, ticket exhaustion
//! checks, and chain query surface generated against a complete real
//! `BlockChain` inside dcrd's internal/blockchain package
//! (`data/template_vectors.txt`): a bulk-imported simnet chain
//! processed through the real `ProcessBlock`, then
//! `CheckConnectBlockTemplate` over templates on the tip (before and
//! after the commitment root fixup) and on the tip's parent (the
//! disconnect path), with the invalid-parent, sanity, positional,
//! and connect rejections; `CheckTicketExhaustion` over a
//! header-only chain approaching stake validation height with no
//! ticket purchases; and the query surface (main chain membership,
//! heights, headers, median times, chain work, tip generation, and
//! height ranges).

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::RuleErrorKind;
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

fn hash_csv(hashes: &[Hash]) -> String {
    hashes
        .iter()
        .map(|h| raw_hex(&h.0))
        .collect::<Vec<_>>()
        .join(",")
}

#[test]
fn template_vectors() {
    let params = simnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    chain.bulk_import_mode = true;
    // The exhaustion chain is separate and header-only.
    let mut xchain = Chain::new(&params, Hash::ZERO, false);
    let data = include_str!("data/template_vectors.txt");
    let now: i64 = 2_000_000_000;
    let mut counts = [0usize; 6];

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
                let (fork_len, errs) = chain.process_block(&block, now, &params);
                assert!(errs.is_empty(), "{line}: {errs:?}");
                assert_eq!(fork_len, 0, "{line}: fork length");
                counts[1] += 1;
            }
            "cbt" => {
                // cbt <blockhex> <kind>
                let (block, _) = MsgBlock::from_bytes(&unhex(f[1])).expect("block");
                let kind = match chain.check_connect_block_template(&block, now, &params) {
                    Ok(()) => "ok".to_string(),
                    Err(e) => e.kind.kind_name().to_string(),
                };
                assert_eq!(kind, f[2], "{line}");
                counts[2] += 1;
            }
            "qh" => {
                // qh <hash> <mainchain> <height|-> <mediantime|-> <work|->
                let hash = parse_hash(f[1]);
                assert_eq!(
                    chain.main_chain_has_block(&hash).to_string(),
                    f[2],
                    "{line}: main chain"
                );
                let height = chain
                    .block_height_by_hash(&hash)
                    .map(|h| h.to_string())
                    .unwrap_or_else(|| "-".to_string());
                assert_eq!(height, f[3], "{line}: height");
                let median = chain
                    .median_time_by_hash(&hash)
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "-".to_string());
                assert_eq!(median, f[4], "{line}: median time");
                let work = chain
                    .chain_work(&hash)
                    .map(|w| w.to_string())
                    .unwrap_or_else(|| "-".to_string());
                assert_eq!(work, f[5], "{line}: work");
                counts[3] += 1;
            }
            "qht" => {
                // qht <height> <hash> <headerhex>
                let height: i64 = f[1].parse().expect("height");
                let hash = chain.block_hash_by_height(height).expect("hash at height");
                assert_eq!(hash, parse_hash(f[2]), "{line}: hash");
                let header = chain.header_by_height(height).expect("header at height");
                assert_eq!(raw_hex(&header.serialize()), f[3], "{line}: header");
                // The hash-keyed variants agree.
                assert_eq!(
                    chain.header_by_hash(&hash).expect("header").serialize(),
                    header.serialize(),
                    "{line}: header by hash"
                );
                assert!(chain.block_by_hash(&hash).is_some(), "{line}: block");
                assert!(chain.block_by_height(height).is_some(), "{line}: block");
            }
            "tipgen" => {
                assert_eq!(hash_csv(&chain.tip_generation()), f[1], "{line}");
            }
            "range" => {
                // range <start> <end> <csv>
                let start: i64 = f[1].parse().expect("start");
                let end: i64 = f[2].parse().expect("end");
                assert_eq!(hash_csv(&chain.height_range(start, end)), f[3], "{line}");
            }
            "xnode" => {
                let (header, _) = BlockHeader::from_bytes(&unhex(f[1])).expect("header");
                let prev = xchain
                    .index
                    .lookup_node(&header.prev_block)
                    .expect("previous node");
                let id = xchain.store.new_node(&header, Some(prev));
                xchain.index.add_node(&xchain.store, id);
                counts[4] += 1;
            }
            "tex" => {
                // tex <hash> <purchases> <kind>
                let hash = parse_hash(f[1]);
                let purchases: u8 = f[2].parse().expect("purchases");
                let kind = match xchain.check_ticket_exhaustion_by_hash(&hash, purchases, &params) {
                    Ok(()) => "ok".to_string(),
                    Err(e) => e.kind.kind_name().to_string(),
                };
                assert_eq!(kind, f[3], "{line}");
                counts[5] += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [8, 12, 7, 2, 135, 8], "row counts");
}

/// `ErrForkTooOld` must be reachable through the template path.
///
/// dcrd's `checkBlockPositional` is a method on the chain and reads the
/// fork rejection checkpoint out of its own index, so the check is live
/// for its only consumer, `CheckConnectBlockTemplate`
/// (`validate.go:1372-1393`, called at `:4432`). The port passed a
/// literal `None` instead, which made the rule structurally unreachable
/// for the one path that can trigger it.
///
/// The state is built rather than replayed because `Chain::new` sets
/// `allow_old_forks` whenever `assume_valid` is zero — which every test
/// chain does — so the checkpoint is never discovered on simnet.
#[test]
fn a_template_forking_before_the_checkpoint_is_rejected() {
    let params = simnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    chain.bulk_import_mode = true;
    let data = include_str!("data/template_vectors.txt");
    let now: i64 = 2_000_000_000;

    // The two templates the battery expects to pass: one at height 13
    // building on the tip, one at height 12 building on the tip's
    // parent (the disconnect path).
    let mut on_tip: Option<MsgBlock> = None;
    let mut off_tip: Option<MsgBlock> = None;

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
            }
            "blk" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[1])).expect("block");
                let (_, errs) = chain.process_block(&block, now, &params);
                assert!(errs.is_empty(), "{line}: {errs:?}");
            }
            "cbt" if f[2] == "ok" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[1])).expect("block");
                if block.header.height == 13 {
                    on_tip = Some(block);
                } else {
                    off_tip = Some(block);
                }
            }
            _ => {}
        }
    }

    let on_tip = on_tip.expect("a height-13 template");
    let off_tip = off_tip.expect("a height-12 template");
    assert_eq!(off_tip.header.height, 12, "the off-tip template's height");

    // Both templates pass with no checkpoint set.
    assert!(
        chain
            .check_connect_block_template(&off_tip, now, &params)
            .is_ok(),
        "the off-tip template is valid without a checkpoint"
    );

    // Put a node at height 13 in the index to anchor the checkpoint on:
    // the height-13 template is a fully valid block on the tip, so its
    // header is accepted unchanged.
    let node13 = chain
        .maybe_accept_block_header(&on_tip.header, false, now, &params)
        .expect("accept the height-13 header");
    assert_eq!(chain.store.node(node13).height, 13);

    chain.allow_old_forks = false;
    chain.reject_forks_checkpoint = Some(node13);

    // The off-tip template is at height 12, below the checkpoint at 13,
    // and is not itself in the index -- so dcrd rejects it.
    let err = chain
        .check_connect_block_template(&off_tip, now, &params)
        .expect_err("a template below the checkpoint must be refused");
    assert_eq!(
        err.kind,
        RuleErrorKind::ForkTooOld,
        "expected ErrForkTooOld, got {err:?}"
    );
}
