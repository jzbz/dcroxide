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
