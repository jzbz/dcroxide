// SPDX-License-Identifier: ISC
//! Replay of dcrd's utxo viewpoint transitions generated inside dcrd's
//! internal/blockchain package (`data/utxoview_vectors.txt`): a parent
//! block's regular transactions connected over a fabricated view, a
//! child block that disapproves the parent connected with both trees
//! (undoing the parent's regular transactions from its journal), and
//! the full disconnect back — comparing every entry field, the spend
//! journals, and the best hashes at each step.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::UtxoEntry;
use dcroxide_blockchain::chainio::SpentTxOut;
use dcroxide_blockchain::utxoview::UtxoView;
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

fn opt_hex(s: &str) -> Vec<u8> {
    if s == "-" { Vec::new() } else { unhex(s) }
}

/// Compare the view's entries and best hash against an emitted
/// snapshot, consuming its rows from the iterator.
fn check_snapshot<'a>(
    view: &UtxoView,
    header: &[&str],
    lines: &mut impl Iterator<Item = &'a str>,
    tag: &str,
) {
    let count: usize = header[1].parse().expect("count");
    let best = parse_hash(header[2]);
    assert_eq!(view.best_hash(), best, "{tag}: best hash");

    let mut got = view.entries();
    for _ in 0..count {
        let line = lines.next().expect("entry row");
        let f: Vec<&str> = line.split(' ').collect();
        assert_eq!(f[0], "e", "expected entry row");
        let (key, entry) = got
            .next()
            .unwrap_or_else(|| panic!("{tag}: missing {line}"));
        let hash = parse_hash(f[1]);
        assert_eq!(key.0, hash.0, "{tag}: outpoint hash {line}");
        assert_eq!(key.1, f[2].parse::<u32>().expect("idx"), "{tag}: idx");
        assert_eq!(key.2, f[3].parse::<i8>().expect("tree"), "{tag}: tree");
        assert_eq!(
            entry.amount(),
            f[4].parse::<i64>().expect("amt"),
            "{tag}: amount {line}"
        );
        assert_eq!(
            entry.block_height() as u32,
            f[5].parse::<u32>().expect("h"),
            "{tag}: height {line}"
        );
        assert_eq!(
            entry.block_index(),
            f[6].parse::<u32>().expect("bi"),
            "{tag}: bindex"
        );
        assert_eq!(
            entry.script_version(),
            f[7].parse::<u16>().expect("sv"),
            "{tag}: sver"
        );
        assert_eq!(
            entry.state_bits(),
            f[8].parse::<u8>().expect("st"),
            "{tag}: state {line}"
        );
        assert_eq!(
            entry.packed_flags_bits(),
            f[9].parse::<u8>().expect("fl"),
            "{tag}: flags {line}"
        );
        assert_eq!(
            entry.pk_script(),
            &opt_hex(f[10])[..],
            "{tag}: script {line}"
        );
        let min_outs = if f[11] == "-" {
            None
        } else {
            Some(unhex(f[11]))
        };
        assert_eq!(
            entry.ticket_minimal_outputs_data().map(|d| d.to_vec()),
            min_outs,
            "{tag}: min outs {line}"
        );
    }
    assert!(got.next().is_none(), "{tag}: extra entries in view");
}

fn check_stxos<'a>(
    stxos: &[SpentTxOut],
    header: &[&str],
    lines: &mut impl Iterator<Item = &'a str>,
    tag: &str,
) {
    let count: usize = header[1].parse().expect("count");
    assert_eq!(stxos.len(), count, "{tag}: stxo count");
    for stxo in stxos {
        let line = lines.next().expect("stxo row");
        let f: Vec<&str> = line.split(' ').collect();
        assert_eq!(f[0], "s", "expected stxo row");
        assert_eq!(
            stxo.amount,
            f[1].parse::<i64>().expect("amt"),
            "{tag}: {line}"
        );
        assert_eq!(
            stxo.block_height,
            f[2].parse::<u32>().expect("h"),
            "{tag}: {line}"
        );
        assert_eq!(
            stxo.block_index,
            f[3].parse::<u32>().expect("bi"),
            "{tag}: {line}"
        );
        assert_eq!(
            stxo.script_version,
            f[4].parse::<u16>().expect("sv"),
            "{tag}: {line}"
        );
        assert_eq!(
            stxo.packed_flags,
            f[5].parse::<u8>().expect("fl"),
            "{tag}: flags {line}"
        );
        assert_eq!(stxo.pk_script, opt_hex(f[6]), "{tag}: script {line}");
        let min_outs = if f[7] == "-" { None } else { Some(unhex(f[7])) };
        assert_eq!(stxo.ticket_min_outs, min_outs, "{tag}: min outs {line}");
    }
}

#[test]
fn utxoview_vectors() {
    const TREASURY: bool = true;
    let data = include_str!("data/utxoview_vectors.txt");
    let mut lines = data.lines();

    let mut view = UtxoView::new();
    let none_resolver = |_: &OutPoint| -> Option<UtxoEntry> { None };
    let mut parent: Option<MsgBlock> = None;
    let mut parent_stxos: Vec<SpentTxOut> = Vec::new();
    let mut block: Option<MsgBlock> = None;
    let mut stxos: Vec<SpentTxOut> = Vec::new();

    while let Some(line) = lines.next() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "base" => {
                // Populate the view from the emitted base entries.
                let count: usize = f[1].parse().expect("count");
                for _ in 0..count {
                    let row = lines.next().expect("entry row");
                    let ef: Vec<&str> = row.split(' ').collect();
                    assert_eq!(ef[0], "e");
                    let outpoint = OutPoint {
                        hash: parse_hash(ef[1]),
                        index: ef[2].parse().expect("idx"),
                        tree: ef[3].parse().expect("tree"),
                    };
                    let mut entry = UtxoEntry::new(
                        ef[4].parse().expect("amt"),
                        opt_hex(ef[10]),
                        ef[5].parse().expect("h"),
                        ef[6].parse().expect("bi"),
                        ef[7].parse().expect("sv"),
                        false,
                        false,
                        TxType::Regular,
                        if ef[11] == "-" {
                            None
                        } else {
                            Some(unhex(ef[11]))
                        },
                    );
                    entry.set_state_bits(ef[8].parse().expect("st"));
                    entry.set_packed_flags_bits(ef[9].parse().expect("fl"));
                    view.insert_entry(&outpoint, entry);
                }
            }
            "parent" => {
                let (blk, _) = MsgBlock::from_bytes(&unhex(f[1])).expect("parent");
                let regular_hashes =
                    dcroxide_blockchain::utxoview::collect_tx_hashes(&blk.transactions);
                view.connect_regular_transactions(
                    &blk,
                    &regular_hashes,
                    Some(&mut parent_stxos),
                    TREASURY,
                )
                .expect("connect parent");
                parent = Some(blk);
            }
            "pstxos" => check_stxos(&parent_stxos, &f, &mut lines, "pstxos"),
            "afterparent" => check_snapshot(&view, &f, &mut lines, "afterparent"),
            "block" => {
                let (blk, _) = MsgBlock::from_bytes(&unhex(f[1])).expect("block");
                let parent = parent.as_ref().expect("parent first");
                // Mirror connectBlock: the header disapproves the
                // parent, so undo its regular transactions first.
                view.disconnect_disapproved_block(parent, &parent_stxos, &none_resolver, TREASURY)
                    .expect("disapprove parent");
                let regular_hashes =
                    dcroxide_blockchain::utxoview::collect_tx_hashes(&blk.transactions);
                let stake_hashes =
                    dcroxide_blockchain::utxoview::collect_tx_hashes(&blk.stransactions);
                view.fetch_input_utxos(&blk, &regular_hashes, &none_resolver, TREASURY);
                view.connect_stake_transactions(&blk, &stake_hashes, Some(&mut stxos), TREASURY)
                    .expect("connect stake");
                view.connect_regular_transactions(
                    &blk,
                    &regular_hashes,
                    Some(&mut stxos),
                    TREASURY,
                )
                .expect("connect regular");
                view.set_best_hash(blk.header.block_hash());
                block = Some(blk);
            }
            "stxos" => check_stxos(&stxos, &f, &mut lines, "stxos"),
            "afterconnect" => check_snapshot(&view, &f, &mut lines, "afterconnect"),
            "afterdisconnect" => check_snapshot(&view, &f, &mut lines, "afterdisconnect"),
            other => panic!("unknown row tag {other}"),
        }
        // Disconnect after verifying the connect snapshot.
        if f[0] == "afterconnect" {
            let blk = block.as_ref().expect("block");
            let parent = parent.as_ref().expect("parent");
            view.disconnect_block(blk, parent, &stxos, &none_resolver, TREASURY)
                .expect("disconnect block");
        }
    }
}
