// SPDX-License-Identifier: ISC
//! Regression coverage for the treasury-agenda flag used to decode a
//! *parent* block's spend journal.
//!
//! A block's spend journal is serialized under that block's own
//! treasury flag (treasury active as-of the block).  At the DCP0006
//! treasury activation boundary the child that activates the agenda
//! sees `is_treasury_enabled == true`, but its parent was connected
//! while the agenda was still inactive, so the parent journal was
//! written with `is_treasury_enabled == false`.  Decoding the parent
//! journal with the child's flag drops the parent's first stake
//! transaction (treated as the treasurybase slot) and misaligns — or
//! overruns — the stxo stream.  dcrd never hits this because it only
//! decodes the parent journal on the *disapprove* path inside
//! `connectBlock`, and the mainnet activation block approved its
//! parent.  These tests pin down (a) the decode mismatch itself and
//! (b) that `UtxoView::connect_block` now fetches the parent journal
//! lazily, only when the block disapproves its parent, matching dcrd.

// Test-harness arithmetic over small fixed lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::cell::Cell;

use dcroxide_blockchain::UtxoEntry;
use dcroxide_blockchain::chainio::{SpentTxOut, serialize_spend_journal_entry};
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::utxoview::{UtxoView, count_spent_outputs};
use dcroxide_chaincfg::simnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint, TxIn, TxOut};

/// A zeroed 180-byte header to fill in field by field.
fn zero_header() -> BlockHeader {
    BlockHeader::from_bytes(&[0u8; 180]).expect("zero header").0
}

/// A version-1 coinbase: a single null input and a single output, so
/// it is recognized by `is_coin_base_tx` and never looks like a
/// treasury spend.  `tag` distinguishes otherwise-identical coinbases
/// so parent and child hash differently.
fn coinbase(tag: u8) -> MsgTx {
    MsgTx {
        tx_in: vec![TxIn {
            previous_out_point: OutPoint {
                hash: Hash::ZERO,
                index: u32::MAX,
                tree: 0,
            },
            sequence: u32::MAX,
            ..Default::default()
        }],
        tx_out: vec![TxOut {
            value: 1,
            version: 0,
            pk_script: vec![0x51, tag],
        }],
        ..Default::default()
    }
}

/// A plain single-input transaction spending the given prior output.
/// The witness fraud-proof fields carry the amount/height/index that
/// the journal decode reconstructs the stxo from, so they must equal
/// the matching [`SpentTxOut`] fields.
fn spend_tx(prev_index: u32, value_in: i64, block_height: u32, block_index: u32) -> MsgTx {
    MsgTx {
        tx_in: vec![TxIn {
            previous_out_point: OutPoint {
                hash: Hash([7u8; 32]),
                index: prev_index,
                tree: 0,
            },
            sequence: u32::MAX,
            value_in,
            block_height,
            block_index,
            signature_script: Vec::new(),
        }],
        tx_out: vec![TxOut {
            value: value_in - 1,
            version: 0,
            pk_script: vec![0x52],
        }],
        ..Default::default()
    }
}

/// The stxo a [`spend_tx`] input restores, in the journal's serialized
/// form (a plain, non-ticket, non-coinbase regular output).
fn stxo(pk_script: Vec<u8>, value_in: i64, block_height: u32, block_index: u32) -> SpentTxOut {
    SpentTxOut {
        amount: value_in,
        pk_script,
        ticket_min_outs: None,
        block_height,
        block_index,
        script_version: 0,
        packed_flags: 0,
    }
}

fn block(height: u32, transactions: Vec<MsgTx>, stransactions: Vec<MsgTx>) -> MsgBlock {
    let mut header = zero_header();
    header.height = height;
    header.vote_bits = 0x0001; // approves parent
    header.nonce = height;
    MsgBlock {
        header,
        transactions,
        stransactions,
    }
}

/// The parent journal is decoded correctly only with the parent's own
/// (pre-activation) treasury flag; the child's post-activation flag
/// drops the parent's first stake transaction and returns a shorter,
/// shifted stxo list — exactly the misalignment the connect path would
/// have fed into `disconnect_disapproved_block`.
#[test]
fn parent_journal_decode_depends_on_the_treasury_flag() {
    let params = simnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);

    // A pre-activation parent (height 552447, just below where DCP0006
    // activated on mainnet): a coinbase plus one regular spend, and a
    // stake transaction occupying the slot a vote would — the slot the
    // treasury-active decode wrongly skips as the treasurybase.
    let stake_stxo = stxo(vec![0x76, 0xa9, 0x14], 1_000, 500_000, 3);
    let reg_stxo = stxo(vec![0x51], 2_000, 499_999, 1);
    let parent = block(
        552_447,
        vec![
            coinbase(0),
            spend_tx(
                2,
                reg_stxo.amount,
                reg_stxo.block_height,
                reg_stxo.block_index,
            ),
        ],
        vec![spend_tx(
            0,
            stake_stxo.amount,
            stake_stxo.block_height,
            stake_stxo.block_index,
        )],
    );

    // The journal is serialized in the block's forward tx order:
    // [stake spend, regular spend]. This is what connecting the parent
    // wrote while the treasury agenda was still inactive.
    let serialized =
        serialize_spend_journal_entry(&[stake_stxo.clone(), reg_stxo.clone()]).expect("journal");
    chain
        .spend_journal
        .insert(parent.header.block_hash().0, serialized);

    // The count of spent outputs does not depend on the flag: two.
    assert_eq!(count_spent_outputs(&parent), 2);

    // Decoding with the parent's own (inactive) flag round-trips every
    // stxo.
    let correct = chain.fetch_spend_journal(&parent, false);
    assert_eq!(correct, vec![stake_stxo.clone(), reg_stxo.clone()]);

    // Decoding with the child's (active) flag skips the parent's first
    // stake transaction as if it were the treasurybase, so the stake
    // spend is silently dropped and the list is one short — a length
    // that would trip `disconnect_disapproved_block`'s stxo-count
    // assertion on the disapprove path.
    let wrong = chain.fetch_spend_journal(&parent, true);
    assert_eq!(wrong, vec![reg_stxo]);
    assert_ne!(wrong.len(), count_spent_outputs(&parent));
}

/// `connect_block` must not touch the parent spend journal on the
/// approve path (the common case, and the one an IBD crosses at the
/// activation boundary); it decodes it only when the block disapproves
/// its parent, exactly like dcrd.
#[test]
fn connect_block_fetches_parent_journal_only_on_disapprove() {
    let none_resolver = |_: &OutPoint| -> Option<UtxoEntry> { None };

    // A coinbase-only parent: nothing to disconnect, so the lazily
    // fetched journal is legitimately empty on the disapprove path.
    // The treasury flag is irrelevant here — the disapprove branch
    // keys off the header's approve-parent vote bit — so keep it
    // inactive and use plain version-1 coinbases.
    let parent = block(552_447, vec![coinbase(0)], Vec::new());
    let parent_hash = parent.header.block_hash();

    // Approving child: the provider must never run.
    {
        let child = block(552_448, vec![coinbase(1)], Vec::new());
        let calls = Cell::new(0usize);
        let mut view = UtxoView::new();
        view.set_best_hash(parent_hash);
        view.connect_block(
            &child,
            &parent,
            || {
                calls.set(calls.get() + 1);
                Vec::new()
            },
            &none_resolver,
            None,
            false,
        )
        .expect("connect approving child");
        assert_eq!(
            calls.get(),
            0,
            "approve path must not decode the parent journal"
        );
    }

    // Disapproving child: the provider runs exactly once.
    {
        let mut child = block(552_448, vec![coinbase(2)], Vec::new());
        child.header.vote_bits = 0x0000; // disapproves parent
        let calls = Cell::new(0usize);
        let mut view = UtxoView::new();
        view.set_best_hash(parent_hash);
        view.connect_block(
            &child,
            &parent,
            || {
                calls.set(calls.get() + 1);
                Vec::new()
            },
            &none_resolver,
            None,
            false,
        )
        .expect("connect disapproving child");
        assert_eq!(
            calls.get(),
            1,
            "disapprove path must decode the parent journal once"
        );
    }
}
