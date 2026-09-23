// SPDX-License-Identifier: ISC
//! In-block (in-flight) utxo resolution for the regular tree, pinned
//! against dcrd's `addRegularInputUtxos` and `UtxoCache.FetchEntries`.
//!
//! Two rules decide which in-block outputs a block's transactions can
//! see.  dcrd adds only the specifically referenced output of an
//! earlier in-block transaction (`AddTxOut(originTx, originIdx)`,
//! since 01208035), and it resolves every queued outpoint from the
//! backend unconditionally, so a forward reference (an input spending
//! an output of a later transaction in the block) ends up nil even
//! when a later input has meanwhile added that output in flight.  In
//! both cases the forward-referencing transaction fails with
//! `ErrMissingTxOut`.  The block shapes below have no dcrd-generated
//! vector, so the expected verdicts come from those two rules.

// Test-harness arithmetic over small fixed amounts and heights.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::UtxoEntry;
use dcroxide_blockchain::chainio::SpentTxOut;
use dcroxide_blockchain::utxoview::{UtxoView, collect_tx_hashes};
use dcroxide_blockchain::validate::{ChainSubsidyParams, check_transactions_and_connect};
use dcroxide_blockchain::{RuleError, RuleErrorKind};
use dcroxide_chaincfg::simnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_stake::TxType;
use dcroxide_standalone::{SubsidyCache, SubsidySplitVariant};
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint, TxIn, TxOut};

/// The height of the block under test; its parent is one below.
const HEIGHT: u32 = 100;
/// Every output pays this much to an anyone-can-spend script.
const OUT_VALUE: i64 = 1_000;
const SCRIPT: [u8; 1] = [0x51]; // OP_TRUE

/// A spendable output outside the block, confirmed long before it.
fn external() -> (OutPoint, UtxoEntry) {
    let outpoint = OutPoint {
        hash: Hash([0xee; 32]),
        index: 0,
        tree: 0,
    };
    let entry = UtxoEntry::new(
        5 * OUT_VALUE,
        SCRIPT.to_vec(),
        50,
        1,
        0,
        false,
        false,
        TxType::Regular,
        None,
    );
    (outpoint, entry)
}

/// An input spending `outpoint`, with fraud proof data matching an
/// output of `value` created at `height` by the transaction at
/// `index` of its block.
fn input(outpoint: OutPoint, value: i64, height: u32, index: u32) -> TxIn {
    TxIn {
        previous_out_point: outpoint,
        sequence: u32::MAX,
        value_in: value,
        block_height: height,
        block_index: index,
        signature_script: Vec::new(),
    }
}

fn tx(inputs: Vec<TxIn>, outputs: usize) -> MsgTx {
    MsgTx {
        tx_in: inputs,
        tx_out: (0..outputs)
            .map(|_| TxOut {
                value: OUT_VALUE,
                version: 0,
                pk_script: SCRIPT.to_vec(),
            })
            .collect(),
        ..MsgTx::default()
    }
}

/// The subsidy a coinbase at `height` must commit to in its input (no
/// voters, treasury agenda inactive).
fn subsidy(height: u32) -> i64 {
    let params = simnet_params();
    let mut cache = SubsidyCache::new(ChainSubsidyParams(&params));
    let height = i64::from(height);
    cache.calc_work_subsidy_v3(height, 0, SubsidySplitVariant::Original)
        + cache.calc_treasury_subsidy(height, 0, false)
}

/// A coinbase at `height` that commits to the subsidy and pays
/// nothing, so no subsidy rule can reject it; `tag` keeps the
/// coinbases of different blocks distinct.
fn coinbase(height: u32, tag: u8) -> MsgTx {
    let mut cb = MsgTx::default();
    cb.tx_in.push(TxIn {
        previous_out_point: OutPoint {
            hash: Hash::ZERO,
            index: u32::MAX,
            tree: 0,
        },
        sequence: u32::MAX,
        value_in: subsidy(height),
        block_height: 0,
        block_index: u32::MAX,
        signature_script: vec![0x01, tag],
    });
    cb.tx_out.push(TxOut {
        value: 0,
        version: 0,
        pk_script: SCRIPT.to_vec(),
    });
    cb
}

fn op(tx: &MsgTx, index: u32) -> OutPoint {
    OutPoint {
        hash: tx.tx_hash(),
        index,
        tree: 0,
    }
}

fn block(height: u32, transactions: Vec<MsgTx>) -> MsgBlock {
    let (mut header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header");
    header.height = height;
    MsgBlock {
        header,
        transactions,
        stransactions: Vec::new(),
    }
}

/// Load the block's inputs into `view` through `resolver` and run
/// dcrd's `checkTransactionsAndConnect` over its regular tree.
fn connect(
    view: &mut UtxoView,
    block: &MsgBlock,
    resolver: &impl Fn(&OutPoint) -> Option<UtxoEntry>,
) -> Result<i64, RuleError> {
    let params = simnet_params();
    let mut subsidy_cache = SubsidyCache::new(ChainSubsidyParams(&params));
    let (mut prev_header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header");
    prev_header.height = block.header.height - 1;
    let hashes = collect_tx_hashes(&block.transactions);
    view.fetch_input_utxos(block, &hashes, resolver, false);
    check_transactions_and_connect(
        &mut subsidy_cache,
        0,
        i64::from(block.header.height),
        Hash::default(),
        0,
        &prev_header,
        &block.transactions,
        &hashes,
        view,
        None,
        false,
        false,
        false,
        SubsidySplitVariant::Original,
        &params,
    )
}

fn assert_missing_tx_out(result: Result<i64, RuleError>, what: &str) {
    match result {
        Err(e) => assert_eq!(e.kind, RuleErrorKind::MissingTxOut, "{what}: {e:?}"),
        Ok(_) => panic!("{what}: block connected, want ErrMissingTxOut"),
    }
}

/// The external output only; nothing created in the block exists yet.
fn backend(outpoint: &OutPoint) -> Option<UtxoEntry> {
    let (ext, entry) = external();
    (*outpoint == ext).then_some(entry)
}

/// Regular tree `[cb, tx3, tx2, tx4]`: tx3 forward-references tx2:0
/// and tx4 legitimately spends tx2:`later`.
fn forward_reference_block(later: u32) -> (MsgBlock, MsgTx) {
    let (ext, _) = external();
    let tx2 = tx(vec![input(ext, 5 * OUT_VALUE, 50, 1)], 2);
    let tx3 = tx(vec![input(op(&tx2, 0), OUT_VALUE, HEIGHT, 2)], 1);
    let tx4 = tx(vec![input(op(&tx2, later), OUT_VALUE, HEIGHT, 2)], 1);
    let block = block(HEIGHT, vec![coinbase(HEIGHT, 0), tx3, tx2.clone(), tx4]);
    (block, tx2)
}

#[test]
fn forward_reference_is_resolved_from_the_backend() {
    // dcrd queues tx3's tx2:0, tx4's in-flight add then puts an output
    // of tx2 into the view, and FetchEntries resets the queued outpoint
    // to the backend's nil either way.
    for later in [0, 1] {
        let (block, tx2) = forward_reference_block(later);
        let hashes = collect_tx_hashes(&block.transactions);
        let mut view = UtxoView::new();
        view.fetch_input_utxos(&block, &hashes, &backend, false);
        assert!(
            view.lookup_entry(&op(&tx2, 0)).is_none(),
            "later spend of tx2:{later}: the forward-referenced tx2:0 must resolve to nil"
        );
    }
}

#[test]
fn forward_reference_rejected_with_missing_tx_out() {
    for later in [0, 1] {
        let (block, _) = forward_reference_block(later);
        let mut view = UtxoView::new();
        assert_missing_tx_out(
            connect(&mut view, &block, &backend),
            &format!("forward reference to tx2:0, later spend of tx2:{later}"),
        );
    }
}

#[test]
fn in_flight_reference_adds_only_the_referenced_output() {
    // [cb, tx2, tx4] with tx4 spending tx2:1: only tx2:1 enters the
    // view; tx2:0 is neither added nor fetched.
    let (ext, _) = external();
    let tx2 = tx(vec![input(ext, 5 * OUT_VALUE, 50, 1)], 2);
    let tx4 = tx(vec![input(op(&tx2, 1), OUT_VALUE, HEIGHT, 1)], 1);
    let block = block(HEIGHT, vec![coinbase(HEIGHT, 0), tx2.clone(), tx4]);
    let hashes = collect_tx_hashes(&block.transactions);
    let mut view = UtxoView::new();
    view.fetch_input_utxos(&block, &hashes, &backend, false);
    assert!(
        view.lookup_entry(&op(&tx2, 1)).is_some(),
        "tx2:1 is referenced"
    );
    assert!(view.lookup_entry(&op(&tx2, 0)).is_none(), "tx2:0 is not");

    // The same block is valid and connects.
    let mut view = UtxoView::new();
    connect(&mut view, &block, &backend).expect("valid in-block spend");
}

/// Parent `P = [cbP, T1]` with T1 spending the external output into
/// two outputs, plus the view state dcrd's disconnect of a disapproved
/// P leaves behind: both of T1's outputs spent, the external output
/// restored.
fn disapproved_parent() -> (UtxoView, MsgTx, impl Fn(&OutPoint) -> Option<UtxoEntry>) {
    let (ext, ext_entry) = external();
    let t1 = tx(vec![input(ext, 5 * OUT_VALUE, 50, 1)], 2);
    let parent = block(HEIGHT - 1, vec![coinbase(HEIGHT - 1, 1), t1.clone()]);

    // After P connected, the backend holds T1's outputs and no longer
    // holds the external output P spent.
    let t1_hash = t1.tx_hash();
    let resolver = move |outpoint: &OutPoint| {
        (outpoint.hash == t1_hash && outpoint.index < 2).then(|| {
            UtxoEntry::new(
                OUT_VALUE,
                SCRIPT.to_vec(),
                HEIGHT - 1,
                1,
                0,
                false,
                false,
                TxType::Regular,
                None,
            )
        })
    };
    let stxos = vec![SpentTxOut {
        amount: ext_entry.amount(),
        pk_script: ext_entry.pk_script().to_vec(),
        ticket_min_outs: None,
        block_height: 50,
        block_index: 1,
        script_version: 0,
        packed_flags: 0,
    }];
    let mut view = UtxoView::new();
    view.disconnect_disapproved_block(&parent, &stxos, &resolver, false)
        .expect("disconnect disapproved parent");
    assert!(
        view.lookup_entry(&op(&t1, 1))
            .expect("T1:1 in view")
            .is_spent()
    );
    (view, t1, resolver)
}

#[test]
fn disapproved_parent_output_stays_spent_for_a_forward_reference() {
    // N re-includes T1 and has regular tree [cb, T0, T1, T2]: T2 spends
    // T1:0 legitimately and T0 forward-references T1:1.  dcrd restores
    // only T1:0, so T0 finds the spent entry the disapproval left.
    let (mut view, t1, resolver) = disapproved_parent();
    let t0 = tx(vec![input(op(&t1, 1), OUT_VALUE, HEIGHT, 2)], 1);
    let t2 = tx(vec![input(op(&t1, 0), OUT_VALUE, HEIGHT, 2)], 1);
    let block = block(HEIGHT, vec![coinbase(HEIGHT, 0), t0, t1.clone(), t2]);
    assert_missing_tx_out(
        connect(&mut view, &block, &resolver),
        "forward reference to a disapproved parent's output",
    );
}

#[test]
fn disapproved_parent_transaction_can_be_reincluded() {
    // The control: re-including T1 and spending its output later in
    // the block is valid.
    let (mut view, t1, resolver) = disapproved_parent();
    let t2 = tx(vec![input(op(&t1, 0), OUT_VALUE, HEIGHT, 1)], 1);
    let block = block(HEIGHT, vec![coinbase(HEIGHT, 0), t1, t2]);
    connect(&mut view, &block, &resolver).expect("re-included transaction connects");
}
