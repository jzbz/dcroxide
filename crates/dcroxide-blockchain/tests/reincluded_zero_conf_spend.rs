// SPDX-License-Identifier: ISC
//! A block that disapproves its parent, reincludes a transaction of the
//! parent's regular tree and spends an output of it later in its own
//! regular tree.  This is the shape of dcrd's disapproval scenario s4
//! (`internal/blockchain/utxoviewpoint_test.go:443-477` at `382ff4dd`),
//! which checks that the reincluded transaction's input and the spent
//! output are not spendable afterwards and the spending transaction's
//! output is.
//!
//! Since `2115b56b` dcrd decides which in-block spends may bypass cache
//! updates when the block's inputs are fetched.  Such a spend must
//! exist in the view alone, which is only guaranteed for outputs the
//! creating transaction newly creates, so an output is eligible only
//! when the view holds none of its transaction's regular outputs at
//! that moment (`utxoviewpoint.go:1161-1183`).  The undo of the
//! disapproved parent runs first and puts every output of the parent's
//! transactions in the view (`utxoviewpoint.go:444-503`), so the
//! reincluded transaction is not eligible, the spend is an ordinary
//! one, and the commit hands it to the cache's spend
//! (`UtxoCache.spendEntry`, `utxocache.go:323-420`), which removes the
//! parent's copy of the output.
//!
//! The chain is one without a database, its cache committed to as
//! dcrd's `UtxoCache.Commit` is; each block's view is built as
//! `checkConnectBlock` builds it, the undo of a disapproved parent
//! first, then the fetch, then `checkTransactionsAndConnect`.

// Test-harness arithmetic over small fixed amounts and heights.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::chainio::SpentTxOut;
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::utxoview::{UtxoView, collect_tx_hashes};
use dcroxide_blockchain::validate::check_transactions_and_connect;
use dcroxide_blockchain::{UTXO_STATE_MODIFIED, UtxoEntry};
use dcroxide_chaincfg::simnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_stake::TxType;
use dcroxide_standalone::{SubsidyCache, SubsidySplitVariant};
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint, TxIn, TxOut};

/// The height of the disapproving block N; its parent P is one below.
const HEIGHT: u32 = 100;
/// Every output pays this much to an anyone-can-spend script.
const OUT_VALUE: i64 = 1_000;
const SCRIPT: [u8; 1] = [0x51]; // OP_TRUE

/// The output T1 spends, confirmed long before P.
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
/// output of `value` created at `height` by the transaction at `index`
/// of its block.
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
    let mut cache = SubsidyCache::new(&params);
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

/// A block at `height` whose vote bits approve its parent when
/// `approves_parent` is set and disapprove it otherwise.
fn block(height: u32, approves_parent: bool, transactions: Vec<MsgTx>) -> MsgBlock {
    let (mut header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header");
    header.height = height;
    header.vote_bits = u16::from(approves_parent);
    MsgBlock {
        header,
        transactions,
        stransactions: Vec::new(),
    }
}

/// Load the block's inputs into `view` through the chain's utxo cache
/// and run dcrd's `checkTransactionsAndConnect` over its regular tree,
/// collecting the block's spend journal.
fn connect(
    chain: &Chain,
    view: &mut UtxoView,
    block: &MsgBlock,
) -> Result<Vec<SpentTxOut>, dcroxide_blockchain::RuleError> {
    let params = simnet_params();
    let mut subsidy_cache = SubsidyCache::new(&params);
    let (mut prev_header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header");
    prev_header.height = block.header.height - 1;
    let hashes = collect_tx_hashes(&block.transactions);
    let resolver = |outpoint: &OutPoint| chain.fetch_utxo_entry(outpoint);
    view.fetch_input_utxos(block, &hashes, &resolver, false);
    let mut stxos = Vec::new();
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
        Some(&mut stxos),
        false,
        false,
        false,
        SubsidySplitVariant::Original,
        &params,
    )?;
    Ok(stxos)
}

/// Whether the chain's utxo set holds `outpoint` unspent.
fn unspent(chain: &Chain, outpoint: &OutPoint) -> bool {
    chain
        .fetch_utxo_entry(outpoint)
        .is_some_and(|entry| !entry.is_spent())
}

#[test]
fn an_output_of_a_reincluded_transaction_spent_in_the_disapproving_block_leaves_the_set() {
    let params = simnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);

    // The utxo set before P holds only the external output.
    let (ext, mut ext_entry) = external();
    ext_entry.set_state_bits(UTXO_STATE_MODIFIED);
    let mut seed = UtxoView::new();
    seed.insert_entry(&ext, ext_entry);
    chain.commit_view(&mut seed);

    // P = [cbP, T1] confirms T1, which spends the external output
    // into two outputs.
    let t1 = tx(vec![input(ext, 5 * OUT_VALUE, 50, 1)], 2);
    let parent = block(HEIGHT - 1, true, vec![coinbase(HEIGHT - 1, 1), t1.clone()]);
    let mut view = UtxoView::new();
    let parent_stxos = connect(&chain, &mut view, &parent).expect("P connects");
    chain.commit_view(&mut view);
    assert!(unspent(&chain, &op(&t1, 0)), "P created T1:0");
    assert!(!unspent(&chain, &ext), "P spent the external output");

    // N disapproves P and has regular tree [cbN, T1, T2]: T1 is
    // reincluded and T2 spends T1:0 later in the same block.
    let t2 = tx(vec![input(op(&t1, 0), OUT_VALUE, HEIGHT, 1)], 1);
    let child = block(
        HEIGHT,
        false,
        vec![coinbase(HEIGHT, 0), t1.clone(), t2.clone()],
    );
    let mut view = UtxoView::new();
    {
        let resolver = |outpoint: &OutPoint| chain.fetch_utxo_entry(outpoint);
        view.disconnect_disapproved_block(&parent, &parent_stxos, &resolver, false)
            .expect("disconnect the disapproved parent");
    }
    let child_stxos = connect(&chain, &mut view, &child).expect("N connects");
    assert_eq!(
        child_stxos.len(),
        2,
        "N spends the external output and T1:0"
    );
    let t1_out0 = view.lookup_entry(&op(&t1, 0)).expect("T1:0 in the view");
    assert!(
        t1_out0.is_spent() && !t1_out0.is_spent_by_zero_conf(),
        "the undo of P put T1's outputs in the view before the fetch, so \
         the spend of the reincluded T1:0 is not a zero-confirmation spend"
    );
    chain.commit_view(&mut view);

    // T2 spent T1:0 in N, so the set no longer holds it.
    assert!(!unspent(&chain, &op(&t1, 0)), "T1:0 was spent by T2 in N");
    assert!(unspent(&chain, &op(&t1, 1)), "T1:1 is created by N");
    assert!(unspent(&chain, &op(&t2, 0)), "T2:0 is created by N");
    assert!(!unspent(&chain, &ext), "N's T1 spends the external output");

    // A later block spending T1:0 finds no such output.
    let t3 = tx(vec![input(op(&t1, 0), OUT_VALUE, HEIGHT - 1, 1)], 1);
    let grandchild = block(HEIGHT + 1, true, vec![coinbase(HEIGHT + 1, 2), t3]);
    let mut view = UtxoView::new();
    let err = connect(&chain, &mut view, &grandchild).expect_err("T1:0 is not spendable");
    assert_eq!(err.kind, dcroxide_blockchain::RuleErrorKind::MissingTxOut);
}
