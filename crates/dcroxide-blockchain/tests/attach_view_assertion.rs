// SPDX-License-Identifier: ISC
//! The reorganization asserts the view of every block it attaches
//! before it connects the block (dcrd `chain.go:1236-1238`, since
//! `22fd2431`), on the branch that skips validation for a block already
//! marked validated as on the one that validates it.  dcrd's message
//! gives the reason these are assertions rather than errors: there is no
//! recovering from a view that violates them, and processing more blocks
//! over it could corrupt the utxo set.
//!
//! A block marked validated is connected without its inputs being
//! checked, as every block of a bulk import is.  Here such a block
//! spends an output whose fraud proof in the spending input names
//! another amount, height or index than the output has.  dcrd 382ff4dd
//! panics with these texts, and the block's state is not written: the
//! tip stays where it was, and the cache holds nothing of the block.

// Test-harness arithmetic over small fixed amounts and heights.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::UtxoEntry;
use dcroxide_blockchain::blockindex::BlockStatus;
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_chaincfg::{Params, regnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_stake::TxType;
use dcroxide_standalone::{SubsidyCache, SubsidySplitVariant, calc_tx_tree_merkle_root};
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint, TxIn, TxOut};

/// The adjusted time the reorganization runs at.
const NOW: i64 = 2_000_000_000;
const SCRIPT: [u8; 1] = [0x51]; // OP_TRUE

/// The output the block spends: confirmed by the transaction at index 2
/// of the block at height 7, worth 1000.
fn funding() -> (OutPoint, UtxoEntry) {
    let outpoint = OutPoint {
        hash: Hash([0x5a; 32]),
        index: 1,
        tree: 0,
    };
    let entry = UtxoEntry::new(
        1_000,
        SCRIPT.to_vec(),
        7,
        2,
        0,
        false,
        false,
        TxType::Regular,
        None,
    );
    (outpoint, entry)
}

/// A coinbase at `height` with its subsidy committed in its input and a
/// single output.
fn coinbase(params: &Params, height: u32) -> MsgTx {
    let mut cache = SubsidyCache::new(params);
    let h = i64::from(height);
    let subsidy = cache.calc_work_subsidy_v3(h, 0, SubsidySplitVariant::Original)
        + cache.calc_treasury_subsidy(h, 0, false);
    MsgTx {
        tx_in: vec![TxIn {
            previous_out_point: OutPoint {
                hash: Hash::ZERO,
                index: u32::MAX,
                tree: 0,
            },
            sequence: u32::MAX,
            value_in: subsidy,
            block_height: 0,
            block_index: u32::MAX,
            signature_script: vec![0x04, 0x01, 0x02, 0x03, 0x04],
        }],
        tx_out: vec![TxOut {
            value: 500,
            version: 0,
            pk_script: SCRIPT.to_vec(),
        }],
        ..MsgTx::default()
    }
}

/// A chain holding the funding output, and the block on its genesis
/// that spends it with the given fraud proof.
fn chain_and_block(value_in: i64, block_height: u32, block_index: u32) -> (Chain, MsgBlock) {
    let params = regnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    let (outpoint, mut entry) = funding();
    entry.set_state_bits(1); // modified
    let mut seed = UtxoView::new();
    seed.insert_entry(&outpoint, entry);
    chain.commit_view(&mut seed);

    let spend = MsgTx {
        tx_in: vec![TxIn {
            previous_out_point: outpoint,
            sequence: u32::MAX,
            value_in,
            block_height,
            block_index,
            signature_script: Vec::new(),
        }],
        tx_out: vec![TxOut {
            value: 900,
            version: 0,
            pk_script: SCRIPT.to_vec(),
        }],
        ..MsgTx::default()
    };
    let tip = chain.best_chain.tip().expect("genesis");
    let regular = vec![coinbase(&params, 1), spend];
    let (mut header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header");
    header.version = 1;
    header.prev_block = chain.store.node(tip).hash;
    header.merkle_root = calc_tx_tree_merkle_root(&regular);
    header.stake_root = calc_tx_tree_merkle_root(&[]);
    header.vote_bits = 1;
    header.bits = params.pow_limit_bits;
    header.sbits = params.minimum_stake_diff;
    header.height = 1;
    header.timestamp = chain.store.node(tip).timestamp as u32 + 300;
    let mut block = MsgBlock {
        header,
        transactions: regular,
        stransactions: Vec::new(),
    };
    block.header.size = block.serialize_size() as u32;
    (chain, block)
}

/// Hand the block to the chain marked validated, as a bulk import does,
/// and reorganize to it.  Returns the text it panics with, if any.
fn attach(chain: &mut Chain, block: &MsgBlock) -> Option<String> {
    let params = regnet_params();
    let parent = chain
        .index
        .lookup_node(&block.header.prev_block)
        .expect("parent in the block index");
    let node = chain.store.new_node(&block.header, Some(parent));
    chain.index.add_node(&chain.store, node);
    chain
        .index
        .set_status_flags(&mut chain.store, node, BlockStatus::VALIDATED);
    chain
        .maybe_accept_block_data(node, block, true, &params)
        .expect("block data accepted");
    let target = chain.index.find_best_chain_candidate(&chain.store);
    let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let errs = chain.reorganize_chain(target, NOW, &params);
        assert!(errs.is_empty(), "{errs:?}");
    }))
    .err()?;
    Some(
        payload
            .downcast_ref::<String>()
            .cloned()
            .expect("a text payload"),
    )
}

/// Whether the chain holds the block as its tip, and whether it holds
/// the output of the block's spend unspent.
fn written(chain: &Chain, block: &MsgBlock) -> (bool, bool) {
    let tip = chain.best_chain.tip().expect("tip");
    let created = OutPoint {
        hash: block.transactions[1].tx_hash(),
        index: 0,
        tree: 0,
    };
    (
        chain.store.node(tip).hash == block.header.block_hash(),
        chain
            .fetch_utxo_entry(&created)
            .is_some_and(|entry| !entry.is_spent()),
    )
}

#[test]
fn a_validated_block_whose_view_holds_is_connected() {
    let (mut chain, block) = chain_and_block(1_000, 7, 2);
    assert_eq!(attach(&mut chain, &block), None);
    assert_eq!(written(&chain, &block), (true, true));
}

#[test]
fn a_validated_block_whose_inputs_name_another_output_panics_unwritten() {
    let (outpoint, _) = funding();
    for (value_in, height, index, mismatch) in [
        (
            999,
            7,
            2,
            "utxo amount mismatch (entry 1000, input witness 999)",
        ),
        (
            1_000,
            6,
            2,
            "utxo block height mismatch (entry 7, input witness 6)",
        ),
        (
            1_000,
            7,
            3,
            "utxo block index mismatch (entry 2, input witness 3)",
        ),
    ] {
        let (mut chain, block) = chain_and_block(value_in, height, index);
        let spend = block.transactions[1].tx_hash();
        let want = format!(
            "block {} regular tree idx 1: tx {spend}:0 spending input {outpoint} (tree 0): \
             {mismatch}",
            block.header.block_hash()
        );
        assert_eq!(attach(&mut chain, &block), Some(want));
        assert_eq!(written(&chain, &block), (false, false), "{mismatch}");
    }
}
