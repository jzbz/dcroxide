// SPDX-License-Identifier: ISC
//! Error texts that block processing and template checks return, pinned
//! to dcrd's own output at `6f6cf21b`.
//!
//! - The amount range failures print `dcrutil.MaxAmount` and the
//!   standalone `maxAtoms`, which are untyped floating-point constants,
//!   so `%v` formats them as a `float64`: `2.1e+15`
//!   (`internal/blockchain/validate.go:3344-3348`, `:3523-3527`,
//!   `:3727-3731`; `blockchain/standalone/tx.go:179-213`).  The battery
//!   texts are those dcrd's `ProcessBlock` returned for `bcb9` and
//!   `bcb10`; the others are those dcrd's `checkTreasurySpendInputs` and
//!   `CheckTransactionInputs` returned for transactions with the same
//!   amounts.
//! - `CheckConnectBlockTemplate` names the tip's parent when it has one,
//!   and has a second form for a tip without one
//!   (`internal/blockchain/validate.go:4665-4675`).  The texts are those
//!   dcrd returned on regnet for the battery's `bfb` with its previous
//!   block replaced, before and after `bfb` was processed.

// Test-harness arithmetic over bounded values.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::validate::{check_transaction_inputs, check_treasury_spend_inputs};
use dcroxide_blockchain::{RuleErrorKind, UtxoEntry};
use dcroxide_chaincfg::regnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_stake::{MAX_AMOUNT, TxType};
use dcroxide_standalone::{SubsidyCache, SubsidySplitVariant};
use dcroxide_testutil::unhex;
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, NULL_VALUE_IN, OutPoint, TxIn, TxOut};

/// The full block battery's rows: name, current time and block.
fn battery() -> Vec<(String, i64, MsgBlock)> {
    let mut now = 0;
    let mut rows = Vec::new();
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let (name, hex) = match f[0] {
            "now" => {
                now = f[1].parse().expect("now");
                continue;
            }
            "accept" => (f[1], f[4]),
            "reject" => (f[1], f[3]),
            "orphanorreject" => (f[1], f[2]),
            _ => continue,
        };
        let (block, _) = MsgBlock::from_bytes(&unhex(hex)).expect("block");
        rows.push((name.to_string(), now, block));
    }
    rows
}

fn input(hash: Hash, index: u32, value_in: i64) -> TxIn {
    TxIn {
        previous_out_point: OutPoint {
            hash,
            index,
            tree: 0,
        },
        value_in,
        ..TxIn::default()
    }
}

fn output(value: i64, pk_script: Vec<u8>) -> TxOut {
    TxOut {
        value,
        version: 0,
        pk_script,
    }
}

/// dcrd's `ProcessBlock` texts for the battery's two amount range
/// rejections, on regnet as shipped.
#[test]
fn battery_amount_range_rejections_carry_dcrds_text() {
    let params = regnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    let mut checked = 0;
    for (name, now, block) in battery() {
        let (_, errs) = chain.process_block(&block, now, &params);
        let want = match name.as_str() {
            "bcb9" => {
                "transaction output value of 2100000000000001 is higher than max allowed value \
                 of 2.1e+15"
            }
            "bcb10" => {
                "total value of all transaction outputs is 2100000000000001 which is higher \
                 than max allowed value of 2.1e+15"
            }
            _ => continue,
        };
        assert_eq!(errs.len(), 1, "{name}: {errs:?}");
        assert_eq!(errs[0].kind, RuleErrorKind::BadTxOutValue, "{name}");
        assert_eq!(errs[0].description, want, "{name}");
        checked += 1;
        if checked == 2 {
            return;
        }
    }
    panic!("bcb9 and bcb10 are in the battery");
}

/// dcrd's `checkTreasurySpendInputs` text for an input value above the
/// maximum amount.
#[test]
fn treasury_spend_input_above_the_maximum_carries_dcrds_text() {
    let tx = MsgTx {
        version: 3,
        tx_in: vec![input(Hash::ZERO, 0, MAX_AMOUNT + 1)],
        tx_out: vec![output(0, vec![0x6a])],
        ..MsgTx::default()
    };
    let err = check_treasury_spend_inputs(&tx).expect_err("above the maximum");
    assert_eq!(err.kind, RuleErrorKind::BadTxInput);
    assert_eq!(
        err.description,
        "treasury spend value of 2100000000000001 is higher than max allowed value of 2.1e+15"
    );
}

/// dcrd's `CheckTransactionInputs` texts for a spent output above the
/// maximum amount and for inputs summing above it.
#[test]
fn transaction_inputs_above_the_maximum_carry_dcrds_text() {
    let params = regnet_params();
    let mut subsidy_cache = SubsidyCache::new(&params);
    let (mut prev_header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header");
    prev_header.height = 199;

    // One source transaction's outputs, at height 100, as dcrd's view
    // held them.
    let src = Hash([0x11; 32]);
    let mut utxos: BTreeMap<u32, UtxoEntry> = BTreeMap::new();
    for (index, amount) in [(0, MAX_AMOUNT + 1), (1, MAX_AMOUNT), (2, 1)] {
        let entry = UtxoEntry::new(
            amount,
            vec![0x51],
            100,
            0,
            0,
            false,
            false,
            TxType::Regular,
            None,
        );
        utxos.insert(index, entry);
    }
    let spend = |indexes: &[u32]| MsgTx {
        version: 1,
        tx_in: indexes
            .iter()
            .map(|i| input(src, *i, NULL_VALUE_IN))
            .collect(),
        tx_out: vec![output(1, vec![0x51])],
        ..MsgTx::default()
    };
    let mut check = |tx: &MsgTx| {
        check_transaction_inputs(
            &mut subsidy_cache,
            tx,
            200,
            |op| (op.hash == src).then(|| utxos.get(&op.index)).flatten(),
            false,
            &params,
            &prev_header,
            false,
            false,
            SubsidySplitVariant::Original,
        )
        .expect_err("above the maximum")
    };

    let err = check(&spend(&[0]));
    assert_eq!(err.kind, RuleErrorKind::BadTxOutValue);
    assert_eq!(
        err.description,
        "transaction output value of 2100000000000001 is higher than max allowed value of \
         2.1e+15"
    );

    let err = check(&spend(&[1, 2]));
    assert_eq!(err.kind, RuleErrorKind::BadTxOutValue);
    assert_eq!(
        err.description,
        "total value of all transaction inputs is 2100000000000001 which is higher than max \
         allowed value of 2.1e+15"
    );
}

/// dcrd's `CheckConnectBlockTemplate` texts for a template that builds
/// on neither the tip nor its parent: with the genesis block as the tip,
/// which has no parent, and then with `bfb` as the tip.
#[test]
fn template_parent_texts_name_the_tips_parent() {
    let params = regnet_params();
    let rows = battery();
    let (_, now, bfb) = rows
        .iter()
        .find(|(name, _, _)| name == "bfb")
        .expect("bfb is in the battery");
    let mut template = bfb.clone();
    template.header.prev_block = Hash([0x55; 32]);
    let genesis = "2ced94b4ae95bba344cfa043268732d230649c640f92dce2d9518823d3057cb0";
    let bogus = "5555555555555555555555555555555555555555555555555555555555555555";

    let mut chain = Chain::new(&params, Hash::ZERO, false);
    assert_eq!(params.genesis_hash.to_string(), genesis);
    let err = chain
        .check_connect_block_template(&template, *now, &params)
        .expect_err("not on the tip");
    assert_eq!(err.kind, RuleErrorKind::InvalidTemplateParent);
    assert_eq!(
        err.description,
        format!("previous block must be the current chain tip {genesis}, but got {bogus}")
    );

    let (_, errs) = chain.process_block(bfb, *now, &params);
    assert!(errs.is_empty(), "bfb: {errs:?}");
    let tip = "680805cdff04a7153821b89a4b2da8f519e9c6f3b0ae3d8920979e13fbaf3585";
    assert_eq!(bfb.header.block_hash().to_string(), tip);
    let err = chain
        .check_connect_block_template(&template, *now, &params)
        .expect_err("not on the tip or its parent");
    assert_eq!(err.kind, RuleErrorKind::InvalidTemplateParent);
    assert_eq!(
        err.description,
        format!(
            "previous block must be the current chain tip {tip} or its parent {genesis}, but \
             got {bogus}"
        )
    );
}
