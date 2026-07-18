// SPDX-License-Identifier: ISC
//! Native pins for the consensus checks dcrd 2.2 introduced where the
//! replayed vector corpora have no covering rows: the revocation
//! null-outpoint rejection in `CheckTransaction` and the treasury
//! spend input battery from `checkTreasurySpendInputs`.

use dcroxide_blockchain::RuleErrorKind;
use dcroxide_blockchain::validate::{AgendaFlags, check_transaction, check_treasury_spend_inputs};
use dcroxide_chaincfg::simnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_testutil::unhex;
use dcroxide_wire::{MsgTx, OutPoint, TxIn, TxOut};

/// A well-formed revocation from the stake-input corpus (two
/// OP_SSRTX-tagged outputs, one ticket input on the stake tree).
const REVOCATION_HEX: &str = "010000000186ec7bdbcfa00df4000000000000000000000000000000000000\
                              0000000000000000000001ffffffff02f011040600000000000018bca9141d\
                              7e609a2e562ff54b9f842c4b73060acd66276387ef1104060000000000001a\
                              bc76a9149ecb04e220e183d6023de24ab3b2afe4b74ce3b288ac0000000000\
                              00000001e123080c00000000000000000000000000";

#[test]
fn revocation_null_outpoint_rejected() {
    let params = simnet_params();
    let (mut tx, _) = MsgTx::from_bytes(&unhex(&REVOCATION_HEX.replace(' ', ""))).expect("tx");

    // The unmutated revocation passes the context checks.
    check_transaction(&tx, &params, AgendaFlags::TREASURY_ENABLED).expect("valid revocation");

    // Null out the ticket reference.  dcrd 2.2 added a dedicated
    // revocation arm for this ("revocation ticket input refers to
    // null previous output"), but it is defense in depth that cannot
    // be reached through `CheckTransaction`: a null outpoint lies on
    // the regular tree while `stake.CheckSSRtx` only classifies
    // transactions whose input is on the stake tree, so the mutated
    // transaction falls out of the revocation type and dcrd rejects
    // it through the general null-input rule instead.  Pin that
    // observable behavior.
    tx.tx_in[0].previous_out_point = OutPoint {
        hash: Hash::ZERO,
        index: u32::MAX,
        tree: 0,
    };
    let err = check_transaction(&tx, &params, AgendaFlags::TREASURY_ENABLED)
        .expect_err("null ticket input");
    assert_eq!(err.kind, RuleErrorKind::BadTxInput);
    assert_eq!(
        err.description,
        "transaction input 0 refers to previous output that is null"
    );
}

/// A minimal treasury-spend shape for `check_treasury_spend_inputs`:
/// one input carrying `value_in` and a first output whose script
/// commits to `commit` in the OP_RETURN amount push.  The function
/// trusts the caller to have classified the transaction, so only the
/// fields it reads need to be well formed.
fn tspend_shape(value_in: i64, commit: i64) -> MsgTx {
    let mut script = vec![0x6a, 0x20]; // OP_RETURN OP_DATA_32
    script.extend_from_slice(&commit.to_le_bytes());
    script.extend_from_slice(&[0u8; 24]);
    let mut tx = MsgTx::default();
    tx.tx_in.push(TxIn {
        value_in,
        ..Default::default()
    });
    tx.tx_out.push(TxOut {
        value: 0,
        version: 0,
        pk_script: script,
    });
    tx
}

#[test]
fn treasury_spend_input_battery() {
    // The input value must match the spend amount commitment.
    check_treasury_spend_inputs(&tspend_shape(1000, 1000)).expect("matching commitment");

    let err = check_treasury_spend_inputs(&tspend_shape(1000, 999)).expect_err("mismatch");
    assert_eq!(err.kind, RuleErrorKind::InvalidTSpendValueIn);
    assert_eq!(
        err.description,
        "treasury spend input value 1000 does not match spend amount commitment 999"
    );

    // Negative and above-max input values are rejected before the
    // commitment comparison.
    let err = check_treasury_spend_inputs(&tspend_shape(-5, -5)).expect_err("negative");
    assert_eq!(err.kind, RuleErrorKind::BadTxInput);
    assert_eq!(err.description, "treasury spend has negative value of -5");

    let over = dcroxide_stake::MAX_AMOUNT + 1;
    let err = check_treasury_spend_inputs(&tspend_shape(over, over)).expect_err("over max");
    assert_eq!(err.kind, RuleErrorKind::BadTxInput);
    assert_eq!(
        err.description,
        format!(
            "treasury spend value of {over} is higher than max allowed value of {}",
            dcroxide_stake::MAX_AMOUNT
        )
    );
}
