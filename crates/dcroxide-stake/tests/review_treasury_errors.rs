// SPDX-License-Identifier: ISC
//! Port of dcrd's `blockchain/stake/treasury_test.go` tables at the
//! parity pin (b9634e01): `TestTreasuryIsFunctions`,
//! `TestTreasurySpendErrors`, `TestTreasuryAddErrors` and
//! `TestTreasuryBaseErrors`, each a small edit of one valid base
//! transaction checked for the exact error kind and for the `Is*`
//! classification refusing it.
//!
//! `dcrd_vectors.rs` replays staketx_test.go only, and until the
//! 2026-09-25 review the stake differential never edited an input's
//! signature script, so nothing pinned the TSpend strict compressed
//! public key rule (`ErrTSpendInvalidPubkey`, `treasury.go:190-194`): a
//! check loosened to take a 0x06 prefix would classify as TSpend a
//! transaction dcrd calls regular, with every other test still passing.
//! This port pins it without the oracle.  dcrd's random OP_RETURN
//! payloads are fixed bytes here; the checks read only their shape.

// Test-harness arithmetic over fixed fixtures.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_chaincfg::{Params, regnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_stake::{
    ErrorKind, RuleError, check_tadd, check_treasury_base, check_tspend, is_stake_base, is_tadd,
    is_treasury_base, is_tspend,
};
use dcroxide_testutil::unhex;
use dcroxide_txscript::stdaddr;
use dcroxide_txscript::{
    OP_DATA_11, OP_DATA_12, OP_DATA_33, OP_DATA_34, OP_DATA_64, OP_DATA_65, OP_RETURN,
    OP_SSTXCHANGE, OP_TADD, OP_TGEN, OP_TRUE, OP_TSPEND,
};
use dcroxide_wire::{
    MAX_PREV_OUT_INDEX, MAX_TX_IN_SEQUENCE_NUM, MsgTx, NULL_BLOCK_HEIGHT, NULL_BLOCK_INDEX,
    OutPoint, TX_TREE_REGULAR, TX_TREE_STAKE, TxIn, TxOut,
};

/// dcrd's `wire.TxVersionTreasury`.
const TX_VERSION_TREASURY: u16 = 3;

/// The serialized compressed public key of dcrd's tests (`publicKey`).
fn public_key() -> Vec<u8> {
    unhex("02a4f64586e172c3d9a20cfa6c7ac8fb12f0115b3f69c3c35aec933a4c47c7d92c")
}

/// dcrd's `validSignature`.
fn valid_signature() -> Vec<u8> {
    unhex(
        "776984f68313b1ac629e624af0595bdc09d8ded02bc2b29fbdb39595e03ac8b0\
         cf818ca536723e6390d3084e0e31c7942229153ce34d873929b16088d9e1af43",
    )
}

/// A canonical data push, as dcrd's `ScriptBuilder.AddData` makes one
/// for the lengths these tests use (none empty, none over 75 bytes).
fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    assert!(!data.is_empty() && data.len() <= 75, "direct push only");
    script.push(data.len() as u8);
    script.extend_from_slice(data);
}

/// dcrd's `opReturnScript`.
fn op_return_script(data: &[u8]) -> Vec<u8> {
    let mut script = vec![OP_RETURN];
    push_data(&mut script, data);
    script
}

/// dcrd's `treasurySpendSignature`: the signature, the public key and
/// OP_TSPEND.  An empty public key adds `OP_0`, as `AddData(nil)` does.
fn treasury_spend_signature(sig: &[u8], pub_key: &[u8]) -> Vec<u8> {
    let mut script = Vec::new();
    push_data(&mut script, sig);
    if pub_key.is_empty() {
        script.push(0x00);
    } else {
        push_data(&mut script, pub_key);
    }
    script.push(OP_TSPEND);
    script
}

fn new_tx_out(value: i64, version: u16, pk_script: Vec<u8>) -> TxOut {
    TxOut {
        value,
        version,
        pk_script,
    }
}

/// A treasury transaction as `wire.NewMsgTx` with the treasury version.
fn treasury_tx() -> MsgTx {
    MsgTx {
        version: TX_VERSION_TREASURY,
        ..MsgTx::default()
    }
}

/// The input dcrd's treasury base and treasury spend have: no previous
/// output.
fn null_input(value_in: i64, signature_script: Vec<u8>) -> TxIn {
    TxIn {
        previous_out_point: OutPoint {
            hash: Hash::ZERO,
            index: MAX_PREV_OUT_INDEX,
            tree: TX_TREE_REGULAR,
        },
        sequence: MAX_TX_IN_SEQUENCE_NUM,
        value_in,
        block_height: NULL_BLOCK_HEIGHT,
        block_index: NULL_BLOCK_INDEX,
        signature_script,
    }
}

/// dcrd's `p2shOpTrueAddr`: pay-to-script-hash of `OP_TRUE` on regnet.
fn p2sh_op_true_addr(params: &Params) -> stdaddr::Address {
    stdaddr::new_address_script_hash_v0(&[OP_TRUE], params).expect("p2sh address")
}

/// dcrd's `baseTreasuryAddTx`: a treasury add with a change output.
fn base_treasury_add_tx(params: &Params) -> MsgTx {
    let (change_ver, change_script) = p2sh_op_true_addr(params)
        .stake_change_script()
        .expect("stake address");
    let mut tx = treasury_tx();
    tx.tx_in.push(TxIn::default());
    tx.tx_out.push(new_tx_out(0, 0, vec![OP_TADD]));
    tx.tx_out.push(new_tx_out(1, change_ver, change_script));
    tx
}

/// dcrd's `baseTreasuryBaseTx`, with a fixed height and payload.
fn base_treasury_base_tx() -> MsgTx {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&0x0123_4567u32.to_le_bytes());
    data.extend_from_slice(&0x89ab_cdef_0123_4567u64.to_le_bytes());
    let mut tx = treasury_tx();
    tx.tx_in.push(null_input(0, Vec::new()));
    tx.tx_out.push(new_tx_out(0, 0, vec![OP_TADD]));
    tx.tx_out.push(new_tx_out(0, 0, op_return_script(&data)));
    tx
}

/// dcrd's `baseTreasurySpendTx`: a treasury spend paying a p2sh script,
/// with a fixed OP_RETURN payload.
fn base_treasury_spend_tx(params: &Params) -> MsgTx {
    const PAYOUT: i64 = 100_000_000;
    const FEE: i64 = 5000;
    let (payout_ver, payout_script) = p2sh_op_true_addr(params)
        .pay_from_treasury_script()
        .expect("stake address");
    let mut data = vec![0x5a; 32];
    data[..8].copy_from_slice(&(PAYOUT as u64).to_le_bytes());
    let mut tx = treasury_tx();
    tx.tx_in.push(null_input(
        FEE + PAYOUT,
        treasury_spend_signature(&valid_signature(), &public_key()),
    ));
    tx.tx_out.push(new_tx_out(0, 0, op_return_script(&data)));
    tx.tx_out.push(new_tx_out(0, payout_ver, payout_script));
    tx
}

/// dcrd's p2pk payout: the payment script to `publicKey` with an OP_TGEN
/// prefix, which no standard method builds since it is invalid.
fn tgen_p2pk_payout(params: &Params) -> (u16, Vec<u8>) {
    let addr = stdaddr::new_address_pub_key_ecdsa_secp256k1_v0_raw(&public_key(), params)
        .expect("p2pk address");
    let (ver, pay_script) = addr.payment_script();
    let mut script = Vec::with_capacity(pay_script.len() + 1);
    script.push(OP_TGEN);
    script.extend_from_slice(&pay_script);
    (ver, script)
}

fn kind<T>(result: Result<T, RuleError>) -> Option<ErrorKind> {
    result.err().map(|e| e.kind)
}

#[test]
fn treasury_is_functions() {
    let params = regnet_params();

    // A stakebase that passes the stakebase checks but is not a TADD.
    let tadd_from_user_with_op_return = {
        const VOTE_SUBSIDY: i64 = 100_000_000;
        const TICKET_PRICE: i64 = 200_000_000;
        let mut tx = base_treasury_base_tx();
        tx.tx_in[0].value_in = VOTE_SUBSIDY;
        tx.tx_in[0].signature_script = params.stake_base_sig_script.clone();
        tx.tx_in.push(TxIn {
            previous_out_point: OutPoint {
                hash: Hash::ZERO,
                index: 0,
                tree: TX_TREE_STAKE,
            },
            sequence: MAX_TX_IN_SEQUENCE_NUM,
            value_in: TICKET_PRICE,
            block_height: NULL_BLOCK_HEIGHT,
            block_index: NULL_BLOCK_INDEX,
            signature_script: vec![OP_TRUE],
        });
        assert!(
            is_stake_base(&tx),
            "transaction does not pass stakebase checks"
        );
        tx
    };

    let tspend_p2pkh = {
        let pk_hash = stdaddr::hash160(&public_key());
        let addr = stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(&pk_hash, &params)
            .expect("p2pkh address");
        let (ver, script) = addr.pay_from_treasury_script().expect("stake address");
        let mut tx = base_treasury_spend_tx(&params);
        tx.tx_out[1].version = ver;
        tx.tx_out[1].pk_script = script;
        tx
    };

    let tspend_p2pk = {
        let (ver, script) = tgen_p2pk_payout(&params);
        let mut tx = base_treasury_spend_tx(&params);
        tx.tx_out[1].version = ver;
        tx.tx_out[1].pk_script = script;
        tx
    };

    let tadd_no_change = {
        let mut tx = base_treasury_add_tx(&params);
        tx.tx_out.truncate(1);
        tx
    };

    // (name, tx, treasury add, treasury base, treasury spend)
    let tests: [(&str, MsgTx, bool, bool, bool); 7] = [
        (
            "treasury add from user with change",
            base_treasury_add_tx(&params),
            true,
            false,
            false,
        ),
        (
            "treasury add from user with no change",
            tadd_no_change,
            true,
            false,
            false,
        ),
        (
            "treasury add from user with OP_RETURN",
            tadd_from_user_with_op_return,
            false,
            false,
            false,
        ),
        (
            "treasury add from treasurybase",
            base_treasury_base_tx(),
            false,
            true,
            false,
        ),
        (
            "treasury spend p2sh",
            base_treasury_spend_tx(&params),
            false,
            false,
            true,
        ),
        ("treasury spend p2pkh", tspend_p2pkh, false, false, true),
        (
            "treasury spend invalid output 1 p2pk (not p2sh/p2pkh)",
            tspend_p2pk,
            false,
            false,
            false,
        ),
    ];
    for (name, tx, tadd, tbase, tspend) in &tests {
        assert_eq!(is_tadd(tx), *tadd, "{name}: treasury add");
        assert_eq!(is_treasury_base(tx), *tbase, "{name}: treasurybase");
        assert_eq!(is_tspend(tx), *tspend, "{name}: treasury spend");
    }
}

#[test]
fn treasury_spend_errors() {
    let params = regnet_params();
    let base = || base_treasury_spend_tx(&params);
    let with = |edit: &dyn Fn(&mut MsgTx)| {
        let mut tx = base();
        edit(&mut tx);
        tx
    };

    let tests: Vec<(&str, MsgTx, ErrorKind)> = vec![
        (
            "treasury spend invalid tx version",
            with(&|tx| tx.version = 1),
            ErrorKind::TSpendInvalidTxVersion,
        ),
        (
            "treasury spend with invalid num inputs",
            with(&|tx| tx.tx_in.clear()),
            ErrorKind::TSpendInvalidLength,
        ),
        (
            "treasury spend with invalid num outputs",
            with(&|tx| tx.tx_out.clear()),
            ErrorKind::TSpendInvalidLength,
        ),
        (
            "treasury spend with an invalid script version",
            with(&|tx| tx.tx_out[1].version = 1),
            ErrorKind::TSpendInvalidVersion,
        ),
        (
            "treasury spend with invalid output - no pubkey script",
            with(&|tx| tx.tx_out[1].pk_script.clear()),
            ErrorKind::TSpendInvalidScriptLength,
        ),
        (
            "treasury spend invalid input sig script - wrong script length",
            with(&|tx| {
                tx.tx_in[0].signature_script = treasury_spend_signature(&valid_signature(), &[]);
            }),
            ErrorKind::TSpendInvalidScript,
        ),
        (
            "treasury spend input sig script invalid - wrong sig len",
            with(&|tx| {
                let sig = &mut tx.tx_in[0].signature_script;
                assert_eq!(sig[0], OP_DATA_64, "signature script format changed");
                sig[0] = OP_DATA_65;
            }),
            ErrorKind::TSpendInvalidScript,
        ),
        (
            "treasury spend input sig script invalid - wrong pubkey len",
            with(&|tx| {
                let sig = &mut tx.tx_in[0].signature_script;
                assert_eq!(sig[65], OP_DATA_33, "signature script format changed");
                sig[65] = OP_DATA_34;
            }),
            ErrorKind::TSpendInvalidScript,
        ),
        (
            "treasury spend input sig invalid - wrong opcode for OP_TSPEND",
            with(&|tx| {
                let sig = &mut tx.tx_in[0].signature_script;
                let last = sig.len() - 1;
                assert_eq!(sig[last], OP_TSPEND, "signature script format changed");
                sig[last] = OP_RETURN;
            }),
            ErrorKind::TSpendInvalidScript,
        ),
        (
            "treasury spend input sig invalid - no tspend opcode",
            with(&|tx| {
                tx.tx_in[0].signature_script.pop();
            }),
            ErrorKind::TSpendInvalidScript,
        ),
        (
            "treasury spend input sig invalid - two tspend opcodes",
            with(&|tx| tx.tx_in[0].signature_script.push(OP_TSPEND)),
            ErrorKind::TSpendInvalidScript,
        ),
        (
            "treasury spend input sig invalid - trailing data",
            with(&|tx| tx.tx_in[0].signature_script.push(0x01)),
            ErrorKind::TSpendInvalidScript,
        ),
        (
            "treasury spend input sig script invalid - bad pubkey type",
            with(&|tx| {
                let mut pub_key = public_key();
                pub_key[0] |= 0x04;
                tx.tx_in[0].signature_script =
                    treasury_spend_signature(&valid_signature(), &pub_key);
            }),
            ErrorKind::TSpendInvalidPubkey,
        ),
        (
            "treasury spend invalid - extra empty output",
            with(&|tx| tx.tx_out.push(TxOut::default())),
            ErrorKind::TSpendInvalidScriptLength,
        ),
        (
            "treasury spend invalid OP_RETURN output - short one byte",
            with(&|tx| {
                tx.tx_out[0].pk_script.pop();
            }),
            ErrorKind::TSpendInvalidTransaction,
        ),
        (
            "treasury spend payment output - wrong opcode for OP_TGEN",
            with(&|tx| {
                assert_eq!(
                    tx.tx_out[1].pk_script[0], OP_TGEN,
                    "payment output format changed"
                );
                tx.tx_out[1].pk_script[0] = OP_RETURN;
            }),
            ErrorKind::TSpendInvalidTGen,
        ),
        (
            "treasury spend payment output - unsupported p2pk",
            with(&|tx| {
                let (ver, script) = tgen_p2pk_payout(&params);
                tx.tx_out[1].version = ver;
                tx.tx_out[1].pk_script = script;
            }),
            ErrorKind::TSpendInvalidSpendScript,
        ),
    ];

    assert!(
        is_tspend(&base()),
        "the base transaction is a treasury spend"
    );
    for (name, tx, expected) in &tests {
        assert_eq!(kind(check_tspend(tx)), Some(*expected), "{name}");
        assert!(
            !is_tspend(tx),
            "{name}: IsTSpend claimed an invalid treasury spend is valid"
        );
    }
}

#[test]
fn treasury_add_errors() {
    let params = regnet_params();
    let base = || base_treasury_add_tx(&params);
    let with = |edit: &dyn Fn(&mut MsgTx)| {
        let mut tx = base();
        edit(&mut tx);
        tx
    };

    let tests: Vec<(&str, MsgTx, ErrorKind)> = vec![
        (
            "treasury add invalid tx version",
            with(&|tx| tx.version = 1),
            ErrorKind::TAddInvalidTxVersion,
        ),
        (
            "treasury add invalid num outputs - none",
            with(&|tx| tx.tx_out.clear()),
            ErrorKind::TAddInvalidCount,
        ),
        (
            "treasury add invalid num outputs - two change outputs",
            with(&|tx| {
                let change = tx.tx_out[1].clone();
                tx.tx_out.push(change);
            }),
            ErrorKind::TAddInvalidCount,
        ),
        (
            "treasury add invalid num inputs - none",
            with(&|tx| tx.tx_in.clear()),
            ErrorKind::TAddInvalidCount,
        ),
        (
            "treasury add with invalid output - bad script version",
            with(&|tx| tx.tx_out[0].version = 1),
            ErrorKind::TAddInvalidVersion,
        ),
        (
            "treasury add with invalid output - missing script",
            with(&|tx| tx.tx_out[0].pk_script.clear()),
            ErrorKind::TAddInvalidScriptLength,
        ),
        (
            "treasury add with invalid output - extra trailing byte",
            with(&|tx| tx.tx_out[0].pk_script.push(OP_TRUE)),
            ErrorKind::TAddInvalidLength,
        ),
        (
            "treasury add with invalid output - wrong opcode for OP_TADD",
            with(&|tx| {
                assert_eq!(
                    tx.tx_out[0].pk_script[0], OP_TADD,
                    "public key script format changed"
                );
                tx.tx_out[0].pk_script[0] = OP_TSPEND;
            }),
            ErrorKind::TAddInvalidOpcode,
        ),
        (
            "treasury add with invalid output - wrong opcode for change",
            with(&|tx| {
                assert_eq!(
                    tx.tx_out[1].pk_script[0], OP_SSTXCHANGE,
                    "public key script format changed"
                );
                tx.tx_out[1].pk_script.remove(0);
            }),
            ErrorKind::TAddInvalidChange,
        ),
    ];

    assert!(is_tadd(&base()), "the base transaction is a treasury add");
    for (name, tx, expected) in &tests {
        assert_eq!(kind(check_tadd(tx)), Some(*expected), "{name}");
        assert!(
            !is_tadd(tx),
            "{name}: IsTAdd claimed an invalid tadd is valid"
        );
    }
}

#[test]
fn treasury_base_errors() {
    let base = base_treasury_base_tx;
    let with = |edit: &dyn Fn(&mut MsgTx)| {
        let mut tx = base();
        edit(&mut tx);
        tx
    };

    let tests: Vec<(&str, MsgTx, ErrorKind)> = vec![
        (
            "treasurybase invalid tx version",
            with(&|tx| tx.version = 1),
            ErrorKind::TreasuryBaseInvalidTxVersion,
        ),
        (
            "treasurybase invalid num inputs - none",
            with(&|tx| tx.tx_in.clear()),
            ErrorKind::TreasuryBaseInvalidCount,
        ),
        (
            "treasurybase invalid num outputs - none",
            with(&|tx| tx.tx_out.clear()),
            ErrorKind::TreasuryBaseInvalidCount,
        ),
        (
            "treasurybase invalid num outputs - extra outupt",
            with(&|tx| tx.tx_out.push(new_tx_out(1, 0, vec![OP_TRUE]))),
            ErrorKind::TreasuryBaseInvalidCount,
        ),
        (
            "treasurybase invalid input 0 - non-empty signature script",
            with(&|tx| tx.tx_in[0].signature_script = vec![OP_TRUE]),
            ErrorKind::TreasuryBaseInvalidLength,
        ),
        (
            "treasurybase invalid output - bad script version",
            with(&|tx| tx.tx_out[1].version = 2),
            ErrorKind::TreasuryBaseInvalidVersion,
        ),
        (
            "treasurybase invalid output 0 - wrong opcode for OP_TADD",
            with(&|tx| {
                assert_eq!(
                    tx.tx_out[0].pk_script[0], OP_TADD,
                    "public key script format changed"
                );
                tx.tx_out[0].pk_script[0] = OP_TSPEND;
            }),
            ErrorKind::TreasuryBaseInvalidOpcode0,
        ),
        (
            "treasurybase invalid output 0 - extra trailing byte",
            with(&|tx| tx.tx_out[0].pk_script.push(OP_TRUE)),
            ErrorKind::TreasuryBaseInvalidOpcode0,
        ),
        (
            "treasurybase invalid output 1 - wrong opcode for OP_RETURN",
            with(&|tx| {
                assert_eq!(
                    tx.tx_out[1].pk_script[0], OP_RETURN,
                    "public key script format changed"
                );
                tx.tx_out[1].pk_script[0] = OP_TADD;
            }),
            ErrorKind::TreasuryBaseInvalidOpcode1,
        ),
        (
            "treasurybase invalid output 1 - extra trailing byte",
            with(&|tx| tx.tx_out[1].pk_script.push(OP_TRUE)),
            ErrorKind::TreasuryBaseInvalidOpcode1,
        ),
        (
            "treasurybase invalid output 1 - wrong data push size",
            with(&|tx| {
                assert_eq!(
                    tx.tx_out[1].pk_script[1], OP_DATA_12,
                    "public key script format changed"
                );
                tx.tx_out[1].pk_script[1] = OP_DATA_11;
            }),
            ErrorKind::TreasuryBaseInvalidOpcode1,
        ),
        (
            "treasurybase invalid input 0 - non-null hash",
            with(&|tx| tx.tx_in[0].previous_out_point.hash.0[0] = 0x01),
            ErrorKind::TreasuryBaseInvalid,
        ),
        (
            "treasurybase invalid input 0 - wrong prev index",
            with(&|tx| tx.tx_in[0].previous_out_point.index = 1),
            ErrorKind::TreasuryBaseInvalid,
        ),
        (
            "treasurybase invalid input 0 - wrong prev tree",
            with(&|tx| tx.tx_in[0].previous_out_point.tree = TX_TREE_STAKE),
            ErrorKind::TreasuryBaseInvalid,
        ),
    ];

    assert!(
        is_treasury_base(&base()),
        "the base transaction is a treasurybase"
    );
    for (name, tx, expected) in &tests {
        assert_eq!(kind(check_treasury_base(tx)), Some(*expected), "{name}");
        assert!(
            !is_treasury_base(tx),
            "{name}: IsTreasuryBase claimed an invalid treasury base is valid"
        );
    }
}
