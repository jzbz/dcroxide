// SPDX-License-Identifier: ISC
//! Focused unit tests ported from dcrd's txscript tests: script number
//! encoding, the builder's canonical selection and size limits, sig-op
//! counting, and script classification helpers.

// Test-harness arithmetic over bounded indices and lengths.
#![allow(clippy::arithmetic_side_effects)]
use dcroxide_txscript::{
    MATH_OP_CODE_MAX_SCRIPT_NUM_LEN, OP_CHECKMULTISIG, OP_CHECKSIG, OP_DUP, OP_EQUAL,
    OP_EQUALVERIFY, OP_HASH160, OP_RETURN, ScriptBuilder, ScriptNum, as_small_int,
    get_precise_sig_op_count, get_sig_op_count, is_pay_to_script_hash, is_push_only_script,
    is_small_int, is_unspendable, make_script_num, opcode_by_name,
};

/// dcrd `scriptnum_test.go` `TestScriptNumBytes` sample encodings.
#[test]
fn script_num_bytes() {
    let cases: &[(i64, &[u8])] = &[
        (0, &[]),
        (1, &[0x01]),
        (-1, &[0x81]),
        (127, &[0x7f]),
        (-127, &[0xff]),
        (128, &[0x80, 0x00]),
        (-128, &[0x80, 0x80]),
        (129, &[0x81, 0x00]),
        (-129, &[0x81, 0x80]),
        (256, &[0x00, 0x01]),
        (-256, &[0x00, 0x81]),
        (32767, &[0xff, 0x7f]),
        (-32767, &[0xff, 0xff]),
        (32768, &[0x00, 0x80, 0x00]),
        (-32768, &[0x00, 0x80, 0x80]),
    ];
    for (val, want) in cases {
        assert_eq!(ScriptNum(*val).bytes(), *want, "encode {val}");
    }
}

/// Minimal-encoding enforcement and range limits (dcrd
/// `TestMakeScriptNum`).
#[test]
fn make_script_num_minimal() {
    // Non-minimal encodings are rejected.
    assert!(make_script_num(&[0x00], 4).is_err());
    assert!(make_script_num(&[0x80], 4).is_err()); // negative zero
    assert!(make_script_num(&[0x7f, 0x00], 4).is_err());
    // Minimal encodings round-trip.
    for &v in &[0i64, 1, -1, 127, 128, -128, 32768, -32768, 2147483647] {
        let bytes = ScriptNum(v).bytes();
        let back = make_script_num(&bytes, 5).expect("decodes");
        assert_eq!(back, ScriptNum(v));
    }
    // Over-length input is rejected.
    assert!(
        make_script_num(
            &[0x01, 0x02, 0x03, 0x04, 0x05],
            MATH_OP_CODE_MAX_SCRIPT_NUM_LEN
        )
        .is_err()
    );
}

/// The builder chooses canonical opcodes and enforces the max element size
/// (dcrd `scriptbuilder_test.go`).
#[test]
fn builder_canonical_and_limits() {
    // Small integers use their dedicated opcodes.
    let script = ScriptBuilder::new()
        .add_int64(0)
        .add_int64(1)
        .add_int64(16)
        .add_int64(17)
        .script()
        .expect("builds");
    // OP_0, OP_1, OP_16, then OP_DATA_1 0x11.
    assert_eq!(script, vec![0x00, 0x51, 0x60, 0x01, 0x11]);

    // Pushing an oversized element leaves the builder in error.
    let oversized = vec![0u8; 2049];
    assert!(ScriptBuilder::new().add_data(&oversized).script().is_err());

    // A standard P2PKH template builds as expected.
    let hash = [0x11u8; 20];
    let script = ScriptBuilder::new()
        .add_op(OP_DUP)
        .add_op(OP_HASH160)
        .add_data(&hash)
        .add_op(OP_EQUALVERIFY)
        .add_op(OP_CHECKSIG)
        .script()
        .expect("builds");
    assert_eq!(script.len(), 25);
    assert_eq!(script[0], OP_DUP);
    assert_eq!(script[24], OP_CHECKSIG);
}

/// P2SH classification and push-only detection (dcrd `script_test.go`).
#[test]
fn classification_helpers() {
    let hash = [0x22u8; 20];
    let p2sh = ScriptBuilder::new()
        .add_op(OP_HASH160)
        .add_data(&hash)
        .add_op(OP_EQUAL)
        .script()
        .expect("builds");
    assert!(is_pay_to_script_hash(&p2sh));
    assert!(!is_pay_to_script_hash(&[OP_DUP, OP_HASH160]));

    assert!(is_push_only_script(&[0x51, 0x52])); // OP_1 OP_2
    assert!(!is_push_only_script(&[OP_CHECKSIG]));

    assert!(is_small_int(0x00));
    assert!(is_small_int(0x60));
    assert!(!is_small_int(OP_CHECKSIG));
    assert_eq!(as_small_int(0x00), 0);
    assert_eq!(as_small_int(0x60), 16);
}

/// Sig-op counting (dcrd `TestGetSigOpCount`/`GetPreciseSigOpCount`).
#[test]
fn sig_op_counts() {
    // Bare CHECKSIG counts as 1.
    assert_eq!(get_sig_op_count(&[OP_CHECKSIG], false), 1);
    // CHECKMULTISIG counts as the max (20) in the non-precise count.
    assert_eq!(get_sig_op_count(&[OP_CHECKMULTISIG], false), 20);

    // Precise count for a 2-of-... multisig: OP_2 ... OP_CHECKMULTISIG.
    let multisig = ScriptBuilder::new()
        .add_int64(2)
        .add_data(&[0x02u8; 33])
        .add_data(&[0x03u8; 33])
        .add_int64(2)
        .add_op(OP_CHECKMULTISIG)
        .script()
        .expect("builds");
    assert_eq!(get_precise_sig_op_count(&[], &multisig, false), 2);
}

/// Unspendable detection (dcrd `TestIsUnspendable`).
#[test]
fn unspendable() {
    // Zero-value outputs are always unspendable in Decred.
    assert!(is_unspendable(0, &[OP_CHECKSIG]));
    // OP_RETURN scripts are unspendable.
    assert!(is_unspendable(1000, &[OP_RETURN, 0x01, 0x02]));
    // A normal P2PKH-ish script with value is spendable.
    assert!(!is_unspendable(1000, &[OP_DUP, OP_HASH160]));
}

/// The opcode-name lookup round-trips including the documented aliases
/// (dcrd `OpcodeByName`).
#[test]
fn opcode_name_lookup() {
    assert_eq!(opcode_by_name("OP_CHECKSIG"), Some(OP_CHECKSIG));
    assert_eq!(opcode_by_name("OP_FALSE"), Some(0x00));
    assert_eq!(opcode_by_name("OP_TRUE"), Some(0x51));
    assert_eq!(opcode_by_name("OP_NOP2"), Some(0xb1));
    assert_eq!(opcode_by_name("OP_NOP3"), Some(0xb2));
    assert_eq!(opcode_by_name("OP_NONEXISTENT"), None);
}
