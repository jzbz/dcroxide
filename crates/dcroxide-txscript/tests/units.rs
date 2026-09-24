// SPDX-License-Identifier: ISC
//! Focused unit tests ported from dcrd's txscript tests: script number
//! encoding, the builder's canonical selection and size limits, sig-op
//! counting, and script classification helpers.

// Test-harness arithmetic over bounded indices and lengths.
#![allow(clippy::arithmetic_side_effects)]
use dcroxide_txscript::{
    MATH_OP_CODE_MAX_SCRIPT_NUM_LEN, MAX_SCRIPT_SIZE, OP_0, OP_1, OP_1NEGATE, OP_2,
    OP_CHECKMULTISIG, OP_CHECKSIG, OP_DATA_1, OP_DATA_2, OP_DATA_3, OP_DATA_4, OP_DATA_5,
    OP_DATA_8, OP_DATA_9, OP_DATA_17, OP_DATA_75, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160,
    OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4, OP_RETURN, ScriptBuilder, ScriptNum, as_small_int,
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

/// dcrd `TestScriptBuilderAddOp`: opcodes pushed one at a time through
/// `add_op` and in bulk through `add_ops` land verbatim.
#[test]
fn builder_add_op_vectors() {
    let cases: &[(&str, &[u8])] = &[
        ("push OP_0", &[OP_0]),
        ("push OP_1 OP_2", &[OP_1, OP_2]),
        ("push OP_HASH160 OP_EQUAL", &[OP_HASH160, OP_EQUAL]),
    ];
    for (name, opcodes) in cases {
        let one_at_a_time = opcodes
            .iter()
            .fold(ScriptBuilder::new(), |b, &op| b.add_op(op))
            .script()
            .expect(name);
        assert_eq!(one_at_a_time, *opcodes, "add_op: {name}");
        let bulk = ScriptBuilder::new().add_ops(opcodes).script().expect(name);
        assert_eq!(bulk, *opcodes, "add_ops: {name}");
    }
}

/// dcrd `TestScriptBuilderAddInt64`, plus the i32 and i64 extremes the
/// table leaves out.  The extremes' bytes follow dcrd's `ScriptNum.Bytes`
/// by hand: `i64::MIN` negates to itself in Go, and `uint64` of that is
/// the same 2^63 the port's `unsigned_abs` produces.
#[test]
fn builder_add_int64_vectors() {
    let mut cases: Vec<(i64, Vec<u8>)> = vec![(-1, vec![OP_1NEGATE]), (0, vec![OP_0])];
    // "push small int 1" through "push small int 16".
    cases.extend((1..=16u8).map(|n| (i64::from(n), vec![OP_1 - 1 + n])));
    cases.extend([
        (17, vec![OP_DATA_1, 0x11]),
        (65, vec![OP_DATA_1, 0x41]),
        (127, vec![OP_DATA_1, 0x7f]),
        (128, vec![OP_DATA_2, 0x80, 0]),
        (255, vec![OP_DATA_2, 0xff, 0]),
        (256, vec![OP_DATA_2, 0, 0x01]),
        (32767, vec![OP_DATA_2, 0xff, 0x7f]),
        (32768, vec![OP_DATA_3, 0, 0x80, 0]),
        (-2, vec![OP_DATA_1, 0x82]),
        (-3, vec![OP_DATA_1, 0x83]),
        (-4, vec![OP_DATA_1, 0x84]),
        (-5, vec![OP_DATA_1, 0x85]),
        (-17, vec![OP_DATA_1, 0x91]),
        (-65, vec![OP_DATA_1, 0xc1]),
        (-127, vec![OP_DATA_1, 0xff]),
        (-128, vec![OP_DATA_2, 0x80, 0x80]),
        (-255, vec![OP_DATA_2, 0xff, 0x80]),
        (-256, vec![OP_DATA_2, 0x00, 0x81]),
        (-32767, vec![OP_DATA_2, 0xff, 0xff]),
        (-32768, vec![OP_DATA_3, 0x00, 0x80, 0x80]),
        // Beyond dcrd's table.
        (i64::from(i32::MAX), vec![OP_DATA_4, 0xff, 0xff, 0xff, 0x7f]),
        (
            i64::from(i32::MIN),
            vec![OP_DATA_5, 0x00, 0x00, 0x00, 0x80, 0x80],
        ),
        (
            i64::MAX,
            vec![OP_DATA_8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
        ),
        (i64::MIN, vec![OP_DATA_9, 0, 0, 0, 0, 0, 0, 0, 0x80, 0x80]),
        (
            i64::MIN + 1,
            vec![OP_DATA_8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ),
    ]);
    for (val, want) in cases {
        let got = ScriptBuilder::new()
            .add_int64(val)
            .script()
            .unwrap_or_else(|e| panic!("push {val}: {e}"));
        assert_eq!(got, want, "push {val}");
    }
}

/// dcrd `TestScriptBuilderAddData`, plus the element-size boundary
/// (2048 bytes, `MAX_SCRIPT_ELEMENT_SIZE`) that dcrd's table only
/// crosses from far above.  `None` is dcrd's `expected: nil`: the push
/// is refused, `script` errors, and the script stays empty.
#[test]
fn builder_add_data_vectors() {
    fn rep(len: usize) -> Vec<u8> {
        vec![0x49; len]
    }
    fn with(prefix: &[u8], data: &[u8]) -> Vec<u8> {
        let mut v = prefix.to_vec();
        v.extend_from_slice(data);
        v
    }
    /// (name, data, expected, use_unchecked)
    type Case = (String, Vec<u8>, Option<Vec<u8>>, bool);
    let mut cases: Vec<Case> = vec![
        (
            "push empty byte sequence".into(),
            vec![],
            Some(vec![OP_0]),
            false,
        ),
        (
            "push 1 byte 0x00".into(),
            vec![0x00],
            Some(vec![OP_0]),
            false,
        ),
    ];
    // BIP0062: 0x01 through 0x10 use OP_n.
    cases.extend((1..=16u8).map(|n| {
        (
            format!("push 1 byte {n:#04x}"),
            vec![n],
            Some(vec![OP_1 - 1 + n]),
            false,
        )
    }));
    cases.extend([
        (
            "push 1 byte 0x81".into(),
            vec![0x81],
            Some(vec![OP_1NEGATE]),
            false,
        ),
        (
            "push 1 byte 0x11".into(),
            vec![0x11],
            Some(vec![OP_DATA_1, 0x11]),
            false,
        ),
        (
            "push 1 byte 0x80".into(),
            vec![0x80],
            Some(vec![OP_DATA_1, 0x80]),
            false,
        ),
        (
            "push 1 byte 0x82".into(),
            vec![0x82],
            Some(vec![OP_DATA_1, 0x82]),
            false,
        ),
        (
            "push 1 byte 0xff".into(),
            vec![0xff],
            Some(vec![OP_DATA_1, 0xff]),
            false,
        ),
        (
            "push data len 17".into(),
            rep(17),
            Some(with(&[OP_DATA_17], &rep(17))),
            false,
        ),
        (
            "push data len 75".into(),
            rep(75),
            Some(with(&[OP_DATA_75], &rep(75))),
            false,
        ),
        (
            "push data len 76".into(),
            rep(76),
            Some(with(&[OP_PUSHDATA1, 76], &rep(76))),
            false,
        ),
        (
            "push data len 255".into(),
            rep(255),
            Some(with(&[OP_PUSHDATA1, 255], &rep(255))),
            false,
        ),
        (
            "push data len 256".into(),
            rep(256),
            Some(with(&[OP_PUSHDATA2, 0, 1], &rep(256))),
            false,
        ),
        (
            "push data len 520".into(),
            rep(520),
            Some(with(&[OP_PUSHDATA2, 0x08, 0x02], &rep(520))),
            false,
        ),
        // Beyond dcrd's table: the largest element allowed, then one more.
        (
            "push data len 2048".into(),
            rep(2048),
            Some(with(&[OP_PUSHDATA2, 0x00, 0x08], &rep(2048))),
            false,
        ),
        ("push data len 2049".into(), rep(2049), None, false),
        // dcrd names this row "push data len 521" but pushes 4097 bytes.
        ("push data len 521".into(), rep(4097), None, false),
        (
            "push data len 32767 (canonical)".into(),
            rep(32767),
            None,
            false,
        ),
        (
            "push data len 65536 (canonical)".into(),
            rep(65536),
            None,
            false,
        ),
        // The unchecked pushes dcrd keeps for regression testing.
        (
            "push data len 32767 (non-canonical)".into(),
            rep(32767),
            Some(with(&[OP_PUSHDATA2, 255, 127], &rep(32767))),
            true,
        ),
        (
            "push data len 65536 (non-canonical)".into(),
            rep(65536),
            Some(with(&[OP_PUSHDATA4, 0, 0, 1, 0], &rep(65536))),
            true,
        ),
    ]);
    for (name, data, want, unchecked) in cases {
        let build = || {
            if unchecked {
                ScriptBuilder::new().add_data_unchecked(&data)
            } else {
                ScriptBuilder::new().add_data(&data)
            }
        };
        assert_eq!(build().script().is_ok(), want.is_some(), "{name}: verdict");
        assert_eq!(
            build().unchecked_script(),
            want.unwrap_or_default(),
            "{name}: script"
        );
    }
}

/// dcrd `TestExceedMaxScriptSize`: from a script exactly
/// `MAX_SCRIPT_SIZE` long, every checked push errors and leaves the
/// script untouched.  `add_ops` is not in dcrd's test; it has the same
/// guard and is checked alongside.
#[test]
fn builder_exceed_max_script_size() {
    let full = || ScriptBuilder::new().add_data_unchecked(&vec![0u8; MAX_SCRIPT_SIZE - 3]);
    let orig = full().script().expect("max size script builds");
    assert_eq!(orig.len(), MAX_SCRIPT_SIZE);

    type Push = fn(ScriptBuilder) -> ScriptBuilder;
    let pushes: [(&str, Push); 4] = [
        ("add_data", |b| b.add_data(&[0x00])),
        ("add_op", |b| b.add_op(OP_0)),
        ("add_ops", |b| b.add_ops(&[OP_0])),
        ("add_int64", |b| b.add_int64(0)),
    ];
    for (name, push) in pushes {
        assert!(push(full()).script().is_err(), "{name} exceeded the max");
        assert_eq!(push(full()).unchecked_script(), orig, "{name} modified");
    }
}

/// dcrd `TestErroredScript`: once a push has errored, every later push,
/// checked or not, is a no-op, and the first error is the one reported.
#[test]
fn builder_errored_script_latches() {
    let near_full = || ScriptBuilder::new().add_data_unchecked(&vec![0u8; MAX_SCRIPT_SIZE - 8]);
    let orig = near_full().script().expect("near max size script builds");
    // A six-byte canonical push against five bytes of room.
    let errored = || near_full().add_data(&[0x00; 5]);
    let first = errored().script().expect_err("five bytes of data overflow");
    assert_eq!(errored().unchecked_script(), orig);

    type Push = fn(ScriptBuilder) -> ScriptBuilder;
    let pushes: [(&str, Push); 5] = [
        ("add_data_unchecked", |b| b.add_data_unchecked(&[0x00])),
        ("add_data", |b| b.add_data(&[0x00])),
        ("add_op", |b| b.add_op(OP_0)),
        ("add_ops_unchecked", |b| b.add_ops_unchecked(&[OP_0])),
        ("add_int64", |b| b.add_int64(0)),
    ];
    for (name, push) in pushes {
        assert_eq!(
            push(errored()).script().expect_err(name),
            first,
            "{name} replaced the first error"
        );
        assert_eq!(push(errored()).unchecked_script(), orig, "{name} modified");
    }
    assert!(!first.to_string().is_empty(), "the error carries text");
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

/// Bytes at index 8..=31 shift to zero, as Go defines, rather than
/// folding back into the low positions as a masked Rust shift would.
///
/// Unreachable through the consensus callers, which pass a
/// `script_num_len` of one, four or five, but `make_script_num` is public
/// and the length is the caller's to choose.  Reported as RVW-021 by an
/// external review of `382864f5`.
#[test]
fn decoding_beyond_eight_bytes_drops_the_high_bytes_like_go() {
    // Nine bytes: value 1 in the low byte, then a byte at index eight.
    // Go shifts that byte by 64 and gets zero, leaving 1.  A masked
    // shift would fold it back to index zero and give 1 | 2 == 3.
    let bytes = [0x01u8, 0, 0, 0, 0, 0, 0, 0, 0x02];
    let decoded = make_script_num(&bytes, 9).expect("length is within the caller's limit");
    assert_eq!(
        decoded.0, 1,
        "the ninth byte must vanish, not wrap into the low byte"
    );
}

/// dcrd shifts by `uint8(8*i)`, so from index 32 the count wraps modulo
/// 256 and the byte folds back into the low positions; the sign-bit mask
/// wraps the same way.  Expected values come from running dcrd's
/// `MakeScriptNum` under Go.
#[test]
fn decoding_from_byte_32_wraps_the_shift_count_like_go() {
    // 33 bytes: 1 in the low byte, 2 at index 32.  uint8(256) == 0, so
    // Go ORs the 2 into the low byte and returns 3.
    let mut bytes = vec![0x01u8];
    bytes.extend_from_slice(&[0u8; 31]);
    bytes.push(0x02);
    assert_eq!(make_script_num(&bytes, 33).expect("minimal").0, 3);

    // The same with the sign bit set on the last byte: Go ORs 0x82 into
    // the low byte, clears bit 7 there (the mask shift wraps to zero as
    // well) and negates, giving -3.
    *bytes.last_mut().expect("non-empty") = 0x82;
    assert_eq!(make_script_num(&bytes, 33).expect("minimal").0, -3);

    // 40 bytes, 1 at index 39: uint8(312) == 56, so Go places it at the
    // top byte of the int64.
    let mut bytes = vec![0u8; 39];
    bytes.push(0x01);
    assert_eq!(make_script_num(&bytes, 40).expect("minimal").0, 1i64 << 56);
}

/// A nine-byte input whose top two bytes are 0x80 decodes to `i64::MIN`
/// (the mask shift of 64 clears nothing), and Go's negation wraps, so
/// dcrd returns `i64::MIN`.  The port used to overflow-panic here in
/// debug and test builds.
#[test]
fn decoding_i64_min_wraps_the_negation_like_go() {
    let bytes = [0u8, 0, 0, 0, 0, 0, 0, 0x80, 0x80];
    assert_eq!(make_script_num(&bytes, 9).expect("minimal").0, i64::MIN);
}
