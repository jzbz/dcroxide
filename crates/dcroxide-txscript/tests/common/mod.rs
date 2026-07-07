// SPDX-License-Identifier: ISC
//! Shared test helpers: the short-form script notation parser
//! (dcrd `parseShortFormV0` from `scriptshortform_test.go`), reference flag
//! parsing, and the reference spending-transaction builder.

// Test-harness arithmetic over bounded indices and lengths. Not every
// helper is used by every test binary that includes this module.
#![allow(clippy::arithmetic_side_effects, dead_code)]
use std::collections::HashMap;

use dcroxide_chainhash::Hash;
use dcroxide_txscript::{ErrorKind, OP_0, OP_1, OP_16, ScriptBuilder, ScriptFlags, opcode_by_name};
use dcroxide_wire::{MsgTx, OutPoint, TxIn, TxOut, TxSerializeType};

/// The short-form opcode name map (dcrd `shortFormOps`): every table name
/// except the OP_UNKNOWN family, the OP_FALSE/OP_TRUE/OP_NOP2/OP_NOP3
/// aliases, and OP_-stripped variants for everything that cannot conflict
/// with plain numbers.
fn short_form_ops() -> HashMap<String, u8> {
    let mut ops = HashMap::new();
    let mut insert = |name: &str| {
        let value = opcode_by_name(name).expect("known opcode name");
        ops.insert(name.to_string(), value);
        // The opcodes named OP_# can't have the OP_ prefix stripped or they
        // would conflict with the plain numbers; OP_FALSE and OP_TRUE are
        // aliases with the same values, so they are allowed by name.
        if (name == "OP_FALSE" || name == "OP_TRUE")
            || (value != OP_0 && !(OP_1..=OP_16).contains(&value))
        {
            ops.insert(name.trim_start_matches("OP_").to_string(), value);
        }
    };

    for value in 0u8..=255 {
        let name = dcroxide_txscript::opcode_name(value);
        if name.contains("OP_UNKNOWN") {
            continue;
        }
        insert(name);
    }
    insert("OP_FALSE");
    insert("OP_TRUE");
    insert("OP_NOP2");
    insert("OP_NOP3");
    ops
}

/// Tokenize a short-form script exactly like dcrd's `tokenRE`
/// (`\<.+?\>\{[0-9]+\}|[^\s]+`): angle-bracketed repeated groups with a
/// brace-suffixed count, otherwise whitespace-separated tokens.
fn tokenize(script: &str) -> Vec<String> {
    let bytes = script.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }

        // Try the non-greedy `<...>{n}` form first, mirroring the regex
        // alternation order: the minimal '>' followed by `{digits}`.
        if bytes[i] == b'<' {
            let mut matched = None;
            let mut j = i + 1;
            while j < bytes.len() {
                if bytes[j] == b'>' && j > i + 1 {
                    // Require `{digits}` immediately after.
                    if j + 1 < bytes.len() && bytes[j + 1] == b'{' {
                        let mut k = j + 2;
                        while k < bytes.len() && bytes[k].is_ascii_digit() {
                            k += 1;
                        }
                        if k > j + 2 && k < bytes.len() && bytes[k] == b'}' {
                            matched = Some(k);
                            break;
                        }
                    }
                }
                j += 1;
            }
            if let Some(end) = matched {
                tokens.push(script[i..=end].to_string());
                i = end + 1;
                continue;
            }
        }

        // Plain token: up to the next whitespace.
        let start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        tokens.push(script[start..i].to_string());
    }
    tokens
}

/// Parse a `0x`-prefixed hex token (dcrd `parseHex`).
fn parse_hex(tok: &str) -> Option<Vec<u8>> {
    let rest = tok.strip_prefix("0x")?;
    if rest.len() % 2 != 0 {
        return None;
    }
    (0..rest.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&rest[i..i + 2], 16).ok())
        .collect()
}

/// Split a `X{n}` repetition suffix: returns (head, count).
fn split_repetition(tok: &str) -> Option<(&str, usize)> {
    let stripped = tok.strip_suffix('}')?;
    let brace = stripped.rfind('{')?;
    let count: usize = stripped[brace + 1..].parse().ok()?;
    Some((&stripped[..brace], count))
}

fn handle_token(
    ops: &HashMap<String, u8>,
    builder: ScriptBuilder,
    tok: &str,
) -> Result<ScriptBuilder, String> {
    // Multiple repeated tokens: <tokens>{n}.
    if tok.starts_with('<')
        && let Some((head, count)) = split_repetition(tok)
        && let Some(inner) = head.strip_prefix('<').and_then(|h| h.strip_suffix('>'))
    {
        let inner_tokens = tokenize(inner);
        let mut builder = builder;
        for _ in 0..count {
            for t in &inner_tokens {
                builder = handle_token(ops, builder, t)?;
            }
        }
        return Ok(builder);
    }

    // Plain number.
    if let Ok(num) = tok.parse::<i64>() {
        return Ok(builder.add_int64(num));
    }

    // Raw data, inserted without modification.
    if let Some(bytes) = parse_hex(tok) {
        return Ok(builder.add_ops_unchecked(&bytes));
    }

    // Repeated raw bytes: 0x..{n}.
    if let Some((head, count)) = split_repetition(tok) {
        let head_lower = head.replace("0X", "0x");
        if let Some(bytes) = parse_hex(&head_lower) {
            return Ok(builder.add_ops_unchecked(&bytes.repeat(count)));
        }
    }

    // Quoted data.
    if tok.len() >= 2 && tok.starts_with('\'') && tok.ends_with('\'') {
        return Ok(builder.add_data_unchecked(&tok.as_bytes()[1..tok.len() - 1]));
    }

    // Repeated quoted data: 'x'{n}.
    if let Some((head, count)) = split_repetition(tok)
        && head.len() >= 2
        && head.starts_with('\'')
        && head.ends_with('\'')
    {
        let data = head[1..head.len() - 1].repeat(count);
        return Ok(builder.add_data_unchecked(data.as_bytes()));
    }

    // Named opcode.
    if let Some(&opcode) = ops.get(tok) {
        return Ok(builder.add_op(opcode));
    }

    Err(format!("bad token {tok:?}"))
}

/// Parse a version 0 script from dcrd's human-readable short form into raw
/// script bytes (dcrd `parseShortFormV0`).
pub fn parse_short_form_v0(script: &str) -> Result<Vec<u8>, String> {
    let ops = short_form_ops();
    let mut builder = ScriptBuilder::new();
    for tok in tokenize(script) {
        builder = handle_token(&ops, builder, &tok)?;
    }
    builder.script().map_err(|e| e.to_string())
}

/// Parse the reference-test flag notation (dcrd `parseScriptFlags`).
pub fn parse_script_flags(flag_str: &str) -> Result<ScriptFlags, String> {
    let mut flags = ScriptFlags::default();
    for flag in flag_str.split(',') {
        flags = flags
            | match flag {
                "" | "NONE" => ScriptFlags::default(),
                "CHECKLOCKTIMEVERIFY" => ScriptFlags::VERIFY_CHECK_LOCK_TIME_VERIFY,
                "CHECKSEQUENCEVERIFY" => ScriptFlags::VERIFY_CHECK_SEQUENCE_VERIFY,
                "CLEANSTACK" => ScriptFlags::VERIFY_CLEAN_STACK,
                "DISCOURAGE_UPGRADABLE_NOPS" => ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS,
                "SIGPUSHONLY" => ScriptFlags::VERIFY_SIG_PUSH_ONLY,
                "SHA256" => ScriptFlags::VERIFY_SHA256,
                "TREASURY" => ScriptFlags::VERIFY_TREASURY,
                other => return Err(format!("invalid flag: {other}")),
            };
    }
    Ok(flags)
}

/// Map a reference-test expected result string to the allowed error kinds
/// (dcrd `parseExpectedResult`); `None` means "OK".
pub fn parse_expected_result(expected: &str) -> Result<Option<Vec<ErrorKind>>, String> {
    use ErrorKind::*;
    Ok(Some(match expected {
        "OK" => return Ok(None),
        "ERR_EARLY_RETURN" => vec![EarlyReturn],
        "ERR_EMPTY_STACK" => vec![EmptyStack],
        "ERR_EVAL_FALSE" => vec![EvalFalse],
        "ERR_SCRIPT_SIZE" => vec![ScriptTooBig],
        "ERR_PUSH_SIZE" => vec![ElementTooBig],
        "ERR_OP_COUNT" => vec![TooManyOperations],
        "ERR_STACK_SIZE" => vec![StackOverflow],
        "ERR_PUBKEY_COUNT" => vec![InvalidPubKeyCount],
        "ERR_SIG_COUNT" => vec![InvalidSignatureCount],
        "ERR_OUT_OF_RANGE" => vec![NumOutOfRange],
        "ERR_VERIFY" => vec![Verify],
        "ERR_EQUAL_VERIFY" => vec![EqualVerify],
        "ERR_DISABLED_OPCODE" => vec![DisabledOpcode],
        "ERR_RESERVED_OPCODE" => vec![ReservedOpcode],
        "ERR_P2SH_STAKE_OPCODES" => vec![P2SHStakeOpCodes],
        "ERR_MALFORMED_PUSH" => vec![MalformedPush],
        "ERR_INVALID_STACK_OPERATION" | "ERR_INVALID_ALTSTACK_OPERATION" => {
            vec![InvalidStackOperation]
        }
        "ERR_UNBALANCED_CONDITIONAL" => vec![UnbalancedConditional],
        "ERR_NEGATIVE_SUBSTR_INDEX" => vec![NegativeSubstrIdx],
        "ERR_OVERFLOW_SUBSTR_INDEX" => vec![OverflowSubstrIdx],
        "ERR_NEGATIVE_ROTATION" => vec![NegativeRotation],
        "ERR_OVERFLOW_ROTATION" => vec![OverflowRotation],
        "ERR_DIVIDE_BY_ZERO" => vec![DivideByZero],
        "ERR_NEGATIVE_SHIFT" => vec![NegativeShift],
        "ERR_OVERFLOW_SHIFT" => vec![OverflowShift],
        "ERR_MINIMAL_DATA" => vec![MinimalData],
        "ERR_SIG_HASH_TYPE" => vec![InvalidSigHashType],
        "ERR_SIG_TOO_SHORT" => vec![SigTooShort],
        "ERR_SIG_TOO_LONG" => vec![SigTooLong],
        "ERR_SIG_INVALID_SEQ_ID" => vec![SigInvalidSeqID],
        "ERR_SIG_INVALID_DATA_LEN" => vec![SigInvalidDataLen],
        "ERR_SIG_MISSING_S_TYPE_ID" => vec![SigMissingSTypeID],
        "ERR_SIG_MISSING_S_LEN" => vec![SigMissingSLen],
        "ERR_SIG_INVALID_S_LEN" => vec![SigInvalidSLen],
        "ERR_SIG_INVALID_R_INT_ID" => vec![SigInvalidRIntID],
        "ERR_SIG_ZERO_R_LEN" => vec![SigZeroRLen],
        "ERR_SIG_NEGATIVE_R" => vec![SigNegativeR],
        "ERR_SIG_TOO_MUCH_R_PADDING" => vec![SigTooMuchRPadding],
        "ERR_SIG_INVALID_S_INT_ID" => vec![SigInvalidSIntID],
        "ERR_SIG_ZERO_S_LEN" => vec![SigZeroSLen],
        "ERR_SIG_NEGATIVE_S" => vec![SigNegativeS],
        "ERR_SIG_TOO_MUCH_S_PADDING" => vec![SigTooMuchSPadding],
        "ERR_SIG_HIGH_S" => vec![SigHighS],
        "ERR_SIG_PUSHONLY" => vec![NotPushOnly],
        "ERR_PUBKEY_TYPE" => vec![PubKeyType],
        "ERR_CLEAN_STACK" => vec![CleanStack],
        "ERR_DISCOURAGE_UPGRADABLE_NOPS" => vec![DiscourageUpgradableNOPs],
        "ERR_NEGATIVE_LOCKTIME" => vec![NegativeLockTime],
        "ERR_UNSATISFIED_LOCKTIME" => vec![UnsatisfiedLockTime],
        other => {
            return Err(format!(
                "unrecognized expected result in test data: {other}"
            ));
        }
    }))
}

/// Generate the reference spending transaction pair for the given signature
/// and public key scripts (dcrd `createSpendingTx`) and return the spending
/// transaction.
pub fn create_spending_tx(sig_script: &[u8], pk_script: &[u8]) -> MsgTx {
    let coinbase_tx = MsgTx {
        ser_type: TxSerializeType::Full,
        version: 1,
        tx_in: vec![TxIn {
            previous_out_point: OutPoint {
                hash: Hash::ZERO,
                index: !0u32,
                tree: dcroxide_wire::TX_TREE_REGULAR,
            },
            sequence: dcroxide_wire::MAX_TX_IN_SEQUENCE_NUM,
            value_in: 0,
            block_height: dcroxide_wire::NULL_BLOCK_HEIGHT,
            block_index: dcroxide_wire::NULL_BLOCK_INDEX,
            signature_script: vec![OP_0, OP_0],
        }],
        tx_out: vec![TxOut {
            value: 0,
            version: 0,
            pk_script: pk_script.to_vec(),
        }],
        lock_time: 0,
        expiry: 0,
    };

    MsgTx {
        ser_type: TxSerializeType::Full,
        version: 1,
        tx_in: vec![TxIn {
            previous_out_point: OutPoint {
                hash: coinbase_tx.tx_hash(),
                index: 0,
                tree: dcroxide_wire::TX_TREE_REGULAR,
            },
            sequence: dcroxide_wire::MAX_TX_IN_SEQUENCE_NUM,
            value_in: 0,
            block_height: dcroxide_wire::NULL_BLOCK_HEIGHT,
            block_index: dcroxide_wire::NULL_BLOCK_INDEX,
            signature_script: sig_script.to_vec(),
        }],
        tx_out: vec![TxOut {
            value: 0,
            version: 0,
            pk_script: Vec::new(),
        }],
        lock_time: 0,
        expiry: 0,
    }
}
