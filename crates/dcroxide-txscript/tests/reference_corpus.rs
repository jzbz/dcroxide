// SPDX-License-Identifier: ISC
//! dcrd's reference test corpus, ported from `reference_test.go` at
//! release-v2.1.5: `script_tests.json` (the full 2,285-entry engine
//! corpus), `tx_valid.json`/`tx_invalid.json` (whole-transaction spends),
//! and `sighash.json` (signature hash vectors). The JSON files are
//! byte-identical copies of dcrd's `testdata/`.

// Test-harness arithmetic over bounded indices and lengths.
#![allow(clippy::arithmetic_side_effects)]
mod common;

use std::collections::HashMap;

use common::{create_spending_tx, parse_expected_result, parse_script_flags, parse_short_form_v0};
use dcroxide_chainhash::Hash;
use dcroxide_txscript::{Engine, ErrorKind, SigHashType, calc_signature_hash_checked};
use dcroxide_wire::{MsgTx, OutPoint};

fn testdata(name: &str) -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/");
    std::fs::read_to_string(format!("{path}{name}")).expect("testdata file readable")
}

/// Run the engine for one reference script test and return the result kind.
fn execute_reference_case(
    sig_script: &[u8],
    pk_script: &[u8],
    flags: dcroxide_txscript::ScriptFlags,
) -> Result<(), ErrorKind> {
    let tx = create_spending_tx(sig_script, pk_script);
    let result = Engine::new(pk_script, &tx, 0, flags, 0).and_then(|mut vm| vm.execute());
    result.map_err(|err| err.kind)
}

#[test]
fn script_tests_corpus() {
    let tests: Vec<Vec<String>> =
        serde_json::from_str(&testdata("script_tests.json")).expect("valid corpus JSON");

    let mut executed = 0usize;
    for (i, test) in tests.iter().enumerate() {
        // Skip single line comments.
        if test.len() == 1 {
            continue;
        }
        assert!(
            test.len() >= 4 && test.len() <= 5,
            "invalid test length {} at #{i}",
            test.len()
        );
        let name = if test.len() == 5 {
            format!("#{i} ({})", test[4])
        } else {
            format!("#{i} ([{}, {}, {}])", test[0], test[1], test[2])
        };

        let sig_script = parse_short_form_v0(&test[0])
            .unwrap_or_else(|e| panic!("{name}: can't parse scriptSig: {e}"));
        let pk_script = parse_short_form_v0(&test[1])
            .unwrap_or_else(|e| panic!("{name}: can't parse scriptPubkey: {e}"));
        let flags = parse_script_flags(&test[2]).unwrap_or_else(|e| panic!("{name}: {e}"));
        let allowed = parse_expected_result(&test[3]).unwrap_or_else(|e| panic!("{name}: {e}"));

        let result = execute_reference_case(&sig_script, &pk_script, flags);
        match (&allowed, &result) {
            (None, Ok(())) => {}
            (None, Err(kind)) => {
                panic!("{name}: failed to execute: {}", kind.kind_name())
            }
            (Some(kinds), Err(kind)) if kinds.contains(kind) => {}
            (Some(kinds), got) => {
                let got = match got {
                    Ok(()) => "OK".to_string(),
                    Err(kind) => kind.kind_name().to_string(),
                };
                panic!("{name}: want error kinds {kinds:?}, got {got}");
            }
        }
        executed += 1;
    }

    // Guard against silently skipping the corpus.
    assert!(executed > 2000, "only {executed} corpus entries executed");
}

/// Convert the JSON float format used for u32 fields, including the -1
/// shortcut for max u32 (dcrd `testVecF64ToUint32`).
fn f64_to_u32(f: f64) -> u32 {
    (f as i64 as i32) as u32
}

/// Parse the shared `[[prevout hash, idx, script]...], txhex, flags` form
/// used by tx_valid.json and tx_invalid.json; returns the deserialized
/// transaction, the prevout script map, and the flags.
#[allow(clippy::type_complexity)]
fn parse_tx_test(
    test: &[serde_json::Value],
) -> Option<(
    MsgTx,
    HashMap<(Hash, u32, i8), Vec<u8>>,
    dcroxide_txscript::ScriptFlags,
)> {
    let inputs = test[0].as_array()?;
    assert_eq!(test.len(), 3, "bad test length");

    let serialized_hex = test[1].as_str().expect("tx hex is a string");
    let serialized: Vec<u8> = (0..serialized_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&serialized_hex[i..i + 2], 16).expect("valid tx hex"))
        .collect();
    let (tx, consumed) = MsgTx::from_bytes(&serialized).expect("tx deserializes");
    assert_eq!(consumed, serialized.len(), "trailing tx bytes");

    let flags =
        parse_script_flags(test[2].as_str().expect("flags are a string")).expect("valid flags");

    let mut prev_outs = HashMap::new();
    for input in inputs {
        let input = input.as_array().expect("input is an array");
        assert_eq!(input.len(), 3, "input has three fields");
        let prev_hash: Hash = input[0]
            .as_str()
            .expect("prev hash is a string")
            .parse()
            .expect("prev hash parses");
        let idx = f64_to_u32(input[1].as_f64().expect("prev idx is numeric"));
        let script = parse_short_form_v0(input[2].as_str().expect("script is a string"))
            .expect("prevout script parses");
        prev_outs.insert((prev_hash, idx, dcroxide_wire::TX_TREE_REGULAR), script);
    }

    Some((tx, prev_outs, flags))
}

fn prevout_key(out: &OutPoint) -> (Hash, u32, i8) {
    (out.hash, out.index, out.tree)
}

#[test]
fn tx_valid_corpus() {
    let tests: Vec<Vec<serde_json::Value>> =
        serde_json::from_str(&testdata("tx_valid.json")).expect("valid JSON");

    for (i, test) in tests.iter().enumerate() {
        let Some((tx, prev_outs, flags)) = parse_tx_test(test) else {
            continue; // Comment row.
        };

        for (k, tx_in) in tx.tx_in.iter().enumerate() {
            let pk_script = prev_outs
                .get(&prevout_key(&tx_in.previous_out_point))
                .unwrap_or_else(|| panic!("bad test (missing {k}th input) {i}"));
            let mut vm = Engine::new(pk_script, &tx, k, flags, 0)
                .unwrap_or_else(|e| panic!("test {i}:{k} failed to create engine: {e}"));
            vm.execute()
                .unwrap_or_else(|e| panic!("test {i}:{k} failed to execute: {e}"));
        }
    }
}

#[test]
fn tx_invalid_corpus() {
    let tests: Vec<Vec<serde_json::Value>> =
        serde_json::from_str(&testdata("tx_invalid.json")).expect("valid JSON");

    'testloop: for (i, test) in tests.iter().enumerate() {
        let Some((tx, prev_outs, flags)) = parse_tx_test(test) else {
            continue; // Comment row.
        };

        for (k, tx_in) in tx.tx_in.iter().enumerate() {
            let pk_script = prev_outs
                .get(&prevout_key(&tx_in.previous_out_point))
                .unwrap_or_else(|| panic!("bad test (missing {k}th input) {i}"));
            // These are meant to fail, so as soon as the first input fails
            // the transaction has failed (some test txns have good inputs
            // too).
            let Ok(mut vm) = Engine::new(pk_script, &tx, k, flags, 0) else {
                continue 'testloop;
            };
            if vm.execute().is_err() {
                continue 'testloop;
            }
        }
        panic!("test {i} succeeded when it should fail");
    }
}

#[test]
fn sighash_vectors() {
    let tests: Vec<Vec<serde_json::Value>> =
        serde_json::from_str(&testdata("sighash.json")).expect("valid JSON");

    let mut executed = 0usize;
    for (i, test) in tests.iter().enumerate() {
        // Skip comment lines.
        if test.len() == 1 {
            continue;
        }
        assert!(
            test.len() >= 6 && test.len() <= 7,
            "test #{i}: wrong length {}",
            test.len()
        );

        let unhex = |s: &str| -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|j| u8::from_str_radix(&s[j..j + 2], 16).expect("valid hex"))
                .collect()
        };

        let raw_tx = unhex(test[0].as_str().expect("tx hex"));
        let (tx, _) = MsgTx::from_bytes(&raw_tx).expect("tx deserializes");
        let sub_script = unhex(test[1].as_str().expect("script hex"));
        let input_idx = test[2].as_f64().expect("input idx") as usize;
        let hash_type = SigHashType(f64_to_u32(test[3].as_f64().expect("hash type")) as u8);
        let expected_hash = unhex(test[4].as_str().expect("expected hash"));
        let expected_err = test[5].as_str().expect("expected result");

        let result = calc_signature_hash_checked(&sub_script, hash_type, &tx, input_idx);
        match expected_err {
            "OK" => {
                let hash = result.unwrap_or_else(|e| panic!("test #{i}: unexpected error {e}"));
                assert_eq!(hash.to_vec(), expected_hash, "test #{i}: sighash mismatch");
            }
            "SIGHASH_SINGLE_IDX" => {
                let err = result.expect_err("expected an error");
                assert_eq!(
                    err.kind,
                    ErrorKind::InvalidSigHashSingleIndex,
                    "test #{i}: wrong error kind"
                );
            }
            other => panic!("test #{i}: unrecognized expected result {other}"),
        }
        executed += 1;
    }
    assert!(executed > 100, "only {executed} sighash vectors executed");
}
