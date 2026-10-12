// SPDX-License-Identifier: ISC
//! Signatures made on mainnet, by software other than this port, run
//! through the script engine without and with the transaction hash
//! (`Engine::set_tx_hash`): every run must give the same result, and
//! every signed input must verify.
//!
//! The data is two files of dcrd's `txscript/testdata`:
//!
//! - `many_inputs_tx.hex`, a byte-identical copy: the transaction of
//!   dcrd's `BenchmarkCalcSigHash` (`bench_test.go:30-65`).
//! - `block432100.hex`: what dcrd's `block432100.bz2` decompresses to,
//!   written as hex because nothing in the workspace reads bzip2.  It
//!   is the block of dcrd's signature cache tests
//!   (`sigcache_test.go:24-40`).
//!
//! Neither file holds the outputs its inputs spend, so the public key
//! script of each is rebuilt from the input's signature script: pay to
//! the hash of the public key it ends with, or pay to the hash of the
//! script it ends with, plain and behind each stake opcode.  The hash in
//! a rebuilt script is the hash of what the input reveals, so the spend
//! satisfies it exactly when its signatures verify against the
//! signature hash of this transaction, which is what the test is after.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_chainhash::Hash;
use dcroxide_testutil::unhex;
use dcroxide_txscript::stdaddr::hash160;
use dcroxide_txscript::{
    Engine, ErrorKind, OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_SSGEN,
    OP_SSRTX, OP_SSTX, OP_SSTXCHANGE, ScriptBuilder, ScriptError, ScriptFlags, ScriptTokenizer,
};
use dcroxide_wire::{MsgBlock, MsgTx};

fn testdata(name: &str) -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/");
    std::fs::read_to_string(format!("{path}{name}")).expect("testdata file readable")
}

/// The script flags of a block connected with every agenda active, and
/// none at all.
fn flag_sets() -> [ScriptFlags; 2] {
    [
        ScriptFlags::VERIFY_CLEAN_STACK
            | ScriptFlags::VERIFY_CHECK_LOCK_TIME_VERIFY
            | ScriptFlags::VERIFY_CHECK_SEQUENCE_VERIFY
            | ScriptFlags::VERIFY_SHA256
            | ScriptFlags::VERIFY_TREASURY,
        ScriptFlags(0),
    ]
}

/// Execute input `idx` of `tx` against `pk_script`, the engine given
/// `tx_hash` when there is one.
fn run(
    pk_script: &[u8],
    tx: &MsgTx,
    idx: usize,
    flags: ScriptFlags,
    tx_hash: Option<&Hash>,
) -> Result<(), ScriptError> {
    let mut vm = Engine::new(pk_script, tx, idx, flags, 0)?;
    if let Some(tx_hash) = tx_hash {
        vm.set_tx_hash(tx_hash);
    }
    vm.execute()
}

/// The data pushes of a signature script, or `None` when it does not
/// parse.
fn pushes(sig_script: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut pushes = Vec::new();
    let mut tokenizer = ScriptTokenizer::new(0, sig_script);
    while tokenizer.next() {
        pushes.push(tokenizer.data().to_vec());
    }
    tokenizer.err().is_none().then_some(pushes)
}

/// `script` behind the stake opcode `tag`, when there is one.
fn tagged(tag: Option<u8>) -> ScriptBuilder {
    match tag {
        Some(tag) => ScriptBuilder::new().add_op(tag),
        None => ScriptBuilder::new(),
    }
}

/// The public key scripts the pushes of a signature script could be
/// spending: pay-to-pubkey-hash of the last push when there are two and
/// it is a compressed public key, and pay-to-script-hash of the last
/// push, each plain and behind each stake opcode.
fn candidate_pk_scripts(pushes: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let Some(last) = pushes.last() else {
        return Vec::new();
    };
    let is_pub_key = pushes.len() == 2 && last.len() == 33 && (last[0] == 2 || last[0] == 3);
    let mut scripts = Vec::new();
    for tag in [
        None,
        Some(OP_SSTX),
        Some(OP_SSGEN),
        Some(OP_SSRTX),
        Some(OP_SSTXCHANGE),
    ] {
        if is_pub_key {
            scripts.push(
                tagged(tag)
                    .add_op(OP_DUP)
                    .add_op(OP_HASH160)
                    .add_data(&hash160(last))
                    .add_op(OP_EQUALVERIFY)
                    .add_op(OP_CHECKSIG)
                    .script()
                    .expect("builds"),
            );
        }
        scripts.push(
            tagged(tag)
                .add_op(OP_HASH160)
                .add_data(&hash160(last))
                .add_op(OP_EQUAL)
                .script()
                .expect("builds"),
        );
    }
    scripts
}

/// What the inputs of some transactions came to.
#[derive(Debug, Default, PartialEq, Eq)]
struct Tally {
    /// The inputs that are not coinbase-style.
    signed: usize,
    /// Those that verify against a rebuilt public key script.
    verified: usize,
    /// Those of the verified whose signatures are all of hash type
    /// `SigHashAll`: the ones whose signature hashes take their prefix
    /// hash from the transaction hash.
    sig_hash_all: usize,
    /// The runs against a rebuilt script that the spend does not
    /// satisfy, which fail alike without and with the hash.
    rejected: usize,
}

/// Run every signed input of the transaction against each of its
/// rebuilt public key scripts under each flag set, without and with the
/// transaction hash, and add the outcome to the tally.  The two runs
/// must agree in full, the error's kind and text included.
fn check_tx(tx: &MsgTx, label: &str, tally: &mut Tally) {
    let tx_hash = tx.tx_hash();
    for (idx, tx_in) in tx.tx_in.iter().enumerate() {
        if tx_in.previous_out_point.index == u32::MAX {
            continue;
        }
        tally.signed += 1;
        let pushes = pushes(&tx_in.signature_script).expect("the signature script parses");
        // Every push but the last is a signature, which ends in its
        // hash type.
        let (_, signatures) = pushes.split_last().expect("a push");
        let sig_hash_all = signatures.iter().all(|sig| sig.last() == Some(&0x01));

        let mut verified = false;
        for pk_script in candidate_pk_scripts(&pushes) {
            for flags in flag_sets() {
                let plain = run(&pk_script, tx, idx, flags, None);
                let given = run(&pk_script, tx, idx, flags, Some(&tx_hash));
                assert_eq!(given, plain, "{label} input {idx}, flags {flags:?}");
                if plain.is_err() {
                    tally.rejected += 1;
                    continue;
                }
                verified = true;

                // Without debug assertions the engine keeps whatever
                // hash it is given.  Given one that is not the
                // transaction's, a spend signed with SigHashAll
                // throughout no longer verifies: the run above built
                // its signature hashes on the transaction hash.  (Under
                // debug assertions the engine refuses such a hash.)
                if !cfg!(debug_assertions) && sig_hash_all {
                    let err = run(&pk_script, tx, idx, flags, Some(&Hash([0x5a; 32])))
                        .expect_err("a hash that is not the transaction's");
                    assert_eq!(err.kind, ErrorKind::EvalFalse, "{label} input {idx}");
                }
            }
        }
        assert!(
            verified,
            "{label} input {idx} verifies against no rebuilt script"
        );
        tally.verified += 1;
        tally.sig_hash_all += usize::from(sig_hash_all);
    }
}

#[test]
fn mainnet_signatures_verify_alike_with_the_transaction_hash() {
    // 89 inputs, each a pay-to-script-hash spend of one three-of-three
    // multisignature script, which satisfies the script hash behind any
    // stake opcode.
    let (tx, _) =
        MsgTx::from_bytes(&unhex(testdata("many_inputs_tx.hex").trim())).expect("decodes");
    assert_eq!(
        tx.tx_hash().to_string(),
        "620f57c92cf05a7f7e7f7d28255d5f7089437bc48e34dcfebf7751d08b7fb8f5"
    );
    // dcrd's benchmark names the script every input spends
    // (`prevOutScript`, `bench_test.go:35`), and the plain script
    // rebuilt from each input is that one.
    let prev_out_script = unhex("a914f5916158e3e2c4551c1796708db8367207ed13bb87");
    for (idx, tx_in) in tx.tx_in.iter().enumerate() {
        let pushes = pushes(&tx_in.signature_script).expect("the signature script parses");
        assert_eq!(
            candidate_pk_scripts(&pushes).first(),
            Some(&prev_out_script),
            "input {idx}"
        );
    }
    let mut tally = Tally::default();
    check_tx(&tx, "many_inputs_tx", &mut tally);
    assert_eq!(
        tally,
        Tally {
            signed: 89,
            verified: 89,
            sig_hash_all: 89,
            rejected: 0,
        }
    );

    // Block 432,100.  Its regular tree spends a vote's reward and a
    // plain output, both paying to a public key hash; its stake tree
    // holds four votes, whose tickets pay to a script hash, and a ticket
    // purchase spending a public key hash.  A public key hash spend
    // verifies against one rebuilt script and fails against the other
    // nine, under either flag set.
    let (block, _) =
        MsgBlock::from_bytes(&unhex(testdata("block432100.hex").trim())).expect("decodes");
    assert_eq!(block.header.height, 432_100);
    for (tree, txs, signed, rejected) in [
        ("regular", &block.transactions, 2, 2 * 9 * 2),
        ("stake", &block.stransactions, 5, 9 * 2),
    ] {
        let mut tally = Tally::default();
        for (tx_idx, tx) in txs.iter().enumerate() {
            check_tx(
                tx,
                &format!("block 432100 {tree} transaction {tx_idx}"),
                &mut tally,
            );
        }
        assert_eq!(
            tally,
            Tally {
                signed,
                verified: signed,
                sig_hash_all: signed,
                rejected,
            },
            "{tree} tree"
        );
    }
}
