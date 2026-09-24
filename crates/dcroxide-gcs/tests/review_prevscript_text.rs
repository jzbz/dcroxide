// SPDX-License-Identifier: ISC
//! The text of a failed version 2 filter build.
//!
//! dcrd's `blockcf2.PrevScriptError` prints "unable to find output
//! script <hash>:<index>:<tree> referenced by <txhash>:<txinidx>", and
//! that text is the description of the `ErrMissingTxOut` rule error
//! `checkConnectBlock` and `fetchBlockFilter` return and part of the
//! mining template's commitment-root error.  The port's error types had
//! only a derived `Debug`, so every caller printed a Rust struct dump.
//! The same went for the wire error inside `FromBytesV2`'s
//! `ErrMisserialized` description, which dcrd prints with `%v`.

use dcroxide_chainhash::Hash;
use dcroxide_gcs::{ErrorKind, FilterV2, blockcf2};
use dcroxide_testutil::{oracle_or_skip, unhex};
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint, TxIn, TxOut, TxSerializeType};

/// No previous scripts at all.
struct NoScripts;

impl blockcf2::PrevScripter for NoScripts {
    fn prev_script(&self, _: &OutPoint) -> Option<(u16, &[u8])> {
        None
    }
}

fn tx(tx_in: Vec<TxIn>) -> MsgTx {
    MsgTx {
        ser_type: TxSerializeType::Full,
        version: 1,
        tx_in,
        tx_out: vec![TxOut {
            value: 1,
            version: 0,
            pk_script: vec![0x51],
        }],
        lock_time: 0,
        expiry: 0,
    }
}

fn input(hash: Hash, index: u32, tree: i8) -> TxIn {
    TxIn {
        previous_out_point: OutPoint { hash, index, tree },
        sequence: 0xffff_ffff,
        value_in: 1,
        block_height: 0,
        block_index: 0xffff_ffff,
        signature_script: vec![0x51],
    }
}

/// A coinbase plus one transaction whose second input spends an
/// outpoint in the stake tree; the first input's script is the one a
/// build over no scripts reports missing.
fn block() -> MsgBlock {
    let (header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("header");
    MsgBlock {
        header,
        transactions: vec![
            tx(vec![input(Hash::ZERO, u32::MAX, 0)]),
            tx(vec![
                input(Hash([0x11; 32]), 7, 1),
                input(Hash([0x22; 32]), 0, 0),
            ]),
        ],
        stransactions: Vec::new(),
    }
}

/// The missing-script error prints dcrd's text: the outpoint as
/// `OutPoint.String` renders it (`hash:index`), then its tree, then the
/// referencing input.
#[test]
fn a_missing_script_prints_dcrds_text() {
    let block = block();
    let err = blockcf2::regular(&block, &NoScripts).expect_err("the script is missing");
    let want = format!(
        "unable to find output script {}:7:1 referenced by {}:0",
        "11".repeat(32),
        block.transactions[1].tx_hash()
    );
    assert_eq!(err.to_string(), want);
    let blockcf2::RegularError::PrevScript(inner) = &err else {
        panic!("a missing script is a PrevScriptError, got {err:?}");
    };
    assert_eq!(inner.to_string(), want);
}

/// The same text as dcrd's own `PrevScriptError.Error`, live through
/// the oracle.
#[test]
fn a_missing_script_prints_what_dcrd_prints() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let block = block();
    let ours = blockcf2::regular(&block, &NoScripts)
        .expect_err("the script is missing")
        .to_string();

    // No previous scripts, then the block.
    let mut req = 0u16.to_be_bytes().to_vec();
    req.extend_from_slice(&block.serialize());
    let resp = oracle.call("gcs_blockcf2", &req);
    assert_eq!(
        resp["kind"].as_str(),
        Some("PrevScriptError"),
        "unexpected oracle response: {resp}"
    );
    assert_eq!(Some(ours.as_str()), resp["error"].as_str());

    // A well-formed request still builds a filter there, so the error
    // above is the missing script and not a malformed request.
    let mut req = 2u16.to_be_bytes().to_vec();
    for (hash, index, tree) in [([0x11u8; 32], 7u32, 1u8), ([0x22; 32], 0, 0)] {
        req.extend_from_slice(&hash);
        req.extend_from_slice(&index.to_be_bytes());
        req.push(tree);
        req.extend_from_slice(&0u16.to_be_bytes());
        req.extend_from_slice(&1u16.to_be_bytes());
        req.push(0x51);
    }
    req.extend_from_slice(&block.serialize());
    let resp = oracle.call("gcs_blockcf2", &req);
    let dump = String::from_utf8(unhex(resp["result"].as_str().expect("a filter"))).expect("UTF-8");
    assert!(dump.starts_with("key="), "unexpected oracle dump: {dump}");
}

/// A serialized filter whose entry count does not decode reports the
/// wire error in Go's text, as dcrd's `%v` does.
#[test]
fn a_misserialized_entry_count_prints_gos_text() {
    let err = FilterV2::from_bytes(blockcf2::B, blockcf2::M, &[0xfd, 0x01])
        .expect_err("a truncated varint");
    assert_eq!(err.kind, ErrorKind::Misserialized);
    assert_eq!(
        err.description,
        "failed to read number of filter items: unexpected EOF"
    );

    let err = FilterV2::from_bytes(blockcf2::B, blockcf2::M, &[0xfd, 0x01, 0x00])
        .expect_err("a non-canonical varint");
    assert_eq!(
        err.description,
        "failed to read number of filter items: ReadVarInt: non-canonical varint 1 - \
         discriminant fd must encode a value greater than fd"
    );
}
