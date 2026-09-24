// SPDX-License-Identifier: ISC
//! A corrupt spend journal row is reported in dcrd's words (review
//! finding B7-c#8).
//!
//! dcrd reports it as `corrupt spend information for <hash>: <err>`
//! (`chainio.go:790-792`), where `<err>` is the chain of
//! `errDeserialize` descriptions, each printing its bare text
//! (`chainio.go:138-141`).  The port formatted the inner error with
//! `{:?}`, which printed `Deserialize("...")` with Debug quoting, and
//! its `Display` put a `deserialize error: ` prefix in front of every
//! nested level.

use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::simnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint, TxIn, TxOut};

fn tx(prev: OutPoint, value_in: i64) -> MsgTx {
    MsgTx {
        tx_in: vec![TxIn {
            previous_out_point: prev,
            sequence: u32::MAX,
            value_in,
            block_height: 10,
            block_index: 1,
            signature_script: Vec::new(),
        }],
        tx_out: vec![TxOut {
            value: 1,
            version: 0,
            pk_script: vec![0x51],
        }],
        ..Default::default()
    }
}

#[test]
fn a_corrupt_journal_row_reads_like_dcrd() {
    let params = simnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);

    let coinbase_in = OutPoint {
        hash: Hash::ZERO,
        index: u32::MAX,
        tree: 0,
    };
    let spent = OutPoint {
        hash: Hash([7u8; 32]),
        index: 3,
        tree: 0,
    };
    let mut header = BlockHeader::from_bytes(&[0u8; 180]).expect("header").0;
    header.height = 11;
    header.vote_bits = 0x0001;
    let block = MsgBlock {
        header,
        transactions: vec![tx(coinbase_in, 0), tx(spent, 2_000)],
        stransactions: Vec::new(),
    };
    let hash = block.header.block_hash();

    // Present and non-empty, but the stxo header runs off the end.
    chain
        .spend_journal
        .insert(hash.0, vec![0xff, 0xff, 0xff, 0xff]);

    let err = chain
        .fetch_spend_journal(&block, false)
        .expect_err("a corrupt row must not decode");
    let want = format!(
        "corrupt spend information for {hash}: unable to decode stxo for {}:{}: ",
        spent.hash, spent.index
    );
    assert!(
        err.description.starts_with(&want),
        "want the prefix {want:?}, got {:?}",
        err.description
    );
    assert!(
        !err.description.contains("Deserialize(") && !err.description.contains("deserialize error"),
        "the inner errors print their bare descriptions: {:?}",
        err.description
    );
}
