// SPDX-License-Identifier: ISC
//! The process's signature pre-verifier is started as its setting says,
//! and fills the signature cache of the chain it was started for.
//!
//! Signature pre-verification of the blocks read ahead is not dcrd's
//! (PARITY *Signature pre-verification ahead of the block thread*).
//! `dcroxide_node::preverify::install` starts the process's one
//! pre-verifier, and the daemon hands it the chain it opened: the cache
//! the chain's connect checks consult must be the one the pre-verifier
//! fills, or every entry it makes is lost.  The process can hold only
//! one, so the test is alone in its file, in a process of its own, and
//! goes through every case in one function: the cases that start
//! nothing first, then the one that starts it, then one more that finds
//! it started.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dcroxide_blockchain::HashedBlock;
use dcroxide_blockchain::process::Chain;
use dcroxide_chainhash::Hash;
use dcroxide_node::preverify::{
    NotStarted, PreverifySetting, install, installed, shutdown, shutdown_line,
};
use dcroxide_txscript::sign::{SignatureType, raw_tx_in_signature};
use dcroxide_txscript::{
    OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160, OP_RETURN, SIG_HASH_ALL, ScriptBuilder,
};
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint, TX_TREE_REGULAR, TxIn, TxOut};

/// The default `--sigcachemaxsize`.
const ENTRIES: u64 = 100_000;

/// A block at height 1 whose one transaction spends a pay-to-pubkey-hash
/// output of the regular tree with a good `SigHashAll` signature: the
/// one shape pre-verification guesses for, guessed right.
fn signed_block() -> MsgBlock {
    let mut private = [0x5au8; 32];
    private[0] = 0x01;
    let public = dcroxide_dcrec::secp256k1::PrivateKey::from_bytes(&private)
        .expect("valid key")
        .public_key()
        .serialize_compressed()
        .to_vec();
    let spent = ScriptBuilder::new()
        .add_op(OP_DUP)
        .add_op(OP_HASH160)
        .add_data(&dcroxide_txscript::stdaddr::hash160(&public))
        .add_op(OP_EQUALVERIFY)
        .add_op(OP_CHECKSIG)
        .script()
        .expect("builds");
    let mut tx = MsgTx {
        tx_in: vec![TxIn {
            previous_out_point: OutPoint {
                hash: Hash([0x33; 32]),
                index: 0,
                tree: TX_TREE_REGULAR,
            },
            sequence: u32::MAX,
            ..TxIn::default()
        }],
        tx_out: vec![TxOut {
            value: 1,
            version: 0,
            pk_script: vec![OP_RETURN],
        }],
        ..MsgTx::default()
    };
    let signature = raw_tx_in_signature(
        &tx,
        0,
        &spent,
        SIG_HASH_ALL,
        &private,
        SignatureType::EcdsaSecp256k1,
    )
    .expect("signs");
    tx.tx_in[0].signature_script = ScriptBuilder::new()
        .add_data(&signature)
        .add_data(&public)
        .script()
        .expect("builds");
    let (mut header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header");
    header.height = 1;
    MsgBlock {
        header,
        transactions: vec![tx],
        stransactions: Vec::new(),
    }
}

#[test]
fn the_installed_preverifier_fills_the_chains_own_cache() {
    let params = dcroxide_chaincfg::regnet_params();
    let chain = Chain::new(&params, Hash::ZERO, false);
    let cache = Arc::clone(chain.sig_cache.as_ref().expect("the default cache"));

    // Off, or with nothing to fill, nothing is started.
    assert_eq!(
        install(&chain, ENTRIES, PreverifySetting::Off),
        Err(NotStarted::Off)
    );
    assert_eq!(
        install(&chain, 0, PreverifySetting::Helpers(2)),
        Err(NotStarted::NoCache)
    );
    let mut cacheless = Chain::new(&params, Hash::ZERO, false);
    cacheless.sig_cache = None;
    assert_eq!(
        install(&cacheless, ENTRIES, PreverifySetting::Default),
        Err(NotStarted::NoCache)
    );
    assert!(installed().is_none(), "nothing was started");
    assert_eq!(shutdown_line(), None);
    shutdown();

    let pool_width = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .saturating_sub(1);
    let helpers = match install(&chain, ENTRIES, PreverifySetting::Helpers(64)) {
        Ok(helpers) => helpers,
        Err(reason) => {
            // A machine of one logical CPU has no helper to give it.
            assert_eq!((reason, pool_width), (NotStarted::NoHelper, 0));
            return;
        }
    };
    assert_eq!(helpers, pool_width.min(64), "capped at the pool's width");
    let preverifier = installed().expect("started");
    assert_eq!(preverifier.helpers(), helpers);
    assert_eq!(
        install(&chain, ENTRIES, PreverifySetting::Helpers(1)),
        Err(NotStarted::AlreadyStarted)
    );
    assert!(Arc::ptr_eq(
        installed().expect("still started"),
        preverifier
    ));

    // The sync chain lowers the floor after its first block; here the
    // test does.  The block's signature lands in the chain's own cache.
    preverifier.set_floor(-1);
    assert!(cache.is_empty());
    let block = HashedBlock::new(Arc::new(signed_block()));
    assert!(preverifier.submit(&block).is_some(), "queued");
    let deadline = Instant::now() + Duration::from_secs(60);
    while preverifier.counts().checked < 1 {
        assert!(Instant::now() < deadline, "the helpers never ran the input");
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(cache.len(), 1, "the chain's own cache was filled");
    let counts = preverifier.counts();
    assert_eq!(
        (
            counts.blocks,
            counts.inputs,
            counts.checked,
            counts.verified
        ),
        (1, 1, 1, 1)
    );

    shutdown();
    assert_eq!(preverifier.submit(&block), None, "shut down");
    assert_eq!(
        shutdown_line().as_deref(),
        Some(
            format!(
                "Signature pre-verification: 1 blocks with 1 inputs to guess for on at most \
                 {helpers} helpers; 1 inputs checked ahead of the block thread, 1 verified; 0 \
                 blocks cut short by the block thread or the shutdown; 0 refused for room"
            )
            .as_str()
        )
    );
}
