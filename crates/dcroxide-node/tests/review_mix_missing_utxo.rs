// SPDX-License-Identifier: ISC
//! A pair request naming an output the chain does not hold is refused
//! with dcrd's rule error.
//!
//! dcrd's `mixpoolChain.FetchUtxoEntry` returns `nil, nil` for a missing
//! output (`server.go:3761-3763`), and `checkAcceptPR` folds a nil entry
//! into the spent-output rejection (`mixing/mixpool/mixpool.go:1448-1451`):
//! `ruleError("output %v is not unspent")`.  The daemon's fetcher used to
//! answer `Err("no utxo entry for …")`, which the pool surfaced as the
//! untyped `PoolError::UtxoFetch` with different text, so
//! `sendrawmixmessage` and the rule-versus-other logging told the two
//! implementations apart.

// Test-harness arithmetic over a fixed height.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::{Arc, Mutex};

use dcroxide_blockchain::process::Chain;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_dcrec::secp256k1::PrivateKey;
use dcroxide_mixing::{
    HashedMessage, PoolError, PoolMessage, RuleKind, SCRIPT_CLASS_P2PKH_V0, sign_message,
};
use dcroxide_netsync::manager::SyncMixPool;
use dcroxide_wire::{MixPairReqUTXO, MsgMixPairReq, OutPoint};

/// A signed pair request over one output that no chain holds, so it
/// reaches the acceptance gauntlet's UTXO loop.
fn pair_request(out_point: OutPoint, tip_height: i64) -> MsgMixPairReq {
    let mut bytes = [0u8; 32];
    bytes[0] = 0x33;
    bytes[31] = 5;
    let priv_key = PrivateKey::from_bytes(&bytes).expect("private key");
    let id = priv_key.public_key().serialize_compressed();
    let mut pr = MsgMixPairReq {
        signature: [0u8; 64],
        identity: id,
        expiry: (tip_height + 10) as u32,
        mix_amount: 10_000_000,
        script_class: SCRIPT_CLASS_P2PKH_V0.to_string(),
        tx_version: 1,
        lock_time: 0,
        message_count: 1,
        input_value: 10_100_000,
        utxos: vec![MixPairReqUTXO {
            out_point,
            script: Vec::new(),
            pub_key: id.to_vec(),
            signature: vec![0u8; 64],
            opcode: 0,
        }],
        change: None,
        flags: 0,
        pairing_flags: 0,
    };
    sign_message(&mut pr, &priv_key).expect("sign pair request");
    pr
}

#[test]
fn a_missing_output_is_rejected_as_not_unspent() {
    let params = dcroxide_chaincfg::simnet_params();
    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    );
    let mix_pool =
        dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone(), &tx_pool);
    let mut sync_pool = dcroxide_node::mixnode::NodeSyncMixPool::new(mix_pool, tx_pool);

    let mut hash = [0u8; 32];
    hash[0] = 5;
    let out_point = OutPoint {
        hash: Hash(hash),
        index: 4,
        tree: 0,
    };
    let msg = HashedMessage::new(PoolMessage::PR(pair_request(out_point, 0)));
    let Err(err) = sync_pool.accept_message(&msg, 1) else {
        panic!("a pair request over a missing output must be refused");
    };

    let want = format!("output {}:4 is not unspent", Hash(hash));
    match &err {
        PoolError::Rule(RuleKind::Other(text)) => assert_eq!(text, &want),
        other => panic!("want the rule error {want:?}, got {other:?}"),
    }
    assert_eq!(err.to_string(), want);
}
