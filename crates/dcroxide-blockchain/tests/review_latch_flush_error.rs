// SPDX-License-Identifier: ISC
//! A failed forced flush on latching to current is the reorganization's
//! whole result (review finding B2-c#8).
//!
//! When `reorganizeChain` latches the chain current it forces the UTXO
//! cache to the backend, and if that flush fails it runs `return err`
//! (`chain.go:1365-1371`): the result is the flush error alone, and the
//! errors gathered from failed reorganization attempts before it are
//! dropped.  The port appended the flush error to those, so a storage
//! failure came back behind an earlier validation error, which is the
//! one callers classify the whole failure by.

use std::collections::BTreeMap;

use dcroxide_blockchain::RuleErrorKind;
use dcroxide_blockchain::notifications::Notification;
use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::regnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;
use tempfile::TempDir;

/// `bf8` extends the `bf7` branch past the best chain, so processing it
/// reorganizes to that branch; `bf8` double spends and fails, and the
/// chain falls back to `bf6`.  The chain then latches current and the
/// forced flush fails, because the database closed as `bf6` was
/// reconnected.  The flush error is the only error returned.
#[test]
fn a_failed_latch_flush_is_returned_alone() {
    let params = regnet_params();
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let mut chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("open chain");

    let mut now = 0;
    let mut accepted = BTreeMap::new();
    let mut bf8 = None;
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("now"),
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                let (_, errs) = chain.process_block(&block, now, &params);
                assert!(errs.is_empty(), "{}: {errs:?}", f[1]);
                accepted.insert(f[1].to_string(), block.header.block_hash());
                if f[1] == "bf7" {
                    break;
                }
            }
            _ => {}
        }
    }
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        if f[0] == "reject" && f[1] == "bf8" {
            assert_eq!(f[2], "ErrMissingTxOut");
            bf8 = Some(MsgBlock::from_bytes(&unhex(f[3])).expect("block").0);
        }
    }
    let bf8 = bf8.expect("bf8 in the battery");
    let bf6 = accepted["bf6"];
    let tip = chain.best_chain.tip().expect("tip");
    assert_eq!(chain.store.node(tip).hash, bf6);

    // Start unlatched so the reorganization's outcome latches the chain
    // current and forces the flush.
    chain.is_current_latch = false;

    // Close the database once the fallback has reconnected `bf6`, the
    // last write the reorganization makes before the forced flush.
    let handle = chain.db.clone().expect("db");
    chain.set_notification_callback(Box::new(move |ntfn| {
        if let Notification::BlockConnected(data) = ntfn
            && data.block.header.block_hash() == bf6
        {
            handle.close().expect("close");
        }
    }));

    let (_, errs) = chain.process_block(&bf8, now, &params);

    // The attempt to `bf8` failed as a rule violation and was branded,
    // and the chain fell back to `bf6` and latched current.
    let bf8_node = chain
        .index
        .lookup_node(&bf8.header.block_hash())
        .expect("bf8 node");
    assert!(chain.store.node(bf8_node).status.known_invalid());
    let tip = chain.best_chain.tip().expect("tip");
    assert_eq!(chain.store.node(tip).hash, bf6);
    assert!(chain.is_current_latch, "the reorganization latched current");

    // Only the flush error comes back.
    assert_eq!(errs.len(), 1, "{errs:?}");
    assert_ne!(errs[0].kind, RuleErrorKind::MissingTxOut, "{errs:?}");
    assert!(
        errs[0].description.contains("database is not open"),
        "the flush's own error: {errs:?}"
    );
}
