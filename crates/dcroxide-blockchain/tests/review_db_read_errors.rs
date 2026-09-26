// SPDX-License-Identifier: ISC
//! A chain database row that cannot be read fails the operation instead
//! of aborting the node or serving wrong data (review finding B2-p#6).
//!
//! Once a block leaves the recent in-memory window, its body, spend
//! journal row, filter and header commitments are read back from the
//! database.  dcrd returns every failure of those reads as an error --
//! `fetchBlockByNode`, the `db.View` around `dbFetchSpendJournalEntry`,
//! and `FilterByBlockHash`/`LocateCFiltersV2` (`headercmt.go:167-183`,
//! `:249-268`) -- so the reorganization or request fails with the node
//! still running.  The port discarded the read result: a block body
//! that could not be read became a `None` its callers `expect`ed, which
//! under the release profile's `panic = "abort"` killed the process;
//! a spend journal read that could not start became the "missing
//! spend journal data" panic; a corrupt filter row was reported as no
//! filter; and a corrupt commitments row was served with a proof over
//! no leaves.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use dcroxide_blockchain::RuleErrorKind;
use dcroxide_blockchain::chaindb::{GCS_FILTER_BUCKET_NAME, HEADER_CMTS_BUCKET_NAME};
use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::{Params, regnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;
use tempfile::TempDir;

/// The battery's accepted blocks by label.
fn battery() -> (i64, BTreeMap<String, MsgBlock>, Vec<String>) {
    let mut now = 0;
    let mut blocks = BTreeMap::new();
    let mut order = Vec::new();
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("now"),
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                blocks.insert(f[1].to_string(), block);
                order.push(f[1].to_string());
            }
            _ => {}
        }
    }
    (now, blocks, order)
}

/// A database-backed chain over the battery's accepted blocks up to and
/// including `last`.
fn chain_through(dir: &TempDir, params: &Params, last: &str) -> Chain {
    let (now, blocks, order) = battery();
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let mut chain = Chain::open(db, params, Hash::ZERO, false, 0).expect("open chain");
    for label in &order {
        let (_, errs) = chain.process_block(&blocks[label], now, params);
        assert!(errs.is_empty(), "{label}: {errs:?}");
        if label == last {
            break;
        }
    }
    chain
}

/// Flip a byte in the middle of the block's record in the flat block
/// files, so the database's checksum rejects the read.
fn damage_block_file(dir: &TempDir, block: &MsgBlock) {
    let raw = block.serialize();
    let db_path = dir.path().join("chain");
    for entry in std::fs::read_dir(&db_path).expect("database directory") {
        let path = entry.expect("entry").path();
        if path.extension().is_some_and(|e| e == "fdb") && damage_in_file(&path, &raw) {
            return;
        }
    }
    panic!(
        "block {} not found in the flat files",
        block.header.block_hash()
    );
}

fn damage_in_file(path: &Path, raw: &[u8]) -> bool {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open block file");
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).expect("read block file");
    let Some(offset) = contents.windows(raw.len()).position(|w| w == raw) else {
        return false;
    };
    let at = offset + raw.len() / 2;
    file.seek(SeekFrom::Start(at as u64)).expect("seek");
    file.write_all(&[contents[at] ^ 0xff]).expect("write");
    file.sync_all().expect("sync");
    true
}

/// Replace a block's row in a chain database bucket.
fn set_row(chain: &Chain, bucket: &[u8], hash: &Hash, row: &[u8]) {
    chain
        .db
        .as_ref()
        .expect("db")
        .update(|tx| {
            let meta = tx.metadata();
            meta.bucket(bucket).expect("bucket").put(&hash.0, row)
        })
        .expect("rewrite the row");
}

/// The reorganization to `bf4` detaches `bf2`, whose parent `bf1` has
/// left the recent window.  A `bf1` body the database cannot read
/// fails the reorganization with the database's error; the node keeps
/// running on its old tip, and the target is not branded invalid.
#[test]
fn an_unreadable_block_body_fails_the_reorg_instead_of_aborting() {
    let params = regnet_params();
    let dir = TempDir::new().expect("tempdir");
    let (now, blocks, _) = battery();
    let mut chain = chain_through(&dir, &params, "bf3");
    let bf1 = &blocks["bf1"];
    let bf2 = blocks["bf2"].header.block_hash();
    assert_eq!(blocks["bf3"].header.prev_block, bf1.header.block_hash());
    let tip = chain.best_chain.tip().expect("tip");
    assert_eq!(chain.store.node(tip).hash, bf2);

    // Keep only the tip in memory, then damage the fork block's body.
    chain.prune_chain_memory(1);
    assert!(!chain.blocks.contains_key(&bf1.header.block_hash().0));
    chain.db.as_ref().expect("db").flush().expect("flush");
    damage_block_file(&dir, bf1);

    let bf4 = &blocks["bf4"];
    let (_, errs) = chain.process_block(bf4, now, &params);
    let err = errs
        .iter()
        .find(|e| e.kind == RuleErrorKind::UtxoBackendCorruption)
        .unwrap_or_else(|| panic!("the reorg must fail on the unreadable body: {errs:?}"));
    assert!(
        err.description
            .contains("block data checksum does not match"),
        "the database's own error: {err:?}"
    );

    let tip = chain.best_chain.tip().expect("tip");
    assert_eq!(chain.store.node(tip).hash, bf2, "the old tip stays");
    let target = chain
        .index
        .lookup_node(&bf4.header.block_hash())
        .expect("bf4 node");
    assert!(
        !chain.store.node(target).status.known_invalid(),
        "local corruption branded the target invalid"
    );
}

/// The template view reads the tip's parent, which has left the recent
/// window; an unreadable body is the error dcrd's
/// `FetchUtxoViewParentTemplate` returns (`headercmt.go:87-94`).
#[test]
fn an_unreadable_block_body_fails_the_template_view() {
    let params = regnet_params();
    let dir = TempDir::new().expect("tempdir");
    let (_, blocks, _) = battery();
    let mut chain = chain_through(&dir, &params, "bbm10");
    let tip_block = &blocks["bbm10"];
    let parent = &blocks["bbm9"];
    assert_eq!(tip_block.header.prev_block, parent.header.block_hash());

    chain.prune_chain_memory(1);
    assert!(!chain.blocks.contains_key(&parent.header.block_hash().0));
    chain.db.as_ref().expect("db").flush().expect("flush");
    damage_block_file(&dir, parent);

    // The tip block itself is a template built on the tip's parent.
    let err = chain
        .fetch_utxo_view_parent_template(tip_block, &params)
        .err()
        .expect("an unreadable parent body must fail the view");
    assert!(
        err.contains("block data checksum does not match"),
        "the database's own error: {err}"
    );
}

/// A template built on the tip reads the tip's body as its parent, and
/// dcrd wraps a failed read there as `ErrMissingParent` carrying the
/// read error's text (`validate.go:4510-4513`).
#[test]
fn a_template_on_the_tip_reports_an_unreadable_parent_as_missing() {
    let params = regnet_params();
    let dir = TempDir::new().expect("tempdir");
    let (now, blocks, _) = battery();
    let mut chain = chain_through(&dir, &params, "bbm10");
    let tip_block = &blocks["bbm10"];
    let template = &blocks["bbm11"];
    assert_eq!(template.header.prev_block, tip_block.header.block_hash());

    // Evict the tip's body from the recent window too, so the template
    // check reads it back from the damaged block file.
    chain.prune_chain_memory(1);
    chain.blocks.remove(&tip_block.header.block_hash().0);
    chain.db.as_ref().expect("db").flush().expect("flush");
    damage_block_file(&dir, tip_block);

    let err = chain
        .check_connect_block_template(template, now, &params)
        .expect_err("an unreadable parent body must fail the template");
    assert_eq!(err.kind, RuleErrorKind::MissingParent, "{err:?}");
    assert!(
        err.description
            .contains("block data checksum does not match"),
        "the database's own error: {err:?}"
    );
}

/// A template built on the tip's parent reads the tip and its parent,
/// and dcrd returns a failed read there as the read error itself
/// (`validate.go:4527-4534`), which the port carries as a local
/// corruption error rather than a rule violation.
#[test]
fn a_template_on_the_tip_parent_reports_an_unreadable_body_as_the_read_error() {
    let params = regnet_params();
    let dir = TempDir::new().expect("tempdir");
    let (now, blocks, _) = battery();
    let mut chain = chain_through(&dir, &params, "bbm10");
    let tip_block = &blocks["bbm10"];
    let parent = &blocks["bbm9"];
    assert_eq!(tip_block.header.prev_block, parent.header.block_hash());

    chain.prune_chain_memory(1);
    assert!(!chain.blocks.contains_key(&parent.header.block_hash().0));
    chain.db.as_ref().expect("db").flush().expect("flush");
    damage_block_file(&dir, parent);

    // The tip block itself is a template built on the tip's parent.
    let err = chain
        .check_connect_block_template(tip_block, now, &params)
        .expect_err("an unreadable parent body must fail the template");
    assert_eq!(err.kind, RuleErrorKind::UtxoBackendCorruption, "{err:?}");
    assert!(!err.kind.is_rule_violation());
    assert!(
        err.description
            .contains("block data checksum does not match"),
        "the database's own error: {err:?}"
    );
}

/// A spend journal read that cannot start is dcrd's failed `db.View`,
/// returned as the error rather than the "missing spend journal data"
/// panic kept for a row that is truly absent.
#[test]
fn a_spend_journal_read_that_cannot_start_is_an_error() {
    let params = regnet_params();
    let dir = TempDir::new().expect("tempdir");
    let (_, blocks, _) = battery();
    let mut chain = chain_through(&dir, &params, "bbm10");
    let parent = &blocks["bbm9"];
    chain.prune_chain_memory(1);
    assert!(
        !chain
            .spend_journal
            .contains_key(&parent.header.block_hash().0)
    );

    chain.db.as_ref().expect("db").close().expect("close");
    let err = chain
        .fetch_spend_journal(parent, true)
        .expect_err("a read that cannot start must fail");
    // Not corruption: dcrd's `ErrDbNotOpen` matches neither of its
    // sync manager's `Critical failure` checks.
    assert_eq!(err.kind, RuleErrorKind::UtxoBackend);
    assert!(
        err.description.contains("database is not open"),
        "the database's own error: {err:?}"
    );
}

/// A filter row that does not decode is dcrd's `ErrCorruption` from
/// `FilterByBlockHash`, not a missing filter; `LocateCFiltersV2` serves
/// the stored bytes without decoding them, as dcrd's
/// `dbFetchRawGCSFilter` does.
#[test]
fn a_corrupt_filter_row_is_an_error_not_a_missing_filter() {
    let params = regnet_params();
    let dir = TempDir::new().expect("tempdir");
    let mut chain = chain_through(&dir, &params, "bbm10");
    chain.prune_chain_memory(2);
    let tip = chain.best_chain.tip().expect("tip");
    let old = chain.store.relative_ancestor(tip, 5).expect("ancestor");
    let hash = chain.store.node(old).hash;
    assert!(!chain.filters.contains_key(&hash.0));
    // An entry count whose varint needs eight more bytes.
    set_row(&chain, GCS_FILTER_BUCKET_NAME, &hash, &[0xff]);

    let err = chain
        .filter_by_block_hash(&hash)
        .expect_err("a corrupt filter row must fail");
    assert_ne!(err.kind, RuleErrorKind::NoFilter, "{err:?}");
    assert!(!err.kind.is_rule_violation());
    assert!(
        err.description
            .starts_with(&format!("corrupt filter for {hash}: ")),
        "dcrd's corrupt filter text: {err:?}"
    );

    let located = chain
        .locate_cfilters_v2(&hash, &hash)
        .expect("the raw filter bytes are served");
    assert_eq!(located.cfilters.len(), 1);
    assert_eq!(located.cfilters[0].data, vec![0xff]);
}

/// A header commitments row that does not decode fails both filter
/// requests, where the port had served a proof over no leaves.
#[test]
fn a_corrupt_commitments_row_is_an_error_not_an_empty_proof() {
    let params = regnet_params();
    let dir = TempDir::new().expect("tempdir");
    let mut chain = chain_through(&dir, &params, "bbm10");
    chain.prune_chain_memory(2);
    let tip = chain.best_chain.tip().expect("tip");
    let old = chain.store.relative_ancestor(tip, 5).expect("ancestor");
    let hash = chain.store.node(old).hash;
    assert!(!chain.header_commitments.contains_key(&hash.0));
    assert!(chain.filter_by_block_hash(&hash).is_ok());
    // Five commitments promised, none present.
    set_row(&chain, HEADER_CMTS_BUCKET_NAME, &hash, &[0x05]);

    let err = chain
        .filter_by_block_hash(&hash)
        .expect_err("a corrupt commitments row must fail");
    assert_eq!(err.kind, RuleErrorKind::UtxoBackendCorruption, "{err:?}");
    let err = chain
        .locate_cfilters_v2(&hash, &hash)
        .expect_err("a corrupt commitments row must fail the batch");
    assert_eq!(err.kind, RuleErrorKind::UtxoBackendCorruption, "{err:?}");
}
