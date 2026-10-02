// SPDX-License-Identifier: ISC
//! Block processing accepts a new header before it looks at the block's
//! data, and checks the data's commitment before the rest of it (dcrd
//! `024899e4`, `ddd3b6d2` and `b56e78f5`, as of `6f6cf21b`).
//!
//! dcrd's `ProcessBlock` (`process.go:445-547`) now runs:
//!
//! 1. the duplicate and known-invalid checks;
//! 2. for an unknown header, `maybeAcceptBlockHeader`: header sanity,
//!    the orphan and invalid-ancestor checks, and the positional header
//!    checks, after which the header is in the block index;
//! 3. `checkBlockDataPreconditions`: the wire size limit and the header's
//!    commitment to the transaction trees, which never marks the block,
//!    and which reports whether the commitment is definitively proven;
//! 4. `checkBlockDataSanity` and `maybeAcceptBlockData`, which mark the
//!    block on a rule violation only when the commitment is proven.
//!
//! The tests below port the upstream `TestProcessLogic` changes
//! (`process_test.go:747-759`, `:780-806`), whose chain forces the header
//! commitments agenda to "no" (`process_test.go:223`), so each is run
//! both on regnet as shipped, where the positional state of that agenda
//! is undetermined, and with it forced.  The battery statuses were
//! produced by replaying `data/fullblock_vectors.txt` through dcrd's own
//! `ProcessBlock` at `6f6cf21b`, in both modes, recording for each
//! rejected block the node status left behind and what processing the
//! block and its header again returns.

// Test-harness arithmetic over bounded values.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::RuleErrorKind;
use dcroxide_blockchain::agendas::VOTE_ID_HEADER_COMMITMENTS;
use dcroxide_blockchain::blockindex::BlockStatus;
use dcroxide_blockchain::chaindb::db_load_block_index;
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::validate::check_proof_of_work_sanity;
use dcroxide_blockchain::{RuleError, UtxoEntry};
use dcroxide_chaincfg::{Params, regnet_params, simnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_stake::TxType;
use dcroxide_standalone::{BigInt, Sign};
use dcroxide_testutil::unhex;
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint, TxOut};

/// Regnet, with the header commitments agenda forced to "no" when
/// `force_no` is set (dcrd's `forceDeploymentResult`).
fn regnet(force_no: bool) -> Params {
    let mut params = regnet_params();
    if force_no {
        let mut found = false;
        for (_, deployments) in &mut params.deployments {
            for deployment in deployments.iter_mut() {
                if deployment.vote.id == VOTE_ID_HEADER_COMMITMENTS {
                    deployment.forced_choice_id = "no";
                    found = true;
                }
            }
        }
        assert!(found, "regnet has a header commitments deployment");
    }
    params
}

/// One row of the full block battery.
struct Row {
    tag: String,
    name: String,
    kind: String,
    block: Option<MsgBlock>,
    now: i64,
}

/// The full block battery, with the current time each row runs at.
fn battery() -> Vec<Row> {
    let mut now = 0;
    let mut rows = Vec::new();
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        let (name, kind, hex) = match f[0] {
            "now" => {
                now = f[1].parse().expect("now");
                continue;
            }
            "accept" => (f[1], "", f[4]),
            "reject" => (f[1], f[2], f[3]),
            "orphanorreject" => (f[1], "", f[2]),
            _ => continue,
        };
        let (block, _) = MsgBlock::from_bytes(&unhex(hex)).expect("block");
        rows.push(Row {
            tag: f[0].to_string(),
            name: name.to_string(),
            kind: kind.to_string(),
            block: Some(block),
            now,
        });
    }
    rows
}

/// The battery block with the given name.
fn battery_block(rows: &[Row], name: &str) -> MsgBlock {
    rows.iter()
        .find(|r| r.name == name)
        .and_then(|r| r.block.clone())
        .unwrap_or_else(|| panic!("{name} is in the battery"))
}

/// Process the battery's rows on a new chain up to, not including, the
/// named row, asserting the accepted ones are accepted.
fn replay_until(rows: &[Row], params: &Params, stop: &str) -> (Chain, i64) {
    replay_rows_until(rows, params, stop, false)
}

/// [`replay_until`], skipping every row but the accepted ones when
/// `accepted_only` is set.
fn replay_rows_until(
    rows: &[Row],
    params: &Params,
    stop: &str,
    accepted_only: bool,
) -> (Chain, i64) {
    let mut chain = Chain::new(params, Hash::ZERO, false);
    let now = replay_into(&mut chain, rows, params, stop, accepted_only);
    (chain, now)
}

/// [`replay_rows_until`] on a chain the caller made, returning the
/// current time of the named row.
fn replay_into(
    chain: &mut Chain,
    rows: &[Row],
    params: &Params,
    stop: &str,
    accepted_only: bool,
) -> i64 {
    for row in rows {
        if row.name == stop {
            return row.now;
        }
        if accepted_only && row.tag != "accept" {
            continue;
        }
        let block = row.block.as_ref().expect("block");
        let (_, errs) = chain.process_block(block, row.now, params);
        if row.tag == "accept" {
            assert!(
                errs.is_empty() || errs[0].kind == RuleErrorKind::MissingParent,
                "{}: {errs:?}",
                row.name
            );
        }
    }
    panic!("{stop} is in the battery");
}

fn first_kind(errs: &[RuleError]) -> &'static str {
    errs.first().map_or("ok", |e| e.kind.kind_name())
}

fn status_of(chain: &Chain, hash: &Hash) -> String {
    chain.index.lookup_node(hash).map_or_else(
        || "-".to_string(),
        |n| chain.store.node(n).status.0.to_string(),
    )
}

fn header_kind(chain: &mut Chain, header: &BlockHeader, now: i64, params: &Params) -> String {
    match chain.process_block_header(header, now, params) {
        Ok(()) => "ok".to_string(),
        Err(e) => e.kind.kind_name().to_string(),
    }
}

/// Grind the header's nonce from zero until its proof of work passes
/// the sanity checks.
fn grind(header: &mut BlockHeader, params: &Params) {
    let pow_limit = BigInt::from_bytes_be(Sign::Plus, &params.pow_limit.to_be_bytes());
    header.nonce = 0;
    while check_proof_of_work_sanity(header, &pow_limit, false).is_err() {
        header.nonce += 1;
    }
}

/// dcrd `process_test.go:747-759`: block data that does not match a
/// known valid header is rejected without marking the header, so the
/// real data is still accepted afterwards.
#[test]
fn mismatched_data_for_a_known_header_leaves_it_valid() {
    let rows = battery();
    let bfb = battery_block(&rows, "bfb");
    let mut mismatched = bfb.clone();
    mismatched.transactions[0].version += 1;
    let hash = bfb.header.block_hash();
    for force_no in [false, true] {
        let params = regnet(force_no);
        let now = rows[0].now;
        let mut chain = Chain::new(&params, Hash::ZERO, false);
        chain
            .process_block_header(&bfb.header, now, &params)
            .expect("bfb's header");

        let (_, errs) = chain.process_block(&mismatched, now, &params);
        assert_eq!(first_kind(&errs), "ErrBadMerkleRoot", "force_no {force_no}");
        assert_eq!(errs.len(), 1);
        assert_eq!(status_of(&chain, &hash), "0", "force_no {force_no}");
        assert!(!chain.have_block(&hash));

        let (_, errs) = chain.process_block(&bfb, now, &params);
        assert!(errs.is_empty(), "force_no {force_no}: {errs:?}");
        let (_, errs) = chain.process_block(&bfb, now, &params);
        assert_eq!(first_kind(&errs), "ErrDuplicateBlock");
    }
}

/// The same with the header unknown: it is accepted to the index before
/// the data is looked at, and stays valid.
#[test]
fn mismatched_data_for_a_new_header_indexes_it_unmarked() {
    let rows = battery();
    let bfb = battery_block(&rows, "bfb");
    let mut mismatched = bfb.clone();
    mismatched.transactions[0].version += 1;
    let hash = bfb.header.block_hash();
    for force_no in [false, true] {
        let params = regnet(force_no);
        let now = rows[0].now;
        let mut chain = Chain::new(&params, Hash::ZERO, false);

        let (_, errs) = chain.process_block(&mismatched, now, &params);
        assert_eq!(first_kind(&errs), "ErrBadMerkleRoot", "force_no {force_no}");
        assert_eq!(status_of(&chain, &hash), "0", "the header is indexed");
        assert_eq!(
            chain.index.best_header().map(|n| chain.store.node(n).hash),
            Some(hash)
        );

        let (_, errs) = chain.process_block(&bfb, now, &params);
        assert!(errs.is_empty(), "force_no {force_no}: {errs:?}");
    }
}

/// The same on simnet, where the agenda is forced active and the
/// commitment checked is DCP0005's combined root: the processed block
/// chain's first block, after its seeded outputs.
#[test]
fn mismatched_data_for_a_known_simnet_header_leaves_it_valid() {
    let params = simnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    let now: i64 = 2_000_000_000;
    let mut first = None;
    for line in include_str!("data/processblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "u" => {
                // u <hash> <idx> <tree> <amount> <height> <bindex>
                //   <sver> <flags> <script>
                let bytes = unhex(f[1]);
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes);
                let op = OutPoint {
                    hash: Hash(hash),
                    index: f[2].parse().expect("idx"),
                    tree: f[3].parse().expect("tree"),
                };
                let mut entry = UtxoEntry::new(
                    f[4].parse().expect("amt"),
                    unhex(f[9]),
                    f[5].parse().expect("h"),
                    f[6].parse().expect("bi"),
                    f[7].parse().expect("sv"),
                    false,
                    false,
                    TxType::Regular,
                    None,
                );
                entry.set_packed_flags_bits(f[8].parse().expect("fl"));
                entry.set_state_bits(1);
                let mut seed_view = dcroxide_blockchain::utxoview::UtxoView::new();
                seed_view.insert_entry(&op, entry);
                chain.commit_view(&mut seed_view);
            }
            "bulk" => chain.bulk_import_mode = f[1] == "1",
            "pb" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[1])).expect("block");
                assert_eq!(f[2], "ok", "the first block is accepted");
                first = Some(block);
                break;
            }
            _ => {}
        }
    }
    let block = first.expect("a first block");
    let hash = block.header.block_hash();
    chain
        .process_block_header(&block.header, now, &params)
        .expect("the header");

    let mut mismatched = block.clone();
    mismatched.transactions[0].version += 1;
    let want = dcroxide_standalone::calc_combined_tx_tree_merkle_root(
        &mismatched.transactions,
        &mismatched.stransactions,
    );
    let (_, errs) = chain.process_block(&mismatched, now, &params);
    assert_eq!(first_kind(&errs), "ErrBadMerkleRoot");
    assert_eq!(
        errs[0].description,
        format!(
            "block merkle root is invalid - block header indicates {}, but calculated value \
             is {want}",
            block.header.merkle_root
        )
    );
    assert_eq!(status_of(&chain, &hash), "0");

    let (_, errs) = chain.process_block(&block, now, &params);
    assert!(errs.is_empty(), "{errs:?}");
    let (_, errs) = chain.process_block(&block, now, &params);
    assert_eq!(first_kind(&errs), "ErrDuplicateBlock");
}

/// dcrd `process_test.go:780-793` (`b1bad`): a block whose new header is
/// valid but whose data fails a sanity check leaves the header in the
/// index, marked invalid when the data commitment is proven, so the
/// header and the block are then known invalid, and it becomes the best
/// invalid header.  The battery's `bsd0` is such a block (a ticket below
/// the stake difficulty); only the accepted blocks before it are
/// processed, so it is the only block that can be invalid.
#[test]
fn a_data_sanity_failure_marks_a_header_whose_commitment_is_proven() {
    let rows = battery();
    for force_no in [false, true] {
        let params = regnet(force_no);
        let (mut chain, now) = replay_rows_until(&rows, &params, "bsd0", true);
        let bsd0 = battery_block(&rows, "bsd0");
        let hash = bsd0.header.block_hash();

        let (_, errs) = chain.process_block(&bsd0, now, &params);
        assert_eq!(first_kind(&errs), "ErrNotEnoughStake");
        let node = chain
            .index
            .lookup_node(&hash)
            .expect("the header is indexed");
        let (again, header, status) = if force_no {
            (
                "ErrKnownInvalidBlock",
                "ErrKnownInvalidBlock",
                BlockStatus::VALIDATE_FAILED,
            )
        } else {
            ("ErrNotEnoughStake", "ok", BlockStatus::NONE)
        };
        assert_eq!(chain.store.node(node).status, status, "force_no {force_no}");
        assert_eq!(header_kind(&mut chain, &bsd0.header, now, &params), header);
        let (_, errs) = chain.process_block(&bsd0, now, &params);
        assert_eq!(first_kind(&errs), again, "force_no {force_no}");
        let best_invalid = if force_no { Some(node) } else { None };
        assert_eq!(
            chain.index.best_invalid(),
            best_invalid,
            "force_no {force_no}"
        );
    }
}

/// dcrd `process_test.go:795-806` (`b1bada`): a positional failure of
/// the data is marked under the same condition.  The battery's `bmf20`
/// carries an expired transaction.
#[test]
fn a_positional_data_failure_marks_a_header_whose_commitment_is_proven() {
    let rows = battery();
    for force_no in [false, true] {
        let params = regnet(force_no);
        let (mut chain, now) = replay_until(&rows, &params, "bmf20");
        let bmf20 = battery_block(&rows, "bmf20");

        let (_, errs) = chain.process_block(&bmf20, now, &params);
        assert_eq!(first_kind(&errs), "ErrExpiredTx");
        let status = status_of(&chain, &bmf20.header.block_hash());
        let (_, errs) = chain.process_block(&bmf20, now, &params);
        if force_no {
            assert_eq!(status, "4");
            assert_eq!(first_kind(&errs), "ErrKnownInvalidBlock");
        } else {
            assert_eq!(status, "0");
            assert_eq!(first_kind(&errs), "ErrExpiredTx");
        }
    }
}

/// The number of votes in the stored block index row for the hash, or
/// `None` when there is no row.
fn stored_votes(chain: &Chain, hash: &Hash) -> Option<usize> {
    let mut votes = None;
    chain
        .db
        .as_ref()
        .expect("db-backed")
        .view(|tx| {
            db_load_block_index(tx, |entry| {
                if entry.header.block_hash() == *hash {
                    votes = Some(entry.vote_info.len());
                }
                Ok(())
            })
            .map_err(|e| panic!("load the block index: {e:?}"))
        })
        .expect("read the block index");
    votes
}

/// Accepting a block's data populates its node's ticket and vote
/// information, which marks the node for the next flush (dcrd
/// `PopulateTicketInfo`, `blockindex.go:955-960`, called at
/// `process.go:296-298`), even when a later check rejects the data
/// without marking the block, so the stored row of the header is
/// rewritten with the block's votes.  The battery's `bmf20` (five votes,
/// an expired transaction) has its header processed and flushed first,
/// then its data, on regnet as shipped; the next accepted row, `bmt2`,
/// flushes the index.  dcrd at `6f6cf21b` leaves one modified node after
/// the block, none after `bmt2`, and a stored row with five votes.
#[test]
fn rejected_block_data_still_rewrites_the_headers_votes() {
    let rows = battery();
    let params = regnet(false);
    let dir = tempfile::tempdir().expect("tempdir");
    let opts = Options::new(dir.path().join("chain"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let mut chain = Chain::open(db, &params, Hash::ZERO, false, 0).expect("open chain");
    let now = replay_into(&mut chain, &rows, &params, "bmf20", false);
    let bmf20 = battery_block(&rows, "bmf20");
    let hash = bmf20.header.block_hash();
    assert_eq!(bmf20.header.voters, 5);

    chain
        .process_block_header(&bmf20.header, now, &params)
        .expect("bmf20's header");
    assert_eq!(chain.index.modified_len(), 0, "the header is flushed");
    assert_eq!(stored_votes(&chain, &hash), Some(0));

    let (_, errs) = chain.process_block(&bmf20, now, &params);
    assert_eq!(first_kind(&errs), "ErrExpiredTx");
    assert_eq!(status_of(&chain, &hash), "0");
    assert_eq!(chain.index.modified_len(), 1, "the populated node");
    assert_eq!(stored_votes(&chain, &hash), Some(0), "not flushed yet");

    // dcrd's harness processes the rows after the target up to and
    // including the next accepted one.
    let start = rows.iter().position(|r| r.name == "bmf20").expect("bmf20") + 1;
    let next = rows[start..]
        .iter()
        .find(|r| r.tag == "accept")
        .expect("an accepted row after bmf20");
    assert_eq!(next.name, "bmt2");
    for row in &rows[start..] {
        let block = row.block.as_ref().expect("block");
        let (_, errs) = chain.process_block(block, row.now, &params);
        if row.name == next.name {
            assert!(errs.is_empty(), "bmt2: {errs:?}");
            break;
        }
    }
    assert_eq!(chain.index.modified_len(), 0, "bmt2's connect flushes");
    assert_eq!(stored_votes(&chain, &hash), Some(5));
}

/// What dcrd's `ProcessBlock` at `6f6cf21b` leaves behind for battery
/// rejections whose outcome depends on the new order, with controls
/// whose outcome does not: `<name> <status> <again> <header>` on regnet
/// as shipped.
const PLAIN_STATUSES: &[&str] = &[
    "bfbbad0 5 ErrDuplicateBlock ErrKnownInvalidBlock",
    "bis1 - ErrInvalidEarlyStakeTx ErrInvalidEarlyStakeTx",
    "bf2 3 ErrDuplicateBlock ok",
    "bf8 9 ErrDuplicateBlock ErrInvalidAncestorBlock",
    "bv1 0 ErrDuplicateTxInputs ok",
    "bv5 0 ErrFreshStakeMismatch ok",
    "bsd0 0 ErrNotEnoughStake ok",
    "bsd1 0 ErrStakeBelowMinimum ok",
    "bmf2 0 ErrNoTransactions ok",
    "bmf4 - ErrTimeTooNew ErrTimeTooNew",
    "bmf5 0 ErrBadMerkleRoot ok",
    "bmf6 0 ErrBadMerkleRoot ok",
    "bmf7 0 ErrWrongBlockSize ok",
    "bmf13 5 ErrDuplicateBlock ErrKnownInvalidBlock",
    "bmf20 0 ErrExpiredTx ok",
    "bmf20b 0 ErrExpiredTx ok",
    "bcb6 0 ErrNoTxInputs ok",
    "bcb7 0 ErrNoTxOutputs ok",
    "bcb8 0 ErrBadTxOutValue ok",
    "bcb9 0 ErrBadTxOutValue ok",
    "bcb10 0 ErrBadTxOutValue ok",
    "bcb14 0 ErrDuplicateTxInputs ok",
];

/// [`PLAIN_STATUSES`] with the header commitments agenda forced to "no".
const FORCED_NO_STATUSES: &[&str] = &[
    "bfbbad0 5 ErrDuplicateBlock ErrKnownInvalidBlock",
    "bis1 - ErrInvalidEarlyStakeTx ErrInvalidEarlyStakeTx",
    "bf2 3 ErrDuplicateBlock ok",
    "bf8 9 ErrDuplicateBlock ErrInvalidAncestorBlock",
    "bv1 4 ErrKnownInvalidBlock ErrKnownInvalidBlock",
    "bv5 4 ErrKnownInvalidBlock ErrKnownInvalidBlock",
    "bsd0 4 ErrKnownInvalidBlock ErrKnownInvalidBlock",
    "bsd1 4 ErrKnownInvalidBlock ErrKnownInvalidBlock",
    "bmf2 4 ErrKnownInvalidBlock ErrKnownInvalidBlock",
    "bmf4 - ErrTimeTooNew ErrTimeTooNew",
    "bmf5 0 ErrBadMerkleRoot ok",
    "bmf6 0 ErrBadMerkleRoot ok",
    "bmf7 4 ErrKnownInvalidBlock ErrKnownInvalidBlock",
    "bmf13 5 ErrDuplicateBlock ErrKnownInvalidBlock",
    "bmf20 4 ErrKnownInvalidBlock ErrKnownInvalidBlock",
    "bmf20b 4 ErrKnownInvalidBlock ErrKnownInvalidBlock",
    "bcb6 4 ErrKnownInvalidBlock ErrKnownInvalidBlock",
    "bcb7 4 ErrKnownInvalidBlock ErrKnownInvalidBlock",
    "bcb8 4 ErrKnownInvalidBlock ErrKnownInvalidBlock",
    "bcb9 4 ErrKnownInvalidBlock ErrKnownInvalidBlock",
    "bcb10 4 ErrKnownInvalidBlock ErrKnownInvalidBlock",
    "bcb14 4 ErrKnownInvalidBlock ErrKnownInvalidBlock",
];

/// Every battery block is processed as dcrd's status replay processed
/// it -- each rejection followed by the block again and then its header
/// -- and the listed rejections must leave dcrd's outcome.
#[test]
fn battery_rejections_leave_dcrds_statuses() {
    let rows = battery();
    for (force_no, table) in [(false, PLAIN_STATUSES), (true, FORCED_NO_STATUSES)] {
        let params = regnet(force_no);
        let mut chain = Chain::new(&params, Hash::ZERO, false);
        let mut checked = 0;
        for row in &rows {
            let block = row.block.as_ref().expect("block");
            let (_, errs) = chain.process_block(block, row.now, &params);
            match row.tag.as_str() {
                "accept" => assert!(
                    errs.is_empty() || errs[0].kind == RuleErrorKind::MissingParent,
                    "force_no {force_no}: {}: {errs:?}",
                    row.name
                ),
                "reject" => {
                    assert_eq!(first_kind(&errs), row.kind, "{}", row.name);
                    let status = status_of(&chain, &block.header.block_hash());
                    let (_, again) = chain.process_block(block, row.now, &params);
                    let header = header_kind(&mut chain, &block.header, row.now, &params);
                    let got = format!("{} {status} {} {header}", row.name, first_kind(&again));
                    if let Some(want) = table
                        .iter()
                        .find(|w| w.split(' ').next() == Some(row.name.as_str()))
                    {
                        assert_eq!(&got, want, "force_no {force_no}");
                        checked += 1;
                    }
                }
                _ => assert!(!errs.is_empty(), "{}", row.name),
            }
        }
        assert_eq!(checked, table.len(), "every listed row is in the battery");
    }
}

/// A block whose data fails the merkle check is reported with the text
/// of the variant checked: on regnet as shipped, where the agenda's
/// state is not determined that early, a block matching neither variant
/// returns the DCP0005 variant's error (`validate.go:2037-2048`); with
/// the agenda forced to "no" it returns the original variant's.
/// The battery's `bmf5` carries a bad merkle root and `bmf6` a bad stake
/// root.
#[test]
fn a_merkle_failure_reports_the_variant_checked() {
    let rows = battery();
    let text = |field: &str, header: Hash, want: Hash| {
        format!(
            "block {field}merkle root is invalid - block header indicates {header}, but \
             calculated value is {want}"
        )
    };
    for force_no in [false, true] {
        let params = regnet(force_no);
        let (mut chain, now) = replay_until(&rows, &params, "bmf5");
        for name in ["bmf5", "bmf6"] {
            let block = battery_block(&rows, name);
            let header = &block.header;
            let (_, errs) = chain.process_block(&block, now, &params);
            assert_eq!(first_kind(&errs), "ErrBadMerkleRoot", "{name}");
            let combined = dcroxide_standalone::calc_combined_tx_tree_merkle_root(
                &block.transactions,
                &block.stransactions,
            );
            let regular = dcroxide_standalone::calc_tx_tree_merkle_root(&block.transactions);
            let stake = dcroxide_standalone::calc_tx_tree_merkle_root(&block.stransactions);
            let want = match (force_no, name) {
                (false, _) => text("", header.merkle_root, combined),
                (true, "bmf5") => text("", header.merkle_root, regular),
                (true, _) => text("stake ", header.stake_root, stake),
            };
            assert_eq!(errs[0].description, want, "force_no {force_no} {name}");
        }
    }
}

/// An orphan is reported as one whatever its data: the header is checked
/// before the data (`process.go:479-486`).
#[test]
fn an_orphan_with_bad_data_is_reported_as_an_orphan() {
    let rows = battery();
    let params = regnet(false);
    let (mut chain, now) = replay_until(&rows, &params, "bm0");
    let mut orphan = battery_block(&rows, "bm0");
    orphan.header.prev_block = Hash([0x55; 32]);
    orphan.transactions.clear();
    grind(&mut orphan.header, &params);
    let (_, errs) = chain.process_block(&orphan, now, &params);
    assert_eq!(first_kind(&errs), "ErrMissingParent");
    assert_eq!(status_of(&chain, &orphan.header.block_hash()), "-");
}

/// A block building on a block known to be invalid is reported as such
/// whatever its data.
#[test]
fn a_child_of_an_invalid_block_with_bad_data_has_an_invalid_ancestor() {
    let rows = battery();
    let params = regnet(false);
    let (mut chain, now) = replay_until(&rows, &params, "bfbbad1");
    let bfbbad0 = battery_block(&rows, "bfbbad0");
    let parent = bfbbad0.header.block_hash();
    assert_eq!(status_of(&chain, &parent), "5", "bfbbad0 failed validation");

    let mut child = battery_block(&rows, "bm0");
    child.header.prev_block = parent;
    child.transactions.clear();
    grind(&mut child.header, &params);
    let (_, errs) = chain.process_block(&child, now, &params);
    assert_eq!(first_kind(&errs), "ErrInvalidAncestorBlock");
}

/// A new header failing a positional check is reported before any fault
/// in its data: here a wrong height with no transactions.
#[test]
fn a_positional_header_fault_comes_before_a_data_fault() {
    let rows = battery();
    let params = regnet(false);
    let (mut chain, now) = replay_until(&rows, &params, "bm0");
    let mut block = battery_block(&rows, "bm0");
    block.header.height += 1;
    block.transactions.clear();
    grind(&mut block.header, &params);
    let (_, errs) = chain.process_block(&block, now, &params);
    assert_eq!(first_kind(&errs), "ErrBadBlockHeight");
    assert_eq!(status_of(&chain, &block.header.block_hash()), "-");
}

/// The wire size limit comes first among the data preconditions, before
/// the merkle check, and like it never marks the header.
#[test]
fn an_oversized_block_for_a_known_header_leaves_it_valid() {
    let rows = battery();
    let bfb = battery_block(&rows, "bfb");
    let mut oversized = bfb.clone();
    oversized.transactions.push(MsgTx {
        tx_out: vec![TxOut {
            value: 0,
            version: 0,
            pk_script: vec![0x6a; dcroxide_wire::MAX_BLOCK_PAYLOAD as usize],
        }],
        ..MsgTx::default()
    });
    let hash = bfb.header.block_hash();
    for force_no in [false, true] {
        let params = regnet(force_no);
        let now = rows[0].now;
        let mut chain = Chain::new(&params, Hash::ZERO, false);
        chain
            .process_block_header(&bfb.header, now, &params)
            .expect("bfb's header");
        let (_, errs) = chain.process_block(&oversized, now, &params);
        assert_eq!(first_kind(&errs), "ErrBlockTooBig", "force_no {force_no}");
        assert_eq!(status_of(&chain, &hash), "0");
        let (_, errs) = chain.process_block(&bfb, now, &params);
        assert!(errs.is_empty(), "force_no {force_no}: {errs:?}");
    }
}

/// A header already in the index is not sanity checked again when its
/// block arrives: only a new header is (`process.go:159-178`).  The
/// block is accepted even though the clock now puts its timestamp too
/// far in the future for a new header.
#[test]
fn a_known_header_is_not_sanity_checked_again() {
    let rows = battery();
    let bfb = battery_block(&rows, "bfb");
    let params = regnet(false);
    let now = rows[0].now;
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    chain
        .process_block_header(&bfb.header, now, &params)
        .expect("bfb's header");

    let earlier = i64::from(bfb.header.timestamp) - 3 * 60 * 60;
    let mut fresh = Chain::new(&params, Hash::ZERO, false);
    let (_, errs) = fresh.process_block(&bfb, earlier, &params);
    assert_eq!(
        first_kind(&errs),
        "ErrTimeTooNew",
        "a new header is checked"
    );

    let (_, errs) = chain.process_block(&bfb, earlier, &params);
    assert!(errs.is_empty(), "{errs:?}");
}

/// A block template's data preconditions come before its sanity checks
/// (dcrd `validate.go:4678-4688`): a template whose header no longer
/// commits to its data and whose size commitment is wrong fails the
/// merkle check.
#[test]
fn a_template_commitment_is_checked_before_its_sanity() {
    let rows = battery();
    let params = regnet(false);
    let (mut chain, now) = replay_until(&rows, &params, "bm4");
    let bm4 = battery_block(&rows, "bm4");
    assert_eq!(
        chain.check_connect_block_template(&bm4, now, &params),
        Ok(())
    );

    let mut wrong_size = bm4.clone();
    wrong_size.header.size += 1;
    let err = chain
        .check_connect_block_template(&wrong_size, now, &params)
        .expect_err("wrong size");
    assert_eq!(err.kind, RuleErrorKind::WrongBlockSize);

    let mut both = wrong_size.clone();
    both.transactions[0].version += 1;
    let err = chain
        .check_connect_block_template(&both, now, &params)
        .expect_err("stale commitment");
    assert_eq!(err.kind, RuleErrorKind::BadMerkleRoot);
}
