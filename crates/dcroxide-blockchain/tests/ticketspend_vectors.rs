// SPDX-License-Identifier: ISC
//! Replay of three upstream unit tests from dcrd's
//! `internal/blockchain/validate_test.go` at `6f6cf21b`
//! (`data/ticketspend_vectors.txt`).  Each one checks the inputs of a
//! vote or a revocation, the transactions that spend a ticket:
//!
//! - `TestImmatureTicketSpend` (`validate_test.go:1741`, `1995f4fc`):
//!   `CheckTransactionInputs` on a vote and a revocation for a ticket
//!   bought in the tip block, at heights on both sides of the ticket
//!   maturity, with automatic revocations off and on.
//! - `TestInvalidTicketInput` (`validate_test.go:1854`, `b6c67575`): a
//!   vote and a revocation for real tickets, and copies whose ticket
//!   input points at the tip block's revocation output instead.  These
//!   run at the tip height plus one, the height the mempool uses for
//!   the next block.
//! - `TestAutoRevocations` through `b5` (`validate_test.go:1946`, with
//!   `855dc8be`'s new `b4`): blocks under `quickVoteActivationParams`
//!   (`validate_test.go:239`) with the automatic revocations deployment
//!   always open for voting.  `b4` carries a version 2 revocation whose
//!   ticket input references output 2, and `ProcessBlock` rejects it
//!   with `ErrInvalidRevokeInput`.  The valid block is now `b5`.
//!   Upstream checks only the block.  The exporter also ran the `b4`
//!   revocation through `CheckTransactionInputs` against the tip's view,
//!   the path the mempool takes, and recorded the same kind.
//!
//! Upstream builds these with its `chaingen` harness.  The port has no
//! such harness, so a scratch exporter in dcrd's `internal/blockchain`
//! package at `6f6cf21b` repeated each test's setup call for call and
//! dumped what it saw.  For `TestAutoRevocations` it stops after `b5`,
//! and it calls `ProcessBlock` itself where upstream calls
//! `RejectTipBlock`, so that it can record the error text along with
//! the kind.  The exporter is not committed; regenerating means writing
//! it again.  Every block hash changes on regeneration, because
//! `chaingen` stamps block 1 with the wall clock.  The exporter dumped:
//!
//! - the harness main chain at the point each test runs its checks;
//! - the utxo entries dcrd's `FetchUtxoView` returned for each checked
//!   transaction's inputs;
//! - the tip header handed to `CheckTransactionInputs`;
//! - dcrd's verdict, fee and error text for every check, and for
//!   `TestAutoRevocations` the `ProcessBlock` verdict and text of every
//!   block it rejects.
//!
//! The replay rebuilds each chain through `Chain::process_block`.  For
//! each check it fetches every input from the port's own utxo set, where
//! upstream calls `FetchUtxoView`, and asserts that each entry equals
//! dcrd's field for field and that the tip header is dcrd's.  Then it
//! runs `check_transaction_inputs`, the function the mempool calls, and
//! compares the kind, the fee and the text.
//!
//! Rows:
//!
//! - `test <name>` starts a section: one upstream test, on a fresh
//!   chain.
//! - `params regnet|quickautorev`.
//! - `now <unix>`: the adjusted time `process_block` is given.
//! - `block <height> <hex>`: a block the chain accepts as its new tip.
//! - `active <vote id> <bool>`: whether the agenda is active for the
//!   block after the tip.
//! - `utxo <hash> <index> <tree> <amount> <script version> <height>
//!   <block index> <coinbase> <expiry> <tx type> <spent> <pk script>
//!   <minimal outputs>`: dcrd's view entry for the next case's next
//!   input, in input order and skipping a vote's stakebase input.
//! - `case <name> <height> <treasury> <autorev> <prev header> <tx>
//!   <kind|ok> <fee|-> <text|->`: one `CheckTransactionInputs` call.
//! - `reject <name> <kind> <hex> <text>`: a block `ProcessBlock`
//!   rejects.
//! - `accept <name> <hex>`: a block accepted as the new tip.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::RuleError;
use dcroxide_blockchain::agendas::VOTE_ID_AUTO_REVOCATIONS;
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_blockchain::validate::check_transaction_inputs;
use dcroxide_chaincfg::{Params, regnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_standalone::{SubsidyCache, SubsidySplitVariant};
use dcroxide_testutil::{hex, unhex};
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx};

/// The rows of one `test` section of the vector file.
fn section(name: &str) -> Vec<&'static str> {
    let data = include_str!("data/ticketspend_vectors.txt");
    let mut rows = Vec::new();
    let mut inside = false;
    for line in data.lines() {
        if let Some(test) = line.strip_prefix("test ") {
            inside = test == name;
            continue;
        }
        if inside {
            rows.push(line);
        }
    }
    assert!(!rows.is_empty(), "no {name} section in the vector file");
    rows
}

/// dcrd's `quickVoteActivationParams` (`validate_test.go:239-263`) with
/// `removeDeploymentTimeConstraints` (`common_test.go:555-558`) applied
/// to the automatic revocations deployment, as `TestAutoRevocations`
/// sets them up.
fn quick_auto_revocations_params() -> Params {
    let mut p = regnet_params();
    p.work_diff_window_size = 200_000;
    p.work_diff_windows = 1;
    p.target_timespan_secs = p.target_time_per_block_secs * p.work_diff_window_size;
    p.coinbase_maturity = 2;
    p.block_enforce_num_required = 5;
    p.block_reject_num_required = 7;
    p.block_upgrade_num_to_check = 10;
    p.ticket_maturity = 2;
    p.ticket_pool_size = 4;
    p.ticket_expiry = 6 * u32::from(p.ticket_pool_size);
    p.stake_enabled_height = i64::from(p.coinbase_maturity) + i64::from(p.ticket_maturity);
    p.stake_validation_height = i64::from(p.coinbase_maturity) + i64::from(p.ticket_pool_size) * 2;
    p.stake_version_interval = 10;
    p.rule_change_activation_interval =
        u32::from(p.ticket_pool_size) * u32::from(p.tickets_per_block);
    p.rule_change_activation_quorum =
        p.rule_change_activation_interval * u32::from(p.tickets_per_block * 100) / 1000;
    let deployment = p
        .deployments
        .iter_mut()
        .flat_map(|(_, deployments)| deployments.iter_mut())
        .find(|d| d.vote.id == VOTE_ID_AUTO_REVOCATIONS)
        .expect("automatic revocations deployment");
    deployment.start_time = 0;
    deployment.expire_time = u64::MAX;
    p
}

fn params_for(name: &str) -> Params {
    match name {
        "regnet" => regnet_params(),
        "quickautorev" => quick_auto_revocations_params(),
        other => panic!("unknown params {other}"),
    }
}

/// What a section replay checked.
#[derive(Debug, Default, PartialEq, Eq)]
struct Tally {
    blocks: usize,
    active: usize,
    cases: usize,
    rejects: usize,
    accepts: usize,
}

/// The kind name of a check's result, `ok` for success.
fn kind_of(result: &Result<i64, RuleError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(e) => e.kind.kind_name(),
    }
}

/// Replays one section.  With `treasury_from_chain`, each case's
/// treasury flag must also be the port's own answer for the tip: there
/// upstream asks its chain rather than passing a constant.
fn replay(name: &str, treasury_from_chain: bool) -> Tally {
    let rows = section(name);
    let params_row = rows
        .iter()
        .find_map(|r| r.strip_prefix("params "))
        .expect("params row");
    let params = params_for(params_row);
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    let mut subsidy_cache = SubsidyCache::new(&params);
    let mut now: Option<i64> = None;
    let mut dcrd_entries: Vec<Vec<&str>> = Vec::new();
    let mut tally = Tally::default();

    for line in rows {
        let tag = line.split(' ').next().expect("row tag");
        match tag {
            "params" => {}
            "now" => now = Some(line["now ".len()..].parse().expect("now")),
            "block" | "accept" => {
                let f: Vec<&str> = line.split(' ').collect();
                let (block, _) = MsgBlock::from_bytes(&unhex(f[2])).expect("block");
                let (_, errs) = chain.process_block(&block, now.expect("now row"), &params);
                assert!(errs.is_empty(), "{name} {tag} {}: {errs:?}", f[1]);
                let best = chain.best_snapshot();
                assert_eq!(best.hash, block.header.block_hash(), "{name} {}: tip", f[1]);
                if tag == "block" {
                    assert_eq!(best.height.to_string(), f[1], "{name}: tip height");
                    tally.blocks += 1;
                } else {
                    tally.accepts += 1;
                }
            }
            "active" => {
                let f: Vec<&str> = line.split(' ').collect();
                assert_eq!(f[1], VOTE_ID_AUTO_REVOCATIONS, "{name}: agenda");
                let tip = chain.best_snapshot().hash;
                let active = chain
                    .is_auto_revocations_agenda_active(&tip, &params)
                    .expect("agenda state");
                assert_eq!(active.to_string(), f[2], "{name}: {} active", f[1]);
                tally.active += 1;
            }
            "reject" => {
                let f: Vec<&str> = line.splitn(5, ' ').collect();
                let (block, _) = MsgBlock::from_bytes(&unhex(f[3])).expect("block");
                let tip = chain.best_snapshot().hash;
                let (_, errs) = chain.process_block(&block, now.expect("now row"), &params);
                let err = errs
                    .first()
                    .unwrap_or_else(|| panic!("{name} {} should be rejected", f[1]));
                assert_eq!(err.kind.kind_name(), f[2], "{name} {}: kind", f[1]);
                assert_eq!(err.description, f[4], "{name} {}: text", f[1]);
                assert_eq!(chain.best_snapshot().hash, tip, "{name} {}: tip", f[1]);
                tally.rejects += 1;
            }
            "utxo" => dcrd_entries.push(line.split(' ').collect()),
            "case" => {
                let f: Vec<&str> = line.splitn(10, ' ').collect();
                let case = f[1];
                let tx_height: i64 = f[2].parse().expect("height");
                let treasury: bool = f[3].parse().expect("treasury");
                let auto_revocations: bool = f[4].parse().expect("autorev");
                let (tx, _) = MsgTx::from_bytes(&unhex(f[6])).expect("tx");

                // dcrd's FetchUtxoView(tx, true) from the port's own utxo
                // set: one entry per input but a vote's stakebase.
                let mut view = UtxoView::new();
                let inputs: Vec<_> = tx
                    .tx_in
                    .iter()
                    .map(|tx_in| &tx_in.previous_out_point)
                    .filter(|op| op.index != u32::MAX)
                    .collect();
                assert_eq!(inputs.len(), dcrd_entries.len(), "{name} {case}: inputs");
                for (op, want) in inputs.into_iter().zip(&dcrd_entries) {
                    let at = [hex(&op.hash.0), op.index.to_string(), op.tree.to_string()];
                    assert_eq!(&at[..], &want[1..4], "{name} {case}: outpoint");
                    let e = chain
                        .fetch_utxo_entry(op)
                        .unwrap_or_else(|| panic!("{name} {case}: no entry for {at:?}"));
                    let got = [
                        e.amount().to_string(),
                        e.script_version().to_string(),
                        e.block_height().to_string(),
                        e.block_index().to_string(),
                        u8::from(e.is_coin_base()).to_string(),
                        u8::from(e.has_expiry()).to_string(),
                        e.transaction_type().to_string(),
                        u8::from(e.is_spent()).to_string(),
                        hex(e.pk_script()),
                        e.ticket_minimal_outputs_data().map_or("-".to_string(), hex),
                    ];
                    assert_eq!(&got[..], &want[4..14], "{name} {case}: entry {at:?}");
                    view.insert_entry(op, e);
                }
                dcrd_entries.clear();

                let tip = chain.best_snapshot().hash;
                let prev_header = chain.header_by_hash(&tip).expect("tip header");
                let (dcrd_prev, _) = BlockHeader::from_bytes(&unhex(f[5])).expect("header");
                assert_eq!(prev_header, dcrd_prev, "{name} {case}: prev header");
                if treasury_from_chain {
                    let active = chain
                        .is_treasury_agenda_active(&tip, &params)
                        .expect("treasury agenda state");
                    assert_eq!(active, treasury, "{name} {case}: treasury agenda");
                }

                let result = check_transaction_inputs(
                    &mut subsidy_cache,
                    &tx,
                    tx_height,
                    |op| view.lookup_entry(op),
                    true,
                    &params,
                    &prev_header,
                    treasury,
                    auto_revocations,
                    SubsidySplitVariant::Original,
                );
                assert_eq!(kind_of(&result), f[7], "{name} {case}: kind {result:?}");
                match &result {
                    Ok(fee) => assert_eq!(fee.to_string(), f[8], "{name} {case}: fee"),
                    Err(e) => {
                        assert_eq!(f[8], "-", "{name} {case}: fee");
                        assert_eq!(e.description, f[9], "{name} {case}: text");
                    }
                }
                tally.cases += 1;
            }
            other => panic!("unknown row tag {other}"),
        }
    }
    assert!(dcrd_entries.is_empty(), "{name}: utxo rows without a case");
    tally
}

/// `TestImmatureTicketSpend`: a vote may spend its ticket one block
/// after the ticket maturity, a revocation one block later still, and
/// with automatic revocations at the same height as a vote
/// (dcrd `validate.go:3144-3157`, `:3248-3271`; port `validate.rs`
/// `check_vote_inputs` and `check_revocation_inputs`).
#[test]
fn immature_ticket_spend() {
    let tally = replay("TestImmatureTicketSpend", false);
    assert_eq!(
        tally,
        Tally {
            blocks: 145,
            cases: 6,
            ..Tally::default()
        }
    );
}

/// `TestInvalidTicketInput`: a vote or revocation whose ticket input
/// references an unspent stake output that no ticket created fails the
/// submission script check (`checkTicketSubmissionInput`, dcrd
/// `validate.go:2879-2898`) with `ErrInvalidVoteInput` or
/// `ErrInvalidRevokeInput` (`validate.go:3137-3142`, `:3241-3246`).
#[test]
fn invalid_ticket_input() {
    let tally = replay("TestInvalidTicketInput", false);
    assert_eq!(
        tally,
        Tally {
            blocks: 146,
            cases: 4,
            ..Tally::default()
        }
    );
}

/// `TestAutoRevocations` through `b5`: blocks missing a revocation, with
/// a version 1 revocation, with a revocation paying a fee, and with a
/// revocation referencing output 2 of its ticket are rejected; the
/// valid block is accepted.  The `b4` revocation also fails
/// `CheckTransactionInputs` on its own, at the input index check
/// (dcrd `validate.go:3215-3224`).
#[test]
fn auto_revocations() {
    let tally = replay("TestAutoRevocations", true);
    assert_eq!(
        tally,
        Tally {
            blocks: 71,
            active: 1,
            cases: 1,
            rejects: 4,
            accepts: 1,
        }
    );
}
