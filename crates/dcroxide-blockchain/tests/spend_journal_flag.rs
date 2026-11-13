// SPDX-License-Identifier: ISC
//! Regression coverage for the treasury-agenda flag used to decode a
//! *parent* block's spend journal.
//!
//! A block's spend journal is serialized under that block's own
//! treasury flag (treasury active as-of the block).  At the DCP0006
//! treasury activation boundary the child that activates the agenda
//! sees `is_treasury_enabled == true`, but its parent was connected
//! while the agenda was still inactive, so the parent journal was
//! written with `is_treasury_enabled == false`.  Decoding the parent
//! journal with the child's flag drops the parent's first stake
//! transaction (treated as the treasurybase slot) and misaligns — or
//! overruns — the stxo stream.  The parent journal is decoded only on
//! the *disapprove* path inside `connectBlock`, and there dcrd decoded
//! it with the child's flag too until `37fd3a3e`, which hands the
//! disapproved parent its own; the mainnet activation block approved
//! its parent.  These tests pin down (a) the decode mismatch itself,
//! (b) that `UtxoView::connect_block` fetches the parent journal
//! lazily, only when the block disapproves its parent, matching dcrd,
//! and (c) that an activation block disapproving its parent undoes and
//! redoes the parent with the parent's flag.

// Test-harness arithmetic over small fixed lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::cell::Cell;

use dcroxide_blockchain::UtxoEntry;
use dcroxide_blockchain::chainio::{SpentTxOut, serialize_spend_journal_entry};
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::utxoview::{UtxoView, count_spent_outputs};
use dcroxide_chaincfg::simnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint, TX_TREE_REGULAR, TxIn, TxOut};

/// A zeroed 180-byte header to fill in field by field.
fn zero_header() -> BlockHeader {
    BlockHeader::from_bytes(&[0u8; 180]).expect("zero header").0
}

/// A version-1 coinbase: a single null input and a single output, so
/// it is recognized by `is_coin_base_tx` and never looks like a
/// treasury spend.  `tag` distinguishes otherwise-identical coinbases
/// so parent and child hash differently.
fn coinbase(tag: u8) -> MsgTx {
    MsgTx {
        tx_in: vec![TxIn {
            previous_out_point: OutPoint {
                hash: Hash::ZERO,
                index: u32::MAX,
                tree: 0,
            },
            sequence: u32::MAX,
            ..Default::default()
        }],
        tx_out: vec![TxOut {
            value: 1,
            version: 0,
            pk_script: vec![0x51, tag],
        }],
        ..Default::default()
    }
}

/// A plain single-input transaction spending the given prior output.
/// The witness fraud-proof fields carry the amount/height/index that
/// the journal decode reconstructs the stxo from, so they must equal
/// the matching [`SpentTxOut`] fields.
fn spend_tx(prev_index: u32, value_in: i64, block_height: u32, block_index: u32) -> MsgTx {
    MsgTx {
        tx_in: vec![TxIn {
            previous_out_point: OutPoint {
                hash: Hash([7u8; 32]),
                index: prev_index,
                tree: 0,
            },
            sequence: u32::MAX,
            value_in,
            block_height,
            block_index,
            signature_script: Vec::new(),
        }],
        tx_out: vec![TxOut {
            value: value_in - 1,
            version: 0,
            pk_script: vec![0x52],
        }],
        ..Default::default()
    }
}

/// The stxo a [`spend_tx`] input restores, in the journal's serialized
/// form (a plain, non-ticket, non-coinbase regular output).
fn stxo(pk_script: Vec<u8>, value_in: i64, block_height: u32, block_index: u32) -> SpentTxOut {
    SpentTxOut {
        amount: value_in,
        pk_script: pk_script.into(),
        ticket_min_outs: None,
        block_height,
        block_index,
        script_version: 0,
        packed_flags: 0,
    }
}

fn block(height: u32, transactions: Vec<MsgTx>, stransactions: Vec<MsgTx>) -> MsgBlock {
    let mut header = zero_header();
    header.height = height;
    header.vote_bits = 0x0001; // approves parent
    header.nonce = height;
    MsgBlock {
        header,
        transactions,
        stransactions,
    }
}

/// The parent journal is decoded correctly only with the parent's own
/// (pre-activation) treasury flag; the child's post-activation flag
/// drops the parent's first stake transaction and returns a shorter,
/// shifted stxo list — exactly the misalignment the connect path would
/// have fed into `disconnect_disapproved_block`.
#[test]
fn parent_journal_decode_depends_on_the_treasury_flag() {
    let params = simnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);

    // A pre-activation parent (height 552447, just below where DCP0006
    // activated on mainnet): a coinbase plus one regular spend, and a
    // stake transaction occupying the slot a vote would — the slot the
    // treasury-active decode wrongly skips as the treasurybase.
    let stake_stxo = stxo(vec![0x76, 0xa9, 0x14], 1_000, 500_000, 3);
    let reg_stxo = stxo(vec![0x51], 2_000, 499_999, 1);
    let parent = block(
        552_447,
        vec![
            coinbase(0),
            spend_tx(
                2,
                reg_stxo.amount,
                reg_stxo.block_height,
                reg_stxo.block_index,
            ),
        ],
        vec![spend_tx(
            0,
            stake_stxo.amount,
            stake_stxo.block_height,
            stake_stxo.block_index,
        )],
    );

    // The journal is serialized in the block's forward tx order:
    // [stake spend, regular spend]. This is what connecting the parent
    // wrote while the treasury agenda was still inactive.
    let serialized =
        serialize_spend_journal_entry(&[stake_stxo.clone(), reg_stxo.clone()]).expect("journal");
    chain
        .spend_journal
        .insert(parent.header.block_hash().0, serialized);

    // The count of spent outputs does not depend on the flag: two.
    assert_eq!(count_spent_outputs(&parent), 2);

    // Decoding with the parent's own (inactive) flag round-trips every
    // stxo.
    let correct = chain.fetch_spend_journal(&parent, false).expect("decodes");
    assert_eq!(correct, vec![stake_stxo.clone(), reg_stxo.clone()]);

    // Decoding with the child's (active) flag skips the parent's first
    // stake transaction as if it were the treasurybase, so the stake
    // spend is silently dropped and the list is one short — a length
    // that would trip `disconnect_disapproved_block`'s stxo-count
    // assertion on the disapprove path.
    let wrong = chain.fetch_spend_journal(&parent, true).expect("decodes");
    assert_eq!(wrong, vec![reg_stxo]);
    assert_ne!(wrong.len(), count_spent_outputs(&parent));
}

/// A chain holding one pre-activation parent block whose spend journal
/// row is present and valid: the shape the two tests below perturb.
fn journal_fixture() -> (Chain, MsgBlock, MsgBlock) {
    let params = simnet_params();
    let mut chain = Chain::new(&params, Hash::ZERO, false);
    let stake_stxo = stxo(vec![0x76, 0xa9, 0x14], 1_000, 500_000, 3);
    let reg_stxo = stxo(vec![0x51], 2_000, 499_999, 1);
    let parent = block(
        552_447,
        vec![
            coinbase(0),
            spend_tx(
                2,
                reg_stxo.amount,
                reg_stxo.block_height,
                reg_stxo.block_index,
            ),
        ],
        vec![spend_tx(
            0,
            stake_stxo.amount,
            stake_stxo.block_height,
            stake_stxo.block_index,
        )],
    );
    let child = block(552_448, vec![coinbase(1)], Vec::new());
    let serialized = serialize_spend_journal_entry(&[stake_stxo, reg_stxo]).expect("journal");
    chain
        .spend_journal
        .insert(parent.header.block_hash().0, serialized);
    (chain, parent, child)
}

/// Bytes that are present and non-empty but are not a journal row: a
/// compact-size length that runs off the end of the buffer.
fn alloc_bad_row() -> Vec<u8> {
    vec![0xff, 0xff, 0xff, 0xff]
}

/// A journal row that is present but does not decode is corruption,
/// not an invariant break: it comes back as an error and the caller
/// fails the reorg with the node still running.
///
/// dcrd draws the same line.  `dbFetchSpendJournalEntry` panics only
/// when the row is *missing* for a block that spends something, and
/// returns `database.ErrCorruption` when a present row fails to
/// deserialize.  The port had one `expect` covering both, so under
/// `panic = "abort"` a corrupt row killed the process the next time any
/// disconnect touched it.  Reported as RVW-020 by an external review of
/// `382864f5`.
#[test]
fn a_corrupt_spend_journal_row_is_an_error_not_a_panic() {
    let (mut chain, parent, _child) = journal_fixture();

    // A row that is present, non-empty, and not a valid journal.
    chain
        .spend_journal
        .insert(parent.header.block_hash().0, alloc_bad_row());

    let err = chain
        .fetch_spend_journal(&parent, false)
        .expect_err("a corrupt row must not decode");
    assert_eq!(
        err.kind.kind_name(),
        "ErrUtxoBackendCorruption",
        "corruption must not be classified as a rule violation the peer is blamed for: {err:?}"
    );
    assert!(
        err.description.contains("corrupt spend information"),
        "the message names the failure: {}",
        err.description
    );
}

/// A row missing entirely for a block that spends something is the
/// invariant break dcrd panics on (`panicf("missing spend journal data
/// for %s")`), and the port keeps panicking there rather than turning
/// it into a recoverable error.
#[test]
#[should_panic(expected = "missing spend journal data")]
fn a_missing_spend_journal_row_still_panics() {
    let (mut chain, parent, _child) = journal_fixture();
    chain.spend_journal.remove(&parent.header.block_hash().0);
    let _ = chain.fetch_spend_journal(&parent, false);
}

/// `connect_block` must not touch the parent spend journal on the
/// approve path (the common case, and the one an IBD crosses at the
/// activation boundary); it decodes it only when the block disapproves
/// its parent, exactly like dcrd.
#[test]
fn connect_block_fetches_parent_journal_only_on_disapprove() {
    let params = simnet_params();
    let none_resolver = |_: &OutPoint| -> Option<UtxoEntry> { None };

    // A coinbase-only parent: nothing to disconnect, so the lazily
    // fetched journal is legitimately empty on the disapprove path.
    // The treasury flag is irrelevant here — the disapprove branch
    // keys off the header's approve-parent vote bit — so keep it
    // inactive and use plain version-1 coinbases.
    let parent = block(552_447, vec![coinbase(0)], Vec::new());
    let parent_hash = parent.header.block_hash();

    // Approving child: the provider must never run.
    {
        let child = block(552_448, vec![coinbase(1)], Vec::new());
        let calls = Cell::new(0usize);
        let mut view = UtxoView::new();
        view.set_best_hash(parent_hash);
        view.connect_block(
            &params,
            &child,
            &parent,
            |_| {
                calls.set(calls.get() + 1);
                Ok(Vec::new())
            },
            &none_resolver,
            None,
            false,
            false,
        )
        .expect("connect approving child");
        assert_eq!(
            calls.get(),
            0,
            "approve path must not decode the parent journal"
        );
    }

    // Disapproving child: the provider runs exactly once.
    {
        let mut child = block(552_448, vec![coinbase(2)], Vec::new());
        child.header.vote_bits = 0x0000; // disapproves parent
        let calls = Cell::new(0usize);
        let mut view = UtxoView::new();
        view.set_best_hash(parent_hash);
        view.connect_block(
            &params,
            &child,
            &parent,
            |_| {
                calls.set(calls.get() + 1);
                Ok(Vec::new())
            },
            &none_resolver,
            None,
            false,
            false,
        )
        .expect("connect disapproving child");
        assert_eq!(
            calls.get(),
            1,
            "disapprove path must decode the parent journal once"
        );
    }
}

/// A child of [`journal_fixture`]'s parent, the first block under the
/// treasury agenda, with a version 3 coinbase, that disapproves the
/// parent.
fn disapproving_activation_child() -> MsgBlock {
    let mut coinbase = coinbase(3);
    coinbase.version = 3;
    let mut child = block(552_448, vec![coinbase], Vec::new());
    child.header.vote_bits = 0x0000; // disapproves parent
    child
}

/// Output `index` of the parent's regular transaction `tx`.
fn regular_out(parent: &MsgBlock, tx: usize, index: u32) -> OutPoint {
    OutPoint {
        hash: parent.transactions[tx].tx_hash(),
        index,
        tree: TX_TREE_REGULAR,
    }
}

/// An activation block that disapproves its parent undoes the parent
/// with the parent's own flag, inactive, though its own is active: the
/// journal provider is handed that flag and both stxos come back.
/// Detaching the block redoes the parent with the same flag, so its
/// version 1 coinbase is judged a coinbase again (dcrd `37fd3a3e`).
/// Before that change the port handed the parent the block's flag at
/// both steps.  The undo then reads the journal short, as
/// [`parent_journal_decode_depends_on_the_treasury_flag`] shows, and the
/// test after this one shows the redo failing.
#[test]
fn an_activation_block_undoes_and_redoes_its_parent_with_the_parents_flag() {
    let params = simnet_params();
    let (chain, parent, _) = journal_fixture();
    let child = disapproving_activation_child();
    let none_resolver = |_: &OutPoint| -> Option<UtxoEntry> { None };
    let coinbase_out = regular_out(&parent, 0, 0);
    let spend_out = regular_out(&parent, 1, 0);
    let spend_input = parent.transactions[1].tx_in[0].previous_out_point;

    let flags = Cell::new(Vec::new());
    let mut view = UtxoView::new();
    view.set_best_hash(parent.header.block_hash());
    let mut child_stxos = Vec::new();
    view.connect_block(
        &params,
        &child,
        &parent,
        |is_parent_treasury_enabled| {
            let mut seen = flags.take();
            seen.push(is_parent_treasury_enabled);
            flags.set(seen);
            let stxos = chain.fetch_spend_journal(&parent, is_parent_treasury_enabled)?;
            assert_eq!(stxos.len(), count_spent_outputs(&parent));
            Ok(stxos)
        },
        &none_resolver,
        Some(&mut child_stxos),
        true,
        false,
    )
    .expect("connect the activation block");
    assert_eq!(flags.take(), vec![false], "the parent's flag, once");
    for out in [&coinbase_out, &spend_out] {
        assert!(
            view.lookup_entry(out).is_none_or(UtxoEntry::is_spent),
            "{out}: the parent's regular outputs are undone"
        );
    }
    let restored = view.lookup_entry(&spend_input).expect("restored input");
    assert!(!restored.is_spent());
    assert_eq!(restored.amount(), 2_000);
    assert_eq!(child_stxos.len(), count_spent_outputs(&child));

    // The detach redoes the parent's regular tree under its own flag.
    view.disconnect_block(
        &params,
        &child,
        &parent,
        &child_stxos,
        &none_resolver,
        true,
        false,
    )
    .expect("detach the activation block");
    let coinbase_entry = view.lookup_entry(&coinbase_out).expect("redone coinbase");
    assert!(!coinbase_entry.is_spent());
    assert!(
        coinbase_entry.is_coin_base(),
        "a version 1 coinbase before the agenda"
    );
    assert!(view.lookup_entry(&spend_out).is_some_and(|e| !e.is_spent()));
    assert!(
        view.lookup_entry(&spend_input)
            .is_some_and(UtxoEntry::is_spent)
    );
}

/// Redone under the activation block's own flag, as the port did before
/// `37fd3a3e`, the parent's version 1 coinbase is not a coinbase under
/// the treasury rules, so the redo tries to spend its null input.  The
/// expected text is the view's current assertion, which this pins.
#[test]
#[should_panic(
    expected = "view missing input 0000000000000000000000000000000000000000000000000000000000000000:4294967295"
)]
fn an_activation_block_redoing_its_parent_with_its_own_flag_spends_the_coinbase_input() {
    let params = simnet_params();
    let (chain, parent, _) = journal_fixture();
    let child = disapproving_activation_child();
    let none_resolver = |_: &OutPoint| -> Option<UtxoEntry> { None };
    let mut view = UtxoView::new();
    view.set_best_hash(parent.header.block_hash());
    let mut child_stxos = Vec::new();
    view.connect_block(
        &params,
        &child,
        &parent,
        |is_parent_treasury_enabled| chain.fetch_spend_journal(&parent, is_parent_treasury_enabled),
        &none_resolver,
        Some(&mut child_stxos),
        true,
        false,
    )
    .expect("connect the activation block");
    let _ = view.disconnect_block(
        &params,
        &child,
        &parent,
        &child_stxos,
        &none_resolver,
        true,
        true,
    );
}
