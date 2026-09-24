// SPDX-License-Identifier: ISC
//! Background template regeneration details dcrd's goroutine and timer
//! machinery gets for free and a synchronous port has to model:
//!
//! - the notified-parents LRU refreshes a hit's recency, as dcrd's
//!   `lru.Set.Contains` does, so eviction and the `newvotes`/`newparent`
//!   reason of later work notifications follow dcrd;
//! - every timer arm is a fresh countdown (a new `time.After`, or
//!   `resetRegenTimer`), which the state machine exposes as an arm
//!   generation the daemon keys its deadlines on;
//! - a failed tip lookup when a reorg finishes arms the one-second
//!   failed-generation retry, through the template-update event dcrd's
//!   `setCurrentTemplate` queues.

// Test-harness arithmetic over small counters.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::UtxoEntry;
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_chainhash::Hash;
use dcroxide_mining::bg_generator::{
    BgGenerator, BgRegenEvent, BgTemplateState, BgTemplateUpdateReason, handle_regen_event,
    handle_template_update,
};
use dcroxide_mining::{
    BlockTemplate, TemplateBest, TemplateChain, TemplateTxSource, TxMiningView, VoteDesc,
};
use dcroxide_standalone::SubsidySplitVariant;
use dcroxide_txscript::ScriptFlags;
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint, TxOut};

/// Five votes per block: three are the minimum to build on a tip.
const TICKETS_PER_BLOCK: u16 = 5;

fn block(height: u32, prev: Hash, nonce: u32) -> MsgBlock {
    let (mut header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("header");
    header.height = height;
    header.prev_block = prev;
    header.nonce = nonce;
    MsgBlock {
        header,
        transactions: Vec::new(),
        stransactions: Vec::new(),
    }
}

fn template(prev: Hash) -> BlockTemplate {
    BlockTemplate {
        block: block(1, prev, 0),
        fees: Vec::new(),
        sig_op_counts: Vec::new(),
        height: 1,
        valid_pay_address: true,
    }
}

/// A vote-shaped transaction whose first output carries the OP_RETURN
/// reference to the block it votes on.
fn vote(voted_on: &Hash, height: u32) -> MsgTx {
    let mut script = vec![0u8; 38];
    script[0] = 0x6a;
    script[1] = 36;
    script[2..34].copy_from_slice(&voted_on.0);
    script[34..38].copy_from_slice(&height.to_le_bytes());
    MsgTx {
        tx_out: vec![TxOut {
            pk_script: script,
            ..TxOut::default()
        }],
        ..MsgTx::default()
    }
}

/// A chain that answers the tip facts, and the tip block unless told
/// to fail the lookup.
struct Chain {
    tip: TemplateBest,
    tip_block: Option<MsgBlock>,
}

impl Chain {
    fn set_tip(&mut self, block: &MsgBlock) {
        self.tip = TemplateBest {
            hash: block.header.block_hash(),
            prev_hash: block.header.prev_block,
            height: i64::from(block.header.height),
            ..TemplateBest::default()
        };
        self.tip_block = Some(block.clone());
    }
}

impl TemplateChain for Chain {
    fn best_snapshot(&self) -> TemplateBest {
        self.tip.clone()
    }
    fn block_by_hash(&self, hash: &Hash) -> Result<MsgBlock, String> {
        self.tip_block
            .clone()
            .ok_or_else(|| format!("block {hash} is not known"))
    }
    fn calc_next_required_difficulty(&self, _h: &Hash, _ts: i64) -> Result<u32, String> {
        unreachable!("unused by the regen state machine")
    }
    fn calc_stake_version_by_hash(&self, _h: &Hash) -> Result<u32, String> {
        unreachable!("unused by the regen state machine")
    }
    fn check_connect_block_template(&mut self, _b: &MsgBlock) -> Result<(), String> {
        unreachable!("unused by the regen state machine")
    }
    fn check_ticket_exhaustion(&self, _h: &Hash, _p: u8) -> Result<(), String> {
        unreachable!("unused by the regen state machine")
    }
    #[allow(clippy::too_many_arguments)]
    fn check_transaction_inputs(
        &mut self,
        _tx: &MsgTx,
        _tx_height: i64,
        _view: &UtxoView,
        _check_fraud_proof: bool,
        _prev_header: &BlockHeader,
        _is_treasury_enabled: bool,
        _is_auto_revocations_enabled: bool,
        _subsidy_split_variant: SubsidySplitVariant,
    ) -> Result<i64, String> {
        unreachable!("unused by the regen state machine")
    }
    fn check_tspend_has_votes(&self, _h: &Hash, _tx: &MsgTx) -> Result<(), String> {
        unreachable!("unused by the regen state machine")
    }
    fn count_total_sig_ops(
        &self,
        _tx: &MsgTx,
        _cb: bool,
        _vote: bool,
        _view: &UtxoView,
        _treasury: bool,
    ) -> Result<u32, String> {
        unreachable!("unused by the regen state machine")
    }
    fn fetch_utxo_entry(&self, _op: &OutPoint) -> Result<Option<UtxoEntry>, String> {
        unreachable!("unused by the regen state machine")
    }
    fn fetch_utxo_view(
        &self,
        _tx: &MsgTx,
        _tx_hash: &Hash,
        _tree: i8,
        _include_regular: bool,
    ) -> Result<UtxoView, String> {
        unreachable!("unused by the regen state machine")
    }
    fn fetch_utxo_view_parent_template(&self, _b: &MsgBlock) -> Result<UtxoView, String> {
        unreachable!("unused by the regen state machine")
    }
    fn force_head_reorganization(&mut self, _former: Hash, _new_best: Hash) -> Result<(), String> {
        unreachable!("no side chain reorganizes here")
    }
    fn header_by_hash(&self, _h: &Hash) -> Result<BlockHeader, String> {
        unreachable!("unused by the regen state machine")
    }
    fn is_finalized_transaction(&self, _tx: &MsgTx, _height: i64, _time: i64) -> bool {
        unreachable!("unused by the regen state machine")
    }
    fn is_header_commitments_agenda_active(&self, _h: &Hash) -> Result<bool, String> {
        unreachable!("unused by the regen state machine")
    }
    fn is_treasury_agenda_active(&self, _h: &Hash) -> Result<bool, String> {
        unreachable!("unused by the regen state machine")
    }
    fn is_auto_revocations_agenda_active(&self, _h: &Hash) -> Result<bool, String> {
        unreachable!("unused by the regen state machine")
    }
    fn is_subsidy_split_agenda_active(&self, _h: &Hash) -> Result<bool, String> {
        unreachable!("unused by the regen state machine")
    }
    fn is_subsidy_split_r2_agenda_active(&self, _h: &Hash) -> Result<bool, String> {
        unreachable!("unused by the regen state machine")
    }
    fn max_treasury_expenditure(&self, _h: &Hash) -> Result<i64, String> {
        unreachable!("unused by the regen state machine")
    }
    fn tip_generation(&self) -> Vec<Hash> {
        unreachable!("no side chain tracking timeout fires here")
    }
    fn validate_transaction_scripts(
        &self,
        _tx: &MsgTx,
        _view: &UtxoView,
        _flags: ScriptFlags,
        _auto_rev: bool,
    ) -> Result<(), String> {
        unreachable!("unused by the regen state machine")
    }
    fn standard_verify_flags(&self) -> Result<ScriptFlags, String> {
        unreachable!("unused by the regen state machine")
    }
    fn adjusted_time_unix(&self) -> i64 {
        unreachable!("unused by the regen state machine")
    }
}

/// A transaction source with a scripted vote count per block.
#[derive(Default)]
struct Votes(Vec<(Hash, usize)>);

impl Votes {
    fn set(&mut self, hash: Hash, n: usize) {
        self.0.retain(|(h, _)| *h != hash);
        self.0.push((hash, n));
    }
}

impl TemplateTxSource for Votes {
    fn mining_view(&self) -> TxMiningView {
        unreachable!("unused by the regen state machine")
    }
    fn have_transaction(&self, _hash: &Hash) -> bool {
        unreachable!("unused by the regen state machine")
    }
    fn have_all_transactions(&self, _hashes: &[Hash]) -> bool {
        unreachable!("unused by the regen state machine")
    }
    fn vote_hashes_for_block(&self, hash: &Hash) -> Vec<Hash> {
        let n = self
            .0
            .iter()
            .find(|(h, _)| h == hash)
            .map_or(0, |(_, n)| *n);
        (0..n)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i as u8 + 1;
                Hash(h)
            })
            .collect()
    }
    fn votes_for_blocks(&self, _hashes: &[Hash]) -> Vec<Vec<VoteDesc>> {
        unreachable!("unused by the regen state machine")
    }
    fn is_reg_tx_tree_known_disapproved(&self, _hash: &Hash) -> bool {
        unreachable!("unused by the regen state machine")
    }
}

fn hash(b: u8) -> Hash {
    Hash([b; 32])
}

/// dcrd's `lru.Set.Contains` makes a hit the most recently used entry.
/// Parents A then B are notified; a new-votes template on A refreshes
/// A; C and D then evict B, not A, so the next new-votes template on A
/// is still reported as new votes (the port used to report new parent).
#[test]
fn a_notified_parent_hit_refreshes_its_recency() {
    let mut g = BgGenerator::new(TICKETS_PER_BLOCK, 0, true);
    let notify = |g: &mut BgGenerator, parent: u8, reason| {
        g.process_generated_template(Some(template(hash(parent))), reason, None, false)
            .expect("a notification")
            .1
    };
    use BgTemplateUpdateReason::{NewParent, NewVotes};

    assert_eq!(notify(&mut g, 0xa, NewParent), NewParent);
    assert_eq!(notify(&mut g, 0xb, NewParent), NewParent);
    assert_eq!(notify(&mut g, 0xa, NewVotes), NewVotes);
    assert_eq!(g.notified_parents, vec![hash(0xa), hash(0xb)]);
    assert_eq!(notify(&mut g, 0xc, NewParent), NewParent);
    assert_eq!(notify(&mut g, 0xd, NewParent), NewParent);
    assert_eq!(g.notified_parents, vec![hash(0xd), hash(0xc), hash(0xa)]);
    assert_eq!(
        notify(&mut g, 0xa, NewVotes),
        NewVotes,
        "A was refreshed by its hit, so C and D evicted B"
    );

    // A miss is still upgraded to a new parent and recorded.
    assert_eq!(notify(&mut g, 0xb, NewVotes), NewParent);
    assert_eq!(g.notified_parents, vec![hash(0xb), hash(0xa), hash(0xd)]);
}

/// Every max-votes arm is a fresh dcrd `time.After`, and nothing else
/// restarts a pending one.  Tip A connects with the minimum votes and
/// arms the timeout; child B connects with too few, which leaves A's
/// timeout running untouched in dcrd; B then reaches the minimum and
/// the lock-in arms a new timeout even though A's is still pending.
#[test]
fn max_votes_timeout_arms_are_fresh_and_only_arms_restart_it() {
    let mut g = BgGenerator::new(TICKETS_PER_BLOCK, 0, true);
    let mut state = BgTemplateState::new();
    let a = block(10, hash(9), 1);
    let b = block(11, a.header.block_hash(), 2);
    let mut chain = Chain {
        tip: TemplateBest::default(),
        tip_block: None,
    };
    let mut votes = Votes::default();

    chain.set_tip(&a);
    votes.set(a.header.block_hash(), 3);
    handle_regen_event(
        &mut g,
        &mut state,
        &mut chain,
        &votes,
        BgRegenEvent::BlockConnected(&a),
        true,
        0,
    );
    assert!(state.max_votes_timeout_armed);
    let armed_for_a = state.max_votes_timeout_gen;

    chain.set_tip(&b);
    votes.set(b.header.block_hash(), 1);
    handle_regen_event(
        &mut g,
        &mut state,
        &mut chain,
        &votes,
        BgRegenEvent::BlockConnected(&b),
        true,
        0,
    );
    assert!(
        state.max_votes_timeout_armed,
        "A's timeout is still pending"
    );
    assert_eq!(
        state.max_votes_timeout_gen, armed_for_a,
        "a connect that does not arm the timeout leaves its countdown alone"
    );
    assert_eq!(state.awaiting_min_votes_hash, Some(b.header.block_hash()));
    let side_chains = state.track_side_chains_timeout_gen;

    votes.set(b.header.block_hash(), 3);
    handle_regen_event(
        &mut g,
        &mut state,
        &mut chain,
        &votes,
        BgRegenEvent::Vote(&vote(&b.header.block_hash(), 11)),
        true,
        0,
    );
    assert!(state.max_votes_timeout_armed);
    assert_ne!(
        state.max_votes_timeout_gen, armed_for_a,
        "the lock-in on B arms a fresh timeout over A's pending one"
    );
    assert_eq!(state.track_side_chains_timeout_gen, side_chains);

    // The side chain timeout the same way: C connects with too few
    // votes and arms it, and D connecting before it fires clears and
    // re-arms it in one step (dcrd's `clearSideChainTracking` then a new
    // `time.After`), a fresh countdown the armed flag alone cannot show.
    let c = block(12, b.header.block_hash(), 3);
    chain.set_tip(&c);
    handle_regen_event(
        &mut g,
        &mut state,
        &mut chain,
        &votes,
        BgRegenEvent::BlockConnected(&c),
        true,
        0,
    );
    assert!(state.track_side_chains_timeout_armed);
    let armed_for_c = state.track_side_chains_timeout_gen;
    assert_ne!(armed_for_c, side_chains);
    let d = block(13, c.header.block_hash(), 4);
    chain.set_tip(&d);
    handle_regen_event(
        &mut g,
        &mut state,
        &mut chain,
        &votes,
        BgRegenEvent::BlockConnected(&d),
        true,
        0,
    );
    assert!(state.track_side_chains_timeout_armed);
    assert_ne!(state.track_side_chains_timeout_gen, armed_for_c);
}

/// `resetRegenTimer` restarts the countdown even when the timer is
/// already armed with the same duration.
#[test]
fn a_regen_reset_to_the_same_duration_restarts_it() {
    let mut state = BgTemplateState::new();
    let tpl = template(hash(1));
    handle_template_update(&mut state, Some(&tpl), false, 100);
    assert!(state.regen_timer_armed);
    let first = state.regen_timer_gen;
    handle_template_update(&mut state, Some(&tpl), false, 101);
    assert_eq!(state.regen_timer_millis, 30_000);
    assert_ne!(state.regen_timer_gen, first, "a reset is a fresh countdown");
}

/// A tip lookup that fails when a reorganization finishes leaves the
/// generator errored; dcrd's `setCurrentTemplate` queues the error as a
/// template update, whose handler arms the one-second retry.  The port
/// armed nothing, so the generator stayed errored until an unrelated
/// event arrived.
#[test]
fn a_failed_tip_lookup_after_a_reorg_arms_the_retry() {
    for (allow_unsynced, is_current, retry) in [
        (false, true, true),
        (true, false, true),
        // The queued event passes `handleRegenEvent`'s sync gate like any
        // other, so an unsynced node that does not mine unsynced arms
        // nothing.
        (false, false, false),
    ] {
        let mut g = BgGenerator::new(TICKETS_PER_BLOCK, 0, allow_unsynced);
        let mut state = BgTemplateState::new();
        let mut chain = Chain {
            tip: TemplateBest {
                hash: hash(7),
                height: 7,
                ..TemplateBest::default()
            },
            tip_block: None,
        };
        let votes = Votes::default();

        for event in [BgRegenEvent::ReorgStarted, BgRegenEvent::ReorgDone] {
            handle_regen_event(&mut g, &mut state, &mut chain, &votes, event, is_current, 0);
        }
        assert_eq!(g.stale_template_count, 0);
        assert!(!state.is_reorganizing);
        assert!(g.template.is_none());
        assert_eq!(
            g.template_err.as_deref(),
            Some(format!("block {} is not known", hash(7)).as_str())
        );
        assert_eq!(
            state.failed_gen_retry_timeout_armed, retry,
            "allow unsynced {allow_unsynced}, current {is_current}"
        );
        assert!(g.gen_requests.is_empty(), "the retry builds when it fires");
    }
}
