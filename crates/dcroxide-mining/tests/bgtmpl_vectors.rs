// SPDX-License-Identifier: ISC
//! Replay of frozen background template generator vectors generated
//! by an in-package dump test at release-v2.1.5: eleven scenarios
//! drive dcrd's own regen event handlers over a scripted chain and
//! transaction source, with template generation failing fast so only
//! the state machine is exercised.  Covered: the below-SVH and
//! max-votes immediate generation paths, the min-votes lock-in with
//! the max-votes propagation timeout, the awaiting-min-votes vote
//! ladder, side chain tracking with vote-driven and timeout-driven
//! reorganizations (including a scripted reorg failure falling back
//! to monitoring and parent generation), the reorg bracket, unsynced
//! gating, template updates, forced regeneration, and disconnects.
//! Every emitted state row is compared field for field.

// Index arithmetic over pinned vector rows.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use dcroxide_blockchain::UtxoEntry;
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_chaincfg::mainnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_mining::bg_generator::{
    BgGenerator, BgRegenEvent, BgTemplateState, handle_regen_event,
    handle_track_side_chains_timeout,
};
use dcroxide_mining::{
    BlockTemplate, TemplateBest, TemplateChain, TemplateTxSource, TxMiningView, VoteDesc,
};
use dcroxide_standalone::SubsidySplitVariant;
use dcroxide_txscript::ScriptFlags;
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint, TxOut};

const VECTORS: &str = include_str!("data/bgtmpl_vectors.txt");

/// Go's zero `time.Time` truncated to the header codec's uint32
/// seconds (`uint32(-62135596800)`); the dump blocks carry it, so it
/// participates in their hashes.
const GO_ZERO_TIME_UNIX_U32: u32 = 2288912640;

fn byte_hash(b: u8) -> Hash {
    let mut h = [0u8; 32];
    h[0] = b;
    Hash(h)
}

/// The dump's `makeBlockNonce`: a block whose header carries only the
/// height, previous block hash, and nonce.
fn make_block(height: u32, prev: Hash, nonce: u32) -> MsgBlock {
    MsgBlock {
        header: BlockHeader {
            version: 0,
            prev_block: prev,
            merkle_root: Hash([0u8; 32]),
            stake_root: Hash([0u8; 32]),
            vote_bits: 0,
            final_state: [0u8; 6],
            voters: 0,
            fresh_stake: 0,
            revocations: 0,
            pool_size: 0,
            bits: 0,
            sbits: 0,
            height,
            size: 0,
            timestamp: GO_ZERO_TIME_UNIX_U32,
            nonce,
            extra_data: [0u8; 32],
            stake_version: 0,
        },
        transactions: Vec::new(),
        stransactions: Vec::new(),
    }
}

/// The dump's `makeVote`: a vote-shaped transaction whose first
/// output carries the OP_RETURN block reference.
fn make_vote(voted_on: &Hash, height: u32) -> MsgTx {
    let mut script = vec![0u8; 38];
    script[0] = 0x6a; // OP_RETURN
    script[1] = 36; // data push
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

/// The scripted chain: mutable tip facts, the tip generation, and a
/// reorganization recorder with scripted failures.
struct BgChain {
    tip: TemplateBest,
    generation: Vec<Hash>,
    reorg_fails: BTreeSet<[u8; 32]>,
    reorgs: Vec<String>,
}

impl TemplateChain for BgChain {
    fn best_snapshot(&self) -> TemplateBest {
        self.tip.clone()
    }
    fn block_by_hash(&self, _hash: &Hash) -> Result<MsgBlock, String> {
        // The dump closure rebuilds the tip block from the tip facts
        // regardless of the requested hash.
        Ok(make_block(self.tip.height as u32, self.tip.prev_hash, 0))
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
    fn count_sig_ops(&self, _tx: &MsgTx, _cb: bool, _ssgen: bool, _treasury: bool) -> i64 {
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
    fn force_head_reorganization(&mut self, former: Hash, new_best: Hash) -> Result<(), String> {
        if self.reorg_fails.contains(&new_best.0) {
            self.reorgs.push(format!("FAIL:{former}>{new_best}"));
            return Err("reorg failed".into());
        }
        self.reorgs.push(format!("OK:{former}>{new_best}"));
        Ok(())
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
        self.generation.clone()
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

/// The dump's `bgDumpTxSource`: a scripted vote count per block hash
/// materialized as distinct placeholder vote hashes.
struct BgSource {
    votes: Vec<([u8; 32], usize)>,
}

impl BgSource {
    fn set_votes(&mut self, hash: &Hash, n: usize) {
        self.votes.retain(|(h, _)| *h != hash.0);
        self.votes.push((hash.0, n));
    }
}

impl TemplateTxSource for BgSource {
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
            .votes
            .iter()
            .find(|(h, _)| *h == hash.0)
            .map_or(0, |(_, n)| *n);
        (0..n).map(|i| byte_hash(i as u8 + 1)).collect()
    }
    fn votes_for_blocks(&self, _hashes: &[Hash]) -> Vec<Vec<VoteDesc>> {
        unreachable!("unused by the regen state machine")
    }
    fn is_reg_tx_tree_known_disapproved(&self, _hash: &Hash) -> bool {
        unreachable!("unused by the regen state machine")
    }
}

/// One scenario's harness: the generator, the handler state, the
/// scripted mocks, and the pinned step rows to compare against.
struct Rig<'v> {
    g: BgGenerator,
    state: BgTemplateState,
    chain: BgChain,
    src: BgSource,
    is_current: bool,
    processed: usize,
    gen_count: usize,
    scen: usize,
    step: usize,
    expected: &'v [&'v str],
}

impl Rig<'_> {
    fn tip(&mut self, hash: Hash, prev: Hash, height: i64) {
        self.chain.tip = TemplateBest {
            hash,
            prev_hash: prev,
            height,
            ..TemplateBest::default()
        };
    }

    fn event(&mut self, event: BgRegenEvent<'_>) {
        handle_regen_event(
            &mut self.g,
            &mut self.state,
            &mut self.chain,
            &self.src,
            event,
            self.is_current,
            0,
        );
    }

    /// Simulate the daemon completing every newly recorded generation
    /// request: each fails fast with the dump's scripted policy error
    /// and queues one template-update regen event.
    fn drain(&mut self) {
        while self.processed < self.g.gen_requests.len() {
            let req = self.g.gen_requests[self.processed];
            self.processed += 1;
            let notification = self.g.process_generated_template(
                None,
                req.reason,
                Some("dump: no template generation".to_string()),
                req.block_retrieval,
            );
            assert!(notification.is_none(), "failed generation must not notify");
            self.gen_count += 1;
        }
    }

    /// Reconstruct the dump's emitted state row and compare it to the
    /// pinned one.
    fn check(&mut self, name: &str) {
        let min_votes = self
            .state
            .awaiting_min_votes_hash
            .map_or_else(|| "-".to_string(), |h| h.to_string());
        let mut side: Vec<String> = self
            .state
            .awaiting_side_chain_min_votes
            .iter()
            .map(|h| h.to_string())
            .collect();
        side.sort();
        let side = if side.is_empty() {
            "-".to_string()
        } else {
            side.join(",")
        };
        let tpl_err = self
            .g
            .template_err
            .clone()
            .unwrap_or_else(|| "-".to_string());
        let reorgs = if self.chain.reorgs.is_empty() {
            "-".to_string()
        } else {
            self.chain.reorgs.join(";")
        };
        let line = format!(
            "bgstep|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.scen,
            self.step,
            name,
            self.state.is_reorganizing,
            self.state.regen_timer_armed,
            min_votes,
            self.state.max_votes_timeout_armed,
            side,
            self.state.track_side_chains_timeout_armed,
            self.state.failed_gen_retry_timeout_armed,
            self.state.base_block_hash,
            self.state.base_block_height,
            self.gen_count,
            self.g.template.is_some(),
            tpl_err,
            reorgs,
        );
        assert_eq!(line, self.expected[self.step], "scenario {}", self.scen);
        self.step += 1;
    }
}

#[test]
fn bg_template_generator_matches_dcrd() {
    let params = mainnet_params();

    // Group the vector rows into scenarios.
    let mut scenarios: Vec<(Vec<&str>, Vec<&str>)> = Vec::new();
    for line in VECTORS.lines() {
        let fields: Vec<&str> = line.split('|').collect();
        match fields[0] {
            "bgscen" => scenarios.push((fields, Vec::new())),
            "bgstep" => scenarios
                .last_mut()
                .expect("scenario row first")
                .1
                .push(line),
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(scenarios.len(), 11, "unexpected scenario count");

    for (header, steps) in &scenarios {
        let scen: usize = header[1].parse().unwrap();
        let name = header[2];
        let allow_unsynced = header[3] == "true";
        let is_current = header[4] == "true";

        let mut rig = Rig {
            g: BgGenerator::new(
                params.tickets_per_block,
                params.stake_validation_height,
                allow_unsynced,
            ),
            state: BgTemplateState::new(),
            chain: BgChain {
                tip: TemplateBest::default(),
                generation: Vec::new(),
                reorg_fails: BTreeSet::new(),
                reorgs: Vec::new(),
            },
            src: BgSource { votes: Vec::new() },
            is_current,
            processed: 0,
            gen_count: 0,
            scen,
            step: 0,
            expected: steps,
        };

        match name {
            "bg: below svh connect" => {
                let blk_a = make_block(100, byte_hash(0x10), 0);
                rig.tip(blk_a.header.block_hash(), byte_hash(0x10), 100);
                rig.event(BgRegenEvent::BlockConnected(&blk_a));
                rig.drain();
                rig.check("connect below svh");

                // A non-tip connect is ignored.
                let blk_stale = make_block(99, byte_hash(0x11), 0);
                rig.event(BgRegenEvent::BlockConnected(&blk_stale));
                rig.drain();
                rig.check("stale connect ignored");
            }
            "bg: max votes connect" => {
                let blk_b = make_block(5000, byte_hash(0x20), 0);
                rig.tip(blk_b.header.block_hash(), byte_hash(0x20), 5000);
                rig.src.set_votes(&blk_b.header.block_hash(), 5);
                rig.event(BgRegenEvent::BlockConnected(&blk_b));
                rig.drain();
                rig.check("connect max votes");
            }
            "bg: min votes connect" => {
                let blk_c = make_block(5000, byte_hash(0x30), 0);
                let blk_c_hash = blk_c.header.block_hash();
                rig.tip(blk_c_hash, byte_hash(0x30), 5000);
                rig.src.set_votes(&blk_c_hash, 3);
                rig.event(BgRegenEvent::BlockConnected(&blk_c));
                rig.drain();
                rig.check("connect min votes");

                // A vote below the maximum with the timeout armed
                // changes nothing; the timeout keeps running.
                rig.src.set_votes(&blk_c_hash, 4);
                rig.event(BgRegenEvent::Vote(&make_vote(&blk_c_hash, 5000)));
                rig.drain();
                rig.check("vote below max with timeout");

                // Reaching the maximum with the timeout armed
                // regenerates as a new parent and disarms the timeout.
                rig.src.set_votes(&blk_c_hash, 5);
                rig.event(BgRegenEvent::Vote(&make_vote(&blk_c_hash, 5000)));
                rig.drain();
                rig.check("vote reaches max with timeout");

                // A subsequent vote with the timeout disarmed
                // regenerates as new votes.
                rig.event(BgRegenEvent::Vote(&make_vote(&blk_c_hash, 5000)));
                rig.drain();
                rig.check("vote after timeout");
            }
            "bg: awaiting min votes" => {
                let blk_d = make_block(5000, byte_hash(0x40), 0);
                let blk_d_hash = blk_d.header.block_hash();
                rig.tip(blk_d_hash, byte_hash(0x40), 5000);
                rig.src.set_votes(&blk_d_hash, 1);
                rig.event(BgRegenEvent::BlockConnected(&blk_d));
                rig.drain();
                rig.check("connect few votes");

                // A vote below the minimum changes nothing.
                rig.src.set_votes(&blk_d_hash, 2);
                rig.event(BgRegenEvent::Vote(&make_vote(&blk_d_hash, 5000)));
                rig.drain();
                rig.check("vote below min");

                // Reaching the minimum locks the tip in and arms the
                // max votes timeout.
                rig.src.set_votes(&blk_d_hash, 3);
                rig.event(BgRegenEvent::Vote(&make_vote(&blk_d_hash, 5000)));
                rig.drain();
                rig.check("vote reaches min");

                // Reaching the maximum triggers generation through
                // the base-block path.
                rig.src.set_votes(&blk_d_hash, 5);
                rig.event(BgRegenEvent::Vote(&make_vote(&blk_d_hash, 5000)));
                rig.drain();
                rig.check("vote reaches max");
            }
            "bg: side chain reorg by vote" => {
                let blk_e = make_block(5000, byte_hash(0x50), 0);
                let blk_e_hash = blk_e.header.block_hash();
                rig.tip(blk_e_hash, byte_hash(0x50), 5000);
                rig.event(BgRegenEvent::BlockConnected(&blk_e));
                rig.drain();
                rig.check("connect no votes");

                // Sibling accepted while the tracking timeout is
                // armed: ignored.
                let sib_f = make_block(5000, byte_hash(0x50), 7);
                let sib_f_hash = sib_f.header.block_hash();
                rig.event(BgRegenEvent::BlockAccepted(&sib_f));
                rig.drain();
                rig.check("sibling during timeout");

                // The tracking timeout expires with no viable
                // candidates: the sibling set fills from the tip
                // generation and, since no template exists yet, one
                // is generated on the parent.
                rig.chain.generation = vec![blk_e_hash, sib_f_hash];
                rig.state.track_side_chains_timeout_armed = false;
                handle_track_side_chains_timeout(
                    &mut rig.g,
                    &mut rig.state,
                    &mut rig.chain,
                    &rig.src,
                );
                rig.drain();
                rig.check("tracking timeout");

                // A vote bringing the sibling to the minimum forces a
                // reorganization.
                rig.src.set_votes(&sib_f_hash, 3);
                rig.event(BgRegenEvent::Vote(&make_vote(&sib_f_hash, 5000)));
                rig.drain();
                rig.check("sibling vote reorg");
            }
            "bg: tracking timeout reorg" => {
                let blk_g = make_block(5000, byte_hash(0x60), 0);
                let blk_g_hash = blk_g.header.block_hash();
                rig.tip(blk_g_hash, byte_hash(0x60), 5000);
                rig.event(BgRegenEvent::BlockConnected(&blk_g));
                rig.drain();
                rig.check("connect no votes");

                let sib_h = make_block(5000, byte_hash(0x60), 8);
                let sib_i = make_block(5000, byte_hash(0x60), 9);
                let sib_h_hash = sib_h.header.block_hash();
                let sib_i_hash = sib_i.header.block_hash();
                rig.chain.generation = vec![blk_g_hash, sib_h_hash, sib_i_hash];
                rig.src.set_votes(&sib_h_hash, 2);
                rig.src.set_votes(&sib_i_hash, 4);
                // The first candidate fails to reorg; the failure
                // falls through to monitoring and, with no template
                // yet, one is generated on the parent.
                rig.chain.reorg_fails.insert(sib_i_hash.0);
                rig.state.track_side_chains_timeout_armed = false;
                handle_track_side_chains_timeout(
                    &mut rig.g,
                    &mut rig.state,
                    &mut rig.chain,
                    &rig.src,
                );
                rig.drain();
                rig.check("timeout reorg fallback");
            }
            "bg: reorg bracket" => {
                let blk_j = make_block(100, byte_hash(0x70), 0);
                rig.tip(blk_j.header.block_hash(), byte_hash(0x70), 100);
                rig.event(BgRegenEvent::BlockConnected(&blk_j));
                rig.drain();
                rig.check("connect");

                // The reorg start clears the template synchronously,
                // which queues one template-update regen event in the
                // daemon.
                rig.event(BgRegenEvent::ReorgStarted);
                rig.drain();
                assert!(rig.g.gen_requests.len() == rig.processed);
                rig.gen_count += 1;
                rig.check("reorg started");

                // Events during the reorg are ignored.
                rig.event(BgRegenEvent::BlockConnected(&blk_j));
                rig.drain();
                rig.check("connect during reorg");

                // The reorg completing treats the tip as freshly
                // connected.
                rig.event(BgRegenEvent::ReorgDone);
                rig.drain();
                rig.check("reorg done");
            }
            "bg: unsynced gating" => {
                let blk_k = make_block(100, byte_hash(0x80), 0);
                rig.tip(blk_k.header.block_hash(), byte_hash(0x80), 100);
                rig.event(BgRegenEvent::BlockConnected(&blk_k));
                rig.drain();
                rig.check("connect while unsynced");
            }
            "bg: template updates" => {
                let tpl = BlockTemplate {
                    block: make_block(5001, byte_hash(0x90), 0),
                    fees: Vec::new(),
                    sig_op_counts: Vec::new(),
                    height: 0,
                    valid_pay_address: false,
                };
                rig.event(BgRegenEvent::TemplateUpdated(Some(&tpl), false));
                rig.drain();
                rig.check("template update ok");

                rig.event(BgRegenEvent::TemplateUpdated(None, true));
                rig.drain();
                rig.check("template update err");
            }
            "bg: force regen" => {
                rig.event(BgRegenEvent::ForceRegen);
                rig.drain();
                rig.check("force regen");

                // A force regen with the max votes timeout armed is
                // ignored.
                rig.state.max_votes_timeout_armed = true;
                rig.event(BgRegenEvent::ForceRegen);
                rig.drain();
                rig.check("force regen ignored");
            }
            "bg: disconnect" => {
                let blk_l = make_block(5000, byte_hash(0xa0), 0);
                rig.tip(byte_hash(0xa0), byte_hash(0xa1), 4999);
                rig.event(BgRegenEvent::BlockDisconnected(&blk_l));
                rig.drain();
                rig.check("disconnect");

                // A disconnect whose parent is not the tip is ignored.
                let blk_m = make_block(5000, byte_hash(0xa2), 0);
                rig.event(BgRegenEvent::BlockDisconnected(&blk_m));
                rig.drain();
                rig.check("stale disconnect ignored");
            }
            other => panic!("unknown scenario {other}"),
        }

        assert_eq!(rig.step, steps.len(), "scenario {scen}: steps consumed");
    }
}
