// SPDX-License-Identifier: ISC
//! Template queue details of dcrd's `NewBlockTemplate` that a direct
//! translation loses:
//!
//! - dcrd's priority lookup is `UtxoViewpoint.PriorityInput`, which
//!   reports a spent entry as missing, so an input whose output the
//!   view holds spent (a disapproved tip's regular tree) adds no input
//!   age;
//! - dcrd's queue and `prioItemMap` share one `*txPrioItem`, so the fee
//!   rate refreshed when an item is popped and skipped is the rate its
//!   later re-promotion carries;
//! - dcrd takes the best chain snapshot once, so after reorganizing to
//!   a sibling tip the sibling's votes fail the winning-ticket check
//!   against the old tip's lottery and the build recycles the new tip
//!   through `handleTooFewVoters`.
//!
//! Script and input validation are stubbed out: the scenarios are
//! about pop order, which they do not affect.

// Test-harness arithmetic over small counters and fixed amounts.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use dcroxide_blockchain::UtxoEntry;
use dcroxide_blockchain::utxoview::UtxoView;
use dcroxide_chaincfg::{Params, mainnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_mining::{
    BlkTmplGenerator, BlockTemplate, ExtraNonces, MiningPolicy, TemplateBest, TemplateChain,
    TemplateTxSource, TxDesc, TxMiningView, VoteDesc,
};
use dcroxide_stake::TxType;
use dcroxide_standalone::SubsidySplitVariant;
use dcroxide_txscript::ScriptFlags;
use dcroxide_wire::{
    BlockHeader, MsgBlock, MsgTx, OutPoint, TX_TREE_REGULAR, TX_TREE_STAKE, TxIn, TxOut,
};

fn params() -> &'static Params {
    Box::leak(Box::new(mainnet_params()))
}

fn header(height: u32, prev: Hash, nonce: u32) -> BlockHeader {
    let (mut header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("header");
    header.version = 1;
    header.height = height;
    header.prev_block = prev;
    header.nonce = nonce;
    header.bits = 0x1d00_ffff;
    header.timestamp = 1_000_000;
    header
}

/// A chain that serves the tip facts, a fetched view over its utxo
/// set, and a head reorganization that switches the best snapshot.
/// Validation always passes.
struct Chain {
    best: TemplateBest,
    blocks: HashMap<[u8; 32], MsgBlock>,
    utxos: UtxoView,
    /// Transactions of the tip's regular tree: a view fetched without
    /// that tree holds their outputs spent, as dcrd's
    /// `disconnectDisapprovedBlock` leaves them.
    tip_regular: HashSet<[u8; 32]>,
    tip_generation: Vec<Hash>,
    /// The snapshot a reorganization to each head makes current.
    reorg_best: HashMap<[u8; 32], TemplateBest>,
    reorgs: Vec<(Hash, Hash)>,
}

impl Chain {
    fn new(best: TemplateBest, tip: MsgBlock) -> Chain {
        let mut blocks = HashMap::new();
        blocks.insert(best.hash.0, tip);
        Chain {
            best,
            blocks,
            utxos: UtxoView::new(),
            tip_regular: HashSet::new(),
            tip_generation: Vec::new(),
            reorg_best: HashMap::new(),
            reorgs: Vec::new(),
        }
    }

    fn add_utxo(&mut self, op: OutPoint, amount: i64, height: u32, tx_type: TxType) {
        let entry = UtxoEntry::new(
            amount,
            vec![0x51],
            height,
            1,
            0,
            false,
            false,
            tx_type,
            None,
        );
        self.utxos.insert_entry(&op, entry);
    }
}

impl TemplateChain for Chain {
    fn best_snapshot(&self) -> TemplateBest {
        self.best.clone()
    }
    fn block_by_hash(&self, hash: &Hash) -> Result<MsgBlock, String> {
        self.blocks
            .get(&hash.0)
            .cloned()
            .ok_or_else(|| format!("no block {hash}"))
    }
    fn calc_next_required_difficulty(&self, _h: &Hash, _ts: i64) -> Result<u32, String> {
        Ok(0x1d00_ffff)
    }
    fn calc_stake_version_by_hash(&self, _h: &Hash) -> Result<u32, String> {
        Ok(0)
    }
    fn check_connect_block_template(&mut self, _b: &MsgBlock) -> Result<(), String> {
        Ok(())
    }
    fn check_ticket_exhaustion(&self, _h: &Hash, _p: u8) -> Result<(), String> {
        Ok(())
    }
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
        Ok(0)
    }
    fn check_tspend_has_votes(&self, _h: &Hash, _tx: &MsgTx) -> Result<(), String> {
        Ok(())
    }
    fn count_total_sig_ops(
        &self,
        _tx: &MsgTx,
        _is_cb: bool,
        _is_vote: bool,
        _view: &UtxoView,
        _treasury: bool,
    ) -> Result<u32, String> {
        Ok(0)
    }
    fn fetch_utxo_entry(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>, String> {
        Ok(self.utxos.lookup_entry(outpoint).cloned())
    }
    fn fetch_utxo_view(
        &self,
        tx: &MsgTx,
        _tx_hash: &Hash,
        _tree: i8,
        include_regular: bool,
    ) -> Result<UtxoView, String> {
        let mut view = UtxoView::new();
        for tx_in in &tx.tx_in {
            let op = &tx_in.previous_out_point;
            if let Some(entry) = self.utxos.lookup_entry(op) {
                let mut entry = entry.clone();
                if !include_regular && self.tip_regular.contains(&op.hash.0) {
                    entry.spend();
                }
                view.insert_entry(op, entry);
            }
        }
        Ok(view)
    }
    fn fetch_utxo_view_parent_template(&self, _b: &MsgBlock) -> Result<UtxoView, String> {
        Ok(UtxoView::new())
    }
    fn force_head_reorganization(&mut self, former: Hash, new: Hash) -> Result<(), String> {
        let best = self
            .reorg_best
            .get(&new.0)
            .cloned()
            .ok_or_else(|| format!("no snapshot for {new}"))?;
        self.reorgs.push((former, new));
        self.best = best;
        Ok(())
    }
    fn header_by_hash(&self, hash: &Hash) -> Result<BlockHeader, String> {
        self.block_by_hash(hash).map(|b| b.header)
    }
    fn is_finalized_transaction(&self, _tx: &MsgTx, _height: i64, _time: i64) -> bool {
        true
    }
    fn is_header_commitments_agenda_active(&self, _h: &Hash) -> Result<bool, String> {
        Ok(false)
    }
    fn is_treasury_agenda_active(&self, _h: &Hash) -> Result<bool, String> {
        Ok(false)
    }
    fn is_auto_revocations_agenda_active(&self, _h: &Hash) -> Result<bool, String> {
        Ok(false)
    }
    fn is_subsidy_split_agenda_active(&self, _h: &Hash) -> Result<bool, String> {
        Ok(false)
    }
    fn is_subsidy_split_r2_agenda_active(&self, _h: &Hash) -> Result<bool, String> {
        Ok(false)
    }
    fn max_treasury_expenditure(&self, _h: &Hash) -> Result<i64, String> {
        Ok(0)
    }
    fn tip_generation(&self) -> Vec<Hash> {
        self.tip_generation.clone()
    }
    fn validate_transaction_scripts(
        &self,
        _tx: &MsgTx,
        _view: &UtxoView,
        _flags: ScriptFlags,
        _auto_rev: bool,
    ) -> Result<(), String> {
        Ok(())
    }
    fn standard_verify_flags(&self) -> Result<ScriptFlags, String> {
        Ok(ScriptFlags(0))
    }
    fn adjusted_time_unix(&self) -> i64 {
        2_000_000
    }
}

/// A transaction source over a tracked mining view, with votes
/// indexed by the block they vote on.
struct Source {
    pool: HashMap<[u8; 32], Arc<TxDesc>>,
    outpoints: HashMap<([u8; 32], u32, i8), Arc<TxDesc>>,
    view: TxMiningView,
    votes: HashMap<[u8; 32], Vec<VoteDesc>>,
    known_disapproved: bool,
}

impl Source {
    fn new() -> Source {
        Source {
            pool: HashMap::new(),
            outpoints: HashMap::new(),
            view: TxMiningView::new(true),
            votes: HashMap::new(),
            known_disapproved: false,
        }
    }

    /// Add a transaction; parents must be added before children.
    fn add(&mut self, tx: MsgTx, tx_type: TxType, fee: i64) -> Hash {
        let tx_hash = tx.tx_hash();
        let tree = if tx_type == TxType::Regular {
            TX_TREE_REGULAR
        } else {
            TX_TREE_STAKE
        };
        let tx_size = tx.serialize_size() as i64;
        let desc = Arc::new(TxDesc {
            tx,
            tx_hash,
            tree,
            tx_type,
            added_unix: 0,
            height: 0,
            fee,
            total_sig_ops: 0,
            tx_size,
        });
        self.pool.insert(tx_hash.0, desc.clone());
        let pool = &self.pool;
        let outpoints = &self.outpoints;
        self.view
            .add_transaction(&desc, &|hash| pool.get(&hash.0).cloned(), &|tx, f| {
                for i in 0..tx.tx.tx_out.len() as u32 {
                    if let Some(redeemer) = outpoints.get(&(tx.tx_hash.0, i, tx.tree)) {
                        f(redeemer.clone());
                    }
                }
            });
        for tx_in in &desc.tx.tx_in {
            let op = &tx_in.previous_out_point;
            self.outpoints
                .insert((op.hash.0, op.index, op.tree), desc.clone());
        }
        if tx_type == TxType::SSGen {
            let (block_hash, _) = dcroxide_stake::ssgen_block_voted_on(&desc.tx);
            self.votes.entry(block_hash.0).or_default().push(VoteDesc {
                vote_hash: tx_hash,
                ticket_hash: desc.tx.tx_in[1].previous_out_point.hash,
                approves_parent: true,
            });
        }
        tx_hash
    }
}

impl TemplateTxSource for Source {
    fn mining_view(&self) -> TxMiningView {
        // Pin the queue insertion order by hash, as the vector
        // harnesses do.
        let pool = &self.pool;
        let mut descs: Vec<_> = pool.values().cloned().collect();
        descs.sort_by_key(|d| d.tx_hash.0);
        self.view
            .clone_view(descs, &|hash| pool.get(&hash.0).cloned())
    }
    fn have_transaction(&self, hash: &Hash) -> bool {
        self.pool.contains_key(&hash.0)
    }
    fn have_all_transactions(&self, hashes: &[Hash]) -> bool {
        hashes.iter().all(|h| self.pool.contains_key(&h.0))
    }
    fn vote_hashes_for_block(&self, hash: &Hash) -> Vec<Hash> {
        self.votes
            .get(&hash.0)
            .map(|v| v.iter().map(|d| d.vote_hash).collect())
            .unwrap_or_default()
    }
    fn votes_for_blocks(&self, hashes: &[Hash]) -> Vec<Vec<VoteDesc>> {
        hashes
            .iter()
            .map(|h| self.votes.get(&h.0).cloned().unwrap_or_default())
            .collect()
    }
    fn is_reg_tx_tree_known_disapproved(&self, _hash: &Hash) -> bool {
        self.known_disapproved
    }
}

fn outpoint(hash: Hash, index: u32, tree: i8) -> OutPoint {
    OutPoint { hash, index, tree }
}

fn tx_in(prev: OutPoint) -> TxIn {
    TxIn {
        previous_out_point: prev,
        sequence: 0xffff_ffff,
        value_in: 0,
        block_height: 0,
        block_index: 0,
        signature_script: Vec::new(),
    }
}

/// A regular transaction spending the given outpoints with two
/// anyone-can-spend outputs, so every transaction built here has the
/// same size for the same input count.
fn regular(inputs: &[OutPoint], tag: i64) -> MsgTx {
    let mut tx = MsgTx::default();
    for prev in inputs {
        tx.tx_in.push(tx_in(*prev));
    }
    for i in 0..2 {
        tx.tx_out.push(TxOut {
            value: 1_000_000 + tag * 10 + i,
            version: 0,
            pk_script: vec![0x51],
        });
    }
    tx
}

fn generator(chain: Chain, source: Source) -> BlkTmplGenerator<'static, Chain, Source> {
    let policy = MiningPolicy {
        block_max_size: 375_000,
        tx_min_free_fee: 10_000,
        aggressive_mining: true,
    };
    BlkTmplGenerator::new(policy, params(), chain, source, 0)
}

fn build(g: &mut BlkTmplGenerator<'static, Chain, Source>) -> BlockTemplate {
    g.new_block_template(
        None,
        &ExtraNonces {
            coinbase: 0,
            treasury: 0,
        },
    )
    .expect("template generation")
    .expect("a template")
}

/// The regular tree after the coinbase.
fn mined(template: &BlockTemplate) -> Vec<Hash> {
    template.block.transactions[1..]
        .iter()
        .map(MsgTx::tx_hash)
        .collect()
}

/// A chain at height 100, below stake validation.
fn low_chain() -> Chain {
    let tip_hash = Hash([0xa1; 32]);
    let best = TemplateBest {
        hash: tip_hash,
        prev_hash: Hash([0xa0; 32]),
        height: 100,
        median_time_unix: 1_000_000,
        next_stake_diff: 1,
        ..TemplateBest::default()
    };
    let tip = MsgBlock {
        header: header(100, best.prev_hash, 0),
        transactions: Vec::new(),
        stransactions: Vec::new(),
    };
    Chain::new(best, tip)
}

/// A child whose rate fell when one parent was mined, and was skipped
/// for it, is re-promoted by its last parent at the rate computed when
/// it was skipped (dcrd `mining.go:1666` updates the `*txPrioItem`
/// `prioItemMap` also holds, and `:1832-1834` pushes that item).
///
/// Every transaction is the same size, with fees setting these rates
/// in atoms/kB: P1 100k, P2 12k, C (spends P1 and P2) 60k, D (spends
/// P2) 90k, X 45k.  C enters the queue at its bundle rate (57.3k).  P1
/// is mined; C pops, refreshes to 36k with P2 left, and is skipped; D
/// pops and mines [P2, D], which promotes C.  At 36k C follows X, as in
/// dcrd; the stale 57.3k copy put it ahead of X.
#[test]
fn a_skipped_child_is_repromoted_at_its_refreshed_rate() {
    let mut chain = low_chain();
    let fund = Hash([0xf0; 32]);
    let fund_ops: Vec<OutPoint> = (0..8).map(|i| outpoint(fund, i, TX_TREE_REGULAR)).collect();
    for op in &fund_ops {
        chain.add_utxo(*op, 5_000_000, 50, TxType::Regular);
    }

    let p1 = regular(&[fund_ops[0], fund_ops[1]], 1);
    let p2 = regular(&[fund_ops[2], fund_ops[3]], 2);
    let c = regular(
        &[
            outpoint(p1.tx_hash(), 0, TX_TREE_REGULAR),
            outpoint(p2.tx_hash(), 0, TX_TREE_REGULAR),
        ],
        3,
    );
    let d = regular(
        &[outpoint(p2.tx_hash(), 1, TX_TREE_REGULAR), fund_ops[4]],
        4,
    );
    let x = regular(&[fund_ops[5], fund_ops[6]], 5);
    let size = p1.serialize_size() as i64;
    for tx in [&p2, &c, &d, &x] {
        assert_eq!(tx.serialize_size() as i64, size, "equal sizes");
    }

    // Fees as atoms per byte times the shared size.
    let mut source = Source::new();
    let p1_hash = source.add(p1, TxType::Regular, 100 * size);
    let p2_hash = source.add(p2, TxType::Regular, 12 * size);
    let c_hash = source.add(c, TxType::Regular, 60 * size);
    let d_hash = source.add(d, TxType::Regular, 90 * size);
    let x_hash = source.add(x, TxType::Regular, 45 * size);

    let mut g = generator(chain, source);
    let template = build(&mut g);
    assert_eq!(
        mined(&template),
        vec![p1_hash, p2_hash, d_hash, x_hash, c_hash],
        "C must be re-promoted at 36k and so follow X",
    );
}

/// With the tip known disapproved the fetched view holds the tip's
/// regular-tree outputs spent, and dcrd's `PriorityInput`
/// (`utxoviewpoint.go:226-233`) reports those as missing, so a child
/// spending one gets no input age.
///
/// P (from the disapproved tip, back in the mempool), its child T, and
/// an unrelated U share one fee rate, so priority orders them.  P's old
/// input puts it first.  U's small, young input still outranks T's
/// zero priority in dcrd; counting T's spent input, 4.98M atoms aged
/// one block, put T ahead of U.
#[test]
fn a_spent_view_entry_adds_no_priority() {
    let mut chain = low_chain();
    let fund = Hash([0xf1; 32]);
    chain.add_utxo(
        outpoint(fund, 0, TX_TREE_REGULAR),
        5_000_000,
        50,
        TxType::Regular,
    );
    let young = Hash([0xf2; 32]);
    chain.add_utxo(
        outpoint(young, 0, TX_TREE_REGULAR),
        1_000_000,
        99,
        TxType::Regular,
    );

    // P was mined in the tip, so its outputs are in the utxo set at the
    // tip height, but the tip's regular tree is disapproved.
    let p = regular(&[outpoint(fund, 0, TX_TREE_REGULAR)], 1);
    let p_hash = p.tx_hash();
    chain.add_utxo(
        outpoint(p_hash, 0, TX_TREE_REGULAR),
        4_980_000,
        100,
        TxType::Regular,
    );
    chain.tip_regular.insert(p_hash.0);

    let t = regular(&[outpoint(p_hash, 0, TX_TREE_REGULAR)], 2);
    let u = regular(&[outpoint(young, 0, TX_TREE_REGULAR)], 3);
    let size = p.serialize_size() as i64;
    assert_eq!(t.serialize_size() as i64, size, "equal sizes");
    assert_eq!(u.serialize_size() as i64, size, "equal sizes");

    let mut source = Source::new();
    source.known_disapproved = true;
    let fee = 20 * size;
    source.add(p, TxType::Regular, fee);
    let t_hash = source.add(t, TxType::Regular, fee);
    let u_hash = source.add(u, TxType::Regular, fee);

    let mut g = generator(chain, source);
    let template = build(&mut g);
    assert_eq!(
        mined(&template),
        vec![p_hash, u_hash, t_hash],
        "T's spent input must not count toward its priority",
    );
}

/// A well-formed vote on `block` at `height` spending `ticket`: a
/// stakebase, the block reference and vote bits pushes, and one
/// OP_SSGEN-tagged payout.
fn vote(block: Hash, height: u32, ticket: Hash) -> MsgTx {
    let mut voted_on = vec![0x6a, 36];
    voted_on.extend_from_slice(&block.0);
    voted_on.extend_from_slice(&height.to_le_bytes());
    let mut payout = vec![0xbb, 0x76, 0xa9, 0x14];
    payout.extend_from_slice(&ticket.0[..20]);
    payout.extend_from_slice(&[0x88, 0xac]);
    let mut tx = MsgTx::default();
    let mut stakebase = tx_in(outpoint(Hash::ZERO, u32::MAX, TX_TREE_REGULAR));
    stakebase.block_height = dcroxide_wire::NULL_BLOCK_HEIGHT;
    stakebase.block_index = dcroxide_wire::NULL_BLOCK_INDEX;
    tx.tx_in.push(stakebase);
    tx.tx_in.push(tx_in(outpoint(ticket, 0, TX_TREE_STAKE)));
    tx.tx_out.push(TxOut {
        value: 0,
        version: 0,
        pk_script: voted_on,
    });
    tx.tx_out.push(TxOut {
        value: 0,
        version: 0,
        pk_script: vec![0x6a, 0x02, 0x01, 0x00],
    });
    tx.tx_out.push(TxOut {
        value: 2_000_000,
        version: 0,
        pk_script: payout,
    });
    assert!(dcroxide_stake::is_ssgen(&tx), "a well-formed vote");
    tx
}

/// dcrd takes `best` once (`mining.go:1200`) and after reorganizing to
/// a sibling moves only `prevHash` (`:1288`).  The sibling's votes then
/// fail the eligibility check against the old tip's winning tickets
/// (`:1722`), the build has no voters, and `handleTooFewVoters`
/// recycles the new tip from a fresh snapshot.  A refreshed snapshot
/// would instead accept the votes and build at the next height.
#[test]
fn a_reorganized_build_keeps_the_old_snapshot_and_recycles_the_new_tip() {
    let parent = Hash([0xb0; 32]);
    let tip_a = Hash([0xa1; 32]);
    let tip_b = Hash([0xb1; 32]);
    let winners_a: Vec<Hash> = (0..5u8).map(|i| Hash([0x10 + i; 32])).collect();
    let winners_b: Vec<Hash> = (0..5u8).map(|i| Hash([0x20 + i; 32])).collect();
    let snapshot = |hash: Hash, winners: &[Hash]| TemplateBest {
        hash,
        prev_hash: parent,
        height: 5000,
        median_time_unix: 1_000_000,
        next_stake_diff: 1,
        next_winning_tickets: winners.to_vec(),
        ..TemplateBest::default()
    };

    let block = |nonce: u32| {
        let mut header = header(5000, parent, nonce);
        header.voters = 5;
        MsgBlock {
            header,
            transactions: Vec::new(),
            stransactions: Vec::new(),
        }
    };
    let mut chain = Chain::new(snapshot(tip_a, &winners_a), block(1));
    chain.blocks.insert(tip_b.0, block(2));
    chain.tip_generation = vec![tip_a, tip_b];
    chain
        .reorg_best
        .insert(tip_b.0, snapshot(tip_b, &winners_b));
    for ticket in &winners_b {
        chain.add_utxo(
            outpoint(*ticket, 0, TX_TREE_STAKE),
            2_000_000,
            4000,
            TxType::SStx,
        );
    }

    // Every vote in the mempool is on B, so B is the only eligible
    // parent.
    let mut source = Source::new();
    for ticket in &winners_b {
        source.add(vote(tip_b, 5000, *ticket), TxType::SSGen, 0);
    }

    let mut g = generator(chain, source);
    let template = build(&mut g);
    assert_eq!(g.chain.reorgs, vec![(tip_a, tip_b)], "reorganized to B");
    assert_eq!(template.height, 5000, "B recycled, not built on");
    assert_eq!(template.block.header.height, 5000);
    assert_eq!(template.block.header.prev_block, parent);
    assert_eq!(template.block.header.nonce, 2, "the recycled block is B");
}
