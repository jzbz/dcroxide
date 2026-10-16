// SPDX-License-Identifier: ISC
//! Round trips of outputs through blocks that disapprove their parent
//! and reinclude a transaction of it, over a database-backed chain whose
//! UTXO cache is flushed and whose node is restarted at chosen points.
//!
//! Each scenario reaches a commit that spends an output the UTXO cache
//! already holds spent.  dcrd leaves such an entry as it is since
//! `9112e4e6` (`internal/blockchain/utxocache.go:340-355` at
//! `382ff4dd`): the view holds a single spend of the output, and
//! double spends are refused when the transactions are validated
//! against the view.  dcrd's comment names the path, which is reached
//! even when every block is flushed: the spend of an output not yet
//! flushed to the backend, undone by a disapproval and spent again in
//! the block that disapproves it.  Since `2115b56b` a spend inside a
//! block bypasses the cache only when the view holds none of its
//! creating transaction's regular outputs when the block's inputs are
//! fetched (`utxoviewpoint.go:1161-1183`), so the spend of a reincluded
//! transaction's output goes through the cache like any other.
//!
//! Every scenario checks that each block is accepted, that an output
//! the chain has spent is absent from the UTXO set afterwards and a
//! later block spending it fails with `ErrMissingTxOut`, and that once
//! the cache is flushed the backend holds no row for it, as dcrd's
//! disapproval scenarios check spendability through the cache
//! (`utxoviewpoint_test.go:259-740`).
//!
//! - Disapproval twice: G confirms T1 and a flush makes G's T1:0 a
//!   backend row; P disapproves G, reincludes T1 and spends T1:0 later
//!   in its regular tree, as dcrd's s4 does (`:443-477`); with no flush
//!   after P, N disapproves P and does the same again.  N's commit
//!   spends T1:0 over P's spent cache entry.
//! - The same chain to P, then N disapproves P with only its coinbase,
//!   and a branch approving P outgrows N, as dcrd's s6 reorganizes to a
//!   branch approving the original parent (`:518-561`).  Detaching N
//!   redoes P's regular tree, T2's spend of T1:0 included, over P's
//!   spent cache entry.
//! - X is a backend row, G confirms T1 spending it, and with no flush
//!   after G, P disapproves G and reincludes T1: the undo of G restores
//!   X in P's view and P's spend of X meets G's spent cache entry, the
//!   path `9112e4e6`'s comment names.  The same commit runs again when
//!   a restart replays G and P.
//!
//! The harness drives the chain through the entry points production
//! uses from the block index onward: `maybe_accept_block_data` stores
//! each block, and `reorganize_chain` connects or detaches it through
//! `UtxoView::connect_block` / `UtxoView::disconnect_block` and
//! `Chain::connect_block` / `Chain::disconnect_block`, which commit the
//! view to the UTXO cache and apply the flush policy.  The only flushes
//! are the explicit ones below (`flush_utxo_cache_for_stats`, the same
//! cache flush the periodic and forced flushes run), and the chain is
//! never current, so no forced flush runs after a connect.
//!
//! The blocks enter the block index already marked validated, as
//! `process_block` marks them for a bulk import and as a reorg finds a
//! branch it validated before, so the connect builds its view with
//! `UtxoView::connect_block` rather than `check_connect_block`.  The two
//! build the same view here: both undo a disapproved parent first and
//! then fetch the block's inputs, which decides its zero-confirmation
//! spends.  Full validation is out of reach for this harness: a block
//! may only disapprove its parent from stake validation height on, with
//! real votes, and before that height `checkBlockHeaderSanity` rejects
//! the vote bits.  The UTXO handling under test depends on neither.

// Test-harness arithmetic over small fixed amounts and heights.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_blockchain::blockindex::BlockStatus;
use dcroxide_blockchain::chaindb::db_fetch_utxo_entry;
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::utxoview::{UtxoView, collect_tx_hashes};
use dcroxide_blockchain::validate::check_transactions_and_connect;
use dcroxide_blockchain::{RuleError, RuleErrorKind, UtxoEntry};
use dcroxide_chaincfg::{Params, regnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_standalone::{SubsidyCache, SubsidySplitVariant, calc_tx_tree_merkle_root};
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint, TxIn, TxOut};
use tempfile::TempDir;

/// The adjusted time every reorganization runs at.  The blocks are
/// timestamped from the regnet genesis, years earlier, so the chain
/// never latches to current and no connect forces a flush.
const NOW: i64 = 2_000_000_000;
/// Every output pays this much to an anyone-can-spend script.
const OUT_VALUE: i64 = 1_000;
const SCRIPT: [u8; 1] = [0x51]; // OP_TRUE

/// An input spending `outpoint`, with fraud proof data naming an output
/// of `value` created at `height` by the transaction at `index` of its
/// block.
fn input(outpoint: OutPoint, value: i64, height: u32, index: u32) -> TxIn {
    TxIn {
        previous_out_point: outpoint,
        sequence: u32::MAX,
        value_in: value,
        block_height: height,
        block_index: index,
        signature_script: Vec::new(),
    }
}

/// A transaction spending `inputs` into one output per value.
fn tx(inputs: Vec<TxIn>, values: &[i64]) -> MsgTx {
    MsgTx {
        tx_in: inputs,
        tx_out: values
            .iter()
            .map(|&value| TxOut {
                value,
                version: 0,
                pk_script: SCRIPT.to_vec(),
            })
            .collect(),
        ..MsgTx::default()
    }
}

fn op(tx: &MsgTx, index: u32) -> OutPoint {
    OutPoint {
        hash: tx.tx_hash(),
        index,
        tree: 0,
    }
}

/// The subsidy a coinbase at `height` commits to in its input (no
/// voters, treasury agenda inactive).
fn subsidy(params: &Params, height: u32) -> i64 {
    let mut cache = SubsidyCache::new(params);
    let height = i64::from(height);
    cache.calc_work_subsidy_v3(height, 0, SubsidySplitVariant::Original)
        + cache.calc_treasury_subsidy(height, 0, false)
}

/// A coinbase at `height` paying `values`, or a single zero output
/// (which never enters the UTXO set) when there are none; `tag` keeps
/// the coinbases of different blocks distinct.
fn coinbase(params: &Params, height: u32, tag: u32, values: &[i64]) -> MsgTx {
    let mut signature_script = vec![0x04];
    signature_script.extend_from_slice(&tag.to_le_bytes());
    let mut cb = tx(
        vec![TxIn {
            previous_out_point: OutPoint {
                hash: Hash::ZERO,
                index: u32::MAX,
                tree: 0,
            },
            sequence: u32::MAX,
            value_in: subsidy(params, height),
            block_height: 0,
            block_index: u32::MAX,
            signature_script,
        }],
        values,
    );
    if cb.tx_out.is_empty() {
        cb.tx_out.push(TxOut {
            value: 0,
            version: 0,
            pk_script: SCRIPT.to_vec(),
        });
    }
    cb
}

/// A node: a chain over a real database it can be restarted from.
struct Node {
    dir: TempDir,
    opts: Options,
    params: Params,
    chain: Chain,
    next_tag: u32,
}

impl Node {
    fn new() -> Node {
        let params = regnet_params();
        let dir = TempDir::new().expect("tempdir");
        let opts = Options::new(dir.path().join("chain"), params.net.0);
        let chain = Chain::open(
            Database::create(&opts).expect("create database"),
            &params,
            Hash::ZERO,
            false,
            0,
        )
        .expect("open chain");
        Node {
            dir,
            opts,
            params,
            chain,
            next_tag: 0,
        }
    }

    fn tip(&self) -> Hash {
        let tip = self.chain.best_chain.tip().expect("best chain tip");
        self.chain.store.node(tip).hash
    }

    /// A block on `parent` that approves it or not, with a coinbase
    /// paying `coinbase_values` followed by `transactions`.
    fn block(
        &mut self,
        parent: Hash,
        approves_parent: bool,
        coinbase_values: &[i64],
        transactions: Vec<MsgTx>,
    ) -> MsgBlock {
        let parent_id = self
            .chain
            .index
            .lookup_node(&parent)
            .expect("parent in the block index");
        let parent_node = self.chain.store.node(parent_id);
        let height = parent_node.height as u32 + 1;
        let timestamp = parent_node.timestamp as u32 + 300;
        self.next_tag += 1;
        let mut regular = vec![coinbase(
            &self.params,
            height,
            self.next_tag,
            coinbase_values,
        )];
        regular.extend(transactions);

        let (mut header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header");
        header.version = 1;
        header.prev_block = parent;
        header.merkle_root = calc_tx_tree_merkle_root(&regular);
        header.stake_root = calc_tx_tree_merkle_root(&[]);
        header.vote_bits = u16::from(approves_parent);
        header.bits = self.params.pow_limit_bits;
        header.sbits = self.params.minimum_stake_diff;
        header.height = height;
        header.timestamp = timestamp;
        let mut block = MsgBlock {
            header,
            transactions: regular,
            stransactions: Vec::new(),
        };
        block.header.size = block.serialize_size() as u32;
        block
    }

    /// Hand the block to the chain as `process_block` does a block it
    /// does not validate again: into the block index marked validated,
    /// its data stored, then a reorganization to the best candidate.
    fn accept(&mut self, block: &MsgBlock) {
        let chain = &mut self.chain;
        let parent = chain
            .index
            .lookup_node(&block.header.prev_block)
            .expect("parent in the block index");
        let node = chain.store.new_node(&block.header, Some(parent));
        chain.index.add_node(&chain.store, node);
        chain
            .index
            .set_status_flags(&mut chain.store, node, BlockStatus::VALIDATED);
        chain
            .maybe_accept_block_data(node, block, true, &self.params)
            .expect("block data accepted");
        let target = chain.index.find_best_chain_candidate(&chain.store);
        let errs = chain.reorganize_chain(target, NOW, &self.params);
        assert!(
            errs.is_empty(),
            "block at height {} was not accepted: {errs:?}",
            block.header.height
        );
    }

    /// [`Self::accept`] a block that must become the tip.
    fn accept_tip(&mut self, block: &MsgBlock) {
        self.accept(block);
        assert_eq!(
            self.tip(),
            block.header.block_hash(),
            "block at height {} is the tip",
            block.header.height
        );
    }

    /// Flush the UTXO cache to the backend at the tip.
    fn utxo_flush(&mut self) {
        self.chain
            .flush_utxo_cache_for_stats()
            .expect("utxo cache flush");
    }

    /// Stop the node as in a crash and open it again from its database:
    /// the UTXO cache is lost, and the open replays the blocks after the
    /// last flush.
    fn restart(self) -> Node {
        let Node {
            dir,
            opts,
            params,
            chain,
            next_tag,
        } = self;
        let db = chain.db.clone().expect("database-backed chain");
        db.flush().expect("database flush");
        drop(chain);
        db.close().expect("close database");
        drop(db);
        let chain = Chain::open(
            Database::open(&opts).expect("reopen database"),
            &params,
            Hash::ZERO,
            false,
            0,
        )
        .expect("reopen chain");
        Node {
            dir,
            opts,
            params,
            chain,
            next_tag,
        }
    }

    /// The backend's row for `outpoint`, read around the cache.
    fn backend_row(&self, outpoint: &OutPoint) -> Option<UtxoEntry> {
        let db = self.chain.db.as_ref().expect("database-backed chain");
        let mut row = None;
        db.view(|tx| {
            row = db_fetch_utxo_entry(tx, outpoint).expect("utxo set row");
            Ok(())
        })
        .expect("read the utxo set");
        row
    }

    /// The entry for `outpoint` when the UTXO set holds it unspent.
    fn unspent(&self, outpoint: &OutPoint) -> Option<UtxoEntry> {
        self.chain
            .fetch_utxo_entry(outpoint)
            .filter(|entry| !entry.is_spent())
    }

    /// Run the input checks of a block on the tip whose regular tree
    /// is `[coinbase, spend]` against the chain's UTXO set.
    fn check_spend(&mut self, spend: MsgTx) -> Result<(), RuleError> {
        let tip = self.tip();
        let block = self.block(tip, true, &[], vec![spend]);
        let prev_id = self.chain.index.lookup_node(&tip).expect("tip node");
        let prev_header = self.chain.store.header(prev_id);
        let hashes = collect_tx_hashes(&block.transactions);
        let mut view = UtxoView::new();
        let resolver = |outpoint: &OutPoint| self.chain.fetch_utxo_entry(outpoint);
        view.fetch_input_utxos(&block, &hashes, &resolver, false);
        let mut subsidy_cache = SubsidyCache::new(&self.params);
        let mut stxos = Vec::new();
        check_transactions_and_connect(
            &mut subsidy_cache,
            0,
            i64::from(block.header.height),
            block.header.block_hash(),
            0,
            &prev_header,
            &block.transactions,
            &hashes,
            &mut view,
            Some(&mut stxos),
            false,
            false,
            false,
            SubsidySplitVariant::Original,
            &self.params,
        )
        .map(|_| ())
    }

    /// `outpoint` is spent: the UTXO set does not hold it, and a block
    /// spending it fails for want of it.
    fn assert_spent(&mut self, outpoint: &OutPoint, height: u32, index: u32, what: &str) {
        if let Some(entry) = self.unspent(outpoint) {
            panic!(
                "{what} was spent, but the utxo set holds it unspent (height {}, index {})",
                entry.block_height(),
                entry.block_index()
            );
        }
        let spend = tx(vec![input(*outpoint, OUT_VALUE, height, index)], &[1]);
        let err = self
            .check_spend(spend)
            .expect_err("a spent output is not spendable");
        assert_eq!(
            err.kind,
            RuleErrorKind::MissingTxOut,
            "a spend of {what}: {err:?}"
        );
    }

    /// [`Self::assert_spent`], and after a flush the backend holds no
    /// row for `outpoint` and a spend of it still fails.
    fn assert_gone(&mut self, outpoint: &OutPoint, height: u32, index: u32, what: &str) {
        self.assert_spent(outpoint, height, index, what);
        self.utxo_flush();
        if let Some(row) = self.backend_row(outpoint) {
            panic!(
                "{what} was spent, but after a flush the backend still holds its row \
                 (height {}, index {})",
                row.block_height(),
                row.block_index()
            );
        }
        self.assert_spent(outpoint, height, index, what);
    }
}

/// The funding every scenario starts from: F pays X from its coinbase,
/// enough blocks follow for X to mature, and a flush leaves X a backend
/// row, as on a node partway through its initial sync.  Returns X and
/// F's height.
fn fund(node: &mut Node) -> (OutPoint, u32) {
    let genesis = node.tip();
    let f = node.block(genesis, true, &[5 * OUT_VALUE], Vec::new());
    node.accept_tip(&f);
    for _ in 0..node.params.coinbase_maturity {
        let tip = node.tip();
        let filler = node.block(tip, true, &[], Vec::new());
        node.accept_tip(&filler);
    }
    node.utxo_flush();
    let x = op(&f.transactions[0], 0);
    assert!(node.backend_row(&x).is_some(), "X was flushed");
    (x, f.header.height)
}

/// The chain to P: G confirms T1, which spends X into T1:0 and T1:1, a
/// flush makes G's T1:0 a backend row, and P disapproves G, reincludes
/// T1 and spends T1:0 later in its regular tree with T2.  Returns T1,
/// T2, X and the heights of G and P.  Nothing flushes after P.
fn through_p(node: &mut Node) -> (MsgTx, MsgTx, OutPoint, u32, u32) {
    let (x, x_height) = fund(node);

    // G = [cbG, T1].
    let t1 = tx(
        vec![input(x, 5 * OUT_VALUE, x_height, 0)],
        &[OUT_VALUE, OUT_VALUE],
    );
    let tip = node.tip();
    let g = node.block(tip, true, &[], vec![t1.clone()]);
    node.accept_tip(&g);
    let g_height = g.header.height;

    // The flush after G.
    node.utxo_flush();
    assert!(
        node.backend_row(&op(&t1, 0)).is_some(),
        "G's T1:0 was flushed"
    );

    // P = [cbP, T1, T2] disapproves G; T2 spends T1:0.
    let p_height = g_height + 1;
    let t2 = tx(
        vec![input(op(&t1, 0), OUT_VALUE, p_height, 1)],
        &[OUT_VALUE],
    );
    let p = node.block(
        g.header.block_hash(),
        false,
        &[],
        vec![t1.clone(), t2.clone()],
    );
    node.accept_tip(&p);
    (t1, t2, x, g_height, p_height)
}

/// N disapproves P, reincludes T1 and spends T1:0 in its own regular
/// tree, as P did.
#[test]
fn a_second_disapproval_spends_the_reincluded_output_in_block_again() {
    let mut node = Node::new();
    let (t1, t2, x, g_height, p_height) = through_p(&mut node);

    // N = [cbN, T1, T2'] disapproves P; T2' spends T1:0, with fraud
    // proof data naming N.
    let n_height = p_height + 1;
    let t2_again = tx(
        vec![input(op(&t1, 0), OUT_VALUE, n_height, 1)],
        &[OUT_VALUE - 1],
    );
    let tip = node.tip();
    let n = node.block(tip, false, &[], vec![t1.clone(), t2_again.clone()]);
    node.accept_tip(&n);

    let t1_out1 = node.unspent(&op(&t1, 1)).expect("N re-created T1:1");
    assert_eq!(
        t1_out1.block_height(),
        i64::from(n_height),
        "N's copy of T1:1"
    );
    assert!(node.unspent(&op(&t2_again, 0)).is_some(), "N created T2':0");
    assert!(
        node.unspent(&op(&t2, 0)).is_none(),
        "P's T2:0 left with P's regular tree"
    );
    assert!(node.unspent(&x).is_none(), "N's T1 spent X");
    node.assert_gone(&op(&t1, 0), g_height, 1, "T1:0");
}

/// N disapproves P and holds only its coinbase, and a competing branch
/// on P that approves it then outgrows N.  Detaching N redoes P's
/// regular tree, T2's spend of T1:0 included.
#[test]
fn detaching_a_block_that_disapproved_an_in_block_spend_redoes_it() {
    let mut node = Node::new();
    let (t1, t2, x, g_height, p_height) = through_p(&mut node);
    let p = node.tip();

    // N = [cbN] disapproves P, which undoes P's regular tree.
    let n = node.block(p, false, &[], Vec::new());
    node.accept_tip(&n);
    assert!(node.unspent(&x).is_some(), "N undid P's spend of X");
    assert!(node.unspent(&op(&t1, 0)).is_none(), "N undid T1:0");
    assert!(node.unspent(&op(&t1, 1)).is_none(), "N undid T1:1");
    assert!(node.unspent(&op(&t2, 0)).is_none(), "N undid T2:0");

    // C1 approves P and C2 extends it: the reorganization to C2 detaches
    // N with no flush since P.
    let c1 = node.block(p, true, &[], Vec::new());
    node.accept(&c1);
    let c2 = node.block(c1.header.block_hash(), true, &[], Vec::new());
    node.accept_tip(&c2);

    // P's regular tree stands again: T1 spent X and T2 spent T1:0.
    let t1_out1 = node.unspent(&op(&t1, 1)).expect("P's T1:1 is back");
    assert_eq!(
        t1_out1.block_height(),
        i64::from(p_height),
        "P's copy of T1:1"
    );
    assert!(node.unspent(&op(&t2, 0)).is_some(), "P's T2:0 is back");
    assert!(node.unspent(&x).is_none(), "P's T1 spent X");
    node.assert_gone(&op(&t1, 0), g_height, 1, "T1:0");
}

/// G confirms T1, which spends the backend row X, and with no flush
/// after G, P disapproves G and reincludes T1, spending X in the block
/// that disapproves G.  P's commit spends X over G's spent cache entry
/// and leaves it as it is, on the first connect and when a restart
/// replays G and P.
#[test]
fn a_disapproval_reincluding_a_transaction_spends_its_input_again() {
    let mut node = Node::new();
    let (x, x_height) = fund(&mut node);

    // G = [cbG, T1]; T1 spends X.  No flush follows.
    let t1 = tx(
        vec![input(x, 5 * OUT_VALUE, x_height, 0)],
        &[OUT_VALUE, OUT_VALUE],
    );
    let tip = node.tip();
    let g = node.block(tip, true, &[], vec![t1.clone()]);
    node.accept_tip(&g);

    // P = [cbP, T1] disapproves G and reincludes T1.
    let p = node.block(g.header.block_hash(), false, &[], vec![t1.clone()]);
    node.accept_tip(&p);
    let p_height = p.header.height;
    let check = |node: &mut Node| {
        for index in 0..2 {
            let entry = node
                .unspent(&op(&t1, index))
                .unwrap_or_else(|| panic!("P created T1:{index}"));
            assert_eq!(
                entry.block_height(),
                i64::from(p_height),
                "P's copy of T1:{index}"
            );
        }
    };
    check(&mut node);
    node.assert_spent(&x, x_height, 0, "X");

    // A crash loses the cache: the restart replays G and P from the
    // flush before G.
    let mut node = node.restart();
    assert_eq!(
        node.tip(),
        p.header.block_hash(),
        "P is the tip after the restart"
    );
    check(&mut node);
    node.assert_gone(&x, x_height, 0, "X");
}
