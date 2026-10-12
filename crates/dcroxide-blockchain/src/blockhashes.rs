// SPDX-License-Identifier: ISC
//! The transaction hashes of one block, computed once and handed to
//! every step of block processing that needs them.
//!
//! dcrd wraps a block in a `dcrutil.Block`, whose `Transactions` and
//! `STransactions` wrap each transaction in a `dcrutil.Tx`
//! (`dcrutil/block.go:162-224`), and `dcrutil.NewTx` hashes the
//! transaction once and keeps the result (`dcrutil/tx.go:94-101`).  The
//! duplicate check, the connect and the daemon's observers therefore
//! all read one hash per transaction.  `dcroxide_wire::MsgTx` caches
//! nothing, so [`BlockTxHashes`] is the side structure that stands in
//! for that cache, and `BlockMerkleLeaves` holds the full hashes the
//! merkle roots are built from.
//!
//! # The rule
//!
//! A value of either type can only be made by hashing a block, and it
//! is only ever used with that same block instance.  Hashes meet a
//! block in exactly four ways:
//!
//! 1. Lexically, in the function that computed them from that
//!    `&MsgBlock`: `Chain::process_block`, and the public functions
//!    that keep dcrd's shapes and hash their own `block` argument.
//! 2. Through the chain's slot for the block being processed, matched
//!    by allocation identity: `Arc::ptr_eq` on the `blocks` mirror's own
//!    `Arc` of the block, which the slot keeps alive so that its address
//!    cannot be reused.  Never by block hash or height.
//! 3. On the connected-block event, where `Chain::connect_block` sends
//!    the block and its hashes together.
//! 4. In a [`HashedBlock`], which owns the `Arc` of the block it hashed
//!    and can be made in no other way.  A block may be hashed into one
//!    before it reaches the chain, on another thread
//!    (`Chain::process_hashed_block`); the chain then reads the block
//!    and its hashes out of that one value, and the block it keeps in
//!    the `blocks` mirror is that same `Arc`.
//!
//! Nothing is keyed by a block hash and nothing is stored.  The slot is
//! empty outside a processing call, and an event holds the hashes of its
//! own block only.  So a block read back from the database is a new
//! allocation and is hashed again, and so is every other block a
//! reorganization attaches, a side-chain block connected later, a block
//! linked by a later block's data, the startup catch-up, an invalidate
//! or reconsider, the template checks and every disconnect.  A mutated
//! block that shares a header hash with a good one can never pick up
//! the good one's hashes.
//!
//! Every function that reads the hashes first checks them against its
//! block with `assert_for`: one hash per transaction of each tree in
//! every build, and a full re-hash and comparison under debug
//! assertions.  The length check is not optional: the connect helpers
//! walk the transactions and the hashes together, and a short list
//! would skip transactions silently.
//!
//! # The script check reads them too
//!
//! The block script check of the connect checks
//! (`validate::check_block_scripts_with_hashes`) hands each hash to the
//! script engines of its transaction, where it stands in for the prefix
//! hash of every `SigHashAll` signature hash
//! (`dcroxide_txscript::Engine::set_tx_hash`).  dcrd's script check
//! reads no cached hash: it carries that path switched off
//! (`txscript/opcode.go:27-32`).  So the rule above is what those
//! signature hashes rest on, as the keys of the block's new outputs do.
//! Under debug assertions each engine also compares the hash it is
//! handed with its transaction's.  A release build checks only that
//! there is one hash per transaction: there an engine handed another
//! transaction's hash would check its `SigHashAll` signatures as though
//! its own transaction had that prefix, rejecting the transaction's own
//! and passing one made for the other transaction at the same input.

use alloc::sync::Arc;
use alloc::vec::Vec;

use dcroxide_chainhash::{HASH_SIZE, Hash, hash_h};
use dcroxide_wire::{MsgBlock, MsgTx};

/// The hash of every transaction of one block
/// (`dcroxide_wire::MsgTx::tx_hash`), per tree and in block order: what
/// dcrd reads from the `dcrutil.Tx` wrappers of a `dcrutil.Block`.
///
/// The fields are private and the only constructors hash a block, so a
/// value is always the true hash list of some block; see the module
/// documentation for the rule that keeps it with that block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockTxHashes {
    /// The hash of `block.transactions[i]`.
    regular: Vec<Hash>,
    /// The hash of `block.stransactions[i]`.
    stake: Vec<Hash>,
}

/// The full hash of every transaction of one block
/// (`dcroxide_wire::MsgTx::tx_hash_full`), per tree and in block order:
/// the leaves of the two transaction merkle trees (dcrd
/// `CalcTxTreeMerkleRoot`, `blockchain/standalone/merkle.go:112-127`).
///
/// A separate type from [`BlockTxHashes`], so that a full hash cannot be
/// passed where a transaction hash is wanted, or the reverse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BlockMerkleLeaves {
    /// The full hash of `block.transactions[i]`.
    regular: Vec<Hash>,
    /// The full hash of `block.stransactions[i]`.
    stake: Vec<Hash>,
}

/// A block together with its block hash, the hashes of its transactions
/// and its merkle leaves, all computed from that block: what dcrd holds
/// in one `dcrutil.Block`, whose transactions carry their hashes
/// (`dcrutil/block.go:162-224`) and whose block hash is computed as the
/// block is wrapped (`NewBlock`, `dcrutil/block.go:288-293`).
///
/// The fields are private and [`HashedBlock::new`] is the only
/// constructor, so the hashes are always those of the block the value
/// owns.  `MsgBlock` has no interior mutability and the block is only
/// ever lent out behind its `Arc`, so it cannot change after it was
/// hashed.  The type is not `Clone`: a second value would have to hash
/// again, and there is no reason for one.
///
/// It exists so that the hashing can be done before the block reaches
/// the chain, away from the thread that connects blocks.  Making one
/// reaches no verdict about the block: nothing is checked, no merkle
/// root is compared, and the chain makes every check it makes of a block
/// that arrives without hashes, in the same order
/// (`Chain::process_hashed_block`).
#[derive(Debug)]
pub struct HashedBlock {
    /// The block.
    block: Arc<MsgBlock>,
    /// The hash of the block's header.
    hash: Hash,
    /// The hash of each of the block's transactions.
    tx_hashes: Arc<BlockTxHashes>,
    /// The full hash of each of the block's transactions.
    merkle_leaves: BlockMerkleLeaves,
}

impl HashedBlock {
    /// Hash the block: its header, and each transaction once for both
    /// the transaction hash and the merkle leaf.
    pub fn new(block: Arc<MsgBlock>) -> HashedBlock {
        let (tx_hashes, merkle_leaves) = BlockTxHashes::compute_with_merkle_leaves(&block);
        let hash = block.header.block_hash();
        HashedBlock {
            block,
            hash,
            tx_hashes: Arc::new(tx_hashes),
            merkle_leaves,
        }
    }

    /// The block that was hashed.
    pub fn block(&self) -> &Arc<MsgBlock> {
        &self.block
    }

    /// The hash of the block's header (dcrd `Block.Hash`).
    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    /// The hash of each of the block's transactions.
    pub fn tx_hashes(&self) -> &Arc<BlockTxHashes> {
        &self.tx_hashes
    }

    /// The leaves of the block's transaction merkle trees.
    pub(crate) fn merkle_leaves(&self) -> &BlockMerkleLeaves {
        &self.merkle_leaves
    }

    /// Give the block back, dropping the hashes.
    pub fn into_block(self) -> Arc<MsgBlock> {
        self.block
    }
}

#[cfg(test)]
std::thread_local! {
    /// How many times this thread hashed a block into a `BlockTxHashes`
    /// (the re-hash `is_for` does under debug assertions is not counted).
    /// It exists in this crate's unit-test builds only, where the tests
    /// read it to tell how often one processing call hashed its block.
    pub(crate) static BLOCKS_HASHED: core::cell::Cell<u64> =
        const { core::cell::Cell::new(0) };

    /// How many times this thread built a block's `BlockMerkleLeaves`
    /// in a pass of their own (`BlockMerkleLeaves::compute`).  The
    /// re-hash `assert_for` does under debug assertions is not counted,
    /// and neither is the pass that builds the leaves together with the
    /// transaction hashes, which `BLOCKS_HASHED` counts.  It exists in
    /// this crate's unit-test builds only, where the tests read it to
    /// tell that a processing call that was handed a block's leaves did
    /// not build them again.
    pub(crate) static LEAVES_HASHED: core::cell::Cell<u64> =
        const { core::cell::Cell::new(0) };
}

/// The hash of each transaction, in order.
fn prefix_hashes(txs: &[MsgTx]) -> Vec<Hash> {
    txs.iter().map(MsgTx::tx_hash).collect()
}

/// The hash and the full hash of each transaction, in order.  The full
/// hash is `MsgTx::tx_hash_full`'s -- the hash of the transaction hash
/// followed by the witness hash -- built from the transaction hash in
/// hand, so that the prefix is serialized and hashed once.
fn prefix_and_full_hashes(txs: &[MsgTx]) -> (Vec<Hash>, Vec<Hash>) {
    let mut prefix = Vec::with_capacity(txs.len());
    let mut full = Vec::with_capacity(txs.len());
    let mut buf = [0u8; 2 * HASH_SIZE];
    for tx in txs {
        let tx_hash = tx.tx_hash();
        buf[..HASH_SIZE].copy_from_slice(tx_hash.as_bytes());
        buf[HASH_SIZE..].copy_from_slice(tx.tx_hash_witness().as_bytes());
        prefix.push(tx_hash);
        full.push(hash_h(&buf));
    }
    (prefix, full)
}

impl BlockTxHashes {
    /// Hash every transaction of the block.
    pub fn compute(block: &MsgBlock) -> BlockTxHashes {
        #[cfg(test)]
        BLOCKS_HASHED.set(BLOCKS_HASHED.get().wrapping_add(1));
        BlockTxHashes {
            regular: prefix_hashes(&block.transactions),
            stake: prefix_hashes(&block.stransactions),
        }
    }

    /// Hash every transaction of the block and build the merkle leaves
    /// from the same pass: one transaction hash and one witness hash per
    /// transaction, and the full hash from the two.
    pub(crate) fn compute_with_merkle_leaves(
        block: &MsgBlock,
    ) -> (BlockTxHashes, BlockMerkleLeaves) {
        #[cfg(test)]
        BLOCKS_HASHED.set(BLOCKS_HASHED.get().wrapping_add(1));
        let (regular, regular_full) = prefix_and_full_hashes(&block.transactions);
        let (stake, stake_full) = prefix_and_full_hashes(&block.stransactions);
        (
            BlockTxHashes { regular, stake },
            BlockMerkleLeaves {
                regular: regular_full,
                stake: stake_full,
            },
        )
    }

    /// The hashes of the block's regular transactions, in block order.
    pub fn regular(&self) -> &[Hash] {
        &self.regular
    }

    /// The hashes of the block's stake transactions, in block order.
    pub fn stake(&self) -> &[Hash] {
        &self.stake
    }

    /// Whether there is exactly one hash per transaction of each of the
    /// block's trees.
    pub fn fits(&self, block: &MsgBlock) -> bool {
        self.regular.len() == block.transactions.len()
            && self.stake.len() == block.stransactions.len()
    }

    /// Whether these are the hashes of the block's transactions, by
    /// hashing them again.
    pub fn is_for(&self, block: &MsgBlock) -> bool {
        self.regular == prefix_hashes(&block.transactions)
            && self.stake == prefix_hashes(&block.stransactions)
    }

    /// Panic unless these hashes belong to the block: [`Self::fits`] in
    /// every build, and [`Self::is_for`] under debug assertions.
    ///
    /// Every consumer of the hashes calls this first.  A failure is a
    /// pairing fault inside the node, and continuing would file outputs
    /// under the wrong transaction and check signatures against another
    /// transaction's hash.
    #[track_caller]
    pub fn assert_for(&self, block: &MsgBlock) {
        assert!(
            self.fits(block),
            "transaction hashes are not one per transaction of the block"
        );
        debug_assert!(
            self.is_for(block),
            "transaction hashes do not match the block's transactions"
        );
    }
}

impl BlockMerkleLeaves {
    /// The full hash of every transaction of the block, each computed
    /// by `MsgTx::tx_hash_full`.
    pub(crate) fn compute(block: &MsgBlock) -> BlockMerkleLeaves {
        #[cfg(test)]
        LEAVES_HASHED.set(LEAVES_HASHED.get().wrapping_add(1));
        Self::hash_block(block)
    }

    /// What [`Self::compute`] computes, without the unit tests' count of
    /// its calls: the comparison [`Self::assert_for`] makes under debug
    /// assertions is not a pass any caller asked for.
    fn hash_block(block: &MsgBlock) -> BlockMerkleLeaves {
        BlockMerkleLeaves {
            regular: block.transactions.iter().map(MsgTx::tx_hash_full).collect(),
            stake: block
                .stransactions
                .iter()
                .map(MsgTx::tx_hash_full)
                .collect(),
        }
    }

    /// The leaves of the regular transaction tree, in block order.
    pub(crate) fn regular(&self) -> &[Hash] {
        &self.regular
    }

    /// The leaves of the stake transaction tree, in block order.
    pub(crate) fn stake(&self) -> &[Hash] {
        &self.stake
    }

    /// Panic unless these leaves belong to the block: one per
    /// transaction of each tree in every build, and equal to freshly
    /// computed ones under debug assertions.
    #[track_caller]
    pub(crate) fn assert_for(&self, block: &MsgBlock) {
        assert!(
            self.regular.len() == block.transactions.len()
                && self.stake.len() == block.stransactions.len(),
            "merkle leaves are not one per transaction of the block"
        );
        debug_assert!(
            *self == Self::hash_block(block),
            "merkle leaves do not match the block's transactions"
        );
    }
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic over small fixed values"
)]
mod tests {
    use std::collections::BTreeSet;

    use dcroxide_standalone::{
        calc_combined_tx_tree_merkle_root, calc_merkle_root, calc_tx_tree_merkle_root,
    };

    use super::*;
    use crate::RuleErrorKind;
    use crate::validate::{
        MerkleRootVariant, check_block_data_sanity_with_hashes, check_merkle_roots_with_leaves,
    };

    /// Every block of dcrd's full block battery, valid or not, by row
    /// name (the one row that does not decode is not a block).
    fn fixture_blocks() -> Vec<(String, MsgBlock)> {
        let mut blocks = Vec::new();
        for line in include_str!("../tests/data/fullblock_vectors.txt").lines() {
            let f: Vec<&str> = line.split(' ').collect();
            let hex = match f[0] {
                "accept" => f[4],
                "reject" => f[3],
                "orphanorreject" => f[2],
                _ => continue,
            };
            let (block, _) = MsgBlock::from_bytes(&dcroxide_testutil::unhex(hex)).expect("block");
            blocks.push((f[1].to_string(), block));
        }
        blocks
    }

    /// The description `check_merkle_roots` fails with, or `None` when
    /// the header commits to the trees: the check as it was before it
    /// took leaves, on the standalone functions that hash the
    /// transactions themselves.
    fn reference_merkle_failure(block: &MsgBlock, variant: MerkleRootVariant) -> Option<String> {
        let header = &block.header;
        match variant {
            MerkleRootVariant::Original => {
                let want = calc_tx_tree_merkle_root(&block.transactions);
                if header.merkle_root != want {
                    return Some(format!(
                        "block merkle root is invalid - block header indicates {}, but \
                         calculated value is {want}",
                        header.merkle_root
                    ));
                }
                let want_stake = calc_tx_tree_merkle_root(&block.stransactions);
                if header.stake_root != want_stake {
                    return Some(format!(
                        "block stake merkle root is invalid - block header indicates {}, but \
                         calculated value is {want_stake}",
                        header.stake_root
                    ));
                }
                None
            }
            MerkleRootVariant::Dcp0005 => {
                let want =
                    calc_combined_tx_tree_merkle_root(&block.transactions, &block.stransactions);
                (header.merkle_root != want).then(|| {
                    format!(
                        "block merkle root is invalid - block header indicates {}, but \
                         calculated value is {want}",
                        header.merkle_root
                    )
                })
            }
        }
    }

    /// The first transaction hash the block repeats, by the loop the
    /// duplicate check ran before it took hashes: every transaction
    /// hashed here, the regular tree and then the stake tree.
    fn reference_duplicate(block: &MsgBlock) -> Option<Hash> {
        let mut seen = BTreeSet::new();
        block
            .transactions
            .iter()
            .chain(&block.stransactions)
            .map(MsgTx::tx_hash)
            .find(|hash| !seen.insert(hash.0))
    }

    /// The hashes handed down the fast path are the ones the slow path
    /// computes, for every block of the battery, and the checks that
    /// read them reach the verdicts the checks that hashed for
    /// themselves reached.  The slow side of every comparison is code
    /// the hash-once change did not touch: `MsgTx::tx_hash`,
    /// `MsgTx::tx_hash_full` and the standalone merkle functions.
    #[test]
    fn cached_hashes_equal_fresh_hashing_for_every_fixture_block() {
        let params = dcroxide_chaincfg::regnet_params();
        let blocks = fixture_blocks();
        assert_eq!(blocks.len(), 561, "the battery's blocks");

        let (mut merkle_ok, mut merkle_bad) = (0usize, 0usize);
        let mut duplicates = Vec::new();
        for (name, block) in &blocks {
            // One pass gives what two separate passes give.
            let hashes = BlockTxHashes::compute(block);
            let (hashes_too, leaves) = BlockTxHashes::compute_with_merkle_leaves(block);
            assert_eq!(hashes, hashes_too, "{name}");
            assert_eq!(leaves, BlockMerkleLeaves::compute(block), "{name}");
            assert!(hashes.fits(block) && hashes.is_for(block), "{name}");

            // Each list is the per-transaction function over its tree,
            // in order.
            let fresh = |txs: &[MsgTx]| txs.iter().map(MsgTx::tx_hash).collect::<Vec<_>>();
            let full = |txs: &[MsgTx]| txs.iter().map(MsgTx::tx_hash_full).collect::<Vec<_>>();
            assert_eq!(hashes.regular(), fresh(&block.transactions), "{name}");
            assert_eq!(hashes.stake(), fresh(&block.stransactions), "{name}");
            assert_eq!(leaves.regular(), full(&block.transactions), "{name}");
            assert_eq!(leaves.stake(), full(&block.stransactions), "{name}");

            // The roots built from the leaves are the standalone
            // functions' roots, the combined one included.
            let regular_root = calc_merkle_root(leaves.regular());
            let stake_root = calc_merkle_root(leaves.stake());
            assert_eq!(
                regular_root,
                calc_tx_tree_merkle_root(&block.transactions),
                "{name}"
            );
            assert_eq!(
                stake_root,
                calc_tx_tree_merkle_root(&block.stransactions),
                "{name}"
            );
            assert_eq!(
                calc_merkle_root(&[regular_root, stake_root]),
                calc_combined_tx_tree_merkle_root(&block.transactions, &block.stransactions),
                "{name}"
            );

            // The merkle check on the leaves: the same verdict and the
            // same text as the check that hashed the transactions.
            for variant in [MerkleRootVariant::Original, MerkleRootVariant::Dcp0005] {
                let got = check_merkle_roots_with_leaves(block, &leaves, variant);
                match reference_merkle_failure(block, variant) {
                    None => {
                        assert!(got.is_ok(), "{name} {variant:?}: {got:?}");
                        merkle_ok += 1;
                    }
                    Some(description) => {
                        let err = got.expect_err("the reference check fails");
                        assert_eq!(err.kind, RuleErrorKind::BadMerkleRoot, "{name} {variant:?}");
                        assert_eq!(err.description, description, "{name} {variant:?}");
                        merkle_bad += 1;
                    }
                }
            }

            // The duplicate check on the hashes.  Other sanity checks
            // run before it, so a block with a duplicate may fail one of
            // those instead; what must hold is that a reported duplicate
            // is the reference loop's, and that a block that passes has
            // none.
            let repeated = reference_duplicate(block);
            match check_block_data_sanity_with_hashes(block, &hashes, &params) {
                Ok(()) => assert_eq!(repeated, None, "{name}: a duplicate went unnoticed"),
                Err(err) if err.kind == RuleErrorKind::DuplicateTx => {
                    let hash = repeated.expect("a duplicate the reference loop finds too");
                    assert_eq!(
                        err.description,
                        format!("block contains duplicate transaction {hash}"),
                        "{name}"
                    );
                    duplicates.push(name.as_str());
                }
                Err(_) => {}
            }
        }
        assert!(merkle_ok > 0 && merkle_bad > 0, "{merkle_ok} {merkle_bad}");
        assert!(
            duplicates.contains(&"bmf14"),
            "bmf14 repeats a transaction: {duplicates:?}"
        );
    }

    /// A hashed block carries the hashes of the block it owns, for every
    /// block of the battery: the transaction hashes and merkle leaves
    /// the chain computes for itself, and the header's hash.  The block
    /// it owns is the allocation it was given, untouched.
    #[test]
    fn a_hashed_block_carries_the_hashes_of_its_own_block() {
        let blocks = fixture_blocks();
        assert_eq!(blocks.len(), 561, "the battery's blocks");
        for (name, block) in blocks {
            let shared = Arc::new(block.clone());
            let hashed = HashedBlock::new(Arc::clone(&shared));

            assert!(Arc::ptr_eq(hashed.block(), &shared), "{name}");
            assert_eq!(**hashed.block(), block, "{name}");
            assert_eq!(*hashed.hash(), block.header.block_hash(), "{name}");
            assert_eq!(
                **hashed.tx_hashes(),
                BlockTxHashes::compute(&block),
                "{name}"
            );
            assert_eq!(
                *hashed.merkle_leaves(),
                BlockMerkleLeaves::compute(&block),
                "{name}"
            );
            // The checks every consumer makes of a pair pass.
            hashed.tx_hashes().assert_for(hashed.block());
            hashed.merkle_leaves().assert_for(hashed.block());

            // Giving the block back gives that same allocation.
            assert!(Arc::ptr_eq(&hashed.into_block(), &shared), "{name}");
        }
    }

    /// Hashing a block into a [`HashedBlock`] is one pass over its
    /// transactions, counted like the chain's own.
    #[test]
    fn hashing_a_block_ahead_is_one_pass() {
        let block = Arc::new(one_transaction_block());
        let before = BLOCKS_HASHED.get();
        let hashed = HashedBlock::new(block);
        assert_eq!(BLOCKS_HASHED.get().wrapping_sub(before), 1);
        // Reading it back hashes nothing.
        let _ = (hashed.hash(), hashed.tx_hashes(), hashed.merkle_leaves());
        assert_eq!(BLOCKS_HASHED.get().wrapping_sub(before), 1);
    }

    /// The regression network's genesis block: one regular transaction
    /// and an empty stake tree.
    fn one_transaction_block() -> MsgBlock {
        dcroxide_chaincfg::regnet_params().genesis_block.clone()
    }

    /// A block of the same shape as [`one_transaction_block`] whose
    /// transaction is another one.
    #[cfg(debug_assertions)]
    fn another_block_of_the_same_shape() -> MsgBlock {
        let mut block = one_transaction_block();
        block.transactions[0].lock_time ^= 1;
        block
    }

    /// A block with one more stake transaction than
    /// [`one_transaction_block`].
    fn a_block_of_another_shape() -> MsgBlock {
        let mut block = one_transaction_block();
        let tx = block.transactions[0].clone();
        block.stransactions.push(tx);
        block
    }

    /// A block with one more regular transaction than
    /// [`one_transaction_block`], and the same stake tree.
    fn a_block_with_another_regular_tree() -> MsgBlock {
        let mut block = one_transaction_block();
        let tx = block.transactions[0].clone();
        block.transactions.push(tx);
        block
    }

    /// The length check reads both trees: a block with one more regular
    /// transaction does not fit, and neither does one with one more
    /// stake transaction.
    #[test]
    fn fits_counts_both_trees() {
        let hashes = BlockTxHashes::compute(&one_transaction_block());
        assert!(hashes.fits(&one_transaction_block()));
        assert!(!hashes.fits(&a_block_with_another_regular_tree()));
        assert!(!hashes.fits(&a_block_of_another_shape()));
    }

    #[test]
    #[should_panic(expected = "merkle leaves are not one per transaction")]
    fn merkle_leaves_assert_for_refuses_another_regular_tree() {
        BlockMerkleLeaves::compute(&one_transaction_block())
            .assert_for(&a_block_with_another_regular_tree());
    }

    // Each consumer of the hashes refuses a pair that does not belong
    // together, with `assert_for`'s own message: a helper's assertion
    // further down, or any other panic, does not satisfy these.

    #[test]
    #[should_panic(expected = "transaction hashes are not one per transaction")]
    fn the_duplicate_check_refuses_hashes_of_another_shape() {
        let hashes = BlockTxHashes::compute(&one_transaction_block());
        let _ = check_block_data_sanity_with_hashes(
            &a_block_of_another_shape(),
            &hashes,
            &dcroxide_chaincfg::regnet_params(),
        );
    }

    #[test]
    #[should_panic(expected = "merkle leaves are not one per transaction")]
    fn the_merkle_check_refuses_leaves_of_another_shape() {
        let leaves = BlockMerkleLeaves::compute(&one_transaction_block());
        let _ = check_merkle_roots_with_leaves(
            &a_block_of_another_shape(),
            &leaves,
            MerkleRootVariant::Original,
        );
    }

    #[test]
    #[should_panic(expected = "transaction hashes are not one per transaction")]
    fn the_view_connect_refuses_hashes_of_another_shape() {
        let hashes = BlockTxHashes::compute(&one_transaction_block());
        let _ = crate::utxoview::UtxoView::new().connect_block_with_hashes(
            &a_block_of_another_shape(),
            &hashes,
            &one_transaction_block(),
            || Ok(Vec::new()),
            &|_: &dcroxide_wire::OutPoint| -> Option<crate::utxoentry::UtxoEntry> { None },
            None,
            false,
        );
    }

    // The script check reads nothing of this block (its one input is a
    // coinbase's), so the count of the hashes is all that can refuse it.
    #[test]
    #[should_panic(expected = "transaction hashes are not one per transaction")]
    fn the_script_check_refuses_hashes_of_another_shape() {
        let hashes = BlockTxHashes::compute(&a_block_of_another_shape());
        let _ = crate::validate::check_block_scripts_with_hashes(
            &one_transaction_block(),
            &hashes,
            &crate::utxoview::UtxoView::new(),
            true,
            dcroxide_txscript::ScriptFlags(0),
            None,
            true,
        );
    }

    #[test]
    fn assert_for_accepts_the_block_the_hashes_came_from() {
        let block = one_transaction_block();
        let (hashes, leaves) = BlockTxHashes::compute_with_merkle_leaves(&block);
        hashes.assert_for(&block);
        leaves.assert_for(&block);
        // A field-for-field copy is the same block as far as the hashes
        // go: this is the copy the chain's mirror holds.
        hashes.assert_for(&block.clone());
        leaves.assert_for(&block.clone());
    }

    #[test]
    #[should_panic(expected = "one per transaction")]
    fn assert_for_refuses_another_shape() {
        let hashes = BlockTxHashes::compute(&one_transaction_block());
        hashes.assert_for(&a_block_of_another_shape());
    }

    #[test]
    #[should_panic(expected = "one per transaction")]
    fn merkle_leaves_assert_for_refuses_another_shape() {
        let leaves = BlockMerkleLeaves::compute(&one_transaction_block());
        leaves.assert_for(&a_block_of_another_shape());
    }

    /// The content check is a debug assertion: a release build checks
    /// the lengths only.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "do not match")]
    fn assert_for_refuses_another_block_of_the_same_shape() {
        let other = another_block_of_the_same_shape();
        let hashes = BlockTxHashes::compute(&one_transaction_block());
        assert!(hashes.fits(&other) && !hashes.is_for(&other));
        hashes.assert_for(&other);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "do not match")]
    fn merkle_leaves_assert_for_refuses_another_block_of_the_same_shape() {
        let leaves = BlockMerkleLeaves::compute(&one_transaction_block());
        leaves.assert_for(&another_block_of_the_same_shape());
    }

    #[test]
    fn an_empty_stake_tree_has_no_leaves_and_a_zero_root() {
        let block = one_transaction_block();
        assert!(block.stransactions.is_empty());
        let (hashes, leaves) = BlockTxHashes::compute_with_merkle_leaves(&block);
        assert!(hashes.stake().is_empty());
        assert!(leaves.stake().is_empty());
        assert_eq!(calc_merkle_root(leaves.stake()), Hash::ZERO);
        assert_eq!(calc_tx_tree_merkle_root(&block.stransactions), Hash::ZERO);
    }
}
