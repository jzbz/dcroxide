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
//! block in exactly three ways:
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
//!
//! Nothing is keyed by a block hash and nothing is stored.  The slot is
//! empty outside `Chain::process_block`, and an event holds the hashes
//! of its own block only.  So a block read back from the database is a
//! new allocation and is hashed again, and so is every other block a
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

#[cfg(test)]
std::thread_local! {
    /// How many times this thread hashed a block into a `BlockTxHashes`
    /// (the re-hash `is_for` does under debug assertions is not counted).
    /// It exists in this crate's unit-test builds only, where the tests
    /// read it to tell how often one processing call hashed its block.
    pub(crate) static BLOCKS_HASHED: core::cell::Cell<u64> =
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
    /// under the wrong transaction.
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
            *self == Self::compute(block),
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

    /// The regression network's genesis block: one regular transaction
    /// and an empty stake tree.
    fn one_transaction_block() -> MsgBlock {
        dcroxide_chaincfg::regnet_params().genesis_block.clone()
    }

    /// A block of the same shape as [`one_transaction_block`] whose
    /// transaction is another one.
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
