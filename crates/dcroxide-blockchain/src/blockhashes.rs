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
//! merkle roots are built from.  `BlockMerkleRoots` holds the roots of
//! the two trees once they have been built from those leaves, for a
//! block that was hashed before it reached the chain.
//!
//! # The rule
//!
//! A value of any of these types can only be made by hashing a block,
//! and it is only ever used with that same block instance.  Hashes meet
//! a block in exactly four ways:
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
//! That rule is about the hashes.  A [`HashedBlock`] may carry one thing
//! more, and that one is stored: the block's record for the block files,
//! made from the bytes the block was decoded from
//! ([`HashedBlock::keep_wire_bytes`]).  It is kept only once those bytes
//! have been compared with the block's serialization, in every build, so
//! it holds the bytes the chain writes for that block when it has no
//! record, and it reaches the chain in the one value that owns the
//! block.  A record is never looked up by a block hash either.
//!
//! Every function that reads the hashes first checks them against its
//! block with `assert_for`: one hash per transaction of each tree in
//! every build, and a full re-hash and comparison under debug
//! assertions.  The length check is not optional: the connect helpers
//! walk the transactions and the hashes together, and a short list
//! would skip transactions silently.  The two roots have no length to
//! check.  They are only ever read beside the leaves they were built
//! from, out of the one [`HashedBlock`] that owns both, and under debug
//! assertions they are compared with roots built from those leaves
//! again.
//!
//! # The block hash
//!
//! The hash of a block's header follows the same rule on a shorter
//! path.  dcrd's `dcrutil.Block` computes it as the block is wrapped
//! and hands it out from then on (`dcrutil/block.go:92-94`,
//! `:288-293`); `dcroxide_wire::MsgBlock` caches nothing.  A processing
//! call takes the hash once, out of the [`HashedBlock`] the block
//! arrived in or by hashing the header where the call starts, and hands
//! it down lexically to the steps that are lent that same block: the
//! record of a proven merkle commitment, the acceptance of the data and
//! the store.  It is filed in the slot beside the transaction hashes,
//! and two later steps read it from there by allocation identity, as the
//! connect reads the transaction hashes: the contextual checks made as
//! the block being processed is accepted, and the filter lookup made as
//! it is attached when it needs no full validation.  No block's hash is
//! taken from the key it is held under in the `blocks` mirror, which is
//! a public map that promises nothing about its keys, or from an index
//! entry.  So every other block is hashed where its hash is needed, the
//! parent that the reorganization's attach loop is handed among them:
//! that loop hashes its header to check that it is the parent, once for
//! each block it attaches.  The view that connects a block attached
//! without full validation is handed no hash either, and hashes the
//! block's header for the best hash it records.  Under debug assertions
//! every function that is handed a header's hash hashes the header again
//! and compares.
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
//! A tree that the chain hands to its script pool is held to more: in
//! every build each of its items has its transaction and its hash
//! compared by address with the block's and the hashes' own at the
//! item's position (`validate::ScriptRunner`).

use alloc::sync::Arc;
use alloc::vec::Vec;

use dcroxide_chainhash::{HASH_SIZE, Hash, hash_h};
use dcroxide_database::BlockRecord;
use dcroxide_standalone::calc_merkle_root;
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

/// The roots of one block's two transaction merkle trees, each built
/// from the block's [`BlockMerkleLeaves`]: what dcrd's
/// `CalcTxTreeMerkleRoot` returns for the regular and for the stake
/// transactions (`blockchain/standalone/merkle.go:112-127`).
///
/// They are the two roots `checkMerkleRoots` builds
/// (`validate.go:1909-1952`).  For the original commitment it builds the
/// stake tree only once the regular root has matched the header, and
/// for DCP0005 it builds both before it compares anything; a
/// [`HashedBlock`] holds both whichever commitment applies.  Holding
/// them decides nothing: which header field a root must equal, and
/// whether the two are first combined into one as DCP0005 specifies,
/// depends on the header commitments agenda, which the chain alone
/// answers.
///
/// The fields are private and [`BlockMerkleRoots::compute`] is the only
/// constructor, so a value is always the pair of roots of some block's
/// leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BlockMerkleRoots {
    /// The root of the tree over the regular transactions' full hashes.
    regular: Hash,
    /// The root of the tree over the stake transactions' full hashes.
    stake: Hash,
}

/// A block together with its block hash, the hashes of its transactions,
/// its merkle leaves and the roots of its two transaction merkle trees,
/// all computed from that block: what dcrd holds in one `dcrutil.Block`,
/// whose transactions carry their hashes (`dcrutil/block.go:162-224`)
/// and whose block hash is computed as the block is wrapped (`NewBlock`,
/// `dcrutil/block.go:288-293`).  dcrd caches no merkle root: it builds
/// both trees inside `checkMerkleRoots`.
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
/// root is compared with the header, and the chain makes every check it
/// makes of a block that arrives without hashes, in the same order
/// (`Chain::process_hashed_block`).
///
/// A block that was decoded from bytes may also carry those bytes, laid
/// out as its record for the block files ([`HashedBlock::keep_wire_bytes`]):
/// what dcrd holds as the `serializedBlock` of a `dcrutil.Block` made by
/// `NewBlockFromBlockAndBytes` (`dcrutil/block.go:54-58`, `:386-392`),
/// which is what its `StoreBlock` writes.  The record is kept only when
/// the bytes compare equal to the block's serialization, so a chain that
/// stores it stores the bytes it would have serialized.
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
    /// The roots of the two trees over `merkle_leaves`.
    merkle_roots: BlockMerkleRoots,
    /// The bytes the block was decoded from, laid out as its block-file
    /// record, when they were handed in and are the block's
    /// serialization ([`HashedBlock::keep_wire_bytes`]).
    record: Option<Arc<BlockRecord>>,
}

impl HashedBlock {
    /// Hash the block: its header, each transaction once for both the
    /// transaction hash and the merkle leaf, and the inner nodes of the
    /// two transaction merkle trees.
    ///
    /// The trees are the smaller part of that work, whatever the block
    /// holds.  A tree of `n` leaves has at most
    /// `n - 1 + ceil(log2(n))` inner nodes
    /// (`dcroxide_standalone::calc_merkle_root`: each level hashes half
    /// the nodes of the one below, rounded up), and each is one hash of
    /// 64 bytes, two BLAKE-256 compressions.  A leaf is one such hash
    /// too, made after a hash of the transaction's prefix and one of its
    /// witness data, so the leaves of a tree take at least `4 * n`
    /// compressions, and two serializations of each transaction, where
    /// its inner nodes take at most `2 * (n - 1 + ceil(log2(n)))`
    /// compressions: fewer for every `n`, and about half as many for a
    /// tree of the smallest transactions a block can be filled with.  So
    /// the trees can never double what this function spends on a block,
    /// and what it spends stays linear in the size of the block as it
    /// was received.  The number of leaves is bounded where the block
    /// was decoded: a block off the wire holds at most
    /// `dcroxide_wire::max_tx_per_tx_tree` transactions in each tree
    /// (dcrd `MsgBlock.BtcDecode`, `wire/msgblock.go:101-131`), whatever
    /// its size.  Each tree is built in a copy of its leaves that is
    /// freed before this returns.
    pub fn new(block: Arc<MsgBlock>) -> HashedBlock {
        let (tx_hashes, merkle_leaves) = BlockTxHashes::compute_with_merkle_leaves(&block);
        let merkle_roots = BlockMerkleRoots::compute(&merkle_leaves);
        let hash = block.header.block_hash();
        HashedBlock {
            block,
            hash,
            tx_hashes: Arc::new(tx_hashes),
            merkle_leaves,
            merkle_roots,
            record: None,
        }
    }

    /// Keep the bytes the block was decoded from, `buf[block_at..]`, as
    /// its record for the block files, laid out in that buffer for
    /// `network` ([`BlockRecord::lay_out`], which needs
    /// [`BlockRecord::PREFIX_LEN`] bytes ahead of the block and takes the
    /// record's checksum).  Says whether the record was kept; when it was
    /// not, the buffer is dropped and the value is as it was, so the
    /// chain serializes the block when it stores it, as it does for a
    /// block that arrives without one.
    ///
    /// The record is kept only when the bytes are the block's
    /// serialization, which is found by comparing them with it
    /// (`MsgBlock::serialize`, the bytes `Transaction::store_block`
    /// stores) in every build.  So the bytes a chain stores for a block
    /// are the same whether or not the block arrived with a record,
    /// whatever was handed in here: another block's bytes, a longer
    /// encoding of this one, or its bytes with more behind them, are
    /// dropped.  The comparison serializes the block once, on the calling
    /// thread, and lets go of that copy before the record is laid out.
    /// That is the price of the stored bytes resting on a comparison and
    /// not on an argument about the decoder, and it is paid away from the
    /// thread that stores the block.
    ///
    /// For the bytes a block was decoded from, with none left over, the
    /// comparison is expected to hold every time.  The decoder reads
    /// every fixed-width field of a block bit for bit into the field
    /// `MsgBlock::serialize` writes it back from, a transaction's
    /// serialization type included, and copies every script.  That
    /// leaves the counts and lengths, the only fields with more than one
    /// encoding, and the decoder refuses a variable length integer
    /// written longer than it need be (`dcroxide_wire::read_var_int`,
    /// dcrd `ReadVarInt`).  Bytes that are dropped therefore mean a
    /// caller that paired a block with bytes it was not decoded from, or
    /// a decoder that no longer reads a field back as it is written;
    /// neither is a reason to store anything but the serialization.
    ///
    /// Bytes that are kept begin with the block's own header, so the
    /// hash the record took of its header ([`BlockRecord::hash`]) is the
    /// hash of the block's, which is the one hash a store files the
    /// record under (`Transaction::store_block_record`).  The hash this
    /// value carries is not consulted.
    ///
    /// Nothing is decided about the block by this: bytes that are not
    /// kept are not a fault of the block's, and the chain treats a block
    /// with a record exactly as one without.
    pub fn keep_wire_bytes(&mut self, buf: Vec<u8>, block_at: usize, network: u32) -> bool {
        let is_serialization = {
            let serialized = self.block.serialize();
            buf.get(block_at..) == Some(serialized.as_slice())
        };
        if !is_serialization {
            return false;
        }
        let Some(record) = BlockRecord::lay_out(buf, block_at, network) else {
            return false;
        };
        self.record = Some(Arc::new(record));
        true
    }

    /// The block's record for the block files, when the bytes it was
    /// decoded from were kept ([`Self::keep_wire_bytes`]): the block's
    /// serialization with the record's network, length and checksum
    /// around it.
    pub fn record(&self) -> Option<&Arc<BlockRecord>> {
        self.record.as_ref()
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

    /// The roots of the block's transaction merkle trees, built from
    /// [`Self::merkle_leaves`].
    pub(crate) fn merkle_roots(&self) -> &BlockMerkleRoots {
        &self.merkle_roots
    }

    /// Give the block back, dropping the hashes and the record.
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

    /// How many transaction merkle trees this thread built from a
    /// block's leaves ([`BlockMerkleLeaves::regular_root`] and
    /// [`BlockMerkleLeaves::stake_root`]).  The trees
    /// `BlockMerkleRoots::assert_for` builds again under debug
    /// assertions are not counted, and neither is the tree of two leaves
    /// that combines the roots under DCP0005.  It exists in this crate's
    /// unit-test builds only, where the tests read it to tell that a
    /// processing call that was handed a block's roots built no tree.
    pub(crate) static TREES_BUILT: core::cell::Cell<u64> =
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

    /// The root of the regular transaction tree, built here (dcrd
    /// `CalcTxTreeMerkleRoot` over `block.Transactions`).
    pub(crate) fn regular_root(&self) -> Hash {
        #[cfg(test)]
        TREES_BUILT.set(TREES_BUILT.get().wrapping_add(1));
        calc_merkle_root(&self.regular)
    }

    /// The root of the stake transaction tree, built here (dcrd
    /// `CalcTxTreeMerkleRoot` over `block.STransactions`).
    pub(crate) fn stake_root(&self) -> Hash {
        #[cfg(test)]
        TREES_BUILT.set(TREES_BUILT.get().wrapping_add(1));
        calc_merkle_root(&self.stake)
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

impl BlockMerkleRoots {
    /// Build both trees from the block's leaves.
    pub(crate) fn compute(leaves: &BlockMerkleLeaves) -> BlockMerkleRoots {
        BlockMerkleRoots {
            regular: leaves.regular_root(),
            stake: leaves.stake_root(),
        }
    }

    /// The root of the regular transaction tree.
    pub(crate) fn regular(&self) -> Hash {
        self.regular
    }

    /// The root of the stake transaction tree.
    pub(crate) fn stake(&self) -> Hash {
        self.stake
    }

    /// Panic, under debug assertions, unless these are the roots of the
    /// trees over the given leaves.  A release build has nothing to
    /// check here: the pairing rests on both having been read out of the
    /// one [`HashedBlock`] that built these from those.
    #[track_caller]
    pub(crate) fn assert_for(&self, leaves: &BlockMerkleLeaves) {
        debug_assert!(
            self.regular == calc_merkle_root(leaves.regular())
                && self.stake == calc_merkle_root(leaves.stake()),
            "merkle roots do not match the block's merkle leaves"
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
    use crate::agendas::AgendaActiveInfo;
    use crate::validate::{
        MerkleRootVariant, check_block_data_preconditions_with_leaves,
        check_block_data_sanity_with_hashes, check_merkle_roots_with_leaves,
    };
    use crate::{RuleError, RuleErrorKind};

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
                let got = check_merkle_roots_with_leaves(block, &leaves, None, variant);
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
    /// transactions, counted like the chain's own, and builds each of
    /// its two merkle trees once.
    #[test]
    fn hashing_a_block_ahead_is_one_pass() {
        let block = Arc::new(one_transaction_block());
        let before = BLOCKS_HASHED.get();
        let trees_before = TREES_BUILT.get();
        let hashed = HashedBlock::new(block);
        assert_eq!(BLOCKS_HASHED.get().wrapping_sub(before), 1);
        assert_eq!(TREES_BUILT.get().wrapping_sub(trees_before), 2);
        // Reading it back hashes nothing.
        let _ = (
            hashed.hash(),
            hashed.tx_hashes(),
            hashed.merkle_leaves(),
            hashed.merkle_roots(),
        );
        assert_eq!(BLOCKS_HASHED.get().wrapping_sub(before), 1);
        assert_eq!(TREES_BUILT.get().wrapping_sub(trees_before), 2);
    }

    /// The root of the tree over the leaves by a walk of its own, one
    /// level at a time with the last node of an odd level paired with
    /// itself (dcrd `CalcMerkleRootInPlace`,
    /// `blockchain/standalone/merkle.go:55-70`), and how many nodes it
    /// hashed on the way.
    fn root_and_inner_nodes(leaves: &[Hash]) -> (Hash, usize) {
        let mut level = leaves.to_vec();
        let mut inner_nodes = 0;
        while level.len() > 1 {
            level = level
                .chunks(2)
                .map(|pair| {
                    let mut both = [0u8; 2 * HASH_SIZE];
                    both[..HASH_SIZE].copy_from_slice(&pair[0].0);
                    both[HASH_SIZE..].copy_from_slice(&pair[pair.len() - 1].0);
                    hash_h(&both)
                })
                .collect();
            inner_nodes += level.len();
        }
        (level.first().copied().unwrap_or(Hash::ZERO), inner_nodes)
    }

    /// How many nodes a tree of that many leaves has above them: each
    /// level has half the nodes of the one below, rounded up.
    fn inner_nodes_of(leaves: usize) -> usize {
        let (mut nodes, mut inner_nodes) = (leaves, 0);
        while nodes > 1 {
            nodes = nodes.div_ceil(2);
            inner_nodes += nodes;
        }
        inner_nodes
    }

    /// The least number of levels that halve `leaves` nodes to one,
    /// `ceil(log2(leaves))`.
    fn ceil_log2(leaves: usize) -> usize {
        leaves.next_power_of_two().trailing_zeros() as usize
    }

    /// The block whose trees cost the most is hashed within the bound
    /// [`HashedBlock::new`] states.  The block decoder allows each tree
    /// `max_tx_per_tx_tree` transactions and accepts a transaction of
    /// five bytes, one that carries only witness data and has no inputs,
    /// so both trees are full in a block a third the size of the largest
    /// payload, and the rest of that size can add no leaf.  Each tree of
    /// that block has no more inner nodes than `n - 1 + ceil(log2(n))`,
    /// each two compressions where a leaf takes four or more, and
    /// [`HashedBlock::new`] builds each tree once.
    #[test]
    fn the_trees_of_the_fullest_block_stay_within_the_stated_bound() {
        use dcroxide_wire::{
            MAX_BLOCK_PAYLOAD, Message, PROTOCOL_VERSION, TxSerializeType, decode_message_payload,
            max_tx_per_tx_tree,
        };

        let smallest = MsgTx {
            ser_type: TxSerializeType::OnlyWitness,
            ..MsgTx::default()
        };
        assert_eq!(smallest.serialize().len(), 5);
        let cap = usize::try_from(max_tx_per_tx_tree(PROTOCOL_VERSION)).expect("cap");
        assert_eq!(cap, 43_691);
        let mut block = one_transaction_block();
        block.transactions = vec![smallest.clone(); cap];
        block.stransactions = vec![smallest.clone(); cap];

        // The decoder takes the block as a peer would send it, and
        // refuses one transaction more in either tree.
        let decode = |block: &MsgBlock| {
            decode_message_payload("block", &block.serialize(), PROTOCOL_VERSION)
        };
        let payload_len = block.serialize().len();
        assert_eq!(payload_len, 437_096);
        assert!(payload_len * 2 < MAX_BLOCK_PAYLOAD as usize);
        let Ok(Message::Block(decoded)) = decode(&block) else {
            panic!("a block of two full trees decodes");
        };
        assert_eq!(decoded, block);
        for regular in [true, false] {
            let mut over = block.clone();
            if regular {
                over.transactions.push(smallest.clone());
            } else {
                over.stransactions.push(smallest.clone());
            }
            assert!(decode(&over).is_err(), "regular: {regular}");
        }

        let trees_before = TREES_BUILT.get();
        let hashed = HashedBlock::new(Arc::new(decoded));
        assert_eq!(TREES_BUILT.get().wrapping_sub(trees_before), 2);
        assert_eq!(
            *hashed.merkle_roots(),
            BlockMerkleRoots {
                regular: calc_tx_tree_merkle_root(&block.transactions),
                stake: calc_tx_tree_merkle_root(&block.stransactions),
            }
        );

        for (leaves, root) in [
            (
                hashed.merkle_leaves().regular(),
                hashed.merkle_roots().regular(),
            ),
            (
                hashed.merkle_leaves().stake(),
                hashed.merkle_roots().stake(),
            ),
        ] {
            let n = leaves.len();
            assert_eq!(n, cap);
            // The root is that of the tree the walk hashes node by node.
            let (walked_root, inner_nodes) = root_and_inner_nodes(leaves);
            assert_eq!(root, walked_root);
            assert_eq!(inner_nodes, 43_698);
            assert!(inner_nodes <= n - 1 + ceil_log2(n));
            // Two compressions a node against four or more a leaf.
            assert!(2 * inner_nodes < 4 * n);
        }
    }

    /// The bound on a tree's inner nodes holds for every number of
    /// leaves up to the decoder's limit and past it, and the count it
    /// bounds is the number of nodes a walk of the tree hashes.
    #[test]
    fn a_tree_has_no_more_inner_nodes_than_the_stated_bound() {
        assert_eq!((inner_nodes_of(0), inner_nodes_of(1)), (0, 0));
        for n in 1usize..=100_000 {
            let inner_nodes = inner_nodes_of(n);
            assert!(inner_nodes <= n - 1 + ceil_log2(n), "{n}: {inner_nodes}");
            assert!(inner_nodes < 2 * n, "{n}: {inner_nodes}");
        }
        for n in 0u8..=64 {
            let leaves: Vec<Hash> = (0..n).map(|i| Hash([i; HASH_SIZE])).collect();
            let (root, inner_nodes) = root_and_inner_nodes(&leaves);
            assert_eq!(root, calc_merkle_root(&leaves), "{n} leaves");
            assert_eq!(inner_nodes, inner_nodes_of(leaves.len()), "{n} leaves");
        }
    }

    /// The tree with its last nodes repeated at the first level that has
    /// an odd number of them, which has the root of the tree without the
    /// repeats: a level of odd length is hashed with its last node
    /// paired with itself.  `None` for a tree with no such level, one of
    /// a power of two leaves or of none.
    fn with_repeated_tail(txs: &[MsgTx]) -> Option<Vec<MsgTx>> {
        let (mut nodes, mut width) = (txs.len(), 1);
        while nodes > 0 && nodes % 2 == 0 {
            nodes /= 2;
            width *= 2;
        }
        (nodes >= 3).then(|| {
            let mut repeated = txs.to_vec();
            repeated.extend_from_slice(&txs[txs.len() - width..]);
            repeated
        })
    }

    /// Blocks made from one block that fail, or may fail, the checks
    /// that read its hashes, by shape: a tree that no longer has the
    /// root the header names, a tree padded with repeats that still has
    /// it, in a block of the size its header names, and trees with
    /// nothing in them.  The header is the block's own unless the shape
    /// says otherwise.
    fn bad_shapes(block: &MsgBlock) -> Vec<(&'static str, MsgBlock)> {
        let mut shapes = Vec::new();
        let mut add = |shape: &'static str, make: &dyn Fn(&mut MsgBlock) -> bool| {
            let mut altered = block.clone();
            if make(&mut altered) {
                shapes.push((shape, altered));
            }
        };
        let alter_last = |txs: &mut Vec<MsgTx>| match txs.last_mut() {
            Some(tx) => {
                tx.lock_time ^= 1;
                true
            }
            None => false,
        };
        let size_of = |block: &MsgBlock| block.serialize_size() as u32;

        add("another regular tree", &|b| alter_last(&mut b.transactions));
        add("another stake tree", &|b| alter_last(&mut b.stransactions));
        add("a stake tree where there was none", &|b| {
            let had_none = b.stransactions.is_empty();
            b.stransactions.extend(b.transactions.first().cloned());
            had_none && !b.stransactions.is_empty()
        });
        add("both trees are others", &|b| {
            alter_last(&mut b.transactions) && alter_last(&mut b.stransactions)
        });
        // A tree with repeats keeps its root, so the header still names
        // it; the header names the size of the block with the repeats.
        add(
            "a regular tree with repeats",
            &|b| match with_repeated_tail(&b.transactions) {
                Some(repeated) => {
                    b.transactions = repeated;
                    b.header.size = size_of(b);
                    true
                }
                None => false,
            },
        );
        add(
            "a stake tree with repeats",
            &|b| match with_repeated_tail(&b.stransactions) {
                Some(repeated) => {
                    b.stransactions = repeated;
                    b.header.size = size_of(b);
                    true
                }
                None => false,
            },
        );
        add("no transactions", &|b| {
            b.transactions.clear();
            b.stransactions.clear();
            true
        });
        add("no regular transactions", &|b| {
            b.transactions.clear();
            true
        });
        // A header that commits to two empty trees, each way a header
        // can.
        add("no transactions, as the header says", &|b| {
            b.transactions.clear();
            b.stransactions.clear();
            b.header.merkle_root = Hash::ZERO;
            b.header.stake_root = Hash::ZERO;
            b.header.fresh_stake = 0;
            b.header.size = size_of(b);
            true
        });
        add("no transactions, as the combined root says", &|b| {
            b.transactions.clear();
            b.stransactions.clear();
            b.header.merkle_root = calc_merkle_root(&[Hash::ZERO, Hash::ZERO]);
            b.header.fresh_stake = 0;
            b.header.size = size_of(b);
            true
        });
        shapes
    }

    /// What the checks that read a block's merkle data and transaction
    /// hashes report, made in the order `Chain::process_block` makes
    /// them: the preconditions with the answer the agenda query gave,
    /// then the sanity checks.  `Ok` carries whether the data commitment
    /// was proven.
    fn first_failure(
        block: &MsgBlock,
        tx_hashes: &BlockTxHashes,
        leaves: &BlockMerkleLeaves,
        roots: Option<&BlockMerkleRoots>,
        agenda: &Result<AgendaActiveInfo, RuleError>,
        params: &dcroxide_chaincfg::Params,
    ) -> Result<bool, (RuleErrorKind, String)> {
        let failure = |err: RuleError| (err.kind, err.description);
        let proven =
            check_block_data_preconditions_with_leaves(block, leaves, roots, || agenda.clone())
                .map_err(failure)?;
        check_block_data_sanity_with_hashes(block, tx_hashes, params).map_err(failure)?;
        Ok(proven)
    }

    /// What decides how many trees the checks build for a block they
    /// are not handed the roots of, worked out on the standalone
    /// functions that hash the transactions themselves.
    struct TreesBuilt {
        /// Whether the block is within the wire protocol's size limit.
        size_passes: bool,
        /// Whether the regular tree has the root in the header's merkle
        /// root field.
        regular_matches: bool,
        /// Whether the block fails the original commitment.
        original_fails: bool,
    }

    impl TreesBuilt {
        fn of(block: &MsgBlock) -> TreesBuilt {
            let size = i64::try_from(block.serialize_size()).expect("size");
            TreesBuilt {
                size_passes: crate::validate::check_block_size_sanity(size).is_ok(),
                regular_matches: calc_tx_tree_merkle_root(&block.transactions)
                    == block.header.merkle_root,
                original_fails: reference_merkle_failure(block, MerkleRootVariant::Original)
                    .is_some(),
            }
        }

        /// How many of the block's two transaction trees the merkle
        /// check builds, which is how many dcrd's `checkMerkleRoots`
        /// builds (`validate.go:1909-1952`): for the original commitment
        /// the stake tree only once the regular root has matched the
        /// header, for DCP0005 both.
        fn by_the_merkle_check(&self, variant: MerkleRootVariant) -> u64 {
            match variant {
                MerkleRootVariant::Original if !self.regular_matches => 1,
                MerkleRootVariant::Original | MerkleRootVariant::Dcp0005 => 2,
            }
        }

        /// The same count for the preconditions, by the answer the
        /// agenda query gave (dcrd `checkBlockDataPreconditions`,
        /// `validate.go:1954-2049`): no tree when the size check or the
        /// query fails first, the trees of the selected commitment when
        /// the agenda is decided, and otherwise those of the original
        /// commitment and, when that one fails, both trees again for
        /// DCP0005.
        fn by_the_preconditions(&self, agenda: &Result<AgendaActiveInfo, RuleError>) -> u64 {
            match agenda {
                _ if !self.size_passes => 0,
                Err(_) => 0,
                Ok(info) if info.is_valid => self.by_the_merkle_check(if info.is_active {
                    MerkleRootVariant::Dcp0005
                } else {
                    MerkleRootVariant::Original
                }),
                Ok(_) => {
                    let original = self.by_the_merkle_check(MerkleRootVariant::Original);
                    if self.original_fails {
                        original + 2
                    } else {
                        original
                    }
                }
            }
        }
    }

    /// A block that arrives with the roots of its merkle trees gets the
    /// verdict of the same block without them, with the same text, from
    /// the same check: for every block of the battery and for every bad
    /// shape made from it, under each answer the header commitments
    /// agenda query can give.  The side without roots builds each tree
    /// where dcrd builds it and no other, so a block whose regular root
    /// fails the original commitment has no stake tree built; the side
    /// with roots builds none.
    #[test]
    fn carried_merkle_roots_give_the_verdicts_of_roots_built_by_the_check() {
        let params = dcroxide_chaincfg::regnet_params();
        let agendas = [
            Ok(AgendaActiveInfo {
                is_valid: true,
                is_active: false,
            }),
            Ok(AgendaActiveInfo {
                is_valid: true,
                is_active: true,
            }),
            Ok(AgendaActiveInfo::default()),
            Err(crate::ruleerror::rule_error(
                RuleErrorKind::UnknownAgendaID,
                "no such agenda",
            )),
        ];

        let mut seen: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
        let mut repeats_keep_the_root = 0usize;
        for (name, block) in fixture_blocks() {
            let mut cases = vec![("the block", block.clone())];
            cases.extend(bad_shapes(&block));
            for (shape, case) in cases {
                let hashed = HashedBlock::new(Arc::new(case.clone()));
                let (tx_hashes, leaves) = BlockTxHashes::compute_with_merkle_leaves(&case);
                assert_eq!(
                    *hashed.merkle_roots(),
                    BlockMerkleRoots {
                        regular: calc_tx_tree_merkle_root(&case.transactions),
                        stake: calc_tx_tree_merkle_root(&case.stransactions),
                    },
                    "{name}, {shape}"
                );
                hashed.merkle_roots().assert_for(hashed.merkle_leaves());
                let trees_built = TreesBuilt::of(&case);
                if shape.contains("with repeats") {
                    // The shape is what it says: other transactions,
                    // the same two roots.
                    assert_ne!(case.serialize_size(), block.serialize_size());
                    assert_eq!(
                        *hashed.merkle_roots(),
                        BlockMerkleRoots::compute(&BlockMerkleLeaves::compute(&block)),
                        "{name}, {shape}"
                    );
                    repeats_keep_the_root += 1;
                }

                // The merkle check alone, against the check that hashes
                // the transactions for itself.
                for variant in [MerkleRootVariant::Original, MerkleRootVariant::Dcp0005] {
                    let before = TREES_BUILT.get();
                    let with_roots = check_merkle_roots_with_leaves(
                        hashed.block(),
                        hashed.merkle_leaves(),
                        Some(hashed.merkle_roots()),
                        variant,
                    );
                    assert_eq!(
                        TREES_BUILT.get(),
                        before,
                        "{name}, {shape}, {variant:?}: a tree was built beside the roots"
                    );
                    let without = check_merkle_roots_with_leaves(&case, &leaves, None, variant);
                    assert_eq!(
                        TREES_BUILT.get().wrapping_sub(before),
                        trees_built.by_the_merkle_check(variant),
                        "{name}, {shape}, {variant:?}: the trees built without roots"
                    );
                    assert_eq!(with_roots, without, "{name}, {shape}, {variant:?}");
                    assert_eq!(
                        with_roots.err().map(|err| (err.kind, err.description)),
                        reference_merkle_failure(&case, variant)
                            .map(|text| (RuleErrorKind::BadMerkleRoot, text)),
                        "{name}, {shape}, {variant:?}"
                    );
                }

                // The checks in the order the chain makes them.
                for agenda in &agendas {
                    let before = TREES_BUILT.get();
                    let with_roots = first_failure(
                        hashed.block(),
                        hashed.tx_hashes(),
                        hashed.merkle_leaves(),
                        Some(hashed.merkle_roots()),
                        agenda,
                        &params,
                    );
                    assert_eq!(
                        TREES_BUILT.get(),
                        before,
                        "{name}, {shape}, {agenda:?}: a tree was built beside the roots"
                    );
                    let without = first_failure(&case, &tx_hashes, &leaves, None, agenda, &params);
                    assert_eq!(
                        TREES_BUILT.get().wrapping_sub(before),
                        trees_built.by_the_preconditions(agenda),
                        "{name}, {shape}, {agenda:?}: the trees built without roots"
                    );
                    assert_eq!(with_roots, without, "{name}, {shape}, {agenda:?}");

                    let verdict = match &with_roots {
                        Ok(proven) => format!("ok, proven: {proven}"),
                        Err((RuleErrorKind::BadMerkleRoot, text)) => {
                            let which = text.split(" is invalid").next().expect("text");
                            format!("ErrBadMerkleRoot, {which}")
                        }
                        Err((kind, _)) => kind.kind_name().to_string(),
                    };
                    *seen.entry(format!("{shape}: {verdict}")).or_default() += 1;
                }
            }
        }

        assert!(
            repeats_keep_the_root >= 100,
            "{repeats_keep_the_root} trees with repeats"
        );
        // Every shape reached the check it was made for, on both sides.
        for verdict in [
            "the block: ok, proven: true",
            "the block: ok, proven: false",
            "the block: ErrUnknownAgendaID",
            "another regular tree: ErrBadMerkleRoot, block merkle root",
            "another stake tree: ErrBadMerkleRoot, block stake merkle root",
            "another stake tree: ErrBadMerkleRoot, block merkle root",
            "a stake tree where there was none: ErrBadMerkleRoot, block stake merkle root",
            "both trees are others: ErrBadMerkleRoot, block merkle root",
            "a regular tree with repeats: ErrDuplicateTx",
            "a stake tree with repeats: ErrDuplicateTx",
            "no transactions: ErrBadMerkleRoot, block merkle root",
            "no regular transactions: ErrBadMerkleRoot, block merkle root",
            "no transactions, as the header says: ErrNoTransactions",
            "no transactions, as the combined root says: ErrNoTransactions",
        ] {
            assert!(
                seen.get(verdict).is_some_and(|&count| count > 0),
                "nothing gave {verdict:?}: {seen:#?}"
            );
        }
        // With both trees wrong, the original variant names the regular
        // root, which it compares first, and never the stake root.
        assert!(
            !seen.contains_key("both trees are others: ErrBadMerkleRoot, block stake merkle root"),
            "{seen:#?}"
        );
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
            None,
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
            crate::validate::ScriptRunner::Scoped(None),
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
