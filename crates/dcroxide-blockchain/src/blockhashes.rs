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
//! block that was hashed before it reached the chain, and
//! `BlockSigOps` holds that block's counts of signature operations
//! (see the section on them).  `DataSanityVerdict` holds the verdict
//! of such a block's data sanity checks, where they were made before it
//! reached the chain (see the last section).
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
//! That rule is about the hashes.  A [`HashedBlock`] may carry two
//! things more.  One is stored: the block's record for the block files,
//! made from the bytes the block was decoded from
//! ([`HashedBlock::keep_wire_bytes`]).  It is kept only once those bytes
//! have been compared with the block's serialization, in every build, so
//! it holds the bytes the chain writes for that block when it has no
//! record, and it reaches the chain in the one value that owns the
//! block.  A record is never looked up by a block hash either.  The
//! other is the verdict of the block's data sanity checks
//! ([`HashedBlock::check_data_sanity`]), which follows the rule as the
//! hashes do (see the last section).
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
//!
//! # The signature operation counts
//!
//! The contextual block check counts the signature operations of every
//! transaction of the block and refuses a block whose sum exceeds the
//! limit (dcrd `checkBlockContext`, `validate.go:2378-2408`, over
//! `countSigOps`, `:3765-3814`).  The count reads nothing but the
//! block and one answer the chain gives, whether the treasury agenda is
//! active.  A [`HashedBlock`] counts the block both ways as it is made
//! (`BlockSigOps`), and carries the two sums.  They follow the rule
//! above as the block hash does: the processing call files them in the
//! slot beside the hashes, and the contextual check made as that same
//! allocation is accepted reads them, and no other check.  There the
//! chain picks the sum its agenda answer selects and compares it with
//! the limit; it runs its own count, which gives the verdict and its
//! text, wherever that sum is over the limit, and for every block that
//! did not arrive counted.  Carrying the sums decides nothing: a sum
//! within the limit says only that the count would pass, and nothing is
//! compared with the limit where the block was counted.  Under debug
//! assertions the check counts the block again and compares.
//!
//! # The data sanity verdict
//!
//! One thing a [`HashedBlock`] may carry is a verdict: that of the
//! context-free checks of the block's data and of each of its
//! transactions (dcrd `checkBlockDataSanity`, `validate.go:878-965`),
//! reached by [`HashedBlock::check_data_sanity`] over the block and the
//! transaction hashes the value owns.  Block processing makes those
//! checks right after the data preconditions, once the header's
//! commitment to the data has been checked, whether or not the agenda's
//! state let that commitment be proven (dcrd `process.go:496-515`).
//! They read nothing but the block, its transaction hashes and two
//! values of the chain parameters ([`crate::validate::DataSanityParams`]).
//! So the verdict can be reached before the block reaches the chain, on
//! another thread, and is the verdict the chain would reach.
//!
//! It is kept with the two values it was reached with
//! (`DataSanityVerdict`), and it follows the rule above: it is read only
//! out of the one value that owns the block, by the processing call that
//! value is handed to, and only at the point where that call makes the
//! checks for any other block.  The call returns it there, error, kind
//! and text, as the checks would have returned it, and goes on exactly
//! as it does after them; a block refused by an earlier check is
//! refused by that check, and its verdict is dropped unread.  A verdict
//! reached with values other than those of the parameters the call
//! processes the block with is not read at all: the call makes the
//! checks itself, as it does for every block that arrives without a
//! verdict.  Nothing else about the block is decided by it, and nothing
//! outside the chain can read it.  Under debug assertions the call makes
//! the checks again where it reads a verdict, and compares.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use dcroxide_chaincfg::Params;
use dcroxide_chainhash::{HASH_SIZE, Hash, hash_h};
use dcroxide_database::BlockRecord;
use dcroxide_standalone::calc_merkle_root;
use dcroxide_wire::{MsgBlock, MsgTx};

use crate::ruleerror::RuleError;
use crate::validate::DataSanityParams;

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

/// The number of signature operations in one block, as the contextual
/// block check counts them, once for each answer the treasury agenda
/// query can give: what `validate::count_block_sig_ops` returns for the
/// block with the agenda inactive and with it active.
///
/// The count is dcrd's (`checkBlockContext`, `validate.go:2378-2408`):
/// `countSigOps` of each regular transaction and then each stake
/// transaction, with the coinbase and vote flags that loop gives it,
/// summed in a `u32`.  The agenda changes it in three places: which
/// transaction is a coinbase, whose input scripts are not counted;
/// a treasurybase counts nothing once it is active; and `OP_TSPEND`
/// counts as one only once it is active (`GetSigOpCount`).  No limit is
/// applied here.  A sum is `None` where an accumulator would overflow,
/// which no block within the wire protocol's size limit can make.
///
/// The fields are private and [`BlockSigOps::compute`] is the only
/// constructor, so a value is always the pair of counts of some block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BlockSigOps {
    /// The count with the treasury agenda inactive.
    treasury_inactive: Option<u32>,
    /// The count with the treasury agenda active.
    treasury_active: Option<u32>,
}

/// The verdict of the context-free checks of one block's data
/// (`validate::check_block_data_sanity_by`, dcrd `checkBlockDataSanity`),
/// reached over the block and its own transaction hashes, with the
/// values of the chain parameters it was reached with.
///
/// The fields are private and [`DataSanityVerdict::reach`] is the only
/// constructor, so a value is always the result of those checks over
/// some block with the values it holds.  See the module documentation
/// for the rule that keeps it with that block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DataSanityVerdict {
    /// The values of the chain parameters the checks read.
    params: DataSanityParams,
    /// What the checks returned.
    result: Result<(), RuleError>,
}

/// A block together with its block hash, the hashes of its transactions,
/// its merkle leaves, the roots of its two transaction merkle trees and
/// its two counts of signature operations, all computed from that
/// block: what dcrd holds in one `dcrutil.Block`, whose transactions
/// carry their hashes (`dcrutil/block.go:162-224`) and whose block hash
/// is computed as the block is wrapped (`NewBlock`,
/// `dcrutil/block.go:288-293`).  dcrd caches no merkle root and no
/// count: it builds both trees inside `checkMerkleRoots` and counts
/// inside `checkBlockContext`.
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
/// root is compared with the header, no count is compared with the
/// limit, and the chain makes every check it makes of a block that
/// arrives without hashes, in the same order
/// (`Chain::process_hashed_block`).
///
/// One verdict may be reached on it before it reaches the chain: that
/// of the context-free checks of the block's data
/// ([`HashedBlock::check_data_sanity`]).  The chain returns it at the
/// point where it makes those checks of any other block, so the order of
/// the checks and every result are unchanged, and makes the checks
/// itself where the block carries none, or one reached with other values
/// of the parameters.  dcrd makes them on the thread that processes the
/// block (`checkBlockDataSanity`, `process.go:501-515`).
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
    /// The block's two counts of signature operations.
    sig_ops: BlockSigOps,
    /// The bytes the block was decoded from, laid out as its block-file
    /// record, when they were handed in and are the block's
    /// serialization ([`HashedBlock::keep_wire_bytes`]).
    record: Option<Arc<BlockRecord>>,
    /// The verdict of the block's data sanity checks, when they were
    /// made here ([`HashedBlock::check_data_sanity`]).  Boxed, so that
    /// a block that carries none, as every block but those the reading
    /// thread checks, is a pointer's width larger and no more.
    data_sanity: Option<Box<DataSanityVerdict>>,
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
    ///
    /// It also counts the block's signature operations twice, once for
    /// each answer the treasury agenda query can give
    /// (`BlockSigOps::compute`): two passes of the count the
    /// contextual check makes, each reading every input and output
    /// script once and the transaction's shape for the coinbase, vote
    /// and treasurybase tests, linear in the size of the block and
    /// allocating nothing that outlives a transaction.
    pub fn new(block: Arc<MsgBlock>) -> HashedBlock {
        let (tx_hashes, merkle_leaves) = BlockTxHashes::compute_with_merkle_leaves(&block);
        let merkle_roots = BlockMerkleRoots::compute(&merkle_leaves);
        let sig_ops = BlockSigOps::compute(&block);
        let hash = block.header.block_hash();
        HashedBlock {
            block,
            hash,
            tx_hashes: Arc::new(tx_hashes),
            merkle_leaves,
            merkle_roots,
            sig_ops,
            record: None,
            data_sanity: None,
        }
    }

    /// Make the context-free checks of the block's data and of each of
    /// its transactions (`validate::check_block_data_sanity`, dcrd
    /// `checkBlockDataSanity`) with the values of the chain parameters
    /// in `params`, over the block and the transaction hashes this value
    /// owns, and keep the verdict with those values, in place of any it
    /// carried.
    ///
    /// The verdict is not handed out: a chain that processes the block
    /// with parameters that hold those values returns it where it would
    /// have made the checks (`Chain::process_hashed_block`), and one that
    /// processes it with any other makes the checks itself.  Nothing else
    /// is decided by it, here or by the chain.
    ///
    /// The checks read every transaction once more, for its sanity
    /// checks and its serialized size, and file the transaction hashes
    /// in an ordered set for the duplicate check, as the chain does: work
    /// that grows with the block as the hashing does, and less of it.
    /// The verdict is kept in one allocation of its own, of 48 bytes on
    /// a 64-bit target, and one that fails also holds its error's
    /// description.
    pub fn check_data_sanity(&mut self, params: DataSanityParams) {
        self.data_sanity = Some(Box::new(DataSanityVerdict::reach(
            &self.block,
            &self.tx_hashes,
            params,
        )));
    }

    /// The values of the chain parameters the block's data sanity checks
    /// were made with here, if they were ([`Self::check_data_sanity`]).
    /// The verdict itself is the chain's to read.
    pub fn data_sanity_params(&self) -> Option<DataSanityParams> {
        self.data_sanity.as_ref().map(|verdict| verdict.params)
    }

    /// The verdict of the block's data sanity checks, if they were made
    /// here ([`Self::check_data_sanity`]).
    pub(crate) fn data_sanity(&self) -> Option<&DataSanityVerdict> {
        self.data_sanity.as_deref()
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

    /// The block's counts of signature operations.
    pub(crate) fn sig_ops(&self) -> &BlockSigOps {
        &self.sig_ops
    }

    /// Give the block back, dropping the hashes, the record and any
    /// verdict.
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

    /// How many times this thread ran the contextual check's own count
    /// of a block's signature operations, the loop that gives its
    /// verdict (`validate::check_block_sig_ops`).  The counts a
    /// [`HashedBlock`] is made with and the count `BlockSigOps::assert_for`
    /// makes again under debug assertions are not counted.  It exists in
    /// this crate's unit-test builds only, where the tests read it to
    /// tell that a check that was handed a block's counts within the
    /// limit did not count.
    pub(crate) static SIG_OP_LOOPS: core::cell::Cell<u64> =
        const { core::cell::Cell::new(0) };

    /// How many times this thread made a block's data sanity checks with
    /// the chain's parameters (`validate::check_block_data_sanity_with_hashes`,
    /// which `validate::check_block_data_sanity` calls too).  The checks
    /// [`HashedBlock::check_data_sanity`] makes, and those
    /// `DataSanityVerdict::assert_for` makes again under debug
    /// assertions, are not counted.  It exists in this crate's unit-test
    /// builds only, where the tests read it to tell that a processing
    /// call that read a block's verdict did not make the checks.
    pub(crate) static SANITY_CHECKS: core::cell::Cell<u64> =
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

impl BlockSigOps {
    /// Count the block's signature operations with the treasury agenda
    /// inactive and with it active.
    pub(crate) fn compute(block: &MsgBlock) -> BlockSigOps {
        BlockSigOps {
            treasury_inactive: crate::validate::count_block_sig_ops(block, false),
            treasury_active: crate::validate::count_block_sig_ops(block, true),
        }
    }

    /// The count for the answer the treasury agenda query gave, `None`
    /// where an accumulator would overflow.
    pub(crate) fn get(&self, is_treasury_enabled: bool) -> Option<u32> {
        if is_treasury_enabled {
            self.treasury_active
        } else {
            self.treasury_inactive
        }
    }

    /// Panic, under debug assertions, unless these are the block's
    /// counts.  A release build has nothing to check here: the pairing
    /// rests on the counts having been read out of the one
    /// [`HashedBlock`] that counted them, or out of the slot beside that
    /// block's own allocation.
    #[track_caller]
    pub(crate) fn assert_for(&self, block: &MsgBlock) {
        debug_assert!(
            *self == Self::compute(block),
            "signature operation counts do not match the block"
        );
    }
}

impl DataSanityVerdict {
    /// Make the block's data sanity checks with the values in `params`,
    /// over the block and its own transaction hashes.
    pub(crate) fn reach(
        block: &MsgBlock,
        tx_hashes: &BlockTxHashes,
        params: DataSanityParams,
    ) -> DataSanityVerdict {
        DataSanityVerdict {
            params,
            result: crate::validate::check_block_data_sanity_by(block, tx_hashes, &params),
        }
    }

    /// The verdict, where it was reached with the values of the chain
    /// parameters the checks read that `params` holds, and `None` where
    /// either value differs.
    pub(crate) fn for_params(&self, params: &Params) -> Option<&Result<(), RuleError>> {
        (self.params == DataSanityParams::of(params)).then_some(&self.result)
    }

    /// Panic, under debug assertions, unless this is the verdict the
    /// checks reach on the block now, with the values it was reached
    /// with.  A release build has nothing to check here: the pairing
    /// rests on the verdict having been read out of the one
    /// [`HashedBlock`] that reached it on its own block and hashes.
    #[track_caller]
    pub(crate) fn assert_for(&self, block: &MsgBlock, tx_hashes: &BlockTxHashes) {
        debug_assert!(
            *self == Self::reach(block, tx_hashes, self.params),
            "the data sanity verdict does not match the block"
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

    /// The block's signature operations by dcrd's count, written out
    /// here (`checkBlockContext`, `validate.go:2378-2408`, over
    /// `countSigOps`, `:3765-3814`): the script engine's quick count of
    /// every output script and of every input script but a coinbase's
    /// and a vote's first, for every transaction but a treasurybase
    /// once the treasury agenda is active.  The sum is taken in a `u64`
    /// and nothing is limited.
    fn reference_sig_ops(block: &MsgBlock, treasury: bool) -> u64 {
        block
            .transactions
            .iter()
            .chain(&block.stransactions)
            .map(|tx| {
                if treasury && dcroxide_stake::is_treasury_base(tx) {
                    return 0;
                }
                let inputs = if dcroxide_standalone::is_coin_base_tx(tx, treasury) {
                    &tx.tx_in[..0]
                } else if dcroxide_stake::is_ssgen(tx) && !tx.tx_in.is_empty() {
                    &tx.tx_in[1..]
                } else {
                    &tx.tx_in[..]
                };
                inputs
                    .iter()
                    .map(|tx_in| &tx_in.signature_script)
                    .chain(tx.tx_out.iter().map(|tx_out| &tx_out.pk_script))
                    .map(|script| dcroxide_txscript::get_sig_op_count(script, treasury) as u64)
                    .sum::<u64>()
            })
            .sum()
    }

    /// The contextual check's own count of the block, the loop that
    /// gives its verdict, with the sum where the block passes.  Before
    /// it returns that, it checks the limit on the block the two ways
    /// the chain can, with the counts the block carries and without,
    /// and asserts that both give that verdict, error and text
    /// included; that the check without counts counts the block, and
    /// the check with them only where the block fails; and that where
    /// the block passes the count it carries is the sum the loop ends
    /// on, and where it fails is over the limit or none.
    fn checked_both_ways(
        block: &MsgBlock,
        counted: &BlockSigOps,
        treasury: bool,
        what: &str,
    ) -> Result<u32, RuleError> {
        use crate::validate::{
            MAX_SIG_OPS_PER_BLOCK, check_block_sig_op_limit, check_block_sig_ops,
        };
        let loops = || SIG_OP_LOOPS.get();

        let before = loops();
        let verdict = check_block_sig_ops(block, treasury);
        assert_eq!(loops() - before, 1, "{what}");

        let before = loops();
        let with_counts = check_block_sig_op_limit(block, Some(counted), treasury);
        let loops_with_counts = loops() - before;
        let before = loops();
        let without = check_block_sig_op_limit(block, None, treasury);
        let loops_without = loops() - before;

        assert_eq!(with_counts, verdict.clone().map(drop), "{what}");
        assert_eq!(without, verdict.clone().map(drop), "{what}");
        assert_eq!(loops_without, 1, "{what}");
        assert_eq!(loops_with_counts, u64::from(verdict.is_err()), "{what}");
        match &verdict {
            Ok(total) => {
                assert_eq!(counted.get(treasury), Some(*total), "{what}");
                assert!(i64::from(*total) <= MAX_SIG_OPS_PER_BLOCK, "{what}");
            }
            Err(err) => {
                assert_eq!(err.kind, RuleErrorKind::TooManySigOps, "{what}");
                assert!(
                    counted
                        .get(treasury)
                        .is_none_or(|count| i64::from(count) > MAX_SIG_OPS_PER_BLOCK),
                    "{what}: {:?}",
                    counted.get(treasury)
                );
            }
        }
        verdict
    }

    /// A block hashed ahead carries the count of signature operations
    /// the contextual check makes, for each answer the treasury agenda
    /// query can give, for every block of the battery: the count dcrd's
    /// loop gives, written out here, and where the check's own count
    /// passes, the sum it ends on.  The limit checked with the carried
    /// counts gives the verdict it gives without them, with the same
    /// error and text, and counts the block itself only where the block
    /// is over the limit.
    #[test]
    fn carried_sig_op_counts_are_the_counts_of_the_block_check() {
        let blocks = fixture_blocks();
        assert_eq!(blocks.len(), 561, "the battery's blocks");
        let (mut within, mut over) = (0usize, Vec::new());
        for (name, block) in &blocks {
            let hashed = HashedBlock::new(Arc::new(block.clone()));
            assert_eq!(*hashed.sig_ops(), BlockSigOps::compute(block), "{name}");
            hashed.sig_ops().assert_for(block);
            for treasury in [false, true] {
                let what = format!("{name}, treasury: {treasury}");
                assert_eq!(
                    hashed.sig_ops().get(treasury).map(u64::from),
                    Some(reference_sig_ops(block, treasury)),
                    "{what}"
                );
                match checked_both_ways(block, hashed.sig_ops(), treasury, &what) {
                    Ok(_) => within += 1,
                    Err(_) => over.push(what),
                }
            }
        }
        // The battery's blocks over the limit by this count, each under
        // both answers: the rows dcrd refuses for it, and one row it
        // refuses for another reason first.  None is over the limit
        // under one answer only.
        let mut expected = Vec::new();
        for name in ["bcs2", "bmo2", "bmo4", "bmo6", "bsc1", "bsc2"] {
            for treasury in [false, true] {
                expected.push(format!("{name}, treasury: {treasury}"));
            }
        }
        assert_eq!(over, expected);
        assert_eq!(within, 2 * blocks.len() - over.len());
    }

    /// A script of `n` signature checks, each counted as one.
    fn checksigs(n: usize) -> Vec<u8> {
        vec![dcroxide_txscript::OP_CHECKSIG; n]
    }

    /// A transaction that spends one output of another transaction with
    /// the given signature script and pays to each of the given scripts.
    fn spending(signature_script: Vec<u8>, pk_scripts: Vec<Vec<u8>>) -> MsgTx {
        MsgTx {
            tx_in: vec![dcroxide_wire::TxIn {
                previous_out_point: dcroxide_wire::OutPoint {
                    hash: Hash([1; HASH_SIZE]),
                    index: 0,
                    tree: 0,
                },
                signature_script,
                ..Default::default()
            }],
            tx_out: pk_scripts
                .into_iter()
                .map(|pk_script| dcroxide_wire::TxOut {
                    value: 1,
                    pk_script,
                    ..Default::default()
                })
                .collect(),
            ..MsgTx::default()
        }
    }

    /// A block of the given trees, under a header made for them that
    /// commits to them.  Each transaction [`spending`] made spends an
    /// output of its own, so that no two of them are the same.  The
    /// counts read the transactions only.
    fn block_of(regular: Vec<MsgTx>, stake: Vec<MsgTx>) -> MsgBlock {
        let mut block = one_transaction_block();
        block.transactions = regular;
        block.stransactions = stake;
        let txs = block
            .transactions
            .iter_mut()
            .chain(&mut block.stransactions);
        for (index, tx) in (0u32..).zip(txs) {
            if let Some(tx_in) = tx.tx_in.first_mut()
                && tx_in.previous_out_point.hash == Hash([1; HASH_SIZE])
            {
                tx_in.previous_out_point.index = index;
            }
        }
        block.header.merkle_root = calc_tx_tree_merkle_root(&block.transactions);
        block.header.stake_root = calc_tx_tree_merkle_root(&block.stransactions);
        block.header.size = block.serialize_size() as u32;
        block
    }

    /// The text the contextual check fails a block with whose sum went
    /// over the limit at `got`.
    fn too_many(got: u32) -> String {
        format!("block contains too many signature operations - got {got}, max 5000")
    }

    /// The carried counts against the check's own, at and around the
    /// limit and where the treasury agenda's answer changes the count.
    /// For each block and each answer the carried count is the count
    /// written out here; where the block passes it is the sum the
    /// check's count ends on and the check does not count; where the
    /// block fails, the check counts it, and fails it at the transaction
    /// that took the sum over the limit, with the sum at that point in
    /// the text, not the block's whole count.
    #[test]
    fn carried_sig_op_counts_at_the_limit_and_by_agenda_answer() {
        use dcroxide_txscript::{OP_CHECKMULTISIG, OP_TADD, OP_TSPEND};

        // A coinbase in shape whose input script counts 4,001 and whose
        // output counts 1,000.  Its version is 1, so it is a coinbase
        // only while the treasury agenda is inactive, and its input
        // script is counted once it is active.
        let mut coinbase = spending(checksigs(4_001), vec![checksigs(1_000)]);
        coinbase.tx_in[0].previous_out_point = dcroxide_wire::OutPoint {
            hash: Hash::ZERO,
            index: u32::MAX,
            tree: 0,
        };
        coinbase.version = 1;
        assert!(dcroxide_standalone::is_coin_base_tx(&coinbase, false));
        assert!(!dcroxide_standalone::is_coin_base_tx(&coinbase, true));

        // A treasurybase, which counts nothing either way.
        let treasurybase = MsgTx {
            version: dcroxide_stake::TX_VERSION_TREASURY,
            tx_in: vec![dcroxide_wire::TxIn {
                previous_out_point: dcroxide_wire::OutPoint {
                    hash: Hash::ZERO,
                    index: u32::MAX,
                    tree: 0,
                },
                ..Default::default()
            }],
            tx_out: vec![
                dcroxide_wire::TxOut {
                    pk_script: vec![OP_TADD],
                    ..Default::default()
                },
                dcroxide_wire::TxOut {
                    pk_script: [&[0x6a, 0x0c][..], &[0u8; 12]].concat(),
                    ..Default::default()
                },
            ],
            ..MsgTx::default()
        };
        assert!(dcroxide_stake::is_treasury_base(&treasurybase));

        // A vote of the battery with signature checks in both its
        // inputs: those of its first, the stakebase, are not counted.
        let mut vote = fixture_blocks()
            .into_iter()
            .flat_map(|(_, block)| block.stransactions)
            .find(dcroxide_stake::is_ssgen)
            .expect("the battery has votes");
        assert_eq!(vote.tx_in.len(), 2);
        let vote_alone = u32::try_from(reference_sig_ops(
            &block_of(Vec::new(), vec![vote.clone()]),
            false,
        ))
        .expect("count");
        vote.tx_in[0].signature_script.extend(checksigs(9));
        vote.tx_in[1].signature_script.extend(checksigs(4));
        assert!(dcroxide_stake::is_ssgen(&vote));
        let vote_count = vote_alone + 4;

        let mut tspend_outputs = checksigs(4_999);
        tspend_outputs.extend([OP_TSPEND, OP_TSPEND]);
        let multisig = |n: usize| vec![OP_CHECKMULTISIG; n];

        // Each block, with its count and its verdict with the agenda
        // inactive and then active: `Ok` with the sum, or `Err` with the
        // sum at which the check stops.
        type Expected = (u32, Result<u32, u32>);
        let cases: Vec<(&str, MsgBlock, [Expected; 2])> = vec![
            (
                "no transactions",
                block_of(Vec::new(), Vec::new()),
                [(0, Ok(0)), (0, Ok(0))],
            ),
            (
                "at the limit",
                block_of(
                    vec![
                        spending(Vec::new(), vec![checksigs(4_000)]),
                        spending(checksigs(1_000), Vec::new()),
                    ],
                    Vec::new(),
                ),
                [(5_000, Ok(5_000)), (5_000, Ok(5_000))],
            ),
            (
                "one over the limit",
                block_of(
                    vec![spending(Vec::new(), vec![checksigs(5_001)])],
                    Vec::new(),
                ),
                [(5_001, Err(5_001)), (5_001, Err(5_001))],
            ),
            (
                "over the limit with more to count",
                block_of(
                    vec![
                        spending(Vec::new(), vec![checksigs(3_000)]),
                        spending(Vec::new(), vec![checksigs(3_000)]),
                        spending(Vec::new(), vec![checksigs(10)]),
                    ],
                    Vec::new(),
                ),
                [(6_010, Err(6_000)), (6_010, Err(6_000))],
            ),
            (
                "over the limit in the stake tree, after the regular one",
                block_of(
                    vec![spending(Vec::new(), vec![checksigs(3_000)])],
                    vec![
                        spending(Vec::new(), vec![checksigs(2_001)]),
                        spending(Vec::new(), vec![checksigs(7)]),
                    ],
                ),
                [(5_008, Err(5_001)), (5_008, Err(5_001))],
            ),
            (
                "multisignature checks at the limit",
                block_of(vec![spending(Vec::new(), vec![multisig(250)])], Vec::new()),
                [(5_000, Ok(5_000)), (5_000, Ok(5_000))],
            ),
            (
                "multisignature checks over the limit",
                block_of(vec![spending(Vec::new(), vec![multisig(251)])], Vec::new()),
                [(5_020, Err(5_020)), (5_020, Err(5_020))],
            ),
            (
                "treasury spend opcodes over the limit once they count",
                block_of(vec![spending(Vec::new(), vec![tspend_outputs])], Vec::new()),
                [(4_999, Ok(4_999)), (5_001, Err(5_001))],
            ),
            (
                "a coinbase until the treasury agenda is active",
                block_of(vec![coinbase], Vec::new()),
                [(1_000, Ok(1_000)), (5_001, Err(5_001))],
            ),
            (
                "a treasurybase",
                block_of(
                    vec![spending(Vec::new(), vec![checksigs(5)])],
                    vec![treasurybase],
                ),
                [(5, Ok(5)), (5, Ok(5))],
            ),
            (
                "a vote with signature checks in its stakebase",
                block_of(Vec::new(), vec![vote]),
                [(vote_count, Ok(vote_count)), (vote_count, Ok(vote_count))],
            ),
        ];

        for (name, block, expected) in &cases {
            let hashed = HashedBlock::new(Arc::new(block.clone()));
            assert_eq!(*hashed.sig_ops(), BlockSigOps::compute(block), "{name}");
            for (treasury, (count, verdict)) in [false, true].into_iter().zip(expected) {
                let what = format!("{name}, treasury: {treasury}");
                assert_eq!(hashed.sig_ops().get(treasury), Some(*count), "{what}");
                assert_eq!(
                    reference_sig_ops(block, treasury),
                    u64::from(*count),
                    "{what}"
                );
                let got = checked_both_ways(block, hashed.sig_ops(), treasury, &what);
                match verdict {
                    Ok(total) => assert_eq!(got, Ok(*total), "{what}"),
                    Err(at) => {
                        let err = got.expect_err("over the limit");
                        assert_eq!(err.description, too_many(*at), "{what}");
                    }
                }
            }
        }
    }

    /// A carried count spares the check its own count only when it is
    /// a count, and at most the limit.
    #[test]
    fn only_a_count_at_most_the_limit_is_within_it() {
        use crate::validate::sig_op_count_is_within_limit;

        for (count, within) in [
            (Some(0), true),
            (Some(4_999), true),
            (Some(5_000), true),
            (Some(5_001), false),
            (Some(u32::MAX), false),
            (None, false),
        ] {
            assert_eq!(sig_op_count_is_within_limit(count), within, "{count:?}");
        }
    }

    /// The sum of a block's counts is `None` once a count is, or once
    /// the `u32` it is taken in overflows, where the check's own count
    /// fails; and no block within the wire protocol's size limit comes
    /// near that, at 20 operations a script byte at most.
    #[test]
    fn a_sum_that_overflows_its_accumulator_is_none() {
        use crate::validate::sum_sig_op_counts;

        assert_eq!(sum_sig_op_counts([]), Some(0));
        assert_eq!(sum_sig_op_counts([Some(5), Some(7)]), Some(12));
        assert_eq!(sum_sig_op_counts([Some(u32::MAX), Some(0)]), Some(u32::MAX));
        assert_eq!(sum_sig_op_counts([Some(u32::MAX), Some(1)]), None);
        assert_eq!(
            sum_sig_op_counts([Some(u32::MAX - 1), Some(1), Some(1)]),
            None
        );
        assert_eq!(sum_sig_op_counts([Some(1), None, Some(1)]), None);
        assert_eq!(sum_sig_op_counts([None]), None);

        // The most one script byte counts, under either answer.
        for treasury in [false, true] {
            let most = (0..=u8::MAX)
                .map(|op| dcroxide_txscript::get_sig_op_count(&[op], treasury))
                .max();
            assert_eq!(most, Some(20), "treasury: {treasury}");
            assert_eq!(
                dcroxide_txscript::get_sig_op_count(&[0xae; 1_000], treasury),
                20_000
            );
        }
        let most_in_a_block = 20 * u64::from(dcroxide_wire::MAX_BLOCK_PAYLOAD);
        assert!(most_in_a_block < 27_000_000);
        assert!(most_in_a_block < u64::from(u32::MAX));
    }

    /// A transaction whose own count overflows the `u32` that
    /// `count_sig_ops` takes it in makes the block's count none, not the
    /// sum of the other transactions' counts, so a block carrying it is
    /// never taken to be within the limit.  Each of its two outputs
    /// counts 20 a byte and fits the accumulator alone; together they do
    /// not.  No block within the wire protocol's size limit can hold
    /// such a transaction, which takes more than 214 million bytes of
    /// script: the path is tested here, not a block that can arrive.
    /// One answer of the treasury agenda is enough, since none of these
    /// bytes is `OP_TSPEND`, and each count reads all of them.
    #[test]
    fn a_transaction_whose_own_count_overflows_makes_the_count_none() {
        use crate::validate::count_block_sig_ops;

        let half = vec![dcroxide_txscript::OP_CHECKMULTISIG; 107_374_183];
        let half_count = 20 * half.len() as u64;
        assert!(half_count <= u64::from(u32::MAX));
        assert!(2 * half_count > u64::from(u32::MAX));

        let mut block = one_transaction_block();
        let small = count_block_sig_ops(&block, false).expect("the genesis block's count");
        assert!(u64::from(small) + half_count <= u64::from(u32::MAX));
        block
            .transactions
            .push(spending(Vec::new(), vec![half.clone(), half]));
        assert_eq!(count_block_sig_ops(&block, false), None);
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
            &dcroxide_chaincfg::regnet_params(),
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

    /// The blocks of dcrd's block sanity vectors
    /// (`tests/data/blocksanity_vectors.txt`), made for mainnet, each with
    /// the kind dcrd's `checkBlockSanity` gave it (`ok` for none) and its
    /// row number.
    fn block_sanity_rows() -> Vec<(String, MsgBlock, String)> {
        include_str!("../tests/data/blocksanity_vectors.txt")
            .lines()
            .enumerate()
            .filter_map(|(row, line)| {
                let f: Vec<&str> = line.split(' ').collect();
                (f[0] == "block").then(|| {
                    let (block, _) =
                        MsgBlock::from_bytes(&dcroxide_testutil::unhex(f[1])).expect("block");
                    (format!("block sanity row {row}"), block, f[2].to_string())
                })
            })
            .collect()
    }

    /// The fixed adjusted time dcrd's block sanity vectors were made at
    /// (`tests/blocksanity_vectors.rs`).
    const BLOCK_SANITY_ADJUSTED_TIME: i64 = 1454954400;

    /// The verdict of its data sanity checks a hashed block carries is the
    /// one the chain's own checks reach on the block, error, kind and
    /// text: for every block of dcrd's full block battery with the
    /// parameters of the network it was made for, and for every block of
    /// dcrd's block sanity vectors with mainnet's.  Where a vector's
    /// header passes its own checks, the verdict's kind is the one dcrd
    /// recorded for the block.  The verdicts cover every kind the
    /// vectors refuse a block's data with.  A verdict is read only with
    /// the values it was reached with, not with the other network's, and
    /// reaching it makes none of the checks the chain counts as its own.
    #[test]
    fn a_carried_data_sanity_verdict_is_the_checks_own() {
        let regnet = dcroxide_chaincfg::regnet_params();
        let mainnet = dcroxide_chaincfg::mainnet_params();
        assert_ne!(
            DataSanityParams::of(&regnet),
            DataSanityParams::of(&mainnet)
        );
        let battery: Vec<(String, MsgBlock, Option<String>)> = fixture_blocks()
            .into_iter()
            .map(|(name, block)| (name, block, None))
            .collect();
        let vectors: Vec<(String, MsgBlock, Option<String>)> = block_sanity_rows()
            .into_iter()
            .map(|(name, block, kind)| (name, block, Some(kind)))
            .collect();

        let mut kinds = BTreeSet::new();
        let (mut passed, mut failed, mut recorded) = (0usize, 0usize, 0usize);
        for (params, other, blocks) in [(&regnet, &mainnet, battery), (&mainnet, &regnet, vectors)]
        {
            for (name, block, dcrd_kind) in &blocks {
                let expected = crate::validate::check_block_data_sanity(block, params);

                let mut hashed = HashedBlock::new(Arc::new(block.clone()));
                assert!(hashed.data_sanity().is_none(), "{name}");
                assert_eq!(hashed.data_sanity_params(), None, "{name}");
                let before = SANITY_CHECKS.get();
                hashed.check_data_sanity(DataSanityParams::of(params));
                assert_eq!(
                    SANITY_CHECKS.get(),
                    before,
                    "{name}: counted as the chain's"
                );
                assert_eq!(
                    hashed.data_sanity_params(),
                    Some(DataSanityParams::of(params)),
                    "{name}"
                );
                let verdict = hashed.data_sanity().expect("a verdict");
                assert_eq!(verdict.for_params(params), Some(&expected), "{name}");
                assert_eq!(verdict.for_params(other), None, "{name}");

                // dcrd's own record of the block, where its header
                // passes the header checks the vector's verdict also
                // made.
                if let Some(dcrd_kind) = dcrd_kind
                    && crate::validate::check_block_header_sanity(
                        &block.header,
                        BLOCK_SANITY_ADJUSTED_TIME,
                        true,
                        params,
                    )
                    .is_ok()
                {
                    let carried_kind = match &expected {
                        Ok(()) => "ok",
                        Err(err) => err.kind.kind_name(),
                    };
                    assert_eq!(carried_kind, dcrd_kind, "{name}");
                    recorded += 1;
                }

                match expected {
                    Ok(()) => passed += 1,
                    Err(err) => {
                        failed += 1;
                        kinds.insert(err.kind.kind_name());
                    }
                }
            }
        }
        assert_eq!((passed, failed, recorded), (597, 114, 138));
        assert_eq!(
            kinds.into_iter().collect::<Vec<_>>(),
            [
                "ErrBadTxOutValue",
                "ErrDuplicateTx",
                "ErrDuplicateTxInputs",
                "ErrFreshStakeMismatch",
                "ErrNoTransactions",
                "ErrNoTxInputs",
                "ErrNoTxOutputs",
                "ErrNotEnoughStake",
                "ErrStakeBelowMinimum",
                "ErrWrongBlockSize",
            ]
        );
    }

    /// The three kinds the data sanity checks can refuse a block with
    /// that no vector reaches, each carried as the checks reach it: a
    /// transaction over the largest size, here a battery block's
    /// coinbase checked with that size set one byte under it; an input
    /// whose fraud proof amount is out of range; and a block over the
    /// largest the wire protocol carries.  The first is also the check
    /// that the verdict is reached with the values it is handed: it is
    /// carried for those values only, and the battery block passes with
    /// the network's own.
    #[test]
    fn the_kinds_no_vector_reaches_are_carried_as_the_checks_reach_them() {
        let regnet = dcroxide_chaincfg::regnet_params();
        let carried = |block: &MsgBlock, params: &dcroxide_chaincfg::Params| {
            let mut hashed = HashedBlock::new(Arc::new(block.clone()));
            hashed.check_data_sanity(DataSanityParams::of(params));
            let verdict = hashed.data_sanity().expect("a verdict").clone();
            let result = verdict
                .for_params(params)
                .expect("read with its own values")
                .clone();
            assert_eq!(
                result,
                crate::validate::check_block_data_sanity(block, params)
            );
            (verdict, result)
        };
        let resized = |mut block: MsgBlock| {
            block.header.size = u32::try_from(block.serialize_size()).expect("size");
            block
        };
        let (name, block) = fixture_blocks()
            .into_iter()
            .find(|(_, block)| {
                block.header.height > 0
                    && crate::validate::check_block_data_sanity(block, &regnet).is_ok()
            })
            .expect("a battery block that passes");

        // One byte too small for the coinbase.
        let mut tight = regnet.clone();
        tight.max_tx_size = block.transactions[0].serialize_size() - 1;
        let (verdict, result) = carried(&block, &tight);
        let err = result.expect_err("over the size");
        assert_eq!(err.kind, RuleErrorKind::TxTooBig, "{name}: {err:?}");
        assert_eq!(verdict.for_params(&regnet), None, "{name}");
        let (_, result) = carried(&block, &regnet);
        assert_eq!(result, Ok(()), "{name}");

        // A fraud proof amount below zero that is not the sentinel.
        let mut fraud = block.clone();
        let input = fraud.transactions[0]
            .tx_in
            .first_mut()
            .expect("a coinbase input");
        input.value_in = -2;
        let fraud = resized(fraud);
        let (_, result) = carried(&fraud, &regnet);
        let err = result.expect_err("out of range");
        assert_eq!(err.kind, RuleErrorKind::FraudAmountIn, "{err:?}");

        // A block one transaction longer, its output script taking it
        // over the largest block the wire protocol carries.
        let mut big = block.clone();
        let mut filler = big.transactions[0].clone();
        filler.tx_out[0].pk_script = alloc::vec![0x51; 1 << 21];
        big.transactions.push(filler);
        let big = resized(big);
        let (_, result) = carried(&big, &regnet);
        let err = result.expect_err("too big");
        assert_eq!(err.kind, RuleErrorKind::BlockTooBig, "{err:?}");
    }

    /// The values a verdict is read with are the two the checks read and
    /// no others: the same parameters, or parameters that differ in
    /// anything else, hold the same; a change to either one holds
    /// others.  Simnet's are regnet's, and mainnet's and testnet's
    /// differ from them.
    #[test]
    fn data_sanity_params_hold_the_two_values_the_checks_read() {
        let regnet = dcroxide_chaincfg::regnet_params();
        let of = DataSanityParams::of;
        assert_eq!(of(&regnet), of(&dcroxide_chaincfg::regnet_params()));
        let mut elsewhere = regnet.clone();
        elsewhere.name = "elsewhere";
        elsewhere.stake_validation_height += 1;
        elsewhere.max_fresh_stake_per_block += 1;
        assert_eq!(of(&elsewhere), of(&regnet));
        let mut larger = regnet.clone();
        larger.max_tx_size += 1;
        assert_ne!(of(&larger), of(&regnet));
        let mut dearer = regnet.clone();
        dearer.minimum_stake_diff += 1;
        assert_ne!(of(&dearer), of(&regnet));
        assert_eq!(of(&dcroxide_chaincfg::simnet_params()), of(&regnet));
        for other in [
            dcroxide_chaincfg::mainnet_params(),
            dcroxide_chaincfg::testnet3_params(),
        ] {
            assert_ne!(of(&other), of(&regnet), "{}", other.name);
        }
    }

    /// What a verdict costs a hashed block: a pointer in place, whether
    /// it carries one or not, and the verdict's own allocation, the two
    /// values and the result.  On a 64-bit target that allocation is 48
    /// bytes and a `HashedBlock` is 192, 8 more than before it could
    /// carry a verdict; a field added to either, or the verdict held in
    /// place, fails here.
    #[test]
    fn a_carried_verdict_is_small() {
        /// The size of the type of the field `field` returns.
        fn field_size<T>(_field: fn(&HashedBlock) -> &T) -> usize {
            core::mem::size_of::<T>()
        }
        assert_eq!(
            field_size(|hashed| &hashed.data_sanity),
            core::mem::size_of::<usize>(),
            "the verdict is held in place, not behind a pointer"
        );
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(core::mem::size_of::<DataSanityVerdict>(), 48);
            assert_eq!(core::mem::size_of::<HashedBlock>(), 192);
        }
    }
}
