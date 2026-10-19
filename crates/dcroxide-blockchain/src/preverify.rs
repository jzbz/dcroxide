// SPDX-License-Identifier: ISC
//! Signature pre-verification: the signatures of blocks the chain has
//! not reached yet, checked on the script pool's helpers so that the
//! signature cache already holds them when the chain connects the
//! blocks.  dcrd does not do this (PARITY.md, *Signature
//! pre-verification ahead of the block thread*).
//!
//! # What enters the cache
//!
//! Nothing but what the script engine puts there.  Each input is run
//! through the public engine against a guessed public key script, with
//! the cache and the transaction's hash attached, exactly as a connect
//! check runs it against the script the input spends.  The engine adds
//! an entry only after its own parse and verify of that signature hash,
//! signature and public key succeeded, and a connect check hits only the
//! identical three, so every entry made here is a signature that
//! verifies, and a hit at connect skips only a verify that would have
//! succeeded.  A wrong guess gives another signature hash: the verify
//! fails and nothing is added, or an entry is added under a hash no
//! connect check of that input computes.  The script flags do not enter
//! an entry, the verify reading none of them, so the guessed scripts run
//! under every agenda's.  The connect path is not changed and does not
//! know whether an input was pre-verified.
//!
//! # The guess
//!
//! Only a signature script of exactly two canonical pushes, a signature
//! of 1 to 75 bytes whose last byte, its hash type, is `SigHashAll`, and
//! a public key of 33 or 65 bytes, gets a guess: pay to the hash of that
//! key, behind the stake opcode the spent output most likely carries.
//! The outpoint's tree and index and the spender decide it:
//!
//! - an output of the regular tree: no stake opcode;
//! - output 0 of a stake transaction, spent from the stake tree by a
//!   transaction that is not a ticket purchase (a vote or a revocation
//!   spending its ticket): `OP_SSTX`;
//! - outputs 0 and 1 otherwise: `OP_SSRTX`, a revocation's payouts;
//! - outputs 2 and up: `OP_SSGEN`, a vote's payouts.
//!
//! The last two are guesses; a ticket's change and a treasury spend's
//! payouts are missed.  Each input gets one guess, and so costs the lane
//! one signature hash and at most one signature verification, whatever
//! the block holds.  Under `SigHashAll` the signature hash takes the
//! transaction's prefix from its hash, which the reader computed, and
//! hashes afresh only the transaction's witness serialization, a byte
//! for each input but the one signed; any other hash type serializes
//! and hashes the whole prefix again for each input, which a block the
//! chain would refuse for its size before running any script could make
//! cost the square of its inputs.  Spends of a script hash are not
//! guessed for the same reason: a redeem script the signature script
//! reveals could make the lane verify many signatures for one input,
//! where the connect checks refuse a block over the sig-op limit before
//! they run any script.
//!
//! # Where it runs
//!
//! A `Preverifier` owns a lane of the process-wide script pool
//! (`crate::scriptpool`): its blocks are checked by helpers no batch of
//! a connected block wants, at most `Preverifier::helpers` at once,
//! and a helper leaves a block for a batch queued meanwhile once the
//! input it holds is done.  Its owner
//! submits a block (`Preverifier::submit`) and withdraws it once the
//! chain is about to process it (`Preverifier::withdraw_through`);
//! from then on the connect checks verify whatever the lane did not
//! reach.  Blocks at or below the floor (`Preverifier::set_floor`),
//! whose scripts the chain will not check, are not taken.  The
//! pre-verifier needs threads: without the `std` feature the crate has
//! none, and only the checks of one input and of one block on the
//! calling thread are here ([`preverify_input`], [`preverify_block`]).

#[cfg(any(test, feature = "std"))]
use alloc::sync::Arc;
use alloc::vec::Vec;
#[cfg(any(test, feature = "std"))]
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};

use dcroxide_chainhash::Hash;
use dcroxide_txscript::{
    Engine, OP_CHECKSIG, OP_DATA_1, OP_DATA_20, OP_DATA_33, OP_DATA_65, OP_DATA_75, OP_DUP,
    OP_EQUALVERIFY, OP_HASH160, OP_SSGEN, OP_SSRTX, OP_SSTX, SIG_HASH_ALL, ScriptFlags, SigCache,
};
use dcroxide_wire::{MsgBlock, MsgTx, OutPoint, TX_TREE_REGULAR, TX_TREE_STAKE};

use crate::blockhashes::BlockTxHashes;
#[cfg(any(test, feature = "std"))]
use crate::blockhashes::HashedBlock;
#[cfg(any(test, feature = "std"))]
use crate::scriptpool::{LaneHandle, LaneJob, Pool, Refusal};

/// The flags the guessed scripts run under: those of a block connected
/// with every agenda active (`validate::consensus_script_verify_flags`).
/// They decide only how far a run gets, never what it adds to the cache.
const FLAGS: ScriptFlags = ScriptFlags(
    ScriptFlags::VERIFY_CLEAN_STACK.0
        | ScriptFlags::VERIFY_CHECK_LOCK_TIME_VERIFY.0
        | ScriptFlags::VERIFY_CHECK_SEQUENCE_VERIFY.0
        | ScriptFlags::VERIFY_SHA256.0
        | ScriptFlags::VERIFY_TREASURY.0,
);

/// The length of a pay-to-pubkey-hash script.
const P2PKH_LEN: usize = 25;

/// A script guessed for an input: pay-to-pubkey-hash, behind a stake
/// opcode or not.
struct Guess {
    bytes: [u8; P2PKH_LEN + 1],
    tagged: bool,
}

impl Guess {
    /// Pay to the hash of `key`, behind `tag` when there is one.
    fn new(tag: Option<u8>, key: &[u8]) -> Guess {
        let hash = dcroxide_txscript::stdaddr::hash160(key);
        let mut bytes = [0u8; P2PKH_LEN + 1];
        let (head, body) = bytes.split_at_mut(1);
        head[0] = tag.unwrap_or(0);
        body[0] = OP_DUP;
        body[1] = OP_HASH160;
        body[2] = OP_DATA_20;
        body[3..23].copy_from_slice(&hash);
        body[23] = OP_EQUALVERIFY;
        body[24] = OP_CHECKSIG;
        Guess {
            bytes,
            tagged: tag.is_some(),
        }
    }

    fn script(&self) -> &[u8] {
        if self.tagged {
            &self.bytes
        } else {
            &self.bytes[1..]
        }
    }
}

/// The signature and the public key of a signature script that is
/// exactly two canonical pushes: a signature of 1 to 75 bytes whose
/// last byte, its hash type, is `SigHashAll`, and a public key of 33 or
/// 65 bytes.
fn sig_and_key(sig_script: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&sig_op, rest) = sig_script.split_first()?;
    if !(OP_DATA_1..=OP_DATA_75).contains(&sig_op) {
        return None;
    }
    let (sig, rest) = rest.split_at_checked(usize::from(sig_op))?;
    // Only `SigHashAll`, whose signature hash reuses the transaction's
    // hash for its prefix (see the module documentation).
    if sig.last() != Some(&SIG_HASH_ALL.0) {
        return None;
    }
    let (&key_op, key) = rest.split_first()?;
    if (key_op != OP_DATA_33 && key_op != OP_DATA_65) || key.len() != usize::from(key_op) {
        return None;
    }
    Some((sig, key))
}

/// The stake opcode the script guessed for an input of `spender`
/// spending `prev` goes behind: `Some(None)` for none, and `None` when
/// no script is guessed (see the module documentation).
fn guessed_tag(spender: &MsgTx, prev: &OutPoint, stake_tree: bool) -> Option<Option<u8>> {
    match prev.tree {
        TX_TREE_REGULAR => Some(None),
        TX_TREE_STAKE => {
            let buys_ticket =
                spender.tx_out.first().and_then(|out| out.pk_script.first()) == Some(&OP_SSTX);
            Some(Some(match prev.index {
                0 if stake_tree && !buys_ticket => OP_SSTX,
                0 | 1 => OP_SSRTX,
                _ => OP_SSGEN,
            }))
        }
        _ => None,
    }
}

/// Run input `tx_in_idx` of `tx` against the script guessed for it,
/// under `tag`, with the cache and the transaction's hash attached.
/// `None` when the input has no guess, and otherwise whether the run
/// succeeded.
fn check_input(
    tx: &MsgTx,
    tx_in_idx: usize,
    tx_hash: &Hash,
    tag: Option<u8>,
    sig_cache: &SigCache,
) -> Option<bool> {
    let tx_in = tx.tx_in.get(tx_in_idx)?;
    let (_, key) = sig_and_key(&tx_in.signature_script)?;
    let guess = Guess::new(tag, key);
    let Ok(mut engine) = Engine::new(guess.script(), tx, tx_in_idx, FLAGS, 0) else {
        return Some(false);
    };
    engine.set_sig_cache(sig_cache);
    engine.set_tx_hash(tx_hash);
    Some(engine.execute().is_ok())
}

/// Pre-verify input `tx_in_idx` of `tx`, a transaction of the stake tree
/// when `stake_tree` is set, on the calling thread: run it against the
/// script guessed for it with `sig_cache` attached, as the lane does.
/// `tx_hash` must be the transaction's hash.  `None` when the input is
/// coinbase-style or gets no guess, and otherwise whether the run
/// succeeded.
pub fn preverify_input(
    tx: &MsgTx,
    tx_in_idx: usize,
    tx_hash: &Hash,
    stake_tree: bool,
    sig_cache: &SigCache,
) -> Option<bool> {
    let prev = &tx.tx_in.get(tx_in_idx)?.previous_out_point;
    if prev.index == u32::MAX {
        return None;
    }
    let tag = guessed_tag(tx, prev, stake_tree)?;
    check_input(tx, tx_in_idx, tx_hash, tag, sig_cache)
}

/// An input a script is guessed for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Candidate {
    stake: bool,
    tx_idx: u32,
    tx_in_idx: u32,
    tag: Option<u8>,
}

/// The inputs of `block` that get a guess, the stake tree's first, in
/// the order the connect checks run them.
fn candidates(block: &MsgBlock) -> Vec<Candidate> {
    let mut found = Vec::new();
    for (stake, txs) in [(true, &block.stransactions), (false, &block.transactions)] {
        for (tx_idx, tx) in txs.iter().enumerate() {
            for (tx_in_idx, tx_in) in tx.tx_in.iter().enumerate() {
                let prev = &tx_in.previous_out_point;
                if prev.index == u32::MAX || sig_and_key(&tx_in.signature_script).is_none() {
                    continue;
                }
                let Some(tag) = guessed_tag(tx, prev, stake) else {
                    continue;
                };
                let (Ok(tx_idx), Ok(tx_in_idx)) = (u32::try_from(tx_idx), u32::try_from(tx_in_idx))
                else {
                    continue;
                };
                found.push(Candidate {
                    stake,
                    tx_idx,
                    tx_in_idx,
                    tag,
                });
            }
        }
    }
    found
}

/// Check a candidate of `block`, whose transaction hashes `tx_hashes`
/// are.  Whether the run succeeded.
fn check_candidate(
    block: &MsgBlock,
    tx_hashes: &BlockTxHashes,
    candidate: &Candidate,
    sig_cache: &SigCache,
) -> bool {
    let (txs, hashes) = if candidate.stake {
        (&block.stransactions, tx_hashes.stake())
    } else {
        (&block.transactions, tx_hashes.regular())
    };
    let tx_idx = candidate.tx_idx as usize;
    let (Some(tx), Some(tx_hash)) = (txs.get(tx_idx), hashes.get(tx_idx)) else {
        return false;
    };
    check_input(
        tx,
        candidate.tx_in_idx as usize,
        tx_hash,
        candidate.tag,
        sig_cache,
    ) == Some(true)
}

/// What pre-verifying some inputs on the calling thread came to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PreverifiedInputs {
    /// The inputs that got a guess and were run.
    pub checked: u64,
    /// Those whose run succeeded.
    pub verified: u64,
}

/// Pre-verify every input of `block` that gets a guess, on the calling
/// thread, as the lane does, `tx_hashes` being the block's.
pub fn preverify_block(
    block: &MsgBlock,
    tx_hashes: &BlockTxHashes,
    sig_cache: &SigCache,
) -> PreverifiedInputs {
    tx_hashes.assert_for(block);
    let mut done = PreverifiedInputs::default();
    for candidate in candidates(block) {
        done.checked = done.checked.wrapping_add(1);
        if check_candidate(block, tx_hashes, &candidate, sig_cache) {
            done.verified = done.verified.wrapping_add(1);
        }
    }
    done
}

/// What a `Preverifier` has counted.  Relaxed sums for a person to
/// read.
#[cfg(any(test, feature = "std"))]
#[derive(Default)]
struct Counters {
    blocks: AtomicU64,
    refused: AtomicU64,
    inputs: AtomicU64,
    checked: AtomicU64,
    verified: AtomicU64,
    cut_short: AtomicU64,
}

/// What a `Preverifier` has done.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PreverifyCounts {
    /// Blocks queued for pre-verification.
    pub blocks: u64,
    /// Blocks refused because its queue held as many bytes as it may.
    /// Blocks offered after a shutdown are refused too, and not counted.
    pub refused: u64,
    /// The inputs of the queued blocks that got a guess.
    pub inputs: u64,
    /// Those the lane ran.
    pub checked: u64,
    /// Those of the run whose run succeeded: every signature of the
    /// guessed script verified, afresh or from the cache.
    pub verified: u64,
    /// Blocks withdrawn before the lane had run every input that got a
    /// guess: the chain reached them first, or the lane was closed.
    pub cut_short: u64,
}

/// The lane job of one block: its inputs that got a guess, claimed one
/// at a time.
#[cfg(any(test, feature = "std"))]
struct BlockJob {
    block: Arc<MsgBlock>,
    tx_hashes: Arc<BlockTxHashes>,
    sig_cache: Arc<SigCache>,
    candidates: Vec<Candidate>,
    /// The next candidate to claim.
    next: AtomicUsize,
    withdrawn: AtomicBool,
    counters: Arc<Counters>,
}

#[cfg(any(test, feature = "std"))]
impl LaneJob for BlockJob {
    fn step(&self) -> bool {
        if self.withdrawn.load(Ordering::Relaxed) {
            return false;
        }
        let index = self.next.fetch_add(1, Ordering::Relaxed);
        let Some(candidate) = self.candidates.get(index) else {
            return false;
        };
        let verified = check_candidate(&self.block, &self.tx_hashes, candidate, &self.sig_cache);
        self.counters.checked.fetch_add(1, Ordering::Relaxed);
        if verified {
            self.counters.verified.fetch_add(1, Ordering::Relaxed);
        }
        true
    }

    fn exhausted(&self) -> bool {
        self.withdrawn.load(Ordering::Relaxed)
            || self.next.load(Ordering::Relaxed) >= self.candidates.len()
    }

    fn withdraw(&self) {
        if !self.withdrawn.swap(true, Ordering::Relaxed)
            && self.next.load(Ordering::Relaxed) < self.candidates.len()
        {
            self.counters.cut_short.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// A block's number in the pre-verifier it was queued in, for
/// `Preverifier::withdraw_through`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ticket(u64);

/// Signature pre-verification on a lane of the process-wide script
/// pool (see the module documentation).  Dropping it shuts it down.
#[cfg(any(test, feature = "std"))]
pub struct Preverifier {
    lane: LaneHandle,
    sig_cache: Arc<SigCache>,
    /// Blocks at or below this height are not taken.
    floor: AtomicI64,
    counters: Arc<Counters>,
}

#[cfg(any(test, feature = "std"))]
impl Preverifier {
    /// A pre-verifier filling `sig_cache`, on at most `helpers` of the
    /// process-wide script pool's helpers at once, never more than the
    /// pool holds, whose queued blocks hold at most `max_bytes` bytes of
    /// serialized blocks.  `None` when that leaves it no helper: with
    /// `helpers` zero, or a pool of none, as on a machine of one logical
    /// CPU.  Its floor starts at the top: nothing is taken until
    /// `Preverifier::set_floor` lowers it.
    pub fn new(sig_cache: Arc<SigCache>, helpers: usize, max_bytes: usize) -> Option<Preverifier> {
        Preverifier::on_pool(Pool::global(), sig_cache, helpers, max_bytes)
    }

    /// `Preverifier::new` on the given pool.
    pub(crate) fn on_pool(
        pool: &Pool,
        sig_cache: Arc<SigCache>,
        helpers: usize,
        max_bytes: usize,
    ) -> Option<Preverifier> {
        // A lane without a helper is closed again as it is dropped.
        let lane = pool.open_lane(helpers, max_bytes);
        if lane.width() == 0 {
            return None;
        }
        Some(Preverifier {
            lane,
            sig_cache,
            floor: AtomicI64::new(i64::MAX),
            counters: Arc::default(),
        })
    }

    /// The most helpers that check its blocks at once.
    pub fn helpers(&self) -> usize {
        self.lane.width()
    }

    /// Take only blocks above `height` from now on: the chain checks no
    /// script of a block at or below it.  A wrong floor costs work done
    /// for nothing or not done, never a verdict.
    pub fn set_floor(&self, height: i64) {
        self.floor.store(height, Ordering::Relaxed);
    }

    /// The height at and below which blocks are not taken.
    pub fn floor(&self) -> i64 {
        self.floor.load(Ordering::Relaxed)
    }

    /// Queue the block for pre-verification, unless its header's height
    /// is at or below the floor, none of its inputs gets a guess, the
    /// pre-verifier was shut down or its queue would then hold more than
    /// its bytes.  The ticket to withdraw it with, when it was queued.
    ///
    /// The block and its hashes are held by reference count until the
    /// block is withdrawn; nothing of it is copied.
    pub fn submit(&self, block: &HashedBlock) -> Option<Ticket> {
        let height = i64::from(block.block().header.height);
        if height <= self.floor() {
            return None;
        }
        self.submit_hashed(block.block(), block.tx_hashes())
    }

    /// `Preverifier::submit` given the block and its hashes, without
    /// the floor.
    pub(crate) fn submit_hashed(
        &self,
        block: &Arc<MsgBlock>,
        tx_hashes: &Arc<BlockTxHashes>,
    ) -> Option<Ticket> {
        tx_hashes.assert_for(block);
        let candidates = candidates(block);
        if candidates.is_empty() {
            return None;
        }
        let inputs = candidates.len();
        let job = Arc::new(BlockJob {
            block: Arc::clone(block),
            tx_hashes: Arc::clone(tx_hashes),
            sig_cache: Arc::clone(&self.sig_cache),
            candidates,
            next: AtomicUsize::new(0),
            withdrawn: AtomicBool::new(false),
            counters: Arc::clone(&self.counters),
        });
        match self.lane.submit(block.serialize_size(), inputs, job) {
            Ok(seq) => {
                self.counters.blocks.fetch_add(1, Ordering::Relaxed);
                self.counters
                    .inputs
                    .fetch_add(u64::try_from(inputs).unwrap_or(u64::MAX), Ordering::Relaxed);
                Some(Ticket(seq))
            }
            // A block refused for room is counted; one refused because
            // the pre-verifier was shut down is not.
            Err(Refusal::Full) => {
                self.counters.refused.fetch_add(1, Ordering::Relaxed);
                None
            }
            Err(Refusal::Closed) => None,
        }
    }

    /// Withdraw the block of `ticket` and every block queued before it:
    /// no helper starts another input of them, and the pre-verifier
    /// lets go of them.  A helper inside one finishes the input it
    /// holds.
    pub fn withdraw_through(&self, ticket: Ticket) {
        self.lane.withdraw_through(ticket.0);
    }

    /// Refuse every later block, withdraw the queued ones, and return
    /// once no helper is checking one of them.  A helper inside an input
    /// finishes it first.
    pub fn shutdown(&self) {
        self.lane.close();
    }

    /// What it has done so far.
    pub fn counts(&self) -> PreverifyCounts {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let counters = &*self.counters;
        PreverifyCounts {
            blocks: load(&counters.blocks),
            refused: load(&counters.refused),
            inputs: load(&counters.inputs),
            checked: load(&counters.checked),
            verified: load(&counters.verified),
            cut_short: load(&counters.cut_short),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic over small fixed values"
)]
mod tests {
    use std::sync::{Condvar, Mutex};
    use std::time::Duration;

    use dcroxide_stake::TxType;
    use dcroxide_txscript::sign::{SignatureType, raw_tx_in_signature};
    use dcroxide_txscript::{
        OP_2, OP_3, OP_CHECKMULTISIG, OP_CHECKSIGALT, OP_RETURN, OP_SSTXCHANGE,
        SIG_HASH_ANY_ONE_CAN_PAY, SIG_HASH_NONE, SIG_HASH_SINGLE, ScriptBuilder, SigHashType,
    };
    use dcroxide_wire::{BlockHeader, TxIn, TxOut};

    use super::*;
    use crate::RuleError;
    use crate::UtxoEntry;
    use crate::scriptpool::Batch;
    use crate::utxoview::UtxoView;
    use crate::validate::check_block_scripts;

    /// How long a test waits for something that must happen.
    const WATCHDOG: Duration = Duration::from_secs(60);

    /// Poll until `done` holds, failing the test after the watchdog.
    fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
        let start = std::time::Instant::now();
        while !done() {
            assert!(start.elapsed() < WATCHDOG, "timed out waiting until {what}");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn secp_key(tag: u8) -> ([u8; 32], Vec<u8>) {
        let mut private = [tag; 32];
        private[0] = 0x01;
        let public = dcroxide_dcrec::secp256k1::PrivateKey::from_bytes(&private)
            .expect("valid key")
            .public_key()
            .serialize_compressed()
            .to_vec();
        (private, public)
    }

    fn p2pkh(tag: Option<u8>, public: &[u8]) -> Vec<u8> {
        let builder = match tag {
            Some(tag) => ScriptBuilder::new().add_op(tag),
            None => ScriptBuilder::new(),
        };
        builder
            .add_op(OP_DUP)
            .add_op(OP_HASH160)
            .add_data(&dcroxide_txscript::stdaddr::hash160(public))
            .add_op(OP_EQUALVERIFY)
            .add_op(OP_CHECKSIG)
            .script()
            .expect("builds")
    }

    /// How a spent output is locked.
    #[derive(Clone, Copy)]
    enum Lock {
        /// Pay to the hash of the key's public key, behind the first
        /// stake opcode when one is given; the signature is made over
        /// the script behind the second, which is the same one unless a
        /// test wants it otherwise.
        PubKeyHash(u8, Option<u8>, Option<u8>),
        /// Two of the three keys from this one on: two signature pushes.
        TwoOfThree(u8),
        /// The key's public key under Schnorr: one signature push.
        Schnorr(u8),
    }

    impl Lock {
        fn pkh(key: u8, tag: Option<u8>) -> Lock {
            Lock::PubKeyHash(key, tag, tag)
        }

        fn pk_script(self) -> Vec<u8> {
            match self {
                Lock::PubKeyHash(key, tag, _) => p2pkh(tag, &secp_key(key).1),
                Lock::TwoOfThree(key) => ScriptBuilder::new()
                    .add_op(OP_2)
                    .add_data(&secp_key(key).1)
                    .add_data(&secp_key(key + 1).1)
                    .add_data(&secp_key(key + 2).1)
                    .add_op(OP_3)
                    .add_op(OP_CHECKMULTISIG)
                    .script()
                    .expect("builds"),
                Lock::Schnorr(key) => ScriptBuilder::new()
                    .add_data(&secp_key(key).1)
                    .add_op(OP_2)
                    .add_op(OP_CHECKSIGALT)
                    .script()
                    .expect("builds"),
            }
        }

        fn sig_script(self, tx: &MsgTx, idx: usize) -> Vec<u8> {
            let sign = |script: &[u8], key: u8, sig_type| {
                raw_tx_in_signature(tx, idx, script, SIG_HASH_ALL, &secp_key(key).0, sig_type)
                    .expect("signs")
            };
            let ecdsa = SignatureType::EcdsaSecp256k1;
            match self {
                Lock::PubKeyHash(key, _, signed_tag) => {
                    let signed_over = p2pkh(signed_tag, &secp_key(key).1);
                    ScriptBuilder::new()
                        .add_data(&sign(&signed_over, key, ecdsa))
                        .add_data(&secp_key(key).1)
                        .script()
                        .expect("builds")
                }
                Lock::TwoOfThree(key) => {
                    let script = self.pk_script();
                    ScriptBuilder::new()
                        .add_data(&sign(&script, key, ecdsa))
                        .add_data(&sign(&script, key + 2, ecdsa))
                        .script()
                        .expect("builds")
                }
                Lock::Schnorr(key) => ScriptBuilder::new()
                    .add_data(&sign(
                        &self.pk_script(),
                        key,
                        SignatureType::SchnorrSecp256k1,
                    ))
                    .script()
                    .expect("builds"),
            }
        }
    }

    /// One input of a test transaction: the outpoint's tree and index,
    /// and the lock of the output it spends; `None` for a stakebase.
    type Spend = Option<(i8, u32, Lock)>;

    /// A transaction with the given inputs and outputs, every input
    /// signed, the outputs it spends added to the view.  `fill` makes its
    /// outpoints its own.
    fn signed_tx(fill: u8, spends: &[Spend], outputs: Vec<Vec<u8>>, view: &mut UtxoView) -> MsgTx {
        let mut tx = MsgTx {
            tx_in: spends
                .iter()
                .enumerate()
                .map(|(i, spend)| TxIn {
                    previous_out_point: match spend {
                        Some((tree, index, _)) => OutPoint {
                            hash: Hash([fill.wrapping_add(i as u8); 32]),
                            index: *index,
                            tree: *tree,
                        },
                        None => OutPoint {
                            hash: Hash::ZERO,
                            index: u32::MAX,
                            tree: TX_TREE_REGULAR,
                        },
                    },
                    sequence: u32::MAX,
                    ..TxIn::default()
                })
                .collect(),
            tx_out: outputs
                .into_iter()
                .enumerate()
                .map(|(i, pk_script)| TxOut {
                    value: 1_000 + i as i64,
                    version: 0,
                    pk_script,
                })
                .collect(),
            lock_time: u32::from(fill),
            ..MsgTx::default()
        };
        for (idx, spend) in spends.iter().enumerate() {
            let Some((_, _, lock)) = spend else {
                continue;
            };
            tx.tx_in[idx].signature_script = lock.sig_script(&tx, idx);
            view.insert_entry(
                &tx.tx_in[idx].previous_out_point,
                UtxoEntry::new(
                    100_000_000,
                    lock.pk_script(),
                    100,
                    0,
                    0,
                    false,
                    false,
                    TxType::Regular,
                    None,
                ),
            );
        }
        tx
    }

    fn null_data() -> Vec<u8> {
        vec![OP_RETURN, 0x00]
    }

    /// The inputs of [`signed_block`] that get a guess, and those of
    /// them whose guess is the script they spend.
    const CANDIDATES: u64 = 14;
    const RIGHT_GUESSES: u64 = 13;
    /// The entries the connect checks of [`signed_block`] leave in a
    /// cold cache: one for each of its sixteen inputs.  The two
    /// signatures of the multisignature spend share one signature hash,
    /// which is the cache's key, so the second's entry replaces the
    /// first's.
    const SIGNATURES: usize = 16;

    /// A block whose two trees spend every kind of output the guess
    /// tells apart, with one wrong guess and two inputs that get none,
    /// and the view of what it spends.
    ///
    /// The regular tree: a coinbase-style transaction; one of six plain
    /// pay-to-pubkey-hash spends and three of stake outputs, a vote's
    /// payout, a revocation's and a ticket's change, the last of which
    /// the guess takes for a vote's payout; one of a two-of-three
    /// multisignature spend and a Schnorr spend, which get no guess.
    /// The stake tree: a vote spending its ticket, a revocation spending
    /// its ticket, and a ticket purchase spending a plain output, a
    /// vote's payout and a revocation's.
    fn signed_block() -> (MsgBlock, UtxoView) {
        let mut view = UtxoView::new();
        let pkh = |key: u8| Some((TX_TREE_REGULAR, 0, Lock::pkh(key, None)));
        let staked =
            |index: u32, key: u8, tag: u8| Some((TX_TREE_STAKE, index, Lock::pkh(key, Some(tag))));
        let plain: Vec<Spend> = (0..6u8).map(|i| pkh(0x40 + i)).collect();
        let mut stake_spends = plain;
        stake_spends.extend([
            staked(2, 0x50, OP_SSGEN),
            staked(0, 0x51, OP_SSRTX),
            staked(2, 0x52, OP_SSTXCHANGE),
        ]);
        let transactions = vec![
            signed_tx(0x01, &[None], vec![null_data()], &mut view),
            signed_tx(0x10, &stake_spends, vec![null_data()], &mut view),
            signed_tx(
                0x20,
                &[
                    Some((TX_TREE_REGULAR, 0, Lock::TwoOfThree(0x60))),
                    Some((TX_TREE_REGULAR, 1, Lock::Schnorr(0x64))),
                ],
                vec![null_data()],
                &mut view,
            ),
        ];
        let vote = signed_tx(
            0x30,
            &[None, staked(0, 0x70, OP_SSTX)],
            vec![
                null_data(),
                null_data(),
                p2pkh(Some(OP_SSGEN), &secp_key(0x71).1),
            ],
            &mut view,
        );
        let revocation = signed_tx(
            0x38,
            &[staked(0, 0x72, OP_SSTX)],
            vec![p2pkh(Some(OP_SSRTX), &secp_key(0x73).1)],
            &mut view,
        );
        let ticket = signed_tx(
            0x40,
            &[
                pkh(0x74),
                staked(3, 0x75, OP_SSGEN),
                staked(0, 0x76, OP_SSRTX),
            ],
            vec![
                p2pkh(Some(OP_SSTX), &secp_key(0x77).1),
                null_data(),
                p2pkh(Some(OP_SSTXCHANGE), &secp_key(0x78).1),
            ],
            &mut view,
        );
        let block = MsgBlock {
            header: BlockHeader::from_bytes(&[0u8; 180]).expect("zero header").0,
            transactions,
            stransactions: vec![vote, revocation, ticket],
        };
        (block, view)
    }

    /// The script check of both trees, as the chain runs it after the
    /// assume-valid block, with the given cache.
    fn verdicts(
        block: &MsgBlock,
        view: &UtxoView,
        cache: Option<&SigCache>,
    ) -> [Result<(), RuleError>; 2] {
        [false, true].map(|regular| check_block_scripts(block, view, regular, FLAGS, cache, true))
    }

    /// `entries` where the signature cache keeps entries, and none where
    /// it is the script crate's inert stand-in, as it is in a build
    /// without `std`.
    fn stored(entries: usize) -> usize {
        if cfg!(feature = "std") { entries } else { 0 }
    }

    /// The entries of the caches [`four_ways`] used: the one the
    /// connect checks filled alone, and those `preverify_block` and a
    /// lane filled, before the connect checks ran and after.
    #[derive(Debug, PartialEq, Eq)]
    struct Entries {
        cold: usize,
        preverified: [usize; 2],
        lane: [usize; 2],
    }

    /// The verdicts of both trees without a cache, with a cold one, with
    /// one `preverify_block` filled and with one a lane filled, which
    /// must all be the same; returned with what the two pre-verifications
    /// counted and the entries of the caches.
    fn four_ways(
        block: &MsgBlock,
        view: &UtxoView,
    ) -> (
        [Result<(), RuleError>; 2],
        PreverifiedInputs,
        PreverifyCounts,
        Entries,
    ) {
        let bare = verdicts(block, view, None);
        let cold_cache = SigCache::new(1_000);
        let cold = verdicts(block, view, Some(&cold_cache));
        assert_eq!(cold, bare, "a cold cache");

        let warmed = SigCache::new(1_000);
        let tx_hashes = BlockTxHashes::compute(block);
        let done = preverify_block(block, &tx_hashes, &warmed);
        let preverified = warmed.len();
        assert_eq!(verdicts(block, view, Some(&warmed)), bare, "pre-verified");

        let pool = Pool::for_tests(3);
        let cache = Arc::new(SigCache::new(1_000));
        let preverifier =
            Preverifier::on_pool(&pool, Arc::clone(&cache), 2, usize::MAX).expect("a lane");
        let shared = Arc::new(block.clone());
        let ticket = preverifier.submit_hashed(&shared, &Arc::new(tx_hashes));
        assert_eq!(ticket.is_some(), done.checked > 0);
        // A unit is counted once its run, and what it added, is done.
        wait_until("the lane has run every input", || {
            let counts = preverifier.counts();
            counts.checked == counts.inputs
        });
        let lane = cache.len();
        assert_eq!(
            verdicts(block, view, Some(&cache)),
            bare,
            "pre-verified on a lane"
        );
        preverifier.shutdown();
        assert_eq!(
            Arc::strong_count(&shared),
            1,
            "the lane let go of the block"
        );
        let entries = Entries {
            cold: cold_cache.len(),
            preverified: [preverified, warmed.len()],
            lane: [lane, cache.len()],
        };
        (bare, done, preverifier.counts(), entries)
    }

    /// The template, the stake opcode chosen for each kind of spend, and
    /// the scripts guessed from them.
    #[test]
    fn the_guess_is_made_for_the_one_template() {
        let (_, key) = secp_key(0x11);
        let mut sig = [0x30u8; 72];
        sig[71] = SIG_HASH_ALL.0;
        let script = |pushes: &[&[u8]]| {
            let mut builder = ScriptBuilder::new();
            for push in pushes {
                builder = builder.add_data(push);
            }
            builder.script().expect("builds")
        };
        let both = script(&[&sig, &key]);
        assert_eq!(sig_and_key(&both), Some((&sig[..], &key[..])));
        let uncompressed = [0x04u8; 65];
        assert!(sig_and_key(&script(&[&sig, &uncompressed])).is_some());
        // The shortest a builder pushes with OP_DATA_N: one byte and the
        // hash type (a lone 0x01 is pushed as OP_1).
        assert!(sig_and_key(&script(&[&sig[70..], &key])).is_some());
        assert!(sig_and_key(&[&[0x01, SIG_HASH_ALL.0][..], &script(&[&key])].concat()).is_some());
        for (what, bad) in [
            ("empty", Vec::new()),
            ("one push", script(&[&sig])),
            ("three pushes", script(&[&sig, &key, &key])),
            ("a 32-byte key", script(&[&sig, &key[..32]])),
            ("a 34-byte key", script(&[&sig, &[0x02; 34]])),
            ("a trailing byte", [both.as_slice(), &[0x51]].concat()),
            ("a truncated key", both[..both.len() - 1].to_vec()),
            (
                "an empty signature",
                [&[0x00u8][..], &script(&[&key])].concat(),
            ),
            (
                "a signature behind OP_PUSHDATA1",
                [&[0x4c, 72][..], &sig, &script(&[&key])].concat(),
            ),
            (
                "a signature of 76 bytes",
                script(&[&[&[0x30; 75][..], &[SIG_HASH_ALL.0]].concat(), &key]),
            ),
            ("a signature running off the end", vec![0x48, 0x30]),
        ] {
            assert_eq!(sig_and_key(&bad), None, "{what}");
        }
        // A signature of any other hash type, whose signature hash
        // serializes the whole prefix again.
        for hash_type in [0x00, 0x02, 0x03, 0x41, 0x81, 0x82, 0x83] {
            let mut other = sig;
            other[71] = hash_type;
            assert_eq!(
                sig_and_key(&script(&[&other, &key])),
                None,
                "hash type {hash_type:#x}"
            );
        }

        // A real signature under each hash type: only `SigHashAll` gets
        // a guess, which verifies and is cached.
        let (private, public) = secp_key(0x12);
        let spent = p2pkh(None, &public);
        let any_one_can_pay =
            |hash_type: SigHashType| SigHashType(hash_type.0 | SIG_HASH_ANY_ONE_CAN_PAY.0);
        for (hash_type, want) in [
            (SIG_HASH_ALL, Some(true)),
            (SIG_HASH_NONE, None),
            (SIG_HASH_SINGLE, None),
            (any_one_can_pay(SIG_HASH_ALL), None),
            (any_one_can_pay(SIG_HASH_NONE), None),
        ] {
            let mut tx = MsgTx {
                tx_in: vec![TxIn {
                    previous_out_point: OutPoint {
                        hash: Hash([7; 32]),
                        index: 0,
                        tree: TX_TREE_REGULAR,
                    },
                    sequence: u32::MAX,
                    ..TxIn::default()
                }],
                tx_out: vec![TxOut {
                    value: 1,
                    version: 0,
                    pk_script: null_data(),
                }],
                ..MsgTx::default()
            };
            let signature = raw_tx_in_signature(
                &tx,
                0,
                &spent,
                hash_type,
                &private,
                SignatureType::EcdsaSecp256k1,
            )
            .expect("signs");
            tx.tx_in[0].signature_script = ScriptBuilder::new()
                .add_data(&signature)
                .add_data(&public)
                .script()
                .expect("builds");
            let cache = SigCache::new(10);
            assert_eq!(
                preverify_input(&tx, 0, &tx.tx_hash(), false, &cache),
                want,
                "{hash_type:?}"
            );
            assert_eq!(
                cache.len(),
                stored(usize::from(want.is_some())),
                "{hash_type:?}"
            );
        }

        let out = |tree, index| OutPoint {
            hash: Hash([1; 32]),
            index,
            tree,
        };
        let spender = |first: Vec<u8>| MsgTx {
            tx_out: vec![TxOut {
                value: 0,
                version: 0,
                pk_script: first,
            }],
            ..MsgTx::default()
        };
        let vote = spender(null_data());
        let ticket = spender(p2pkh(Some(OP_SSTX), &key));
        let plain = MsgTx::default();
        for (spender, prev, stake_tree, want) in [
            (&plain, out(TX_TREE_REGULAR, 0), false, Some(None)),
            (&plain, out(TX_TREE_REGULAR, 7), true, Some(None)),
            (&vote, out(TX_TREE_STAKE, 0), true, Some(Some(OP_SSTX))),
            (&plain, out(TX_TREE_STAKE, 0), true, Some(Some(OP_SSTX))),
            (&ticket, out(TX_TREE_STAKE, 0), true, Some(Some(OP_SSRTX))),
            (&vote, out(TX_TREE_STAKE, 0), false, Some(Some(OP_SSRTX))),
            (&plain, out(TX_TREE_STAKE, 1), true, Some(Some(OP_SSRTX))),
            (&ticket, out(TX_TREE_STAKE, 2), true, Some(Some(OP_SSGEN))),
            (&plain, out(TX_TREE_STAKE, 9), false, Some(Some(OP_SSGEN))),
            (&plain, out(2, 0), false, None),
            (&plain, out(-1, 0), true, None),
        ] {
            assert_eq!(
                guessed_tag(spender, &prev, stake_tree),
                want,
                "{prev:?} from the stake tree: {stake_tree}"
            );
        }

        // A coinbase-style input gets no guess, whatever its signature
        // script holds: no script of it is ever checked.
        let mut coinbase = MsgTx::default();
        coinbase.tx_in.push(TxIn {
            previous_out_point: OutPoint {
                hash: Hash::ZERO,
                index: u32::MAX,
                tree: TX_TREE_REGULAR,
            },
            signature_script: both.clone(),
            ..TxIn::default()
        });
        let cache = SigCache::new(10);
        assert_eq!(
            preverify_input(&coinbase, 0, &coinbase.tx_hash(), false, &cache),
            None
        );
        let shaped = MsgBlock {
            header: BlockHeader::from_bytes(&[0u8; 180]).expect("zero header").0,
            transactions: vec![coinbase.clone()],
            stransactions: vec![coinbase],
        };
        assert!(candidates(&shaped).is_empty());

        for tag in [None, Some(OP_SSTX), Some(OP_SSGEN), Some(OP_SSRTX)] {
            assert_eq!(Guess::new(tag, &key).script(), p2pkh(tag, &key).as_slice());
        }
        assert_eq!(
            Guess::new(None, &uncompressed).script(),
            p2pkh(None, &uncompressed)
        );
    }

    /// A block's scripts get the same verdict whether its signatures
    /// were pre-verified or not: `Ok`, and for any one bad signature,
    /// in either tree, guessed for or not, the same error naming the
    /// same input.  The guesses are made for the inputs they should be
    /// and verify where they are right, and what they cache is what the
    /// connect checks then find: the checks add only the entries of the
    /// inputs no right guess reached, and end with the entries they
    /// leave in a cold cache, where a guess cached under another hash
    /// would leave more.
    #[test]
    fn pre_verified_blocks_get_the_verdicts_they_get_without() {
        let (block, view) = signed_block();
        let (verdict, done, counts, entries) = four_ways(&block, &view);
        assert_eq!(verdict, [Ok(()), Ok(())]);
        let right = stored(RIGHT_GUESSES as usize);
        let all = stored(SIGNATURES);
        assert_eq!(
            entries,
            Entries {
                cold: all,
                preverified: [right, all],
                lane: [right, all],
            }
        );
        assert_eq!(
            done,
            PreverifiedInputs {
                checked: CANDIDATES,
                verified: RIGHT_GUESSES,
            }
        );
        assert_eq!(
            counts,
            PreverifyCounts {
                blocks: 1,
                refused: 0,
                inputs: CANDIDATES,
                checked: CANDIDATES,
                verified: RIGHT_GUESSES,
                cut_short: 0,
            }
        );
        let found = candidates(&block);
        assert_eq!(found.len() as u64, CANDIDATES);
        // The stake tree's first, then the regular tree's; the vote's
        // stakebase and the inputs without the template are left out.
        assert!(found[..5].iter().all(|c| c.stake));
        assert_eq!(
            found[..2]
                .iter()
                .map(|c| (c.tx_idx, c.tx_in_idx, c.tag))
                .collect::<Vec<_>>(),
            [(0, 1, Some(OP_SSTX)), (1, 0, Some(OP_SSTX))]
        );
        assert!(found[5..].iter().all(|c| !c.stake && c.tx_idx == 1));

        // One bad signature at a time, wherever it is.
        let mut places = Vec::new();
        for (stake, txs) in [(true, &block.stransactions), (false, &block.transactions)] {
            for (tx_idx, tx) in txs.iter().enumerate() {
                for (tx_in_idx, tx_in) in tx.tx_in.iter().enumerate() {
                    if tx_in.previous_out_point.index != u32::MAX {
                        places.push((stake, tx_idx, tx_in_idx));
                    }
                }
            }
        }
        assert_eq!(places.len(), 16);
        for (stake, tx_idx, tx_in_idx) in places {
            let mut forged = block.clone();
            {
                let txs = if stake {
                    &mut forged.stransactions
                } else {
                    &mut forged.transactions
                };
                txs[tx_idx].tx_in[tx_in_idx].signature_script[10] ^= 0x01;
            }
            let (verdict, _, _, _) = four_ways(&forged, &view);
            let tree = usize::from(!stake);
            let err = verdict[tree].clone().expect_err("a bad signature");
            let tx = if stake {
                &forged.stransactions[tx_idx]
            } else {
                &forged.transactions[tx_idx]
            };
            assert!(
                err.description.starts_with(&format!(
                    "failed to validate input {}:{tx_in_idx} ",
                    tx.tx_hash()
                )),
                "{}",
                err.description
            );
            assert_eq!(verdict[1 - tree], Ok(()));
        }
    }

    /// Signatures that do not verify for their input are never taken
    /// for ones that do: a forged signature, one made with another key
    /// and one made for another input of the transaction fail their
    /// pre-verification and are rejected at connect as they are
    /// without it.
    #[test]
    fn a_forged_or_mismatched_signature_is_never_cached() {
        let (block, view) = signed_block();
        let regular = 1;
        type Spoil = fn(&mut MsgTx);
        let cases: [(&str, Spoil); 3] = [
            ("forged", |tx| tx.tx_in[0].signature_script[12] ^= 0x80),
            ("another key", |tx| {
                // The signature of input 1, whose key differs, behind
                // input 0's own key.
                let theirs = sig_and_key(&tx.tx_in[1].signature_script)
                    .map(|(sig, _)| sig.to_vec())
                    .expect("template");
                let mine = sig_and_key(&tx.tx_in[0].signature_script)
                    .map(|(_, key)| key.to_vec())
                    .expect("template");
                tx.tx_in[0].signature_script = ScriptBuilder::new()
                    .add_data(&theirs)
                    .add_data(&mine)
                    .script()
                    .expect("builds");
            }),
            ("another input", |tx| {
                // Input 1's whole signature script on input 0.
                tx.tx_in[0].signature_script = tx.tx_in[1].signature_script.clone();
            }),
        ];
        for (what, spoil) in cases {
            let mut bad = block.clone();
            spoil(&mut bad.transactions[regular]);
            let (verdict, done, counts, _) = four_ways(&bad, &view);
            assert_eq!(verdict[0], Ok(()), "{what}: the stake tree");
            let err = verdict[1].clone().expect_err(what);
            assert!(
                err.description.starts_with(&format!(
                    "failed to validate input {}:0 ",
                    bad.transactions[regular].tx_hash()
                )),
                "{what}: {}",
                err.description
            );
            assert_eq!(done.verified, RIGHT_GUESSES - 1, "{what}");
            assert_eq!(counts.verified, RIGHT_GUESSES - 1, "{what}");
        }
    }

    /// A signature made over the script the lane guesses, where the
    /// output spent pays to another, verifies on the lane and is cached
    /// under the guessed script's signature hash, which the connect
    /// check of that input does not compute: the input is rejected as
    /// it is without pre-verification.
    #[test]
    fn a_signature_over_the_guessed_script_does_not_pass_for_the_spent_one() {
        for (prev_tree, index, spent, guessed) in [
            (TX_TREE_STAKE, 2, Some(OP_SSTXCHANGE), Some(OP_SSGEN)),
            (TX_TREE_STAKE, 0, Some(OP_SSGEN), Some(OP_SSRTX)),
            (TX_TREE_REGULAR, 0, Some(OP_SSGEN), None),
        ] {
            let mut view = UtxoView::new();
            let spends = [
                Some((TX_TREE_REGULAR, 0, Lock::pkh(0x21, None))),
                Some((prev_tree, index, Lock::PubKeyHash(0x22, spent, guessed))),
            ];
            let tx = signed_tx(0x50, &spends, vec![null_data()], &mut view);
            let block = MsgBlock {
                header: BlockHeader::from_bytes(&[0u8; 180]).expect("zero header").0,
                transactions: vec![tx],
                stransactions: Vec::new(),
            };
            let (verdict, done, counts, entries) = four_ways(&block, &view);
            let err = verdict[1].clone().expect_err("signed over another script");
            assert!(
                err.description.starts_with(&format!(
                    "failed to validate input {}:1 ",
                    block.transactions[0].tx_hash()
                )),
                "{}",
                err.description
            );
            // Both inputs verified on the lane: the second against the
            // script its signature was made over, under a signature hash
            // its connect check does not compute.  The check finds the
            // first input's entry, not the second's, and adds nothing.
            assert_eq!(done.verified, 2);
            assert_eq!(counts.verified, 2);
            assert_eq!(
                entries,
                Entries {
                    cold: stored(1),
                    preverified: [stored(2); 2],
                    lane: [stored(2); 2],
                }
            );
        }
    }

    /// A withdrawn block hands out no more inputs, and is counted cut
    /// short once, when inputs were left; one whose every input was
    /// handed out is not.
    #[test]
    fn a_withdrawn_block_hands_out_no_more_inputs() {
        let (block, _) = signed_block();
        let block = Arc::new(block);
        let tx_hashes = Arc::new(BlockTxHashes::compute(&block));
        let counters = Arc::new(Counters::default());
        let job = |candidates: Vec<Candidate>| BlockJob {
            block: Arc::clone(&block),
            tx_hashes: Arc::clone(&tx_hashes),
            sig_cache: Arc::new(SigCache::new(100)),
            candidates,
            next: AtomicUsize::new(0),
            withdrawn: AtomicBool::new(false),
            counters: Arc::clone(&counters),
        };
        let all = candidates(&block);

        let cut = job(all.clone());
        assert!(cut.step());
        assert!(!cut.exhausted());
        cut.withdraw();
        cut.withdraw();
        assert!(cut.exhausted());
        assert!(!cut.step());
        assert_eq!(counters.cut_short.load(Ordering::SeqCst), 1);
        assert_eq!(counters.checked.load(Ordering::SeqCst), 1);

        let done = job(all[..2].to_vec());
        assert!(done.step() && done.step());
        assert!(done.exhausted());
        assert!(!done.step());
        done.withdraw();
        assert_eq!(counters.cut_short.load(Ordering::SeqCst), 1);
        assert_eq!(counters.checked.load(Ordering::SeqCst), 3);
        assert_eq!(counters.verified.load(Ordering::SeqCst), 3);
    }

    /// Only blocks above the floor are taken, the floor starting at the
    /// top, and a block with nothing to guess is not queued.
    #[test]
    fn blocks_at_or_below_the_floor_are_not_taken() {
        let (mut block, _) = signed_block();
        block.header.height = 500;
        let hashed = HashedBlock::new(Arc::new(block));
        let pool = Pool::for_tests(2);
        let preverifier = Preverifier::on_pool(&pool, Arc::new(SigCache::new(100)), 1, usize::MAX)
            .expect("a lane");
        assert_eq!(preverifier.floor(), i64::MAX);
        assert_eq!(preverifier.submit(&hashed), None);
        preverifier.set_floor(500);
        assert_eq!(preverifier.submit(&hashed), None);
        preverifier.set_floor(499);
        let ticket = preverifier.submit(&hashed).expect("taken");
        preverifier.set_floor(-1);
        let unsigned = HashedBlock::new(Arc::new(MsgBlock {
            header: hashed.block().header,
            transactions: vec![MsgTx::default()],
            stransactions: Vec::new(),
        }));
        assert_eq!(preverifier.submit(&unsigned), None);
        preverifier.withdraw_through(ticket);
        let counts = preverifier.counts();
        assert_eq!((counts.blocks, counts.refused), (1, 0));
        assert_eq!(counts.inputs, CANDIDATES);
    }

    /// Asked for no helper, or on a pool of none, there is no
    /// pre-verifier: the node then runs as it does without one.
    #[test]
    fn no_helper_means_no_preverifier() {
        let cache = Arc::new(SigCache::new(100));
        let pool = Pool::for_tests(4);
        assert!(Preverifier::on_pool(&pool, Arc::clone(&cache), 0, usize::MAX).is_none());
        let none = Pool::for_tests(0);
        assert!(Preverifier::on_pool(&none, Arc::clone(&cache), 4, usize::MAX).is_none());
        let some = Preverifier::on_pool(&pool, cache, 9, usize::MAX).expect("a lane");
        assert_eq!(some.helpers(), 4);
    }

    /// A batch that holds every helper of its pool until it is let go.
    struct Hold {
        len: usize,
        inside: Arc<(Mutex<(usize, bool)>, Condvar)>,
    }

    impl Batch for Hold {
        fn len(&self) -> usize {
            self.len
        }

        fn check(&self, _index: usize) -> Result<(), RuleError> {
            let (state, changed) = &*self.inside;
            let mut state = state.lock().expect("hold poisoned");
            state.0 += 1;
            changed.notify_all();
            let (_state, timeout) = changed
                .wait_timeout_while(state, WATCHDOG, |state| !state.1)
                .expect("hold poisoned");
            assert!(!timeout.timed_out(), "the hold was let go");
            Ok(())
        }
    }

    /// Shut down with blocks queued and the helpers busy elsewhere: the
    /// blocks are let go unchecked, the shutdown does not wait for the
    /// helpers, later blocks are refused without being counted as
    /// refused for room, and the helpers are free for batches
    /// afterwards.
    #[test]
    fn shutdown_with_blocks_queued_lets_go_of_every_block() {
        let (block, _) = signed_block();
        let pool = Arc::new(Pool::for_tests(1));
        let preverifier = Preverifier::on_pool(&pool, Arc::new(SigCache::new(100)), 1, usize::MAX)
            .expect("a lane");
        let inside = Arc::new((Mutex::new((0usize, false)), Condvar::new()));
        std::thread::scope(|s| {
            // The pool's one helper and the submitter are held inside a
            // batch, so the lane gets no helper.
            let hold = s.spawn({
                let (pool, inside) = (Arc::clone(&pool), Arc::clone(&inside));
                move || pool.run(Hold { len: 2, inside })
            });
            wait_until("both are held", || {
                inside.0.lock().expect("hold poisoned").0 == 2
            });

            let blocks: Vec<Arc<MsgBlock>> = (0..8).map(|_| Arc::new(block.clone())).collect();
            for shared in &blocks {
                let tx_hashes = Arc::new(BlockTxHashes::compute(shared));
                assert!(preverifier.submit_hashed(shared, &tx_hashes).is_some());
            }
            preverifier.shutdown();
            for shared in &blocks {
                assert_eq!(Arc::strong_count(shared), 1, "a queued block was let go");
            }
            let tx_hashes = Arc::new(BlockTxHashes::compute(&blocks[0]));
            assert_eq!(preverifier.submit_hashed(&blocks[0], &tx_hashes), None);
            let counts = preverifier.counts();
            assert_eq!(
                (
                    counts.blocks,
                    counts.refused,
                    counts.checked,
                    counts.cut_short
                ),
                (8, 0, 0, 8)
            );

            inside.0.lock().expect("hold poisoned").1 = true;
            inside.1.notify_all();
            assert_eq!(hold.join().expect("the hold returns"), Ok(()));
        });
        // Shutting down twice is harmless, and so is dropping.
        preverifier.shutdown();
        drop(preverifier);
    }

    /// The connect checks of the chain, on the process-wide pool, give
    /// the verdicts they give alone while a lane of that same pool
    /// pre-verifies the block they check: for the block and for it with
    /// each input's signature spoiled in turn, round after round, each
    /// time with a cache of its own, so that what the checks find there
    /// the lane put there.  In every other round the checks start only
    /// once the lane has cached a signature of the block (has run an
    /// input, where the cache keeps nothing), so that they surely run
    /// beside a lane at work; in the others they may start first.
    /// Whichever ran first, the unspoiled block's cache ends with the
    /// entries the checks alone would have made.
    #[test]
    fn pooled_connect_checks_racing_the_lane_give_the_same_verdicts() {
        use crate::validate::{ScriptRunner, check_block_scripts_with_hashes};

        let pool = Pool::global();
        if pool.width() == 0 {
            return;
        }
        let (block, view) = signed_block();
        let mut variants = vec![block.clone()];
        for (stake, txs) in [(true, &block.stransactions), (false, &block.transactions)] {
            for (tx_idx, tx) in txs.iter().enumerate() {
                for (tx_in_idx, tx_in) in tx.tx_in.iter().enumerate() {
                    if tx_in.previous_out_point.index == u32::MAX {
                        continue;
                    }
                    let mut spoiled = block.clone();
                    let txs = if stake {
                        &mut spoiled.stransactions
                    } else {
                        &mut spoiled.transactions
                    };
                    txs[tx_idx].tx_in[tx_in_idx].signature_script[10] ^= 0x01;
                    variants.push(spoiled);
                }
            }
        }
        assert_eq!(variants.len(), 17);
        let alone: Vec<[Result<(), RuleError>; 2]> = variants
            .iter()
            .map(|variant| verdicts(variant, &view, None))
            .collect();

        let (mut blocks, mut checked) = (0, 0);
        for round in 0..10 {
            for (index, (variant, want)) in variants.iter().zip(&alone).enumerate() {
                let cache = Arc::new(SigCache::new(1_000));
                let preverifier =
                    Preverifier::new(Arc::clone(&cache), pool.width(), usize::MAX).expect("a lane");
                preverifier.set_floor(-1);
                let hashed = HashedBlock::new(Arc::new(variant.clone()));
                let ticket = preverifier.submit(&hashed).expect("queued");
                if round % 2 == 1 {
                    wait_until("the lane has cached a signature", || {
                        if cfg!(feature = "std") {
                            !cache.is_empty()
                        } else {
                            preverifier.counts().checked > 0
                        }
                    });
                }
                let got = [false, true].map(|regular| {
                    check_block_scripts_with_hashes(
                        hashed.block(),
                        hashed.tx_hashes(),
                        &view,
                        regular,
                        FLAGS,
                        ScriptRunner::Pooled {
                            block: hashed.block(),
                            tx_hashes: hashed.tx_hashes(),
                            sig_cache: Some(&cache),
                        },
                        true,
                    )
                });
                assert_eq!(&got, want, "round {round}, variant {index}");
                preverifier.withdraw_through(ticket);
                preverifier.shutdown();
                let counts = preverifier.counts();
                assert!(counts.checked <= counts.inputs);
                blocks += counts.blocks;
                checked += counts.checked;
                if index == 0 {
                    assert_eq!(cache.len(), stored(SIGNATURES), "round {round}");
                }
            }
        }
        assert_eq!(blocks, 170);
        assert!(checked > 0, "the lane ran");
    }
}
