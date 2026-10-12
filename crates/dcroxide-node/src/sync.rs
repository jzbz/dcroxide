// SPDX-License-Identifier: ISC
//! The daemon's seams for the ported netsync sync manager — the
//! adapters dcrd's `netsync.Config` receives as its chain, mempool,
//! and mixpool instances.
//!
//! [`NodeSyncChain`] adapts the shared chain behind its mutex to the
//! manager's [`SyncChain`] trait, injecting the server's median-adjusted
//! time ([`crate::mediantime`]) where dcrd's blockchain reads its
//! median-time source.  [`new_sync_manager`] builds the daemon's manager
//! over it, the shared mempool ([`crate::txmempool::NodeSyncTxPool`]),
//! and the shared mixing pool ([`crate::mixnode::NodeSyncMixPool`]);
//! the daemon drives that manager from the peer dispatch path
//! ([`crate::dispatch`]).  [`default_block_window`] is the block
//! download window that manager syncs with, and
//! [`apply_block_window_setting`] the operator's way to choose another,
//! dcrd's included.  [`SyncGate`] exposes the manager's is-current
//! state (dcrd `SyncManager.IsCurrent`) to the gates that cannot take
//! the manager lock.  [`NullTxPool`] and [`NullMixPool`] are empty-pool
//! test doubles for exercising the chain adapter on its own.

use std::sync::{Arc, Mutex};

use dcroxide_blockchain::process::{Chain, is_persisted_db_corruption};
use dcroxide_blockchain::{HashedBlock, RuleError, RuleErrorKind, render_multi_error};
use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_netsync::manager::{
    BUDGET_WINDOW_BLOCKS, BestSnapshot, BlockWindow, Config, LogLevel, MAX_BUDGET_WINDOW_BLOCKS,
    MAX_IN_FLIGHT_BLOCKS, ProcessBlockFailure, ProcessTxFailure, SyncChain, SyncManager,
    SyncMixPool, SyncTxPool,
};
use dcroxide_uint256::Uint256;
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx};

/// The daemon's concrete sync manager over the shared chain, mempool,
/// and mixing pool.
pub type NodeSyncManager =
    SyncManager<NodeSyncChain, crate::txmempool::NodeSyncTxPool, crate::mixnode::NodeSyncMixPool>;

/// The maximum number of recently confirmed transactions to track
/// (dcrd `maxRecentlyConfirmedTxns`: about one hour of main network
/// blocks full of minimum-size transactions).
const MAX_RECENTLY_CONFIRMED_TXNS: u32 = 23000;

/// The false positive rate for the recently-confirmed filter (dcrd
/// `recentlyConfirmedTxnsFPRate`).
const RECENTLY_CONFIRMED_TXNS_FP_RATE: f64 = 0.000001;

/// A block a peer delivered, on its way through the sync manager to the
/// chain (dcrd's `*dcrutil.Block`, handed from `OnBlock` to
/// `ProcessBlock`).
///
/// The block is shared by reference count either way, and the chain
/// keeps that allocation.  What differs is whether its transactions have
/// been hashed yet: a block the connection's reader thread read ahead
/// arrives with its hashes ([`crate::readahead`]), and every other block
/// arrives without and is hashed inside the chain, where dcrd's
/// `ProcessBlock` first asks for them.
pub enum ArrivedBlock {
    /// The block as it was decoded.
    Plain(Arc<MsgBlock>),
    /// The block with the hashes computed from it.
    Hashed(HashedBlock),
}

impl ArrivedBlock {
    /// The block's hash: the one already computed for a hashed block,
    /// and the header hashed here otherwise.
    pub fn hash(&self) -> Hash {
        match self {
            ArrivedBlock::Plain(block) => block.header.block_hash(),
            ArrivedBlock::Hashed(hashed) => *hashed.hash(),
        }
    }
}

impl std::ops::Deref for ArrivedBlock {
    type Target = MsgBlock;

    fn deref(&self) -> &MsgBlock {
        match self {
            ArrivedBlock::Plain(block) => block,
            ArrivedBlock::Hashed(hashed) => hashed.block(),
        }
    }
}

/// A block from a local source, the RPC server or the CPU miner, arrives
/// without hashes.
impl From<Arc<MsgBlock>> for ArrivedBlock {
    fn from(block: Arc<MsgBlock>) -> ArrivedBlock {
        ArrivedBlock::Plain(block)
    }
}

/// The chain adapter handing the manager the shared chain instance
/// (dcrd passes `s.chain` directly; the mutex stands in for Go's
/// internal chain locking).
pub struct NodeSyncChain {
    chain: Arc<Mutex<Chain>>,
    params: Params,
    ntfn_handler: Option<crate::chainntfns::ChainNtfnHandler>,
}

impl NodeSyncChain {
    /// Adapt the shared chain for the sync manager.
    pub fn new(chain: Arc<Mutex<Chain>>, params: Params) -> NodeSyncChain {
        NodeSyncChain {
            chain,
            params,
            ntfn_handler: None,
        }
    }

    /// Install the chain event handler whose deferred winning-tickets
    /// lookups drain after each processing call (dcrd runs the lookup
    /// in its handler with the chain lock released; the daemon's
    /// callback runs under the chain mutex, so the lookup waits here).
    pub fn set_chain_ntfn_handler(&mut self, handler: crate::chainntfns::ChainNtfnHandler) {
        self.ntfn_handler = Some(handler);
    }

    fn locked(&self) -> std::sync::MutexGuard<'_, Chain> {
        self.chain.lock().expect("chain mutex poisoned")
    }
}

/// The current unix time adjusted by the median of the peers' clock
/// samples (dcrd's `timeSource.AdjustedTime()`, the chain's and sync
/// manager's time source).
fn adjusted_time_unix() -> i64 {
    crate::mediantime::adjusted_time_unix()
}

impl SyncChain for NodeSyncChain {
    type Block = ArrivedBlock;

    fn best_header(&mut self) -> (Hash, i64) {
        self.locked().best_header()
    }

    fn header_by_hash(&mut self, hash: &Hash) -> Option<BlockHeader> {
        self.locked().header_by_hash(hash)
    }

    fn block_locator_from_hash(&mut self, hash: &Hash) -> Vec<Hash> {
        self.locked().block_locator_from_hash(hash)
    }

    fn put_next_needed_blocks(&mut self, max_results: usize) -> Vec<Hash> {
        self.locked().put_next_needed_blocks(max_results)
    }

    fn best_snapshot(&mut self) -> BestSnapshot {
        let chain = self.locked();
        let best = chain.best_snapshot();
        BestSnapshot {
            hash: best.hash,
            height: best.height,
            next_stake_diff: best.next_stake_diff,
        }
    }

    fn is_current(&mut self) -> bool {
        self.locked().is_current_at(adjusted_time_unix())
    }

    fn maybe_update_is_current(&mut self) {
        self.locked()
            .maybe_update_is_current_at(adjusted_time_unix());
    }

    fn adjusted_time_unix(&mut self) -> i64 {
        adjusted_time_unix()
    }

    fn chain_work(&mut self, hash: &Hash) -> Option<Uint256> {
        self.locked().chain_work(hash)
    }

    fn have_header(&mut self, hash: &Hash) -> bool {
        self.locked().have_header(hash)
    }

    fn have_block(&mut self, hash: &Hash) -> bool {
        self.locked().have_block(hash)
    }

    fn process_block_header(&mut self, header: &BlockHeader) -> Result<(), ProcessBlockFailure> {
        let mut chain = self.locked();
        let err = match chain.process_block_header(header, adjusted_time_unix(), &self.params) {
            Ok(()) => return Ok(()),
            Err(err) => err,
        };

        // Classified the way a block failure is (see
        // `combine_process_block_result`): a persistence failure
        // latched by the store is a disk fault, not a rejected header.
        let storage_failed = chain
            .db
            .as_ref()
            .is_some_and(dcroxide_database::Database::is_fatal);
        Err(ProcessBlockFailure {
            is_duplicate_block: false,
            is_rule_error: !storage_failed && err.kind.is_rule_violation(),
            is_corruption: is_corruption(&err),
            message: err.description,
        })
    }

    fn process_block(&mut self, block: &ArrivedBlock) -> Result<i64, ProcessBlockFailure> {
        // The chain keeps this very allocation in its mirror of recent
        // blocks (dcrd's `ProcessBlock` caching the `*dcrutil.Block` it
        // is handed), so a block is not copied between the peer that
        // sent it and the chain.  A block that arrived without hashes
        // goes in without: the chain hashes it at the point it always
        // has, after its duplicate and header checks.
        let (fork_len, errs) = {
            let mut chain = self.locked();
            match block {
                ArrivedBlock::Plain(block) => {
                    chain.process_shared_block(block, adjusted_time_unix(), &self.params)
                }
                ArrivedBlock::Hashed(hashed) => {
                    chain.process_hashed_block(hashed, adjusted_time_unix(), &self.params)
                }
            }
        };

        // Run the deferred mempool maintenance and winning-tickets
        // lookups the callback queued, now that the chain mutex is
        // free (dcrd handles both inline with its chain lock
        // released).
        if let Some(handler) = &self.ntfn_handler {
            handler.drain_pending(&self.chain, adjusted_time_unix());
        }

        // Ask the store whether it has failed, and pass that down: the
        // chain renders a persistence failure as a RuleError so it can
        // flow through the existing error paths, which makes a disk fault
        // indistinguishable from a peer sending a bad block unless
        // something checks.
        let storage_failed = self
            .locked()
            .db
            .as_ref()
            .is_some_and(dcroxide_database::Database::is_fatal);

        combine_process_block_result(fork_len, errs, storage_failed)
    }
}

/// Fold the chain's block-processing outcome into the manager's result,
/// rendering every error exactly as dcrd's `blockchain.ProcessBlock`
/// renders its combined `finalErr` (via [`render_multi_error`]).
///
/// dcrd surfaces a `blockchain.ErrDuplicateBlock` rejection only as a
/// lone early return, so the duplicate-block classification the manager
/// needs comes from the first error; the message renders the whole flat
/// error slice so the rare block that both fails acceptance and whose
/// ensuing reorganization also errors reports dcrd's `multiple errors
/// (N):` text rather than only the first error's.
fn combine_process_block_result(
    fork_len: i64,
    errs: Vec<RuleError>,
    storage_failed: bool,
) -> Result<i64, ProcessBlockFailure> {
    match errs.first() {
        None => Ok(fork_len),
        Some(first) => Err(ProcessBlockFailure {
            is_duplicate_block: first.kind == RuleErrorKind::DuplicateBlock,
            // A failure is a rule error unless the store has latched
            // fatal, in which case this is a disk fault wearing a rule
            // error's clothes.
            //
            // `Chain::flush` converts a persistence failure into a
            // `RuleError` (`persist_rule_error`) so it can travel the
            // existing paths, and dcrd has no equivalent because its
            // database failures are plain errors. Reporting one as a rule
            // error tells the manager a peer sent an invalid block: it
            // logs "Rejected block ... from <peer>" at INFO and carries
            // on, so a failing disk reads as a misbehaving network. The
            // store's own latch is the only thing that can tell them
            // apart from here.
            //
            // An earlier comment here claimed the port surfaces database
            // failures through panics. It does not, and never did.
            //
            // The latch only catches persistence faults.  dcrd also
            // splits on the error's *class*: `AssertError` for an
            // internal inconsistency and `ContextError` for a backend
            // or deployment fault are both outside
            // `blockchain.RuleError`, so neither reaches the peer-
            // blaming branch.  The port folds all three into one
            // `RuleError` carrying dcrd's kind name, so the kind is
            // what reconstructs the split.
            is_rule_error: !storage_failed && first.kind.is_rule_violation(),
            // dcrd's `MultiError` answers `errors.Is` for any of its
            // errors, so any corruption among them counts.
            is_corruption: errs.iter().any(is_corruption),
            message: render_multi_error(&errs),
        }),
    }
}

/// Whether the chain error is one dcrd's sync manager singles out with
/// its `Critical failure` line: `database.ErrCorruption` or
/// `blockchain.ErrUtxoBackendCorruption` (`manager.go:1265-1269`,
/// `:1646-1648`).
///
/// The port hands both over as a `RuleError`, so the split is
/// reconstructed from what each carries:
///
/// - The UTXO backend and spend journal corruption the chain detects
///   carry dcrd's `ErrUtxoBackendCorruption` kind, and dcrd reports
///   the spend journal case as `database.ErrCorruption`.  So does a
///   chain database read that fails as corruption (a block whose
///   checksum does not match, a filter or commitments row that does not
///   decode); a read that fails any other way (an I/O error, a missing
///   block, a closed store) carries `ErrUtxoBackend` instead, as dcrd's
///   plain database error matches neither check
///   (`process::db_read_rule_error`).  The corruption kind also stands
///   in for dcrd's missing-input `AssertError`
///   (`UtxoView::assert_missing`), which dcrd's check does not match;
///   it renders with `AssertError`'s `assertion failed: ` prefix.
/// - A database corruption the store reports travels through
///   `persist_rule_error`, which keeps the database error's
///   `ErrorKind::Corruption` (dcrd `database.ErrCorruption`) only in
///   its rendered text; the chain crate reads it back next to the code
///   that writes it ([`is_persisted_db_corruption`]).
fn is_corruption(err: &RuleError) -> bool {
    if err.kind == RuleErrorKind::UtxoBackendCorruption {
        return !err.description.starts_with("assertion failed: ");
    }
    is_persisted_db_corruption(err)
}

/// A transaction pool that behaves like an empty pool rejecting
/// everything: a test double, since the daemon's manager runs over
/// [`crate::txmempool::NodeSyncTxPool`].
#[derive(Default)]
pub struct NullTxPool;

impl SyncTxPool for NullTxPool {
    fn process_transaction_accepted(
        &mut self,
        _tx: &MsgTx,
        _allow_orphan: bool,
        _allow_high_fees: bool,
        _tag: u64,
    ) -> Result<Vec<(Hash, MsgTx)>, ProcessTxFailure> {
        // A rejection, like the empty pool it stands in for, not an
        // internal failure to log.
        Err(ProcessTxFailure {
            is_rule_error: true,
            message: "the null transaction pool accepts nothing".to_string(),
        })
    }

    fn have_transaction(&mut self, _hash: &Hash) -> bool {
        false
    }

    fn prune_stake_tx(&mut self, _required_stake_difficulty: i64, _height: i64) {}

    fn prune_expired_tx(&mut self, _height: i64) {}
}

/// A mixing pool that behaves like an empty pool rejecting everything:
/// a test double, since the daemon's manager runs over
/// [`crate::mixnode::NodeSyncMixPool`].
#[derive(Default)]
pub struct NullMixPool;

impl SyncMixPool for NullMixPool {
    type Msg = dcroxide_wire::Message;
    type Err = String;

    fn mix_hash(&mut self, _msg: &Self::Msg) -> Hash {
        Hash([0u8; 32])
    }

    fn accept_message(&mut self, _msg: &Self::Msg, _source: u64) -> Result<Vec<Self::Msg>, String> {
        Err("the null mixing pool accepts nothing".to_string())
    }

    fn recent_message(&mut self, _hash: &Hash) -> bool {
        false
    }

    fn remove_spent_prs(&mut self, _txs: &[MsgTx]) {}

    fn expire_messages_in_background(&mut self, _height: u32) {}
}

/// The daemon-side view of dcrd `SyncManager.IsCurrent`, over the
/// manager's shared is-current flag and sync height (dcrd's
/// `isCurrent` is an `atomic.Bool` readable from any goroutine): the
/// accepted-block relay, fee-estimator enable, and background-generator
/// gates evaluate it without taking the manager lock, which the gates
/// cannot do because the manager itself takes the chain lock.
#[derive(Clone)]
pub struct SyncGate {
    current: Arc<std::sync::atomic::AtomicBool>,
    sync_height: Arc<std::sync::atomic::AtomicI64>,
}

impl SyncGate {
    /// A gate over the manager's shared state handles.
    pub fn from_manager(manager: &NodeSyncManager) -> SyncGate {
        let (current, sync_height) = manager.current_state_handles();
        SyncGate {
            current,
            sync_height,
        }
    }

    /// A gate that always reports current, for tests and tools that
    /// have no sync manager.
    pub fn always_current() -> SyncGate {
        SyncGate {
            current: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            sync_height: Arc::new(std::sync::atomic::AtomicI64::new(0)),
        }
    }

    /// A gate that has not latched and has no sync peer, so it opens
    /// exactly when the chain itself reports current — the manager's
    /// own state on a fresh chain before any peer connects.
    pub fn unsynced() -> SyncGate {
        SyncGate {
            current: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            sync_height: Arc::new(std::sync::atomic::AtomicI64::new(0)),
        }
    }

    /// A gate that has not latched and whose sync peer is at
    /// `sync_height`: it stays closed while the chain is below that
    /// height, whatever the age of its tip, and from that height on
    /// opens, and latches, once the chain itself reports current — the
    /// manager's state during an initial sync.
    pub fn syncing_to(sync_height: i64) -> SyncGate {
        SyncGate {
            current: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            sync_height: Arc::new(std::sync::atomic::AtomicI64::new(sync_height)),
        }
    }

    /// dcrd `SyncManager.IsCurrent` over an already-locked chain:
    /// `maybeUpdateIsCurrent` — nothing to do when the flag is already
    /// set; otherwise the chain is considered synced once it believes
    /// it is current and the best height reaches the sync height —
    /// then the flag read.
    pub fn is_current_locked(&self, chain: &mut Chain, now_unix: i64) -> bool {
        use std::sync::atomic::Ordering;
        if self.current.load(Ordering::SeqCst) {
            return true;
        }
        let best_height = chain.best_snapshot().height;
        if best_height >= self.sync_height.load(Ordering::SeqCst) && chain.is_current_at(now_unix) {
            self.current.store(true, Ordering::SeqCst);
            return true;
        }
        false
    }

    /// [`SyncGate::is_current_locked`] taking the chain lock itself.
    pub fn is_current(&self, chain: &Arc<Mutex<Chain>>, now_unix: i64) -> bool {
        use std::sync::atomic::Ordering;
        if self.current.load(Ordering::SeqCst) {
            return true;
        }
        let mut chain = chain.lock().expect("chain mutex poisoned");
        self.is_current_locked(&mut chain, now_unix)
    }
}

/// The environment variable that selects the block download window
/// ([`apply_block_window_setting`]).
pub const BLOCK_WINDOW_VAR: &str = "DCROXIDE_BLOCK_WINDOW";

/// The block download window the daemon syncs with unless
/// [`BLOCK_WINDOW_VAR`] says otherwise: the budgeted window, which dcrd
/// does not have (PARITY *Block download window*), at
/// [`BUDGET_WINDOW_BLOCKS`] blocks at most.
///
/// Its byte budget is worked out from the smallest of the network's
/// maximum block sizes and is capped at eight main network blocks
/// (`dcroxide_netsync::manager::MAX_BUDGET_WINDOW_BYTES`), which is what
/// it comes to on all four networks.
pub fn default_block_window(params: &Params) -> BlockWindow {
    let max_block_size = params
        .maximum_block_sizes
        .iter()
        .copied()
        .min()
        .unwrap_or(dcroxide_wire::MAX_BLOCK_PAYLOAD as usize);
    BlockWindow::budget(max_block_size, BUDGET_WINDOW_BLOCKS)
}

/// The block download window a [`BLOCK_WINDOW_VAR`] value names, or
/// `None` for a value that names none.
///
/// `dcrd`, in any case, is dcrd's own window of 16 blocks refilled below
/// 10.  A whole number from 16 to 505 is the budgeted window with that
/// many blocks at most in place of [`BUDGET_WINDOW_BLOCKS`], a setting
/// for measurement: 16 is the most dcrd's window keeps requested and the
/// fewest this one may be set to, and 505 is the largest getdata that
/// costs no ban score ([`MAX_BUDGET_WINDOW_BLOCKS`]).  Surrounding
/// whitespace is ignored.
pub fn parse_block_window(raw: &str, params: &Params) -> Option<BlockWindow> {
    let value = raw.trim();
    if value.eq_ignore_ascii_case("dcrd") {
        return Some(BlockWindow::Dcrd);
    }
    // Digits only: `parse` alone would also take a leading plus sign.
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let max_blocks = value.parse::<usize>().ok()?;
    if !(MAX_IN_FLIGHT_BLOCKS..=MAX_BUDGET_WINDOW_BLOCKS).contains(&max_blocks) {
        return None;
    }
    let BlockWindow::Budget { max_bytes, .. } = default_block_window(params) else {
        return None;
    };
    Some(BlockWindow::Budget {
        max_bytes,
        max_blocks,
    })
}

/// Give the manager the block download window the [`BLOCK_WINDOW_VAR`]
/// setting names, returning it with the line to log about the setting,
/// if any, and the level to log it at.
///
/// Unset leaves the manager as [`new_sync_manager`] built it and says
/// nothing.  A value [`parse_block_window`] accepts is applied, and the
/// line reports the window read back from the manager afterwards, so it
/// cannot name a window the manager does not have.  Any other value is
/// ignored with a warning rather than being fatal, like the daemon's
/// other tuning variables.
///
/// The window named is the widest the manager uses.  A budgeted window
/// halves itself when it loses its sync peer with more than 16 blocks
/// requested from it and says so in a `SYNC` line of its own
/// (`dcroxide_netsync::BlockWindow::Budget`).
///
/// The manager is taken and returned by value, so a caller cannot log
/// the setting and leave the manager it uses untouched.
pub fn apply_block_window_setting<C, T, M>(
    manager: SyncManager<C, T, M>,
    setting: Option<&str>,
    params: &Params,
) -> (SyncManager<C, T, M>, Option<(LogLevel, String)>)
where
    C: SyncChain,
    T: SyncTxPool,
    M: SyncMixPool,
{
    let Some(raw) = setting else {
        return (manager, None);
    };
    let Some(window) = parse_block_window(raw, params) else {
        let line = format!(
            "{BLOCK_WINDOW_VAR}={} is neither dcrd nor a whole number of blocks from \
             {MAX_IN_FLIGHT_BLOCKS} to {MAX_BUDGET_WINDOW_BLOCKS}; using the default",
            raw.trim()
        );
        return (manager, Some((LogLevel::Warn, line)));
    };
    let manager = manager.with_block_window(window);
    let line = match manager.block_window() {
        BlockWindow::Dcrd => format!(
            "Block download window set to dcrd's {MAX_IN_FLIGHT_BLOCKS} blocks in flight by \
             {BLOCK_WINDOW_VAR}"
        ),
        BlockWindow::Budget { max_blocks, .. } => format!(
            "Block download window set to at most {max_blocks} blocks in flight by \
             {BLOCK_WINDOW_VAR}"
        ),
    };
    (manager, Some((LogLevel::Info, line)))
}

/// Construct the daemon's sync manager over the shared chain (dcrd
/// `newServer` building its `netsync.Config`), with the daemon's block
/// download window in place of dcrd's ([`default_block_window`]).
pub fn new_sync_manager(
    chain: Arc<Mutex<Chain>>,
    params: &Params,
    no_mining_state_sync: bool,
    max_outbound_peers: u64,
    max_orphan_txs: usize,
    tx_pool: Arc<Mutex<crate::txmempool::NodeTxPool>>,
    mix_pool: Arc<Mutex<crate::mixnode::NodeMixPool>>,
) -> NodeSyncManager {
    SyncManager::new(Config {
        chain: NodeSyncChain::new(chain, params.clone()),
        tx_mem_pool: crate::txmempool::NodeSyncTxPool::new(Arc::clone(&tx_pool)),
        mix_pool: crate::mixnode::NodeSyncMixPool::new(mix_pool, tx_pool),
        min_known_chain_work: params.min_known_chain_work,
        net: params.net,
        target_time_per_block_secs: params.target_time_per_block_secs,
        no_mining_state_sync,
        max_outbound_peers,
        max_orphan_txs,
        recently_confirmed_txns: Arc::new(Mutex::new(dcroxide_containers::apbf::new_filter(
            MAX_RECENTLY_CONFIRMED_TXNS,
            RECENTLY_CONFIRMED_TXNS_FP_RATE,
        ))),
    })
    .with_block_window(default_block_window(params))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_err(kind: RuleErrorKind, description: &str) -> RuleError {
        RuleError {
            kind,
            description: description.to_string(),
        }
    }

    /// The four networks, by name.
    fn networks() -> [(&'static str, Params); 4] {
        [
            ("mainnet", dcroxide_chaincfg::mainnet_params()),
            ("testnet3", dcroxide_chaincfg::testnet3_params()),
            ("simnet", dcroxide_chaincfg::simnet_params()),
            ("regnet", dcroxide_chaincfg::regnet_params()),
        ]
    }

    /// The daemon's sync manager over a new chain for the network, built
    /// as the daemon builds it, with the directory its database is in.
    fn daemon_sync_manager(params: &Params) -> (tempfile::TempDir, NodeSyncManager) {
        let dir = tempfile::tempdir().expect("database directory");
        let opts = dcroxide_database::Options::new(dir.path().join("blocks_ffldb"), params.net.0);
        dcroxide_database::create_dir_all_owner_only(&opts.path).expect("create the directory");
        let db = dcroxide_database::Database::create(&opts).expect("create the database");
        let chain = Arc::new(Mutex::new(
            Chain::open(db, params, params.assume_valid, false, 0).expect("open the chain"),
        ));
        let tx_pool = crate::txmempool::new_shared_tx_pool(
            Arc::clone(&chain),
            params,
            false,
            100,
            10_000,
            false,
            false,
        );
        let mix_pool =
            crate::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone(), &tx_pool);
        let manager = new_sync_manager(chain, params, false, 8, 100, tx_pool, mix_pool);
        (dir, manager)
    }

    /// The window the daemon syncs with by default is the budgeted one,
    /// at 128 blocks and eight of the main network's maximum-size blocks
    /// on every network: the others allow larger blocks, and the budget
    /// does not follow them up.
    #[test]
    fn the_default_block_window_is_budgeted_on_every_network() {
        let main_net = dcroxide_chaincfg::mainnet_params();
        assert_eq!(main_net.maximum_block_sizes, vec![393_216]);
        assert_eq!(
            dcroxide_netsync::manager::MAX_BUDGET_WINDOW_BYTES,
            8 * 393_216,
            "eight maximum-size main network blocks"
        );
        for (name, params) in networks() {
            assert!(
                params
                    .maximum_block_sizes
                    .iter()
                    .all(|size| *size >= 393_216),
                "{name}"
            );
            assert_eq!(
                default_block_window(&params),
                BlockWindow::Budget {
                    max_bytes: 3_145_728,
                    max_blocks: 128,
                },
                "{name}"
            );
        }

        // A network of smaller blocks is budgeted from the smallest of
        // its maximum sizes.
        let mut small = dcroxide_chaincfg::simnet_params();
        small.maximum_block_sizes = vec![200_000, 100_000, 300_000];
        assert_eq!(
            default_block_window(&small),
            BlockWindow::Budget {
                max_bytes: 800_000,
                max_blocks: 128,
            }
        );
    }

    /// `DCROXIDE_BLOCK_WINDOW` names dcrd's window or a count for the
    /// budgeted one, from dcrd's 16 to the largest getdata that costs no
    /// ban score.  Nothing else is a window.
    #[test]
    fn block_window_settings_parse() {
        let params = dcroxide_chaincfg::mainnet_params();
        for raw in ["dcrd", "DCRD", "Dcrd", " dcrd ", "\tdcrd\n"] {
            assert_eq!(
                parse_block_window(raw, &params),
                Some(BlockWindow::Dcrd),
                "{raw:?}"
            );
        }
        for (raw, max_blocks) in [
            ("16", 16),
            ("17", 17),
            ("128", 128),
            (" 256 ", 256),
            ("0064", 64),
            ("504", 504),
            ("505", 505),
        ] {
            assert_eq!(
                parse_block_window(raw, &params),
                Some(BlockWindow::Budget {
                    max_bytes: 3_145_728,
                    max_blocks,
                }),
                "{raw:?}"
            );
        }
        for raw in [
            "",
            " ",
            "0",
            "1",
            "15",
            "506",
            "50000",
            "99999999999999999999999999",
            "-1",
            "-128",
            "+128",
            "128 blocks",
            "12 8",
            "1e2",
            "0x80",
            "128.0",
            "abc",
            "dcrd16",
            "default",
            "budget",
        ] {
            assert_eq!(parse_block_window(raw, &params), None, "{raw:?}");
        }
    }

    /// The manager the daemon builds syncs with the daemon's default
    /// window, not with the window the core starts with, on every
    /// network.
    #[test]
    fn the_daemons_sync_manager_has_the_default_block_window() {
        for (name, params) in networks() {
            let (_dir, manager) = daemon_sync_manager(&params);
            assert_eq!(
                manager.block_window(),
                default_block_window(&params),
                "{name}"
            );
            assert_ne!(manager.block_window(), BlockWindow::Dcrd, "{name}");
        }
    }

    /// The setting reaches the manager: what comes back syncs with the
    /// window the setting names, and the line to log says which.  An
    /// unset variable changes nothing and says nothing; a value that
    /// names no window changes nothing and warns.
    #[test]
    fn a_block_window_setting_is_applied_to_the_manager() {
        let params = dcroxide_chaincfg::simnet_params();
        let default = default_block_window(&params);
        let apply = |setting: Option<&str>| {
            let (_dir, manager) = daemon_sync_manager(&params);
            let (manager, notice) = apply_block_window_setting(manager, setting, &params);
            (manager.block_window(), notice)
        };

        assert_eq!(apply(None), (default, None));
        assert_eq!(
            apply(Some("dcrd")),
            (
                BlockWindow::Dcrd,
                Some((
                    LogLevel::Info,
                    "Block download window set to dcrd's 16 blocks in flight by \
                     DCROXIDE_BLOCK_WINDOW"
                        .to_string()
                ))
            )
        );
        assert_eq!(
            apply(Some(" 256 ")),
            (
                BlockWindow::Budget {
                    max_bytes: 3_145_728,
                    max_blocks: 256,
                },
                Some((
                    LogLevel::Info,
                    "Block download window set to at most 256 blocks in flight by \
                     DCROXIDE_BLOCK_WINDOW"
                        .to_string()
                ))
            )
        );
        for bad in ["15", "506", "", "fast"] {
            assert_eq!(
                apply(Some(bad)),
                (
                    default,
                    Some((
                        LogLevel::Warn,
                        format!(
                            "DCROXIDE_BLOCK_WINDOW={bad} is neither dcrd nor a whole number of \
                             blocks from 16 to 505; using the default"
                        )
                    ))
                ),
                "{bad:?}"
            );
        }
    }

    /// A sync chain over a new in-memory regnet chain, the chain it
    /// wraps, and the first three blocks of dcrd's full block battery
    /// that extend its tip one after another.
    fn regnet_sync_chain() -> (NodeSyncChain, Arc<Mutex<Chain>>, Vec<Arc<MsgBlock>>) {
        let params = dcroxide_chaincfg::regnet_params();
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dcroxide-blockchain/tests/data/fullblock_vectors.txt"
        );
        let data = std::fs::read_to_string(path).expect("fullblock vectors");
        let mut tip = params.genesis_hash;
        let mut blocks = Vec::new();
        for line in data.lines() {
            let f: Vec<&str> = line.split(' ').collect();
            // accept <name> <mainchain> <orphan> <blockhex>
            if f[0] != "accept" || f[2] != "true" {
                continue;
            }
            let (block, _) = MsgBlock::from_bytes(&dcroxide_testutil::unhex(f[4])).expect("block");
            if block.header.prev_block != tip {
                continue;
            }
            tip = block.header.block_hash();
            blocks.push(Arc::new(block));
            if blocks.len() == 3 {
                break;
            }
        }
        assert_eq!(blocks.len(), 3, "the battery provides the prefix");
        let chain = Arc::new(Mutex::new(Chain::new(&params, Hash::ZERO, false)));
        let sync_chain = NodeSyncChain::new(Arc::clone(&chain), params);
        (sync_chain, chain, blocks)
    }

    /// A block that arrives without hashes is handed to the chain
    /// without: the chain hashes it itself, at the point it always has,
    /// and keeps the allocation that arrived.
    #[test]
    fn a_plain_block_is_hashed_inside_the_chain() {
        let (mut sync_chain, chain, blocks) = regnet_sync_chain();
        for (i, block) in blocks.iter().enumerate() {
            let arrived = ArrivedBlock::from(Arc::clone(block));
            assert!(matches!(arrived, ArrivedBlock::Plain(_)));
            assert_eq!(arrived.hash(), block.header.block_hash());
            assert_eq!(*arrived, **block);

            let before = chain.lock().expect("chain").arrivals_hashed;
            assert_eq!(sync_chain.process_block(&arrived).expect("accepted"), 0);
            let chain = chain.lock().expect("chain");
            assert_eq!(
                chain.arrivals_hashed.wrapping_sub(before),
                1,
                "block {i}: the chain did not hash the block itself"
            );
            assert_eq!(chain.best_snapshot().hash, block.header.block_hash());
            assert!(Arc::ptr_eq(
                &chain.blocks[&block.header.block_hash().0],
                block
            ));
        }
    }

    /// A block that arrives with its hashes reaches the chain with them:
    /// the chain hashes nothing, connects the block, and keeps the
    /// allocation the hashed block owns.
    #[test]
    fn a_hashed_block_reaches_the_chain_with_its_hashes() {
        let (mut sync_chain, chain, blocks) = regnet_sync_chain();
        for (i, block) in blocks.iter().enumerate() {
            let arrived = ArrivedBlock::Hashed(HashedBlock::new(Arc::clone(block)));
            assert_eq!(arrived.hash(), block.header.block_hash());
            assert_eq!(*arrived, **block);

            let before = chain.lock().expect("chain").arrivals_hashed;
            assert_eq!(sync_chain.process_block(&arrived).expect("accepted"), 0);
            let chain = chain.lock().expect("chain");
            assert_eq!(
                chain.arrivals_hashed, before,
                "block {i}: the chain hashed a block that arrived hashed"
            );
            assert_eq!(chain.tx_hash_recomputes, 0, "block {i}");
            assert_eq!(chain.best_snapshot().hash, block.header.block_hash());
            assert!(Arc::ptr_eq(
                &chain.blocks[&block.header.block_hash().0],
                block
            ));
        }

        // A duplicate is refused the same way either way.
        for arrived in [
            ArrivedBlock::Plain(Arc::clone(&blocks[0])),
            ArrivedBlock::Hashed(HashedBlock::new(Arc::clone(&blocks[0]))),
        ] {
            let failure = sync_chain
                .process_block(&arrived)
                .expect_err("the chain has the block");
            assert!(failure.is_duplicate_block, "{}", failure.message);
        }
    }

    #[test]
    fn no_errors_yields_the_fork_length() {
        assert_eq!(
            combine_process_block_result(3, Vec::new(), false).unwrap(),
            3
        );
    }

    #[test]
    fn a_single_error_reports_its_bare_description() {
        // The common single-error rejection: a lone duplicate-block
        // error classifies the failure and renders unadorned, exactly
        // as dcrd's `submitblock` reports it after `rejected: `.
        let failure = combine_process_block_result(
            0,
            vec![rule_err(
                RuleErrorKind::DuplicateBlock,
                "already have block abc",
            )],
            false,
        )
        .unwrap_err();
        assert!(failure.is_duplicate_block);
        assert_eq!(failure.message, "already have block abc");
    }

    #[test]
    fn multiple_errors_render_dcrd_multi_error_text() {
        // The rare block that both fails contextual acceptance and
        // whose ensuing reorganization also errors: dcrd combines the
        // acceptance error (element 0) with the reorganization errors
        // into one flat `MultiError`, so `submitblock` reports the
        // whole `multiple errors (N):` block rather than only the
        // first error's text.  The classification still comes from the
        // first error, which is never a duplicate-block rejection.
        let failure = combine_process_block_result(
            0,
            vec![
                rule_err(RuleErrorKind::UnexpectedDifficulty, "accept-err"),
                rule_err(RuleErrorKind::BadMerkleRoot, "reorg-err-1"),
                rule_err(RuleErrorKind::BadMerkleRoot, "reorg-err-2"),
            ],
            false,
        )
        .unwrap_err();
        assert!(!failure.is_duplicate_block);
        assert_eq!(
            failure.message,
            "multiple errors (3):\n - accept-err\n - reorg-err-1\n - reorg-err-2\n"
        );
    }

    /// A consensus rejection is a rule error, so the manager may blame
    /// the peer that sent it.
    #[test]
    fn a_consensus_rejection_stays_a_rule_error() {
        let failure = combine_process_block_result(
            0,
            vec![rule_err(RuleErrorKind::BadMerkleRoot, "bad merkle root")],
            false,
        )
        .unwrap_err();
        assert!(
            failure.is_rule_error,
            "a real rule violation must remain attributable to the peer"
        );
    }

    /// A storage failure is NOT, even though the chain hands it over
    /// wearing a rule error's clothes.
    ///
    /// `Chain::flush` converts a persistence failure into a `RuleError`
    /// (`persist_rule_error`) so it can travel the existing paths. Taken
    /// at face value that tells the sync manager a peer sent an invalid
    /// block: it logs "Rejected block ... from <peer>" at INFO and keeps
    /// syncing, so a failing disk reads as a misbehaving network and the
    /// real fault is never surfaced. The store's fatal latch is what
    /// distinguishes them.
    ///
    /// The kind used here is deliberately the one `persist_rule_error`
    /// fabricates, so this test breaks if that mapping changes.
    #[test]
    fn a_storage_failure_is_not_blamed_on_the_peer() {
        let failure = combine_process_block_result(
            0,
            vec![rule_err(
                RuleErrorKind::UnknownBlock,
                "chain database failure: Db(Error { kind: Fatal, .. })",
            )],
            true,
        )
        .unwrap_err();
        assert!(
            !failure.is_rule_error,
            "a disk fault must not be reported as a consensus violation"
        );
        assert!(
            !failure.is_duplicate_block,
            "and must not be swallowed as a duplicate"
        );
    }

    /// An internal inconsistency is not the peer's fault either.
    ///
    /// dcrd's `connectTransaction` raises `AssertError("view missing
    /// input ...")` when the view lost an input
    /// (`utxoviewpoint.go:290-294`).  `AssertError` is not a
    /// `blockchain.RuleError`, so dcrd's sync manager takes the
    /// `Failed to process block` branch (`manager.go:1263`) rather than
    /// `Rejected block %v from %s`.
    ///
    /// The port has no separate assertion type -- it carries dcrd's
    /// `ErrUtxoBackendCorruption` kind -- so the kind is what has to
    /// reconstruct the split.  No storage fault is latched here on
    /// purpose: an internal inconsistency never sets the database's
    /// fatal flag, which is exactly why the latch alone was not enough.
    #[test]
    fn an_internal_inconsistency_is_not_blamed_on_the_peer() {
        let failure = combine_process_block_result(
            0,
            vec![rule_err(
                RuleErrorKind::UtxoBackendCorruption,
                "assertion failed: view missing input \
                 0000000000000000000000000000000000000000000000000000000000000000:0",
            )],
            false,
        )
        .unwrap_err();
        assert!(
            !failure.is_rule_error,
            "a local view/backend inconsistency must not be reported as a consensus violation"
        );
    }

    /// The split is kind-level, not a one-off for the view assertion.
    ///
    /// `ErrUnknownAgendaID` is what an agenda query inside block
    /// validation raises (`agendas.go:719-722`), and it and
    /// `ErrUnknownDeploymentID` (`thresholdstate.go:530-534` among
    /// others) are `contextError`s in dcrd, so they carry the same
    /// misclassification and the same fix.
    #[test]
    fn a_deployment_context_error_is_not_blamed_on_the_peer() {
        for (kind, text) in [
            (
                RuleErrorKind::UnknownAgendaID,
                "agenda ID bogusagenda does not exist",
            ),
            (RuleErrorKind::UnknownDeploymentID, "unknown deployment ID"),
        ] {
            let failure =
                combine_process_block_result(0, vec![rule_err(kind, text)], false).unwrap_err();
            assert!(
                !failure.is_rule_error,
                "a context error must not be reported as a consensus violation"
            );
        }
    }

    /// The rule error the chain's `persist_rule_error` makes of a
    /// database error of the given kind.
    fn persisted_db_error(kind: dcroxide_database::ErrorKind) -> RuleError {
        dcroxide_blockchain::process::persist_rule_error(
            dcroxide_blockchain::chaindb::ChainDbError::Db(dcroxide_database::Error {
                kind,
                description: "bad checksum".to_string(),
            }),
        )
    }

    /// The rule error the chain's view raises for an input it lost
    /// (`UtxoView::assert_missing`, dcrd's `AssertError`): a regular
    /// transaction spending an output an empty view does not hold.
    fn missing_input_assertion() -> RuleError {
        let tx = dcroxide_wire::MsgTx {
            tx_in: vec![dcroxide_wire::TxIn {
                previous_out_point: dcroxide_wire::OutPoint {
                    hash: Hash([1; 32]),
                    index: 0,
                    tree: 0,
                },
                ..Default::default()
            }],
            ..Default::default()
        };
        let err = dcroxide_blockchain::utxoview::UtxoView::new()
            .connect_regular_transaction(
                &tx,
                &tx.tx_hash(),
                1,
                1,
                &mut std::collections::BTreeMap::new(),
                true,
                None,
                false,
            )
            .unwrap_err();
        assert_eq!(err.kind, RuleErrorKind::UtxoBackendCorruption);
        err
    }

    /// dcrd's sync manager adds a `Critical failure` error line for
    /// `database.ErrCorruption` and `blockchain.ErrUtxoBackendCorruption`
    /// (`manager.go:1265-1269`).  The port hands both over as rule
    /// errors, so the adapter has to recognise them: a corrupt spend
    /// journal or UTXO backend by its kind, a database corruption by the
    /// kind `persist_rule_error` records in its text.  Neither the
    /// missing-input assertion that shares the UTXO kind nor any other
    /// database failure counts.  Both texts come from the chain's own
    /// producers, so a change to either breaks this test.
    #[test]
    fn corruption_is_classified_for_the_critical_failure_line() {
        let classify = |errs: Vec<RuleError>, storage_failed: bool| {
            combine_process_block_result(0, errs, storage_failed)
                .unwrap_err()
                .is_corruption
        };

        assert!(classify(
            vec![rule_err(
                RuleErrorKind::UtxoBackendCorruption,
                "corrupt spend information for 00ab: Deserialize",
            )],
            false,
        ));
        assert!(classify(
            vec![persisted_db_error(dcroxide_database::ErrorKind::Corruption)],
            true,
        ));

        assert!(!classify(vec![missing_input_assertion()], false));
        assert!(!classify(
            vec![persisted_db_error(dcroxide_database::ErrorKind::Fatal)],
            true,
        ));
        // The chain's own consistency failures on the block paths (a
        // missing bucket, a spent entry reaching the UTXO writer) are
        // not the database's `ErrCorruption`: dcrd has no error value
        // there (a nil bucket, and a spent entry is deleted instead).
        assert!(!classify(
            vec![dcroxide_blockchain::process::persist_rule_error(
                dcroxide_blockchain::chaindb::ChainDbError::Corrupt(
                    "missing utxo set bucket".to_string()
                ),
            )],
            true,
        ));
        assert!(!classify(
            vec![rule_err(RuleErrorKind::BadMerkleRoot, "bad merkle root")],
            false,
        ));

        // A chain database read that fails: only the database's own
        // `ErrCorruption` (dcrd's checksum mismatch) counts, never an
        // I/O error, a missing block or a closed store, which dcrd
        // returns as plain database errors.
        let read_error = |kind| {
            dcroxide_blockchain::process::db_read_rule_error(
                dcroxide_blockchain::chaindb::ChainDbError::Db(dcroxide_database::Error {
                    kind,
                    description: "read failed".to_string(),
                }),
            )
        };
        assert!(classify(
            vec![read_error(dcroxide_database::ErrorKind::Corruption)],
            false,
        ));
        for kind in [
            dcroxide_database::ErrorKind::DriverSpecific,
            dcroxide_database::ErrorKind::BlockNotFound,
            dcroxide_database::ErrorKind::DbNotOpen,
            dcroxide_database::ErrorKind::Fatal,
        ] {
            let failure =
                combine_process_block_result(0, vec![read_error(kind)], false).unwrap_err();
            assert!(!failure.is_corruption, "{kind:?}");
            assert!(!failure.is_rule_error, "{kind:?}");
        }
        // A stored row that does not decode is dcrd's `ErrCorruption`.
        assert!(classify(
            vec![dcroxide_blockchain::process::db_read_rule_error(
                dcroxide_blockchain::chaindb::ChainDbError::Corrupt(
                    "corrupt filter for 00ab: bad".to_string()
                ),
            )],
            false,
        ));

        // dcrd's `MultiError.Is` matches any of its errors.
        assert!(classify(
            vec![
                rule_err(RuleErrorKind::BadMerkleRoot, "accept-err"),
                persisted_db_error(dcroxide_database::ErrorKind::Corruption),
            ],
            false,
        ));
    }
}
