// SPDX-License-Identifier: ISC

//! Headers-first chain processing from dcrd's
//! `internal/blockchain/process.go`: accepting block headers to the
//! block index with full context-free and positional validation, the
//! known-invalid short circuits, the assumed-valid and old fork
//! rejection checkpoint tracking, and the full block processing path
//! (`ProcessBlock` and the reorganization machinery it drives).

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::sync::atomic::{AtomicBool, Ordering};

use dcroxide_chaincfg::{ConsensusDeployment, Params};
use dcroxide_chainhash::Hash;
use dcroxide_wire::BlockHeader;

use dcroxide_gcs::FilterV2;
use dcroxide_stake::ticketdb::UndoTicketData;
use dcroxide_stake::ticketnode::{Node as StakeNode, StakeNodeParams};
use dcroxide_uint256::Uint256;
use dcroxide_wire::{MsgBlock, MsgTx, OutPoint};

use crate::RuleError;
use crate::blockindex::{BlockIndex, BlockStatus, NodeId, NodeStore};
use crate::chainio::SpentTxOut;
use crate::chainview_nodes::{NodeBranchView, NodeChainView};
use crate::notifications::{
    BlockAcceptedNtfnsData, BlockConnectedNtfnsData, BlockDisconnectedNtfnsData, LogCallback,
    LogLevel, Notification, NotificationCallback, ReorganizationNtfnsData, TicketNotificationsData,
};
use crate::ruleerror::RuleErrorKind;
use crate::stakever::calc_want_height;
use crate::thresholdstate::{
    ThresholdStateTuple, VoteCounts, deployment_state, state_last_changed,
};
use crate::utxoentry::UtxoEntry;
use crate::utxoview::{OutPointKey, UtxoView, count_spent_outputs};
use crate::validate::{
    ChainSubsidyParams, ForkRejection, check_block_header_positional, check_block_header_sanity,
};

/// Statistics on the current UTXO set (dcrd `UtxoStats`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoStats {
    /// The number of unspent outputs.
    pub utxos: i64,
    /// The number of distinct transactions with unspent outputs.
    pub transactions: i64,
    /// The serialized size of all entries.
    pub size: i64,
    /// The total amount of all unspent outputs in atoms.
    pub total: i64,
    /// The merkle root of the BLAKE-256 hashes of the serialized
    /// entries, taken in serialized-key order.
    pub serialized_hash: Hash,
}

/// One utxo of the in-memory backend reduced to just what the set
/// statistics need, sorted into serialized-key order before the fold:
/// the key it sorts by, the leaf hash of its serialized entry, that
/// entry's length, its amount, and its transaction hash.
///
/// The entry bytes themselves are hashed on sight and dropped rather
/// than carried, so the sort holds a fixed ~88 bytes per utxo instead
/// of every serialized entry at once.  The database walk needs no rows:
/// it folds each entry as the bucket hands it over, already in order.
type UtxoStatsRow = (Vec<u8>, Hash, i64, i64, [u8; 32]);

fn rule_error(kind: RuleErrorKind, description: impl Into<String>) -> RuleError {
    RuleError {
        kind,
        description: description.into(),
    }
}

/// The proof index for the filter header commitment (dcrd
/// `HeaderCmtFilterIndex`).
pub const HEADER_CMT_FILTER_INDEX: u32 = 0;

/// A merkle tree inclusion proof and associated proof index for a
/// header commitment, letting clients prove the commitment root
/// commits to specific data at the given index (dcrd `HeaderProof`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderProof {
    /// The leaf index the proof is for.
    pub proof_index: u32,
    /// The sibling hashes forming the inclusion proof.
    pub proof_hashes: Vec<Hash>,
}

/// The default maximum UTXO-cache size (dcrd's
/// `defaultUtxoCacheMaxSize` of 150 MiB, in bytes).
const DEFAULT_UTXO_CACHE_MAX_BYTES: u64 = 150 * 1024 * 1024;

/// The size of an outpoint in dcrd's cache accounting (dcrd
/// `outpointSize`, `unsafe.Sizeof(wire.OutPoint{})` on 64-bit).
const UTXO_CACHE_OUTPOINT_SIZE: u64 = 56;

/// The size of a pointer in dcrd's cache accounting (dcrd
/// `pointerSize`).
const UTXO_CACHE_POINTER_SIZE: u64 = 8;

/// The per-entry map overhead in dcrd's cache accounting (dcrd
/// `mapOverhead`).
const UTXO_CACHE_MAP_OVERHEAD: u64 = 57;

/// The base size of a utxo entry in dcrd's cache accounting (dcrd
/// `baseEntrySize`).
const UTXO_BASE_ENTRY_SIZE: u64 = 56;

/// The fraction of the eviction depth to evict when the cache reaches
/// its maximum size (dcrd `evictionPercentage`).
const UTXO_CACHE_EVICTION_PERCENTAGE: f64 = 0.15;

/// The seconds between periodic cache flushes during the initial
/// chain sync (dcrd `periodicFlushInterval` of two minutes).
const UTXO_PERIODIC_FLUSH_SECS: i64 = 120;

/// The default maximum number of entries in the signature
/// verification cache (dcrd config.go `defaultSigCacheMaxSize`; dcrd
/// sizes the cache by entry count, not bytes).
pub const DEFAULT_SIG_CACHE_MAX_ENTRIES: usize = 100000;

/// The in-memory size of a utxo entry in dcrd's cache accounting
/// (dcrd `UtxoEntry.size`): the base size plus the script and, for
/// ticket submissions, the serialized minimal-outputs data.
fn utxo_entry_size(entry: &UtxoEntry) -> u64 {
    UTXO_BASE_ENTRY_SIZE
        .saturating_add(entry.pk_script().len() as u64)
        .saturating_add(
            entry
                .ticket_minimal_outputs_data()
                .map(|d| d.len() as u64)
                .unwrap_or(0),
        )
}

/// The chain's read-through resolver over its utxo cache and backend
/// (dcrd's utxo viewpoints fetch through `UtxoCache`): single
/// lookups go through [`Chain::fetch_utxo_entry`], and the view's
/// per-block batches go through [`Chain::fetch_utxo_entries`] so all
/// cache misses of a block read the backend in one database view
/// transaction.
struct ChainUtxoResolver<'a> {
    chain: &'a Chain,
}

impl crate::utxoview::UtxoResolver for ChainUtxoResolver<'_> {
    fn resolve(&self, outpoint: &OutPoint) -> Option<UtxoEntry> {
        self.chain.fetch_utxo_entry(outpoint)
    }

    fn resolve_batch(&self, outpoints: &[OutPoint]) -> Vec<Option<UtxoEntry>> {
        self.chain.fetch_utxo_entries(outpoints)
    }
}

/// The growing chain state: the block tree arena and index together
/// with the chain state and configuration (the subset of dcrd's
/// `BlockChain` struct this port reads).  dcrd's locks are not
/// reproduced -- the daemon holds one mutex over the whole chain --
/// but its database flush points are.
pub struct Chain {
    /// The block tree arena.
    pub store: NodeStore,
    /// The block index over the arena.
    pub index: BlockIndex,
    /// The assumed valid block hash from configuration (dcrd
    /// `config.AssumeValid`); the zero hash disables it.
    pub assume_valid: Hash,
    /// The block node for the assumed valid block once its header is
    /// known.
    pub assume_valid_node: Option<NodeId>,
    /// The block to treat as the checkpoint for rejecting old forks,
    /// once discovered.
    pub reject_forks_checkpoint: Option<NodeId>,
    /// Whether old fork rejection semantics are disabled.
    pub allow_old_forks: bool,
    /// The expected number of blocks in two weeks, cached from the
    /// target block time.
    pub expected_blocks_in_two_weeks: i64,

    /// The view of the current best chain.
    pub best_chain: NodeChainView,
    /// Full block data by block hash: a recent-window mirror of the
    /// blocks stored in the database, standing in for dcrd's recent
    /// block cache.  Every block is stored to the database when its
    /// data is accepted; the mirror keeps only the recent ones (see
    /// [`Chain::MIN_MEMORY_STAKE_NODES`]), and older ones are read back
    /// from the database.  Without a database it is the only copy and is
    /// never evicted.  The blocks are shared as `Arc`s so the connect
    /// path hands the mirror's copy to the attach loop and to the
    /// notifications instead of copying it, like dcrd sharing one
    /// `*dcrutil.Block` from its cache.
    pub blocks: BTreeMap<[u8; 32], Arc<MsgBlock>>,
    /// Per-height ticket undo data for main chain blocks: a
    /// recent-window mirror of dcrd's ticket database undo rows, which
    /// `connect_block` writes through `WriteConnectedBestNode`; evicted
    /// with the other mirrors and read back from the database past the
    /// window.
    pub stake_undo: BTreeMap<i64, Vec<UndoTicketData>>,
    /// Per-height maturing ticket hashes for main chain blocks: the
    /// recent-window mirror of dcrd's ticket database new tickets rows,
    /// kept like [`Chain::stake_undo`].
    pub stake_new_tickets: BTreeMap<i64, Vec<dcroxide_chainhash::Hash>>,

    /// The flushed UTXO set by outpoint for chains WITHOUT a backing
    /// database: the in-memory utxo backend the pure differential-test
    /// chains flush into.  Database-backed chains never touch it —
    /// their backend is the utxo set bucket on disk, read through
    /// [`Self::fetch_utxo_entry`] exactly as dcrd's cache reads its
    /// leveldb backend.
    pub utxo_backend: BTreeMap<OutPointKey, UtxoEntry>,
    /// The UTXO cache with dcrd's exact `UtxoCache` semantics: a
    /// read-through cache over the backend (misses are cached, missing
    /// outputs negatively cached) and a write-back cache for the
    /// connect/disconnect paths.  Fresh entries have never been
    /// flushed, spent non-fresh entries are retained as tombstones
    /// until the next flush, and an explicit `None` marks an output
    /// known to be absent from the backend.  These distinctions are
    /// observable through the entry fields that survive
    /// reorganizations.  Interior mutability lets `&self` reads cache
    /// their misses like dcrd's mutex-guarded cache does.
    pub utxo_cache: RefCell<BTreeMap<OutPointKey, Option<UtxoEntry>>>,
    /// The transaction spend journal by block hash, in dcrd's
    /// serialized journal format: a recent-window mirror of dcrd's
    /// spend journal bucket, which `connect_block` writes; evicted with
    /// the other mirrors and read back from the database past the
    /// window.  The serialization is deliberately round tripped because
    /// dcrd reconstructs the spent entries' heights and indexes from the
    /// spending inputs' fraud proofs on load.
    pub spend_journal: BTreeMap<[u8; 32], Vec<u8>>,
    /// The version 2 GCS filters by block hash; like dcrd, filters
    /// are intentionally not removed on disconnect.
    pub filters: BTreeMap<[u8; 32], FilterV2>,
    /// The header commitment merkle tree leaves by block hash.
    pub header_commitments: BTreeMap<[u8; 32], Vec<Hash>>,
    /// The best chain state snapshot.
    pub state_snapshot: BestState,
    /// Whether several validation checks are skipped for bulk imports
    /// (dcrd `bulkImportMode`).
    pub bulk_import_mode: bool,
    /// The unix time the in-memory state was last pruned (dcrd
    /// `chainPruner.lastPruneTime`).
    last_prune_unix: i64,
    /// The pruning interval in seconds — the target block time (dcrd
    /// `chainPruner.pruningInterval`).
    prune_interval_secs: i64,
    /// The maximum size in bytes the UTXO cache may reach before a
    /// flush and eviction are required (dcrd's `utxoCache.maxSize`
    /// from `--utxocachemaxsize`).
    utxo_cache_max_bytes: u64,
    /// The total size of all utxo entries in the cache in bytes (dcrd
    /// `totalEntrySize`), updated as entries enter and leave.  A cell
    /// because `&self` reads cache their misses.
    utxo_total_entry_size: Cell<u64>,
    /// The cache hit counter (dcrd `hits`).
    utxo_cache_hits: Cell<u64>,
    /// The cache miss counter (dcrd `misses`).
    utxo_cache_misses: Cell<u64>,
    /// The block hash of the last utxo cache flush (dcrd
    /// `lastFlushHash`), compared against the backend's recorded utxo
    /// set state on startup.
    utxo_last_flush_hash: Hash,
    /// The adjusted-clock unix time of the last utxo cache flush
    /// (dcrd `lastFlushTime`, which uses the wall clock; the port
    /// drives the periodic flush interval from the same adjusted
    /// clock the pruner uses so the decision core stays
    /// deterministic).
    utxo_last_flush_unix: i64,
    /// The block height of the last cache eviction (dcrd
    /// `lastEvictionHeight`).
    utxo_last_eviction_height: u32,
    /// The adjusted unix time of the processing call in flight,
    /// feeding the periodic flush check.
    utxo_clock_unix: i64,
    /// Whether the chain has latched to believing it is current.
    pub is_current_latch: bool,
    /// The minimum known cumulative chain work from the parameters.
    pub min_known_work: Option<Uint256>,
    /// The backing database when the chain is persistent.
    pub db: Option<dcroxide_database::Database>,
    /// The treasury state rows by block hash: a recent-window mirror
    /// of dcrd's treasury bucket, evicted with the other mirrors and
    /// read through the database fallback beyond it (the whole bucket
    /// for chains without a database).
    pub treasury_state: BTreeMap<[u8; 32], crate::treasurydb::TreasuryState>,
    /// The blocks each treasury spend was mined in: the in-memory
    /// mirror of dcrd's tspend bucket.
    pub tspend_blocks: BTreeMap<[u8; 32], Vec<Hash>>,
    /// The floor for treasury expenditure limits per DCP0013.
    pub treasury_spend_limit_floor: i64,
    /// The chain event callback (dcrd `BlockChain.notifications`);
    /// invoked synchronously from the processing paths when installed.
    notifications: Option<crate::notifications::NotificationCallback>,
    /// The package log sink (dcrd's `internal/blockchain` package
    /// `log`, installed by its `UseLogger`).  `None` is dcrd's
    /// `slog.Disabled` default, under which the package logs nothing.
    log_sink: Option<LogCallback>,
    /// The shared signature verification cache threaded into every
    /// script engine the connect and mempool paths create (dcrd wires
    /// `s.sigCache` into `blockchain.Config.SigCache`).  Defaults to
    /// a [`DEFAULT_SIG_CACHE_MAX_ENTRIES`]-entry cache; `None`
    /// verifies every signature directly.  Shared behind an `Arc` so
    /// the daemon's mempool seams reuse the same cache.
    pub sig_cache: Option<Arc<dcroxide_txscript::SigCache>>,
    /// The blocks that recently passed the contextual checks (dcrd
    /// `recentContextChecks`).
    recent_context_checks: RecentContextChecks,
    /// The shutdown interrupt (dcrd `BlockChain.interrupt`, its
    /// context's `Done` channel), set by [`Chain::open_with_interrupt`].
    /// Only the startup UTXO catch-up checks it, as dcrd's
    /// `UtxoCache.Initialize` does; the reorganization loops do not
    /// (see [`Chain::reorganize_chain_internal`]).
    interrupt: Option<Arc<AtomicBool>>,
    /// The adjusted-clock unix time the cached chain tips were last
    /// pruned (dcrd `blockIndex.cachedTipsLastPruned`, a wall-clock
    /// time); zero until a connect first observes the clock.
    cached_tips_last_pruned_unix: i64,
}

/// The time between prunes of the cached chain tips, in seconds (dcrd
/// `cachedTipsPruneInterval`, `blockindex.go:50-52`).
const CACHED_TIPS_PRUNE_INTERVAL_SECS: i64 = 5 * 60;

/// The number of recent successful contextual block checks tracked
/// (dcrd `contextCheckCacheSize`, `chain.go:50-52`).
const CONTEXT_CHECK_CACHE_SIZE: usize = 25;

/// The hashes of blocks that recently passed the contextual checks
/// (dcrd's `recentContextChecks`, an `lru.Set` of
/// [`CONTEXT_CHECK_CACHE_SIZE`] hashes, `chain.go:219-223`).
///
/// It is not only an optimization.  dcrd's `checkBlockContext` returns
/// early on a hit (`validate.go:1937-1940`) whatever flags it is called
/// with, and `maybeAcceptBlocks` records every block it checks, with
/// the flags of the block being processed.  A block linked by a
/// fast-added parent is therefore checked with `BFFastAdd` there and
/// skips the full-flag context checks when it is attached, although it
/// was never marked validated itself.
#[derive(Default)]
struct RecentContextChecks {
    /// The hashes, least recently used first.
    hashes: alloc::collections::VecDeque<[u8; 32]>,
}

impl RecentContextChecks {
    /// Whether the hash is present, making it the most recently used
    /// when it is (lru `Set.Contains`).
    fn contains(&mut self, hash: &Hash) -> bool {
        let Some(pos) = self.hashes.iter().position(|h| *h == hash.0) else {
            return false;
        };
        if let Some(h) = self.hashes.remove(pos) {
            self.hashes.push_back(h);
        }
        true
    }

    /// Add the hash, or refresh it, as the most recently used, evicting
    /// the least recently used past the limit (lru `Set.Put`).
    fn put(&mut self, hash: Hash) {
        if let Some(pos) = self.hashes.iter().position(|h| *h == hash.0) {
            self.hashes.remove(pos);
        } else if self.hashes.len() >= CONTEXT_CHECK_CACHE_SIZE {
            self.hashes.pop_front();
        }
        self.hashes.push_back(hash.0);
    }

    /// Remove the hash when present (lru `Set.Delete`).
    fn delete(&mut self, hash: &Hash) {
        if let Some(pos) = self.hashes.iter().position(|h| *h == hash.0) {
            self.hashes.remove(pos);
        }
    }
}

/// Information about the current best chain block and related state
/// (dcrd `BestState`).
#[derive(Clone, Debug)]
pub struct BestState {
    /// The hash of the block.
    pub hash: Hash,
    /// The previous block hash.
    pub prev_hash: Hash,
    /// The height of the block.
    pub height: i64,
    /// The difficulty bits of the block.
    pub bits: u32,
    /// The next ticket pool size.
    pub next_pool_size: u32,
    /// The next stake difficulty.
    pub next_stake_diff: i64,
    /// The size of the block.
    pub block_size: u64,
    /// The number of transactions in the block.
    pub num_txns: u64,
    /// The total number of transactions in the chain.
    pub total_txns: u64,
    /// The past median time as unix seconds.
    pub median_time: i64,
    /// The total subsidy for the chain.
    pub total_subsidy: i64,
    /// The tickets set to expire next block.
    pub next_expiring_tickets: Vec<Hash>,
    /// The eligible tickets to vote on the next block.
    pub next_winning_tickets: Vec<Hash>,
    /// The missed tickets set to be revoked.
    pub missed_tickets: Vec<Hash>,
    /// The lottery state for the next block.
    pub next_final_state: [u8; 6],
}

/// The stake node parameters for a network.
pub fn stake_node_params(params: &Params) -> StakeNodeParams {
    StakeNodeParams {
        votes_per_block: params.tickets_per_block,
        stake_validation_begin_height: params.stake_validation_height,
        stake_enable_height: params.stake_enabled_height,
        ticket_expiry_blocks: params.ticket_expiry,
    }
}

impl Chain {
    /// Create the chain state with the genesis block node in the
    /// index, mirroring the relevant configuration derivation in dcrd
    /// `New` (the fork rejection semantics are disabled when
    /// explicitly requested or the network has no hard-coded assumed
    /// valid hash).
    pub fn new(params: &Params, config_assume_valid: Hash, config_allow_old_forks: bool) -> Chain {
        const TIME_IN_TWO_WEEKS_SECS: i64 = 14 * 24 * 60 * 60;
        let expected_blocks_in_two_weeks =
            TIME_IN_TWO_WEEKS_SECS / params.target_time_per_block_secs;
        let allow_old_forks = config_allow_old_forks || params.assume_valid == Hash::ZERO;

        let mut store = NodeStore::new();
        let mut index = BlockIndex::new();
        let genesis = store.new_node(&params.genesis_block.header, None);
        store.node_mut(genesis).status =
            BlockStatus(BlockStatus::DATA_STORED.0 | BlockStatus::VALIDATED.0);
        store.node_mut(genesis).is_fully_linked = true;
        store.node_mut(genesis).stake_node = Some(StakeNode::genesis(stake_node_params(params)));
        index.add_node(&store, genesis);
        let best_chain = NodeChainView::new(&store, Some(genesis));

        let mut blocks = BTreeMap::new();
        blocks.insert(
            params.genesis_block.header.block_hash().0,
            Arc::new(params.genesis_block.clone()),
        );

        // The initial best state uses the genesis block's own values
        // (dcrd `createChainState`).
        let genesis_block = &params.genesis_block;
        let num_txns = genesis_block.transactions.len() as u64;
        let state_snapshot = BestState {
            hash: genesis_block.header.block_hash(),
            prev_hash: Hash::ZERO,
            height: 0,
            bits: genesis_block.header.bits,
            next_pool_size: 0,
            next_stake_diff: params.minimum_stake_diff,
            block_size: genesis_block.serialize_size() as u64,
            num_txns,
            total_txns: num_txns,
            median_time: i64::from(genesis_block.header.timestamp),
            total_subsidy: 0,
            next_expiring_tickets: Vec::new(),
            next_winning_tickets: Vec::new(),
            missed_tickets: Vec::new(),
            next_final_state: [0u8; 6],
        };

        // The genesis block's committed filter, mirroring dcrd's
        // createChainState which stores it so it can be served like
        // any other block's (the open path stores it too).
        let mut filters = BTreeMap::new();
        {
            struct NoScripts;
            impl dcroxide_gcs::blockcf2::PrevScripter for NoScripts {
                fn prev_script(&self, _out: &OutPoint) -> Option<(u16, &[u8])> {
                    None
                }
            }
            if let Ok(genesis_filter) =
                dcroxide_gcs::blockcf2::regular(&params.genesis_block, &NoScripts)
            {
                filters.insert(params.genesis_block.header.block_hash().0, genesis_filter);
            }
        }

        Chain {
            store,
            index,
            assume_valid: config_assume_valid,
            assume_valid_node: None,
            reject_forks_checkpoint: None,
            allow_old_forks,
            expected_blocks_in_two_weeks,
            best_chain,
            blocks,
            stake_undo: BTreeMap::new(),
            stake_new_tickets: BTreeMap::new(),
            utxo_backend: BTreeMap::new(),
            utxo_cache: RefCell::new(BTreeMap::new()),
            spend_journal: BTreeMap::new(),
            filters,
            header_commitments: BTreeMap::new(),
            state_snapshot,
            bulk_import_mode: false,
            last_prune_unix: 0,
            prune_interval_secs: params.target_time_per_block_secs,
            utxo_cache_max_bytes: DEFAULT_UTXO_CACHE_MAX_BYTES,
            utxo_total_entry_size: Cell::new(0),
            utxo_cache_hits: Cell::new(0),
            utxo_cache_misses: Cell::new(0),
            utxo_last_flush_hash: Hash::ZERO,
            utxo_last_flush_unix: 0,
            utxo_last_eviction_height: 0,
            utxo_clock_unix: 0,
            is_current_latch: false,
            min_known_work: params.min_known_chain_work,
            db: None,
            treasury_state: BTreeMap::new(),
            tspend_blocks: BTreeMap::new(),
            treasury_spend_limit_floor: (params.base_subsidy / 10)
                * (params.treasury_vote_interval * params.treasury_vote_interval_multiplier) as i64,
            notifications: None,
            log_sink: None,
            sig_cache: Some(Arc::new(dcroxide_txscript::SigCache::new(
                DEFAULT_SIG_CACHE_MAX_ENTRIES,
            ))),
            recent_context_checks: RecentContextChecks::default(),
            interrupt: None,
            cached_tips_last_pruned_unix: 0,
        }
    }

    /// Replace the signature verification cache with one holding at
    /// most `max_entries` entries (the `--sigcachemaxsize` config
    /// knob; dcrd sizes the cache by entry count and passes it to
    /// `txscript.NewSigCache` at server creation).  Zero keeps a
    /// cache that never stores anything, exactly like dcrd's.
    pub fn set_sig_cache_max_entries(&mut self, max_entries: usize) {
        self.sig_cache = Some(Arc::new(dcroxide_txscript::SigCache::new(max_entries)));
    }

    /// Install the chain event callback (dcrd `Config.Notifications`).
    /// The callback runs synchronously on the processing thread and
    /// must not call back into the chain.  Installing it after the
    /// chain opens also mirrors dcrd, whose init-time reorganizations
    /// run with notifications suppressed.
    pub fn set_notification_callback(&mut self, callback: NotificationCallback) {
        self.notifications = Some(callback);
    }

    /// Invoke the notification callback when one is installed (dcrd
    /// `sendNotification`).
    fn send_ntfn(
        notifications: &mut Option<NotificationCallback>,
        notification: &Notification<'_>,
    ) {
        if let Some(callback) = notifications {
            callback(notification);
        }
    }

    /// Install the package log sink (dcrd `blockchain.UseLogger`,
    /// which dcrd's `log.go:85` calls at init with the `CHAN` logger).
    /// Until one is installed the chain logs nothing, exactly as dcrd's
    /// `slog.Disabled` package default does.
    pub fn set_log_callback(&mut self, callback: LogCallback) {
        self.log_sink = Some(callback);
    }

    /// Emit a log line when a sink is installed (dcrd's package-level
    /// `log` calls, which are no-ops under `slog.Disabled`).
    fn log(&mut self, level: LogLevel, message: &str) {
        if let Some(sink) = &mut self.log_sink {
            sink(level, message);
        }
    }

    /// Whether the node is an ancestor of (or is) the target (dcrd
    /// `blockNode.IsAncestorOf`), delegating to the block index's own
    /// ancestor walk so the reorg gate and the store never drift.
    fn is_ancestor_of(&self, node: NodeId, target: NodeId) -> bool {
        self.store.is_ancestor_of(node, target)
    }

    /// Open a persistent chain over the database, creating the
    /// initial chain state when the database is fresh and loading the
    /// block index, best chain state, stake node, and chain data
    /// otherwise (dcrd `createChainState`/`initChainState`; the
    /// legacy version migration and `upgradeDB` paths are not
    /// applicable to dcroxide's fresh-sync databases).
    ///
    /// Nor is `New`'s version 3 test network pass (`chain.go:2498-2528`),
    /// which invalidates, with notifications suppressed, every chain
    /// tip whose ancestor at `testNet3MaxDiffActivationHeight` is not
    /// `block962928Hash`.  It cleans up databases that stored the
    /// pre-reset branch before dcrd enforced that checkpoint.  No
    /// dcroxide database can hold such a branch: the only runtime
    /// insertion into the block index, in `maybe_accept_block_header`,
    /// runs `check_block_header_positional` first, and that rejects
    /// any other header at the height with `ErrBadMaxDiffCheckpoint`
    /// whether or not the block is a fast add -- a check that predates
    /// the port's first persisted chain state.
    pub fn open(
        db: dcroxide_database::Database,
        params: &Params,
        config_assume_valid: Hash,
        config_allow_old_forks: bool,
        created_unix: u64,
    ) -> Result<Chain, crate::chaindb::ChainDbError> {
        Self::open_with_interrupt(
            db,
            params,
            config_assume_valid,
            config_allow_old_forks,
            created_unix,
            None,
        )
    }

    /// [`Chain::open`] with the shutdown interrupt, which dcrd's `New`
    /// takes as its context and keeps as `interrupt: ctx.Done()`
    /// (`chain.go:2457`).  Setting it stops the startup UTXO catch-up
    /// replay at the next block with
    /// [`crate::chaindb::ChainDbError::Interrupted`], as dcrd's
    /// `UtxoCache.Initialize` returns `errInterruptRequested`.
    pub fn open_with_interrupt(
        db: dcroxide_database::Database,
        params: &Params,
        config_assume_valid: Hash,
        config_allow_old_forks: bool,
        created_unix: u64,
        interrupt: Option<Arc<AtomicBool>>,
    ) -> Result<Chain, crate::chaindb::ChainDbError> {
        use crate::chaindb;

        let mut chain = Chain::new(params, config_assume_valid, config_allow_old_forks);
        chain.interrupt = interrupt;

        // Determine the state of the database.
        let mut db_info: Option<chaindb::DatabaseInfo> = None;
        db.view(|tx| {
            db_info = chaindb::db_fetch_database_info(tx).ok().flatten();
            Ok(())
        })?;

        // Don't allow downgrades of the database, its compression
        // version, or its block index (dcrd `initChainState`,
        // `chainio.go:1627-1650`, with its messages).  The spend
        // journal version has no such check in dcrd either.
        if let Some(info) = &db_info {
            if info.version > chaindb::CURRENT_DATABASE_VERSION {
                return Err(chaindb::ChainDbError::Corrupt(format!(
                    "the current blockchain database is no longer compatible with this \
                     version of the software ({} > {})",
                    info.version,
                    chaindb::CURRENT_DATABASE_VERSION
                )));
            }
            if info.comp_ver > crate::CURRENT_COMPRESSION_VERSION {
                return Err(chaindb::ChainDbError::Corrupt(format!(
                    "the current database compression version is no longer compatible with \
                     this version of the software ({} > {})",
                    info.comp_ver,
                    crate::CURRENT_COMPRESSION_VERSION
                )));
            }
            if info.bidx_ver > chaindb::CURRENT_BLOCK_INDEX_VERSION {
                return Err(chaindb::ChainDbError::Corrupt(format!(
                    "the current database block index version is no longer compatible with \
                     this version of the software ({} > {})",
                    info.bidx_ver,
                    chaindb::CURRENT_BLOCK_INDEX_VERSION
                )));
            }
        }

        if db_info.is_none() {
            // Create the initial chain state (dcrd `createChainState`).
            let genesis_block = params.genesis_block.clone();
            let genesis_hash = genesis_block.header.block_hash();
            let genesis = chain.best_chain.tip().expect("genesis node");
            let stake_params = stake_node_params(params);
            db.update(|tx| {
                let meta = tx.metadata();
                meta.create_bucket(chaindb::BCDB_INFO_BUCKET_NAME)?;
                chaindb::db_put_database_info(
                    tx,
                    &chaindb::DatabaseInfo {
                        version: chaindb::CURRENT_DATABASE_VERSION,
                        comp_ver: crate::CURRENT_COMPRESSION_VERSION,
                        bidx_ver: chaindb::CURRENT_BLOCK_INDEX_VERSION,
                        created_unix,
                        stxo_ver: chaindb::CURRENT_SPEND_JOURNAL_VERSION,
                    },
                )
                .map_err(chain_db_to_db_error)?;
                meta.create_bucket(chaindb::BLOCK_INDEX_BUCKET_NAME)?;
                meta.create_bucket(chaindb::SPEND_JOURNAL_BUCKET_NAME)?;

                // The genesis block index row and best chain state.
                let entry = crate::chainio::BlockIndexEntry {
                    header: genesis_block.header,
                    status: chain.store.node(genesis).status.0,
                    vote_info: Vec::new(),
                };
                chaindb::db_put_block_index_entry(tx, &genesis_hash, 0, &entry)
                    .map_err(chain_db_to_db_error)?;
                chaindb::db_put_best_state(
                    tx,
                    genesis_hash,
                    0,
                    chain.state_snapshot.total_txns,
                    0,
                    chain.store.node(genesis).work_sum,
                )
                .map_err(chain_db_to_db_error)?;

                // The stake database and the genesis block itself.
                dcroxide_stake::stakedb::init_database_state(
                    tx,
                    stake_params,
                    &genesis_hash,
                    created_unix as u32,
                )
                .map_err(|e| db_driver_error(format!("stake db: {e:?}")))?;
                tx.store_block(&genesis_block)?;

                // The remaining buckets and the empty genesis filter.
                meta.create_bucket(chaindb::GCS_FILTER_BUCKET_NAME)?;
                struct NoScripts;
                impl dcroxide_gcs::blockcf2::PrevScripter for NoScripts {
                    fn prev_script(&self, _out: &OutPoint) -> Option<(u16, &[u8])> {
                        None
                    }
                }
                let genesis_filter = dcroxide_gcs::blockcf2::regular(&genesis_block, &NoScripts)
                    .map_err(|e| db_driver_error(format!("genesis filter: {e:?}")))?;
                chaindb::db_put_gcs_filter(tx, &genesis_hash, &genesis_filter)
                    .map_err(chain_db_to_db_error)?;
                meta.create_bucket(chaindb::TREASURY_BUCKET_NAME)?;
                meta.create_bucket(chaindb::TREASURY_TSPEND_BUCKET_NAME)?;
                meta.create_bucket(chaindb::HEADER_CMTS_BUCKET_NAME)?;
                meta.create_bucket(chaindb::UTXO_SET_BUCKET_NAME)?;

                // The deployment version row.
                chaindb::db_put_deployment_ver(
                    tx,
                    crate::thresholdstate::current_deployment_version(params),
                )
                .map_err(chain_db_to_db_error)?;
                Ok(())
            })?;
            chain.filters.insert(genesis_hash.0, {
                struct NoScripts;
                impl dcroxide_gcs::blockcf2::PrevScripter for NoScripts {
                    fn prev_script(&self, _out: &OutPoint) -> Option<(u16, &[u8])> {
                        None
                    }
                }
                dcroxide_gcs::blockcf2::regular(&params.genesis_block, &NoScripts)
                    .expect("genesis filter")
            });
            chain.db = Some(db);
            // Record the fresh utxo set state at the genesis tip
            // (dcrd initializes the utxo cache during `New`).
            chain.initialize_utxo_state(params)?;
            return Ok(chain);
        }

        // Load the chain state (dcrd `initChainState`).
        let mut load_err: Option<chaindb::ChainDbError> = None;
        let mut new_rules_start_time = 0u64;
        db.view(|tx| {
            match chain.load_chain_state(tx, params) {
                Ok(start_time) => new_rules_start_time = start_time,
                Err(err) => load_err = Some(err),
            }
            Ok(())
        })?;
        if let Some(err) = load_err {
            return Err(err);
        }
        chain.db = Some(db);

        // dcrd flushes the block index here when new rules were
        // detected, "since blocks may have been unmarked", before it
        // advances the deployment version (`chainio.go:1776-1793`).
        // The unmarking never marks those nodes modified, though, so
        // that flush writes none of their rows (`blockindex.go:1411`
        // returns on an empty modified set): the cleared statuses live
        // in memory only.  The flush is kept for whatever else is
        // queued, as dcrd has it.
        if new_rules_start_time != 0 {
            chain.flush_block_index(params)?;
        }
        chain.update_deployment_version(params)?;

        // Catch the utxo set up to the tip of the best chain: the
        // cache only flushes periodically, so an unclean shutdown
        // leaves the on-disk set behind the chain (dcrd initializes
        // the utxo cache during `New`).
        chain.initialize_utxo_state(params)?;
        Ok(chain)
    }

    /// Load the block index, best chain state, stake node, and chain
    /// data from the database transaction (the body of dcrd
    /// `initChainState` after initialization is known to have
    /// happened).
    ///
    /// Returns the start time of the newly detected deployments, which
    /// the caller needs: a non-zero one is what makes dcrd flush the
    /// block index before advancing the stored deployment version
    /// (`chainio.go:1776-1793`).
    fn load_chain_state(
        &mut self,
        tx: &dcroxide_database::Transaction,
        params: &Params,
    ) -> Result<u64, crate::chaindb::ChainDbError> {
        use crate::chaindb;

        let state = chaindb::db_fetch_best_state(tx)?;

        // Determine the earliest start time of newly detected
        // deployment versions and update the stored version.
        let cur_version = crate::thresholdstate::current_deployment_version(params);
        let prev_version = chaindb::db_fetch_deployment_ver(tx);
        let mut new_rules_start_time: u64 = 0;
        if cur_version != 0 && cur_version > prev_version {
            let next_version = crate::thresholdstate::next_deployment_version(params, prev_version);
            if let Some((_, deployments)) =
                params.deployments.iter().find(|(v, _)| *v == next_version)
                && let Some(first) = deployments.first()
            {
                new_rules_start_time = first.start_time;
            }
        }

        // Load the block index in height order, building each node as
        // its row is decoded rather than collecting the rows first, as
        // dcrd's `loadBlockIndex` walks its cursor
        // (`chainio.go:1416-1509`).  Only the first entry is hashed
        // here, for the genesis check; `new_node` hashes every other
        // header once, as dcrd's `initBlockNode` does.
        let genesis_hash = params.genesis_block.header.block_hash();
        let mut first = true;
        let mut last_node: Option<NodeId> = None;
        chaindb::db_load_block_index(tx, |entry| {
            if first {
                // The first entry is the genesis block, which the
                // constructor already created, so there is nothing to
                // add -- only the shape to check.
                first = false;
                if entry.header.block_hash() != genesis_hash {
                    return Err(chaindb::ChainDbError::Corrupt(
                        "expected first block index entry to be the genesis block".into(),
                    ));
                }
                last_node = self.index.lookup_node(&genesis_hash);
                return Ok(());
            }
            // Rows arrive in height order, so the previous one is very
            // likely the parent (dcrd's `lastNode` shortcut).
            let parent = match last_node {
                Some(last) if entry.header.prev_block == self.store.node(last).hash => last,
                _ => self
                    .index
                    .lookup_node(&entry.header.prev_block)
                    .ok_or_else(|| {
                        chaindb::ChainDbError::Corrupt(format!(
                            "could not find parent for block {}",
                            entry.header.block_hash()
                        ))
                    })?,
            };
            let node = self.store.new_node(&entry.header, Some(parent));
            {
                // Only the votes come back from the row.  The voted and
                // revoked tickets stay unpopulated, exactly as dcrd's
                // `loadBlockIndex` leaves `ticketsVoted`/`ticketsRevoked`
                // nil (`chainio.go:1488-1502`), so the first
                // `maybe_fetch_ticket_info` re-reads them from the block
                // (`stakenode.go:71-81`).  Marking them populated here
                // handed `fetch_stake_node` empty lists, which recorded
                // every voter as missed and dropped every revocation.
                let n = self.store.node_mut(node);
                n.status = crate::blockindex::BlockStatus(entry.status);
                n.votes = entry.vote_info;
            }

            // Unmark blocks that failed validation before newly
            // detected consensus rules took effect.  The change is made
            // in memory only, exactly as in dcrd: its `loadBlockIndex`
            // clears the bits and then inserts the node with
            // `addNodeFromDB`, which never marks it modified
            // (`chainio.go:1494-1502`, `blockindex.go:733-751`).  So the
            // row keeps its failure on disk until something else
            // rewrites it -- a revalidation, or a ticket info reload
            // (`maybe_fetch_ticket_info` marks like dcrd's
            // `PopulateTicketInfo`) -- and a node restarted again
            // before that reloads it as failed, even though the
            // deployment version has moved on by then.
            if new_rules_start_time != 0 {
                let status = self.store.node(node).status;
                if status.known_validate_failed() || status.known_invalid_ancestor() {
                    let median_time = self.store.calc_past_median_time(node);
                    if median_time >= 0 && median_time as u64 >= new_rules_start_time {
                        let n = self.store.node_mut(node);
                        n.status = crate::blockindex::BlockStatus(
                            n.status.0
                                & !(crate::blockindex::BlockStatus::VALIDATE_FAILED.0
                                    | crate::blockindex::BlockStatus::INVALID_ANCESTOR.0),
                        );
                    }
                }
            }

            let parent_can_validate = self.index.can_validate(&self.store, parent);
            self.store.node_mut(node).is_fully_linked = parent_can_validate;
            self.index.add_node_from_db(&self.store, node);
            last_node = Some(node);
            Ok(())
        })?;
        // Set the best chain to the stored state.
        let tip = self.index.lookup_node(&state.hash).ok_or_else(|| {
            crate::chaindb::ChainDbError::Corrupt(format!(
                "cannot find chain tip {} in block index",
                state.hash
            ))
        })?;
        self.best_chain.set_tip(&self.store, Some(tip));
        self.index.prune_cached_tips(&self.store, tip);
        self.index.add_best_chain_candidate(tip);

        // Load the stake node for the tip.
        let tip_header = self.store.header(tip);
        let stake_node = dcroxide_stake::stakedb::load_best_node(
            tx,
            state.height,
            &state.hash,
            &tip_header.serialize(),
            stake_node_params(params),
        )
        .map_err(|e| crate::chaindb::ChainDbError::Corrupt(format!("stake node: {e:?}")))?;
        {
            let n = self.store.node_mut(tip);
            n.new_tickets = Some(stake_node.new_tickets().to_vec());
            n.stake_node = Some(stake_node.clone());
        }

        // Warm the recent-window mirrors (blocks, spend journals,
        // filters, commitments, treasury state rows) only within
        // `MIN_MEMORY_STAKE_NODES` of the tip; everything older is
        // served from the database on demand through the fallbacks, so
        // a restart at a large tip does not load the whole chain into
        // memory.  dcrd keeps none of these resident; it reads its
        // database, which the fallbacks do past the window.
        let keep_below = i64::from(state.height).saturating_sub(Self::MIN_MEMORY_STAKE_NODES);
        let node_ids: Vec<NodeId> = {
            let mut ids = Vec::new();
            let _ = self.index.for_each_chain_tip(|t| -> Result<(), ()> {
                let mut n = Some(t);
                while let Some(id) = n {
                    if self.store.node(id).height < keep_below {
                        break;
                    }
                    ids.push(id);
                    n = self.store.node(id).parent;
                }
                Ok(())
            });
            ids.sort_unstable();
            ids.dedup();
            ids
        };
        for id in node_ids {
            let n = self.store.node(id);
            if !n.status.have_data() {
                continue;
            }
            let hash = n.hash;
            let raw = tx.fetch_block(&hash)?;
            let (block, _) = dcroxide_wire::MsgBlock::from_bytes(&raw).map_err(|e| {
                crate::chaindb::ChainDbError::Corrupt(format!("bad stored block: {e:?}"))
            })?;
            self.blocks.insert(hash.0, Arc::new(block));

            let meta = tx.metadata();
            if let Some(bucket) = meta.bucket(crate::chaindb::SPEND_JOURNAL_BUCKET_NAME)
                && let Some(journal) = bucket.get(&hash.0)
            {
                self.spend_journal.insert(hash.0, journal);
            }
            if let Some(filter) = crate::chaindb::db_fetch_gcs_filter(tx, &hash)? {
                self.filters.insert(hash.0, filter);
            }
            let commitments = crate::chaindb::db_fetch_header_commitments(tx, &hash)?;
            if !commitments.is_empty() {
                self.header_commitments.insert(hash.0, commitments);
            }
            if let Some(ts) = crate::treasurydb::db_fetch_treasury_balance(tx, &hash)? {
                self.treasury_state.insert(hash.0, ts);
            }
        }

        // The per-height ticket database rows are read from the
        // database on demand (through `ticket_rows_by_height`) during
        // the stake-node regeneration walk, so they are not warmed
        // into memory here.
        let meta = tx.metadata();

        // The treasury spend rows, one per mined treasury spend, are
        // loaded in full: `check_tspend_exists` reads only the mirror.
        if let Some(bucket) = meta.bucket(crate::chaindb::TREASURY_TSPEND_BUCKET_NAME) {
            let mut rows: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            bucket.for_each(|k, v| {
                rows.push((k.to_vec(), v.to_vec()));
                Ok(())
            })?;
            for (k, v) in rows {
                if k.len() == 32 {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&k);
                    let blocks = crate::treasurydb::deserialize_tspend(&v)
                        .map_err(crate::chaindb::ChainDbError::Corrupt)?;
                    self.tspend_blocks.insert(hash, blocks);
                }
            }
        }

        // The UTXO set stays on disk: entries are read through the
        // cache on demand (dcrd's utxo backend), and
        // `initialize_utxo_state` catches the set up to the tip after
        // the chain state loads.

        // Rebuild the best state snapshot.
        let tip_block = self
            .blocks
            .get(&state.hash.0)
            .ok_or_else(|| crate::chaindb::ChainDbError::Corrupt("missing tip block".into()))?
            .clone();
        let stake_node = self
            .store
            .node(tip)
            .stake_node
            .clone()
            .expect("tip stake node loaded");
        let next_stake_diff = {
            let view = NodeBranchView {
                store: &self.store,
                tip,
            };
            let node_diff = crate::difficulty::ChainView::node(&view, self.store.node(tip).height);
            crate::agendas::calc_next_required_stake_difficulty(&view, node_diff.as_ref(), params)
        };
        self.maybe_set_fork_rejection_checkpoint(params);
        if self.assume_valid != Hash::ZERO {
            self.assume_valid_node = self.index.lookup_node(&self.assume_valid);
        }
        let tip_node = self.store.node(tip);
        self.state_snapshot = BestState {
            hash: tip_node.hash,
            prev_hash: tip_node
                .parent
                .map(|p| self.store.node(p).hash)
                .unwrap_or(Hash::ZERO),
            height: tip_node.height,
            bits: tip_node.bits,
            next_pool_size: stake_node.pool_size() as u32,
            next_stake_diff,
            block_size: tip_block.serialize_size() as u64,
            num_txns: tip_block.transactions.len() as u64,
            total_txns: state.total_txns,
            median_time: self.store.calc_past_median_time(tip),
            total_subsidy: state.total_subsidy,
            next_expiring_tickets: stake_node.expiring_next_block(),
            next_winning_tickets: stake_node.winners().to_vec(),
            missed_tickets: stake_node.missed_tickets(),
            next_final_state: stake_node.final_state(),
        };
        Ok(new_rules_start_time)
    }

    /// Advance the stored deployment version to the binary's (dcrd
    /// `updateDeploymentVersion`, `chainio.go:1547-1572`).
    ///
    /// Its own transaction, after the block index flush, because the
    /// stored version is what tells the next startup whether the
    /// new-rules pass still has work: writing it before those rows are
    /// durable would let a crash in between skip the pass forever.
    fn update_deployment_version(
        &self,
        params: &Params,
    ) -> Result<(), crate::chaindb::ChainDbError> {
        let cur_version = crate::thresholdstate::current_deployment_version(params);
        // Zero means the network does not track deployments and always
        // uses the latest rules, so there is nothing to record.
        if cur_version == 0 {
            return Ok(());
        }
        let Some(db) = &self.db else {
            return Ok(());
        };
        db.update(|tx| {
            if crate::chaindb::db_fetch_deployment_ver(tx) != cur_version {
                crate::chaindb::db_put_deployment_ver(tx, cur_version)
                    .map_err(chain_db_to_db_error)?;
            }
            Ok(())
        })
        .map_err(crate::chaindb::ChainDbError::Db)
    }

    /// Flush the durable chain state: the modified block index rows,
    /// the UTXO cache, its set state, and the best chain state (the
    /// clean-shutdown flush dcrd performs).
    pub fn flush(&mut self, params: &Params) -> Result<(), crate::chaindb::ChainDbError> {
        if self.db.is_none() {
            return Ok(());
        }
        let rows = self.take_block_index_rows(params)?;
        let tip = self.best_chain.tip().expect("best chain tip");
        let (tip_hash, tip_height, work_sum) = {
            let n = self.store.node(tip);
            (n.hash, n.height, n.work_sum)
        };
        let eviction_height = self.utxo_calc_flush_eviction_height(tip_height as u32);
        let snapshot = self.state_snapshot.clone();
        let db = self.db.as_ref().expect("checked above");
        let cache = self.utxo_cache.borrow();
        // One transaction for the block index rows, the UTXO entries,
        // and both state markers: dcrd's backend `PutUtxos` couples the
        // entry writes with the utxo set state atomically, so a crash
        // mid-shutdown can never leave the flushed set ahead of (or
        // behind) its recorded state.
        db.update(|tx| {
            for (hash, height, entry) in &rows {
                crate::chaindb::db_put_block_index_entry(tx, hash, *height, entry)
                    .map_err(chain_db_to_db_error)?;
            }
            crate::chaindb::db_put_utxos(tx, utxo_flush_rows(&cache))
                .map_err(chain_db_to_db_error)?;
            crate::chaindb::db_put_utxo_set_state(
                tx,
                &crate::utxoio::UtxoSetState {
                    last_flush_height: tip_height as u32,
                    last_flush_hash: tip_hash,
                },
            )
            .map_err(chain_db_to_db_error)?;
            crate::chaindb::db_put_best_state(
                tx,
                snapshot.hash,
                snapshot.height as u32,
                snapshot.total_txns,
                snapshot.total_subsidy,
                work_sum,
            )
            .map_err(chain_db_to_db_error)?;
            Ok(())
        })?;
        drop(cache);
        self.utxo_flush_finish(eviction_height, tip_hash);
        // Make everything durable: dcrd's UTXO cache flush makes the
        // block database durable on every flush (`flushBlockDB` at
        // the start of dcrd's `UtxoCache.flush`); with the single
        // shared database here, one flush after the combined update
        // covers both atomically.
        if let Err(e) = self.db.as_ref().expect("checked above").flush() {
            return Err(crate::chaindb::ChainDbError::Db(e));
        }
        Ok(())
    }

    /// Flush the modified block index rows and warn rather than fail
    /// on the write (dcrd `flushBlockIndexWarnOnly`,
    /// `chain.go:1516-1520`).
    ///
    /// The administrative paths use this: their work is already done by
    /// the time they reach it, and dcrd does not fail an
    /// `invalidateblock` because the write did not land.
    ///
    /// The warning goes to the package log sink, which the daemon
    /// renders under dcrd's `CHAN` tag; with no sink installed nothing
    /// is emitted, exactly as dcrd's `slog.Disabled` package default.
    /// The text after the colon is this storage layer's own error
    /// description, not dcrd's.
    ///
    /// Note that dcrd's `blockIndex.Flush` clears its modified set only
    /// after a successful write, so a failed flush there is retried by
    /// the next one; here the rows are already drained by the time the
    /// failure is seen, so nothing retries them.  That divergence is
    /// recorded in PARITY.md and is not changed by this warning.
    fn flush_block_index_warn_only(&mut self, params: &Params) {
        if let Err(e) = self.flush_block_index(params) {
            self.log(
                LogLevel::Warn,
                &format!("Unable to flush block index changes to db: {e}"),
            );
        }
    }

    /// Write the modified block index entries to the database,
    /// populating pruned ticket info first (dcrd `flushBlockIndex`).
    fn flush_block_index(&mut self, params: &Params) -> Result<(), crate::chaindb::ChainDbError> {
        if self.db.is_none() {
            return Ok(());
        }
        // Nothing to flush when no node is modified: dcrd's
        // `blockIndex.Flush` returns before it touches the database at
        // all (`blockindex.go:1409-1414`).  Without this the
        // unconditional `db.update` below still opens a write
        // transaction, which a closed or write-latched store refuses
        // (`check_open`/`check_writable` run before the closure), so
        // `flush_block_index_warn_only` would warn where dcrd is
        // silent -- notably on `force_head_reorganization`'s success
        // path, where dcrd's own comment says the index is modified
        // only if the block failed to connect.
        if self.index.modified_len() == 0 {
            return Ok(());
        }
        let rows = self.take_block_index_rows(params)?;
        let db = self.db.as_ref().expect("checked above");
        db.update(|tx| {
            for (hash, height, entry) in &rows {
                crate::chaindb::db_put_block_index_entry(tx, hash, *height, entry)
                    .map_err(chain_db_to_db_error)?;
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Collect the modified block index rows for a flush, populating
    /// pruned ticket info first (the row half of dcrd
    /// `flushBlockIndex`).
    fn take_block_index_rows(
        &mut self,
        params: &Params,
    ) -> Result<Vec<(Hash, u32, crate::chainio::BlockIndexEntry)>, crate::chaindb::ChainDbError>
    {
        let modified = self.index.take_modified();
        // Reload any pruned ticket info for the modified nodes that can
        // be validated (dcrd `flushBlockIndex`, `chain.go:1490-1503`).
        // `can_validate` rather than `have_data` is dcrd's gate: it
        // guarantees every ancestor has its data, which the maturing
        // tickets lookup reads.
        for &id in &modified {
            if !self.index.can_validate(&self.store, id) {
                continue;
            }
            if let Err(err) = self.maybe_fetch_ticket_info(id, params) {
                // dcrd returns before `blockIndex.Flush` clears its
                // modified set, so the nodes stay queued.
                for &id in &modified {
                    self.index.mark_modified(id);
                }
                return Err(crate::chaindb::ChainDbError::Corrupt(err.description));
            }
        }
        // The reload marks each node it populates, which dcrd does
        // before `Flush` drains the set; every one of them is already
        // in `modified`, so drain the marks again rather than rewrite
        // those rows at the next flush.
        let _ = self.index.take_modified();
        let mut rows = Vec::with_capacity(modified.len());
        for id in modified {
            let n = self.store.node(id);
            rows.push((
                n.hash,
                n.height as u32,
                crate::chainio::BlockIndexEntry {
                    header: self.store.header(id),
                    status: n.status.0,
                    vote_info: n.votes.clone(),
                },
            ));
        }
        Ok(rows)
    }

    /// Apply the view's committed changes to the UTXO cache with dcrd
    /// `UtxoCache.Commit` semantics: spent view entries go through
    /// the spend bookkeeping and everything else is added or updated.
    pub fn commit_view(&mut self, view: &mut UtxoView) {
        for (key, entry) in view.commit() {
            if entry.is_spent() {
                self.cache_spend_entry(key);
            } else {
                self.cache_add_entry(key, entry);
            }
        }
    }

    /// Add or update an unspent entry in the cache (dcrd
    /// `UtxoCache.addEntry`): new-to-cache entries are marked fresh
    /// and updates take the existing entry's freshness, clearing any
    /// fresh bit the incoming entry carries when the existing one is
    /// not (`utxocache.go:305-309`) -- a fresh entry over a row the
    /// backend holds would make a later spend drop the entry without
    /// ever deleting that row.
    fn cache_add_entry(&mut self, key: OutPointKey, mut entry: UtxoEntry) {
        entry.set_state_bits(entry.state_bits() | crate::utxoentry::UTXO_STATE_MODIFIED);
        let entry_size = utxo_entry_size(&entry);
        let mut total = self.utxo_total_entry_size.get();
        // One descent of the map for the probe and the store alike.
        let slot = self.utxo_cache.get_mut().entry(key).or_insert(None);
        match slot {
            Some(existing) => {
                if existing.is_fresh() {
                    entry.set_state_bits(entry.state_bits() | crate::utxoentry::UTXO_STATE_FRESH);
                } else {
                    entry.set_state_bits(entry.state_bits() & !crate::utxoentry::UTXO_STATE_FRESH);
                }
                total = total.saturating_sub(utxo_entry_size(existing));
            }
            // Both a missing entry and an explicit spent marker mean
            // the backend has never seen this output (dcrd's map
            // lookup returns nil for both).
            None => {
                entry.set_state_bits(entry.state_bits() | crate::utxoentry::UTXO_STATE_FRESH);
            }
        }
        *slot = Some(entry);
        self.utxo_total_entry_size
            .set(total.saturating_add(entry_size));
    }

    /// Spend an output in the cache (dcrd `UtxoCache.spendEntry`):
    /// fresh entries are replaced with an explicit spent marker since
    /// the backend never knew about them, other cached entries become
    /// spent tombstones, and cache misses pull the backend entry in
    /// as a tombstone so the next flush removes it.
    fn cache_spend_entry(&mut self, key: OutPointKey) {
        // What the cache probe decided; the mutating follow-ups run
        // with the probe's borrow released.
        enum SpendAction {
            Done,
            Tombstone(u64),
            BackendLookup,
        }
        let action = match self.utxo_cache.get_mut().get_mut(&key) {
            Some(slot) => match slot {
                None => SpendAction::Done,
                Some(entry) => {
                    assert!(!entry.is_spent(), "attempt to double spend in view commit");
                    if entry.is_fresh() {
                        // A fresh entry was never flushed: replace it
                        // in place with an explicit spent marker so
                        // later lookups still hit.
                        let removed_size = utxo_entry_size(entry);
                        *slot = None;
                        SpendAction::Tombstone(removed_size)
                    } else {
                        entry.set_state_bits(
                            entry.state_bits()
                                | crate::utxoentry::UTXO_STATE_SPENT
                                | crate::utxoentry::UTXO_STATE_MODIFIED,
                        );
                        SpendAction::Done
                    }
                }
            },
            None => SpendAction::BackendLookup,
        };
        match action {
            SpendAction::Done => {}
            SpendAction::Tombstone(removed_size) => {
                self.utxo_total_entry_size.set(
                    self.utxo_total_entry_size
                        .get()
                        .saturating_sub(removed_size),
                );
            }
            // The output has no cache entry at all: pull it from the
            // backend so the next flush removes its row (a missing
            // backend entry is not an error and is NOT negatively
            // cached here — a double spend would be the only future
            // lookup).
            SpendAction::BackendLookup => {
                self.utxo_cache_misses
                    .set(self.utxo_cache_misses.get().wrapping_add(1));
                if let Some(mut entry) = self.backend_fetch_entry(&key) {
                    self.utxo_total_entry_size.set(
                        self.utxo_total_entry_size
                            .get()
                            .saturating_add(utxo_entry_size(&entry)),
                    );
                    entry.set_state_bits(
                        entry.state_bits()
                            | crate::utxoentry::UTXO_STATE_SPENT
                            | crate::utxoentry::UTXO_STATE_MODIFIED,
                    );
                    self.utxo_cache.get_mut().insert(key, Some(entry));
                }
            }
        }
    }

    /// Fetch an entry from the backend, bypassing the cache: the
    /// utxo set bucket on disk for database-backed chains (dcrd
    /// `levelDbUtxoBackend.FetchEntry`) and the in-memory map for the
    /// pure-memory test chains.  Missing outputs return `None`;
    /// entries for spent outputs and undecodable rows panic — the
    /// resolver seam has no error channel, so the class dcrd surfaces
    /// as backend errors aborts here (a documented divergence).
    ///
    /// A redb *read* error aborts here too.  `db_fetch_utxo_entry`
    /// reads with `Bucket::try_get`, which returns it rather than
    /// reading it as a missing output, as `levelDbUtxoBackend.Get`
    /// separates `ErrNotFound` from a real error and `dbFetchUtxoEntry`
    /// propagates it.  Read as absence it would not stay within one
    /// transaction: after an I/O error redb keeps serving cached pages
    /// and fails only the uncached ones, so every later block needing
    /// an uncached output would be rejected as `ErrMissingTxOut` until
    /// restart.
    fn backend_fetch_entry(&self, key: &OutPointKey) -> Option<UtxoEntry> {
        let Some(db) = &self.db else {
            return self.utxo_backend.get(key).cloned();
        };
        let outpoint = OutPoint {
            hash: Hash(key.0),
            index: key.1,
            tree: key.2,
        };
        let mut found: Option<UtxoEntry> = None;
        db.view(|tx| {
            found = crate::chaindb::db_fetch_utxo_entry(tx, &outpoint)
                .expect("corrupt utxo backend entry");
            Ok(())
        })
        .expect("utxo backend read");
        found
    }

    /// The eviction height for a flush at the given best height —
    /// the height the flush records, exactly the parameter dcrd's
    /// `flush` receives: entries in blocks below it leave the cache
    /// when the maximum size has been reached, and zero (no height
    /// eviction) otherwise (the eviction half of dcrd
    /// `UtxoCache.flush`).
    fn utxo_calc_flush_eviction_height(&self, best_height: u32) -> u32 {
        if self.utxo_cache_total_size() < self.utxo_cache_max_bytes {
            return 0;
        }
        self.calc_eviction_height(best_height)
    }

    /// The eviction height from the best height and the last eviction
    /// height (dcrd `UtxoCache.calcEvictionHeight`).
    fn calc_eviction_height(&self, best_height: u32) -> u32 {
        if best_height < self.utxo_last_eviction_height {
            return best_height;
        }
        let last_eviction_depth = best_height - self.utxo_last_eviction_height;
        let num_blocks_to_evict =
            (f64::from(last_eviction_depth) * UTXO_CACHE_EVICTION_PERCENTAGE).ceil() as u32;
        self.utxo_last_eviction_height
            .saturating_add(num_blocks_to_evict)
    }

    /// The total size of the cache in dcrd's accounting: the map
    /// overhead, outpoint, and pointer per entry plus the entry sizes
    /// (dcrd `UtxoCache.totalSize`).
    fn utxo_cache_total_size(&self) -> u64 {
        let num_entries = self.utxo_cache.borrow().len() as u64;
        UTXO_CACHE_MAP_OVERHEAD
            .saturating_add(UTXO_CACHE_OUTPOINT_SIZE)
            .saturating_add(UTXO_CACHE_POINTER_SIZE)
            .saturating_mul(num_entries)
            .saturating_add(self.utxo_total_entry_size.get())
    }

    /// Whether a non-forced flush is due (dcrd
    /// `UtxoCache.shouldFlush`): not when already flushed through the
    /// best hash, and otherwise when the maximum size or the periodic
    /// flush interval has been reached.
    fn utxo_should_flush(&self, best_hash: &Hash) -> bool {
        if self.utxo_last_flush_hash == *best_hash {
            return false;
        }
        if self.utxo_cache_total_size() >= self.utxo_cache_max_bytes {
            return true;
        }
        self.utxo_clock_unix
            .saturating_sub(self.utxo_last_flush_unix)
            >= UTXO_PERIODIC_FLUSH_SECS
    }

    /// Conditionally flush the cache to the backend (dcrd
    /// `UtxoCache.MaybeFlush`).
    fn maybe_flush_utxo_cache(
        &mut self,
        best_hash: Hash,
        best_height: u32,
        force: bool,
    ) -> Result<(), crate::chaindb::ChainDbError> {
        if force || self.utxo_should_flush(&best_hash) {
            self.flush_utxo_cache(best_hash, best_height)?;
        }
        Ok(())
    }

    /// Flush the cache to the backend (dcrd `UtxoCache.flush`): the
    /// modified entries are written — spent tombstones delete their
    /// backend rows, unspent entries land with the cache state
    /// cleared — and the cache then evicts tombstones, spent entries,
    /// and (once the maximum size has been reached) entries in blocks
    /// below the eviction height, keeping the rest as clean read
    /// cache.  The entry writes and the utxo set state land in ONE
    /// database transaction, exactly as dcrd's backend
    /// `PutUtxos(utxos, state)` couples them, so a crash can never
    /// leave the flushed set and its recorded state out of step.
    fn flush_utxo_cache(
        &mut self,
        last_flush_hash: Hash,
        last_flush_height: u32,
    ) -> Result<(), crate::chaindb::ChainDbError> {
        let eviction_height = self.utxo_calc_flush_eviction_height(last_flush_height);
        if let Some(db) = &self.db {
            // The rows are serialized straight out of the cache, which
            // ignores the state bits, so nothing is cloned to clear
            // them first.
            let cache = self.utxo_cache.borrow();
            db.update(|tx| {
                crate::chaindb::db_put_utxos(tx, utxo_flush_rows(&cache))
                    .map_err(chain_db_to_db_error)?;
                crate::chaindb::db_put_utxo_set_state(
                    tx,
                    &crate::utxoio::UtxoSetState {
                        last_flush_height,
                        last_flush_hash,
                    },
                )
                .map_err(chain_db_to_db_error)?;
                Ok(())
            })
            .map_err(crate::chaindb::ChainDbError::Db)?;
        } else {
            self.utxo_flush_to_memory_backend();
        }
        // The eviction needs the rows only committed, not durable: an
        // evicted entry is read back through the database cache's
        // overlay until that reaches disk, and a crash before then loses
        // the in-memory state along with it.
        self.utxo_flush_finish(eviction_height, last_flush_hash);
        // Bound the crash-loss window to the UTXO flush cadence like
        // dcrd, whose every UTXO cache flush makes the block database
        // durable (`flushBlockDB`).
        if let Some(db) = self.db.as_ref()
            && let Err(e) = db.flush()
        {
            return Err(crate::chaindb::ChainDbError::Db(e));
        }
        Ok(())
    }

    /// Apply the modified cache entries to the in-memory backend of a
    /// chain without a database (the write half of dcrd
    /// `UtxoCache.flush`; dcrd's `dbPutUtxoEntry` skips unmodified
    /// entries the same way).  Database-backed chains write
    /// [`utxo_flush_rows`] inside their flush transaction instead.
    fn utxo_flush_to_memory_backend(&mut self) {
        let mut memory_writes: Vec<(OutPointKey, Option<UtxoEntry>)> = Vec::new();
        for (key, entry) in self.utxo_cache.get_mut().iter() {
            let Some(entry) = entry else {
                continue;
            };
            if !entry.is_modified() {
                continue;
            }
            if entry.is_spent() {
                memory_writes.push((*key, None));
            } else {
                let mut cleaned = entry.clone();
                cleaned.set_state_bits(0);
                memory_writes.push((*key, Some(cleaned)));
            }
        }
        for (key, write) in memory_writes {
            match write {
                None => {
                    self.utxo_backend.remove(&key);
                }
                Some(entry) => {
                    self.utxo_backend.insert(key, entry);
                }
            }
        }
    }

    /// Evict and clean the cache after a successful backend write
    /// (the post-write half of dcrd `UtxoCache.flush`): tombstones,
    /// spent entries, and entries below the eviction height leave;
    /// everything retained has its modified and fresh flags cleared.
    fn utxo_flush_finish(&mut self, eviction_height: u32, last_flush_hash: Hash) {
        let mut total = self.utxo_total_entry_size.get();
        self.utxo_cache.get_mut().retain(|_, entry| {
            let evict = match entry {
                None => true,
                Some(e) => e.is_spent() || e.block_height() < i64::from(eviction_height),
            };
            if evict {
                if let Some(e) = entry {
                    total = total.saturating_sub(utxo_entry_size(e));
                }
                return false;
            }
            if let Some(e) = entry {
                e.set_state_bits(
                    e.state_bits()
                        & !(crate::utxoentry::UTXO_STATE_MODIFIED
                            | crate::utxoentry::UTXO_STATE_FRESH),
                );
            }
            true
        });
        self.utxo_total_entry_size.set(total);
        self.utxo_last_flush_hash = last_flush_hash;
        self.utxo_last_flush_unix = self.utxo_clock_unix;
        if eviction_height != 0 {
            self.utxo_last_eviction_height = eviction_height;
        }
    }

    /// Catch the utxo set up to the tip of the best chain (dcrd
    /// `UtxoCache.Initialize`, without the backend upgrade step that
    /// does not apply to a fresh implementation): since the cache
    /// only flushes periodically, an unclean shutdown leaves the
    /// recorded utxo set state behind the best chain — or past it,
    /// across an interrupted disconnect.  Blocks are disconnected
    /// back to the fork point using their spend journals and replayed
    /// forward through the cache until the set matches the tip.  On a
    /// fresh backend the state is simply recorded at the tip.
    pub fn initialize_utxo_state(
        &mut self,
        params: &Params,
    ) -> Result<(), crate::chaindb::ChainDbError> {
        if self.db.is_none() {
            return Ok(());
        }

        // The recorded utxo set state.
        let mut state: Option<crate::utxoio::UtxoSetState> = None;
        let mut state_err: Option<crate::chaindb::ChainDbError> = None;
        {
            let db = self.db.as_ref().expect("checked above");
            db.view(|tx| {
                match crate::chaindb::db_fetch_utxo_set_state(tx) {
                    Ok(s) => state = s,
                    Err(e) => state_err = Some(e),
                }
                Ok(())
            })
            .map_err(crate::chaindb::ChainDbError::Db)?;
        }
        if let Some(e) = state_err {
            return Err(e);
        }

        let tip = self.best_chain.tip().expect("best chain tip");
        let (tip_hash, tip_height) = {
            let n = self.store.node(tip);
            (n.hash, n.height)
        };

        // A fresh backend: record the state at the tip (dcrd's
        // `PutUtxos` over the empty cache).
        let state = match state {
            None => {
                let recorded = crate::utxoio::UtxoSetState {
                    last_flush_height: tip_height as u32,
                    last_flush_hash: tip_hash,
                };
                let db = self.db.as_ref().expect("checked above");
                db.update(|tx| {
                    crate::chaindb::db_put_utxo_set_state(tx, &recorded)
                        .map_err(chain_db_to_db_error)?;
                    Ok(())
                })
                .map_err(crate::chaindb::ChainDbError::Db)?;
                recorded
            }
            Some(s) => s,
        };

        // Start from the recorded state (dcrd seeds the last flush
        // hash and eviction height from it).
        self.utxo_last_flush_hash = state.last_flush_hash;
        self.utxo_last_eviction_height = state.last_flush_height;

        // Already caught up to the tip.
        if state.last_flush_hash == tip_hash {
            return Ok(());
        }

        // The last flushed block must exist in the index; anything
        // else is backend corruption (dcrd panics identically).
        let last_flushed = self
            .index
            .lookup_node(&state.last_flush_hash)
            .unwrap_or_else(|| {
                panic!(
                    "last flushed block node hash {} (height {}) does not exist",
                    state.last_flush_hash, state.last_flush_height
                )
            });

        // The marker must also agree with the index about that block's
        // HEIGHT, which the lookup above does not check.
        //
        // This is the one place a rolled-back metadata store is cheaply
        // detectable. `reconcileDB` compares the block-file cursor against
        // the block files and nothing else, so a store that lost recent
        // commits comes up looking like an ordinary unclean shutdown; the
        // 2026-08-17 fjall work found a journal truncation leaving rows the
        // marker does not account for, and nothing at startup noticed. A
        // marker and an index that disagree about the same hash's height is
        // the signature of exactly that: two durability domains that rolled
        // back by different amounts.
        //
        // It is narrower than the invariant `crash.rs` asserts, which counts
        // the rows a marker names. A live UTXO set records no expected row
        // count, so that check has nothing to compare against here. This one
        // costs a field comparison on a node already loaded.
        let indexed_height = self.store.node(last_flushed).height;
        if indexed_height as u32 != state.last_flush_height {
            panic!(
                "utxo set state names block {} at height {}, but the block index has it at \
                 height {indexed_height}: the metadata store and the block index disagree, \
                 which a consistent shutdown cannot produce",
                state.last_flush_hash, state.last_flush_height
            );
        }
        let fork = self.best_chain.find_fork(&self.store, last_flushed);

        let mut view = UtxoView::new();
        view.set_best_hash(tip_hash);

        // Disconnect back to the point of the fork: unspend the spent
        // txos from each block's journal and remove the utxos it
        // created.  Blocks only need disconnecting when an unclean
        // shutdown occurred between a block being disconnected and
        // the cache being flushed; in the typical catch-up the fork
        // IS the last flushed node and this loop is skipped.
        let mut n = Some(last_flushed);
        let mut next_block_to_detach: Option<Arc<MsgBlock>> = None;
        while let Some(id) = n {
            if Some(id) == fork {
                break;
            }
            // Stop promptly on a shutdown request, before each block
            // (dcrd `utxocache.go:884-889`).  The replay so far stays
            // in the cache, unflushed, exactly as dcrd leaves it.
            if self.interrupt_requested() {
                return Err(crate::chaindb::ChainDbError::Interrupted);
            }
            let block = match next_block_to_detach.take() {
                Some(b) => b,
                None => self.block_arc(id)?,
            };
            assert_eq!(
                self.store.node(id).hash,
                block.header.block_hash(),
                "detach block node hash does not match the block"
            );
            // The parent is also the next block to detach, so it moves
            // into `next_block_to_detach` once this block is done with
            // it rather than being loaded again (dcrd
            // `nextBlockToDetach`).
            let parent_id = self.store.node(id).parent.expect("detached block parent");
            let parent = self.block_arc(parent_id)?;

            let prev_height = Some(self.store.node(parent_id).height);
            let is_treasury_enabled = {
                let parent_view = NodeBranchView {
                    store: &self.store,
                    tip: parent_id,
                };
                crate::agendas::is_treasury_agenda_active(&parent_view, prev_height, params)
                    .map_err(|_| {
                        crate::chaindb::ChainDbError::Corrupt("unknown deployment".into())
                    })?
            };
            let stxos = self
                .fetch_spend_journal(&block, is_treasury_enabled)
                .map_err(|e| crate::chaindb::ChainDbError::Corrupt(e.description.clone()))?;
            view.disconnect_block(
                &block,
                &parent,
                &stxos,
                &ChainUtxoResolver { chain: self },
                is_treasury_enabled,
            )
            .map_err(|e| {
                crate::chaindb::ChainDbError::Corrupt(format!("utxo catch-up disconnect: {e:?}"))
            })?;
            self.commit_view(&mut view);
            let (parent_hash, parent_height) = {
                let p = self.store.node(parent_id);
                (p.hash, p.height as u32)
            };
            self.maybe_flush_utxo_cache(parent_hash, parent_height, false)?;
            next_block_to_detach = Some(parent);
            n = Some(parent_id);
        }

        // Replay the blocks after the fork point forward through the
        // cache.
        let mut attach_nodes = Vec::new();
        let mut m = Some(tip);
        while let Some(id) = m {
            if Some(id) == fork {
                break;
            }
            attach_nodes.push(id);
            m = self.store.node(id).parent;
        }
        attach_nodes.reverse();
        let mut prev_block_attached: Option<Arc<MsgBlock>> = None;
        for id in attach_nodes {
            // dcrd checks for a shutdown request before each block here
            // too (`utxocache.go:974-979`).
            if self.interrupt_requested() {
                return Err(crate::chaindb::ChainDbError::Interrupted);
            }
            // The parent is the block attached on the previous
            // iteration; only the first node's parent is fetched (dcrd
            // `prevBlockAttached`), so each block is loaded once.
            let block = self.block_arc(id)?;
            let parent_id = self.store.node(id).parent.expect("attach parent");
            let parent = match prev_block_attached.take() {
                Some(p) => p,
                None => self.block_arc(parent_id)?,
            };
            assert_eq!(
                self.store.node(parent_id).hash,
                parent.header.block_hash(),
                "attach block node parent hash does not match the parent block"
            );
            let prev_height = Some(self.store.node(parent_id).height);
            let is_treasury_enabled = {
                let parent_view = NodeBranchView {
                    store: &self.store,
                    tip: parent_id,
                };
                crate::agendas::is_treasury_agenda_active(&parent_view, prev_height, params)
                    .map_err(|_| {
                        crate::chaindb::ChainDbError::Corrupt("unknown deployment".into())
                    })?
            };
            view.connect_block(
                &block,
                &parent,
                || self.fetch_spend_journal(&parent, is_treasury_enabled),
                &ChainUtxoResolver { chain: self },
                None,
                is_treasury_enabled,
            )
            .map_err(|e| {
                crate::chaindb::ChainDbError::Corrupt(format!("utxo catch-up connect: {e:?}"))
            })?;
            self.commit_view(&mut view);
            let (node_hash, node_height) = {
                let nd = self.store.node(id);
                (nd.hash, nd.height as u32)
            };
            self.maybe_flush_utxo_cache(node_hash, node_height, false)?;
            prev_block_attached = Some(block);
        }
        // The unflushed tail stays in the cache for the normal flush
        // triggers, exactly like dcrd's initialization.
        Ok(())
    }

    /// Whether a shutdown has been requested through the interrupt the
    /// chain was opened with (dcrd's non-blocking receive from
    /// `b.interrupt`).
    fn interrupt_requested(&self) -> bool {
        self.interrupt
            .as_ref()
            .is_some_and(|interrupt| interrupt.load(Ordering::SeqCst))
    }

    /// Fetch an entry through the cache and backend (dcrd
    /// `UtxoCache.FetchEntry`): cache hits return a clone with the
    /// modified and fresh flags cleared — spent tombstones are still
    /// returned spent, which is what preserves original entry fields
    /// across disconnects — and misses read the backend, caching the
    /// entry (or its absence) for later lookups.
    pub fn fetch_utxo_entry(&self, op: &OutPoint) -> Option<UtxoEntry> {
        let key = (op.hash.0, op.index, op.tree);
        if let Some(entry) = self.utxo_cache.borrow().get(&key) {
            self.utxo_cache_hits
                .set(self.utxo_cache_hits.get().wrapping_add(1));
            let mut cloned = entry.clone()?;
            cloned.set_state_bits(
                cloned.state_bits()
                    & !(crate::utxoentry::UTXO_STATE_MODIFIED | crate::utxoentry::UTXO_STATE_FRESH),
            );
            return Some(cloned);
        }
        self.utxo_cache_misses
            .set(self.utxo_cache_misses.get().wrapping_add(1));
        let fetched = self.backend_fetch_entry(&key);
        if let Some(entry) = &fetched {
            self.utxo_total_entry_size.set(
                self.utxo_total_entry_size
                    .get()
                    .saturating_add(utxo_entry_size(entry)),
            );
        }
        // Backend entries carry no state flags, and a missing output
        // is negatively cached so other code can use the presence of
        // an entry to avoid reloading it (dcrd caches the nil too).
        self.utxo_cache.borrow_mut().insert(key, fetched.clone());
        fetched
    }

    /// Fetch a batch of entries through the cache and backend, one
    /// result per outpoint in order: per-outpoint semantics are
    /// exactly [`Self::fetch_utxo_entry`]'s — hits are cloned with
    /// the modified and fresh flags cleared, misses are cached
    /// (missing outputs negatively) — but every cache miss of the
    /// batch reads the backend within ONE database view transaction
    /// instead of opening one per outpoint (dcrd's
    /// `UtxoCache.FetchEntries` needs no such batching because its
    /// leveldb reads are transactionless).
    pub fn fetch_utxo_entries(&self, outpoints: &[OutPoint]) -> Vec<Option<UtxoEntry>> {
        // Serve cache hits and collect the missing indexes (one
        // borrow across the pass; the counters update in bulk after).
        let mut results: Vec<Option<UtxoEntry>> = Vec::with_capacity(outpoints.len());
        let mut missing: Vec<usize> = Vec::new();
        {
            let cache = self.utxo_cache.borrow();
            for (i, op) in outpoints.iter().enumerate() {
                let key = (op.hash.0, op.index, op.tree);
                match cache.get(&key) {
                    Some(entry) => {
                        results.push(entry.clone().map(|mut cloned| {
                            cloned.set_state_bits(
                                cloned.state_bits()
                                    & !(crate::utxoentry::UTXO_STATE_MODIFIED
                                        | crate::utxoentry::UTXO_STATE_FRESH),
                            );
                            cloned
                        }));
                    }
                    None => {
                        missing.push(i);
                        results.push(None);
                    }
                }
            }
        }
        self.utxo_cache_misses.set(
            self.utxo_cache_misses
                .get()
                .wrapping_add(missing.len() as u64),
        );
        self.utxo_cache_hits.set(
            self.utxo_cache_hits
                .get()
                .wrapping_add((outpoints.len().wrapping_sub(missing.len())) as u64),
        );
        if missing.is_empty() {
            return results;
        }

        // Read every miss from the backend in one view transaction
        // (or the in-memory map for the pure-memory test chains),
        // with [`Self::backend_fetch_entry`]'s exact panic semantics
        // for corruption and read failures.
        let miss_outpoints: Vec<OutPoint> = missing.iter().map(|&i| outpoints[i]).collect();
        let fetched: Vec<Option<UtxoEntry>> = match &self.db {
            Some(db) => {
                let mut fetched = Vec::new();
                db.view(|tx| {
                    fetched = crate::chaindb::db_fetch_utxo_entries(tx, &miss_outpoints)
                        .expect("corrupt utxo backend entry");
                    Ok(())
                })
                .expect("utxo backend read");
                fetched
            }
            None => miss_outpoints
                .iter()
                .map(|op| {
                    self.utxo_backend
                        .get(&(op.hash.0, op.index, op.tree))
                        .cloned()
                })
                .collect(),
        };

        // Cache each fetched entry (or its absence) and fill in the
        // result slots, exactly as the per-outpoint path does.  A
        // duplicate outpoint within the batch caches (and accounts
        // for) its entry only once — the key can only already be
        // present from an earlier duplicate in this same loop, since
        // the first pass saw it missing.
        let mut cache = self.utxo_cache.borrow_mut();
        for (&i, entry) in missing.iter().zip(fetched) {
            let op = &outpoints[i];
            let key = (op.hash.0, op.index, op.tree);
            if let alloc::collections::btree_map::Entry::Vacant(slot) = cache.entry(key) {
                if let Some(entry) = &entry {
                    self.utxo_total_entry_size.set(
                        self.utxo_total_entry_size
                            .get()
                            .saturating_add(utxo_entry_size(entry)),
                    );
                }
                slot.insert(entry.clone());
            }
            results[i] = entry;
        }
        results
    }

    /// Force the UTXO cache out to the backend at the current tip, so
    /// the backend holds the full set for a stats walk (dcrd's
    /// `FetchStats` opens with `maybeFlushFn(…, force: true, …)`,
    /// `utxocache.go:532`).
    ///
    /// This is the half of the stats path that must run with exclusive
    /// chain access, and it is deliberately kept that way.  dcrd reads
    /// `bestChain.Tip()` in `FetchUtxoStats` (`utxocache.go:1084`)
    /// without holding `chainLock`, while its connect path commits to
    /// the cache and flushes *before* publishing the tip
    /// (`chain.go:728`, `:739`, `:746`).  A stats call landing in that
    /// window force-flushes against the previous tip and leaves a
    /// `lastFlushHash` on disk that is one block behind a backend which
    /// already contains the newer block; the catch-up replay then
    /// reconnects an already-applied block, and both implementations
    /// reject that rather than absorbing it — dcrd with
    /// `AssertError("view missing input …")`
    /// (`utxoviewpoint.go:292`, reached from the replay at
    /// `utxocache.go:1015`), the port with the same guard in
    /// `utxoview.rs` surfacing as `ChainDbError::Corrupt` out of
    /// [`Self::initialize_utxo_state`].  Holding the chain lock across
    /// the flush closes that window, so the port does not inherit the
    /// race.  Only the walk below is safe to run unlocked.
    pub fn flush_utxo_cache_for_stats(&mut self) -> Result<(), crate::chaindb::ChainDbError> {
        let tip = self.best_chain.tip().expect("best chain tip");
        let (tip_hash, tip_height) = {
            let n = self.store.node(tip);
            (n.hash, n.height)
        };
        self.flush_utxo_cache(tip_hash, tip_height as u32)
    }

    /// Statistics on the current UTXO set (dcrd
    /// `BlockChain.FetchUtxoStats`).  Flushes, then walks; callers that
    /// hold the chain behind a lock should instead call
    /// [`Self::flush_utxo_cache_for_stats`], release the lock, and walk
    /// with [`Self::utxo_stats_from_backend`], which is what dcrd's
    /// `FetchStats` does — its backend walk
    /// (`utxobackend.go:529`) runs with no lock held at all.
    pub fn fetch_utxo_stats(&mut self) -> Result<UtxoStats, crate::chaindb::ChainDbError> {
        self.flush_utxo_cache_for_stats()?;
        match &self.db {
            Some(db) => Self::utxo_stats_from_backend(db),
            None => self.utxo_stats_from_memory(),
        }
    }

    /// Walk a database-backed UTXO set and fold it into the stats (dcrd
    /// `levelDbUtxoBackend.FetchStats`, `utxobackend.go:529`).
    ///
    /// Takes only the backend handle — no `self` — so it structurally
    /// cannot touch the chain, and therefore cannot be holding the
    /// chain lock while it runs.  That signature is the guarantee: on
    /// mainnet this walks millions of entries, and dcrd holds nothing
    /// across the equivalent walk.  The caller must have forced a flush
    /// first (see [`Self::flush_utxo_cache_for_stats`]), which is what
    /// makes the backend a complete and consistent view.
    pub fn utxo_stats_from_backend(
        db: &dcroxide_database::Database,
    ) -> Result<UtxoStats, crate::chaindb::ChainDbError> {
        // The forced flush means the backend holds the full set: the
        // utxo bucket, walked in serialized-key order exactly as dcrd's
        // backend iterates.  The walk is already in key order, so the
        // running totals and leaf order accumulate straight in.
        let mut streamed = UtxoStats {
            utxos: 0,
            transactions: 0,
            size: 0,
            total: 0,
            serialized_hash: Hash::ZERO,
        };
        // dcrd collects the distinct transaction hashes in a map, but the
        // keys lead with the hash and the walk is in key order, so every
        // output of a transaction is adjacent: counting the changes of
        // hash gives the same count without holding a hash per
        // transaction.
        let mut transactions: i64 = 0;
        let mut last_tx_hash: Option<[u8; 32]> = None;
        let mut leaves: Vec<Hash> = Vec::new();
        {
            let mut corrupt: Option<String> = None;
            db.view(|tx| {
                let Some(bucket) = tx.metadata().bucket(crate::chaindb::UTXO_SET_BUCKET_NAME)
                else {
                    corrupt = Some("missing utxo set bucket".into());
                    return Ok(());
                };
                // `try_for_each`: dcrd's `FetchStats` checks the
                // iterator's error after its walk, so a read fault fails
                // the stats instead of truncating them.  The walk streams
                // the bucket a window at a time rather than gathering
                // every key of the set before the first row (dcrd's
                // iterator holds one row).
                bucket.try_for_each(|k, v| {
                    if corrupt.is_some() {
                        return Ok(());
                    }
                    match crate::chaindb::decode_outpoint_key(k) {
                        Ok(outpoint) => {
                            if v.is_empty() {
                                corrupt = Some(format!(
                                    "database contains entry for spent tx output {}:{}",
                                    outpoint.hash, outpoint.index
                                ));
                                return Ok(());
                            }
                            match crate::utxoio::deserialize_utxo_entry(v, outpoint.index) {
                                Ok(entry) => {
                                    // The walk visits the bucket in
                                    // serialized-key order, so the
                                    // running totals and leaf order are
                                    // already what the sorted pass
                                    // below would produce — nothing
                                    // needs collecting.
                                    streamed.utxos += 1;
                                    streamed.size += v.len() as i64;
                                    streamed.total += entry.amount();
                                    if last_tx_hash != Some(outpoint.hash.0) {
                                        transactions += 1;
                                        last_tx_hash = Some(outpoint.hash.0);
                                    }
                                    leaves.push(dcroxide_chainhash::hash_h(v));
                                }
                                // dcrd's text, with the inner error's
                                // bare description
                                // (`utxobackend.go:563-566`).
                                Err(e) => {
                                    corrupt = Some(format!(
                                        "corrupt utxo entry for {}:{}: {e}",
                                        outpoint.hash, outpoint.index
                                    ))
                                }
                            }
                        }
                        Err(e) => {
                            // dcrd `utxobackend.go:539-542`.
                            let key: String = k.iter().map(|b| format!("{b:02x}")).collect();
                            corrupt = Some(format!("corrupt outpoint for key {key}: {e}"))
                        }
                    }
                    Ok(())
                })
            })
            .map_err(crate::chaindb::ChainDbError::Db)?;
            if let Some(desc) = corrupt {
                return Err(crate::chaindb::ChainDbError::Corrupt(desc));
            }
        }

        let mut stats = streamed;
        stats.serialized_hash = dcroxide_standalone::calc_merkle_root_in_place(&mut leaves);
        stats.transactions = transactions;
        Ok(stats)
    }

    /// Fold the in-memory UTXO backend into the stats, for the chains
    /// without a backing database that the pure differential tests use.
    /// The VLQ-coded output index makes serialized-key order diverge
    /// from numeric order across VLQ length boundaries, so these rows
    /// are sorted by their serialized keys rather than trusting the
    /// map's tuple order — the database walk gets that ordering from
    /// the bucket for free.
    fn utxo_stats_from_memory(&self) -> Result<UtxoStats, crate::chaindb::ChainDbError> {
        let mut streamed = UtxoStats {
            utxos: 0,
            transactions: 0,
            size: 0,
            total: 0,
            serialized_hash: Hash::ZERO,
        };
        // Counted as the database walk counts them: the sorted rows keep
        // each transaction's outputs adjacent.
        let mut transactions: i64 = 0;
        let mut last_tx_hash: Option<[u8; 32]> = None;
        let mut leaves: Vec<Hash> = Vec::new();
        {
            let mut rows: Vec<UtxoStatsRow> = Vec::with_capacity(self.utxo_backend.len());
            for (key, entry) in &self.utxo_backend {
                let outpoint = OutPoint {
                    hash: Hash(key.0),
                    index: key.1,
                    tree: key.2,
                };
                let serialized = crate::utxoio::serialize_utxo_entry(entry)
                    .expect("the utxo backend never holds spent entries");
                // Reduce to the leaf hash and the counters here; the
                // serialized bytes are not needed past this point.
                rows.push((
                    crate::utxoio::outpoint_key(&outpoint),
                    dcroxide_chainhash::hash_h(&serialized),
                    serialized.len() as i64,
                    entry.amount(),
                    key.0,
                ));
            }
            rows.sort_by(|a, b| a.0.cmp(&b.0));
            leaves.reserve(rows.len());
            for (_, leaf, size, amount, tx_hash) in rows {
                streamed.utxos += 1;
                streamed.size += size;
                streamed.total += amount;
                if last_tx_hash != Some(tx_hash) {
                    transactions += 1;
                    last_tx_hash = Some(tx_hash);
                }
                leaves.push(leaf);
            }
        }

        let mut stats = streamed;
        stats.serialized_hash = dcroxide_standalone::calc_merkle_root_in_place(&mut leaves);
        stats.transactions = transactions;
        Ok(stats)
    }

    /// The spent txouts for the block from the spend journal,
    /// reconstructing the fraud proof fields from the block's
    /// spending inputs (dcrd `dbFetchSpendJournalEntry`).
    pub fn fetch_spend_journal(
        &self,
        block: &MsgBlock,
        is_treasury_enabled: bool,
    ) -> Result<Vec<SpentTxOut>, RuleError> {
        // A transaction that cannot be opened fails the operation, as
        // dcrd's `db.View` around `dbFetchSpendJournalEntry` does.
        let serialized = self
            .spend_journal_row(&block.header.block_hash())
            .map_err(db_read_rule_error)?
            .unwrap_or_default();

        // The block's own transactions, lent rather than copied.
        let mut block_txns: Vec<&MsgTx> = Vec::new();
        if !block.stransactions.is_empty() && is_treasury_enabled {
            // Skip the treasurybase and remove treasury spends.
            for stx in &block.stransactions[1..] {
                if dcroxide_stake::is_tspend(stx) {
                    continue;
                }
                block_txns.push(stx);
            }
        } else {
            block_txns.extend(block.stransactions.iter());
        }
        block_txns.extend(block.transactions.iter().skip(1));

        // dcrd separates two failures here and the port had merged
        // them.  Journal data missing for a block that spends anything
        // is a broken invariant and it panics (`panicf("missing spend
        // journal data for %s")`), but a row that is present and fails
        // to decode is corruption: `dbFetchSpendJournalEntry` returns
        // it as `database.ErrCorruption` and the reorg fails cleanly
        // with the node still up.  Panicking on that arm too meant a
        // corrupt row killed the process under `panic = "abort"` the
        // next time any disconnect touched it.
        if !block_txns.is_empty() && serialized.is_empty() {
            panic!(
                "missing spend journal data for {}",
                block.header.block_hash()
            );
        }
        crate::chainio::deserialize_spend_journal_entry(&serialized, &block_txns).map_err(|e| {
            // Carried as `ErrUtxoBackendCorruption` for the reason
            // `UtxoView::assert_missing` carries it: dcrd expresses this
            // through a type the port has no counterpart for, and the
            // kind is what keeps `is_rule_violation` from blaming the
            // peer for local corruption.
            // The inner error prints as dcrd's bare `errDeserialize`
            // text (`chainio.go:790-792`).
            rule_error(
                RuleErrorKind::UtxoBackendCorruption,
                alloc::format!(
                    "corrupt spend information for {}: {e}",
                    block.header.block_hash()
                ),
            )
        })
    }

    /// The full block data for a node.  The data must have been
    /// stored previously; callers only request blocks whose data
    /// availability is tracked by the block index (dcrd
    /// `fetchBlockByNode` over its database and recent block cache).
    pub fn block_by_node(&self, node: NodeId) -> MsgBlock {
        self.block_data(node)
            .expect("block data for node is stored")
    }

    /// The block data for a node on the stake-node paths, or the error
    /// dcrd's `fetchBlockByNode` returns there: the database's
    /// `ErrBlockNotFound` with its "block %s does not exist" text
    /// (`database/ffldb/db.go:1241`), or the failed read or decode.
    /// The stake-node error type has no database kind, so it travels
    /// as `ErrDatabaseCorrupt`; only the description is dcrd's.
    fn stake_block_by_node(
        &self,
        node: NodeId,
    ) -> Result<Arc<MsgBlock>, dcroxide_stake::RuleError> {
        self.block_arc(node).map_err(|e| dcroxide_stake::RuleError {
            kind: dcroxide_stake::ErrorKind::DatabaseCorrupt,
            description: format!("{e}"),
        })
    }

    /// Load the list of newly maturing tickets for a node by looking
    /// back to the block containing the tickets to mature (dcrd
    /// `maybeFetchNewTickets`).  `None` means never looked up while
    /// an empty list means no tickets mature at this node.
    pub fn maybe_fetch_new_tickets(
        &mut self,
        node: NodeId,
        params: &Params,
    ) -> Result<(), dcroxide_stake::RuleError> {
        if self.store.node(node).new_tickets.is_some() {
            return Ok(());
        }

        // No tickets in the live ticket pool are possible before
        // stake enabled height.
        if self.store.node(node).height < params.stake_enabled_height {
            self.store.node_mut(node).new_tickets = Some(Vec::new());
            return Ok(());
        }

        let Some(mature_node) = self
            .store
            .relative_ancestor(node, i64::from(params.ticket_maturity))
        else {
            let n = self.store.node(node);
            return Err(dcroxide_stake::RuleError {
                kind: dcroxide_stake::ErrorKind::DatabaseCorrupt,
                description: format!(
                    "unable to obtain ancestor {} blocks prior to {} (height {})",
                    params.ticket_maturity, n.hash, n.height
                ),
            });
        };
        let mature_block = self.stake_block_by_node(mature_node)?;
        let tickets: Vec<dcroxide_chainhash::Hash> = mature_block
            .stransactions
            .iter()
            .filter(|stx| dcroxide_stake::is_sstx(stx))
            .map(|stx| stx.tx_hash())
            .collect();
        self.store.node_mut(node).new_tickets = Some(tickets);
        Ok(())
    }

    /// Load and populate the prunable ticket information in the node
    /// if needed (dcrd `maybeFetchTicketInfo`).
    ///
    /// The block comes through `block_data`, so a node whose body has
    /// left the recent window is re-read from the database, and a
    /// missing body is an error rather than a panic, as in dcrd.  The
    /// node is marked modified like dcrd's `PopulateTicketInfo` marks
    /// it (`blockindex.go:955-960`), so its row is rewritten at the
    /// next flush with whatever status it holds in memory.
    pub fn maybe_fetch_ticket_info(
        &mut self,
        node: NodeId,
        params: &Params,
    ) -> Result<(), dcroxide_stake::RuleError> {
        self.maybe_fetch_new_tickets(node, params)?;

        if !self.store.node(node).ticket_info_populated {
            let block = self.stake_block_by_node(node)?;
            let info = dcroxide_stake::find_spent_tickets_in_block(&block);
            let votes = info.votes.iter().map(|v| (v.version, v.bits)).collect();
            self.store
                .populate_ticket_info(node, info.voted_tickets, info.revoked_tickets, votes);
            self.index.mark_modified(node);
        }
        Ok(())
    }

    /// Record the recent-window mirror of the ticket database rows for
    /// a main chain node whose stake node is loaded: the undo data and
    /// maturing tickets by height (the row content of dcrd
    /// `stake.WriteConnectedBestNode`, which `connect_block` also writes
    /// to the database in its connect transaction).
    pub fn write_stake_db_rows(&mut self, node: NodeId) {
        let n = self.store.node(node);
        let stake_node = n.stake_node.as_ref().expect("stake node loaded");
        self.stake_undo
            .insert(n.height, stake_node.undo_data().to_vec());
        self.stake_new_tickets
            .insert(n.height, stake_node.new_tickets().to_vec());
    }

    /// The stake node for the requested node, creating it if needed:
    /// a cached node is returned directly, a node whose parent stake
    /// node is loaded is connected forward, and anything else is
    /// reached by disconnecting from the current best chain tip back
    /// to the fork point (regenerating pruned nodes from the ticket
    /// undo rows) and replaying any side chain blocks up to the
    /// requested node (dcrd `fetchStakeNode`).
    pub fn fetch_stake_node(
        &mut self,
        node: NodeId,
        params: &Params,
    ) -> Result<StakeNode, dcroxide_stake::RuleError> {
        // Return the cached immutable stake node when it is already
        // loaded.
        if let Some(stake_node) = &self.store.node(node).stake_node {
            return Ok(stake_node.clone());
        }

        // Create the requested stake node from the parent stake node
        // when it is already loaded as an optimization.
        if let Some(parent) = self.store.node(node).parent
            && self.store.node(parent).stake_node.is_some()
        {
            self.maybe_fetch_ticket_info(node, params)?;
            let n = self.store.node(node);
            let voted = n.tickets_voted.clone();
            let revoked = n.tickets_revoked.clone();
            let new_tickets = n.new_tickets.clone().expect("new tickets loaded");
            let iv = self.store.lottery_iv(node);
            let parent_stake_node = self.store.node(parent).stake_node.as_ref().expect("loaded");
            let stake_node = parent_stake_node.connect(iv, &voted, &revoked, &new_tickets)?;
            self.store.node_mut(node).stake_node = Some(stake_node.clone());
            return Ok(stake_node);
        }

        // Undo the effects from the current tip back to, and
        // including, the fork point, regenerating and populating any
        // stake nodes along the way that are not already loaded.
        let tip = self.best_chain.tip().expect("best chain tip");
        let fork = self.best_chain.find_fork(&self.store, node);
        let mut cur = Some(tip);
        while let Some(n) = cur {
            if Some(n) == fork {
                break;
            }
            let prev = self.store.node(n).parent;
            let Some(prev_id) = prev else {
                break;
            };
            if self.store.node(prev_id).stake_node.is_none() {
                // Generate the previous stake node by starting with
                // the child stake node and undoing the modifications
                // caused by the stake details in the previous block,
                // restoring the previous node's own bookkeeping from
                // the ticket database rows like dcrd does.  A row that
                // cannot be read fails the fetch, as it does in dcrd.
                let prev_height = self.store.node(prev_id).height;
                let (utds, tickets) = self.ticket_rows_by_height(prev_height)?;
                let prev_iv = self.store.lottery_iv(prev_id);
                let stake_node = self
                    .store
                    .node(n)
                    .stake_node
                    .as_ref()
                    .expect("stake node along the walk is loaded")
                    .disconnect(prev_iv, &utds, &tickets)?;
                self.store.node_mut(prev_id).stake_node = Some(stake_node);
            }
            cur = prev;
        }

        // Nothing more to do if the requested node is the fork point
        // itself.
        if fork == Some(node) {
            return Ok(self
                .store
                .node(node)
                .stake_node
                .clone()
                .expect("fork stake node loaded"));
        }

        // The requested node is on a side chain, so replay the
        // effects of the blocks up to the requested node.
        let mut attach_nodes = Vec::new();
        let mut n = Some(node);
        while let Some(id) = n {
            if Some(id) == fork {
                break;
            }
            attach_nodes.push(id);
            n = self.store.node(id).parent;
        }
        for &id in attach_nodes.iter().rev() {
            if self.store.node(id).stake_node.is_some() {
                continue;
            }
            self.maybe_fetch_ticket_info(id, params)?;
            let nd = self.store.node(id);
            let voted = nd.tickets_voted.clone();
            let revoked = nd.tickets_revoked.clone();
            let new_tickets = nd.new_tickets.clone().expect("new tickets loaded");
            let parent = nd.parent.expect("side chain node has a parent");
            let iv = self.store.lottery_iv(id);
            let parent_stake_node = self
                .store
                .node(parent)
                .stake_node
                .as_ref()
                .expect("parent stake node loaded along the attach path");
            let stake_node = parent_stake_node.connect(iv, &voted, &revoked, &new_tickets)?;
            self.store.node_mut(id).stake_node = Some(stake_node);
        }

        Ok(self
            .store
            .node(node)
            .stake_node
            .clone()
            .expect("requested stake node loaded"))
    }

    /// The error for a block already known to be invalid, either
    /// directly or through an invalid ancestor (dcrd
    /// `checkKnownInvalidBlock`).
    pub fn check_known_invalid_block(&self, node: NodeId) -> Result<(), RuleError> {
        let status = self.index.node_status(&self.store, node);
        if status.known_validate_failed() {
            return Err(rule_error(
                RuleErrorKind::KnownInvalidBlock,
                format!(
                    "block {} is known to be invalid",
                    self.store.node(node).hash
                ),
            ));
        }
        if status.known_invalid_ancestor() {
            return Err(rule_error(
                RuleErrorKind::InvalidAncestorBlock,
                format!(
                    "block {} is known to be part of an invalid branch",
                    self.store.node(node).hash
                ),
            ));
        }
        Ok(())
    }

    /// Attempt to discover and set the old fork rejection checkpoint
    /// node: two weeks worth of blocks behind the hard-coded assumed
    /// valid block once its header is known (dcrd
    /// `maybeSetForkRejectionCheckpoint`).
    pub fn maybe_set_fork_rejection_checkpoint(&mut self, params: &Params) {
        if self.reject_forks_checkpoint.is_some() || self.allow_old_forks {
            return;
        }
        let Some(hard_coded) = self.index.lookup_node(&params.assume_valid) else {
            return;
        };
        let mut checkpoint_height =
            self.store.node(hard_coded).height - self.expected_blocks_in_two_weeks;
        if checkpoint_height < 0 {
            checkpoint_height = 0;
        }
        self.reject_forks_checkpoint = self.store.ancestor(hard_coded, checkpoint_height);
    }

    /// Update the assumed valid node when the provided node matches
    /// the configured assumed valid hash (dcrd
    /// `maybeUpdateAssumeValid`).
    pub fn maybe_update_assume_valid(&mut self, node: NodeId) {
        if self.assume_valid == Hash::ZERO || self.assume_valid != self.store.node(node).hash {
            return;
        }
        self.assume_valid_node = Some(node);
    }

    /// Whether the node is both an ancestor of the assumed valid node
    /// and an ancestor of the best header, with the assumed valid
    /// node clamped back to at least two weeks worth of blocks behind
    /// the best header (dcrd `isAssumeValidAncestor`).
    pub fn is_assume_valid_ancestor(&self, node: NodeId) -> bool {
        let Some(mut assume_valid_node) = self.assume_valid_node else {
            return false;
        };
        let Some(best_header) = self.index.best_header() else {
            return false;
        };
        if !self.store.is_ancestor_of(node, best_header) {
            return false;
        }
        let best_height = self.store.node(best_header).height;
        if best_height < self.expected_blocks_in_two_weeks {
            return false;
        }
        let clamp_to_height = best_height - self.expected_blocks_in_two_weeks;
        if self.store.node(assume_valid_node).height > clamp_to_height {
            assume_valid_node = self
                .store
                .ancestor(assume_valid_node, clamp_to_height)
                .expect("clamp height is within the branch");
        }
        self.store.is_ancestor_of(node, assume_valid_node)
    }

    /// Potentially accept the header to the block index and return
    /// its block node (dcrd `maybeAcceptBlockHeader`).  Performs the
    /// context-free header sanity checks (unless the caller already
    /// ran them as part of full block sanity) and the positional
    /// checks, rejects orphan headers and headers on known invalid
    /// branches, and updates the assumed valid and fork rejection
    /// checkpoint tracking.
    pub fn maybe_accept_block_header(
        &mut self,
        header: &BlockHeader,
        check_header_sanity: bool,
        adjusted_time_unix: i64,
        params: &Params,
    ) -> Result<NodeId, RuleError> {
        // Avoid validating the header again if its validation status
        // is already known.
        let hash = header.block_hash();
        if let Some(node) = self.index.lookup_node(&hash) {
            self.check_known_invalid_block(node)?;
            return Ok(node);
        }

        if check_header_sanity {
            check_block_header_sanity(header, adjusted_time_unix, false, params)?;
        }

        // Orphan headers are not allowed and this function should
        // never be called with the genesis block.
        let prev_hash = header.prev_block;
        let Some(prev_node) = self.index.lookup_node(&prev_hash) else {
            return Err(rule_error(
                RuleErrorKind::MissingParent,
                format!("previous block {prev_hash} is not known"),
            ));
        };

        // There is no need to validate the header if an ancestor is
        // already known to be invalid.
        if self
            .index
            .node_status(&self.store, prev_node)
            .known_invalid()
        {
            return Err(rule_error(
                RuleErrorKind::InvalidAncestorBlock,
                format!("previous block {prev_hash} is known to be invalid"),
            ));
        }

        // The block header must pass all of the validation rules
        // which depend on its position within the block chain.  The
        // fork rejection facts dcrd reads from its index mid-check
        // are supplied up front; the block is never in the index on
        // this path due to the lookup above.
        let fork_rejection = self.reject_forks_checkpoint.map(|cp| ForkRejection {
            checkpoint_height: self.store.node(cp).height,
            prev_is_checkpoint_ancestor: self.store.is_ancestor_of(prev_node, cp),
            block_in_index: false,
        });
        let prev_height = self.store.node(prev_node).height;
        let view = NodeBranchView {
            store: &self.store,
            tip: prev_node,
        };
        check_block_header_positional(
            &view,
            header,
            Some(prev_height),
            false,
            fork_rejection.as_ref(),
            params,
        )?;

        // Create a new block node for the block and add it to the
        // block index.
        let new_node = self.store.new_node(header, Some(prev_node));
        self.store.node_mut(new_node).status = BlockStatus::NONE;
        self.index.add_node(&self.store, new_node);

        self.maybe_set_fork_rejection_checkpoint(params);
        self.maybe_update_assume_valid(new_node);

        Ok(new_node)
    }

    /// Insert a new block header into the chain using headers-first
    /// semantics (dcrd `ProcessBlockHeader`).
    ///
    /// The modified block index entries are flushed after every header,
    /// since a new header always adds one (`process.go:267-271`).  Like
    /// dcrd's, the flush is a metadata commit into the database's write
    /// cache, which reaches disk only when the cache itself flushes, so
    /// it costs an in-memory overlay commit per header and no sync.
    ///
    /// Without it nothing drained the set until a block connected, and
    /// sync is strictly headers-first: the whole header chain
    /// accumulated, so the first connect materialized every row at once
    /// -- roughly 250 MB for mainnet, a header apiece -- and none of it
    /// was durable in the meantime, so a host that could not afford that
    /// allocation re-downloaded every header and failed at the same
    /// point again.
    pub fn process_block_header(
        &mut self,
        header: &BlockHeader,
        adjusted_time_unix: i64,
        params: &Params,
    ) -> Result<(), RuleError> {
        self.maybe_accept_block_header(header, true, adjusted_time_unix, params)?;
        self.flush_block_index(params).map_err(persist_rule_error)?;
        Ok(())
    }

    /// Connect the block to the end of the best chain (dcrd
    /// `connectBlock`): flush the block index, write the best state,
    /// spend journal, ticket database rows, treasury balance and spend
    /// rows, filter, and header commitment leaves in one database
    /// transaction, commit the view to the UTXO cache and maybe flush
    /// it, move the best chain tip and maybe prune the cached chain
    /// tips, replace the best state snapshot, send the connected and
    /// new-tickets notifications, and prune the parent's stake node
    /// once it falls far enough behind the best header.
    ///
    /// Not reproduced: the difficulty retarget debug log lines, and
    /// `addRecentBlock`, whose recent block cache the `blocks` mirror
    /// stands in for (the block entered it when its data was accepted).
    #[allow(clippy::too_many_arguments)]
    pub fn connect_block(
        &mut self,
        node: NodeId,
        block: &Arc<MsgBlock>,
        parent: &Arc<MsgBlock>,
        view: &mut UtxoView,
        stxos: Vec<SpentTxOut>,
        filter: FilterV2,
        params: &Params,
    ) -> Result<(), RuleError> {
        // Make sure it's extending the end of the best chain.
        let tip = self.best_chain.tip().expect("best chain tip");
        assert_eq!(
            block.header.prev_block,
            self.store.node(tip).hash,
            "block connects to a block other than the best chain tip"
        );

        let parent_id = self
            .store
            .node(node)
            .parent
            .expect("connected block has a parent");
        let prev_height = Some(self.store.node(parent_id).height);
        let check_tx_flags = {
            let parent_view = NodeBranchView {
                store: &self.store,
                tip: parent_id,
            };
            crate::validate::determine_check_tx_flags(&parent_view, prev_height, params)?
        };

        // Sanity check the correct number of stxos are provided.
        assert_eq!(
            stxos.len(),
            count_spent_outputs(block),
            "provided stxos do not match the outputs the block spends"
        );

        let stake_node = self
            .fetch_stake_node(node, params)
            .map_err(stake_rule_error)?;

        // Calculate the next stake difficulty and the header
        // commitment leaves for the active agendas.
        let filter_hash = filter.hash();
        let (next_stake_diff, hdr_commitments_active) = {
            let node_view = NodeBranchView {
                store: &self.store,
                tip: node,
            };
            let node_diff =
                crate::difficulty::ChainView::node(&node_view, self.store.node(node).height);
            let next_stake_diff = crate::agendas::calc_next_required_stake_difficulty(
                &node_view,
                node_diff.as_ref(),
                params,
            );
            let parent_view = NodeBranchView {
                store: &self.store,
                tip: parent_id,
            };
            let active = crate::agendas::is_header_commitments_agenda_active(
                &parent_view,
                prev_height,
                params,
            )
            .map_err(|_| unknown_deployment_error())?;
            (next_stake_diff, active)
        };
        let hdr_commitment_leaves = if hdr_commitments_active {
            alloc::vec![filter_hash]
        } else {
            Vec::new()
        };

        // Generate the new best state snapshot.
        let subsidy = crate::validate::calculate_added_subsidy(block, parent);
        let num_txns = (block.transactions.len() + block.stransactions.len()) as u64;
        let n = self.store.node(node);
        let node_hash = n.hash;
        let node_height = n.height;
        let state = BestState {
            hash: node_hash,
            prev_hash: block.header.prev_block,
            height: node_height,
            bits: n.bits,
            next_pool_size: stake_node.pool_size() as u32,
            next_stake_diff,
            block_size: u64::from(block.header.size),
            num_txns,
            total_txns: self.state_snapshot.total_txns + num_txns,
            median_time: self.store.calc_past_median_time(node),
            total_subsidy: self.state_snapshot.total_subsidy + subsidy,
            next_expiring_tickets: stake_node.expiring_next_block(),
            next_winning_tickets: stake_node.winners().to_vec(),
            missed_tickets: stake_node.missed_tickets(),
            next_final_state: stake_node.final_state(),
        };
        let tickets_new = stake_node.new_tickets().to_vec();

        // The database writes: the spend journal record, the ticket
        // database rows, the filter, and the commitment leaves.
        let serialized_journal =
            crate::chainio::serialize_spend_journal_entry(&stxos).unwrap_or_default();
        self.spend_journal
            .insert(node_hash.0, serialized_journal.clone());
        self.write_stake_db_rows(node);
        self.filters.insert(node_hash.0, filter.clone());
        self.header_commitments
            .insert(node_hash.0, hdr_commitment_leaves.clone());
        // The treasury account and spend rows when the agenda is active
        // (dcrd `connectBlock` taking the flag once at `chain.go:616`).
        // Computed before the transaction opens and published after it
        // commits, so the rows travel with the best state they belong
        // to: dcrd writes both inside its single `db.Update`
        // (`chain.go:671-719`), and a durable best state whose treasury
        // row is missing reads back as a zero balance that every
        // descendant then inherits.
        let treasury_records = check_tx_flags
            .is_treasury_enabled()
            .then(|| self.treasury_records_for_block(node, block, params));

        if self.db.is_some() {
            self.flush_block_index(params).map_err(persist_rule_error)?;
            let work_sum = self.store.node(node).work_sum;
            let (total_txns, total_subsidy) = (state.total_txns, state.total_subsidy);
            let db = self.db.as_ref().expect("checked above");
            db.update(|tx| {
                crate::chaindb::db_put_best_state(
                    tx,
                    node_hash,
                    node_height as u32,
                    total_txns,
                    total_subsidy,
                    work_sum,
                )
                .map_err(chain_db_to_db_error)?;
                crate::chaindb::db_put_spend_journal_entry(tx, &node_hash, &serialized_journal)
                    .map_err(chain_db_to_db_error)?;
                dcroxide_stake::stakedb::write_connected_best_node(tx, &stake_node, &node_hash)
                    .map_err(|e| db_driver_error(format!("stake db: {e:?}")))?;
                if let Some((block_hash, ts, tspend_updates)) = &treasury_records {
                    Self::db_write_treasury_records(tx, block_hash, ts, tspend_updates)?;
                }
                crate::chaindb::db_put_gcs_filter(tx, &node_hash, &filter)
                    .map_err(chain_db_to_db_error)?;
                crate::chaindb::db_put_header_commitments(tx, &node_hash, &hdr_commitment_leaves)
                    .map_err(chain_db_to_db_error)?;
                Ok(())
            })
            .map_err(|e| persist_rule_error(crate::chaindb::ChainDbError::Db(e)))?;
        }

        // The rows are durable now (or there is no database), so the
        // mirrors consensus reads can catch up.
        if let Some((block_hash, ts, tspend_updates)) = treasury_records {
            self.apply_treasury_records(block_hash, ts, &tspend_updates);
        }

        // Commit all entries in the view to the UTXO set, then
        // conditionally flush the cache to the backend.  A flush is
        // forced when the chain believes it is current since blocks
        // connect infrequently at that point; during the initial sync
        // the size limit and periodic interval gate it (dcrd
        // `MaybeFlush(&node.hash, height, isCurrent, ...)` after each
        // connect).
        self.commit_view(view);
        let is_chain_current = self.is_current(node, self.utxo_clock_unix);
        self.maybe_flush_utxo_cache(node_hash, node_height as u32, is_chain_current)
            .map_err(persist_rule_error)?;

        // This node is now the end of the best chain.
        self.best_chain.set_tip(&self.store, Some(node));
        self.maybe_prune_cached_tips(node);
        self.state_snapshot = state;

        // The connected and new-tickets events (dcrd sends the former
        // with the chain lock released and the latter with it held;
        // the synchronous callback here must only queue either way).
        Self::send_ntfn(
            &mut self.notifications,
            &Notification::BlockConnected(BlockConnectedNtfnsData {
                block: Arc::clone(block),
                parent_block: Arc::clone(parent),
                check_tx_flags,
            }),
        );
        if node_height >= params.stake_enabled_height {
            Self::send_ntfn(
                &mut self.notifications,
                &Notification::NewTickets(TicketNotificationsData {
                    hash: node_hash,
                    height: node_height,
                    stake_difficulty: next_stake_diff,
                    tickets_new,
                }),
            );
        }

        // Optimization: immediately prune the parent's stake node when
        // it is no longer needed due to being too far behind the best
        // known header (dcrd `connectBlock`, `chain.go:795-808`).
        // During initial sync that is every block, so memory stays flat
        // however fast blocks connect, instead of growing until the
        // next timed prune.  The parent's entries in the port's
        // recent-window mirrors go with it when a database backs them:
        // dcrd holds none of those in memory at all.
        let best_header_height = self
            .index
            .best_header()
            .map_or(0, |h| self.store.node(h).height);
        let mut prune_height = 0;
        if best_header_height > Self::MIN_MEMORY_STAKE_NODES {
            prune_height = best_header_height - Self::MIN_MEMORY_STAKE_NODES;
        }
        if node_height < prune_height {
            self.prune_node_memory(parent_id, self.db.is_some());
        }
        Ok(())
    }

    /// Disconnect the block from the end of the main chain: restore
    /// the parent's best state, drop the ticket database rows above
    /// the parent, apply the view to the UTXO set, and remove the
    /// block's spend journal record (dcrd `disconnectBlock`; the GCS
    /// filter and commitment leaves are intentionally retained).
    pub fn disconnect_block(
        &mut self,
        node: NodeId,
        block: &Arc<MsgBlock>,
        parent: &Arc<MsgBlock>,
        view: &mut UtxoView,
        params: &Params,
    ) -> Result<(), RuleError> {
        // Make sure the node being disconnected is the end of the
        // best chain.
        let tip = self.best_chain.tip().expect("best chain tip");
        assert_eq!(
            self.store.node(node).hash,
            self.store.node(tip).hash,
            "block being disconnected is not the end of the best chain"
        );

        let parent_id = self.store.node(node).parent.expect("parent");
        let prev_height = Some(self.store.node(parent_id).height);
        let parent_view = NodeBranchView {
            store: &self.store,
            tip: parent_id,
        };
        let check_tx_flags =
            crate::validate::determine_check_tx_flags(&parent_view, prev_height, params)?;

        self.fetch_stake_node(node, params)
            .map_err(stake_rule_error)?;
        let parent_stake_node = self
            .fetch_stake_node(parent_id, params)
            .map_err(stake_rule_error)?;

        // Generate the new best state snapshot for the parent.  The
        // next stake difficulty comes from the disconnected block's
        // own header commitment like dcrd.
        let num_parent_txns = (parent.transactions.len() + parent.stransactions.len()) as u64;
        let num_block_txns = (block.transactions.len() + block.stransactions.len()) as u64;
        let subsidy = crate::validate::calculate_added_subsidy(block, parent);
        let pn = self.store.node(parent_id);
        let state = BestState {
            hash: pn.hash,
            prev_hash: pn
                .parent
                .map(|gp| self.store.node(gp).hash)
                .unwrap_or(Hash::ZERO),
            height: pn.height,
            bits: pn.bits,
            next_pool_size: parent_stake_node.pool_size() as u32,
            next_stake_diff: self.store.node(node).sbits,
            block_size: u64::from(parent.header.size),
            num_txns: num_parent_txns,
            total_txns: self.state_snapshot.total_txns - num_block_txns,
            median_time: self.store.calc_past_median_time(parent_id),
            total_subsidy: self.state_snapshot.total_subsidy - subsidy,
            next_expiring_tickets: parent_stake_node.expiring_next_block(),
            next_winning_tickets: parent_stake_node.winners().to_vec(),
            missed_tickets: parent_stake_node.missed_tickets(),
            next_final_state: parent_stake_node.final_state(),
        };

        // Drop the ticket database rows above the new tip (the row
        // effect of dcrd `stake.WriteDisconnectedBestNode`).
        let node_height = self.store.node(node).height;
        self.stake_undo.retain(|h, _| *h < node_height);
        self.stake_new_tickets.retain(|h, _| *h < node_height);
        if self.db.is_some() {
            self.flush_block_index(params).map_err(persist_rule_error)?;
            let node_work = self.store.node(node).work_sum;
            let parent_hash = self.store.node(parent_id).hash;
            let child_undo = self
                .store
                .node(node)
                .stake_node
                .as_ref()
                .expect("child stake node loaded")
                .undo_data()
                .to_vec();
            let (total_txns, total_subsidy) = (state.total_txns, state.total_subsidy);
            let parent_height = self.store.node(parent_id).height;
            let db = self.db.as_ref().expect("checked above");
            db.update(|tx| {
                crate::chaindb::db_put_best_state(
                    tx,
                    parent_hash,
                    parent_height as u32,
                    total_txns,
                    total_subsidy,
                    node_work,
                )
                .map_err(chain_db_to_db_error)?;
                dcroxide_stake::stakedb::write_disconnected_best_node(
                    tx,
                    &parent_stake_node,
                    &parent_hash,
                    &child_undo,
                )
                .map_err(|e| db_driver_error(format!("stake db: {e:?}")))?;
                Ok(())
            })
            .map_err(|e| persist_rule_error(crate::chaindb::ChainDbError::Db(e)))?;
        }

        // Commit all entries in the view to the UTXO set.  dcrd then
        // forces a cache flush on every disconnect, which drops the
        // spent tombstones; blocks detached after this point resurrect
        // their spent outputs from the journal's fraud proof fields
        // rather than the retained originals, and reproducing that
        // timing matters for field-level parity.  The flush records
        // the parent — the new tip — as the utxo set state, exactly
        // the hash and height dcrd's disconnect passes `MaybeFlush`.
        self.commit_view(view);
        let (parent_hash, parent_height) = {
            let p = self.store.node(parent_id);
            (p.hash, p.height as u32)
        };
        self.flush_utxo_cache(parent_hash, parent_height)
            .map_err(persist_rule_error)?;

        // Remove the block's spend journal record after the flush like
        // dcrd, since the journal is the cache's recovery source: dcrd
        // runs `dbRemoveSpendJournalEntry` in its own transaction
        // intentionally AFTER the forced `MaybeFlush`, so a crash
        // between the best-state write and the flush still finds the
        // journal record it needs to recover.
        let node_hash = self.store.node(node).hash;
        if let Some(db) = self.db.as_ref() {
            db.update(|tx| {
                crate::chaindb::db_remove_spend_journal_entry(tx, &node_hash)
                    .map_err(chain_db_to_db_error)?;
                Ok(())
            })
            .map_err(|e| persist_rule_error(crate::chaindb::ChainDbError::Db(e)))?;
        }
        self.spend_journal.remove(&node_hash.0);

        // This node's parent is now the end of the best chain.
        self.best_chain.set_tip(&self.store, Some(parent_id));
        self.state_snapshot = state;

        // The disconnected event with the flags that were active for
        // the DISCONNECTED block (dcrd sends it with the chain lock
        // released; the synchronous callback here must only queue).
        Self::send_ntfn(
            &mut self.notifications,
            &Notification::BlockDisconnected(BlockDisconnectedNtfnsData {
                block: Arc::clone(block),
                parent_block: Arc::clone(parent),
                check_tx_flags,
            }),
        );
        Ok(())
    }

    /// The version 2 GCS filter for the block, loaded when previously
    /// stored and created from the post-connect view otherwise (dcrd
    /// `loadOrCreateFilter`).
    pub fn load_or_create_filter(
        &self,
        block: &MsgBlock,
        view: &UtxoView,
    ) -> Result<FilterV2, RuleError> {
        if let Some(filter) = self.filters.get(&block.header.block_hash().0) {
            return Ok(filter.clone());
        }
        struct ViewScripts<'a>(&'a UtxoView);
        impl dcroxide_gcs::blockcf2::PrevScripter for ViewScripts<'_> {
            fn prev_script(&self, out: &OutPoint) -> Option<(u16, &[u8])> {
                let entry = self.0.lookup_entry(out)?;
                Some((entry.script_version(), entry.pk_script()))
            }
        }
        dcroxide_gcs::blockcf2::regular(block, &ViewScripts(view)).map_err(|e| RuleError {
            kind: RuleErrorKind::MissingTxOut,
            description: format!("{e:?}"),
        })
    }

    /// Reorganize the chain to the given target without attempting to
    /// undo failed reorgs: disconnect blocks back to the fork point
    /// and connect the blocks of the new branch, fully validating any
    /// that have not been validated before (dcrd
    /// `reorganizeChainInternal`; the shutdown interrupt checks are
    /// not reproduced).
    pub fn reorganize_chain_internal(
        &mut self,
        target: NodeId,
        params: &Params,
    ) -> Result<(), RuleError> {
        let mut tip = self.best_chain.tip();
        let fork = self.best_chain.find_fork(&self.store, target);

        // Disconnect all of the blocks back to the point of the fork.
        let mut view = UtxoView::new();
        if let Some(t) = tip {
            view.set_best_hash(self.store.node(t).hash);
        }
        let mut next_block_to_detach: Option<Arc<MsgBlock>> = None;
        while let Some(n) = tip {
            if Some(n) == fork {
                break;
            }
            let block = match next_block_to_detach.take() {
                Some(b) => b,
                None => self.stored_block_arc(n)?,
            };
            assert_eq!(
                self.store.node(n).hash,
                block.header.block_hash(),
                "detach block node hash does not match the block"
            );
            let parent_id = self.store.node(n).parent.expect("detached block parent");
            let parent = self.stored_block_arc(parent_id)?;
            next_block_to_detach = Some(Arc::clone(&parent));

            let parent_view = NodeBranchView {
                store: &self.store,
                tip: parent_id,
            };
            let prev_height = Some(self.store.node(parent_id).height);
            let is_treasury_enabled =
                crate::agendas::is_treasury_agenda_active(&parent_view, prev_height, params)
                    .map_err(|_| unknown_deployment_error())?;

            // Load the spent txos for the block from the spend
            // journal and update the view to unspend them.
            let stxos = self.fetch_spend_journal(&block, is_treasury_enabled)?;
            view.disconnect_block(
                &block,
                &parent,
                &stxos,
                &ChainUtxoResolver { chain: self },
                is_treasury_enabled,
            )?;

            // Update the chain state.
            self.disconnect_block(n, &block, &parent, &mut view, params)?;
            tip = Some(parent_id);
        }

        // Determine the blocks to attach after the fork point in
        // forward order.
        let mut attach_nodes = Vec::new();
        let mut n = Some(target);
        while let Some(id) = n {
            if Some(id) == fork {
                break;
            }
            attach_nodes.push(id);
            n = self.store.node(id).parent;
        }
        attach_nodes.reverse();

        // The parent of the first block attached is the fork block, which
        // the detach loop already loaded when it ran (dcrd `forkBlock`);
        // every later block's parent is the block attached before it
        // (`prevBlockAttached`).  Only a fork block no detach loaded is
        // fetched.  Every fetch shares the `blocks` mirror's `Arc`, so a
        // block that extends the tip -- whose body and parent are both in
        // the mirror -- is attached without copying either.
        let mut fork_block = next_block_to_detach;
        let mut prev_block_attached: Option<Arc<MsgBlock>> = None;
        for node in attach_nodes {
            let block = self.stored_block_arc(node)?;
            let parent_id = self.store.node(node).parent.expect("attach parent");
            let parent = match prev_block_attached.take().or_else(|| fork_block.take()) {
                Some(parent) => parent,
                None => self.stored_block_arc(parent_id)?,
            };
            assert_eq!(
                self.store.node(parent_id).hash,
                parent.header.block_hash(),
                "attach block node parent hash does not match the parent block"
            );
            prev_block_attached = Some(Arc::clone(&block));

            let prev_height = Some(self.store.node(parent_id).height);
            let is_treasury_enabled = {
                let parent_view = NodeBranchView {
                    store: &self.store,
                    tip: parent_id,
                };
                crate::agendas::is_treasury_agenda_active(&parent_view, prev_height, params)
                    .map_err(|_| unknown_deployment_error())?
            };

            // Skip validation when the block has already been
            // validated; the view, stxos, and header commitment data
            // are still needed.
            let mut stxos: Vec<SpentTxOut> = Vec::with_capacity(count_spent_outputs(&block));
            let filter;
            if self.index.node_status(&self.store, node).has_validated() {
                view.connect_block(
                    &block,
                    &parent,
                    || self.fetch_spend_journal(&parent, is_treasury_enabled),
                    &ChainUtxoResolver { chain: self },
                    Some(&mut stxos),
                    is_treasury_enabled,
                )?;
                filter = self.load_or_create_filter(&block, &view)?;
            } else {
                // The block must pass all of the validation rules
                // which depend on having the full block data for all
                // of its ancestors available, unless it recently did
                // (dcrd's `checkBlockContext` returns early on a
                // `recentContextChecks` hit, `validate.go:1937-1940`,
                // before it fetches the parent stake node).
                let node_hash = self.store.node(node).hash;
                if !self.recent_context_checks.contains(&node_hash) {
                    let parent_stake_node = self
                        .fetch_stake_node(parent_id, params)
                        .map_err(stake_rule_error)?;
                    let context_result = check_block_context_for(
                        &self.store,
                        parent_id,
                        &block,
                        &parent_stake_node,
                        false,
                        params,
                    );
                    if let Err(err) = context_result {
                        self.mark_block_failed_on_rule_violation(node, &err);
                        return Err(err);
                    }
                }

                // Mark the block as recently checked to avoid checking
                // it again when processing (dcrd `chain.go:1228-1230`).
                self.recent_context_checks.put(node_hash);

                let run_scripts = !self.bulk_import_mode && !self.is_assume_valid_ancestor(node);
                let mut subsidy_cache =
                    dcroxide_standalone::SubsidyCache::new(ChainSubsidyParams(params));
                let node_info = {
                    let nd = self.store.node(node);
                    (nd.height, nd.hash, nd.voters, nd.vote_bits)
                };
                let connect_result = {
                    let parent_view = NodeBranchView {
                        store: &self.store,
                        tip: parent_id,
                    };
                    crate::validate::check_connect_block(
                        &parent_view,
                        &mut subsidy_cache,
                        node_info.0,
                        node_info.1,
                        node_info.2,
                        node_info.3,
                        &block,
                        &parent,
                        || self.fetch_spend_journal(&parent, is_treasury_enabled),
                        &mut view,
                        &ChainUtxoResolver { chain: self },
                        Some(&mut stxos),
                        run_scripts,
                        self.sig_cache.as_deref(),
                        &|blk: &MsgBlock| self.tspend_checks(parent_id, blk, params),
                        params,
                    )
                };
                match connect_result {
                    // The connect checks built the filter from the
                    // post-connect view and checked the header commitment
                    // against it; it is stored as is (dcrd receives it
                    // through the header commitment data out-param).
                    Ok(checked_filter) => filter = checked_filter,
                    Err(err) => {
                        self.mark_block_failed_on_rule_violation(node, &err);
                        return Err(err);
                    }
                }
                self.index
                    .set_status_flags(&mut self.store, node, BlockStatus::VALIDATED);
            }

            // Update the chain state and drop any best chain
            // candidates that now have less work than the new tip.
            self.connect_block(node, &block, &parent, &mut view, stxos, filter, params)?;
            self.index.remove_less_work_candidates(&self.store, node);
        }

        Ok(())
    }

    /// Reorganize the chain to the given target with handling for
    /// failed reorgs: when the target is or becomes invalid, fall
    /// back to the best valid chain candidate (dcrd
    /// `reorganizeChain`).  All accumulated reorg errors are returned
    /// (dcrd wraps multiple in a `MultiError`), unless the forced UTXO
    /// cache flush on latching to current fails: that error is then
    /// returned alone, as dcrd's `return err` does.
    pub fn reorganize_chain(
        &mut self,
        target: Option<NodeId>,
        adjusted_time_unix: i64,
        params: &Params,
    ) -> Vec<RuleError> {
        let mut reorg_errs = Vec::new();
        let mut target = target;
        let tip = self.best_chain.tip();
        if target.is_none() || tip == target {
            return reorg_errs;
        }

        let orig_tip = tip;
        let mut sent_reorging_ntfn = false;
        while let Some(t) = target {
            let cur_tip = self.best_chain.tip();
            if cur_tip == Some(t) {
                break;
            }

            // Notify a reorganization to a competing branch is under
            // way; a plain tip extension sends nothing (dcrd sends
            // this at most once with the chain lock held).
            if !sent_reorging_ntfn
                && cur_tip.is_some_and(|tip_node| !self.is_ancestor_of(tip_node, t))
            {
                Self::send_ntfn(&mut self.notifications, &Notification::ChainReorgStarted);
                sent_reorging_ntfn = true;
            }

            if let Err(err) = self.reorganize_chain_internal(t, params) {
                reorg_errs.push(err);

                // Determine a new best candidate since the reorg
                // failed; bail out if it does not change to avoid
                // attempting the same reorg over and over.
                let new_target = self.index.find_best_chain_candidate(&self.store);
                if new_target == Some(t) {
                    break;
                }
                target = new_target;
            }
        }

        // Potentially update whether the chain believes it is current
        // based on the actual new tip.
        let mut latch_flush_failed = false;
        if let Some(new_tip) = self.best_chain.tip() {
            let was_latched = self.is_current_latch;
            self.maybe_update_is_current(new_tip, adjusted_time_unix);

            // If the chain just latched to current, force the UTXO
            // cache to flush to the backend, which ensures the full
            // set is on disk when the chain becomes current and
            // allows fetching up-to-date utxo set stats (dcrd
            // `reorganizeChain`).
            if !was_latched && self.is_current_latch {
                let (new_hash, new_height) = {
                    let n = self.store.node(new_tip);
                    (n.hash, n.height)
                };
                if let Err(e) = self.flush_utxo_cache(new_hash, new_height as u32) {
                    // dcrd returns the flush error here, which skips
                    // the reorganization-outcome notification below
                    // (its deferred completion event still fires), and
                    // it is the whole result: the reorg errors gathered
                    // above are dropped (`chain.go:1365-1371`).
                    reorg_errs = alloc::vec![persist_rule_error(e)];
                    latch_flush_failed = true;
                }
            }
        }

        // The reorganization outcome when the tip actually moved,
        // then the completion event dcrd defers, which fires even
        // when every attempt failed.
        if sent_reorging_ntfn {
            let new_tip = self.best_chain.tip();
            if !latch_flush_failed
                && new_tip != orig_tip
                && let (Some(orig), Some(new)) = (orig_tip, new_tip)
            {
                let (old_hash, old_height) = {
                    let n = self.store.node(orig);
                    (n.hash, n.height)
                };
                let (new_hash, new_height) = {
                    let n = self.store.node(new);
                    (n.hash, n.height)
                };
                Self::send_ntfn(
                    &mut self.notifications,
                    &Notification::Reorganization(ReorganizationNtfnsData {
                        old_hash,
                        old_height,
                        new_hash,
                        new_height,
                    }),
                );
            }
            Self::send_ntfn(&mut self.notifications, &Notification::ChainReorgDone);
        }
        reorg_errs
    }

    /// Accept the data for the block, updating the block index state
    /// for the full data now being available, and return the
    /// descendant blocks now eligible for validation (dcrd
    /// `maybeAcceptBlockData`).  The block is stored to the database and
    /// to the `blocks` mirror; the stake node pruner dcrd calls here
    /// runs at the end of `process_block` instead.
    pub fn maybe_accept_block_data(
        &mut self,
        node: NodeId,
        block: &MsgBlock,
        fast_add: bool,
        params: &Params,
    ) -> Result<Vec<NodeId>, RuleError> {
        let _ = params;
        if self.index.node_status(&self.store, node).have_data() {
            return Ok(Vec::new());
        }

        // Populate the prunable ticket and vote information.
        let info = dcroxide_stake::find_spent_tickets_in_block(block);
        let votes = info.votes.iter().map(|v| (v.version, v.bits)).collect();
        self.store
            .populate_ticket_info(node, info.voted_tickets, info.revoked_tickets, votes);

        // The block data must pass the position-dependent checks.
        let prev_height = self
            .store
            .node(node)
            .parent
            .map(|p| self.store.node(p).height);
        if let Err(err) = crate::validate::check_block_data_positional(block, prev_height, fast_add)
        {
            self.index
                .mark_block_failed_validation(&mut self.store, node);
            return Err(err);
        }

        // Store the block and update the index state for the data now
        // being available, which may make descendants fully linked.
        // The store is skipped when the database already has the
        // block (dcrd `dbMaybeStoreBlock`): a crash between a prior
        // store and the index status flush leaves the bytes present
        // without the stored bit, and the redelivered block must heal
        // that window rather than be rejected on the database's
        // block-exists error.
        //
        // This insert is the one copy of the block the chain makes: the
        // caller keeps its own (`process_block` borrows it, where dcrd's
        // `ProcessBlock` caches the caller's pointer, `process.go:562`),
        // and every later step shares the mirror's `Arc`.
        self.blocks
            .insert(block.header.block_hash().0, Arc::new(block.clone()));
        if let Some(db) = &self.db {
            let stored = db.update(|tx| {
                if tx.has_block(&block.header.block_hash())? {
                    return Ok(());
                }
                tx.store_block(block)
            });
            if let Err(err) = stored {
                return Err(persist_rule_error(crate::chaindb::ChainDbError::Db(err)));
            }
        }
        self.index
            .set_status_flags(&mut self.store, node, BlockStatus::DATA_STORED);
        let tip = self.best_chain.tip().expect("best chain tip");
        Ok(self.index.accept_block_data(&mut self.store, node, tip))
    }

    /// Tentatively accept fully linked blocks by running the
    /// contextual checks over each, marking any rule violations, and
    /// return those accepted along with the error for the first failure
    /// (dcrd `maybeAcceptBlocks`; the `blocks` mirror stands in for its
    /// recent block cache).  Each block that passes is recorded as recently
    /// checked, so the connect does not check it again.  A checked
    /// block that directly extends the current tip while the chain is
    /// current sends the early new-tip event.
    pub fn maybe_accept_blocks(
        &mut self,
        nodes: Vec<NodeId>,
        fast_add: bool,
        adjusted_time_unix: i64,
        params: &Params,
    ) -> (Vec<NodeId>, Option<RuleError>) {
        let cur_tip = self.best_chain.tip();
        let is_current = cur_tip.is_some_and(|t| self.is_current(t, adjusted_time_unix));
        for (i, &node) in nodes.iter().enumerate() {
            let parent_id = self.store.node(node).parent.expect("linked block parent");
            let node_hash = self.store.node(node).hash;
            // The block is shared from the `blocks` mirror, where
            // `maybe_accept_block_data` put it, rather than copied out
            // of it (dcrd's `fetchBlockByNode` hands back its recent
            // block cache's pointer); only a block the mirror no longer
            // holds is read back.  dcrd fetches it first and returns a
            // failed read as `nodes[:i], err` (`process.go:370-373`).
            let block = match self.stored_block_arc(node) {
                Ok(block) => block,
                Err(err) => return (nodes[..i].to_vec(), Some(err)),
            };
            // dcrd's `checkBlockContext` returns early on a
            // `recentContextChecks` hit (`validate.go:1937-1940`).
            let parent_stake_node = if self.recent_context_checks.contains(&node_hash) {
                None
            } else {
                match self.fetch_stake_node(parent_id, params) {
                    Ok(sn) => Some(sn),
                    Err(err) => return (nodes[..i].to_vec(), Some(stake_rule_error(err))),
                }
            };
            if let Some(parent_stake_node) = &parent_stake_node
                && let Err(err) = check_block_context_for(
                    &self.store,
                    parent_id,
                    &block,
                    parent_stake_node,
                    fast_add,
                    params,
                )
            {
                self.mark_block_failed_on_rule_violation(node, &err);
                return (nodes[..i].to_vec(), Some(err));
            }

            // Mark the block as recently checked to avoid checking it
            // again when connecting it in the typical case (dcrd
            // `process.go:385-396`).  The flags it was checked with are
            // not recorded, exactly as in dcrd.
            self.recent_context_checks.put(node_hash);

            // The block checked out and intends to directly extend
            // the tip as of processing entry: dcrd's early new-tip
            // event, sent with the chain lock held so the daemon can
            // relay before the expensive connect.
            if is_current && self.store.node(node).parent == cur_tip {
                Self::send_ntfn(
                    &mut self.notifications,
                    &Notification::NewTipBlockChecked(&block),
                );
            }
        }
        (nodes, None)
    }

    /// The main workhorse for inserting new blocks into the chain,
    /// including duplicate rejection, all validation rules, best
    /// chain selection, and reorganization (dcrd `ProcessBlock`; the
    /// block index flush is not reproduced).  Returns the length of
    /// the fork the block
    /// extended alongside any errors; the fork length is zero when
    /// the block extended or became the best chain tip.
    pub fn process_block(
        &mut self,
        block: &MsgBlock,
        adjusted_time_unix: i64,
        params: &Params,
    ) -> (i64, Vec<RuleError>) {
        // The adjusted clock drives the periodic UTXO cache flush
        // interval for the connects this call performs (dcrd's cache
        // reads the wall clock; the port pins it to the same adjusted
        // time the pruner uses so decisions stay deterministic).  The
        // first observed clock also seeds the flush baseline so no
        // periodic flush fires within the interval of startup, like
        // dcrd's `lastFlushTime: time.Now()` at cache construction.
        self.utxo_clock_unix = adjusted_time_unix;
        if self.utxo_last_flush_unix == 0 {
            self.utxo_last_flush_unix = adjusted_time_unix;
        }

        // The block must not already exist in the main chain or side
        // chains.
        let hash = block.header.block_hash();
        if self.index.have_block(&self.store, &hash) {
            return (
                0,
                alloc::vec![rule_error(
                    RuleErrorKind::DuplicateBlock,
                    format!("already have block {hash}"),
                )],
            );
        }

        // Reject blocks that are already known to be invalid.
        let existing = self.index.lookup_node(&hash);
        if let Some(node) = existing
            && let Err(err) = self.check_known_invalid_block(node)
        {
            return (0, alloc::vec![err]);
        }

        // Perform preliminary sanity checks on the block and its
        // transactions.
        if let Err(err) =
            crate::validate::check_block_sanity(block, adjusted_time_unix, false, params)
        {
            if let Some(node) = existing {
                self.index
                    .mark_block_failed_validation(&mut self.store, node);
            }
            return (0, alloc::vec![err]);
        }

        // Potentially accept the header to the block index when it
        // does not already exist; the header sanity checks were just
        // performed as part of the full block sanity checks.
        let node = match existing {
            Some(node) => node,
            None => {
                match self.maybe_accept_block_header(
                    &block.header,
                    false,
                    adjusted_time_unix,
                    params,
                ) {
                    Ok(node) => node,
                    Err(err) => return (0, alloc::vec![err]),
                }
            }
        };

        // Skip the more expensive validation checks when the block is
        // an ancestor of the assumed valid block or a bulk import.
        let mut fast_add = false;
        if self.bulk_import_mode || self.is_assume_valid_ancestor(node) {
            self.index
                .set_status_flags(&mut self.store, node, BlockStatus::VALIDATED);
            fast_add = true;
        }

        // Accept the block data and determine the blocks now eligible
        // for full validation.  dcrd also flushes the block index here
        // (`process.go:543`); this port does not, because `connect_block`
        // flushes moments later and the data-stored bits self-heal
        // through the store-block dedup window, so it would be a write
        // per block for nothing.
        let linked = match self.maybe_accept_block_data(node, block, fast_add, params) {
            Ok(linked) => linked,
            Err(err) => return (0, alloc::vec![err]),
        };

        // Tentatively accept the linked blocks, then find the best
        // chain candidate and attempt to reorganize to it regardless
        // of any acceptance failure, exactly like dcrd.
        let mut final_errs = Vec::new();
        let (accepted, accept_err) =
            self.maybe_accept_blocks(linked, fast_add, adjusted_time_unix, params);
        if let Some(err) = accept_err {
            final_errs.push(err);
        }

        let target = self.index.find_best_chain_candidate(&self.store);
        final_errs.extend(self.reorganize_chain(target, adjusted_time_unix, params));

        // The acceptance events, sent after any reorganization so the
        // data is relative to the final best chain, skipping nodes
        // already known invalid; the processed block is the data for
        // every accepted node, exactly like dcrd.
        let best_height = self
            .best_chain
            .tip()
            .map(|t| self.store.node(t).height)
            .unwrap_or(0);
        for &accepted_node in &accepted {
            if self
                .index
                .node_status(&self.store, accepted_node)
                .known_invalid()
            {
                continue;
            }
            let mut accepted_fork_len = 0;
            if let Some(fork) = self.best_chain.find_fork(&self.store, accepted_node) {
                accepted_fork_len =
                    self.store.node(accepted_node).height - self.store.node(fork).height;
            }
            Self::send_ntfn(
                &mut self.notifications,
                &Notification::BlockAccepted(BlockAcceptedNtfnsData {
                    best_height,
                    fork_len: accepted_fork_len,
                    block,
                }),
            );
        }

        let mut fork_len = 0;
        if final_errs.is_empty()
            && let Some(fork) = self.best_chain.find_fork(&self.store, node)
        {
            fork_len = self.store.node(node).height - self.store.node(fork).height;
        }

        // Prune old in-memory state on the pruning interval so a
        // sustained sync stays memory-bounded (dcrd
        // `chainPruner.pruneChainIfNeeded`, which `maybeAcceptBlockData`
        // calls before storing the block, `process.go:320`; here it runs
        // once the call's reorganization is done, which changes nothing
        // but when the memory is released).
        self.prune_if_needed(adjusted_time_unix);

        (fork_len, final_errs)
    }

    /// Manually invalidate the block as if it had violated a
    /// consensus rule, mark its descendants as having an invalid
    /// ancestor, and reorganize to the best remaining valid chain
    /// (dcrd `InvalidateBlock`).
    pub fn invalidate_block(
        &mut self,
        hash: &Hash,
        adjusted_time_unix: i64,
        params: &Params,
    ) -> Vec<RuleError> {
        // The reorganization below flushes the utxo cache; keep the
        // periodic-flush clock on the caller's adjusted time (and
        // seed the flush baseline on first observation, like
        // `process_block`).
        self.utxo_clock_unix = adjusted_time_unix;
        if self.utxo_last_flush_unix == 0 {
            self.utxo_last_flush_unix = adjusted_time_unix;
        }
        let Some(node) = self.index.lookup_node(hash) else {
            return alloc::vec![rule_error(
                RuleErrorKind::UnknownBlock,
                format!("block {hash} is not known"),
            )];
        };

        // Disallow invalidation of the genesis block.
        if self.store.node(node).height == 0 {
            return alloc::vec![rule_error(
                RuleErrorKind::InvalidateGenesisBlock,
                "invalidating the genesis block is not allowed",
            )];
        }

        // Nothing to do when the block already failed validation;
        // a block that is merely on an invalid branch is still
        // manually marked.
        if self
            .index
            .node_status(&self.store, node)
            .known_validate_failed()
        {
            return Vec::new();
        }

        // Simply mark the block when it is not part of the current
        // best chain.  Either way it must not pass the contextual
        // checks on a cache hit again (dcrd `process.go:699`).
        let node_hash = self.store.node(node).hash;
        self.recent_context_checks.delete(&node_hash);
        if !self.best_chain.contains(&self.store, node) {
            self.index
                .mark_block_failed_validation(&mut self.store, node);
            self.flush_block_index_warn_only(params);
            return Vec::new();
        }

        // Reorganize back to the parent and mark the block and its
        // descendants.
        let parent = self.store.node(node).parent.expect("non-genesis parent");
        let errs = self.reorganize_chain(Some(parent), adjusted_time_unix, params);
        if !errs.is_empty() {
            // dcrd flushes warn-only before returning here
            // (`process.go:715-719`).  The roll-back already moved the
            // tip and marked descendants, so the modified set holds
            // work that a restart would otherwise redo.
            self.flush_block_index_warn_only(params);
            return errs;
        }
        self.index
            .mark_block_failed_validation(&mut self.store, node);
        self.flush_block_index_warn_only(params);

        // Reset whether the chain believes it is current since the
        // best chain was just invalidated.
        let new_tip = self.best_chain.tip().expect("best chain tip");
        self.is_current_latch = false;
        self.maybe_update_is_current(new_tip, adjusted_time_unix);

        // Repopulate the best chain candidates by scouring the block
        // tree, since the new tip was likely removed from them.
        self.index.add_best_chain_candidate(new_tip);
        let mut tips: Vec<NodeId> = Vec::new();
        let _ = self.index.for_each_chain_tip(|tip| -> Result<(), ()> {
            tips.push(tip);
            Ok(())
        });
        let new_tip_work = self.store.node(new_tip).work_sum;
        for tip in tips {
            // Chain tips with less work than the new tip are not
            // candidates, nor are any of their ancestors.
            if self.store.node(tip).work_sum < new_tip_work {
                continue;
            }

            // Find the first ancestor of the tip that is not known to
            // be invalid and can be validated.
            let mut n = Some(tip);
            while let Some(id) = n {
                if !self.store.node(id).status.known_invalid()
                    && self.index.can_validate(&self.store, id)
                {
                    break;
                }
                n = self.store.node(id).parent;
            }
            if let Some(id) = n
                && id != new_tip
                && self.store.node(id).work_sum >= new_tip_work
            {
                self.index.add_best_chain_candidate(id);
            }
        }

        // Reorganize to the best remaining candidate.
        let target = self.index.find_best_chain_candidate(&self.store);
        self.flush_block_index_warn_only(params);
        self.reorganize_chain(target, adjusted_time_unix, params)
    }

    /// Remove the known invalid status from the block and its
    /// ancestors, clear the invalid ancestor status from descendants
    /// not otherwise invalid, and reorganize to the best resulting
    /// chain (dcrd `ReconsiderBlock`).
    pub fn reconsider_block(
        &mut self,
        hash: &Hash,
        adjusted_time_unix: i64,
        params: &Params,
    ) -> Vec<RuleError> {
        // The reorganization below flushes the utxo cache; keep the
        // periodic-flush clock on the caller's adjusted time (and
        // seed the flush baseline on first observation, like
        // `process_block`).
        self.utxo_clock_unix = adjusted_time_unix;
        if self.utxo_last_flush_unix == 0 {
            self.utxo_last_flush_unix = adjusted_time_unix;
        }
        let Some(node) = self.index.lookup_node(hash) else {
            return alloc::vec![rule_error(
                RuleErrorKind::UnknownBlock,
                format!("block {hash} is not known"),
            )];
        };

        // Remove invalidity flags from the block and its ancestors
        // while tracking the earliest block marked as having failed
        // validation, adding any that become eligible as best chain
        // candidates and restoring unlinked children entries.
        let cur_best_tip = self.best_chain.tip().expect("best chain tip");
        let cur_best_work = self.store.node(cur_best_tip).work_sum;
        let mut vf_node = node;
        let mut n = Some(node);
        while let Some(id) = n {
            if self.store.node(id).height == 0 {
                break;
            }
            let status = self.store.node(id).status;
            if status.known_invalid() {
                if status.known_validate_failed() {
                    vf_node = id;
                }
                self.index.unset_status_flags(
                    &mut self.store,
                    id,
                    BlockStatus(BlockStatus::VALIDATE_FAILED.0 | BlockStatus::INVALID_ANCESTOR.0),
                );
                // Ensure it undergoes full revalidation should that be
                // necessary (dcrd `process.go:826`).
                let hash = self.store.node(id).hash;
                self.recent_context_checks.delete(&hash);
            }

            if self.index.can_validate(&self.store, id)
                && self.store.node(id).work_sum >= cur_best_work
            {
                self.index.add_best_chain_candidate(id);
            }

            let nd = self.store.node(id);
            if !nd.is_fully_linked
                && nd.status.have_data()
                && let Some(parent) = nd.parent
            {
                self.index.add_unlinked_child(parent, id);
            }
            n = self.store.node(id).parent;
        }

        // Remove the invalid ancestor flag from descendants of the
        // earliest failed block that are neither themselves marked as
        // failed nor descendants of another such block.
        let mut tips: Vec<NodeId> = Vec::new();
        let _ = self.index.for_each_chain_tip_after_height(
            &self.store,
            vf_node,
            |tip| -> Result<(), ()> {
                tips.push(tip);
                Ok(())
            },
        );
        for tip in tips {
            if !self.store.is_ancestor_of(vf_node, tip) {
                continue;
            }

            // Find the final descendant not known to descend from
            // another block that failed validation.
            let mut final_ok = tip;
            let mut m = tip;
            while m != vf_node {
                if self.store.node(m).status.known_validate_failed() {
                    final_ok = self.store.node(m).parent.expect("descendant parent");
                }
                m = self.store.node(m).parent.expect("descendant parent");
            }

            let mut m = final_ok;
            while m != vf_node {
                self.index.unset_status_flags(
                    &mut self.store,
                    m,
                    BlockStatus(BlockStatus::INVALID_ANCESTOR.0),
                );
                let hash = self.store.node(m).hash;
                self.recent_context_checks.delete(&hash);
                if self.index.can_validate(&self.store, m)
                    && self.store.node(m).work_sum >= cur_best_work
                {
                    self.index.add_best_chain_candidate(m);
                }
                let nd = self.store.node(m);
                if !nd.is_fully_linked
                    && nd.status.have_data()
                    && let Some(parent) = nd.parent
                {
                    self.index.add_unlinked_child(parent, m);
                }
                m = self.store.node(m).parent.expect("descendant parent");
            }
        }

        // Update the best known invalid block and the best header
        // over all tips.
        self.index.reset_best_invalid();
        let mut all_tips: Vec<NodeId> = Vec::new();
        let _ = self.index.for_each_chain_tip(|tip| -> Result<(), ()> {
            all_tips.push(tip);
            Ok(())
        });
        for tip in all_tips {
            if self.store.node(tip).status.known_invalid() {
                self.index.maybe_update_best_invalid(&self.store, tip);
            }
            self.index
                .maybe_update_best_header_for_tip(&self.store, tip);
        }

        // Reset the current latch and reorganize to the best
        // candidate, then force pruning of the cached chain tips.
        self.is_current_latch = false;
        let target = self.index.find_best_chain_candidate(&self.store);
        self.flush_block_index_warn_only(params);
        let errs = self.reorganize_chain(target, adjusted_time_unix, params);
        let best = self.best_chain.tip().expect("best chain tip");
        self.index.prune_cached_tips(&self.store, best);
        // dcrd's `pruneCachedTips` stamps the time of the prune.
        self.cached_tips_last_pruned_unix = self.utxo_clock_unix;
        errs
    }

    /// Prune the cached chain tips relative to the new best node at
    /// most once per [`CACHED_TIPS_PRUNE_INTERVAL_SECS`] (dcrd
    /// `blockIndex.MaybePruneCachedTips`, `blockindex.go:1045-1056`,
    /// called by `connectBlock` right after the tip moves), timed on the
    /// adjusted clock of the processing call in flight like the other
    /// periodic work here.  dcrd's load path prunes and stamps the wall
    /// clock (`chainio.go:1710`); the load here prunes without a clock,
    /// so the first observed time stands in for that stamp and the first
    /// timed prune comes one interval later, as it does in dcrd.
    fn maybe_prune_cached_tips(&mut self, best_node: NodeId) {
        let now = self.utxo_clock_unix;
        if self.cached_tips_last_pruned_unix == 0 {
            self.cached_tips_last_pruned_unix = now;
            return;
        }
        if now.saturating_sub(self.cached_tips_last_pruned_unix) >= CACHED_TIPS_PRUNE_INTERVAL_SECS
        {
            self.index.prune_cached_tips(&self.store, best_node);
            self.cached_tips_last_pruned_unix = now;
        }
    }

    /// Force a reorganization to a sibling of the current best chain
    /// tip (dcrd `forceHeadReorganization`).
    pub fn force_head_reorganization(
        &mut self,
        former_best: Hash,
        new_best: Hash,
        adjusted_time_unix: i64,
        params: &Params,
    ) -> Vec<RuleError> {
        // The reorganization below flushes the utxo cache; keep the
        // periodic-flush clock on the caller's adjusted time (and
        // seed the flush baseline on first observation, like
        // `process_block`).
        self.utxo_clock_unix = adjusted_time_unix;
        if self.utxo_last_flush_unix == 0 {
            self.utxo_last_flush_unix = adjusted_time_unix;
        }
        if former_best == new_best {
            return alloc::vec![rule_error(
                RuleErrorKind::ForceReorgSameBlock,
                "tried to force reorg to the same block",
            )];
        }
        let former_best_node = self.best_chain.tip().expect("best chain tip");
        if self.store.node(former_best_node).hash != former_best {
            return alloc::vec![rule_error(
                RuleErrorKind::ForceReorgWrongChain,
                "tried to force reorg on wrong chain",
            )];
        }
        let new_best_node = self.index.lookup_node(&new_best);
        let valid_sibling = new_best_node
            .is_some_and(|n| self.store.node(n).parent == self.store.node(former_best_node).parent);
        if !valid_sibling {
            return alloc::vec![rule_error(
                RuleErrorKind::ForceReorgMissingChild,
                "missing child of common parent for forced reorg",
            )];
        }
        let new_best_node = new_best_node.expect("checked above");
        let status = self.index.node_status(&self.store, new_best_node);
        if status.known_invalid() {
            return alloc::vec![rule_error(
                RuleErrorKind::KnownInvalidBlock,
                "block is known to be invalid",
            )];
        }
        if !status.have_data() {
            return alloc::vec![rule_error(
                RuleErrorKind::NoBlockData,
                "block data is not available",
            )];
        }
        // dcrd flushes warn-only after the reorganization whether or
        // not it succeeded, "as the only time the index will be
        // modified is if the block failed to connect"
        // (`chain.go:1453-1458`).
        let errs = self.reorganize_chain(Some(new_best_node), adjusted_time_unix, params);
        self.flush_block_index_warn_only(params);
        errs
    }

    /// Fully validate that connecting the block template to the
    /// current tip of the main chain or its parent does not violate
    /// any consensus rules aside from proof of work (dcrd
    /// `CheckConnectBlockTemplate`).
    pub fn check_connect_block_template(
        &mut self,
        block: &MsgBlock,
        adjusted_time_unix: i64,
        params: &Params,
    ) -> Result<(), RuleError> {
        // The template must build off the current tip or its parent.
        let tip = self.best_chain.tip().expect("best chain tip");
        let tip_hash = self.store.node(tip).hash;
        let tip_parent = self.store.node(tip).parent;
        let parent_hash = block.header.prev_block;
        let prev_node = if parent_hash == tip_hash {
            Some(tip)
        } else {
            tip_parent.filter(|tp| parent_hash == self.store.node(*tp).hash)
        };
        let Some(prev_node) = prev_node else {
            return Err(rule_error(
                RuleErrorKind::InvalidTemplateParent,
                format!(
                    "previous block must be the current chain tip {tip_hash} or its parent, \
                     but got {parent_hash}"
                ),
            ));
        };
        let prev_height = self.store.node(prev_node).height;

        // Context-free sanity checks, skipping the proof of work.
        crate::validate::check_block_sanity(block, adjusted_time_unix, true, params)?;

        // The positional checks over the parent branch.  dcrd's
        // `checkBlockPositional` is a method on the chain and reads the
        // fork rejection checkpoint from its own index, so the check is
        // live on this path (`validate.go:1372-1393`, whose sole caller
        // is `CheckConnectBlockTemplate` at `:4432`).  Supplying `None`
        // here made `ErrForkTooOld` structurally unreachable for the
        // one consumer dcrd has.
        //
        // `block_in_index` is looked up rather than assumed false: dcrd
        // evaluates `b.index.LookupNode(&blockHash) == nil` on this
        // path too, and a caller may hand over a block already in the
        // index.
        let fork_rejection = self.reject_forks_checkpoint.map(|cp| ForkRejection {
            checkpoint_height: self.store.node(cp).height,
            prev_is_checkpoint_ancestor: self.store.is_ancestor_of(prev_node, cp),
            block_in_index: self.index.lookup_node(&block.header.block_hash()).is_some(),
        });
        {
            let view = NodeBranchView {
                store: &self.store,
                tip: prev_node,
            };
            crate::validate::check_block_positional(
                &view,
                block,
                Some(prev_height),
                false,
                fork_rejection.as_ref(),
                params,
            )?;
        }

        // The contextual checks, again skipping the proof of work.
        // dcrd's `checkBlockContext` skips them for a block that
        // recently passed them (`validate.go:1937-1940`), which a
        // caller handing over an already processed block can reach.
        if !self
            .recent_context_checks
            .contains(&block.header.block_hash())
        {
            let prev_stake_node = self
                .fetch_stake_node(prev_node, params)
                .map_err(stake_rule_error)?;
            let view = NodeBranchView {
                store: &self.store,
                tip: prev_node,
            };
            crate::validate::check_block_context(
                &view,
                block,
                Some(prev_height),
                false,
                true,
                prev_stake_node.pool_size() as u32,
                prev_stake_node.final_state(),
                Some(&prev_stake_node),
                params,
            )?;
        }

        // A template is never in the block index, so the assumed
        // valid ancestry check inside dcrd's connect always reports
        // false and scripts run unless bulk importing.
        let run_scripts = !self.bulk_import_mode;
        let is_treasury_enabled = {
            let view = NodeBranchView {
                store: &self.store,
                tip: prev_node,
            };
            crate::agendas::is_treasury_agenda_active(&view, Some(prev_height), params)
                .map_err(|_| unknown_deployment_error())?
        };

        let mut view = UtxoView::new();
        view.set_best_hash(tip_hash);
        let template_info = (
            prev_height + 1,
            block.header.block_hash(),
            block.header.voters,
            block.header.vote_bits,
        );
        let mut subsidy_cache = dcroxide_standalone::SubsidyCache::new(ChainSubsidyParams(params));

        if prev_node == tip {
            // Use the chain state as is when extending the main chain.
            // dcrd wraps a failed parent fetch here, and only here, as
            // `ErrMissingParent` carrying the fetch error's text
            // (`validate.go:4510-4513`); the tip-parent arm below
            // returns the fetch error itself.
            let parent = self
                .block_arc(tip)
                .map_err(|e| rule_error(RuleErrorKind::MissingParent, format!("{e}")))?;
            let branch_view = NodeBranchView {
                store: &self.store,
                tip: prev_node,
            };
            return crate::validate::check_connect_block(
                &branch_view,
                &mut subsidy_cache,
                template_info.0,
                template_info.1,
                template_info.2,
                template_info.3,
                block,
                &parent,
                || self.fetch_spend_journal(&parent, is_treasury_enabled),
                &mut view,
                &ChainUtxoResolver { chain: self },
                None,
                run_scripts,
                self.sig_cache.as_deref(),
                &|blk: &MsgBlock| self.tspend_checks(prev_node, blk, params),
                params,
            )
            .map(|_| ());
        }

        // The template builds on the parent of the current tip: undo
        // the tip block to reach the template's point of view.
        let tip_block = self.stored_block_arc(tip)?;
        let parent = self.stored_block_arc(prev_node)?;
        let stxos = self.fetch_spend_journal(&tip_block, is_treasury_enabled)?;
        view.disconnect_block(
            &tip_block,
            &parent,
            &stxos,
            &ChainUtxoResolver { chain: self },
            is_treasury_enabled,
        )?;
        let branch_view = NodeBranchView {
            store: &self.store,
            tip: prev_node,
        };
        crate::validate::check_connect_block(
            &branch_view,
            &mut subsidy_cache,
            template_info.0,
            template_info.1,
            template_info.2,
            template_info.3,
            block,
            &parent,
            || self.fetch_spend_journal(&parent, is_treasury_enabled),
            &mut view,
            &ChainUtxoResolver { chain: self },
            None,
            run_scripts,
            self.sig_cache.as_deref(),
            &|blk: &MsgBlock| self.tspend_checks(prev_node, blk, params),
            params,
        )
        .map(|_| ())
    }

    /// Load utxo details from the point of view of just having
    /// connected the given block, which must be a block template that
    /// connects to the parent of the current tip of the main chain
    /// (dcrd `FetchUtxoViewParentTemplate`).  dcrd's rule errors
    /// (`ErrInvalidTemplateParent`) surface here as their message
    /// strings, matching the mining seam that consumes them.
    pub fn fetch_utxo_view_parent_template(
        &self,
        block: &MsgBlock,
        params: &Params,
    ) -> Result<UtxoView, String> {
        // The block template must build off the parent of the current
        // tip of the main chain.
        let tip = self.best_chain.tip().expect("best chain tip");
        let tip_hash = self.store.node(tip).hash;
        let Some(tip_parent) = self.store.node(tip).parent else {
            return Err(format!(
                "unable to fetch utxos for non-existent parent of the current tip {tip_hash}"
            ));
        };
        let tip_parent_hash = self.store.node(tip_parent).hash;
        let parent_hash = block.header.prev_block;
        if parent_hash != tip_parent_hash {
            return Err(format!(
                "previous block must be the parent of the current chain tip {tip_parent_hash}, \
                 but got {parent_hash}"
            ));
        }

        // Since the block template is building on the parent of the
        // current tip, undo the transactions and spend information
        // for the tip block to reach the point of view of the block
        // template.
        let mut view = UtxoView::new();
        view.set_best_hash(tip_hash);
        let tip_block = self.block_arc(tip).map_err(|e| format!("{e}"))?;
        let parent = self.block_arc(tip_parent).map_err(|e| format!("{e}"))?;

        // Determine if the treasury agenda is active.
        let is_treasury_enabled = self
            .is_treasury_agenda_active(&tip_parent_hash, params)
            .map_err(|e| e.description)?;

        // Load all of the spent txos for the tip block from the spend
        // journal, then update the view to unspend all of them and
        // remove the utxos created by the tip block.  Also, if the
        // block votes against its parent, reconnect all of the
        // regular transactions.
        let stxos = self
            .fetch_spend_journal(&tip_block, is_treasury_enabled)
            .map_err(|e| e.description.clone())?;
        view.disconnect_block(
            &tip_block,
            &parent,
            &stxos,
            &ChainUtxoResolver { chain: self },
            is_treasury_enabled,
        )
        .map_err(|e| e.description)?;

        // The view is now from the point of view of the parent of the
        // current tip block.  However, calculating the commitment
        // root requires the view to include outputs created in the
        // candidate block, so update the view to mark all utxos
        // referenced by the block as spent and add all transactions
        // being created by the block to it.  In the case the block
        // votes against the parent, also disconnect all of the
        // regular transactions in the parent block (dcrd passes nil
        // stxos to collect here; the parent journal is decoded lazily,
        // only on that disapproval path, as dcrd does).
        view.connect_block(
            block,
            &parent,
            || self.fetch_spend_journal(&parent, is_treasury_enabled),
            &ChainUtxoResolver { chain: self },
            None,
            is_treasury_enabled,
        )
        .map_err(|e| e.description)?;

        Ok(view)
    }

    /// Ensure extending the provided block with one containing the
    /// specified number of ticket purchases cannot make the chain
    /// unrecoverable through ticket exhaustion (dcrd
    /// `checkTicketExhaustion`).
    pub fn check_ticket_exhaustion(
        &self,
        prev_node: NodeId,
        ticket_purchases: u8,
        params: &Params,
    ) -> Result<(), RuleError> {
        // Nothing to do when the chain is not far enough along for
        // exhaustion to be an issue.
        let prev = self.store.node(prev_node);
        let next_height = prev.height + 1;
        let ticket_maturity = i64::from(params.ticket_maturity);
        if next_height + ticket_maturity + 1 < params.stake_validation_height {
            return Ok(());
        }

        // The final live pool size after the maturity period.
        let mut final_pool_size = i64::from(prev.pool_size);
        {
            let view = NodeBranchView {
                store: &self.store,
                tip: prev_node,
            };
            final_pool_size += crate::difficulty::sum_purchased_tickets(
                &view,
                Some(prev.height),
                ticket_maturity + 1,
            );
        }
        final_pool_size += i64::from(ticket_purchases);
        let mut voting_blocks_in_maturity_period = ticket_maturity + 2;
        if prev.height < params.stake_validation_height {
            voting_blocks_in_maturity_period -= params.stake_validation_height - prev.height;
        }
        let votes_per_block = i64::from(params.tickets_per_block);
        final_pool_size -= voting_blocks_in_maturity_period * votes_per_block;

        if final_pool_size < votes_per_block {
            let purchases_needed = votes_per_block - final_pool_size;
            return Err(rule_error(
                RuleErrorKind::TicketExhaustion,
                format!(
                    "extending block {} (height {}) with a block that contains fewer than \
                     {purchases_needed} ticket purchase(s) would result in an unrecoverable \
                     chain due to ticket exhaustion",
                    prev.hash, prev.height
                ),
            ));
        }
        Ok(())
    }

    /// The hash-keyed wrapper for the ticket exhaustion check (dcrd
    /// `CheckTicketExhaustion`).
    pub fn check_ticket_exhaustion_by_hash(
        &self,
        hash: &Hash,
        ticket_purchases: u8,
        params: &Params,
    ) -> Result<(), RuleError> {
        let node = self.index.lookup_node(hash).ok_or_else(|| {
            rule_error(
                RuleErrorKind::UnknownBlock,
                format!("block {hash} is not known"),
            )
        })?;
        self.check_ticket_exhaustion(node, ticket_purchases, params)
    }

    /// Whether the block with the given hash is in the main chain
    /// (dcrd `MainChainHasBlock`).
    pub fn main_chain_has_block(&self, hash: &Hash) -> bool {
        self.index
            .lookup_node(hash)
            .is_some_and(|n| self.best_chain.contains(&self.store, n))
    }

    /// The height of the main chain block with the given hash (dcrd
    /// `BlockHeightByHash`).
    pub fn block_height_by_hash(&self, hash: &Hash) -> Option<i64> {
        self.index
            .lookup_node(hash)
            .filter(|n| self.best_chain.contains(&self.store, *n))
            .map(|n| self.store.node(n).height)
    }

    /// The hash of the main chain block at the given height (dcrd
    /// `BlockHashByHeight`).
    pub fn block_hash_by_height(&self, height: i64) -> Option<Hash> {
        self.best_chain
            .node_by_height(height)
            .map(|n| self.store.node(n).hash)
    }

    /// The header of the block with the given hash regardless of
    /// chain (dcrd `HeaderByHash`).
    pub fn header_by_hash(&self, hash: &Hash) -> Option<BlockHeader> {
        self.index.lookup_node(hash).map(|n| self.store.header(n))
    }

    /// The header of the main chain block at the given height (dcrd
    /// `HeaderByHeight`).
    pub fn header_by_height(&self, height: i64) -> Option<BlockHeader> {
        self.best_chain
            .node_by_height(height)
            .map(|n| self.store.header(n))
    }

    /// Fetch a stored block from the database — the fallback once the
    /// recent in-memory window has been pruned (dcrd serves every
    /// block from its database through `dbFetchBlockByNode`).  A failed
    /// read, including the database's own `ErrBlockNotFound`, and a
    /// body that does not decode come back as the error dcrd returns
    /// there, never as a missing block.  A chain without a database
    /// holds every block in the window, so a block missing from it is
    /// reported with the database's "does not exist" text.
    fn db_fetch_stored_block(&self, hash: &Hash) -> Result<MsgBlock, crate::chaindb::ChainDbError> {
        fetch_stored_block(self.db.as_ref(), hash)
    }

    /// The block data for a node from the recent in-memory window or
    /// the database (dcrd `fetchBlockByNode`).  A block in the window
    /// comes back as the mirror's own `Arc`, not a copy, the way dcrd's
    /// recent block cache hands back its pointer.
    fn block_arc(&self, node: NodeId) -> Result<Arc<MsgBlock>, crate::chaindb::ChainDbError> {
        let hash = self.store.node(node).hash;
        if let Some(block) = self.blocks.get(&hash.0) {
            return Ok(Arc::clone(block));
        }
        self.db_fetch_stored_block(&hash).map(Arc::new)
    }

    /// [`Self::block_arc`] on the paths that return a rule error: the
    /// reorganization loops, `maybe_accept_blocks` and the template
    /// checks, where dcrd returns `fetchBlockByNode`'s error and the
    /// operation fails with the node still running.  The database error
    /// is carried as `ErrUtxoBackendCorruption` with its own text, the
    /// kind the port gives the other local-corruption errors (see
    /// `fetch_spend_journal`), so `is_rule_violation` neither brands the
    /// block nor blames the peer for it.
    fn stored_block_arc(&self, node: NodeId) -> Result<Arc<MsgBlock>, RuleError> {
        self.block_arc(node).map_err(db_read_rule_error)
    }

    /// The block data for a node as an owned block, for the public
    /// accessors that return one: a copy of a block in the window, or
    /// the block read back from the database.
    fn block_data(&self, node: NodeId) -> Option<MsgBlock> {
        self.block_arc(node).ok().map(Arc::unwrap_or_clone)
    }

    /// A block's serialized spend journal row from the recent window
    /// or the database.  A transaction that cannot be opened is dcrd's
    /// failed `db.View` and comes back as the error; a row the bucket
    /// does not return is `None`, which is all dcrd's ffldb `Get` can
    /// say even when the underlying read failed.
    fn spend_journal_row(
        &self,
        hash: &Hash,
    ) -> Result<Option<Vec<u8>>, crate::chaindb::ChainDbError> {
        if let Some(row) = self.spend_journal.get(&hash.0) {
            return Ok(Some(row.clone()));
        }
        let Some(db) = self.db.as_ref() else {
            return Ok(None);
        };
        let mut found = None;
        db.view(|tx| {
            let meta = tx.metadata();
            if let Some(bucket) = meta.bucket(crate::chaindb::SPEND_JOURNAL_BUCKET_NAME) {
                found = bucket.get(&hash.0);
            }
            Ok(())
        })?;
        Ok(found)
    }

    /// A block's version 2 GCS filter from the recent window or the
    /// database: `Ok(None)` when no filter is stored, and the error
    /// dcrd's `dbFetchGCSFilter` returns for a failed read or a row
    /// that does not decode.
    fn gcs_filter(&self, hash: &Hash) -> Result<Option<FilterV2>, crate::chaindb::ChainDbError> {
        if let Some(filter) = self.filters.get(&hash.0) {
            return Ok(Some(filter.clone()));
        }
        let Some(db) = self.db.as_ref() else {
            return Ok(None);
        };
        let mut found = Ok(None);
        db.view(|tx| {
            found = crate::chaindb::db_fetch_gcs_filter(tx, hash);
            Ok(())
        })?;
        found
    }

    /// A block's serialized version 2 GCS filter from the recent window
    /// or the database, without decoding it (dcrd
    /// `dbFetchRawGCSFilter`, which `LocateCFiltersV2` serves from).
    fn raw_gcs_filter(&self, hash: &Hash) -> Result<Option<Vec<u8>>, crate::chaindb::ChainDbError> {
        if let Some(filter) = self.filters.get(&hash.0) {
            return Ok(Some(filter.bytes().to_vec()));
        }
        let Some(db) = self.db.as_ref() else {
            return Ok(None);
        };
        let mut found = Ok(None);
        db.view(|tx| {
            found = crate::chaindb::db_fetch_raw_gcs_filter(tx, hash);
            Ok(())
        })?;
        found
    }

    /// A block's header commitment leaves from the recent window or
    /// the database, or the error dcrd's `dbFetchHeaderCommitments`
    /// returns for a failed read or a row that does not decode.
    fn commitments_by_block_hash(
        &self,
        hash: &Hash,
    ) -> Result<Vec<Hash>, crate::chaindb::ChainDbError> {
        if let Some(leaves) = self.header_commitments.get(&hash.0) {
            return Ok(leaves.clone());
        }
        let Some(db) = self.db.as_ref() else {
            return Ok(Vec::new());
        };
        let mut found = Ok(Vec::new());
        db.view(|tx| {
            found = crate::chaindb::db_fetch_header_commitments(tx, hash);
            Ok(())
        })?;
        found
    }

    /// A block's treasury state row from the recent window or the
    /// database (dcrd reads `dbFetchTreasuryBalance` on every lookup).
    /// `Ok(None)` is dcrd's `errDbTreasury`, the missing key, which
    /// `sumPastTreasuryChanges` reads as the end of the records.  A row
    /// that does not decode (dcrd's `errDeserialize`) or a failed read
    /// is `Err` with its text: `sumPastTreasuryChanges` returns those,
    /// and only `calculateTreasuryBalance` reads every error as zero.
    fn treasury_state_row(
        &self,
        hash: &Hash,
    ) -> Result<Option<alloc::borrow::Cow<'_, crate::treasurydb::TreasuryState>>, String> {
        if let Some(ts) = self.treasury_state.get(&hash.0) {
            return Ok(Some(alloc::borrow::Cow::Borrowed(ts)));
        }
        let Some(db) = self.db.as_ref() else {
            return Ok(None);
        };
        let mut found = Ok(None);
        db.view(|tx| {
            found = crate::treasurydb::db_fetch_treasury_balance(tx, hash);
            Ok(())
        })
        .map_err(|e| format!("{e}"))?;
        found
            .map(|row| row.map(alloc::borrow::Cow::Owned))
            .map_err(|e| format!("{e}"))
    }

    /// A height's ticket database rows (undo data and new tickets)
    /// from the recent window or the database, the fallback in dcrd's
    /// `stake.Node.DisconnectNode` (`tickets.go:762-779`), which reads
    /// both through `DbFetchBlockUndoData` and `DbFetchNewTickets`.
    ///
    /// A failed read, a missing row and a row that does not decode come
    /// back as the error dcrd's fetchers return, which `fetchStakeNode`
    /// passes up with the node still running.  The stake-node error
    /// type has no database kind, so each travels as
    /// `ErrDatabaseCorrupt` with the ticket database error's
    /// description (as `stake_block_by_node` carries dcrd's
    /// `ErrBlockNotFound`).
    fn ticket_rows_by_height(
        &self,
        height: i64,
    ) -> Result<(Vec<UndoTicketData>, Vec<Hash>), dcroxide_stake::RuleError> {
        if let (Some(utds), Some(ths)) = (
            self.stake_undo.get(&height),
            self.stake_new_tickets.get(&height),
        ) {
            return Ok((utds.clone(), ths.clone()));
        }
        let corrupt = |description: String| dcroxide_stake::RuleError {
            kind: dcroxide_stake::ErrorKind::DatabaseCorrupt,
            description,
        };
        let stake_db_error = |err: dcroxide_stake::stakedb::StakeDbError| match err {
            dcroxide_stake::stakedb::StakeDbError::Db(e) => corrupt(format!("{e}")),
            dcroxide_stake::stakedb::StakeDbError::Ticket(e) => corrupt(e.description),
            dcroxide_stake::stakedb::StakeDbError::Rule(e) => e,
        };
        // A chain without a database keeps every row in the mirrors, so
        // a row missing there is the missing key.
        let Some(db) = self.db.as_ref() else {
            let what = if self.stake_undo.contains_key(&height) {
                "new tickets"
            } else {
                "block undo data"
            };
            return Err(corrupt(format!("missing key for {what}")));
        };
        let mut found = Err(corrupt(String::new()));
        db.view(|tx| {
            found = dcroxide_stake::stakedb::db_fetch_block_undo_data(tx, height as u32)
                .and_then(|utds| {
                    dcroxide_stake::stakedb::db_fetch_new_tickets(tx, height as u32)
                        .map(|ths| (utds, ths))
                })
                .map_err(stake_db_error);
            Ok(())
        })
        .map_err(|e| corrupt(format!("{e}")))?;
        found
    }

    /// The depth of the recent window: how many blocks keep their stake
    /// nodes and recent-window mirror entries in memory (dcrd
    /// `minMemoryStakeNodes`).  The timed prune measures it below the
    /// best chain tip, but the connect-time prune measures it below the
    /// best known header (`chain.go:795-808`), so during initial sync,
    /// with the header chain far ahead, each connected block's parent
    /// leaves memory at once and next to nothing stays.
    pub const MIN_MEMORY_STAKE_NODES: i64 = 288;

    /// Set the maximum pending-UTXO-cache size before a connect flushes
    /// it (dcrd's `--utxocachemaxsize`, in bytes).
    pub fn set_utxo_cache_max_bytes(&mut self, bytes: u64) {
        self.utxo_cache_max_bytes = bytes;
    }

    /// Prune old in-memory state on the pruning interval — the target
    /// block time (dcrd's `chainPruner.pruneChainIfNeeded`, called from
    /// `maybeAcceptBlockData`, `process.go:320`).  A chain without a
    /// database never prunes: the memory is its only store.
    pub fn prune_if_needed(&mut self, now_unix: i64) {
        if self.db.is_none() {
            return;
        }
        // The first observation seeds the interval clock without
        // pruning (dcrd's `chainPruner.lastPruneTime = time.Now()`), so
        // the first prune fires one interval later, not immediately.
        if self.last_prune_unix == 0 {
            self.last_prune_unix = now_unix;
            return;
        }
        if now_unix.saturating_sub(self.last_prune_unix) < self.prune_interval_secs {
            return;
        }
        self.last_prune_unix = now_unix;
        self.prune_chain_memory(Self::MIN_MEMORY_STAKE_NODES);
    }

    /// Drop a rejected block's body from the in-memory mirror.
    ///
    /// `maybe_accept_block_data` stores every block that clears the
    /// positional checks, which is before the contextual and connect
    /// checks run, so a block that fails one of those has already been
    /// cloned into `blocks`.  The stale sweep in `prune_chain_memory`
    /// only reaches heights below `tip - MIN_MEMORY_STAKE_NODES`, so a
    /// peer that keeps feeding proof-of-work-valid blocks that fail a
    /// later check at a stationary tip holds every one of them resident
    /// for as long as the flood lasts.  dcrd cannot grow this way: it
    /// stores bodies to the database only and mirrors just
    /// `recentBlockCacheSize = 12` of them, and its own comment is
    /// explicit that proof-of-work is what makes filling the *disk*
    /// prohibitive -- it never puts the memory at stake in the first
    /// place.
    ///
    /// Only a chain that has a database may drop them: without one the
    /// map is the only copy.  That is the same guard the stale sweep
    /// uses, and for the same reason -- `block_data` falls back to
    /// `db_fetch_stored_block`, and every block reaching here was
    /// written by `maybe_accept_block_data` on the way in.
    fn forget_rejected_block_body(&mut self, node: NodeId) {
        if self.db.is_some() {
            let hash = self.store.node(node).hash;
            self.blocks.remove(&hash.0);
        }
    }

    /// Mark a block whose contextual or connect checks failed as
    /// having failed validation, and drop its body, only when the
    /// failure is a consensus rule violation.
    ///
    /// dcrd marks on `errors.As(err, &RuleError)` alone
    /// (`chain.go:1220-1243`, `process.go:377-381`).  Database
    /// corruption, assertion and context errors fail the operation
    /// without branding the block, so it stays a candidate and is
    /// retried after a restart or repair.  The port carries those
    /// failures as the kinds `RuleErrorKind::is_rule_violation`
    /// excludes -- a corrupt parent spend journal row on the
    /// disapproval path is `ErrUtxoBackendCorruption` -- so that is the
    /// test here, as it already is for peer blame.
    fn mark_block_failed_on_rule_violation(&mut self, node: NodeId, err: &RuleError) {
        if err.kind.is_rule_violation() {
            self.index
                .mark_block_failed_validation(&mut self.store, node);
            self.forget_rejected_block_body(node);
        }
    }

    /// Drop one node's prunable in-memory state: the stake-related
    /// fields dcrd's pruners nil (`stakeNode`, `newTickets`,
    /// `ticketsVoted`, `ticketsRevoked`), and, when `evict_mirrors` is
    /// set, the block's entries in the port's recent-window mirrors,
    /// which the database fallbacks serve from then on.
    fn prune_node_memory(&mut self, id: NodeId, evict_mirrors: bool) {
        let (hash, height) = {
            let node = self.store.node(id);
            (node.hash, node.height)
        };
        {
            // dcrd nils the ticket slices, which is what makes its
            // `maybeFetchTicketInfo` re-read them; the flag is that
            // nil-ness here, so it has to go with the lists.
            let node = self.store.node_mut(id);
            node.stake_node = None;
            node.new_tickets = None;
            node.tickets_voted = Vec::new();
            node.tickets_revoked = Vec::new();
            node.ticket_info_populated = false;
        }
        if !evict_mirrors {
            return;
        }
        // The genesis block stays resident: chains are created
        // around it and it has no journal or ticket rows.
        if height > 0 {
            self.blocks.remove(&hash.0);
        }
        self.spend_journal.remove(&hash.0);
        self.filters.remove(&hash.0);
        self.header_commitments.remove(&hash.0);
        self.stake_undo.remove(&height);
        self.stake_new_tickets.remove(&height);
        self.treasury_state.remove(&hash.0);
    }

    /// dcrd `pruneStakeNodes`, extended for the port's recent-window
    /// mirrors: clear the stake-related fields on block nodes deeper
    /// than the keep depth below the tip, and, when a database backs
    /// the chain, evict those blocks' bodies, spend journal rows,
    /// filters, commitment leaves, per-height ticket rows and treasury
    /// state rows from memory — every one of them is persisted per
    /// connect and read back through the database fallbacks.  Without
    /// a database the mirrors are the only copy and stay.  The walk
    /// stops at the first already-pruned node exactly like dcrd's
    /// `stakeNode == nil` bound.
    pub fn prune_chain_memory(&mut self, keep_depth: i64) {
        let Some(tip) = self.best_chain.tip() else {
            return;
        };
        let mut prune_to = tip;
        for _ in 0..keep_depth.saturating_sub(1) {
            match self.store.node(prune_to).parent {
                Some(parent) => prune_to = parent,
                None => return,
            }
        }
        let Some(first) = self.store.node(prune_to).parent else {
            return;
        };

        // Only a chain that has a database may drop the mirrors: without
        // one they are the only copy, and an evicted treasury row would
        // read as a zero balance instead of failing.  A resident body
        // then no longer extends the walk either, since nothing below
        // dcrd's bound is left to evict.
        let evict_mirrors = self.db.is_some();
        let mut prune_nodes = Vec::new();
        let mut walk = Some(first);
        while let Some(id) = walk {
            let node = self.store.node(id);
            if node.stake_node.is_none()
                && !(evict_mirrors && self.blocks.contains_key(&node.hash.0))
            {
                break;
            }
            prune_nodes.push(id);
            walk = node.parent;
        }

        // Oldest to newest, like dcrd.
        for id in prune_nodes.into_iter().rev() {
            self.prune_node_memory(id, evict_mirrors);
        }

        // The walk above follows `parent` from the best-chain tip, so it
        // only ever visits ancestors of that tip.  Three populations are
        // therefore never visited: side-chain blocks, blocks
        // disconnected by a reorg, and blocks that cleared the
        // positional checks and were then rejected by a contextual or
        // connect check.
        //
        // The third is dropped at the point of rejection now, by
        // `forget_rejected_block_body`, because it was the one an
        // attacker controls: a peer feeding proof-of-work-valid blocks
        // that fail a later check does not move the tip, so nothing it
        // sends ever falls below the sweep horizon and the map grew for
        // as long as the flood ran.  The other two are bounded by
        // honest fork churn rather than by an attacker, and are left to
        // the height sweep below.
        //
        // dcrd has no equivalent leak to prune, because it never
        // accumulates bodies in the first place: `maybeAcceptBlockData`
        // stores to the *database* only (`process.go:331-337`, whose
        // comment says keeping doomed-but-proof-of-work-valid blocks on
        // disk is deliberate), and the sole in-memory copy is a fixed
        // `recentBlockCacheSize = 12` LRU (`chain.go:43-48`).  Its
        // steady-state body footprint is 12 whatever the fork history.
        // Its spend journal, filters and header commitments have no
        // in-memory mirror at all.
        //
        // Dropping these costs a database read: every one was written by
        // `maybe_accept_block_data`, and `block_data` already falls back
        // to `db_fetch_stored_block`.  Only a chain that *has* a
        // database may drop them -- without one the map is the only
        // copy, and `prune_chain_memory` is `pub`, so the guard belongs
        // here rather than only in `prune_if_needed`.
        if self.db.is_some() {
            let keep_from = self.store.node(prune_to).height;
            let stale: Vec<[u8; 32]> = self
                .blocks
                .keys()
                .copied()
                .filter(|raw| match self.index.lookup_node(&Hash(*raw)) {
                    Some(id) => {
                        let height = self.store.node(id).height;
                        height > 0 && height < keep_from
                    }
                    None => false,
                })
                .collect();
            for raw in stale {
                self.blocks.remove(&raw);
                self.spend_journal.remove(&raw);
                self.filters.remove(&raw);
                self.header_commitments.remove(&raw);
            }

            // Treasury rows are written at connect, so a side-chain row
            // can outlive its body in `blocks`; sweep them on their own.
            let stale: Vec<[u8; 32]> = self
                .treasury_state
                .keys()
                .copied()
                .filter(|raw| match self.index.lookup_node(&Hash(*raw)) {
                    Some(id) => self.store.node(id).height < keep_from,
                    None => false,
                })
                .collect();
            for raw in stale {
                self.treasury_state.remove(&raw);
            }
        }
    }

    /// The block with the given hash when its data is available (dcrd
    /// `BlockByHash`).
    pub fn block_by_hash(&self, hash: &Hash) -> Option<MsgBlock> {
        self.index
            .lookup_node(hash)
            .filter(|n| self.index.node_status(&self.store, *n).have_data())
            .and_then(|n| self.block_data(n))
    }

    /// The main chain block at the given height (dcrd
    /// `BlockByHeight`).
    pub fn block_by_height(&self, height: i64) -> Option<MsgBlock> {
        self.best_chain
            .node_by_height(height)
            .and_then(|n| self.block_data(n))
    }

    /// The past median time of the block with the given hash (dcrd
    /// `MedianTimeByHash`).
    pub fn median_time_by_hash(&self, hash: &Hash) -> Option<i64> {
        self.index
            .lookup_node(hash)
            .map(|n| self.store.calc_past_median_time(n))
    }

    /// The cumulative work of the block with the given hash (dcrd
    /// `ChainWork`).
    pub fn chain_work(&self, hash: &Hash) -> Option<Uint256> {
        self.index
            .lookup_node(hash)
            .map(|n| self.store.node(n).work_sum)
    }

    /// The hashes for the next blocks after the current best chain
    /// tip that are needed to make progress towards the current best
    /// known header, skipping any blocks that already have their data
    /// available, up to the given maximum (dcrd `PutNextNeededBlocks`
    /// with the provided slice length as the maximum).
    pub fn put_next_needed_blocks(&self, max_results: usize) -> Vec<Hash> {
        // Nothing to do when no results are requested.
        let mut out = Vec::with_capacity(max_results);
        if max_results == 0 {
            return out;
        }

        // Populate the results by making use of a sliding window.  Note
        // that the needed block hashes are populated in forwards order
        // while it is necessary to walk the block index backwards to
        // determine them.  Further, an unknown number of blocks may
        // already have their data and need to be skipped, so it's not
        // possible to determine the precise height after the fork point
        // to start iterating from.  Using a sliding window efficiently
        // handles these conditions without needing additional
        // allocations.
        //
        // The strategy is to initially determine the common ancestor
        // between the current best chain tip and the current best known
        // header as the starting fork point and move the fork point
        // forward by the window size after populating the output with
        // all relevant nodes in the window until either there are no
        // more results or the desired number of results have been
        // populated.
        const WINDOW_SIZE: i64 = 32;
        let mut window = [Hash([0u8; 32]); WINDOW_SIZE as usize];
        let Some(best_header) = self.index.best_header() else {
            return out;
        };
        let mut fork = self.best_chain.find_fork(&self.store, best_header);
        while out.len() < max_results && fork.is_some() && fork != Some(best_header) {
            let fork_node = fork.expect("fork checked above");

            // Determine the final descendant block on the branch that
            // leads to the best known header in this window by clamping
            // the number of descendants to consider to the window size.
            let mut end_node = best_header;
            let fork_height = self.store.node(fork_node).height;
            let num_blocks_to_consider = self.store.node(end_node).height - fork_height;
            if num_blocks_to_consider > WINDOW_SIZE {
                end_node = self
                    .store
                    .ancestor(end_node, fork_height + WINDOW_SIZE)
                    .expect("ancestor within branch");
            }

            // Populate the blocks in this window from back to front by
            // walking backwards from the final block to consider in the
            // window to the first one excluding any blocks that already
            // have their data available.
            let mut window_idx = WINDOW_SIZE as usize;
            let mut node = Some(end_node);
            while let Some(n) = node {
                if n == fork_node {
                    break;
                }
                if !self.index.node_status(&self.store, n).have_data() {
                    window_idx -= 1;
                    window[window_idx] = self.store.node(n).hash;
                }
                node = self.store.node(n).parent;
            }

            // Populate the outputs with as many from the back of the
            // window as possible (since the window might not have been
            // fully populated due to skipped blocks).
            for hash in &window[window_idx..] {
                if out.len() >= max_results {
                    break;
                }
                out.push(*hash);
            }

            // Move the fork point forward to the final block of the
            // window.
            fork = Some(end_node);
        }

        out
    }

    /// The entire generation of blocks at the current tip height
    /// (dcrd `TipGeneration`).
    pub fn tip_generation(&self) -> Vec<Hash> {
        let Some(tip) = self.best_chain.tip() else {
            return Vec::new();
        };
        let height = self.store.node(tip).height;
        self.index
            .tips_at_height(height)
            .into_iter()
            .map(|n| self.store.node(n).hash)
            .collect()
    }

    /// The main chain block hashes in the half-open height range
    /// `[start_height, end_height)`, with the end limited to the best
    /// chain height (dcrd `HeightRange`, `chain.go:1775-1823`).  A
    /// negative start or an end below the start is dcrd's plain error,
    /// with its text.
    pub fn height_range(&self, start_height: i64, end_height: i64) -> Result<Vec<Hash>, String> {
        if start_height < 0 {
            return Err(format!(
                "start height of fetch range must not be less than zero - got {start_height}"
            ));
        }
        if end_height < start_height {
            return Err(format!(
                "end height of fetch range must not be less than the start height - got \
                 start {start_height}, end {end_height}"
            ));
        }
        let mut out = Vec::new();
        let mut h = start_height;
        while h < end_height {
            match self.best_chain.node_by_height(h) {
                Some(n) => out.push(self.store.node(n).hash),
                None => break,
            }
            h += 1;
        }
        Ok(out)
    }

    /// Look up a block node that the chain can validate, the shared
    /// entry check of dcrd's hash-keyed query surface
    /// (`unknownBlockError` on failure).
    fn lookup_validatable(&self, hash: &Hash) -> Result<NodeId, RuleError> {
        self.index
            .lookup_node(hash)
            .filter(|n| self.index.can_validate(&self.store, *n))
            .ok_or_else(|| {
                rule_error(
                    RuleErrorKind::UnknownBlock,
                    format!("block {hash} is not known"),
                )
            })
    }

    /// Cooked stake version information for up to `count` blocks
    /// walking backwards from the given block (dcrd
    /// `GetStakeVersions`).  dcrd reports the unknown block through
    /// its context error and the negative count through a plain
    /// error; both surface here as message strings.
    pub fn get_stake_versions(
        &self,
        hash: &Hash,
        count: i32,
    ) -> Result<Vec<StakeVersions>, String> {
        let start_node = self.lookup_validatable(hash).map_err(|e| e.description)?;

        // Nothing to do if no count requested.
        if count == 0 {
            return Ok(Vec::new());
        }
        if count < 0 {
            return Err(format!("count must not be less than zero - got {count}"));
        }

        // Limit the requested count to the max possible for the
        // requested block.
        let mut count = i64::from(count);
        let start_height = self.store.node(start_node).height;
        if count > start_height + 1 {
            count = start_height + 1;
        }

        let mut result = Vec::with_capacity(count as usize);
        let mut prev_node = Some(start_node);
        let mut i = 0i64;
        while let Some(id) = prev_node {
            if i >= count {
                break;
            }
            let node = self.store.node(id);
            result.push(StakeVersions {
                hash: node.hash,
                height: node.height,
                block_version: node.block_version,
                stake_version: node.stake_version,
                votes: node.votes.clone(),
            });
            prev_node = node.parent;
            i += 1;
        }
        Ok(result)
    }

    /// The expected stake version for the block AFTER the given block
    /// hash (dcrd `CalcStakeVersionByHash`): the last prior valid
    /// majority stake version, walking back one interval at a time.
    pub fn calc_stake_version_by_hash(&self, hash: &Hash, params: &Params) -> Result<u32, String> {
        let node = self.lookup_validatable(hash).map_err(|e| e.description)?;
        let view = NodeBranchView {
            store: &self.store,
            tip: node,
        };
        let height = self.store.node(node).height;
        // The view is passed directly so the stake version caches
        // engage (dcrd `CalcStakeVersionByHash` reads the same
        // caches).
        Ok(crate::stakever::calc_stake_version(&view, height, params))
    }

    /// The required proof of work difficulty for the block AFTER the
    /// given block hash, based on the active difficulty retarget
    /// rules (dcrd `CalcNextRequiredDifficulty`).
    pub fn calc_next_required_difficulty_by_hash(
        &self,
        hash: &Hash,
        new_block_time_unix: i64,
        params: &Params,
    ) -> Result<u32, String> {
        let node = self.lookup_validatable(hash).map_err(|e| e.description)?;
        let view = NodeBranchView {
            store: &self.store,
            tip: node,
        };
        let prev_node = crate::difficulty::ChainView::node(&view, self.store.node(node).height)
            .expect("node at its own height");
        crate::agendas::calc_next_required_difficulty(
            &view,
            &prev_node,
            new_block_time_unix,
            params,
        )
        .map_err(|_| String::from("deployment ID blake3pow does not exist"))
    }

    /// The rule change threshold state of the given deployment for the
    /// block AFTER the given block hash (dcrd `NextThresholdState`).
    pub fn next_threshold_state(
        &self,
        hash: &Hash,
        deployment_id: &str,
        params: &Params,
    ) -> Result<ThresholdStateTuple, RuleError> {
        let node = self.lookup_validatable(hash)?;
        let (version, deployment) = crate::agendas::find_deployment(params, deployment_id)
            .ok_or_else(|| {
                rule_error(
                    RuleErrorKind::UnknownDeploymentID,
                    format!("deployment ID {deployment_id} does not exist"),
                )
            })?;
        let view = NodeBranchView {
            store: &self.store,
            tip: node,
        };
        let height = self.store.node(node).height;
        Ok(deployment_state(
            &view,
            Some(height),
            version,
            deployment,
            params,
        ))
    }

    /// The maximum allowed block size for the block after the given
    /// one, honoring the max-block-size vote where the network defines
    /// it (dcrd `BlockChain.MaxBlockSize`).
    pub fn max_block_size(&self, hash: &Hash, params: &Params) -> Result<i64, RuleError> {
        let node = self.lookup_validatable(hash)?;
        let view = NodeBranchView {
            store: &self.store,
            tip: node,
        };
        let height = self.store.node(node).height;
        Ok(crate::agendas::max_block_size(&view, Some(height), params))
    }

    /// Whether the DCP0006 treasury agenda is active for the block
    /// AFTER the given block (dcrd
    /// `BlockChain.IsTreasuryAgendaActive`).
    pub fn is_treasury_agenda_active(
        &self,
        prev_hash: &Hash,
        params: &Params,
    ) -> Result<bool, RuleError> {
        self.is_agenda_active_by_hash_fn(
            prev_hash,
            crate::agendas::VOTE_ID_TREASURY,
            |view, prev_height| {
                crate::agendas::is_treasury_agenda_active(view, prev_height, params)
            },
        )
    }

    /// Whether the DCP0011 blake3 proof of work agenda is active for
    /// the block AFTER the given block (dcrd
    /// `BlockChain.IsBlake3PowAgendaActive`).
    pub fn is_blake3_pow_agenda_active(
        &self,
        prev_hash: &Hash,
        params: &Params,
    ) -> Result<bool, RuleError> {
        self.is_agenda_active_by_hash(prev_hash, crate::agendas::VOTE_ID_BLAKE3_POW, params)
    }

    /// Whether the DCP0009 automatic ticket revocations agenda is
    /// active for the block AFTER the given block (dcrd
    /// `BlockChain.IsAutoRevocationsAgendaActive`).
    pub fn is_auto_revocations_agenda_active(
        &self,
        prev_hash: &Hash,
        params: &Params,
    ) -> Result<bool, RuleError> {
        self.is_agenda_active_by_hash(prev_hash, crate::agendas::VOTE_ID_AUTO_REVOCATIONS, params)
    }

    /// Whether the given single-choice agenda is active for the block
    /// AFTER the given block, the by-hash query every agenda without a
    /// special case of its own goes through.
    fn is_agenda_active_by_hash(
        &self,
        prev_hash: &Hash,
        vote_id: &'static str,
        params: &Params,
    ) -> Result<bool, RuleError> {
        self.is_agenda_active_by_hash_fn(prev_hash, vote_id, |view, prev_height| {
            crate::agendas::is_agenda_active(view, prev_height, vote_id, params)
        })
    }

    /// The shared body of the by-hash agenda queries (dcrd
    /// `isAgendaActiveByHash`, `thresholdstate.go:539-554`): inactive
    /// for the genesis block, the unknown-block error for a block the
    /// chain cannot validate, and otherwise the agenda's own check
    /// (dcrd's `isActiveFn`) from the point of view of that block.
    fn is_agenda_active_by_hash_fn(
        &self,
        prev_hash: &Hash,
        vote_id: &'static str,
        is_active_fn: impl FnOnce(
            &NodeBranchView<'_>,
            Option<i64>,
        ) -> Result<bool, crate::agendas::UnknownDeployment>,
    ) -> Result<bool, RuleError> {
        // Agendas are never active for the genesis block.
        if *prev_hash == Hash::ZERO {
            return Ok(false);
        }
        let node = self.lookup_validatable(prev_hash)?;
        let view = NodeBranchView {
            store: &self.store,
            tip: node,
        };
        let height = self.store.node(node).height;
        is_active_fn(&view, Some(height)).map_err(|_| {
            rule_error(
                RuleErrorKind::UnknownDeploymentID,
                format!("deployment ID {vote_id} does not exist"),
            )
        })
    }

    /// Whether the DCP0010 modified subsidy split agenda is active for
    /// the block AFTER the given block (dcrd
    /// `BlockChain.IsSubsidySplitAgendaActive`).
    pub fn is_subsidy_split_agenda_active(
        &self,
        prev_hash: &Hash,
        params: &Params,
    ) -> Result<bool, RuleError> {
        self.is_agenda_active_by_hash(
            prev_hash,
            crate::agendas::VOTE_ID_CHANGE_SUBSIDY_SPLIT,
            params,
        )
    }

    /// Whether the DCP0012 modified subsidy split round 2 agenda is
    /// active for the block AFTER the given block (dcrd
    /// `BlockChain.IsSubsidySplitR2AgendaActive`).
    pub fn is_subsidy_split_r2_agenda_active(
        &self,
        prev_hash: &Hash,
        params: &Params,
    ) -> Result<bool, RuleError> {
        self.is_agenda_active_by_hash(
            prev_hash,
            crate::agendas::VOTE_ID_CHANGE_SUBSIDY_SPLIT_R2,
            params,
        )
    }

    /// Whether the DCP0002/DCP0003 LN features agenda is active for
    /// the block AFTER the given block (dcrd
    /// `BlockChain.IsLNFeaturesAgendaActive`).
    pub fn is_ln_features_agenda_active(
        &self,
        prev_hash: &Hash,
        params: &Params,
    ) -> Result<bool, RuleError> {
        self.is_agenda_active_by_hash(prev_hash, crate::agendas::VOTE_ID_LN_FEATURES, params)
    }

    /// Whether the DCP0005 header commitments agenda is active for
    /// the block AFTER the given block (dcrd
    /// `BlockChain.IsHeaderCommitmentsAgendaActive`).
    pub fn is_header_commitments_agenda_active(
        &self,
        prev_hash: &Hash,
        params: &Params,
    ) -> Result<bool, RuleError> {
        self.is_agenda_active_by_hash(
            prev_hash,
            crate::agendas::VOTE_ID_HEADER_COMMITMENTS,
            params,
        )
    }

    /// The height at which the given deployment last changed state as
    /// of the given block hash (dcrd `StateLastChangedHeight`); zero
    /// when the state has never changed.
    pub fn state_last_changed_height(
        &self,
        hash: &Hash,
        deployment_id: &str,
        params: &Params,
    ) -> Result<i64, RuleError> {
        let node = self.lookup_validatable(hash)?;

        // Determine the deployment details for the provided deployment
        // id.
        let (version, deployment) = crate::agendas::find_deployment(params, deployment_id)
            .ok_or_else(|| {
                rule_error(
                    RuleErrorKind::UnknownDeploymentID,
                    format!("deployment ID {deployment_id} does not exist"),
                )
            })?;
        if !deployment.forced_choice_id.is_empty() {
            // The state change height is 1 since the genesis block
            // never experiences changes regardless of consensus rule
            // changes.
            return Ok(1);
        }

        // Find the height at which the current state changed.
        let view = NodeBranchView {
            store: &self.store,
            tip: node,
        };
        let height = self.store.node(node).height;
        Ok(state_last_changed(&view, height, version, deployment, params).unwrap_or(0))
    }

    /// The vote counts for the deployment over the current rule change
    /// activation interval as of the best chain tip (the walk inside
    /// dcrd `getVoteCounts`).
    fn get_vote_counts_internal(
        &self,
        node: NodeId,
        version: u32,
        deployment: &ConsensusDeployment,
        params: &Params,
    ) -> VoteCounts {
        // Don't try to count votes before the stake validation height
        // since there could not possibly have been any.
        let svh = params.stake_validation_height;
        let mut result = VoteCounts {
            total: 0,
            total_abstain: 0,
            vote_choices: alloc::vec![0u32; deployment.vote.choices.len()],
        };
        let node_height = self.store.node(node).height;
        if node_height < svh {
            return result;
        }

        // Calculate the final height of the prior interval.
        let rcai = i64::from(params.rule_change_activation_interval);
        let height = calc_want_height(svh, rcai, node_height);

        let mut count_node = node;
        while self.store.node(count_node).height > height {
            for vote in &self.store.node(count_node).votes {
                // Wrong versions do not count.
                if vote.0 != version {
                    continue;
                }

                // Increase total votes.
                result.total += 1;

                match deployment.vote.vote_index(vote.1) {
                    None => {
                        // Invalid votes are treated as abstain.
                        result.total_abstain += 1;
                    }
                    Some(index) => {
                        if deployment.vote.choices[index].is_abstain {
                            result.total_abstain += 1;
                        }
                        result.vote_choices[index] += 1;
                    }
                }
            }
            count_node = self
                .store
                .node(count_node)
                .parent
                .expect("above the interval boundary implies a parent");
        }
        result
    }

    /// The vote counts for the specified version and deployment
    /// identifier for the current rule change activation interval
    /// (dcrd `GetVoteCounts`).
    pub fn get_vote_counts(
        &self,
        version: u32,
        deployment_id: &str,
        params: &Params,
    ) -> Result<VoteCounts, RuleError> {
        if let Some((_, deployments)) = params.deployments.iter().find(|(v, _)| *v == version) {
            for deployment in deployments {
                if deployment.vote.id == deployment_id {
                    let tip = self.best_chain.tip().expect("best chain tip");
                    return Ok(self.get_vote_counts_internal(tip, version, deployment, params));
                }
            }
        }
        Err(rule_error(
            RuleErrorKind::UnknownDeploymentID,
            format!("deployment ID {deployment_id} does not exist"),
        ))
    }

    /// The total number of version votes for the current rule change
    /// activation interval as of the best chain tip (dcrd
    /// `CountVoteVersion`).
    pub fn count_vote_version(&self, version: u32, params: &Params) -> u32 {
        let count_tip = self.best_chain.tip().expect("best chain tip");

        // Don't try to count votes before the stake validation height
        // since there could not possibly have been any.
        let svh = params.stake_validation_height;
        let tip_height = self.store.node(count_tip).height;
        if tip_height < svh {
            return 0;
        }

        // Calculate the final height of the prior interval.
        let rcai = i64::from(params.rule_change_activation_interval);
        let height = calc_want_height(svh, rcai, tip_height);

        let mut total: u32 = 0;
        let mut count_node = count_tip;
        while self.store.node(count_node).height > height {
            for vote in &self.store.node(count_node).votes {
                // Wrong versions do not count.
                if vote.0 != version {
                    continue;
                }

                // Increase total votes.
                total += 1;
            }
            count_node = self
                .store
                .node(count_node)
                .parent
                .expect("above the interval boundary implies a parent");
        }
        total
    }

    /// Information on the consensus deployment agendas and their
    /// respective states at the provided hash for the provided
    /// deployment version (dcrd `GetVoteInfo`).
    pub fn get_vote_info(
        &self,
        hash: &Hash,
        version: u32,
        params: &Params,
    ) -> Result<VoteInfo, RuleError> {
        let deployments = params
            .deployments
            .iter()
            .find(|(v, _)| *v == version)
            .map(|(_, d)| d)
            .ok_or_else(|| {
                rule_error(
                    RuleErrorKind::UnknownDeploymentVersion,
                    format!("stake version {version} does not exist"),
                )
            })?;

        let mut vote_info = VoteInfo {
            agendas: Vec::with_capacity(deployments.len()),
            agenda_status: Vec::with_capacity(deployments.len()),
        };
        for deployment in deployments {
            vote_info.agendas.push(deployment.clone());
            let status = self.next_threshold_state(hash, deployment.vote.id, params)?;
            vote_info.agenda_status.push(status);
        }
        Ok(vote_info)
    }

    /// Locate the block after the first known block in the locator
    /// along with the number of subsequent blocks needed, respecting
    /// the stop hash and max entries (dcrd `locateInventory`).
    fn locate_inventory(
        &self,
        locator: &[Hash],
        hash_stop: &Hash,
        max_entries: u32,
    ) -> (Option<NodeId>, u32) {
        // There are no block locators so a specific block is being
        // requested as identified by the stop hash.
        let stop_node = self.index.lookup_node(hash_stop);
        if locator.is_empty() {
            let Some(stop) = stop_node else {
                // No blocks with the stop hash were found so there is
                // nothing to do.
                return (None, 0);
            };
            return (Some(stop), 1);
        }

        // Find the most recent locator block hash in the main chain.
        // In the case none of the hashes in the locator are in the
        // main chain, fall back to the genesis block.
        let mut start_node = self.best_chain.genesis();
        for hash in locator {
            if let Some(node) = self.index.lookup_node(hash)
                && self.best_chain.contains(&self.store, node)
            {
                start_node = Some(node);
                break;
            }
        }

        // Start at the block after the most recently known block.
        // When there is no next block it means the most recently known
        // block is the tip of the best chain, so there is nothing more
        // to do.
        let Some(start_node) = start_node.and_then(|n| self.best_chain.next(&self.store, n)) else {
            return (None, 0);
        };

        // Calculate how many entries are needed.
        let tip = self.best_chain.tip().expect("best chain tip");
        let start_height = self.store.node(start_node).height;
        let mut total = (self.store.node(tip).height - start_height + 1) as u32;
        if let Some(stop) = stop_node
            && self.best_chain.contains(&self.store, stop)
            && self.store.node(stop).height >= start_height
        {
            total = (self.store.node(stop).height - start_height + 1) as u32;
        }
        if total > max_entries {
            total = max_entries;
        }

        (Some(start_node), total)
    }

    /// The hashes of the blocks after the first known block in the
    /// locator until the provided stop hash is reached, or up to the
    /// provided max number of block hashes (dcrd `LocateBlocks`).
    ///
    /// When no locators are provided the stop hash is treated as a
    /// request for that block itself; when none of the locators are
    /// known, hashes starting after the genesis block are returned.
    pub fn locate_blocks(&self, locator: &[Hash], hash_stop: &Hash, max_hashes: u32) -> Vec<Hash> {
        // Find the node after the first known block in the locator and
        // the total number of nodes after it needed while respecting
        // the stop hash and max entries.
        let (mut node, total) = self.locate_inventory(locator, hash_stop, max_hashes);

        // Populate and return the found hashes.
        let mut hashes = Vec::with_capacity(total as usize);
        for _ in 0..total {
            let id = node.expect("the total is bounded by the chain view");
            hashes.push(self.store.node(id).hash);
            node = self.best_chain.next(&self.store, id);
        }
        hashes
    }

    /// The headers of the blocks after the first known block in the
    /// locator until the provided stop hash is reached, or up to
    /// wire's max headers per message (dcrd `LocateHeaders`).
    pub fn locate_headers(&self, locator: &[Hash], hash_stop: &Hash) -> Vec<BlockHeader> {
        let max_headers = dcroxide_wire::MAX_BLOCK_HEADERS_PER_MSG as u32;
        let (mut node, total) = self.locate_inventory(locator, hash_stop, max_headers);

        // Populate and return the found headers.
        let mut headers = Vec::with_capacity(total as usize);
        for _ in 0..total {
            let id = node.expect("the total is bounded by the chain view");
            headers.push(self.store.header(id));
            node = self.best_chain.next(&self.store, id);
        }
        headers
    }

    /// A block locator for the passed block hash, or for the latest
    /// known tip of the best chain when the hash is not known (dcrd
    /// `BlockLocatorFromHash`).
    pub fn block_locator_from_hash(&self, hash: &Hash) -> Vec<Hash> {
        let node = self.index.lookup_node(hash);
        self.best_chain.block_locator(&self.store, node)
    }

    /// The best chain state snapshot (dcrd `BlockChain.BestSnapshot`).
    pub fn best_snapshot(&self) -> &BestState {
        &self.state_snapshot
    }

    /// The stake node at the tip of the best chain, if loaded.
    fn tip_stake_node(&self) -> Option<&StakeNode> {
        let tip = self.best_chain.tip()?;
        self.store.node(tip).stake_node.as_ref()
    }

    /// Whether the ticket exists in the live ticket treap of the best
    /// node (dcrd `BlockChain.CheckLiveTicket`).
    pub fn check_live_ticket(&self, hash: &Hash) -> bool {
        self.tip_stake_node()
            .is_some_and(|sn| sn.exists_live_ticket(hash))
    }

    /// Whether each ticket exists in the live ticket treap of the best
    /// node (dcrd `BlockChain.CheckLiveTickets`).
    pub fn check_live_tickets(&self, hashes: &[Hash]) -> Vec<bool> {
        match self.tip_stake_node() {
            Some(sn) => hashes.iter().map(|h| sn.exists_live_ticket(h)).collect(),
            None => alloc::vec![false; hashes.len()],
        }
    }

    /// All currently live tickets from the best node's stake state
    /// (dcrd `BlockChain.LiveTickets`).
    pub fn live_tickets(&self) -> Vec<Hash> {
        self.tip_stake_node()
            .map(StakeNode::live_tickets)
            .unwrap_or_default()
    }

    /// The value of all the locked funds in the ticket pool, summing
    /// the amount of every live ticket's stake submission output (dcrd
    /// `BlockChain.TicketPoolValue`).  Returns `None` when a live
    /// ticket's utxo is unexpectedly missing, matching dcrd's error.
    ///
    /// dcrd fetches the entries one at a time through its cache
    /// (`stakeext.go:146-154`); the port fetches them as one batch,
    /// with the same per-entry cache semantics, so the cache misses of
    /// a cold call -- the whole live pool, tens of thousands of entries
    /// on mainnet -- share one read transaction instead of opening one
    /// apiece.
    pub fn ticket_pool_value(&self) -> Option<i64> {
        let outpoints: Vec<OutPoint> = self
            .live_tickets()
            .into_iter()
            .map(|hash| OutPoint {
                hash,
                index: 0,
                tree: dcroxide_wire::TX_TREE_STAKE,
            })
            .collect();
        let mut amt: i64 = 0;
        for utxo in self.fetch_utxo_entries(&outpoints) {
            amt += utxo?.amount();
        }
        Some(amt)
    }

    /// The next tickets eligible for voting, the number of tickets in
    /// the ticket pool, and the final state of the lottery PRNG for
    /// the given block, including side chain blocks (dcrd
    /// `BlockChain.LotteryDataForBlock`).  Returns empty data below
    /// stake enabled height and the unknown-block error when the
    /// block is not in the index.
    pub fn lottery_data_for_block(
        &mut self,
        hash: &Hash,
        params: &Params,
    ) -> Result<(Vec<Hash>, usize, [u8; 6]), RuleError> {
        let Some(node) = self.index.lookup_node(hash) else {
            return Err(rule_error(
                RuleErrorKind::UnknownBlock,
                format!("block {hash} is not known"),
            ));
        };
        if self.store.node(node).height < params.stake_enabled_height {
            return Ok((Vec::new(), 0, [0u8; 6]));
        }
        let stake_node = self
            .fetch_stake_node(node, params)
            .map_err(|e| rule_error(RuleErrorKind::UnknownBlock, e.description))?;
        Ok((
            stake_node.winners().to_vec(),
            stake_node.pool_size(),
            stake_node.final_state(),
        ))
    }

    /// The version 2 GCS filter for the given block hash along with a
    /// header commitment inclusion proof, regardless of whether the
    /// block is part of the main chain (dcrd
    /// `BlockChain.FilterByBlockHash`).  A missing filter surfaces as
    /// the no-filter error kind; the filter and commitment leaves are
    /// served from the recent window or the database, and a failed read
    /// or a row that does not decode is the database error dcrd
    /// returns (`headercmt.go:167-183`), never a missing filter or a
    /// proof over no leaves.
    pub fn filter_by_block_hash(&self, hash: &Hash) -> Result<(FilterV2, HeaderProof), RuleError> {
        // Avoid a lookup when there is no way the filter data for the
        // requested block is available.
        let have_data = self
            .index
            .lookup_node(hash)
            .is_some_and(|node| self.index.node_status(&self.store, node).have_data());
        if !have_data {
            return Err(rule_error(
                RuleErrorKind::NoFilter,
                format!("no filter available for block {hash}"),
            ));
        }

        let Some(filter) = self.gcs_filter(hash).map_err(db_read_rule_error)? else {
            return Err(rule_error(
                RuleErrorKind::NoFilter,
                format!("no filter available for block {hash}"),
            ));
        };
        let leaves = self
            .commitments_by_block_hash(hash)
            .map_err(db_read_rule_error)?;

        // Generate the header commitment inclusion proof for the
        // filter.
        let proof = dcroxide_standalone::generate_inclusion_proof(&leaves, HEADER_CMT_FILTER_INDEX);
        Ok((
            filter,
            HeaderProof {
                proof_index: HEADER_CMT_FILTER_INDEX,
                proof_hashes: proof,
            },
        ))
    }

    /// All committed filters between the start and end hashes
    /// (inclusive) prepared as a batched cfilters response (dcrd
    /// `BlockChain.LocateCFiltersV2`).  Both blocks must exist and the
    /// start must be an ancestor of the end; the batch is bounded by
    /// the wire maximum.
    pub fn locate_cfilters_v2(
        &self,
        start_hash: &Hash,
        end_hash: &Hash,
    ) -> Result<dcroxide_wire::MsgCFiltersV2, RuleError> {
        let start_node = self.index.lookup_node(start_hash).ok_or_else(|| {
            rule_error(
                RuleErrorKind::UnknownBlock,
                format!("block {start_hash} is not known"),
            )
        })?;
        let end_node = self.index.lookup_node(end_hash).ok_or_else(|| {
            rule_error(
                RuleErrorKind::UnknownBlock,
                format!("block {end_hash} is not known"),
            )
        })?;
        if !self.store.is_ancestor_of(start_node, end_node) {
            return Err(rule_error(
                RuleErrorKind::NotAnAncestor,
                format!("start block {start_hash} is not an ancestor of end block {end_hash}"),
            ));
        }

        let nb = self.store.node(end_node).height - self.store.node(start_node).height + 1;
        if nb > dcroxide_wire::MAX_CFILTERS_V2_PER_BATCH as i64 {
            return Err(rule_error(
                RuleErrorKind::RequestTooLarge,
                format!(
                    "number of requested cfilters {nb} greater than max allowed {}",
                    dcroxide_wire::MAX_CFILTERS_V2_PER_BATCH
                ),
            ));
        }
        let nb = nb as usize;

        // Fetch the block hashes for the range by walking parents back
        // from the end node.
        let mut hashes = alloc::vec![Hash([0u8; 32]); nb];
        let mut node = Some(end_node);
        for slot in hashes.iter_mut().rev() {
            let id = node.expect("the range is bounded by the ancestor check");
            *slot = self.store.node(id).hash;
            node = self.store.node(id).parent;
        }

        // Build the per-block filter responses with their inclusion
        // proofs.
        let mut cfilters = Vec::with_capacity(nb);
        for hash in &hashes {
            // The recent window or the database, so a pruned range is
            // still served (dcrd reads every filter from its cfilter
            // database).  dcrd serves the stored bytes without decoding
            // them (`dbFetchRawGCSFilter`), but returns a commitments
            // row that fails to read or decode as the error
            // (`headercmt.go:249-268`).
            let Some(filter) = self.raw_gcs_filter(hash).map_err(db_read_rule_error)? else {
                return Err(rule_error(
                    RuleErrorKind::NoFilter,
                    format!("no filter available for block {hash}"),
                ));
            };
            let leaves = self
                .commitments_by_block_hash(hash)
                .map_err(db_read_rule_error)?;
            let proof =
                dcroxide_standalone::generate_inclusion_proof(&leaves, HEADER_CMT_FILTER_INDEX);
            cfilters.push(dcroxide_wire::MsgCFilterV2 {
                block_hash: *hash,
                data: filter,
                proof_index: HEADER_CMT_FILTER_INDEX,
                proof_hashes: proof,
            });
        }

        Ok(dcroxide_wire::MsgCFiltersV2 { cfilters })
    }

    /// Estimate the next stake difficulty by pretending the given
    /// number of tickets will be purchased in the remainder of the
    /// interval, or the maximum possible number when the flag is set
    /// (dcrd `EstimateNextStakeDifficulty`).  dcrd reports the unknown
    /// block through its context error and the excessive ticket counts
    /// through plain errors; both surface here as message strings.
    pub fn estimate_next_stake_difficulty(
        &self,
        hash: &Hash,
        new_tickets: i64,
        use_max_tickets: bool,
        params: &Params,
    ) -> Result<i64, String> {
        let node = self.lookup_validatable(hash).map_err(|e| e.description)?;
        let view = NodeBranchView {
            store: &self.store,
            tip: node,
        };
        let cur_node = crate::difficulty::ChainView::node(&view, self.store.node(node).height);
        crate::agendas::estimate_next_stake_difficulty(
            &view,
            cur_node.as_ref(),
            new_tickets,
            use_max_tickets,
            params,
        )
    }

    /// The treasury balance as of the block after the given node:
    /// the node's stored balance plus the maturing values from the
    /// coinbase-maturity ancestor (dcrd `calculateTreasuryBalance`).
    pub fn calculate_treasury_balance(&self, prev_node: NodeId, params: &Params) -> i64 {
        let relative_maturity = i64::from(params.coinbase_maturity) - 1;
        let Some(want_node) = self.store.relative_ancestor(prev_node, relative_maturity) else {
            return 0;
        };
        // dcrd reads any error from either fetch as a zero balance, not
        // only the missing key.
        let Ok(Some(ts)) = self.treasury_state_row(&self.store.node(prev_node).hash) else {
            return 0;
        };
        let Ok(Some(wts)) = self.treasury_state_row(&self.store.node(want_node).hash) else {
            return 0;
        };
        let mut net_value = 0i64;
        for v in &wts.values {
            net_value += v.amount;
        }
        ts.balance + net_value
    }

    /// The treasury state and spend rows a connected block produces
    /// (dcrd's method forms of `dbPutTreasuryBalance` and `dbPutTSpend`,
    /// up to the point where they write).
    ///
    /// Pure, so the rows can be written inside `connect_block`'s single
    /// transaction and the in-memory mirrors published only once that
    /// transaction commits.  Reading the existing spend list rather than
    /// inserting into it is what keeps the mirror from moving ahead of
    /// the write.
    ///
    /// One divergence follows from that read: a block carrying the same
    /// tspend hash twice yields `[H]` where the mutating form yielded
    /// `[H, H]`.  Consensus cannot produce such a block --
    /// `check_block_sanity` rejects duplicate transactions -- but
    /// [`Self::put_treasury_records`] is public and harnesses drive it
    /// directly.
    fn treasury_records_for_block(
        &self,
        node: NodeId,
        block: &MsgBlock,
        params: &Params,
    ) -> (
        Hash,
        crate::treasurydb::TreasuryState,
        Vec<(Hash, Vec<Hash>)>,
    ) {
        let parent = self.store.node(node).parent.expect("connected parent");
        let balance = self.calculate_treasury_balance(parent, params);
        let ts = crate::treasurydb::treasury_state_for_block(block, balance);
        let block_hash = self.store.node(node).hash;

        let mut tspend_updates: Vec<(Hash, Vec<Hash>)> = Vec::new();
        for stx in &block.stransactions {
            if !dcroxide_stake::is_tspend(stx) {
                continue;
            }
            let tx_hash = stx.tx_hash();
            let mut blocks = self
                .tspend_blocks
                .get(&tx_hash.0)
                .cloned()
                .unwrap_or_default();
            blocks.push(block_hash);
            tspend_updates.push((tx_hash, blocks));
        }

        (block_hash, ts, tspend_updates)
    }

    /// Publish the treasury rows to the in-memory mirrors consensus
    /// reads, after the transaction carrying them has committed.
    fn apply_treasury_records(
        &mut self,
        block_hash: Hash,
        ts: crate::treasurydb::TreasuryState,
        tspend_updates: &[(Hash, Vec<Hash>)],
    ) {
        self.treasury_state.insert(block_hash.0, ts);
        for (tx_hash, blocks) in tspend_updates {
            self.tspend_blocks.insert(tx_hash.0, blocks.clone());
        }
    }

    /// Write the treasury rows for a connected block inside the caller's
    /// transaction (dcrd `connectBlock`'s `dbPutTreasuryBalance` and
    /// `dbPutTSpend` calls, `chain.go:691-703`).
    fn db_write_treasury_records(
        tx: &dcroxide_database::Transaction,
        block_hash: &Hash,
        ts: &crate::treasurydb::TreasuryState,
        tspend_updates: &[(Hash, Vec<Hash>)],
    ) -> Result<(), dcroxide_database::Error> {
        crate::treasurydb::db_put_treasury_balance(tx, block_hash, ts)
            .map_err(chain_db_to_db_error)?;
        for (tx_hash, blocks) in tspend_updates {
            crate::treasurydb::db_put_tspend(tx, tx_hash, blocks).map_err(chain_db_to_db_error)?;
        }
        Ok(())
    }

    /// Record the treasury state and spend rows for a connected block
    /// (dcrd's method forms of `dbPutTreasuryBalance` and
    /// `dbPutTSpend`), writing through to the database when
    /// persistent.
    ///
    /// `connect_block` does not call this: it folds the same rows into
    /// its own transaction so the best state and the treasury cannot
    /// land on opposite sides of a crash.  Kept for the harnesses that
    /// drive the treasury database directly.
    pub fn put_treasury_records(
        &mut self,
        node: NodeId,
        block: &MsgBlock,
        params: &Params,
    ) -> Result<(), RuleError> {
        let (block_hash, ts, tspend_updates) = self.treasury_records_for_block(node, block, params);

        if let Some(db) = &self.db {
            db.update(|tx| Self::db_write_treasury_records(tx, &block_hash, &ts, &tspend_updates))
                .map_err(|e| persist_rule_error(crate::chaindb::ChainDbError::Db(e)))?;
        }
        self.apply_treasury_records(block_hash, ts, &tspend_updates);
        Ok(())
    }

    /// The blocks a treasury spend was mined in (dcrd `FetchTSpend`).
    pub fn fetch_tspend(&self, tspend: &Hash) -> Vec<Hash> {
        self.tspend_blocks
            .get(&tspend.0)
            .cloned()
            .unwrap_or_default()
    }

    /// Verify the treasury spend has not been mined in a block on the
    /// chain of the previous node (dcrd `checkTSpendExists`).
    pub fn check_tspend_exists(&self, prev_node: NodeId, tspend: &Hash) -> Result<(), String> {
        let Some(blocks) = self.tspend_blocks.get(&tspend.0) else {
            return Ok(());
        };
        for block_hash in blocks {
            let Some(node) = self.index.lookup_node(block_hash) else {
                continue;
            };
            if !self.store.is_ancestor_of(node, prev_node) {
                continue;
            }
            return Err(format!(
                "treasury spend has already been mined on this chain {tspend}"
            ));
        }
        Ok(())
    }

    /// Capture a treasury spend's voting window up to the given node
    /// for a tally taken later, possibly with the chain lock released
    /// (the window checks and the node walk of dcrd `tSpendCountVotes`).
    /// The window and inside-window checks run here, before any block
    /// is read, in dcrd's order; see [`TSpendVoteWindow`] for why the
    /// tally itself needs nothing from the chain.
    pub fn tspend_vote_window(
        &self,
        prev_node: NodeId,
        tspend: &MsgTx,
        params: &Params,
    ) -> Result<TSpendVoteWindow, String> {
        let expiry = tspend.expiry;
        let (start, end) = dcroxide_standalone::calc_tspend_window(
            expiry,
            params.treasury_vote_interval,
            params.treasury_vote_interval_multiplier,
        )
        .map_err(|e| format!("{e}"))?;

        let tspend_hash = tspend.tx_hash();
        let next_height = self.store.node(prev_node).height + 1;
        if !dcroxide_standalone::inside_tspend_window(
            next_height,
            expiry,
            params.treasury_vote_interval,
            params.treasury_vote_interval_multiplier,
        ) {
            return Err(format!(
                "treasury spend {tspend_hash} at height {next_height} with expiry {expiry} is \
                 outside of the valid window [{start}, {end}]"
            ));
        }

        // The window's blocks from the node back to the window start,
        // each with the recent window's copy of its body when it holds
        // one (dcrd's `lookupRecentBlock` inside `fetchBlockByNode`).
        let mut blocks = Vec::new();
        let mut node = Some(prev_node);
        while let Some(id) = node {
            let n = self.store.node(id);
            if n.height < i64::from(start) {
                break;
            }
            blocks.push((n.height, n.hash, self.blocks.get(&n.hash.0).map(Arc::clone)));
            node = n.parent;
        }
        Ok(TSpendVoteWindow {
            start,
            end,
            next_height,
            tspend_hash,
            blocks,
            db: self.db.clone(),
        })
    }

    /// Tally the treasury votes for a treasury spend up to the given
    /// node (dcrd `tSpendCountVotes`).  Returns the window start and
    /// end alongside the yes and no counts.
    pub fn tspend_count_votes(
        &self,
        prev_node: NodeId,
        tspend: &MsgTx,
        params: &Params,
    ) -> Result<(u32, u32, u32, u32), String> {
        self.tspend_vote_window(prev_node, tspend, params)?
            .count_votes()
    }

    /// Verify the treasury spend has enough votes to be included in a
    /// block after the given node (dcrd `checkTSpendHasVotes`).
    pub fn check_tspend_has_votes(
        &self,
        prev_node: NodeId,
        tspend: &MsgTx,
        params: &Params,
    ) -> Result<(), String> {
        self.tspend_vote_window(prev_node, tspend, params)?
            .check_has_votes(params)
    }

    /// Sum the debits and credits over the given number of blocks
    /// ending at the node (dcrd `sumPastTreasuryChanges`).  Returns
    /// the spent and added totals along with the node before the
    /// window.
    ///
    /// Only a missing row ends the walk early, as dcrd's `errDbTreasury`
    /// check does; a row that does not decode, or a failed read, is
    /// returned as the error, which `tspend_checks` turns into
    /// `ErrInvalidExpenditure` as dcrd's `tspendChecks` does.  It is
    /// carried as `ErrUtxoBackendCorruption`, the kind the port gives
    /// the other local-corruption errors dcrd returns as plain errors
    /// (see `fetch_spend_journal`).
    fn sum_past_treasury_changes(
        &self,
        pre_tvi_node: NodeId,
        nb_blocks: u64,
    ) -> Result<(i64, i64, Option<NodeId>), RuleError> {
        let mut node = Some(pre_tvi_node);
        let mut spent = 0i64;
        let mut added = 0i64;
        let mut i = 0u64;
        while let Some(id) = node {
            if i >= nb_blocks {
                break;
            }
            let row = self
                .treasury_state_row(&self.store.node(id).hash)
                .map_err(|e| rule_error(RuleErrorKind::UtxoBackendCorruption, e))?;
            let Some(ts) = row else {
                // The record doesn't exist: the end of when treasury
                // records are available.
                node = None;
                break;
            };
            for v in &ts.values {
                if v.typ.is_debit() {
                    spent += -v.amount;
                } else {
                    added += v.amount;
                }
            }
            node = self.store.node(id).parent;
            i += 1;
        }
        Ok((spent, added, node))
    }

    /// The maximum treasury expenditure per the original DCP0006
    /// policy (dcrd `maxTreasuryExpenditureDCP0006`).
    fn max_treasury_expenditure_dcp0006(
        &self,
        pre_tvi_node: NodeId,
        params: &Params,
    ) -> Result<i64, RuleError> {
        let policy_window = params.treasury_vote_interval
            * params.treasury_vote_interval_multiplier
            * params.treasury_expenditure_window;

        let (spent_recent_window, _, mut node) =
            self.sum_past_treasury_changes(pre_tvi_node, policy_window)?;

        let mut spent_prior_windows = 0i64;
        let mut nb_non_empty_windows = 0i64;
        let mut i = 0u64;
        while i < params.treasury_expenditure_policy {
            let Some(id) = node else {
                break;
            };
            let (spent, _, next) = self.sum_past_treasury_changes(id, policy_window)?;
            if spent > 0 {
                spent_prior_windows += spent;
                nb_non_empty_windows += 1;
            }
            node = next;
            i += 1;
        }

        let avg_spent_prior_windows = if nb_non_empty_windows > 0 {
            spent_prior_windows / nb_non_empty_windows
        } else {
            params.treasury_expenditure_bootstrap as i64
        };
        let avg_plus_allowance = avg_spent_prior_windows + avg_spent_prior_windows / 2;
        if avg_plus_allowance > spent_recent_window {
            Ok(avg_plus_allowance - spent_recent_window)
        } else {
            Ok(0)
        }
    }

    /// The maximum treasury expenditure per the DCP0007 reverted
    /// policy (dcrd `maxTreasuryExpenditureDCP0007`).
    fn max_treasury_expenditure_dcp0007(
        &self,
        pre_tvi_node: NodeId,
        params: &Params,
    ) -> Result<i64, RuleError> {
        let policy_window = params.treasury_vote_interval
            * params.treasury_vote_interval_multiplier
            * params.treasury_expenditure_window;
        let (spent_recent, added_recent, _) =
            self.sum_past_treasury_changes(pre_tvi_node, policy_window)?;
        let added_plus_allowance = added_recent + added_recent / 2;
        if added_plus_allowance > spent_recent {
            Ok(added_plus_allowance - spent_recent)
        } else {
            Ok(0)
        }
    }

    /// The maximum treasury expenditure per the DCP0013 policy (dcrd
    /// `maxTreasuryExpenditureDCP0013`).
    fn max_treasury_expenditure_dcp0013(
        &self,
        pre_tvi_node: NodeId,
        params: &Params,
    ) -> Result<i64, RuleError> {
        let policy_window = params.treasury_vote_interval
            * params.treasury_vote_interval_multiplier
            * params.treasury_expenditure_window;
        let (spent_recent, _, _) = self.sum_past_treasury_changes(pre_tvi_node, policy_window)?;
        let treasury_balance = self.calculate_treasury_balance(pre_tvi_node, params);

        let mut max_spendable = (treasury_balance + spent_recent) * 4 / 100;
        if max_spendable < self.treasury_spend_limit_floor {
            max_spendable = self.treasury_spend_limit_floor;
        }
        let mut allowed_to_spend = 0i64;
        if max_spendable > spent_recent {
            allowed_to_spend = max_spendable - spent_recent;
        }
        if allowed_to_spend > treasury_balance {
            allowed_to_spend = treasury_balance;
        }
        Ok(allowed_to_spend)
    }

    /// The maximum treasury expenditure at the block after the node,
    /// selected by the active policy agenda (dcrd
    /// `maxTreasuryExpenditure`).
    pub fn max_treasury_expenditure(
        &self,
        pre_tvi_node: NodeId,
        params: &Params,
    ) -> Result<i64, RuleError> {
        let prev_height = Some(self.store.node(pre_tvi_node).height);
        let view = NodeBranchView {
            store: &self.store,
            tip: pre_tvi_node,
        };
        let dcp0013_active = crate::agendas::is_agenda_active(
            &view,
            prev_height,
            dcroxide_chaincfg::VOTE_ID_MAX_TREASURY_SPEND,
            params,
        )
        .map_err(|_| unknown_deployment_error())?;
        if dcp0013_active {
            return self.max_treasury_expenditure_dcp0013(pre_tvi_node, params);
        }
        let revert_active = crate::agendas::is_agenda_active(
            &view,
            prev_height,
            crate::agendas::VOTE_ID_REVERT_TREASURY_POLICY,
            params,
        )
        .map_err(|_| unknown_deployment_error())?;
        if revert_active {
            return self.max_treasury_expenditure_dcp0007(pre_tvi_node, params);
        }
        self.max_treasury_expenditure_dcp0006(pre_tvi_node, params)
    }

    /// Verify the total treasury spend amount is within the allowed
    /// expenditure for a block extending the node (dcrd
    /// `checkTSpendsExpenditure`).
    pub fn check_tspends_expenditure(
        &self,
        pre_tvi_node: NodeId,
        total_tspend_amount: i64,
        params: &Params,
    ) -> Result<(), String> {
        if total_tspend_amount == 0 {
            return Ok(());
        }
        if total_tspend_amount < 0 {
            return Err(format!(
                "invalid precondition: totalTSpendAmount must not be negative (got \
                 {total_tspend_amount})"
            ));
        }
        let treasury_balance = self.calculate_treasury_balance(pre_tvi_node, params);
        if treasury_balance - total_tspend_amount < 0 {
            return Err(format!(
                "treasury balance may not become negative: balance {treasury_balance} spend \
                 {total_tspend_amount}"
            ));
        }
        let allowed_to_spend = self
            .max_treasury_expenditure(pre_tvi_node, params)
            .map_err(|e| format!("{e}"))?;
        if total_tspend_amount > allowed_to_spend {
            return Err(format!(
                "treasury spend greater than allowed {total_tspend_amount} > {allowed_to_spend}"
            ));
        }
        Ok(())
    }

    /// The complete treasury spend checks for a block on a treasury
    /// vote interval, incl. the duplicate-mine, vote tally, and
    /// expenditure rules the stateless subset defers (dcrd
    /// `tspendChecks`).
    pub fn tspend_checks(
        &self,
        prev_node: NodeId,
        block: &MsgBlock,
        params: &Params,
    ) -> Result<(), RuleError> {
        let block_height = self.store.node(prev_node).height + 1;
        let tvi = params.treasury_vote_interval;
        if !dcroxide_standalone::is_treasury_vote_interval(block_height as u64, tvi) {
            return Ok(());
        }

        let mut total_tspend_amount = 0i64;
        for stx in &block.stransactions {
            if !dcroxide_stake::is_tspend(stx) {
                continue;
            }

            // The expiry window.
            let exp = stx.expiry;
            if !dcroxide_standalone::inside_tspend_window(
                block_height,
                exp,
                tvi,
                params.treasury_vote_interval_multiplier,
            ) {
                return Err(rule_error(
                    RuleErrorKind::InvalidTSpendWindow,
                    format!(
                        "block at height {block_height} contains treasury spend transaction \
                         {} with expiry {exp} that is outside of the valid window",
                        stx.tx_hash()
                    ),
                ));
            }

            // A valid treasury spend always stores the entire amount
            // the treasury is spending in the first input.  It has
            // already been verified to match the commitment value by
            // checkTreasurySpendInputs during the stake tree connect
            // (dcrd 2.2 moved the value-in check there), so here it
            // only accumulates the total while checking for overflow.
            let value_in = stx.tx_in[0].value_in;
            let (sum, ok) =
                crate::checkedmath::AddSigned::add_signed(total_tspend_amount, value_in);
            total_tspend_amount = sum;
            if !ok {
                return Err(rule_error(
                    RuleErrorKind::BadTxOutValue,
                    "total value of all treasury spends overflows accumulator",
                ));
            }

            // The duplicate-mine check.
            if let Err(err) = self.check_tspend_exists(prev_node, &stx.tx_hash()) {
                return Err(rule_error(
                    RuleErrorKind::TSpendExists,
                    format!(
                        "block contains a TSpend transaction ({}) that has been mined in \
                         another block: {err}",
                        stx.tx_hash()
                    ),
                ));
            }

            // The vote tally.
            if let Err(err) = self.check_tspend_has_votes(prev_node, stx, params) {
                return Err(rule_error(
                    RuleErrorKind::NotEnoughTSpendVotes,
                    format!(
                        "block contains a TSpend transaction ({}) that does not have enough \
                         votes: {err}",
                        stx.tx_hash()
                    ),
                ));
            }
        }

        // The aggregate expenditure bound.
        if total_tspend_amount > 0
            && let Err(err) = self.check_tspends_expenditure(prev_node, total_tspend_amount, params)
        {
            return Err(rule_error(
                RuleErrorKind::InvalidExpenditure,
                format!("block contains a TSpend that has an invalid expenditure: {err}"),
            ));
        }
        Ok(())
    }

    /// Whether the node's timestamp is more than 24 hours old
    /// relative to the adjusted time (dcrd `isOldTimestamp`).
    fn is_old_timestamp(&self, node: NodeId, adjusted_time_unix: i64) -> bool {
        const DAY_SECS: i64 = 24 * 60 * 60;
        self.store.node(node).timestamp < adjusted_time_unix - DAY_SECS
    }

    /// Potentially update whether the chain believes it is current,
    /// latching once it becomes so (dcrd `maybeUpdateIsCurrent`).
    pub fn maybe_update_is_current(&mut self, cur_best: NodeId, adjusted_time_unix: i64) {
        if !self.is_current_latch {
            // Not current with less cumulative work than the minimum
            // known work for the network.
            if let Some(min_work) = &self.min_known_work
                && self.store.node(cur_best).work_sum < *min_work
            {
                return;
            }

            // Not current when not synced to the best header.
            let Some(best_header) = self.index.best_header() else {
                return;
            };
            let synced = self.store.node(cur_best).height == self.store.node(best_header).height
                || self.store.is_ancestor_of(best_header, cur_best);
            if !synced {
                return;
            }
        }

        self.is_current_latch = !self.is_old_timestamp(cur_best, adjusted_time_unix);
    }

    /// Whether the chain believes it is current (dcrd `isCurrent`).
    pub fn is_current(&self, cur_best: NodeId, adjusted_time_unix: i64) -> bool {
        self.is_current_latch && !self.is_old_timestamp(cur_best, adjusted_time_unix)
    }

    /// Whether the chain believes it is current, resolved at the best
    /// chain tip (dcrd's exported `IsCurrent`; the adjusted time is
    /// injected rather than read from a time source).
    pub fn is_current_at(&self, adjusted_time_unix: i64) -> bool {
        let tip = self.best_chain.tip().expect("best chain tip");
        self.is_current(tip, adjusted_time_unix)
    }

    /// Potentially update whether the chain believes it is current,
    /// resolved at the best chain tip (dcrd's exported
    /// `MaybeUpdateIsCurrent`).
    pub fn maybe_update_is_current_at(&mut self, adjusted_time_unix: i64) {
        let tip = self.best_chain.tip().expect("best chain tip");
        self.maybe_update_is_current(tip, adjusted_time_unix);
    }

    /// The hash and height of the current best known header, which may
    /// be ahead of the best block during a sync (dcrd `BestHeader`).
    pub fn best_header(&self) -> (Hash, i64) {
        let id = self
            .index
            .best_header()
            .expect("the genesis header always exists");
        let node = self.store.node(id);
        (node.hash, node.height)
    }

    /// Whether the header is known to the chain (dcrd `HaveHeader`).
    pub fn have_header(&self, hash: &Hash) -> bool {
        self.index.lookup_node(hash).is_some()
    }

    /// Whether the block data is available (dcrd `HaveBlock`).
    pub fn have_block(&self, hash: &Hash) -> bool {
        self.index.have_block(&self.store, hash)
    }
}

/// The text [`persist_rule_error`] gives a database error, up to the
/// error's kind: it renders the `ChainDbError` with `{:?}`, so a
/// `dcroxide_database::Error` shows its kind first.
const PERSISTED_DB_ERROR_PREFIX: &str = "chain database failure: Db(Error { kind: ";

/// Convert a persistence failure into a rule error so it flows
/// through the existing error paths (dcrd surfaces these as plain
/// errors).  Public so tests can check [`is_persisted_db_corruption`]
/// against the text this produces.
pub fn persist_rule_error(err: crate::chaindb::ChainDbError) -> RuleError {
    RuleError {
        kind: RuleErrorKind::UnknownBlock,
        description: format!("chain database failure: {err:?}"),
    }
}

/// Convert a failed chain database read -- a block body, filter or
/// header commitments row that cannot be read or does not decode --
/// into the error the rule-error paths return.  dcrd returns these as
/// plain database errors, never rule violations, so they travel as
/// `ErrUtxoBackendCorruption` with the database error's own text, the
/// kind the port gives the other local-corruption errors (see
/// `fetch_spend_journal`).
fn db_read_rule_error(err: crate::chaindb::ChainDbError) -> RuleError {
    rule_error(RuleErrorKind::UtxoBackendCorruption, format!("{err}"))
}

/// Read a stored block from the database (the database half of dcrd
/// `fetchBlockByNode`, `dbFetchBlockByNode` inside a `View`), for
/// [`Chain::db_fetch_stored_block`] and for a [`TSpendVoteWindow`]
/// tallied after the chain lock is released.  With no database the
/// block is reported with the database's "does not exist" text.
fn fetch_stored_block(
    db: Option<&dcroxide_database::Database>,
    hash: &Hash,
) -> Result<MsgBlock, crate::chaindb::ChainDbError> {
    let Some(db) = db else {
        return Err(crate::chaindb::ChainDbError::Db(dcroxide_database::Error {
            kind: dcroxide_database::ErrorKind::BlockNotFound,
            description: format!("block {hash} does not exist"),
        }));
    };
    let mut raw = Vec::new();
    db.view(|tx| {
        raw = tx.fetch_block(hash)?;
        Ok(())
    })?;
    let (block, _) = dcroxide_wire::MsgBlock::from_bytes(&raw)
        .map_err(|e| crate::chaindb::ChainDbError::Corrupt(format!("{e}")))?;
    Ok(block)
}

/// A treasury spend's voting window captured from the chain by
/// [`Chain::tspend_vote_window`]: the window bounds, the window's
/// blocks from the tallying node back to the window start with the
/// recent window's copy of each body it holds, and the database the
/// rest are read from.
///
/// dcrd's exported `TSpendCountVotes` and `CheckTSpendHasVotes` take no
/// `chainLock` (`treasury.go:1090-1102`, `:1155-1161`):
/// `tSpendCountVotes` reads each body through `fetchBlockByNode` under
/// a database `View` only.  The daemon's RPC and mining seams therefore
/// capture this under the chain mutex and read and tally the blocks
/// after releasing it, as `fetch_utxo_stats` does for its backend walk,
/// so a block waiting to connect does not wait for up to TVI x
/// multiplier block reads per treasury spend.  Nothing the tally reads
/// can change under it: block bodies are never rewritten or deleted,
/// and `fetchBlockByNode` does not populate dcrd's recent block cache,
/// so a read after the lock is released returns what one under it
/// would.  The connect path (`tspend_checks`) tallies under the lock,
/// where dcrd also holds `chainLock`.
pub struct TSpendVoteWindow {
    start: u32,
    end: u32,
    /// The height of the block the tally is for, one past the
    /// tallying node.
    next_height: i64,
    tspend_hash: Hash,
    /// Height, hash and the recent window's body, newest first.
    blocks: Vec<(i64, Hash, Option<Arc<MsgBlock>>)>,
    db: Option<dcroxide_database::Database>,
}

impl TSpendVoteWindow {
    /// Tally the yes and no votes for the treasury spend over the
    /// window (the tally loop of dcrd `tSpendCountVotes`).  Returns the
    /// window start and end alongside the yes and no counts.
    pub fn count_votes(&self) -> Result<(u32, u32, u32, u32), String> {
        let tspend_hash = self.tspend_hash;

        // Tally the total number of yes and no votes in the voting
        // window.  dcrd 2.2 guards the tallies against overflow even
        // though the voting window and per-block vote limits make it
        // unreachable in practice.
        let mut total_yes = 0u32;
        let mut total_no = 0u32;
        for (height, hash, recent) in &self.blocks {
            // dcrd returns `fetchBlockByNode`'s error here ("Should not
            // happen", `treasury.go:1026-1030`), and the RPC seam can
            // hand over any indexed header, including one whose body
            // was never stored, so a missing body must not panic.
            let fetched;
            let block = match recent {
                Some(block) => block.as_ref(),
                None => {
                    fetched =
                        fetch_stored_block(self.db.as_ref(), hash).map_err(|e| format!("{e}"))?;
                    &fetched
                }
            };
            for stx in &block.stransactions {
                let Ok(votes) = dcroxide_stake::check_ssgen_votes(stx) else {
                    // Not a stake vote.
                    continue;
                };
                for vote in &votes {
                    if vote.hash != tspend_hash {
                        continue;
                    }
                    match vote.vote {
                        dcroxide_stake::TREASURY_VOTE_YES => {
                            let (sum, ok) =
                                crate::checkedmath::AddUnsigned::add_unsigned(total_yes, 1);
                            total_yes = sum;
                            if !ok {
                                return Err(format!(
                                    "yes vote for treasury spend {tspend_hash} at height \
                                     {height} causes yes count to overflow"
                                ));
                            }
                        }
                        dcroxide_stake::TREASURY_VOTE_NO => {
                            let (sum, ok) =
                                crate::checkedmath::AddUnsigned::add_unsigned(total_no, 1);
                            total_no = sum;
                            if !ok {
                                return Err(format!(
                                    "no vote for treasury spend {tspend_hash} at height \
                                     {height} causes no count to overflow"
                                ));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok((self.start, self.end, total_yes, total_no))
    }

    /// Verify the treasury spend has enough votes to be included in the
    /// block after the tallying node (dcrd `checkTSpendHasVotes`).
    pub fn check_has_votes(&self, params: &Params) -> Result<(), String> {
        let (start, end, yes, no) = self.count_votes()?;

        // Passing criteria are the quorum and required percentages.
        // dcrd computes maxVotes in wrapping u32 before widening.
        let max_votes = u64::from(u32::from(params.tickets_per_block).wrapping_mul(end - start));
        let quorum = max_votes * params.treasury_vote_quorum_multiplier
            / params.treasury_vote_quorum_divisor;
        // Go adds the u32 tallies before widening; mirror the wrapping
        // semantics exactly.
        let num_votes_cast = u64::from(yes.wrapping_add(no));
        if num_votes_cast < quorum {
            return Err(format!(
                "quorum not met: yes {yes} no {no}  quorum {quorum} max {max_votes}"
            ));
        }

        // Treat the maximum remaining votes as possible no votes,
        // enabling early passage only when yes cannot drop below the
        // threshold.
        let cur_block_height = self.next_height as u32;
        let remaining_blocks = end - cur_block_height;
        let max_remaining_votes =
            u64::from(remaining_blocks.wrapping_mul(u32::from(params.tickets_per_block)));
        let required_votes = (num_votes_cast + max_remaining_votes)
            * params.treasury_vote_required_multiplier
            / params.treasury_vote_required_divisor;
        if u64::from(yes) < required_votes {
            return Err(format!(
                "not enough yes votes: yes {yes} no {no} quorum {quorum} max {max_votes} \
                 required {required_votes} maxRemainingVotes {max_remaining_votes}"
            ));
        }
        Ok(())
    }
}

/// Whether the rule error is a database corruption that
/// [`persist_rule_error`] carried: a `dcroxide_database::Error` of kind
/// `Corruption` (dcrd `database.ErrCorruption`), whose kind the rule
/// error keeps only in its rendered text.  The daemon's sync adapter
/// reads it for dcrd's corruption-only `Critical failure` line
/// (netsync `manager.go:1265-1269`, `:1646-1648`).
pub fn is_persisted_db_corruption(err: &RuleError) -> bool {
    err.kind == RuleErrorKind::UnknownBlock
        && err
            .description
            .strip_prefix(PERSISTED_DB_ERROR_PREFIX)
            .is_some_and(|rest| rest.starts_with("Corruption,"))
}

/// Wrap a message as a driver-specific database error for use inside
/// database transaction closures.
fn db_driver_error(description: String) -> dcroxide_database::Error {
    dcroxide_database::Error {
        kind: dcroxide_database::ErrorKind::DriverSpecific,
        description,
    }
}

/// Convert a chain database error into a database error for use
/// inside database transaction closures.
fn chain_db_to_db_error(err: crate::chaindb::ChainDbError) -> dcroxide_database::Error {
    match err {
        crate::chaindb::ChainDbError::Db(err) => err,
        other => db_driver_error(format!("{other:?}")),
    }
}

/// The backend writes a UTXO cache flush makes, borrowed straight out
/// of the cache (the write half of dcrd `UtxoCache.flush`): nothing
/// for unmodified entries or absent markers, a delete for spent ones,
/// and the entry itself otherwise, whose serialization ignores the
/// cache state bits.
fn utxo_flush_rows(
    cache: &BTreeMap<OutPointKey, Option<UtxoEntry>>,
) -> impl Iterator<Item = (OutPoint, Option<&UtxoEntry>)> {
    cache.iter().filter_map(|(key, entry)| {
        let entry = entry.as_ref()?;
        if !entry.is_modified() {
            return None;
        }
        let outpoint = OutPoint {
            hash: Hash(key.0),
            index: key.1,
            tree: key.2,
        };
        Some((outpoint, (!entry.is_spent()).then_some(entry)))
    })
}

/// Convert a stake rule error from the ticket state machine into a
/// chain rule error like dcrd's error pass-through.
///
/// `ErrDatabaseCorrupt` is what the stake-node paths carry a database
/// failure as (a ticket row or block body that cannot be read), which
/// dcrd returns as a plain database error, never a rule violation.  It
/// passes through with its own text as `ErrUtxoBackendCorruption`, the
/// kind the port gives the other local-corruption errors (see
/// `fetch_spend_journal`), so `is_rule_violation` does not blame a peer
/// for it.
fn stake_rule_error(err: dcroxide_stake::RuleError) -> RuleError {
    if err.kind == dcroxide_stake::ErrorKind::DatabaseCorrupt {
        return rule_error(RuleErrorKind::UtxoBackendCorruption, err.description);
    }
    RuleError {
        kind: RuleErrorKind::TicketUnavailable,
        description: format!("stake node error: {err:?}"),
    }
}

fn unknown_deployment_error() -> RuleError {
    RuleError {
        kind: RuleErrorKind::UnknownDeploymentID,
        description: "deployment not defined on this network".into(),
    }
}

/// Run the contextual block checks for an attach candidate over its
/// parent branch (the dcrd `checkBlockContext` call inside the reorg
/// attach loop).
fn check_block_context_for(
    store: &NodeStore,
    parent_id: NodeId,
    block: &MsgBlock,
    parent_stake_node: &StakeNode,
    fast_add: bool,
    params: &Params,
) -> Result<(), RuleError> {
    let parent_view = NodeBranchView {
        store,
        tip: parent_id,
    };
    let prev_height = Some(store.node(parent_id).height);
    crate::validate::check_block_context(
        &parent_view,
        block,
        prev_height,
        fast_add,
        false,
        parent_stake_node.pool_size() as u32,
        parent_stake_node.final_state(),
        Some(parent_stake_node),
        params,
    )
}

/// Cooked per-block stake version information walking backwards from a
/// block (dcrd `StakeVersions`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StakeVersions {
    /// The block hash.
    pub hash: Hash,
    /// The block height.
    pub height: i64,
    /// The block header version.
    pub block_version: i32,
    /// The block header stake version.
    pub stake_version: u32,
    /// The votes in the block as (version, bits) pairs.
    pub votes: Vec<(u32, u16)>,
}

/// Information on consensus deployment agendas and their respective
/// states for a deployment version (dcrd `VoteInfo`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoteInfo {
    /// The agendas for the version.
    pub agendas: Vec<ConsensusDeployment>,
    /// The threshold state of each agenda, index-aligned with
    /// [`Self::agendas`].
    pub agenda_status: Vec<ThresholdStateTuple>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_of(n: u8) -> Hash {
        Hash([n; 32])
    }

    /// dcrd's `recentContextChecks` is an `lru.Set` of
    /// `contextCheckCacheSize` hashes whose `Contains` refreshes a hit.
    #[test]
    fn recent_context_checks_is_a_bounded_lru_set() {
        let mut cache = RecentContextChecks::default();
        for n in 0..CONTEXT_CHECK_CACHE_SIZE as u8 {
            cache.put(hash_of(n));
        }
        // A hit becomes the most recently used, so the next insertion
        // evicts the second-oldest instead.
        assert!(cache.contains(&hash_of(0)));
        cache.put(hash_of(200));
        assert_eq!(cache.hashes.len(), CONTEXT_CHECK_CACHE_SIZE);
        assert!(cache.contains(&hash_of(0)));
        assert!(!cache.contains(&hash_of(1)));
        assert!(cache.contains(&hash_of(200)));

        // Putting a present hash refreshes rather than duplicates it.
        cache.put(hash_of(2));
        assert_eq!(cache.hashes.len(), CONTEXT_CHECK_CACHE_SIZE);
        assert_eq!(cache.hashes.back(), Some(&hash_of(2).0));

        cache.delete(&hash_of(2));
        assert!(!cache.contains(&hash_of(2)));
        assert_eq!(cache.hashes.len(), CONTEXT_CHECK_CACHE_SIZE - 1);
    }

    /// Accepted blocks are recorded as context-checked (dcrd
    /// `process.go:396`, `chain.go:1230`), and invalidating a block
    /// forgets it (`process.go:699`), so it is fully checked again
    /// should it need to be.
    #[test]
    fn accepted_blocks_are_recorded_and_invalidation_forgets_them() {
        let params = dcroxide_chaincfg::regnet_params();
        let mut chain = Chain::new(&params, Hash::ZERO, false);
        let mut now = 0;
        let mut accepted = 0;
        for line in include_str!("../tests/data/fullblock_vectors.txt").lines() {
            let f: Vec<&str> = line.split(' ').collect();
            match f[0] {
                "now" => now = f[1].parse().expect("now"),
                "accept" => {
                    let raw = dcroxide_testutil::unhex(f[4]);
                    let (block, _) = MsgBlock::from_bytes(&raw).expect("block");
                    let (_, errs) = chain.process_block(&block, now, &params);
                    assert!(errs.is_empty(), "{}: {errs:?}", f[1]);
                    accepted += 1;
                    if accepted == 30 {
                        break;
                    }
                }
                _ => {}
            }
        }
        let tip = chain.best_chain.tip().expect("tip");
        let tip_hash = chain.store.node(tip).hash;
        assert!(
            chain.recent_context_checks.hashes.contains(&tip_hash.0),
            "the connected block was not recorded as context-checked"
        );

        let errs = chain.invalidate_block(&tip_hash, now, &params);
        assert!(errs.is_empty(), "{errs:?}");
        assert!(
            !chain.recent_context_checks.hashes.contains(&tip_hash.0),
            "an invalidated block must not skip its context checks"
        );

        // Reconsidering reconnects it, running the checks again since
        // the invalidation cleared its validated status.
        let errs = chain.reconsider_block(&tip_hash, now, &params);
        assert!(errs.is_empty(), "{errs:?}");
        assert_eq!(chain.best_chain.tip(), Some(tip), "the block reconnects");
        assert!(chain.recent_context_checks.hashes.contains(&tip_hash.0));
    }

    /// A database failure on the stake-node paths is local corruption,
    /// which dcrd returns as the ticket database's own error, not a rule
    /// violation a peer could be blamed for (review finding S1-p#2).
    #[test]
    fn stake_database_errors_are_not_rule_violations() {
        let err = stake_rule_error(dcroxide_stake::RuleError {
            kind: dcroxide_stake::ErrorKind::DatabaseCorrupt,
            description: "missing key for block undo data".into(),
        });
        assert_eq!(err.kind, RuleErrorKind::UtxoBackendCorruption);
        assert!(!err.kind.is_rule_violation());
        assert_eq!(err.description, "missing key for block undo data");
    }

    /// Connecting blocks prunes the cached chain tips at most once per
    /// `cachedTipsPruneInterval`, relative to the block just connected
    /// (dcrd `connectBlock` calling `MaybePruneCachedTips`,
    /// `chain.go:747`).  The port pruned only at load and on reconsider,
    /// so the cached tips never moved past the startup height (review
    /// finding B7-c#4).
    #[test]
    fn connecting_blocks_prunes_the_cached_tips_on_the_interval() {
        use crate::blockindex::CACHED_TIPS_PRUNE_DEPTH;

        let params = dcroxide_chaincfg::regnet_params();
        let mut chain = Chain::new(&params, Hash::ZERO, false);
        let mut now = 0;
        let blocks: Vec<MsgBlock> = include_str!("../tests/data/fullblock_vectors.txt")
            .lines()
            .filter_map(|line| {
                let f: Vec<&str> = line.split(' ').collect();
                match f[0] {
                    "now" => {
                        now = f[1].parse().expect("now");
                        None
                    }
                    "accept" => Some(
                        MsgBlock::from_bytes(&dcroxide_testutil::unhex(f[4]))
                            .expect("block")
                            .0,
                    ),
                    _ => None,
                }
            })
            .collect();
        let mut blocks = blocks.iter();
        // Process blocks at the clock until one moves the tip, returning
        // the new tip's height.
        let mut connect_one = |chain: &mut Chain, clock: i64| loop {
            let before = chain.best_chain.tip();
            let block = blocks.next().expect("the battery has blocks left");
            let (_, errs) = chain.process_block(block, clock, &params);
            let is_orphan = errs.len() == 1 && errs[0].kind == RuleErrorKind::MissingParent;
            assert!(errs.is_empty() || is_orphan, "{errs:?}");
            let tip = chain.best_chain.tip();
            if tip != before {
                return chain.store.node(tip.expect("tip")).height;
            }
        };

        // The first connect only stamps the clock, and nothing prunes
        // within the interval.
        for _ in 0..40 {
            connect_one(&mut chain, now);
        }
        assert_eq!(chain.index.cached_tips_start(), 0, "pruned too early");

        // A connect one interval on prunes relative to its block.
        let later = now + CACHED_TIPS_PRUNE_INTERVAL_SECS;
        let height = connect_one(&mut chain, later);
        assert!(height > CACHED_TIPS_PRUNE_DEPTH, "the chain is deep enough");
        assert_eq!(
            chain.index.cached_tips_start(),
            height - CACHED_TIPS_PRUNE_DEPTH,
            "the cached tips were not pruned after the interval"
        );

        // Not again until another interval has passed.
        for _ in 0..3 {
            connect_one(&mut chain, later + CACHED_TIPS_PRUNE_INTERVAL_SECS - 1);
        }
        assert_eq!(
            chain.index.cached_tips_start(),
            height - CACHED_TIPS_PRUNE_DEPTH,
            "pruned again within the interval"
        );
        let height = connect_one(&mut chain, later + CACHED_TIPS_PRUNE_INTERVAL_SECS);
        assert_eq!(
            chain.index.cached_tips_start(),
            height - CACHED_TIPS_PRUNE_DEPTH
        );
    }

    /// A block that extends the tip is attached, and announced, as the
    /// `blocks` mirror's own copy, together with its parent's, not as
    /// fresh copies of either: dcrd shares one `*dcrutil.Block` from its
    /// recent block cache and reuses the fork block as the first
    /// parent (`chain.go:1146-1178`).  The port deep-copied both out of
    /// the mirror for every connect (review finding B2-p#4).
    #[test]
    fn connecting_a_block_shares_the_mirrored_block_and_parent() {
        type Connected = Vec<(Arc<MsgBlock>, Arc<MsgBlock>)>;

        let params = dcroxide_chaincfg::regnet_params();
        let mut chain = Chain::new(&params, Hash::ZERO, false);
        let connected: Arc<std::sync::Mutex<Connected>> = Arc::default();
        let sink = Arc::clone(&connected);
        chain.set_notification_callback(Box::new(move |ntfn| {
            if let Notification::BlockConnected(data) = ntfn {
                sink.lock()
                    .expect("sink")
                    .push((Arc::clone(&data.block), Arc::clone(&data.parent_block)));
            }
        }));

        let mut now = 0;
        let mut checked = 0;
        for line in include_str!("../tests/data/fullblock_vectors.txt").lines() {
            let f: Vec<&str> = line.split(' ').collect();
            match f[0] {
                "now" => now = f[1].parse().expect("now"),
                "accept" => {
                    let (block, _) =
                        MsgBlock::from_bytes(&dcroxide_testutil::unhex(f[4])).expect("block");
                    let before = chain.best_chain.tip();
                    let (_, errs) = chain.process_block(&block, now, &params);
                    assert!(errs.is_empty(), "{}: {errs:?}", f[1]);
                    let last = core::mem::take(&mut *connected.lock().expect("connected")).pop();
                    let tip = chain.best_chain.tip().expect("tip");
                    if chain.store.node(tip).parent != before {
                        continue;
                    }
                    let parent = before.expect("parent");
                    let (block_arc, parent_arc) = last.expect("a connect notification");
                    let mirrored = |id: NodeId| &chain.blocks[&chain.store.node(id).hash.0];
                    assert!(
                        Arc::ptr_eq(&block_arc, mirrored(tip)),
                        "{}: the connected block is a copy of the mirror's",
                        f[1]
                    );
                    assert!(
                        Arc::ptr_eq(&parent_arc, mirrored(parent)),
                        "{}: the connected block's parent is a copy of the mirror's",
                        f[1]
                    );
                    checked += 1;
                    if checked == 20 {
                        break;
                    }
                }
                _ => {}
            }
        }
        assert_eq!(checked, 20, "the battery extends the tip often enough");
    }

    /// `prune_chain_memory` is `pub`, and on a chain without a database
    /// the recent-window mirrors are the only copy of the bodies, spend
    /// journal rows and ticket rows, so it leaves them and clears only
    /// the stake fields.  A reorganization across the pruned blocks
    /// then still finds all of them (review finding B2-c#6).
    #[test]
    fn pruning_a_memory_only_chain_keeps_what_a_reorg_needs() {
        let params = dcroxide_chaincfg::regnet_params();
        let mut chain = Chain::new(&params, Hash::ZERO, false);
        let mut now = 0;
        let mut bf4 = None;
        for line in include_str!("../tests/data/fullblock_vectors.txt").lines() {
            let f: Vec<&str> = line.split(' ').collect();
            match f[0] {
                "now" => now = f[1].parse().expect("now"),
                "accept" => {
                    let (block, _) =
                        MsgBlock::from_bytes(&dcroxide_testutil::unhex(f[4])).expect("block");
                    if f[1] == "bf4" {
                        bf4 = Some(block);
                        break;
                    }
                    let (_, errs) = chain.process_block(&block, now, &params);
                    assert!(errs.is_empty(), "{}: {errs:?}", f[1]);
                }
                _ => {}
            }
        }
        let bf4 = bf4.expect("bf4 in the battery");

        // Everything below the tip leaves memory on a chain with a
        // database; here only the stake fields may go.
        chain.prune_chain_memory(1);
        let tip = chain.best_chain.tip().expect("tip");
        let fork = chain.store.node(tip).parent.expect("fork");
        assert!(chain.store.node(fork).stake_node.is_none());
        let fork_hash = chain.store.node(fork).hash;
        assert!(chain.blocks.contains_key(&fork_hash.0));
        assert!(chain.spend_journal.contains_key(&fork_hash.0));

        // `bf4` extends the side branch off the fork past the tip, so
        // the tip is detached against the fork block.
        let (_, errs) = chain.process_block(&bf4, now, &params);
        assert!(errs.is_empty(), "{errs:?}");
        let tip = chain.best_chain.tip().expect("tip");
        assert_eq!(chain.store.node(tip).hash, bf4.header.block_hash());
    }

    /// `height_range` is dcrd's half-open `[start, end)` range capped at
    /// the best chain height, and a negative start or an end below the
    /// start is dcrd's plain error with its text rather than an empty
    /// list (`chain.go:1782-1823`; review finding B3-p#8).
    #[test]
    fn height_range_is_half_open_and_rejects_dcrd_argument_errors() {
        let params = dcroxide_chaincfg::regnet_params();
        let chain = Chain::new(&params, Hash::ZERO, false);
        let genesis = chain.store.node(chain.best_chain.tip().expect("tip")).hash;

        assert_eq!(
            chain.height_range(-1, 0),
            Err(String::from(
                "start height of fetch range must not be less than zero - got -1"
            ))
        );
        assert_eq!(
            chain.height_range(2, 1),
            Err(String::from(
                "end height of fetch range must not be less than the start height - got start \
                 2, end 1"
            ))
        );
        assert_eq!(chain.height_range(0, 0), Ok(Vec::new()));
        // Exclusive of the end, and capped at the tip.
        assert_eq!(chain.height_range(0, 1), Ok(alloc::vec![genesis]));
        assert_eq!(chain.height_range(0, 5), Ok(alloc::vec![genesis]));
        assert_eq!(chain.height_range(1, 5), Ok(Vec::new()));
    }
}
