// SPDX-License-Identifier: ISC

//! Headers-first chain processing from dcrd's
//! `internal/blockchain/process.go`: accepting block headers to the
//! block index with full context-free and positional validation, the
//! known-invalid short circuits, and the assumed-valid and old fork
//! rejection checkpoint tracking.  The full block processing path
//! (`ProcessBlock` and the reorganization machinery it drives)
//! arrives with the chain engine.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

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
    BlockAcceptedNtfnsData, BlockConnectedNtfnsData, BlockDisconnectedNtfnsData, Notification,
    NotificationCallback, ReorganizationNtfnsData, TicketNotificationsData,
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

/// A stats fold row: the serialized outpoint key the fold orders by,
/// the serialized entry, its amount, and its transaction hash.
type UtxoStatsRow = (Vec<u8>, Vec<u8>, i64, [u8; 32]);

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

/// The growing chain state: the block tree arena and index together
/// with the header-processing configuration (the subset of dcrd's
/// `BlockChain` struct the headers-first path reads).  dcrd's
/// database flushes, locks, and notification plumbing are not
/// reproduced; index persistence arrives with the engine wiring.
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
    /// Full block data by block hash: the in-memory stand-in for
    /// dcrd's database block storage and recent block cache until the
    /// persistence wiring lands.
    pub blocks: BTreeMap<[u8; 32], MsgBlock>,
    /// Per-height ticket undo data for main chain blocks: the
    /// in-memory stand-in for dcrd's ticket database undo rows
    /// (written by `WriteConnectedBestNode`).
    pub stake_undo: BTreeMap<i64, Vec<UndoTicketData>>,
    /// Per-height maturing ticket hashes for main chain blocks: the
    /// in-memory stand-in for dcrd's ticket database new tickets
    /// rows.
    pub stake_new_tickets: BTreeMap<i64, Vec<dcroxide_chainhash::Hash>>,

    /// The flushed UTXO set by outpoint: the in-memory stand-in for
    /// dcrd's utxo backend until the persistence wiring lands.
    pub utxo_backend: BTreeMap<OutPointKey, UtxoEntry>,
    /// The UTXO cache overlay with dcrd's exact semantics: fresh
    /// entries have never been flushed, spent non-fresh entries are
    /// retained as tombstones until the next flush, and an explicit
    /// `None` marks an output known to be spent whose backing entry
    /// was never flushed.  These distinctions are observable through
    /// the entry fields that survive reorganizations.
    pub utxo_cache: BTreeMap<OutPointKey, Option<UtxoEntry>>,
    /// The transaction spend journal by block hash, in dcrd's
    /// serialized journal format: the in-memory stand-in for dcrd's
    /// spend journal bucket.  The serialization is deliberately round
    /// tripped because dcrd reconstructs the spent entries' heights
    /// and indexes from the spending inputs' fraud proofs on load.
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
    /// Whether the chain has latched to believing it is current.
    pub is_current_latch: bool,
    /// The minimum known cumulative chain work from the parameters.
    pub min_known_work: Option<Uint256>,
    /// The backing database when the chain is persistent.
    pub db: Option<dcroxide_database::Database>,
    /// The treasury state rows by block hash: the in-memory mirror of
    /// dcrd's treasury bucket.
    pub treasury_state: BTreeMap<[u8; 32], crate::treasurydb::TreasuryState>,
    /// The blocks each treasury spend was mined in: the in-memory
    /// mirror of dcrd's tspend bucket.
    pub tspend_blocks: BTreeMap<[u8; 32], Vec<Hash>>,
    /// The floor for treasury expenditure limits per DCP0013.
    pub treasury_spend_limit_floor: i64,
    /// The chain event callback (dcrd `BlockChain.notifications`);
    /// invoked synchronously from the processing paths when installed.
    notifications: Option<crate::notifications::NotificationCallback>,
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
            params.genesis_block.clone(),
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
            block_size: genesis_block.serialize().len() as u64,
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
            utxo_cache: BTreeMap::new(),
            spend_journal: BTreeMap::new(),
            filters,
            header_commitments: BTreeMap::new(),
            state_snapshot,
            bulk_import_mode: false,
            is_current_latch: false,
            min_known_work: params.min_known_chain_work,
            db: None,
            treasury_state: BTreeMap::new(),
            tspend_blocks: BTreeMap::new(),
            treasury_spend_limit_floor: (params.base_subsidy / 10)
                * (params.treasury_vote_interval * params.treasury_vote_interval_multiplier) as i64,
            notifications: None,
        }
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

    /// Whether the node is an ancestor of (or is) the target (dcrd
    /// `blockNode.IsAncestorOf`).
    fn is_ancestor_of(&self, node: NodeId, target: NodeId) -> bool {
        let node_height = self.store.node(node).height;
        let target_height = self.store.node(target).height;
        if target_height < node_height {
            return false;
        }
        self.store
            .relative_ancestor(target, target_height - node_height)
            == Some(node)
    }

    /// Open a persistent chain over the database, creating the
    /// initial chain state when the database is fresh and loading the
    /// block index, best chain state, stake node, and chain data
    /// otherwise (dcrd `createChainState`/`initChainState`; the
    /// legacy version migration and `upgradeDB` paths are not
    /// applicable to dcroxide's fresh-sync databases).
    pub fn open(
        db: dcroxide_database::Database,
        params: &Params,
        config_assume_valid: Hash,
        config_allow_old_forks: bool,
        created_unix: u64,
    ) -> Result<Chain, crate::chaindb::ChainDbError> {
        use crate::chaindb;

        let mut chain = Chain::new(params, config_assume_valid, config_allow_old_forks);

        // Determine the state of the database.
        let mut db_info: Option<chaindb::DatabaseInfo> = None;
        db.view(|tx| {
            db_info = chaindb::db_fetch_database_info(tx).ok().flatten();
            Ok(())
        })?;

        if let Some(info) = &db_info
            && info.version > chaindb::CURRENT_DATABASE_VERSION
        {
            return Err(chaindb::ChainDbError::Corrupt(format!(
                "the database is no longer compatible ({} > {})",
                info.version,
                chaindb::CURRENT_DATABASE_VERSION
            )));
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
            return Ok(chain);
        }

        // Load the chain state (dcrd `initChainState`).
        let mut load_err: Option<chaindb::ChainDbError> = None;
        db.view(|tx| {
            if let Err(err) = chain.load_chain_state(tx, params) {
                load_err = Some(err);
            }
            Ok(())
        })?;
        if let Some(err) = load_err {
            return Err(err);
        }
        chain.db = Some(db);
        Ok(chain)
    }

    /// Load the block index, best chain state, stake node, and chain
    /// data from the database transaction (the body of dcrd
    /// `initChainState` after initialization is known to have
    /// happened).
    fn load_chain_state(
        &mut self,
        tx: &dcroxide_database::Transaction,
        params: &Params,
    ) -> Result<(), crate::chaindb::ChainDbError> {
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

        // Load the block index in height order.
        let entries = chaindb::db_load_block_index(tx)?;
        let genesis_hash = params.genesis_block.header.block_hash();
        for (i, entry) in entries.iter().enumerate() {
            let block_hash = entry.header.block_hash();
            if i == 0 {
                // The first entry is the genesis block, which the
                // constructor already created; update its status.
                if block_hash != genesis_hash {
                    return Err(chaindb::ChainDbError::Corrupt(
                        "expected first block index entry to be the genesis block".into(),
                    ));
                }
                continue;
            }
            let parent = self
                .index
                .lookup_node(&entry.header.prev_block)
                .ok_or_else(|| {
                    chaindb::ChainDbError::Corrupt(format!(
                        "could not find parent for block {block_hash}"
                    ))
                })?;
            let node = self.store.new_node(&entry.header, Some(parent));
            {
                let n = self.store.node_mut(node);
                n.status = crate::blockindex::BlockStatus(entry.status);
                n.votes = entry.vote_info.clone();
                n.ticket_info_populated = crate::blockindex::BlockStatus(entry.status).have_data();
            }

            // Unmark blocks that failed validation before newly
            // detected consensus rules took effect.
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
        }
        if cur_version != 0 && cur_version != prev_version {
            // dcrd updates the stored version here; deferred to the
            // caller's update transaction via flush.
        }

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

        // Load the blocks for every node with data, the spend
        // journals, filters, commitments, ticket rows, and the UTXO
        // set into the in-memory maps (the disk-backed lazy access is
        // an optimization that arrives later).
        let node_ids: Vec<NodeId> = {
            let mut ids = Vec::new();
            let _ = self.index.for_each_chain_tip(|t| -> Result<(), ()> {
                let mut n = Some(t);
                while let Some(id) = n {
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
            self.blocks.insert(hash.0, block);

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
        }

        // The per-height ticket database rows.
        let meta = tx.metadata();
        if let Some(bucket) =
            meta.bucket(dcroxide_stake::ticketdb::STAKE_BLOCK_UNDO_DATA_BUCKET_NAME)
        {
            let mut rows: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            bucket.for_each(|k, v| {
                rows.push((k.to_vec(), v.to_vec()));
                Ok(())
            })?;
            for (k, v) in rows {
                if k.len() == 4 {
                    let height = i64::from(u32::from_le_bytes([k[0], k[1], k[2], k[3]]));
                    let utds =
                        dcroxide_stake::ticketdb::deserialize_block_undo_data(&v).map_err(|e| {
                            crate::chaindb::ChainDbError::Corrupt(format!("undo: {e:?}"))
                        })?;
                    self.stake_undo.insert(height, utds);
                }
            }
        }
        if let Some(bucket) = meta.bucket(dcroxide_stake::ticketdb::TICKETS_IN_BLOCK_BUCKET_NAME) {
            let mut rows: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            bucket.for_each(|k, v| {
                rows.push((k.to_vec(), v.to_vec()));
                Ok(())
            })?;
            for (k, v) in rows {
                if k.len() == 4 {
                    let height = i64::from(u32::from_le_bytes([k[0], k[1], k[2], k[3]]));
                    let ths =
                        dcroxide_stake::ticketdb::deserialize_ticket_hashes(&v).map_err(|e| {
                            crate::chaindb::ChainDbError::Corrupt(format!("tickets: {e:?}"))
                        })?;
                    self.stake_new_tickets.insert(height, ths);
                }
            }
        }

        // The treasury account and spend rows.
        if let Some(bucket) = meta.bucket(crate::chaindb::TREASURY_BUCKET_NAME) {
            let mut rows: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            bucket.for_each(|k, v| {
                rows.push((k.to_vec(), v.to_vec()));
                Ok(())
            })?;
            for (k, v) in rows {
                if k.len() == 32 {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&k);
                    let ts = crate::treasurydb::deserialize_treasury_state(&v)
                        .map_err(crate::chaindb::ChainDbError::Corrupt)?;
                    self.treasury_state.insert(hash, ts);
                }
            }
        }
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

        // The UTXO set.
        for (outpoint, entry) in crate::chaindb::db_load_utxo_set(tx)? {
            self.utxo_backend
                .insert((outpoint.hash.0, outpoint.index, outpoint.tree), entry);
        }

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
            block_size: tip_block.serialize().len() as u64,
            num_txns: tip_block.transactions.len() as u64,
            total_txns: state.total_txns,
            median_time: self.store.calc_past_median_time(tip),
            total_subsidy: state.total_subsidy,
            next_expiring_tickets: stake_node.expiring_next_block(),
            next_winning_tickets: stake_node.winners().to_vec(),
            missed_tickets: stake_node.missed_tickets(),
            next_final_state: stake_node.final_state(),
        };
        Ok(())
    }

    /// Flush the durable chain state: the modified block index rows,
    /// the UTXO cache, its set state, and the best chain state (the
    /// clean-shutdown flush dcrd performs).
    pub fn flush(&mut self, params: &Params) -> Result<(), crate::chaindb::ChainDbError> {
        if self.db.is_none() {
            return Ok(());
        }
        self.flush_block_index(params)?;
        self.flush_utxo_cache();
        let tip = self.best_chain.tip().expect("best chain tip");
        let (tip_hash, tip_height, work_sum) = {
            let n = self.store.node(tip);
            (n.hash, n.height, n.work_sum)
        };
        let snapshot = self.state_snapshot.clone();
        let db = self.db.as_ref().expect("checked above");
        db.update(|tx| {
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
        Ok(())
    }

    /// Write the modified block index entries to the database,
    /// populating pruned ticket info first (dcrd `flushBlockIndex`).
    fn flush_block_index(&mut self, params: &Params) -> Result<(), crate::chaindb::ChainDbError> {
        if self.db.is_none() {
            return Ok(());
        }
        let modified = self.index.take_modified();
        // Populate prunable ticket info for nodes with data available.
        for &id in &modified {
            let n = self.store.node(id);
            if n.status.have_data()
                && !n.ticket_info_populated
                && self.blocks.contains_key(&n.hash.0)
            {
                self.maybe_fetch_ticket_info(id, params);
            }
        }
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

    /// Apply the view's committed changes to the UTXO cache with dcrd
    /// `UtxoCache.Commit` semantics: spent view entries go through
    /// the spend bookkeeping and everything else is added or updated.
    pub fn commit_view(&mut self, view: &mut UtxoView) {
        for (key, entry) in view.commit() {
            if entry.is_spent() {
                Self::cache_spend_entry(&self.utxo_backend, &mut self.utxo_cache, key);
            } else {
                Self::cache_add_entry(&mut self.utxo_cache, key, entry);
            }
        }
    }

    /// Add or update an unspent entry in the cache (dcrd
    /// `UtxoCache.addEntry`): new-to-cache entries are marked fresh
    /// and updates preserve the existing freshness.
    fn cache_add_entry(
        cache: &mut BTreeMap<OutPointKey, Option<UtxoEntry>>,
        key: OutPointKey,
        mut entry: UtxoEntry,
    ) {
        entry.set_state_bits(entry.state_bits() | crate::utxoentry::UTXO_STATE_MODIFIED);
        match cache.get(&key) {
            Some(Some(existing)) => {
                if existing.is_fresh() {
                    entry.set_state_bits(entry.state_bits() | crate::utxoentry::UTXO_STATE_FRESH);
                }
            }
            // Both a missing entry and an explicit spent marker mean
            // the backend has never seen this output.
            _ => {
                entry.set_state_bits(entry.state_bits() | crate::utxoentry::UTXO_STATE_FRESH);
            }
        }
        cache.insert(key, Some(entry));
    }

    /// Spend an output in the cache (dcrd `UtxoCache.spendEntry`):
    /// fresh entries are replaced with an explicit spent marker since
    /// the backend never knew about them, other cached entries become
    /// spent tombstones, and cache misses pull the backend entry in
    /// as a tombstone so the next flush removes it.
    fn cache_spend_entry(
        backend: &BTreeMap<OutPointKey, UtxoEntry>,
        cache: &mut BTreeMap<OutPointKey, Option<UtxoEntry>>,
        key: OutPointKey,
    ) {
        match cache.get_mut(&key) {
            Some(None) => {}
            Some(Some(entry)) => {
                assert!(!entry.is_spent(), "attempt to double spend in view commit");
                if entry.is_fresh() {
                    cache.insert(key, None);
                } else {
                    entry.set_state_bits(
                        entry.state_bits()
                            | crate::utxoentry::UTXO_STATE_SPENT
                            | crate::utxoentry::UTXO_STATE_MODIFIED,
                    );
                }
            }
            None => {
                if let Some(backend_entry) = backend.get(&key) {
                    let mut entry = backend_entry.clone();
                    entry.set_state_bits(
                        entry.state_bits()
                            | crate::utxoentry::UTXO_STATE_SPENT
                            | crate::utxoentry::UTXO_STATE_MODIFIED,
                    );
                    cache.insert(key, Some(entry));
                }
            }
        }
    }

    /// Flush the cache to the backend (dcrd `UtxoCache.MaybeFlush`
    /// when forced): spent tombstones delete their backend rows,
    /// unspent entries are written with the cache state cleared, and
    /// the cache empties.
    fn flush_utxo_cache(&mut self) {
        let cache = core::mem::take(&mut self.utxo_cache);
        let mut db_updates: Vec<(OutPoint, Option<UtxoEntry>)> = Vec::new();
        for (key, entry) in cache {
            let outpoint = OutPoint {
                hash: Hash(key.0),
                index: key.1,
                tree: key.2,
            };
            match entry {
                None => {}
                Some(entry) if entry.is_spent() => {
                    self.utxo_backend.remove(&key);
                    db_updates.push((outpoint, None));
                }
                Some(mut entry) => {
                    entry.set_state_bits(0);
                    db_updates.push((outpoint, Some(entry.clone())));
                    self.utxo_backend.insert(key, entry);
                }
            }
        }
        if let Some(db) = &self.db {
            db.update(|tx| {
                for (outpoint, entry) in &db_updates {
                    crate::chaindb::db_put_utxo(tx, outpoint, entry.as_ref())
                        .map_err(chain_db_to_db_error)?;
                }
                Ok(())
            })
            .expect("utxo flush");
        }
    }

    /// Fetch an entry through the cache and backend (dcrd
    /// `UtxoCache.FetchEntry` semantics; spent tombstones are
    /// returned like dcrd's cache hands them to views, which is what
    /// preserves original entry fields across disconnects).
    pub fn fetch_utxo_entry(&self, op: &OutPoint) -> Option<UtxoEntry> {
        Self::cache_fetch(&self.utxo_backend, &self.utxo_cache, op)
    }

    /// Statistics on the current UTXO set (dcrd
    /// `BlockChain.FetchUtxoStats`).  The cache is flushed first, and
    /// the utxo set state is written for the current tip, exactly as
    /// dcrd's forced cache flush does before its backend computes the
    /// stats over the full set.
    pub fn fetch_utxo_stats(&mut self) -> Result<UtxoStats, crate::chaindb::ChainDbError> {
        self.flush_utxo_cache();
        if let Some(db) = &self.db {
            let tip = self.best_chain.tip().expect("best chain tip");
            let (tip_hash, tip_height) = {
                let n = self.store.node(tip);
                (n.hash, n.height)
            };
            db.update(|tx| {
                crate::chaindb::db_put_utxo_set_state(
                    tx,
                    &crate::utxoio::UtxoSetState {
                        last_flush_height: tip_height as u32,
                        last_flush_hash: tip_hash,
                    },
                )
                .map_err(chain_db_to_db_error)?;
                Ok(())
            })?;
        }

        // dcrd's backend iterates the set by serialized key bytes;
        // the VLQ-coded output index makes that order diverge from
        // numeric order across VLQ length boundaries, so sort by the
        // serialized keys rather than trusting the in-memory map's
        // tuple order.
        let mut rows: Vec<UtxoStatsRow> = Vec::with_capacity(self.utxo_backend.len());
        for (key, entry) in &self.utxo_backend {
            let outpoint = OutPoint {
                hash: Hash(key.0),
                index: key.1,
                tree: key.2,
            };
            let serialized = crate::utxoio::serialize_utxo_entry(entry)
                .expect("the utxo backend never holds spent entries");
            rows.push((
                crate::utxoio::outpoint_key(&outpoint),
                serialized,
                entry.amount(),
                key.0,
            ));
        }
        rows.sort_by(|a, b| a.0.cmp(&b.0));

        let mut stats = UtxoStats {
            utxos: 0,
            transactions: 0,
            size: 0,
            total: 0,
            serialized_hash: Hash::ZERO,
        };
        let mut transactions: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut leaves: Vec<Hash> = Vec::with_capacity(rows.len());
        for (_, serialized, amount, tx_hash) in rows {
            stats.utxos += 1;
            stats.size += serialized.len() as i64;
            transactions.insert(tx_hash);
            leaves.push(dcroxide_chainhash::hash_h(&serialized));
            stats.total += amount;
        }
        stats.serialized_hash = dcroxide_standalone::calc_merkle_root_in_place(&mut leaves);
        stats.transactions = transactions.len() as i64;
        Ok(stats)
    }

    fn cache_fetch(
        backend: &BTreeMap<OutPointKey, UtxoEntry>,
        cache: &BTreeMap<OutPointKey, Option<UtxoEntry>>,
        op: &OutPoint,
    ) -> Option<UtxoEntry> {
        let key = (op.hash.0, op.index, op.tree);
        match cache.get(&key) {
            Some(entry) => entry.clone(),
            None => backend.get(&key).cloned(),
        }
    }

    /// The spent txouts for the block from the spend journal,
    /// reconstructing the fraud proof fields from the block's
    /// spending inputs (dcrd `dbFetchSpendJournalEntry`).
    pub fn fetch_spend_journal(
        &self,
        block: &MsgBlock,
        is_treasury_enabled: bool,
    ) -> Vec<SpentTxOut> {
        let serialized = self
            .spend_journal
            .get(&block.header.block_hash().0)
            .cloned()
            .unwrap_or_default();

        let mut block_txns: Vec<MsgTx> = Vec::new();
        if !block.stransactions.is_empty() && is_treasury_enabled {
            // Skip the treasurybase and remove treasury spends.
            for stx in &block.stransactions[1..] {
                if dcroxide_stake::is_tspend(stx) {
                    continue;
                }
                block_txns.push(stx.clone());
            }
        } else {
            block_txns.extend(block.stransactions.iter().cloned());
        }
        block_txns.extend(block.transactions.iter().skip(1).cloned());

        crate::chainio::deserialize_spend_journal_entry(&serialized, &block_txns)
            .expect("valid spend journal serialization")
    }

    /// The full block data for a node.  The data must have been
    /// stored previously; callers only request blocks whose data
    /// availability is tracked by the block index (dcrd
    /// `fetchBlockByNode` over its database and recent block cache).
    pub fn block_by_node(&self, node: NodeId) -> &MsgBlock {
        self.blocks
            .get(&self.store.node(node).hash.0)
            .expect("block data for node is stored")
    }

    /// Load the list of newly maturing tickets for a node by looking
    /// back to the block containing the tickets to mature (dcrd
    /// `maybeFetchNewTickets`).  `None` means never looked up while
    /// an empty list means no tickets mature at this node.
    pub fn maybe_fetch_new_tickets(&mut self, node: NodeId, params: &Params) {
        if self.store.node(node).new_tickets.is_some() {
            return;
        }

        // No tickets in the live ticket pool are possible before
        // stake enabled height.
        if self.store.node(node).height < params.stake_enabled_height {
            self.store.node_mut(node).new_tickets = Some(Vec::new());
            return;
        }

        let mature_node = self
            .store
            .relative_ancestor(node, i64::from(params.ticket_maturity))
            .expect("ancestor at the ticket maturity distance");
        let mature_block = self.block_by_node(mature_node);
        let tickets: Vec<dcroxide_chainhash::Hash> = mature_block
            .stransactions
            .iter()
            .filter(|stx| dcroxide_stake::is_sstx(stx))
            .map(|stx| stx.tx_hash())
            .collect();
        self.store.node_mut(node).new_tickets = Some(tickets);
    }

    /// Load and populate the prunable ticket information in the node
    /// if needed (dcrd `maybeFetchTicketInfo`).
    pub fn maybe_fetch_ticket_info(&mut self, node: NodeId, params: &Params) {
        self.maybe_fetch_new_tickets(node, params);

        if !self.store.node(node).ticket_info_populated {
            let block = self
                .blocks
                .get(&self.store.node(node).hash.0)
                .expect("block data for node is stored");
            let info = dcroxide_stake::find_spent_tickets_in_block(block);
            let votes = info.votes.iter().map(|v| (v.version, v.bits)).collect();
            self.store
                .populate_ticket_info(node, info.voted_tickets, info.revoked_tickets, votes);
        }
    }

    /// Record the in-memory ticket database rows for a main chain
    /// node whose stake node is loaded: the undo data and maturing
    /// tickets by height (the row content of dcrd
    /// `stake.WriteConnectedBestNode`; the database-backed rows
    /// arrive with the persistence wiring).
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
            self.maybe_fetch_ticket_info(node, params);
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
                // the ticket database rows like dcrd does.
                let prev_height = self.store.node(prev_id).height;
                let utds = self
                    .stake_undo
                    .get(&prev_height)
                    .expect("ticket undo row for main chain height")
                    .clone();
                let tickets = self
                    .stake_new_tickets
                    .get(&prev_height)
                    .expect("ticket row for main chain height")
                    .clone();
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
            self.maybe_fetch_ticket_info(id, params);
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
    /// semantics (dcrd `ProcessBlockHeader`).  dcrd additionally
    /// flushes modified block index entries to the database here;
    /// index persistence arrives with the engine wiring.
    pub fn process_block_header(
        &mut self,
        header: &BlockHeader,
        adjusted_time_unix: i64,
        params: &Params,
    ) -> Result<(), RuleError> {
        self.maybe_accept_block_header(header, true, adjusted_time_unix, params)
            .map(|_| ())
    }

    /// Connect the block to the end of the best chain: record the
    /// spend journal, ticket database rows, filter, and header
    /// commitment leaves, apply the view to the UTXO set, move the
    /// best chain tip, and replace the best state snapshot (dcrd
    /// `connectBlock`; the treasury balance and treasury spend rows
    /// arrive with the treasury database, and the block index flush,
    /// cache flush tuning, notifications, and the stake node memory
    /// prune optimization are not reproduced).
    #[allow(clippy::too_many_arguments)]
    pub fn connect_block(
        &mut self,
        node: NodeId,
        block: &MsgBlock,
        parent: &MsgBlock,
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
                crate::chaindb::db_put_gcs_filter(tx, &node_hash, &filter)
                    .map_err(chain_db_to_db_error)?;
                crate::chaindb::db_put_header_commitments(tx, &node_hash, &hdr_commitment_leaves)
                    .map_err(chain_db_to_db_error)?;
                Ok(())
            })
            .map_err(|e| persist_rule_error(crate::chaindb::ChainDbError::Db(e)))?;
        }

        // The treasury account and spend records when the agenda is
        // active.
        let is_treasury_enabled = {
            let parent_view = NodeBranchView {
                store: &self.store,
                tip: parent_id,
            };
            crate::agendas::is_treasury_agenda_active(&parent_view, prev_height, params)
                .map_err(|_| unknown_deployment_error())?
        };
        if is_treasury_enabled {
            self.put_treasury_records(node, block, params)?;
        }

        // Commit all entries in the view to the UTXO set.
        self.commit_view(view);

        // This node is now the end of the best chain.
        self.best_chain.set_tip(&self.store, Some(node));
        self.state_snapshot = state;

        // The connected and new-tickets events (dcrd sends the former
        // with the chain lock released and the latter with it held;
        // the synchronous callback here must only queue either way).
        Self::send_ntfn(
            &mut self.notifications,
            &Notification::BlockConnected(BlockConnectedNtfnsData {
                block,
                parent_block: parent,
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
        block: &MsgBlock,
        parent: &MsgBlock,
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
            let node_hash = self.store.node(node).hash;
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
                crate::chaindb::db_remove_spend_journal_entry(tx, &node_hash)
                    .map_err(chain_db_to_db_error)?;
                Ok(())
            })
            .map_err(|e| persist_rule_error(crate::chaindb::ChainDbError::Db(e)))?;
        }

        // Commit all entries in the view to the UTXO set.  dcrd then
        // forces a cache flush on every disconnect, which drops the
        // spent tombstones; blocks detached after this point resurrect
        // their spent outputs from the journal's fraud proof fields
        // rather than the retained originals, and reproducing that
        // timing matters for field-level parity.
        self.commit_view(view);
        self.flush_utxo_cache();

        // Remove the block's spend journal record after the flush like
        // dcrd, since the journal is its cache recovery source.
        let node_hash = self.store.node(node).hash;
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
                block,
                parent_block: parent,
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
    /// `reorganizeChainInternal`; the shutdown interrupt checks and
    /// notifications are not reproduced).
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
        let mut next_block_to_detach: Option<MsgBlock> = None;
        while let Some(n) = tip {
            if Some(n) == fork {
                break;
            }
            let block = match next_block_to_detach.take() {
                Some(b) => b,
                None => self.block_by_node(n).clone(),
            };
            assert_eq!(
                self.store.node(n).hash,
                block.header.block_hash(),
                "detach block node hash does not match the block"
            );
            let parent_id = self.store.node(n).parent.expect("detached block parent");
            let parent = self.block_by_node(parent_id).clone();
            next_block_to_detach = Some(parent.clone());

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
            let stxos = self.fetch_spend_journal(&block, is_treasury_enabled);
            view.disconnect_block(
                &block,
                &parent,
                &stxos,
                &|op: &OutPoint| Self::cache_fetch(&self.utxo_backend, &self.utxo_cache, op),
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

        for node in attach_nodes {
            let block = self.block_by_node(node).clone();
            let parent_id = self.store.node(node).parent.expect("attach parent");
            let parent = self.block_by_node(parent_id).clone();
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
                    .map_err(|_| unknown_deployment_error())?
            };

            // Skip validation when the block has already been
            // validated; the view, stxos, and header commitment data
            // are still needed.
            let mut stxos: Vec<SpentTxOut> = Vec::with_capacity(count_spent_outputs(&block));
            let filter;
            if self.index.node_status(&self.store, node).has_validated() {
                let parent_stxos = self.fetch_spend_journal(&parent, is_treasury_enabled);
                view.connect_block(
                    &block,
                    &parent,
                    &parent_stxos,
                    &|op: &OutPoint| Self::cache_fetch(&self.utxo_backend, &self.utxo_cache, op),
                    Some(&mut stxos),
                    is_treasury_enabled,
                )?;
                filter = self.load_or_create_filter(&block, &view)?;
            } else {
                // The block must pass all of the validation rules
                // which depend on having the full block data for all
                // of its ancestors available.
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
                    self.index
                        .mark_block_failed_validation(&mut self.store, node);
                    return Err(err);
                }

                let run_scripts = !self.bulk_import_mode && !self.is_assume_valid_ancestor(node);
                let parent_stxos = self.fetch_spend_journal(&parent, is_treasury_enabled);
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
                        &parent_stxos,
                        &mut view,
                        &|op: &OutPoint| {
                            Self::cache_fetch(&self.utxo_backend, &self.utxo_cache, op)
                        },
                        Some(&mut stxos),
                        run_scripts,
                        params,
                    )
                };
                match connect_result {
                    Ok(filter_hash) => {
                        // The filter was computed inside the connect
                        // checks; recreate it from the post-connect
                        // view for storage (dcrd receives it through
                        // the header commitment data out-param).
                        filter = self.load_or_create_filter(&block, &view)?;
                        assert_eq!(filter.hash(), filter_hash, "filter hash mismatch");
                    }
                    Err(err) => {
                        self.index
                            .mark_block_failed_validation(&mut self.store, node);
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
    /// `reorganizeChain`; notifications and the current-latch cache
    /// flush are not reproduced).  All accumulated reorg errors are
    /// returned (dcrd wraps multiple in a `MultiError`).
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
        if let Some(new_tip) = self.best_chain.tip() {
            self.maybe_update_is_current(new_tip, adjusted_time_unix);
        }

        // The reorganization outcome when the tip actually moved,
        // then the completion event dcrd defers, which fires even
        // when every attempt failed.
        if sent_reorging_ntfn {
            let new_tip = self.best_chain.tip();
            if new_tip != orig_tip
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
    /// `maybeAcceptBlockData`; the stake node pruner and the block
    /// database write are respectively a memory optimization and the
    /// in-memory block map here).
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
        self.blocks
            .insert(block.header.block_hash().0, block.clone());
        if let Some(db) = &self.db {
            let stored = db.update(|tx| tx.store_block(block));
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
    /// contextual checks over each, marking any failures, and return
    /// those accepted along with the error for the first failure
    /// (dcrd `maybeAcceptBlocks`; the recent block and context check
    /// caches are not reproduced).  A checked block that directly
    /// extends the current tip while the chain is current sends the
    /// early new-tip event.
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
            let block = self.block_by_node(node).clone();
            let parent_id = self.store.node(node).parent.expect("linked block parent");
            let parent_stake_node = match self.fetch_stake_node(parent_id, params) {
                Ok(sn) => sn,
                Err(err) => return (nodes[..i].to_vec(), Some(stake_rule_error(err))),
            };
            if let Err(err) = check_block_context_for(
                &self.store,
                parent_id,
                &block,
                &parent_stake_node,
                fast_add,
                params,
            ) {
                self.index
                    .mark_block_failed_validation(&mut self.store, node);
                return (nodes[..i].to_vec(), Some(err));
            }

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
    /// block index flush and the acceptance notifications are not
    /// reproduced).  Returns the length of the fork the block
    /// extended alongside any errors; the fork length is zero when
    /// the block extended or became the best chain tip.
    pub fn process_block(
        &mut self,
        block: &MsgBlock,
        adjusted_time_unix: i64,
        params: &Params,
    ) -> (i64, Vec<RuleError>) {
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
        // for full validation.  dcrd flushes the block index to the
        // database here; index persistence arrives with the wiring.
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
        (fork_len, final_errs)
    }

    /// Manually invalidate the block as if it had violated a
    /// consensus rule, mark its descendants as having an invalid
    /// ancestor, and reorganize to the best remaining valid chain
    /// (dcrd `InvalidateBlock`; the context check cache and block
    /// index flushes are not reproduced).
    pub fn invalidate_block(
        &mut self,
        hash: &Hash,
        adjusted_time_unix: i64,
        params: &Params,
    ) -> Vec<RuleError> {
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
        // best chain.
        if !self.best_chain.contains(&self.store, node) {
            self.index
                .mark_block_failed_validation(&mut self.store, node);
            return Vec::new();
        }

        // Reorganize back to the parent and mark the block and its
        // descendants.
        let parent = self.store.node(node).parent.expect("non-genesis parent");
        let errs = self.reorganize_chain(Some(parent), adjusted_time_unix, params);
        if !errs.is_empty() {
            return errs;
        }
        self.index
            .mark_block_failed_validation(&mut self.store, node);

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
        let errs = self.reorganize_chain(target, adjusted_time_unix, params);
        let best = self.best_chain.tip().expect("best chain tip");
        self.index.prune_cached_tips(&self.store, best);
        errs
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
        self.reorganize_chain(Some(new_best_node), adjusted_time_unix, params)
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

        // The positional checks over the parent branch.
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
                params,
            )?;
        }

        // The contextual checks, again skipping the proof of work.
        let prev_stake_node = self
            .fetch_stake_node(prev_node, params)
            .map_err(stake_rule_error)?;
        {
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
            let parent = self.block_by_node(tip).clone();
            let parent_stxos = self.fetch_spend_journal(&parent, is_treasury_enabled);
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
                &parent_stxos,
                &mut view,
                &|op: &OutPoint| Self::cache_fetch(&self.utxo_backend, &self.utxo_cache, op),
                None,
                run_scripts,
                params,
            )
            .map(|_| ());
        }

        // The template builds on the parent of the current tip: undo
        // the tip block to reach the template's point of view.
        let tip_block = self.block_by_node(tip).clone();
        let parent = self.block_by_node(prev_node).clone();
        let stxos = self.fetch_spend_journal(&tip_block, is_treasury_enabled);
        view.disconnect_block(
            &tip_block,
            &parent,
            &stxos,
            &|op: &OutPoint| Self::cache_fetch(&self.utxo_backend, &self.utxo_cache, op),
            is_treasury_enabled,
        )?;
        let parent_stxos = self.fetch_spend_journal(&parent, is_treasury_enabled);
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
            &parent_stxos,
            &mut view,
            &|op: &OutPoint| Self::cache_fetch(&self.utxo_backend, &self.utxo_cache, op),
            None,
            run_scripts,
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
        let tip_block = self.block_by_node(tip).clone();
        let parent = self.block_by_node(tip_parent).clone();

        // Determine if the treasury agenda is active.
        let is_treasury_enabled = self
            .is_treasury_agenda_active(&tip_parent_hash, params)
            .map_err(|e| e.description)?;

        // Load all of the spent txos for the tip block from the spend
        // journal, then update the view to unspend all of them and
        // remove the utxos created by the tip block.  Also, if the
        // block votes against its parent, reconnect all of the
        // regular transactions.
        let stxos = self.fetch_spend_journal(&tip_block, is_treasury_enabled);
        view.disconnect_block(
            &tip_block,
            &parent,
            &stxos,
            &|op: &OutPoint| Self::cache_fetch(&self.utxo_backend, &self.utxo_cache, op),
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
        // stxos to collect here; the parent journal feeds the
        // disapproval handling this port hoists to the caller).
        let parent_stxos = self.fetch_spend_journal(&parent, is_treasury_enabled);
        view.connect_block(
            block,
            &parent,
            &parent_stxos,
            &|op: &OutPoint| Self::cache_fetch(&self.utxo_backend, &self.utxo_cache, op),
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

    /// The block with the given hash when its data is available (dcrd
    /// `BlockByHash`).
    pub fn block_by_hash(&self, hash: &Hash) -> Option<MsgBlock> {
        self.index
            .lookup_node(hash)
            .filter(|n| self.index.node_status(&self.store, *n).have_data())
            .and_then(|n| self.blocks.get(&self.store.node(n).hash.0).cloned())
    }

    /// The main chain block at the given height (dcrd
    /// `BlockByHeight`).
    pub fn block_by_height(&self, height: i64) -> Option<MsgBlock> {
        self.best_chain
            .node_by_height(height)
            .and_then(|n| self.blocks.get(&self.store.node(n).hash.0).cloned())
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

    /// The main chain block hashes in the given inclusive height
    /// range (dcrd `HeightRange` semantics over the best chain).
    pub fn height_range(&self, start_height: i64, end_height: i64) -> Vec<Hash> {
        let mut out = Vec::new();
        let mut h = start_height;
        while h < end_height {
            match self.best_chain.node_by_height(h) {
                Some(n) => out.push(self.store.node(n).hash),
                None => break,
            }
            h += 1;
        }
        out
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
        Ok(crate::stakever::calc_stake_version(
            &crate::sequencelock::AsVersionView(&view),
            height,
            params,
        ))
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
        // Agendas are never active for the genesis block (dcrd
        // `isAgendaActiveByHash`'s zero-hash special case).
        if *prev_hash == Hash::ZERO {
            return Ok(false);
        }
        let node = self.lookup_validatable(prev_hash)?;
        let view = NodeBranchView {
            store: &self.store,
            tip: node,
        };
        let height = self.store.node(node).height;
        crate::agendas::is_treasury_agenda_active(&view, Some(height), params).map_err(|_| {
            rule_error(
                RuleErrorKind::UnknownDeploymentID,
                format!(
                    "deployment ID {} does not exist",
                    crate::agendas::VOTE_ID_TREASURY
                ),
            )
        })
    }

    /// Whether the DCP0009 automatic ticket revocations agenda is
    /// active for the block AFTER the given block (dcrd
    /// `BlockChain.IsAutoRevocationsAgendaActive`).
    pub fn is_auto_revocations_agenda_active(
        &self,
        prev_hash: &Hash,
        params: &Params,
    ) -> Result<bool, RuleError> {
        // Agendas are never active for the genesis block (dcrd
        // `isAgendaActiveByHash`'s zero-hash special case).
        if *prev_hash == Hash::ZERO {
            return Ok(false);
        }
        let node = self.lookup_validatable(prev_hash)?;
        let view = NodeBranchView {
            store: &self.store,
            tip: node,
        };
        let height = self.store.node(node).height;
        crate::agendas::is_agenda_active(
            &view,
            Some(height),
            crate::agendas::VOTE_ID_AUTO_REVOCATIONS,
            params,
        )
        .map_err(|_| {
            rule_error(
                RuleErrorKind::UnknownDeploymentID,
                format!(
                    "deployment ID {} does not exist",
                    crate::agendas::VOTE_ID_AUTO_REVOCATIONS
                ),
            )
        })
    }

    /// Whether the given agenda is active for the block AFTER the
    /// given block (the shared body of the by-hash agenda queries,
    /// dcrd `isAgendaActiveByHash`).
    fn is_agenda_active_by_hash(
        &self,
        prev_hash: &Hash,
        vote_id: &'static str,
        params: &Params,
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
        crate::agendas::is_agenda_active(&view, Some(height), vote_id, params).map_err(|_| {
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
    pub fn ticket_pool_value(&self) -> Option<i64> {
        let mut amt: i64 = 0;
        for hash in self.live_tickets() {
            let op = OutPoint {
                hash,
                index: 0,
                tree: dcroxide_wire::TX_TREE_STAKE,
            };
            let utxo = self.fetch_utxo_entry(&op)?;
            amt += utxo.amount();
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
    /// served from the in-memory caches the engine keeps in step with
    /// the database.
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

        let Some(filter) = self.filters.get(&hash.0) else {
            return Err(rule_error(
                RuleErrorKind::NoFilter,
                format!("no filter available for block {hash}"),
            ));
        };
        let leaves = self
            .header_commitments
            .get(&hash.0)
            .cloned()
            .unwrap_or_default();

        // Generate the header commitment inclusion proof for the
        // filter.
        let proof = dcroxide_standalone::generate_inclusion_proof(&leaves, HEADER_CMT_FILTER_INDEX);
        Ok((
            filter.clone(),
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
            let Some(filter) = self.filters.get(&hash.0) else {
                return Err(rule_error(
                    RuleErrorKind::NoFilter,
                    format!("no filter available for block {hash}"),
                ));
            };
            let leaves = self
                .header_commitments
                .get(&hash.0)
                .cloned()
                .unwrap_or_default();
            let proof =
                dcroxide_standalone::generate_inclusion_proof(&leaves, HEADER_CMT_FILTER_INDEX);
            cfilters.push(dcroxide_wire::MsgCFilterV2 {
                block_hash: *hash,
                data: filter.bytes().to_vec(),
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
        let Some(ts) = self.treasury_state.get(&self.store.node(prev_node).hash.0) else {
            return 0;
        };
        let Some(wts) = self.treasury_state.get(&self.store.node(want_node).hash.0) else {
            return 0;
        };
        let mut net_value = 0i64;
        for v in &wts.values {
            net_value += v.amount;
        }
        ts.balance + net_value
    }

    /// Record the treasury state and spend rows for a connected block
    /// (dcrd's method forms of `dbPutTreasuryBalance` and
    /// `dbPutTSpend`), writing through to the database when
    /// persistent.
    pub fn put_treasury_records(
        &mut self,
        node: NodeId,
        block: &MsgBlock,
        params: &Params,
    ) -> Result<(), RuleError> {
        let parent = self.store.node(node).parent.expect("connected parent");
        let balance = self.calculate_treasury_balance(parent, params);
        let ts = crate::treasurydb::treasury_state_for_block(block, balance);
        let block_hash = self.store.node(node).hash;
        self.treasury_state.insert(block_hash.0, ts.clone());

        let mut tspend_updates: Vec<(Hash, Vec<Hash>)> = Vec::new();
        for stx in &block.stransactions {
            if !dcroxide_stake::is_tspend(stx) {
                continue;
            }
            let tx_hash = stx.tx_hash();
            let blocks = self.tspend_blocks.entry(tx_hash.0).or_default();
            blocks.push(block_hash);
            tspend_updates.push((tx_hash, blocks.clone()));
        }

        if let Some(db) = &self.db {
            db.update(|tx| {
                crate::treasurydb::db_put_treasury_balance(tx, &block_hash, &ts)
                    .map_err(chain_db_to_db_error)?;
                for (tx_hash, blocks) in &tspend_updates {
                    crate::treasurydb::db_put_tspend(tx, tx_hash, blocks)
                        .map_err(chain_db_to_db_error)?;
                }
                Ok(())
            })
            .map_err(|e| persist_rule_error(crate::chaindb::ChainDbError::Db(e)))?;
        }
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

    /// Tally the treasury votes for a treasury spend up to the given
    /// node (dcrd `tSpendCountVotes`).  Returns the window start and
    /// end alongside the yes and no counts.
    pub fn tspend_count_votes(
        &self,
        prev_node: NodeId,
        tspend: &MsgTx,
        params: &Params,
    ) -> Result<(u32, u32, u32, u32), String> {
        let expiry = tspend.expiry;
        let (start, end) = dcroxide_standalone::calc_tspend_window(
            expiry,
            params.treasury_vote_interval,
            params.treasury_vote_interval_multiplier,
        )
        .map_err(|e| format!("{e:?}"))?;

        let next_height = self.store.node(prev_node).height + 1;
        if !dcroxide_standalone::inside_tspend_window(
            next_height,
            expiry,
            params.treasury_vote_interval,
            params.treasury_vote_interval_multiplier,
        ) {
            return Err(format!(
                "tspend outside of window: nextHeight {next_height} start {start} expiry {expiry}"
            ));
        }

        let tspend_hash = tspend.tx_hash();
        let mut yes = 0u32;
        let mut no = 0u32;
        let mut node = Some(prev_node);
        while let Some(id) = node {
            if self.store.node(id).height < i64::from(start) {
                break;
            }
            let block = self.block_by_node(id);
            for stx in &block.stransactions {
                let Ok(votes) = dcroxide_stake::check_ssgen_votes(stx) else {
                    // Not a vote.
                    continue;
                };
                for vote in &votes {
                    if vote.hash != tspend_hash {
                        continue;
                    }
                    match vote.vote {
                        dcroxide_stake::TREASURY_VOTE_YES => yes += 1,
                        dcroxide_stake::TREASURY_VOTE_NO => no += 1,
                        _ => {}
                    }
                }
            }
            node = self.store.node(id).parent;
        }
        Ok((start, end, yes, no))
    }

    /// Verify the treasury spend has enough votes to be included in a
    /// block after the given node (dcrd `checkTSpendHasVotes`).
    pub fn check_tspend_has_votes(
        &self,
        prev_node: NodeId,
        tspend: &MsgTx,
        params: &Params,
    ) -> Result<(), String> {
        let (start, end, yes, no) = self.tspend_count_votes(prev_node, tspend, params)?;

        // Passing criteria are the quorum and required percentages.
        let max_votes = u64::from(params.tickets_per_block) * u64::from(end - start);
        let quorum = max_votes * params.treasury_vote_quorum_multiplier
            / params.treasury_vote_quorum_divisor;
        let num_votes_cast = u64::from(yes + no);
        if num_votes_cast < quorum {
            return Err(format!(
                "quorum not met: yes {yes} no {no}  quorum {quorum} max {max_votes}"
            ));
        }

        // Treat the maximum remaining votes as possible no votes,
        // enabling early passage only when yes cannot drop below the
        // threshold.
        let cur_block_height = (self.store.node(prev_node).height + 1) as u32;
        let remaining_blocks = end - cur_block_height;
        let max_remaining_votes = u64::from(remaining_blocks) * u64::from(params.tickets_per_block);
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

    /// Sum the debits and credits over the given number of blocks
    /// ending at the node (dcrd `sumPastTreasuryChanges`).  Returns
    /// the spent and added totals along with the node before the
    /// window.
    fn sum_past_treasury_changes(
        &self,
        pre_tvi_node: NodeId,
        nb_blocks: u64,
    ) -> (i64, i64, Option<NodeId>) {
        let mut node = Some(pre_tvi_node);
        let mut spent = 0i64;
        let mut added = 0i64;
        let mut i = 0u64;
        while let Some(id) = node {
            if i >= nb_blocks {
                break;
            }
            let Some(ts) = self.treasury_state.get(&self.store.node(id).hash.0) else {
                // The end of available treasury records.
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
        (spent, added, node)
    }

    /// The maximum treasury expenditure per the original DCP0006
    /// policy (dcrd `maxTreasuryExpenditureDCP0006`).
    fn max_treasury_expenditure_dcp0006(&self, pre_tvi_node: NodeId, params: &Params) -> i64 {
        let policy_window = params.treasury_vote_interval
            * params.treasury_vote_interval_multiplier
            * params.treasury_expenditure_window;

        let (spent_recent_window, _, mut node) =
            self.sum_past_treasury_changes(pre_tvi_node, policy_window);

        let mut spent_prior_windows = 0i64;
        let mut nb_non_empty_windows = 0i64;
        let mut i = 0u64;
        while i < params.treasury_expenditure_policy {
            let Some(id) = node else {
                break;
            };
            let (spent, _, next) = self.sum_past_treasury_changes(id, policy_window);
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
            avg_plus_allowance - spent_recent_window
        } else {
            0
        }
    }

    /// The maximum treasury expenditure per the DCP0007 reverted
    /// policy (dcrd `maxTreasuryExpenditureDCP0007`).
    fn max_treasury_expenditure_dcp0007(&self, pre_tvi_node: NodeId, params: &Params) -> i64 {
        let policy_window = params.treasury_vote_interval
            * params.treasury_vote_interval_multiplier
            * params.treasury_expenditure_window;
        let (spent_recent, added_recent, _) =
            self.sum_past_treasury_changes(pre_tvi_node, policy_window);
        let added_plus_allowance = added_recent + added_recent / 2;
        if added_plus_allowance > spent_recent {
            added_plus_allowance - spent_recent
        } else {
            0
        }
    }

    /// The maximum treasury expenditure per the DCP0013 policy (dcrd
    /// `maxTreasuryExpenditureDCP0013`).
    fn max_treasury_expenditure_dcp0013(&self, pre_tvi_node: NodeId, params: &Params) -> i64 {
        let policy_window = params.treasury_vote_interval
            * params.treasury_vote_interval_multiplier
            * params.treasury_expenditure_window;
        let (spent_recent, _, _) = self.sum_past_treasury_changes(pre_tvi_node, policy_window);
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
        allowed_to_spend
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
            return Ok(self.max_treasury_expenditure_dcp0013(pre_tvi_node, params));
        }
        let revert_active = crate::agendas::is_agenda_active(
            &view,
            prev_height,
            crate::agendas::VOTE_ID_REVERT_TREASURY_POLICY,
            params,
        )
        .map_err(|_| unknown_deployment_error())?;
        if revert_active {
            return Ok(self.max_treasury_expenditure_dcp0007(pre_tvi_node, params));
        }
        Ok(self.max_treasury_expenditure_dcp0006(pre_tvi_node, params))
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
            .map_err(|e| format!("{e:?}"))?;
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

            // The value-in commitment in the OP_RETURN.
            let value_in = stx.tx_in[0].value_in;
            total_tspend_amount += value_in;
            let mut le = [0u8; 8];
            le.copy_from_slice(&stx.tx_out[0].pk_script[2..10]);
            let value_in_op_ret = i64::from_le_bytes(le);
            if value_in != value_in_op_ret {
                return Err(rule_error(
                    RuleErrorKind::InvalidTSpendValueIn,
                    format!(
                        "block contains TSpend transaction ({}) that did not encode ValueIn \
                         correctly got {value_in_op_ret} wanted {value_in}",
                        stx.tx_hash()
                    ),
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

/// Convert a persistence failure into a rule error so it flows
/// through the existing error paths (dcrd surfaces these as plain
/// errors).
fn persist_rule_error(err: crate::chaindb::ChainDbError) -> RuleError {
    RuleError {
        kind: RuleErrorKind::UnknownBlock,
        description: format!("chain database failure: {err:?}"),
    }
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

/// Convert a stake rule error from the ticket state machine into a
/// chain rule error like dcrd's error pass-through.
fn stake_rule_error(err: dcroxide_stake::RuleError) -> RuleError {
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
