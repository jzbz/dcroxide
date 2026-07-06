// SPDX-License-Identifier: ISC
//! The RPC server scaffold (dcrd internal/rpcserver `Server`/`Config`),
//! carrying the configuration surface the ported command handlers
//! consume.  The chain sits behind the [`RpcChain`] trait standing in
//! for the used subset of dcrd's `Chain` interface; the remaining
//! interfaces arrive with their handler slices.

use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_dcrjson::RPCError;
use dcroxide_standalone::SubsidyCache;
use dcroxide_uint256::Uint256;
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx};

use crate::rpcerrors::rpc_internal_err;

/// The subsidy parameters adapter over owned chain parameters (the
/// owned variant of the blockchain crate's `ChainSubsidyParams`).
pub struct RpcSubsidyParams(pub Params);

impl dcroxide_standalone::SubsidyParams for RpcSubsidyParams {
    fn block_one_subsidy(&self) -> i64 {
        self.0.block_one_subsidy()
    }
    fn base_subsidy_value(&self) -> i64 {
        self.0.base_subsidy
    }
    fn subsidy_reduction_multiplier(&self) -> i64 {
        self.0.mul_subsidy
    }
    fn subsidy_reduction_divisor(&self) -> i64 {
        self.0.div_subsidy
    }
    fn subsidy_reduction_interval_blocks(&self) -> i64 {
        self.0.subsidy_reduction_interval
    }
    fn work_subsidy_proportion(&self) -> u16 {
        self.0.work_reward_proportion
    }
    fn stake_subsidy_proportion(&self) -> u16 {
        self.0.stake_reward_proportion
    }
    fn treasury_subsidy_proportion(&self) -> u16 {
        self.0.block_tax_proportion
    }
    fn stake_validation_begin_height(&self) -> i64 {
        self.0.stake_validation_height
    }
    fn votes_per_block(&self) -> u16 {
        self.0.tickets_per_block
    }
}

/// The chain operations the ported handlers perform (the used subset
/// of dcrd's `rpcserver.Chain` interface; it grows with each handler
/// slice).
pub trait RpcChain {
    /// The current best chain snapshot (dcrd `BestSnapshot`).
    fn best_snapshot(&mut self) -> RpcBestState {
        unimplemented!("best_snapshot")
    }
    /// The hash and height of the current best known header (dcrd
    /// `BestHeader`).
    fn best_header(&mut self) -> (Hash, i64) {
        unimplemented!("best_header")
    }
    /// The block with the given hash (dcrd `BlockByHash`).
    fn block_by_hash(&mut self, _hash: &Hash) -> Result<MsgBlock, String> {
        unimplemented!("block_by_hash")
    }
    /// The hash of the main chain block at the given height (dcrd
    /// `BlockHashByHeight`).
    fn block_hash_by_height(&mut self, _height: i64) -> Result<Hash, String> {
        unimplemented!("block_hash_by_height")
    }
    /// The height of the main chain block with the given hash (dcrd
    /// `BlockHeightByHash`).
    fn block_height_by_hash(&mut self, _hash: &Hash) -> Result<i64, String> {
        unimplemented!("block_height_by_hash")
    }
    /// The current chain tips (dcrd `ChainTips`).
    fn chain_tips(&mut self) -> Vec<RpcChainTip> {
        unimplemented!("chain_tips")
    }
    /// The cumulative work of the block with the given hash (dcrd
    /// `ChainWork`).
    fn chain_work(&mut self, _hash: &Hash) -> Result<Uint256, String> {
        unimplemented!("chain_work")
    }
    /// The header of the block with the given hash (dcrd
    /// `HeaderByHash`).
    fn header_by_hash(&mut self, _hash: &Hash) -> Result<BlockHeader, String> {
        unimplemented!("header_by_hash")
    }
    /// Whether the chain believes it is current (dcrd `IsCurrent`).
    fn is_current(&mut self) -> bool {
        unimplemented!("is_current")
    }
    /// The headers after the first known block in the provided
    /// locators up to the stop hash (dcrd `LocateHeaders`).
    fn locate_headers(&mut self, _locators: &[Hash], _hash_stop: &Hash) -> Vec<BlockHeader> {
        unimplemented!("locate_headers")
    }
    /// Whether the block is in the main chain (dcrd
    /// `MainChainHasBlock`).
    fn main_chain_has_block(&mut self, _hash: &Hash) -> bool {
        unimplemented!("main_chain_has_block")
    }
    /// The maximum allowed block size as of the given block (dcrd
    /// `MaxBlockSize`).
    fn max_block_size(&mut self, _prev_blk_hash: &Hash) -> Result<i64, String> {
        unimplemented!("max_block_size")
    }
    /// The past median time of the block with the given hash, as unix
    /// seconds (dcrd `MedianTimeByHash`).
    fn median_time_by_hash(&mut self, _hash: &Hash) -> Result<i64, String> {
        unimplemented!("median_time_by_hash")
    }
    /// The next threshold state of the given agenda as of the given
    /// block (dcrd `NextThresholdState`).
    fn next_threshold_state(
        &mut self,
        _prev_blk_hash: &Hash,
        _deployment_id: &str,
    ) -> Result<crate::helpers::threshold::State, String> {
        unimplemented!("next_threshold_state")
    }
    /// The height the agenda's state last changed (dcrd
    /// `StateLastChangedHeight`).
    fn state_last_changed_height(
        &mut self,
        _hash: &Hash,
        _deployment_id: &str,
    ) -> Result<i64, String> {
        unimplemented!("state_last_changed_height")
    }
    /// Whether the blake3 proof of work agenda is active (dcrd
    /// `IsBlake3PowAgendaActive`).
    fn is_blake3_pow_agenda_active(&mut self, _prev_blk_hash: &Hash) -> Result<bool, String> {
        unimplemented!("is_blake3_pow_agenda_active")
    }
    /// The expected next stake difficulty given a number of new
    /// tickets, or assuming the max possible when set (dcrd
    /// `EstimateNextStakeDifficulty`).
    fn estimate_next_stake_difficulty(
        &mut self,
        _hash: &Hash,
        _new_tickets: i64,
        _use_max_tickets: bool,
    ) -> Result<i64, String> {
        unimplemented!("estimate_next_stake_difficulty")
    }
    /// Whether the ticket is currently live (dcrd `CheckLiveTicket`).
    fn check_live_ticket(&mut self, _hash: &Hash) -> bool {
        unimplemented!("check_live_ticket")
    }
    /// Whether each of the tickets is currently live (dcrd
    /// `CheckLiveTickets`).
    fn check_live_tickets(&mut self, _hashes: &[Hash]) -> Vec<bool> {
        unimplemented!("check_live_tickets")
    }
    /// The final height of the stake version interval containing the
    /// given height (dcrd `CalcWantHeight`).
    fn calc_want_height(&mut self, _interval: i64, _height: i64) -> i64 {
        unimplemented!("calc_want_height")
    }
    /// The stake versions of the count blocks ending at the given hash
    /// (dcrd `GetStakeVersions`).
    fn get_stake_versions(
        &mut self,
        _hash: &Hash,
        _count: i32,
    ) -> Result<Vec<RpcStakeVersions>, String> {
        unimplemented!("get_stake_versions")
    }
    /// The agendas for the given vote version as of the given block
    /// (dcrd `GetVoteInfo`).
    fn get_vote_info(
        &mut self,
        _hash: &Hash,
        _version: u32,
    ) -> Result<Vec<dcroxide_chaincfg::ConsensusDeployment>, VoteInfoFailure> {
        unimplemented!("get_vote_info")
    }
    /// The total number of votes cast with the given version (dcrd
    /// `CountVoteVersion`).
    fn count_vote_version(&mut self, _version: u32) -> Result<u32, String> {
        unimplemented!("count_vote_version")
    }
    /// The cumulative vote counts for the given agenda (dcrd
    /// `GetVoteCounts`).
    fn get_vote_counts(
        &mut self,
        _version: u32,
        _deployment_id: &str,
    ) -> Result<RpcVoteCounts, String> {
        unimplemented!("get_vote_counts")
    }
    /// The total value of the live ticket pool (dcrd
    /// `TicketPoolValue`).
    fn ticket_pool_value(&mut self) -> Result<i64, String> {
        unimplemented!("ticket_pool_value")
    }
    /// The treasury balance as of the given block (dcrd
    /// `TreasuryBalance`).
    fn treasury_balance(
        &mut self,
        _hash: &Hash,
    ) -> Result<RpcTreasuryBalance, TreasuryBalanceFailure> {
        unimplemented!("treasury_balance")
    }
    /// The currently live tickets (dcrd `LiveTickets`).
    fn live_tickets(&mut self) -> Result<Vec<Hash>, String> {
        unimplemented!("live_tickets")
    }
    /// The unspent output entry for the outpoint, `None` when it does
    /// not exist (dcrd `FetchUtxoEntry`).
    fn fetch_utxo_entry(
        &mut self,
        _tx_hash: &Hash,
        _index: u32,
        _tree: i8,
    ) -> Result<Option<RpcUtxoEntry>, String> {
        unimplemented!("fetch_utxo_entry")
    }
    /// Statistics on the unspent transaction output set (dcrd
    /// `FetchUtxoStats`).
    fn fetch_utxo_stats(&mut self) -> Result<RpcUtxoStats, String> {
        unimplemented!("fetch_utxo_stats")
    }
    /// The live tickets paying to the given stake address (dcrd
    /// `TicketsWithAddress`).
    fn tickets_with_address(
        &mut self,
        _addr: &dcroxide_txscript::stdaddr::Address,
    ) -> Result<Vec<Hash>, String> {
        unimplemented!("tickets_with_address")
    }
    /// The header of the main chain block at the given height (dcrd
    /// `HeaderByHeight`; the error text only feeds the wrapped
    /// internal error).
    fn header_by_height(&mut self, _height: i64) -> Result<BlockHeader, String> {
        unimplemented!("header_by_height")
    }
    /// Whether the treasury agenda is active as of the block AFTER the
    /// given block (dcrd `IsTreasuryAgendaActive`).
    fn is_treasury_agenda_active(&mut self, _prev_blk_hash: &Hash) -> Result<bool, String> {
        unimplemented!("is_treasury_agenda_active")
    }
    /// Whether the DCP0010 subsidy split agenda is active (dcrd
    /// `IsSubsidySplitAgendaActive`).
    fn is_subsidy_split_agenda_active(&mut self, _prev_blk_hash: &Hash) -> Result<bool, String> {
        unimplemented!("is_subsidy_split_agenda_active")
    }
    /// Whether the DCP0012 subsidy split agenda is active (dcrd
    /// `IsSubsidySplitR2AgendaActive`).
    fn is_subsidy_split_r2_agenda_active(&mut self, _prev_blk_hash: &Hash) -> Result<bool, String> {
        unimplemented!("is_subsidy_split_r2_agenda_active")
    }
}

/// A transaction index entry (the used subset of dcrd
/// `indexers.TxIndexEntry`).
#[derive(Debug, Clone)]
pub struct RpcTxIndexEntry {
    /// The hash of the block containing the transaction.
    pub block_hash: Hash,
    /// The byte offset of the transaction within the serialized block.
    pub offset: u32,
    /// The length of the serialized transaction.
    pub len: u32,
    /// The offset of the transaction within the block's regular tree.
    pub block_index: u32,
}

/// The transaction index operations the ported handlers perform (the
/// used subset of dcrd's `rpcserver.TxIndexer` interface).
pub trait RpcTxIndexer {
    /// The human-readable index name (dcrd `Name`).
    fn name(&mut self) -> String {
        unimplemented!("name")
    }
    /// The current index tip (dcrd `Tip`).
    fn tip(&mut self) -> Result<(i64, Hash), String> {
        unimplemented!("tip")
    }
    /// The index entry for the transaction (dcrd `Entry`; `None` for
    /// an unindexed transaction).
    fn entry(&mut self, _tx_hash: &Hash) -> Result<Option<RpcTxIndexEntry>, String> {
        unimplemented!("entry")
    }
    /// Wait for the index to signal synchronization, returning whether
    /// the signal fired before dcrd's three-second timeout (dcrd
    /// selects `WaitForSync` against `syncWait`).
    fn wait_for_sync(&mut self) -> bool {
        unimplemented!("wait_for_sync")
    }
}

impl RpcTxIndexer for () {}

/// The database operations the ported handlers perform (the used
/// subset of dcrd's `database.DB` config field).
pub trait RpcDb {
    /// Fetch the raw bytes of a block region (dcrd
    /// `Tx.FetchBlockRegion` under `DB.View`).
    fn fetch_block_region(
        &mut self,
        _block_hash: &Hash,
        _offset: u32,
        _len: u32,
    ) -> Result<Vec<u8>, String> {
        unimplemented!("fetch_block_region")
    }
}

impl RpcDb for () {}

/// A version 2 filter with its header commitment proof (the used
/// subset of dcrd `gcs.FilterV2` + `blockchain.HeaderProof`).
#[derive(Debug, Clone)]
pub struct RpcFilterProof {
    /// The serialized filter bytes.
    pub filter_bytes: Vec<u8>,
    /// The leaf index of the filter in the header commitment.
    pub proof_index: u32,
    /// The inclusion proof hashes.
    pub proof_hashes: Vec<Hash>,
}

/// A filter lookup failure with the classification the handler needs
/// (dcrd `blockchain.ErrNoFilter`).
#[derive(Debug, Clone)]
pub struct FilterFailure {
    /// Whether the failure is dcrd `blockchain.ErrNoFilter`.
    pub is_no_filter: bool,
    /// The error text.
    pub message: String,
}

/// The version 2 filter source (the used subset of dcrd's
/// `rpcserver.FiltererV2` interface).
pub trait RpcFiltererV2 {
    /// The filter and its commitment proof for the given block (dcrd
    /// `FilterByBlockHash`).
    fn filter_by_block_hash(&mut self, _hash: &Hash) -> Result<RpcFilterProof, FilterFailure> {
        unimplemented!("filter_by_block_hash")
    }
}

impl RpcFiltererV2 for () {}

/// An unspent transaction output entry (the used subset of dcrd
/// `blockchain.UtxoEntry`).
#[derive(Debug, Clone)]
pub struct RpcUtxoEntry {
    /// The output amount in atoms.
    pub amount: i64,
    /// The output script version.
    pub script_version: u16,
    /// The output script.
    pub pk_script: Vec<u8>,
    /// The height of the block containing the output.
    pub block_height: i64,
    /// Whether the containing transaction is a coinbase.
    pub is_coinbase: bool,
    /// Whether the output is spent by a main chain transaction.
    pub is_spent: bool,
}

/// Unspent transaction output set statistics (the used subset of
/// dcrd `blockchain.UtxoStats`).
#[derive(Debug, Clone)]
pub struct RpcUtxoStats {
    /// The number of unspent outputs.
    pub utxos: i64,
    /// The number of transactions with unspent outputs.
    pub transactions: i64,
    /// The serialized size of the set.
    pub size: i64,
    /// The total amount in atoms.
    pub total: i64,
    /// The hash of the serialized set.
    pub serialized_hash: Hash,
}

/// The configuration fields the ported handlers consume (the used
/// subset of dcrd's `rpcserver.Config`).
pub struct Config<C> {
    /// The chain the server operates on.
    pub chain: C,
    /// The network parameters.
    pub chain_params: Params,
    /// The subsidy cache over the same parameters.
    pub subsidy_cache: SubsidyCache<RpcSubsidyParams>,
    /// The minimum relay fee in atoms (dcrd `MinRelayTxFee`).
    pub min_relay_tx_fee: i64,
    /// The maximum protocol version the server supports (drives
    /// message serialization).
    pub max_protocol_version: u32,
    /// The sync manager (dcrd `SyncMgr`).
    pub sync_mgr: Box<dyn RpcSyncManager>,
    /// The connection manager (dcrd `ConnMgr`).
    pub conn_mgr: Box<dyn RpcConnManager>,
    /// The mempool (dcrd `TxMempooler`).
    pub tx_mempooler: Box<dyn RpcTxMempooler>,
    /// The clock (dcrd `Clock`).
    pub clock: Box<dyn RpcClock>,
    /// The local network interface lookup used by address
    /// normalization (dcrd resolves interface names live).
    pub interfaces: Box<dyn crate::helpers::InterfaceLookup>,
    /// The random nonce source (dcrd uses the global math/rand).
    pub rand_u64: Box<dyn FnMut() -> u64>,
    /// The optional transaction index (dcrd `TxIndexer`, nil when
    /// disabled).
    pub tx_indexer: Option<Box<dyn RpcTxIndexer>>,
    /// The block database (dcrd `DB`).
    pub db: Box<dyn RpcDb>,
    /// The version 2 filter source (dcrd `FiltererV2`).
    pub filterer_v2: Box<dyn RpcFiltererV2>,
    /// The optional exists-address index (dcrd `ExistsAddresser`, nil
    /// when disabled).
    pub exists_addresser: Option<Box<dyn RpcExistsAddresser>>,
}

/// The sync manager operations the ported handlers perform (the used
/// subset of dcrd's `rpcserver.SyncManager` interface).
pub trait RpcSyncManager {
    /// The latest known block height being synced to (dcrd
    /// `SyncHeight`).
    fn sync_height(&mut self) -> i64 {
        unimplemented!("sync_height")
    }
    /// The id of the current sync peer, zero when none (dcrd
    /// `SyncPeerID`).
    fn sync_peer_id(&mut self) -> i32 {
        unimplemented!("sync_peer_id")
    }
}

/// The no-op stand-in for server dependencies a caller does not
/// exercise.
impl RpcSyncManager for () {}

/// The connection manager operations the ported handlers perform
/// (the used subset of dcrd's `rpcserver.ConnManager` interface).
pub trait RpcConnManager {
    /// The number of currently connected peers (dcrd
    /// `ConnectedCount`).
    fn connected_count(&mut self) -> i32 {
        unimplemented!("connected_count")
    }
    /// The total bytes received and sent across all peers (dcrd
    /// `NetTotals`).
    fn net_totals(&mut self) -> (u64, u64) {
        unimplemented!("net_totals")
    }
    /// Add the address as a persistent or one-try peer (dcrd
    /// `Connect`).
    fn connect(&mut self, _addr: &str, _permanent: bool) -> Result<(), String> {
        unimplemented!("connect")
    }
    /// Remove the persistent peer with the given id (dcrd
    /// `RemoveByID`).
    fn remove_by_id(&mut self, _id: i32) -> Result<(), String> {
        unimplemented!("remove_by_id")
    }
    /// Remove the persistent peer with the given address (dcrd
    /// `RemoveByAddr`).
    fn remove_by_addr(&mut self, _addr: &str) -> Result<(), String> {
        unimplemented!("remove_by_addr")
    }
    /// Disconnect the peer with the given id (dcrd `DisconnectByID`).
    fn disconnect_by_id(&mut self, _id: i32) -> Result<(), String> {
        unimplemented!("disconnect_by_id")
    }
    /// Disconnect the peer with the given address (dcrd
    /// `DisconnectByAddr`).
    fn disconnect_by_addr(&mut self, _addr: &str) -> Result<(), String> {
        unimplemented!("disconnect_by_addr")
    }
    /// The currently connected peers (the subset of dcrd
    /// `ConnectedPeers` the ported handlers read).
    fn connected_peers(&mut self) -> Vec<RpcPeerInfo> {
        unimplemented!("connected_peers")
    }
    /// The persistent (added) peers (the subset of dcrd
    /// `PersistentPeers` the ported handlers read).
    fn persistent_peers(&mut self) -> Vec<RpcAddedNode> {
        unimplemented!("persistent_peers")
    }
    /// DNS-resolve the host to its addresses rendered as strings
    /// (dcrd `Lookup`).
    fn lookup(&mut self, _host: &str) -> Result<Vec<String>, String> {
        unimplemented!("lookup")
    }
    /// Broadcast the message to all connected peers (dcrd
    /// `BroadcastMessage`).
    fn broadcast_message(&mut self, _msg: &dcroxide_wire::Message) {
        unimplemented!("broadcast_message")
    }
}

impl RpcConnManager for () {}

/// A connected peer as the ported handlers read it (the used subset
/// of dcrd `rpcserver.Peer` plus its `peer.StatsSnap`).
#[derive(Debug, Clone)]
pub struct RpcPeerInfo {
    /// The unique peer id.
    pub id: i32,
    /// The peer address.
    pub addr: String,
    /// The local address of the connection, when known.
    pub local_addr: Option<String>,
    /// The services the peer advertised.
    pub services: u64,
    /// Whether the peer has disabled transaction relay.
    pub tx_relay_disabled: bool,
    /// The last send time as unix seconds.
    pub last_send_unix: i64,
    /// The last receive time as unix seconds.
    pub last_recv_unix: i64,
    /// The total bytes sent.
    pub bytes_sent: u64,
    /// The total bytes received.
    pub bytes_recv: u64,
    /// The connection time as unix seconds.
    pub conn_time_unix: i64,
    /// The peer's time offset.
    pub time_offset: i64,
    /// The negotiated protocol version.
    pub version: u32,
    /// The peer's user agent.
    pub user_agent: String,
    /// Whether the peer is inbound.
    pub inbound: bool,
    /// The height the peer advertised at connect time.
    pub starting_height: i64,
    /// The latest block height the peer is known to have.
    pub last_block: i64,
    /// The peer's current ban score.
    pub ban_score: u32,
    /// The nonce of the outstanding ping, zero when none.
    pub last_ping_nonce: u64,
    /// When the outstanding ping was sent, as unix nanoseconds.
    pub last_ping_time_unix_nanos: i64,
    /// The last measured round trip in microseconds.
    pub last_ping_micros: i64,
    /// Whether the peer is currently connected.
    pub connected: bool,
}

/// A persistent (added) peer as the ported handlers read it.
#[derive(Debug, Clone)]
pub struct RpcAddedNode {
    /// The peer address.
    pub addr: String,
    /// Whether the peer is currently connected.
    pub connected: bool,
    /// Whether the peer is inbound.
    pub inbound: bool,
}

/// The exists-address index operations the ported handlers perform
/// (the used subset of dcrd's `rpcserver.ExistsAddresser`
/// interface).
pub trait RpcExistsAddresser {
    /// The human-readable index name (dcrd `Name`).
    fn name(&mut self) -> String {
        unimplemented!("name")
    }
    /// The current index tip (dcrd `Tip`).
    fn tip(&mut self) -> Result<(i64, Hash), String> {
        unimplemented!("tip")
    }
    /// Wait for the index to signal synchronization, returning whether
    /// the signal fired before dcrd's three-second timeout.
    fn wait_for_sync(&mut self) -> bool {
        unimplemented!("wait_for_sync")
    }
    /// Whether the address has ever been seen on chain (dcrd
    /// `ExistsAddress`).
    fn exists_address(
        &mut self,
        _addr: &dcroxide_txscript::stdaddr::Address,
    ) -> Result<bool, String> {
        unimplemented!("exists_address")
    }
    /// Whether each of the addresses has ever been seen on chain
    /// (dcrd `ExistsAddresses`).
    fn exists_addresses(
        &mut self,
        _addrs: &[dcroxide_txscript::stdaddr::Address],
    ) -> Result<Vec<bool>, String> {
        unimplemented!("exists_addresses")
    }
}

impl RpcExistsAddresser for () {}

/// A mempool transaction descriptor (the used subset of dcrd
/// `mempool.TxDesc`).
#[derive(Debug, Clone)]
pub struct RpcMempoolTx {
    /// The transaction.
    pub tx: MsgTx,
    /// The stake type of the transaction.
    pub tx_type: dcroxide_stake::TxType,
}

/// A verbose mempool transaction descriptor (the used subset of dcrd
/// `mempool.VerboseTxDesc`).
#[derive(Debug, Clone)]
pub struct RpcVerboseMempoolTx {
    /// The transaction.
    pub tx: MsgTx,
    /// The stake type of the transaction.
    pub tx_type: dcroxide_stake::TxType,
    /// When the transaction was added to the pool, as unix seconds.
    pub added_unix: i64,
    /// The block height when the transaction was added.
    pub height: i64,
    /// The total fee in atoms.
    pub fee: i64,
    /// The hashes of unconfirmed pool transactions this one redeems.
    pub depends: Vec<Hash>,
}

/// The mempool operations the ported handlers perform (the used
/// subset of dcrd's `rpcserver.TxMempooler` interface).
pub trait RpcTxMempooler {
    /// The descriptors for all pool transactions (dcrd `TxDescs`).
    fn tx_descs(&mut self) -> Vec<RpcMempoolTx> {
        unimplemented!("tx_descs")
    }
    /// The verbose descriptors for all pool transactions (dcrd
    /// `VerboseTxDescs`).
    fn verbose_tx_descs(&mut self) -> Vec<RpcVerboseMempoolTx> {
        unimplemented!("verbose_tx_descs")
    }
    /// Whether each of the transactions is in the pool (dcrd
    /// `HaveTransactions`).
    fn have_transactions(&mut self, _hashes: &[Hash]) -> Vec<bool> {
        unimplemented!("have_transactions")
    }
    /// The pool transaction with the given hash along with the tree
    /// it lives in (dcrd `FetchTransaction`; the error text is
    /// discarded by the handlers).
    fn fetch_transaction(&mut self, _tx_hash: &Hash) -> Result<(MsgTx, i8), String> {
        unimplemented!("fetch_transaction")
    }
}

impl RpcTxMempooler for () {}

/// The clock the ported handlers read (the used subset of dcrd's
/// `rpcserver.Clock` interface).
pub trait RpcClock {
    /// The current time as unix milliseconds (dcrd `Clock.Now` through
    /// the handler's millisecond conversion).
    fn now_unix_millis(&mut self) -> i64 {
        unimplemented!("now_unix_millis")
    }
    /// The nanoseconds elapsed since the given unix-nanosecond time
    /// (dcrd `Clock.Since`).
    fn since_nanos(&mut self, _t_unix_nanos: i64) -> i64 {
        unimplemented!("since_nanos")
    }
}

impl RpcClock for () {}

/// The best chain snapshot fields the ported handlers consume (a
/// growing subset of dcrd's `blockchain.BestState`).
#[derive(Debug, Clone)]
pub struct RpcBestState {
    /// The hash of the best block.
    pub hash: Hash,
    /// The previous block hash.
    pub prev_hash: Hash,
    /// The height of the best block.
    pub height: i64,
    /// The difficulty bits of the best block.
    pub bits: u32,
    /// The next stake difficulty.
    pub next_stake_diff: i64,
    /// The total subsidy issued by the chain.
    pub total_subsidy: i64,
}

/// A per-block stake versions record (dcrd
/// `blockchain.StakeVersions`).
#[derive(Debug, Clone)]
pub struct RpcStakeVersions {
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

/// Cumulative vote counts for an agenda (dcrd
/// `blockchain.VoteCounts`).
#[derive(Debug, Clone)]
pub struct RpcVoteCounts {
    /// The total number of votes.
    pub total: u32,
    /// The number of abstaining votes.
    pub total_abstain: u32,
    /// Per-choice vote counts, parallel to the agenda's choices.
    pub vote_choices: Vec<u32>,
}

/// Treasury balance information (dcrd
/// `blockchain.TreasuryBalanceInfo`).
#[derive(Debug, Clone)]
pub struct RpcTreasuryBalance {
    /// The height of the queried block.
    pub block_height: i64,
    /// The balance in atoms.
    pub balance: u64,
    /// The balance updates over the recent blocks.
    pub updates: Vec<i64>,
}

/// A treasury balance failure with the classification the handler
/// needs (dcrd `ErrUnknownBlock`/`ErrNoTreasuryBalance`).
#[derive(Debug, Clone)]
pub struct TreasuryBalanceFailure {
    /// Whether the failure is dcrd `blockchain.ErrUnknownBlock`.
    pub is_unknown_block: bool,
    /// Whether the failure is dcrd `blockchain.ErrNoTreasuryBalance`.
    pub is_no_treasury_balance: bool,
    /// The error text (log only otherwise).
    pub message: String,
}

/// A vote info failure with the classification the handler needs
/// (dcrd `ErrUnknownDeploymentVersion`).
#[derive(Debug, Clone)]
pub struct VoteInfoFailure {
    /// Whether the failure is dcrd
    /// `blockchain.ErrUnknownDeploymentVersion`.
    pub is_unknown_deployment_version: bool,
    /// The error text.
    pub message: String,
}

/// A chain tip description (dcrd `blockchain.ChainTipInfo`).
#[derive(Debug, Clone)]
pub struct RpcChainTip {
    /// The height of the tip.
    pub height: i64,
    /// The hash of the tip block.
    pub hash: Hash,
    /// The length of the branch off the main chain.
    pub branch_len: i64,
    /// The tip status string.
    pub status: String,
}

/// The RPC server core (dcrd `Server`): the handler host.
pub struct Server<C> {
    /// The configuration, treated as immutable after creation like
    /// dcrd's.
    pub cfg: Config<C>,
}

impl<C: RpcChain> Server<C> {
    /// A new server over the given configuration (the used subset of
    /// dcrd `New`).
    pub fn new(cfg: Config<C>) -> Server<C> {
        Server { cfg }
    }

    /// Whether the treasury agenda is active as of the block AFTER the
    /// given block, with chain failures wrapped as internal errors
    /// (dcrd `Server.isTreasuryAgendaActive`).
    pub(crate) fn is_treasury_agenda_active(
        &mut self,
        prev_blk_hash: &Hash,
    ) -> Result<bool, RPCError> {
        self.cfg
            .chain
            .is_treasury_agenda_active(prev_blk_hash)
            .map_err(|e| rpc_internal_err(&e))
    }

    /// dcrd `Server.isSubsidySplitAgendaActive`.
    pub(crate) fn is_subsidy_split_agenda_active(
        &mut self,
        prev_blk_hash: &Hash,
    ) -> Result<bool, RPCError> {
        self.cfg
            .chain
            .is_subsidy_split_agenda_active(prev_blk_hash)
            .map_err(|e| rpc_internal_err(&e))
    }

    /// dcrd `Server.isBlake3PowAgendaActive`.
    pub(crate) fn is_blake3_pow_agenda_active(
        &mut self,
        prev_blk_hash: &Hash,
    ) -> Result<bool, RPCError> {
        self.cfg
            .chain
            .is_blake3_pow_agenda_active(prev_blk_hash)
            .map_err(|e| rpc_internal_err(&e))
    }

    /// dcrd `Server.isSubsidySplitR2AgendaActive`.
    pub(crate) fn is_subsidy_split_r2_agenda_active(
        &mut self,
        prev_blk_hash: &Hash,
    ) -> Result<bool, RPCError> {
        self.cfg
            .chain
            .is_subsidy_split_r2_agenda_active(prev_blk_hash)
            .map_err(|e| rpc_internal_err(&e))
    }
}
