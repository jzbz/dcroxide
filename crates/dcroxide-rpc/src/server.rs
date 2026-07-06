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
use dcroxide_wire::{BlockHeader, MsgBlock};

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
    fn best_snapshot(&mut self) -> RpcBestState;
    /// The hash and height of the current best known header (dcrd
    /// `BestHeader`).
    fn best_header(&mut self) -> (Hash, i64);
    /// The block with the given hash (dcrd `BlockByHash`).
    fn block_by_hash(&mut self, hash: &Hash) -> Result<MsgBlock, String>;
    /// The hash of the main chain block at the given height (dcrd
    /// `BlockHashByHeight`).
    fn block_hash_by_height(&mut self, height: i64) -> Result<Hash, String>;
    /// The current chain tips (dcrd `ChainTips`).
    fn chain_tips(&mut self) -> Vec<RpcChainTip>;
    /// The cumulative work of the block with the given hash (dcrd
    /// `ChainWork`).
    fn chain_work(&mut self, hash: &Hash) -> Result<Uint256, String>;
    /// The header of the block with the given hash (dcrd
    /// `HeaderByHash`).
    fn header_by_hash(&mut self, hash: &Hash) -> Result<BlockHeader, String>;
    /// Whether the chain believes it is current (dcrd `IsCurrent`).
    fn is_current(&mut self) -> bool;
    /// The headers after the first known block in the provided
    /// locators up to the stop hash (dcrd `LocateHeaders`).
    fn locate_headers(&mut self, locators: &[Hash], hash_stop: &Hash) -> Vec<BlockHeader>;
    /// Whether the block is in the main chain (dcrd
    /// `MainChainHasBlock`).
    fn main_chain_has_block(&mut self, hash: &Hash) -> bool;
    /// The maximum allowed block size as of the given block (dcrd
    /// `MaxBlockSize`).
    fn max_block_size(&mut self, prev_blk_hash: &Hash) -> Result<i64, String>;
    /// The past median time of the block with the given hash, as unix
    /// seconds (dcrd `MedianTimeByHash`).
    fn median_time_by_hash(&mut self, hash: &Hash) -> Result<i64, String>;
    /// The next threshold state of the given agenda as of the given
    /// block (dcrd `NextThresholdState`).
    fn next_threshold_state(
        &mut self,
        prev_blk_hash: &Hash,
        deployment_id: &str,
    ) -> Result<crate::helpers::threshold::State, String>;
    /// The height the agenda's state last changed (dcrd
    /// `StateLastChangedHeight`).
    fn state_last_changed_height(
        &mut self,
        hash: &Hash,
        deployment_id: &str,
    ) -> Result<i64, String>;
    /// Whether the blake3 proof of work agenda is active (dcrd
    /// `IsBlake3PowAgendaActive`).
    fn is_blake3_pow_agenda_active(&mut self, prev_blk_hash: &Hash) -> Result<bool, String>;
    /// The header of the main chain block at the given height (dcrd
    /// `HeaderByHeight`; the error text only feeds the wrapped
    /// internal error).
    fn header_by_height(&mut self, height: i64) -> Result<BlockHeader, String>;
    /// Whether the treasury agenda is active as of the block AFTER the
    /// given block (dcrd `IsTreasuryAgendaActive`).
    fn is_treasury_agenda_active(&mut self, prev_blk_hash: &Hash) -> Result<bool, String>;
    /// Whether the DCP0010 subsidy split agenda is active (dcrd
    /// `IsSubsidySplitAgendaActive`).
    fn is_subsidy_split_agenda_active(&mut self, prev_blk_hash: &Hash) -> Result<bool, String>;
    /// Whether the DCP0012 subsidy split agenda is active (dcrd
    /// `IsSubsidySplitR2AgendaActive`).
    fn is_subsidy_split_r2_agenda_active(&mut self, prev_blk_hash: &Hash) -> Result<bool, String>;
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
}

/// The sync manager operations the ported handlers perform (the used
/// subset of dcrd's `rpcserver.SyncManager` interface).
pub trait RpcSyncManager {
    /// The latest known block height being synced to (dcrd
    /// `SyncHeight`).
    fn sync_height(&mut self) -> i64;
}

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
    /// The total subsidy issued by the chain.
    pub total_subsidy: i64,
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
