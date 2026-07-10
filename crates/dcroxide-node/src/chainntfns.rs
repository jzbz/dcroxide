// SPDX-License-Identifier: ISC
//! The daemon's chain event handler (dcrd server.go
//! `handleBlockchainNotification`): the chain's notification callback
//! forwards connected, disconnected, reorganization, and new-ticket
//! events straight into the websocket notification manager, and runs
//! dcrd's winning-tickets announcement gate over accepted blocks.
//!
//! The callback executes inside the chain's critical section (the
//! daemon holds the chain mutex through the whole processing call
//! where dcrd releases its chain lock around some sends), so the
//! winning-tickets lottery lookup — a chain query — cannot run there.
//! The gate-passing blocks queue instead, and the sync adapter drains
//! them right after the processing call returns with the mutex free,
//! which is exactly the lock situation dcrd's handler runs under.
//!
//! The reorg-started and reorg-done events only feed dcrd's
//! background template generator, and the early new-tip event only
//! feeds its block relay; neither is wired yet, so both are ignored
//! here.  The mix-observer refusal gate is likewise skipped until the
//! mixpool arrives — without a pool there are no misbehaving mix
//! inputs to refuse.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use dcroxide_blockchain::notifications::{BlockAcceptedNtfnsData, Notification};
use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_rpc::websocket::RpcNtfnManager;
use dcroxide_wire::{BlockHeader, CurrencyNet};

use crate::websocket::NodeNtfnMgr;

/// The maximum depth of a reorganization a side-chain block may sit
/// past while still announcing its winning tickets (dcrd
/// `maxReorgDepthNotify`); doubles as the exhaustion-attack guard
/// against expensive lottery calculations for old orphans.
const MAX_REORG_DEPTH_NOTIFY: i64 = 6;

/// The daemon's chain event handler state (dcrd's `server` fields the
/// handler consults).  Clones share the same state.
#[derive(Clone)]
pub struct ChainNtfnHandler {
    ntfn: NodeNtfnMgr,
    params: Params,
    allow_unsynced_mining: bool,
    /// The blocks whose winning tickets were already announced (dcrd
    /// `lotteryDataBroadcast`; the reference release never prunes it).
    lottery_data_broadcast: Arc<Mutex<HashSet<Hash>>>,
    /// Gate-passing accepted blocks awaiting their lottery lookup.
    pending_winning_tickets: Arc<Mutex<Vec<(Hash, i64)>>>,
}

impl ChainNtfnHandler {
    /// A handler forwarding into the given notification manager.
    pub fn new(ntfn: NodeNtfnMgr, params: Params, allow_unsynced_mining: bool) -> ChainNtfnHandler {
        ChainNtfnHandler {
            ntfn,
            params,
            allow_unsynced_mining,
            lottery_data_broadcast: Arc::default(),
            pending_winning_tickets: Arc::default(),
        }
    }

    /// The chain callback body (dcrd `handleBlockchainNotification`);
    /// runs inside the chain's critical section and only queues.
    pub fn handle(&self, notification: &Notification<'_>) {
        match notification {
            // The early new-tip event only feeds dcrd's block relay,
            // which is not wired yet.
            Notification::NewTipBlockChecked(_) => {}
            Notification::BlockAccepted(data) => self.handle_block_accepted(data),
            Notification::BlockConnected(data) => {
                self.ntfn.notify_block_connected(data.block.clone());
            }
            Notification::BlockDisconnected(data) => {
                self.ntfn.notify_block_disconnected(data.block.clone());
            }
            // These only feed dcrd's background template generator,
            // which is not wired yet.
            Notification::ChainReorgStarted | Notification::ChainReorgDone => {}
            Notification::Reorganization(data) => {
                self.ntfn.notify_reorganization(
                    data.old_hash,
                    data.old_height,
                    data.new_hash,
                    data.new_height,
                );
            }
            Notification::NewTickets(data) => {
                self.ntfn.notify_new_tickets(
                    data.hash,
                    data.height,
                    data.stake_difficulty,
                    data.tickets_new.clone(),
                );
            }
        }
    }

    /// Queue the winning-tickets lookup for an accepted block that
    /// passes dcrd's announcement gate.
    fn handle_block_accepted(&self, data: &BlockAcceptedNtfnsData<'_>) {
        if !should_notify_winning_tickets(
            &self.params,
            &data.block.header,
            data.best_height,
            data.fork_len,
        ) {
            return;
        }
        let block_hash = data.block.header.block_hash();
        if self
            .lottery_data_broadcast
            .lock()
            .expect("lottery broadcast set")
            .contains(&block_hash)
        {
            return;
        }
        self.pending_winning_tickets
            .lock()
            .expect("pending winning tickets")
            .push((block_hash, i64::from(data.block.header.height)));
    }

    /// Run the queued lottery lookups now that the chain mutex is
    /// free, announcing each block's winning tickets and recording it
    /// in the broadcast set (dcrd's inline `LotteryDataForBlock` +
    /// `NotifyWinningTickets` + `lotteryDataBroadcast` insert).  dcrd
    /// gates the whole accepted case on the sync being current unless
    /// unsynced mining is allowed.
    pub fn drain_pending_winning_tickets(
        &self,
        chain: &Arc<Mutex<Chain>>,
        adjusted_time_unix: i64,
    ) {
        let pending: Vec<(Hash, i64)> = core::mem::take(
            &mut *self
                .pending_winning_tickets
                .lock()
                .expect("pending winning tickets"),
        );
        if pending.is_empty() {
            return;
        }

        let mut chain = chain.lock().expect("chain mutex poisoned");
        if !self.allow_unsynced_mining && !chain.is_current_at(adjusted_time_unix) {
            return;
        }
        for (block_hash, block_height) in pending {
            {
                let broadcast = self
                    .lottery_data_broadcast
                    .lock()
                    .expect("lottery broadcast set");
                if broadcast.contains(&block_hash) {
                    continue;
                }
            }
            // A failed lookup skips the block without recording it,
            // like dcrd's logged break.
            let Ok((winners, _pool_size, _final_state)) =
                chain.lottery_data_for_block(&block_hash, &self.params)
            else {
                continue;
            };
            let mut mgr = self.ntfn.clone();
            RpcNtfnManager::notify_winning_tickets(&mut mgr, &block_hash, block_height, &winners);
            self.lottery_data_broadcast
                .lock()
                .expect("lottery broadcast set")
                .insert(block_hash);
        }
    }
}

/// dcrd's winning-tickets announcement gate over an accepted block
/// (server.go's NTBlockAccepted case): stake voting must be at hand,
/// the block must not sit past a deep reorganization, and old
/// pre-vote-version mainnet blocks are skipped.
pub fn should_notify_winning_tickets(
    params: &Params,
    header: &BlockHeader,
    best_height: i64,
    fork_len: i64,
) -> bool {
    let block_height = i64::from(header.height);
    let reorg_depth = best_height.saturating_sub(block_height.saturating_sub(fork_len));
    let is_old_mainnet_block =
        params.net == CurrencyNet::MAIN_NET && block_height >= 1_035_288 && header.version < 11;
    block_height >= params.stake_validation_height.saturating_sub(1)
        && reorg_depth < MAX_REORG_DEPTH_NOTIFY
        && !is_old_mainnet_block
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(height: u32, version: i32) -> BlockHeader {
        BlockHeader {
            version,
            prev_block: Hash::ZERO,
            merkle_root: Hash::ZERO,
            stake_root: Hash::ZERO,
            vote_bits: 0,
            final_state: [0u8; 6],
            voters: 0,
            fresh_stake: 0,
            revocations: 0,
            pool_size: 0,
            bits: 0,
            sbits: 0,
            height,
            size: 0,
            timestamp: 0,
            nonce: 0,
            extra_data: [0u8; 32],
            stake_version: 0,
        }
    }

    #[test]
    fn the_gate_requires_stake_validation_to_be_at_hand() {
        let params = dcroxide_chaincfg::testnet3_params();
        let svh = params.stake_validation_height;
        let at_hand = header((svh - 1) as u32, 11);
        assert!(should_notify_winning_tickets(&params, &at_hand, svh - 1, 0));
        let early = header((svh - 2) as u32, 11);
        assert!(!should_notify_winning_tickets(&params, &early, svh - 2, 0));
    }

    #[test]
    fn the_gate_refuses_deep_reorg_side_chains() {
        // dcrd's worked example shifted above simnet's stake
        // validation height: block 203' on a side chain forked after
        // 200 with best tip 206 has reorg depth 206 - (203 - 3) = 6,
        // which is refused; depth 5 passes.
        let params = dcroxide_chaincfg::simnet_params();
        let block = header(203, 11);
        assert!(!should_notify_winning_tickets(&params, &block, 206, 3));
        assert!(should_notify_winning_tickets(&params, &block, 205, 3));
    }

    #[test]
    fn the_gate_skips_old_mainnet_blocks() {
        let params = dcroxide_chaincfg::mainnet_params();
        let old = header(1_035_288, 10);
        assert!(!should_notify_winning_tickets(&params, &old, 1_035_288, 0));
        let new_version = header(1_035_288, 11);
        assert!(should_notify_winning_tickets(
            &params,
            &new_version,
            1_035_288,
            0
        ));
        // The same old version off mainnet is unaffected.
        let simnet = dcroxide_chaincfg::simnet_params();
        let off_mainnet = header(1_035_288, 10);
        assert!(should_notify_winning_tickets(
            &simnet,
            &off_mainnet,
            1_035_288,
            0
        ));
    }
}
