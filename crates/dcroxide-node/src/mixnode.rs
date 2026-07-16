// SPDX-License-Identifier: ISC
//! The daemon's seams for the ported mixing pool (dcrd's `mixpool.Pool`
//! wired into `server.go`).  [`NodeMixChain`] and [`NodeMixUtxoFetcher`]
//! adapt the shared chain to the pool's `BlockChain` and UTXO-fetch
//! interfaces, [`shared_mix_pool`] builds the pool the daemon shares
//! between the getdata serve path and the netsync manager, and
//! [`NodeSyncMixPool`] hands that shared pool to the sync manager as its
//! `SyncMixPool`.
//!
//! The pool validates pair-request ownership against the live UTXO set,
//! so a mix message that references a spent or unknown output is
//! rejected exactly as dcrd's mixpool rejects it.

use std::sync::{Arc, Mutex};

use dcroxide_blockchain::process::Chain;
use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_mixing::{MixBlockChain, MixUtxoEntry, MixUtxoFetcher, Pool, PoolError, PoolMessage};
use dcroxide_netsync::manager::SyncMixPool;
use dcroxide_wire::{Message, MsgTx, OutPoint};

/// The mixing pool the daemon shares, over the node's chain adapter.
pub type NodeMixPool = Pool<NodeMixChain>;

/// The chain view the mixing pool consults for its tip and parameters
/// (dcrd mixpool `BlockChain`).
pub struct NodeMixChain {
    params: Params,
    chain: Arc<Mutex<Chain>>,
}

impl MixBlockChain for NodeMixChain {
    fn chain_params(&self) -> &Params {
        &self.params
    }

    fn current_tip(&self) -> (Hash, i64) {
        let chain = self.chain.lock().expect("chain mutex poisoned");
        let best = chain.best_snapshot();
        (best.hash, best.height)
    }
}

/// The UTXO fetcher the mixing pool validates pair-request ownership
/// against (dcrd mixpool's `utxoFetcher` over `chain.FetchUtxoEntry`).
struct NodeMixUtxoFetcher {
    chain: Arc<Mutex<Chain>>,
}

impl MixUtxoFetcher for NodeMixUtxoFetcher {
    fn fetch_utxo_entry(&self, op: &OutPoint) -> Result<Box<dyn MixUtxoEntry>, String> {
        let entry = self
            .chain
            .lock()
            .expect("chain mutex poisoned")
            .fetch_utxo_entry(op);
        match entry {
            Some(entry) => Ok(Box::new(NodeMixUtxo(entry))),
            None => Err(format!("no utxo entry for {}:{}", op.hash, op.index)),
        }
    }
}

/// A UTXO entry as the mixing pool reads it (dcrd's `blockchain.UtxoEntry`
/// behind the mixpool's interface).
struct NodeMixUtxo(dcroxide_blockchain::UtxoEntry);

impl MixUtxoEntry for NodeMixUtxo {
    fn is_spent(&self) -> bool {
        self.0.is_spent()
    }

    fn pk_script(&self) -> &[u8] {
        self.0.pk_script()
    }

    fn script_version(&self) -> u16 {
        self.0.script_version()
    }

    fn block_height(&self) -> i64 {
        self.0.block_height()
    }

    fn amount(&self) -> i64 {
        self.0.amount()
    }
}

/// Build the shared mixing pool over the daemon's chain (dcrd
/// `newServer` building `mixpool.NewPool`).
pub fn shared_mix_pool(chain: Arc<Mutex<Chain>>, params: Params) -> Arc<Mutex<NodeMixPool>> {
    let utxo_fetcher = Arc::new(NodeMixUtxoFetcher {
        chain: Arc::clone(&chain),
    });
    let pool = Pool::new(NodeMixChain { params, chain }, Some(utxo_fetcher));
    Arc::new(Mutex::new(pool))
}

/// The mixing pool as the sync manager drives it (dcrd's mixpool behind
/// the `netsync.Config`); shares the same pool the getdata serve path
/// reads.
pub struct NodeSyncMixPool {
    pool: Arc<Mutex<NodeMixPool>>,
}

impl NodeSyncMixPool {
    /// Adapt the shared pool for the sync manager.
    pub fn new(pool: Arc<Mutex<NodeMixPool>>) -> NodeSyncMixPool {
        NodeSyncMixPool { pool }
    }
}

impl SyncMixPool for NodeSyncMixPool {
    type Msg = PoolMessage;
    type Err = PoolError;

    fn mix_hash(&mut self, msg: &PoolMessage) -> Hash {
        // A message that cannot be hashed is rejected downstream; a zero
        // hash is never a real message id, so the rejected-message
        // bookkeeping keyed on it is harmless.
        msg.mix_hash().unwrap_or(Hash([0u8; 32]))
    }

    fn accept_message(
        &mut self,
        msg: &PoolMessage,
        source: u64,
    ) -> Result<Vec<PoolMessage>, PoolError> {
        self.pool
            .lock()
            .expect("mix pool mutex poisoned")
            .accept_message(msg, source)
    }

    fn recent_message(&mut self, hash: &Hash) -> bool {
        self.pool
            .lock()
            .expect("mix pool mutex poisoned")
            .recent_message(hash)
            .is_some()
    }

    fn remove_spent_prs(&mut self, txs: &[MsgTx]) {
        self.pool
            .lock()
            .expect("mix pool mutex poisoned")
            .remove_spent_prs(txs);
    }

    fn expire_messages_in_background(&mut self, height: u32) {
        self.pool
            .lock()
            .expect("mix pool mutex poisoned")
            .expire_messages_in_background(height);
    }
}

/// Convert a received wire mix message into a pool message (dcrd's
/// `OnMix*` handlers passing the concrete `mixing.Message` to
/// `onMixMessage`).  A non-mix message is `None`.
pub fn wire_to_pool_message(msg: Message) -> Option<PoolMessage> {
    match msg {
        Message::MixPairReq(m) => Some(PoolMessage::PR(m)),
        Message::MixKeyExchange(m) => Some(PoolMessage::KE(m)),
        Message::MixCiphertexts(m) => Some(PoolMessage::CT(m)),
        Message::MixSlotReserve(m) => Some(PoolMessage::SR(m)),
        Message::MixDCNet(m) => Some(PoolMessage::DC(m)),
        Message::MixConfirm(m) => Some(PoolMessage::CM(m)),
        Message::MixFactoredPoly(m) => Some(PoolMessage::FP(m)),
        Message::MixSecrets(m) => Some(PoolMessage::RS(m)),
        _ => None,
    }
}

/// Convert a pool message back to its wire message so an accepted or
/// requested mix message can be relayed or served (dcrd hands the same
/// `mixing.Message` value to `QueueMessage`).
pub fn pool_to_wire_message(msg: PoolMessage) -> Message {
    match msg {
        PoolMessage::PR(m) => Message::MixPairReq(m),
        PoolMessage::KE(m) => Message::MixKeyExchange(m),
        PoolMessage::CT(m) => Message::MixCiphertexts(m),
        PoolMessage::SR(m) => Message::MixSlotReserve(m),
        PoolMessage::DC(m) => Message::MixDCNet(m),
        PoolMessage::CM(m) => Message::MixConfirm(m),
        PoolMessage::FP(m) => Message::MixFactoredPoly(m),
        PoolMessage::RS(m) => Message::MixSecrets(m),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcroxide_wire::{
        MsgMixCiphertexts, MsgMixConfirm, MsgMixDCNet, MsgMixFactoredPoly, MsgMixKeyExchange,
        MsgMixPairReq, MsgMixSecrets, MsgMixSlotReserve, MsgTx,
    };

    /// One structurally-minimal instance of each of the eight wire mix
    /// messages (field contents are irrelevant to the enum remap; the
    /// point is one of every variant so a mis-paired arm is caught).
    fn one_of_each() -> Vec<Message> {
        vec![
            Message::MixPairReq(MsgMixPairReq {
                signature: [0u8; 64],
                identity: [0u8; 33],
                expiry: 0,
                mix_amount: 0,
                script_class: String::new(),
                tx_version: 0,
                lock_time: 0,
                message_count: 0,
                input_value: 0,
                utxos: Vec::new(),
                change: None,
                flags: 0,
                pairing_flags: 0,
            }),
            Message::MixKeyExchange(Box::new(MsgMixKeyExchange {
                signature: [0u8; 64],
                identity: [0u8; 33],
                session_id: [0u8; 32],
                epoch: 0,
                run: 0,
                pos: 0,
                ecdh: [0u8; 33],
                pqpk: [0u8; 1218],
                commitment: [0u8; 32],
                seen_prs: Vec::new(),
            })),
            Message::MixCiphertexts(MsgMixCiphertexts {
                signature: [0u8; 64],
                identity: [0u8; 33],
                session_id: [0u8; 32],
                run: 0,
                ciphertexts: Vec::new(),
                seen_key_exchanges: Vec::new(),
            }),
            Message::MixSlotReserve(MsgMixSlotReserve {
                signature: [0u8; 64],
                identity: [0u8; 33],
                session_id: [0u8; 32],
                run: 0,
                dc_mix: Vec::new(),
                seen_ciphertexts: Vec::new(),
            }),
            Message::MixDCNet(MsgMixDCNet {
                signature: [0u8; 64],
                identity: [0u8; 33],
                session_id: [0u8; 32],
                run: 0,
                dc_net: Vec::new(),
                seen_slot_reserves: Vec::new(),
            }),
            Message::MixConfirm(MsgMixConfirm {
                signature: [0u8; 64],
                identity: [0u8; 33],
                session_id: [0u8; 32],
                run: 0,
                mix: MsgTx::default(),
                seen_dc_nets: Vec::new(),
            }),
            Message::MixFactoredPoly(MsgMixFactoredPoly {
                signature: [0u8; 64],
                identity: [0u8; 33],
                session_id: [0u8; 32],
                run: 0,
                roots: Vec::new(),
                seen_slot_reserves: Vec::new(),
            }),
            Message::MixSecrets(MsgMixSecrets {
                signature: [0u8; 64],
                identity: [0u8; 33],
                session_id: [0u8; 32],
                run: 0,
                seed: [0u8; 32],
                slot_reserve_msgs: Vec::new(),
                dc_net_msgs: Vec::new(),
                seen_secrets: Vec::new(),
            }),
        ]
    }

    /// Every mix message survives wire -> pool -> wire unchanged, so the
    /// eight-arm remaps in both directions stay paired (a swapped arm
    /// would surface as an inequality here rather than as a silently
    /// mis-typed relay).
    #[test]
    fn mix_message_conversions_round_trip() {
        for original in one_of_each() {
            let pool = wire_to_pool_message(original.clone())
                .expect("every mix variant converts to a pool message");
            let back = pool_to_wire_message(pool);
            assert_eq!(
                back, original,
                "mix message must round-trip through the pool"
            );
        }
    }

    /// A non-mix message is not mistaken for one (the intake gate returns
    /// `None` so the dispatcher falls through to the normal handlers).
    #[test]
    fn non_mix_message_is_not_converted() {
        assert!(wire_to_pool_message(Message::MemPool).is_none());
        assert!(wire_to_pool_message(Message::GetAddr).is_none());
    }
}
