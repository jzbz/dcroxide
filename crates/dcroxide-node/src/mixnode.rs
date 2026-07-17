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

/// The running mix epoch observer; [`MixObserver::shutdown`] stops
/// the ticker.
pub struct MixObserver {
    stop: std::sync::mpsc::Sender<()>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl MixObserver {
    /// Stop the ticker and wait for it.
    pub fn shutdown(mut self) {
        let _ = self.stop.send(());
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Wake at every epoch boundary (UTC unix time truncated to the epoch,
/// plus one epoch — dcrd `Observer.waitForEpoch`) and hand the
/// previous finished epoch to the callback, skipping the first
/// boundary because no full epoch has finished yet (dcrd
/// `Observer.Run`'s `prevEpoch == 0` skip).  The callback's error
/// stops the loop, exactly as dcrd's `Run` returns it.
fn run_epoch_ticker(
    epoch: std::time::Duration,
    stopped: &std::sync::mpsc::Receiver<()>,
    mut on_prev_epoch: impl FnMut(u64) -> Result<(), String>,
) {
    let epoch_secs = epoch.as_secs().max(1);
    let mut prev_epoch = 0u64;
    loop {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        // epoch_secs is clamped to at least one above.
        let now_sub = now.as_secs().checked_rem(epoch_secs).unwrap_or(0);
        let until_boundary = std::time::Duration::from_secs(epoch_secs.saturating_sub(now_sub))
            .saturating_sub(std::time::Duration::from_nanos(u64::from(
                now.subsec_nanos(),
            )));
        let boundary = now
            .as_secs()
            .saturating_sub(now_sub)
            .saturating_add(epoch_secs);
        match stopped.recv_timeout(until_boundary) {
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            // A stop signal or a dropped sender ends the loop.
            _ => return,
        }
        if prev_epoch == 0 {
            prev_epoch = boundary;
            continue;
        }
        if on_prev_epoch(prev_epoch).is_err() {
            return;
        }
        prev_epoch = boundary;
    }
}

/// Drive the mixpool's misbehavior observer on the epoch ticker (dcrd
/// `Server.Run` running `s.mixObserver.Run(ctx)`): after each epoch
/// completes, the previous epoch's sessions are checked for timeout
/// misbehavior, feeding the strike set behind
/// [`Pool::misbehaving_block`] and [`Pool::misbehaving_tx`].  A check
/// error stops the observer, exactly as dcrd's `Run` returns it.
pub fn start_mix_epoch_observer(pool: Arc<Mutex<NodeMixPool>>) -> MixObserver {
    let (stop, stopped) = std::sync::mpsc::channel::<()>();
    let epoch_secs = pool
        .lock()
        .expect("mix pool mutex poisoned")
        .epoch_secs()
        .max(1) as u64;
    let join = std::thread::spawn(move || {
        run_epoch_ticker(
            std::time::Duration::from_secs(epoch_secs),
            &stopped,
            |prev_epoch| {
                pool.lock()
                    .expect("mix pool mutex poisoned")
                    .check_prev_epoch(prev_epoch)
                    .map_err(|e| {
                        crate::logging::error("MIXP", &format!("mix observer check failed: {e:?}"));
                        format!("{e:?}")
                    })
            },
        );
    });
    MixObserver {
        stop,
        join: Some(join),
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
    /// The epoch ticker skips the first boundary (no finished epoch
    /// yet), then hands each completed epoch's boundary time to the
    /// callback in order, and the stop signal ends it (dcrd
    /// `Observer.Run`'s prevEpoch skip over `waitForEpoch`).
    #[test]
    fn epoch_ticker_reports_previous_epochs() {
        let (stop, stopped) = std::sync::mpsc::channel::<()>();
        let fired: Arc<Mutex<Vec<u64>>> = Arc::default();
        let thread_fired = Arc::clone(&fired);
        let ticker = std::thread::spawn(move || {
            run_epoch_ticker(std::time::Duration::from_secs(1), &stopped, |prev| {
                thread_fired.lock().expect("fired").push(prev);
                Ok(())
            });
        });
        // Three boundaries: the first is skipped, so at least one and
        // possibly two callbacks land.
        std::thread::sleep(std::time::Duration::from_millis(3200));
        stop.send(()).expect("stop");
        ticker.join().expect("ticker thread");

        let fired = fired.lock().expect("fired");
        assert!(!fired.is_empty(), "a completed epoch must be reported");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        for window in fired.windows(2) {
            assert!(window[0] < window[1], "epochs must be increasing");
        }
        for prev in fired.iter() {
            assert!(*prev <= now, "a reported epoch lies in the past");
        }
    }

    #[test]
    fn non_mix_message_is_not_converted() {
        assert!(wire_to_pool_message(Message::MemPool).is_none());
        assert!(wire_to_pool_message(Message::GetAddr).is_none());
    }
}
