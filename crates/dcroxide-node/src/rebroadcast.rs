// SPDX-License-Identifier: ISC
//! The transaction rebroadcast machinery (dcrd server.go
//! `rebroadcastHandler`): user-submitted transactions that have not
//! yet made it into a block are periodically re-relayed in case the
//! peers restarted or otherwise lost track of them.  A dedicated
//! thread owns the pending inventory, fed add, remove, and prune
//! commands over a channel exactly like dcrd's
//! `modifyRebroadcastInv`; the first resend waits five minutes and
//! every following one a uniformly random duration up to thirty
//! minutes.
//!
//! Only the RPC `sendrawtransaction` path adds inventory (votes
//! excluded — they are only valid for a specific block), a confirmed
//! transaction removes its entry, and every block connect and
//! disconnect triggers a prune pass over dcrd's three rules: a ticket
//! whose price no longer matches the stake difficulty, an expired
//! ticket, and a revocation whose ticket is not in the live set (the
//! reference release checks strict live-treap membership here, so a
//! normally-missed ticket's pending revocation is pruned on the first
//! pass — kept bug for bug).
//!
//! dcrd sends the remove and the prune whatever the handler holds.
//! Here neither is sent while the thread holds nothing and no add is
//! on its way, which is when the handler would do nothing with them;
//! see [`RebroadcastSink`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::validate::is_expired_tx;
use dcroxide_chainhash::Hash;
use dcroxide_stake::{TxType, determine_tx_type};
use dcroxide_wire::{InvType, InvVect, MsgTx, ServiceFlag};

use crate::dispatch::SyncPeers;
use crate::server::RelayInvFacts;

/// The wait before the first rebroadcast (dcrd's fixed five-minute
/// initial timer).
const INITIAL_DELAY: Duration = Duration::from_secs(5 * 60);

/// The upper bound of the randomized wait between rebroadcasts (dcrd
/// resets its timer to `rand.Duration(30 * time.Minute)` — uniform in
/// `[0, 30min)`).
const MAX_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// A command for the rebroadcast thread (dcrd's
/// `broadcastInventoryAdd`, `broadcastInventoryDel`, and
/// `broadcastPruneInventory` messages over `modifyRebroadcastInv`).
enum RebroadcastCommand {
    /// Track the inventory with its transaction until confirmed.
    Add(InvVect, MsgTx),
    /// Stop tracking the inventory.
    Del(InvVect),
    /// Run the prune rules over the pending inventory.
    Prune,
    /// Wind the thread down.
    Stop,
    /// Report the inventory tracked once every earlier command has been
    /// applied.
    #[cfg(test)]
    Tracked(mpsc::Sender<Vec<InvVect>>),
}

/// The pending rebroadcast inventory owned by the thread (dcrd's
/// `pendingInvs` map local to `rebroadcastHandler`).
#[derive(Default)]
struct PendingInvs {
    invs: HashMap<InvVect, MsgTx>,
}

impl PendingInvs {
    /// Apply an add or remove (the corresponding dcrd message cases).
    /// An add says whether it replaced an entry and a remove whether
    /// it found one, for the count the sink reads.
    fn add(&mut self, iv: InvVect, tx: MsgTx) -> bool {
        self.invs.insert(iv, tx).is_some()
    }

    fn del(&mut self, iv: &InvVect) -> bool {
        self.invs.remove(iv).is_some()
    }

    /// Drop entries a block change invalidated (dcrd's
    /// `broadcastPruneInventory` case): a ticket whose purchase price
    /// no longer matches the next stake difficulty, an expired
    /// ticket, and a revocation whose referenced ticket is not in the
    /// live set.  Regular transactions are never pruned — only
    /// confirmation removes them.  Returns how many entries went.
    fn prune(&mut self, chain: &Arc<Mutex<Chain>>) -> usize {
        let chain = chain.lock().expect("chain mutex poisoned");
        let best = chain.best_snapshot();
        let (next_stake_diff, best_height) = (best.next_stake_diff, best.height);
        let before = self.invs.len();
        self.invs.retain(|_, tx| {
            match determine_tx_type(tx) {
                TxType::SStx => {
                    // Ticket price no longer matching the stake
                    // difficulty.
                    let Some(out) = tx.tx_out.first() else {
                        return true;
                    };
                    if out.value != next_stake_diff {
                        return false;
                    }
                    // Expired ticket.
                    !is_expired_tx(tx, best_height)
                }
                TxType::SSRtx => {
                    // A revocation whose ticket is not in the live
                    // set.  dcrd's check is strict live-treap
                    // membership, so the normally-missed ticket
                    // behind a pending revocation fails it and the
                    // entry is pruned on the first pass (the comment
                    // in the reference release describes the revived
                    // case; the code is kept bug for bug).
                    let Some(tx_in) = tx.tx_in.first() else {
                        return true;
                    };
                    chain.check_live_ticket(&tx_in.previous_out_point.hash)
                }
                _ => true,
            }
        });
        before.saturating_sub(self.invs.len())
    }

    /// Re-relay every pending entry (dcrd's timer case: each
    /// inventory relayed with the transaction data and `immediate`
    /// false).  The transaction goes back into the
    /// recently-advertised cache so a peer's getdata is served.
    fn fire(
        &self,
        sync_peers: &SyncPeers,
        recently_advertised: &Arc<Mutex<dcroxide_containers::lru::Map<Hash, MsgTx>>>,
    ) {
        for (iv, tx) in &self.invs {
            let advertised = sync_peers.relay_inventory(&RelayInvFacts {
                inv_type: iv.inv_type,
                inv_hash: iv.hash,
                req_services: ServiceFlag(0),
                immediate: false,
                data_is_block_header: false,
                data_is_tx: true,
            });
            // Refresh the recently-advertised cache only when a peer
            // qualified, matching dcrd's per-peer cache update.
            if advertised {
                recently_advertised
                    .lock()
                    .expect("recently advertised poisoned")
                    .put(iv.hash, tx.clone());
            }
        }
    }
}

/// A uniformly random duration in `[0, max)` without modulo bias
/// (dcrd `rand.Duration(30 * time.Minute)` resetting the rebroadcast
/// timer, `server.go:3345`).
///
/// From the process-wide generator, and reduced the way dcrd reduces.
/// The loop this replaced drew from the kernel and rejected outside a
/// zone of `(u64::MAX / n) * n`, which reaches the same distribution by
/// different arithmetic and a different draw count; dcrd's `Duration`
/// (`crypto/rand/uniform.go:202-209`) goes through `Uint64N`'s
/// multiply-shift (`:102-148`).  Both are bias-free, so nothing
/// about the timer's spread changes -- what changes is that the draw no
/// longer reads the kernel, on a path that fires every rebroadcast
/// round for the life of the process.
fn rand_duration(max: Duration) -> Duration {
    Duration::from_nanos(dcroxide_crypto::rand::duration(max.as_nanos() as i64) as u64)
}

/// The cheap cloneable feeder the RPC connection manager and the
/// chain handler hold (dcrd's `AddRebroadcastInventory`,
/// `RemoveRebroadcastInventory`, and `PruneRebroadcastInventory`
/// methods; a send after shutdown is absorbed like dcrd's
/// quit-guarded channel sends).
#[derive(Clone)]
pub struct RebroadcastSink {
    sender: mpsc::Sender<RebroadcastCommand>,
    /// The entries the thread holds plus the adds on their way to it;
    /// see [`Self::tracks_nothing`].
    tracked: Arc<AtomicUsize>,
}

impl RebroadcastSink {
    /// Track the transaction for periodic rebroadcast until it is
    /// confirmed (dcrd `AddRebroadcastInventory`).
    pub fn add_rebroadcast_inventory(&self, tx_hash: &Hash, tx: &MsgTx) {
        let iv = InvVect {
            inv_type: InvType::TX,
            hash: *tx_hash,
        };
        // Counted before it is sent, which is what lets a remove or a
        // prune trust a count of zero.
        self.tracked.fetch_add(1, Ordering::SeqCst);
        let _ = self.sender.send(RebroadcastCommand::Add(iv, tx.clone()));
    }

    /// Stop tracking the transaction (dcrd
    /// `RemoveRebroadcastInventory`).
    pub fn remove_rebroadcast_inventory(&self, tx_hash: &Hash) {
        if self.tracks_nothing() {
            return;
        }
        let iv = InvVect {
            inv_type: InvType::TX,
            hash: *tx_hash,
        };
        let _ = self.sender.send(RebroadcastCommand::Del(iv));
    }

    /// Run the prune rules over the pending inventory (dcrd
    /// `PruneRebroadcastInventory`).
    pub fn prune_rebroadcast_inventory(&self) {
        if self.tracks_nothing() {
            return;
        }
        let _ = self.sender.send(RebroadcastCommand::Prune);
    }

    /// Whether a remove or a prune sent at this instant would find the
    /// pending inventory empty, so that not sending it changes nothing.
    ///
    /// dcrd sends both for every connected block and its handler finds
    /// nothing to do with them unless a transaction came in over RPC
    /// (`server.go:3287-3288`, `:3290-3331`).  The count is every add
    /// sent so far less every entry the thread has since removed or
    /// replaced, and an add is counted before it is sent, so a count of
    /// zero says that every add sent before this instant has reached
    /// the thread and its entry is gone again.  The thread takes its
    /// commands in the order they were sent, so a remove or a prune
    /// sent now would come after all of those and find nothing.
    ///
    /// An add that another thread sends while this one is between the
    /// reading and the send it skips is counted after the reading, so
    /// it is sent after this instant: skipping is the same as having
    /// sent the command before that add, which is one of the two orders
    /// dcrd's handler can take the two in, and the one in which the
    /// command does nothing.  A remove or a prune that follows an add
    /// on any thread reads a count the add has already raised.
    fn tracks_nothing(&self) -> bool {
        self.tracked.load(Ordering::SeqCst) == 0
    }
}

/// The running rebroadcast thread and its feeder.
pub struct Rebroadcaster {
    sink: RebroadcastSink,
    thread: Option<JoinHandle<()>>,
}

impl Rebroadcaster {
    /// The cloneable feeder handle.
    pub fn sink(&self) -> RebroadcastSink {
        self.sink.clone()
    }

    /// Wind the thread down and wait for it (the context cancellation
    /// dcrd's handler selects on).
    pub fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        let _ = self.sink.sender.send(RebroadcastCommand::Stop);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Rebroadcaster {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Start the rebroadcast thread over the daemon's relay handles (dcrd
/// `server.Run` launching `rebroadcastHandler`).
pub fn start_rebroadcaster(
    chain: Arc<Mutex<Chain>>,
    sync_peers: SyncPeers,
    recently_advertised: Arc<Mutex<dcroxide_containers::lru::Map<Hash, MsgTx>>>,
) -> Rebroadcaster {
    start_with_delays(
        chain,
        sync_peers,
        recently_advertised,
        INITIAL_DELAY,
        MAX_INTERVAL,
    )
}

/// The thread body with injectable delays for the tests.
fn start_with_delays(
    chain: Arc<Mutex<Chain>>,
    sync_peers: SyncPeers,
    recently_advertised: Arc<Mutex<dcroxide_containers::lru::Map<Hash, MsgTx>>>,
    initial_delay: Duration,
    max_interval: Duration,
) -> Rebroadcaster {
    let (sender, receiver) = mpsc::channel();
    let tracked = Arc::new(AtomicUsize::new(0));
    let sink_tracked = Arc::clone(&tracked);
    let thread = std::thread::spawn(move || {
        let mut pending = PendingInvs::default();
        let mut deadline = Instant::now()
            .checked_add(initial_delay)
            .expect("rebroadcast deadline");
        loop {
            let wait = deadline.saturating_duration_since(Instant::now());
            // The count the sink reads comes down only once an entry is
            // gone, so it is never zero while one is held: an add that
            // replaces an entry leaves one entry for two adds counted.
            let gone = match receiver.recv_timeout(wait) {
                Ok(RebroadcastCommand::Add(iv, tx)) => usize::from(pending.add(iv, tx)),
                Ok(RebroadcastCommand::Del(iv)) => usize::from(pending.del(&iv)),
                Ok(RebroadcastCommand::Prune) => pending.prune(&chain),
                Ok(RebroadcastCommand::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                #[cfg(test)]
                Ok(RebroadcastCommand::Tracked(reply)) => {
                    let _ = reply.send(pending.invs.keys().copied().collect());
                    0
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // Any inventory we have has not made it into a
                    // block yet; resubmit it, then fire again at a
                    // random time up to the interval bound in the
                    // future.
                    pending.fire(&sync_peers, &recently_advertised);
                    deadline = Instant::now()
                        .checked_add(rand_duration(max_interval))
                        .expect("rebroadcast deadline");
                    0
                }
            };
            if gone > 0 {
                tracked.fetch_sub(gone, Ordering::SeqCst);
            }
        }
    });
    Rebroadcaster {
        sink: RebroadcastSink {
            sender,
            tracked: sink_tracked,
        },
        thread: Some(thread),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcroxide_database::{Database, Options};
    use dcroxide_testutil::unhex;
    use dcroxide_wire::{MsgBlock, OutPoint, TxIn, TxOut};

    /// A regnet chain with the first `history` linear accepted blocks
    /// of dcrd's full-block battery processed.
    fn battery_chain(history: usize) -> (tempfile::TempDir, Arc<Mutex<Chain>>) {
        let params = dcroxide_chaincfg::regnet_params();
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dcroxide-blockchain/tests/data/fullblock_vectors.txt"
        );
        let data = std::fs::read_to_string(path).expect("fullblock vectors");
        let mut now: i64 = 0;
        let mut tip = params.genesis_hash;
        let mut blocks = Vec::new();
        for line in data.lines() {
            let f: Vec<&str> = line.split(' ').collect();
            match f[0] {
                "now" => now = f[1].parse().expect("generation time"),
                // accept <name> <mainchain> <orphan> <blockhex>
                "accept" => {
                    let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                    if f[2] != "true" || block.header.prev_block != tip {
                        continue;
                    }
                    tip = block.header.block_hash();
                    blocks.push(block);
                    if blocks.len() == history {
                        break;
                    }
                }
                _ => {}
            }
        }
        let dir = tempfile::tempdir().expect("temp dir");
        let opts = Options::new(dir.path().join("blocks"), params.net.0);
        let db = Database::create(&opts).expect("create database");
        let mut chain =
            Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain");
        for block in &blocks {
            let (_, errs) = chain.process_block(block, now, &params);
            assert!(errs.is_empty(), "history block must accept: {errs:?}");
        }
        (dir, Arc::new(Mutex::new(chain)))
    }

    /// The first ticket purchase and revocation from the frozen
    /// mempool stake battery (real dcrd-generated stake transactions).
    fn stake_txs() -> (MsgTx, MsgTx) {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../dcroxide-mempool/tests/data/txstake_vectors.txt"
        );
        let data = std::fs::read_to_string(path).expect("stake vectors");
        let mut sstx = None;
        let mut ssrtx = None;
        for line in data.lines() {
            let f: Vec<&str> = line.split(' ').collect();
            if f[0] != "pt" {
                continue;
            }
            let (tx, _) = MsgTx::from_bytes(&unhex(f[1])).expect("tx");
            match determine_tx_type(&tx) {
                TxType::SStx if sstx.is_none() => sstx = Some(tx),
                TxType::SSRtx if ssrtx.is_none() => ssrtx = Some(tx),
                _ => {}
            }
            if sstx.is_some() && ssrtx.is_some() {
                break;
            }
        }
        (
            sstx.expect("battery ticket"),
            ssrtx.expect("battery revocation"),
        )
    }

    fn regular_tx(tag: u8) -> MsgTx {
        MsgTx {
            tx_in: vec![TxIn {
                previous_out_point: OutPoint {
                    hash: Hash([tag; 32]),
                    index: 0,
                    tree: dcroxide_wire::TX_TREE_REGULAR,
                },
                ..TxIn::default()
            }],
            tx_out: vec![TxOut {
                value: 1,
                ..TxOut::default()
            }],
            ..MsgTx::default()
        }
    }

    fn iv(tx: &MsgTx) -> InvVect {
        InvVect {
            inv_type: InvType::TX,
            hash: tx.tx_hash(),
        }
    }

    /// The prune applies dcrd's three rules and nothing else: tickets
    /// priced off the stake difficulty or expired go, revocations of
    /// not-live tickets go, and regular transactions always stay.
    #[test]
    fn prune_applies_dcrds_rules() {
        let (_dir, chain) = battery_chain(2);
        let (next_stake_diff, height) = {
            let chain = chain.lock().expect("chain");
            let best = chain.best_snapshot();
            (best.next_stake_diff, best.height)
        };
        assert_eq!(height, 2);
        let (sstx, ssrtx) = stake_txs();

        let regular = regular_tx(9);
        let wrong_price = sstx.clone();
        assert_ne!(
            wrong_price.tx_out[0].value, next_stake_diff,
            "battery ticket must not match regnet's stake difficulty"
        );
        let mut kept_ticket = sstx.clone();
        kept_ticket.tx_out[0].value = next_stake_diff;
        kept_ticket.expiry = 0;
        let mut expired_ticket = sstx.clone();
        expired_ticket.tx_out[0].value = next_stake_diff;
        expired_ticket.expiry = 1;

        let mut pending = PendingInvs::default();
        for tx in [
            &regular,
            &wrong_price,
            &kept_ticket,
            &expired_ticket,
            &ssrtx,
        ] {
            pending.add(iv(tx), (*tx).clone());
        }
        pending.prune(&chain);

        assert!(pending.invs.contains_key(&iv(&regular)), "regular kept");
        assert!(
            !pending.invs.contains_key(&iv(&wrong_price)),
            "off-price ticket pruned"
        );
        assert!(
            pending.invs.contains_key(&iv(&kept_ticket)),
            "priced unexpired ticket kept"
        );
        assert!(
            !pending.invs.contains_key(&iv(&expired_ticket)),
            "expired ticket pruned"
        );
        assert!(
            !pending.invs.contains_key(&iv(&ssrtx)),
            "revocation of a not-live ticket pruned"
        );
    }

    /// Register a single relay-enabled peer so a rebroadcast fire
    /// actually advertises the inventory (dcrd only records a
    /// recently-advertised transaction when a peer clears the relay
    /// gate, so the cache stays empty with no eligible peer).
    fn register_relay_peer(peers: &SyncPeers) {
        // The relay marks the transaction advertised before it queues
        // the inventory, so the dropped receiver (a failed queue send)
        // does not affect the recently-advertised bookkeeping under test.
        let (queue, _rx) = crate::peerloop::OutboundQueue::channel();
        let facts = crate::server::RelayPeerFacts {
            connected: true,
            services: ServiceFlag(0),
            wants_headers: false,
            disable_relay_tx: false,
            protocol_version: dcroxide_wire::PROTOCOL_VERSION,
        };
        let peer = Arc::new(Mutex::new(dcroxide_peer::Peer::new_inbound(
            dcroxide_peer::Config::default(),
        )));
        peers.register(
            1,
            queue,
            None,
            Arc::new(Mutex::new(crate::dispatch::RelayPeerState::new(facts))),
            peer,
            None,
            false,
            None,
            None,
            None,
        );
    }

    /// A timer fire re-relays every pending entry: the transactions
    /// land back in the recently-advertised cache serving getdata.
    #[test]
    fn fire_reannounces_the_pending_inventory() {
        let cache = crate::dispatch::new_recently_advertised();
        let peers = SyncPeers::new();
        register_relay_peer(&peers);
        let mut pending = PendingInvs::default();
        let tx = regular_tx(3);
        pending.add(iv(&tx), tx.clone());
        pending.fire(&peers, &cache);
        assert!(
            cache.lock().expect("cache").get(&tx.tx_hash()).is_some(),
            "fired transaction must serve from the cache"
        );
    }

    /// A fire with no eligible peer leaves the recently-advertised cache
    /// empty: dcrd's per-peer `recentlyAdvertisedTxns.Put` runs inside
    /// the relay loop, so with no peer to iterate it never records the
    /// transaction (P3-2).
    #[test]
    fn fire_without_a_peer_does_not_cache() {
        let cache = crate::dispatch::new_recently_advertised();
        let peers = SyncPeers::new();
        let mut pending = PendingInvs::default();
        let tx = regular_tx(5);
        pending.add(iv(&tx), tx.clone());
        pending.fire(&peers, &cache);
        assert!(
            cache.lock().expect("cache").get(&tx.tx_hash()).is_none(),
            "no eligible peer means the tx is never advertised or cached"
        );
    }

    /// The random interval stays inside dcrd's [0, max) bound.
    #[test]
    fn rand_duration_stays_in_bounds() {
        for _ in 0..1000 {
            let d = rand_duration(MAX_INTERVAL);
            assert!(d < MAX_INTERVAL);
        }
    }

    /// A sink over a channel the test reads, with nothing tracked.
    fn sink_and_receiver() -> (RebroadcastSink, mpsc::Receiver<RebroadcastCommand>) {
        let (sender, receiver) = mpsc::channel();
        let sink = RebroadcastSink {
            sender,
            tracked: Arc::default(),
        };
        (sink, receiver)
    }

    /// A rebroadcast thread that never fires, over the given chain.
    fn quiet_rebroadcaster(chain: Arc<Mutex<Chain>>) -> Rebroadcaster {
        let never = Duration::from_secs(24 * 60 * 60);
        start_with_delays(
            chain,
            SyncPeers::new(),
            crate::dispatch::new_recently_advertised(),
            never,
            never,
        )
    }

    /// The inventory the thread tracks once it has applied every command
    /// sent before this call, and the count the sink reads then.
    fn tracked(sink: &RebroadcastSink) -> (Vec<InvVect>, usize) {
        let (reply, answer) = mpsc::channel();
        sink.sender
            .send(RebroadcastCommand::Tracked(reply))
            .expect("the thread is running");
        let mut invs = answer
            .recv_timeout(Duration::from_secs(30))
            .expect("the thread answers");
        invs.sort_by_key(|iv| iv.hash.0);
        // The thread brings the count down before it takes its next
        // command, and this one came after the ones being asked about.
        (invs, sink.tracked.load(Ordering::SeqCst))
    }

    fn sorted(mut invs: Vec<InvVect>) -> Vec<InvVect> {
        invs.sort_by_key(|iv| iv.hash.0);
        invs
    }

    /// While nothing is tracked, a confirmed transaction and a block
    /// send the thread nothing.  Once an add has been sent, both are
    /// sent again, in the order they are called.
    #[test]
    fn nothing_is_sent_while_nothing_is_tracked() {
        let (sink, receiver) = sink_and_receiver();
        let (confirmed, submitted) = (regular_tx(1), regular_tx(2));

        sink.remove_rebroadcast_inventory(&confirmed.tx_hash());
        sink.prune_rebroadcast_inventory();
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));

        sink.add_rebroadcast_inventory(&submitted.tx_hash(), &submitted);
        sink.remove_rebroadcast_inventory(&confirmed.tx_hash());
        sink.prune_rebroadcast_inventory();
        match receiver.try_recv() {
            Ok(RebroadcastCommand::Add(got, tx)) => {
                assert_eq!((got, tx), (iv(&submitted), submitted.clone()));
            }
            _ => panic!("the add is sent first"),
        }
        match receiver.try_recv() {
            Ok(RebroadcastCommand::Del(got)) => assert_eq!(got, iv(&confirmed)),
            _ => panic!("the remove is sent second"),
        }
        assert!(matches!(receiver.try_recv(), Ok(RebroadcastCommand::Prune)));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }

    /// With entries tracked, a block's prune and a confirmed
    /// transaction's remove reach the thread and do what they did
    /// before the count: the prune takes the off-price ticket and
    /// leaves the regular transaction, the remove takes the transaction
    /// it names.  The count is the number of entries throughout: after
    /// an add of a tracked transaction, after a prune that takes
    /// nothing, and after one that takes two entries at once.  It is
    /// back at zero, with nothing sent, once the last entry is gone.
    #[test]
    fn a_tracked_entry_is_pruned_and_removed_as_before() {
        let (_dir, chain) = battery_chain(2);
        let next_stake_diff = chain.lock().expect("chain").best_snapshot().next_stake_diff;
        let (off_price, _) = stake_txs();
        assert_ne!(off_price.tx_out[0].value, next_stake_diff);
        let (regular, other) = (regular_tx(9), regular_tx(10));
        let rebroadcaster = quiet_rebroadcaster(chain);
        let sink = rebroadcaster.sink();
        assert_eq!(tracked(&sink), (Vec::new(), 0));

        sink.add_rebroadcast_inventory(&regular.tx_hash(), &regular);
        sink.add_rebroadcast_inventory(&off_price.tx_hash(), &off_price);
        sink.add_rebroadcast_inventory(&regular.tx_hash(), &regular);
        assert_eq!(
            tracked(&sink),
            (sorted(vec![iv(&regular), iv(&off_price)]), 2)
        );

        // A transaction that is not tracked: sent, and nothing goes.
        sink.remove_rebroadcast_inventory(&other.tx_hash());
        assert_eq!(
            tracked(&sink),
            (sorted(vec![iv(&regular), iv(&off_price)]), 2)
        );

        // A block: the off-price ticket goes.
        sink.prune_rebroadcast_inventory();
        assert_eq!(tracked(&sink), (vec![iv(&regular)], 1));

        // Another block, which takes nothing: the entry is still
        // counted.
        sink.prune_rebroadcast_inventory();
        assert_eq!(tracked(&sink), (vec![iv(&regular)], 1));

        // The transaction is confirmed.
        sink.remove_rebroadcast_inventory(&regular.tx_hash());
        assert_eq!(tracked(&sink), (Vec::new(), 0));

        // And tracked again from nothing.
        sink.add_rebroadcast_inventory(&other.tx_hash(), &other);
        assert_eq!(tracked(&sink), (vec![iv(&other)], 1));
        sink.remove_rebroadcast_inventory(&other.tx_hash());
        assert_eq!(tracked(&sink), (Vec::new(), 0));

        // A block that takes two entries takes both from the count.
        let mut second_off_price = off_price.clone();
        second_off_price.lock_time = 1;
        assert_eq!(determine_tx_type(&second_off_price), TxType::SStx);
        sink.add_rebroadcast_inventory(&off_price.tx_hash(), &off_price);
        sink.add_rebroadcast_inventory(&second_off_price.tx_hash(), &second_off_price);
        assert_eq!(
            tracked(&sink),
            (sorted(vec![iv(&off_price), iv(&second_off_price)]), 2)
        );
        sink.prune_rebroadcast_inventory();
        assert_eq!(tracked(&sink), (Vec::new(), 0));
        rebroadcaster.shutdown();
    }

    /// A transaction submitted while a block that confirms it is being
    /// handled on another thread: whichever way the two fall, the thread
    /// ends with that one entry or with none, and the count is the
    /// number of entries it holds.  Both orders occur.  A remove that
    /// follows the add always empties the inventory and the count.
    ///
    /// That the add is counted before it is sent is not held here: an
    /// add counted late ends a round with the entry kept and counted,
    /// as an add that came second does;
    /// `an_add_is_counted_before_it_is_sent` holds it.
    #[test]
    fn an_add_racing_a_block_leaves_the_count_and_the_inventory_agreeing() {
        let (_dir, chain) = battery_chain(2);
        let rebroadcaster = quiet_rebroadcaster(chain);
        let sink = rebroadcaster.sink();
        let (mut kept, mut removed) = (0, 0);
        for round in 0..1000u32 {
            let mut tx = regular_tx(11);
            tx.lock_time = round;
            let hash = tx.tx_hash();
            // The side that reaches the barrier last runs on while the
            // other is woken, so the two take turns at that, and the
            // one that runs on is then held back by a different amount
            // each round: they meet in both orders and at many
            // distances.
            let late = (round / 2).wrapping_mul(7) % 3000;
            let start = std::sync::Barrier::new(2);
            let held_back = |late: u32| {
                start.wait();
                for _ in 0..late {
                    std::hint::spin_loop();
                }
            };
            let add = |late: u32| {
                held_back(late);
                sink.add_rebroadcast_inventory(&hash, &tx);
            };
            let block = |late: u32| {
                held_back(late);
                sink.remove_rebroadcast_inventory(&hash);
                sink.prune_rebroadcast_inventory();
            };
            std::thread::scope(|scope| {
                if round % 2 == 0 {
                    scope.spawn(|| add(0));
                    block(late);
                } else {
                    scope.spawn(|| block(0));
                    add(late);
                }
            });
            let (invs, count) = tracked(&sink);
            assert_eq!(invs.len(), count, "round {round}");
            if invs.is_empty() {
                removed += 1;
            } else {
                assert_eq!(invs, vec![iv(&tx)], "round {round}");
                kept += 1;
            }

            // The block that confirms it, after the add.
            sink.remove_rebroadcast_inventory(&hash);
            sink.prune_rebroadcast_inventory();
            assert_eq!(tracked(&sink), (Vec::new(), 0), "round {round}");
        }
        assert!(
            kept > 50 && removed > 50,
            "the add came second in {kept} rounds and first in {removed}"
        );
        rebroadcaster.shutdown();
    }

    /// An add is counted before it is sent: whenever one arrives, the
    /// count already holds it.  A count raised after the send would let
    /// a remove that follows the add on another thread read zero and be
    /// skipped with the add already on its way.
    #[test]
    fn an_add_is_counted_before_it_is_sent() {
        const ADDS: usize = 200_000;
        let (sink, receiver) = sink_and_receiver();
        let tx = regular_tx(12);
        let hash = tx.tx_hash();
        std::thread::scope(|scope| {
            let counted = &sink.tracked;
            scope.spawn(move || {
                let mut arrived = 0;
                while arrived < ADDS {
                    match receiver.try_recv() {
                        Ok(RebroadcastCommand::Add(..)) => {
                            arrived += 1;
                            let counted = counted.load(Ordering::SeqCst);
                            assert!(
                                counted >= arrived,
                                "add {arrived} arrived with {counted} counted"
                            );
                        }
                        Ok(_) => panic!("only adds are sent"),
                        Err(mpsc::TryRecvError::Empty) => std::hint::spin_loop(),
                        Err(mpsc::TryRecvError::Disconnected) => panic!("the sink is gone"),
                    }
                }
            });
            for _ in 0..ADDS {
                sink.add_rebroadcast_inventory(&hash, &tx);
            }
        });
        assert_eq!(sink.tracked.load(Ordering::SeqCst), ADDS);
    }

    /// The thread accepts commands over the sink, fires on the timer,
    /// and winds down cleanly.
    #[test]
    fn the_thread_fires_and_shuts_down() {
        let params = dcroxide_chaincfg::testnet3_params();
        let dir = tempfile::tempdir().expect("temp dir");
        let opts = Options::new(dir.path().join("blocks"), params.net.0);
        let db = Database::create(&opts).expect("create database");
        let chain = Arc::new(Mutex::new(
            Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
        ));
        let cache = crate::dispatch::new_recently_advertised();
        let peers = SyncPeers::new();
        register_relay_peer(&peers);
        let rebroadcaster = start_with_delays(
            chain,
            peers,
            Arc::clone(&cache),
            Duration::from_millis(30),
            Duration::from_millis(30),
        );
        let tx = regular_tx(7);
        rebroadcaster
            .sink()
            .add_rebroadcast_inventory(&tx.tx_hash(), &tx);
        let deadline = Instant::now() + Duration::from_secs(5);
        while cache.lock().expect("cache").get(&tx.tx_hash()).is_none() {
            assert!(Instant::now() < deadline, "fire must reach the cache");
            std::thread::sleep(Duration::from_millis(10));
        }
        rebroadcaster.shutdown();
    }
}
