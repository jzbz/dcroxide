// SPDX-License-Identifier: ISC
//! The block download window the sync manager keeps open on its sync
//! peer during the initial chain sync.
//!
//! dcrd keeps at most 16 blocks requested and asks for more once fewer
//! than 10 are (`internal/netsync/manager.go:31-38`, `:490-546`,
//! `:1359-1371`), so over a link with a round trip of tens of
//! milliseconds the round trip, not the machine, sets the pace of the
//! sync.  A manager built with `SyncManager::new` keeps that window, and
//! the dcrd-generated vectors run against it.
//!
//! `BlockWindow::Budget` is the window dcrd does not have: blocks are
//! requested while the sizes their headers carry, summed over what is
//! requested from the sync peer, stay within a byte budget and their
//! number within a count, with dcrd's 16 blocks as a floor the bytes do
//! not apply below.  A sync peer that leaves with more than those 16
//! requested halves both limits, and enough blocks accepted from one
//! sync peer afterwards double them again.  These tests drive both
//! windows over a chain whose headers are all known and whose blocks
//! arrive as they are asked for, and hold dcrd's window to dcrd's rule
//! on the paths where the two differ.

// Test-harness arithmetic over small scripted chains.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use dcroxide_chainhash::Hash;
use dcroxide_containers::apbf;
use dcroxide_netsync::manager::{
    BUDGET_WINDOW_BLOCKS, MAX_BUDGET_WINDOW_BLOCKS, MAX_IN_FLIGHT_BLOCKS, MIN_IN_FLIGHT_BLOCKS,
    NEXT_BLOCKS_BUF_SIZE, WINDOW_RECOVERY_WINDOWS,
};
use dcroxide_netsync::{
    Action, BestSnapshot, BlockWindow, Config, LogLevel, Peer, ProcessBlockFailure,
    ProcessTxFailure, SyncChain, SyncManager, SyncMixPool, SyncTxPool,
};
use dcroxide_wire::{
    BlockHeader, CurrencyNet, InvType, InvVect, Message, MsgBlock, MsgHeaders, MsgNotFound, MsgTx,
    PROTOCOL_VERSION, ServiceFlag,
};

/// The main network's maximum block size.
const MAX_BLOCK_SIZE: u32 = 393_216;

/// The peer the chain is synced from.
const SYNC_PEER: i32 = 7;

/// Another peer that could be synced from.
const OTHER_PEER: i32 = 8;

/// A third peer that could be synced from.
const THIRD_PEER: i32 = 9;

/// A chain whose headers are all known and linked, and whose block data
/// arrives through `process_block`.  Each header carries a scripted size.
///
/// The blocks `new` is given are one branch, at indexes from 0, and its
/// last block is the best header.  `fork` adds a sibling branch at the
/// indexes after them, and `follow` moves the best header to it.
struct WindowChain {
    headers: Vec<BlockHeader>,
    hashes: Vec<Hash>,
    by_hash: HashMap<Hash, usize>,
    have_data: Vec<bool>,
    /// How many blocks have their data.
    num_stored: usize,
    /// The indexes of the blocks on the branch that leads to the best
    /// header, from its first block to that header's.
    best_branch: Vec<usize>,
    /// Whether the chain believes it is current.
    current: bool,
    /// Blocks whose header the chain does not supply by hash.
    no_header: HashSet<usize>,
    /// Blocks whose next processing fails as a rule violation, once.
    reject_once: HashSet<usize>,
    /// Blocks whose next processing reports that the chain already has
    /// them, once.
    duplicate_once: HashSet<usize>,
    /// Blocks the chain accepts onto a side chain one block long.
    side_chain: HashSet<usize>,
    /// The maximum each `put_next_needed_blocks` call asked for.
    asked: Vec<usize>,
}

impl WindowChain {
    /// A chain of one block per size, at heights from 1.
    fn new(sizes: &[u32]) -> WindowChain {
        let mut chain = WindowChain {
            headers: Vec::with_capacity(sizes.len()),
            hashes: Vec::with_capacity(sizes.len()),
            by_hash: HashMap::new(),
            have_data: Vec::with_capacity(sizes.len()),
            num_stored: 0,
            best_branch: Vec::with_capacity(sizes.len()),
            current: false,
            no_header: HashSet::new(),
            reject_once: HashSet::new(),
            duplicate_once: HashSet::new(),
            side_chain: HashSet::new(),
            asked: Vec::new(),
        };
        let mut prev_block = Hash::ZERO;
        for (i, size) in sizes.iter().enumerate() {
            prev_block = chain.push(prev_block, i as u32 + 1, *size, 0);
            chain.best_branch.push(i);
        }
        chain
    }

    /// Add a block and return its hash.  The nonce tells a block from
    /// its sibling at the same height on another branch.
    fn push(&mut self, prev_block: Hash, height: u32, size: u32, nonce: u32) -> Hash {
        let (mut header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header");
        header.prev_block = prev_block;
        header.height = height;
        header.size = size;
        header.nonce = nonce;
        let hash = header.block_hash();
        self.by_hash.insert(hash, self.headers.len());
        self.headers.push(header);
        self.hashes.push(hash);
        self.have_data.push(false);
        hash
    }

    /// Add a branch of one block per size that builds on the first
    /// `shared` blocks, returning its blocks' indexes.  The best header
    /// stays where it is.
    fn fork(&mut self, shared: usize, sizes: &[u32]) -> std::ops::Range<usize> {
        let first = self.headers.len();
        let mut prev_block = self.hashes[shared - 1];
        for (i, size) in sizes.iter().enumerate() {
            prev_block = self.push(prev_block, (shared + i) as u32 + 1, *size, 1);
        }
        first..self.headers.len()
    }

    /// Move the best header to the last block of a branch from `fork`.
    fn follow(&mut self, shared: usize, branch: std::ops::Range<usize>) {
        self.best_branch = (0..shared).chain(branch).collect();
    }

    /// Mark the block as having its data.
    fn store(&mut self, index: usize) {
        if !std::mem::replace(&mut self.have_data[index], true) {
            self.num_stored += 1;
        }
    }
}

impl SyncChain for WindowChain {
    fn best_header(&mut self) -> (Hash, i64) {
        (
            self.best_branch
                .last()
                .map_or(Hash::ZERO, |i| self.hashes[*i]),
            self.best_branch.len() as i64,
        )
    }
    fn header_by_hash(&mut self, hash: &Hash) -> Option<BlockHeader> {
        self.by_hash
            .get(hash)
            .filter(|i| !self.no_header.contains(i))
            .map(|i| self.headers[*i])
    }
    fn block_locator_from_hash(&mut self, _hash: &Hash) -> Vec<Hash> {
        vec![Hash::ZERO]
    }
    fn put_next_needed_blocks(&mut self, max_results: usize) -> Vec<Hash> {
        self.asked.push(max_results);
        self.best_branch
            .iter()
            .filter(|i| !self.have_data[**i])
            .map(|i| self.hashes[*i])
            .take(max_results)
            .collect()
    }
    fn best_snapshot(&mut self) -> BestSnapshot {
        BestSnapshot {
            hash: Hash::ZERO,
            height: self.num_stored as i64,
            next_stake_diff: 0,
        }
    }
    fn is_current(&mut self) -> bool {
        self.current
    }
    fn adjusted_time_unix(&mut self) -> i64 {
        0
    }
    fn maybe_update_is_current(&mut self) {}
    fn chain_work(&mut self, _hash: &Hash) -> Option<dcroxide_uint256::Uint256> {
        None
    }
    fn have_header(&mut self, hash: &Hash) -> bool {
        *hash == Hash::ZERO || self.by_hash.contains_key(hash)
    }
    fn have_block(&mut self, hash: &Hash) -> bool {
        self.by_hash.get(hash).is_some_and(|i| self.have_data[*i])
    }
    fn process_block_header(&mut self, header: &BlockHeader) -> Result<(), ProcessBlockFailure> {
        // A known header that builds on the best header becomes it.
        let (best, _) = self.best_header();
        if header.prev_block == best
            && let Some(i) = self.by_hash.get(&header.block_hash())
        {
            self.best_branch.push(*i);
        }
        Ok(())
    }
    fn process_block(&mut self, block: &MsgBlock) -> Result<i64, ProcessBlockFailure> {
        let i = self.by_hash[&block.header.block_hash()];
        if self.reject_once.remove(&i) {
            return Err(ProcessBlockFailure {
                is_duplicate_block: false,
                is_rule_error: true,
                is_corruption: false,
                message: "scripted".to_string(),
            });
        }
        if self.duplicate_once.remove(&i) {
            return Err(ProcessBlockFailure {
                is_duplicate_block: true,
                is_rule_error: true,
                is_corruption: false,
                message: "scripted duplicate".to_string(),
            });
        }
        self.store(i);
        Ok(i64::from(self.side_chain.contains(&i)))
    }
}

/// A pool that holds nothing and is never handed a transaction here.
struct EmptyTxPool;

impl SyncTxPool for EmptyTxPool {
    fn process_transaction_accepted(
        &mut self,
        _tx: &MsgTx,
        _allow_orphan: bool,
        _allow_high_fees: bool,
        _tag: u64,
    ) -> Result<Vec<(Hash, MsgTx)>, ProcessTxFailure> {
        unreachable!("no transaction is delivered in these tests")
    }
    fn have_transaction(&mut self, _hash: &Hash) -> bool {
        false
    }
    fn prune_stake_tx(&mut self, _required_stake_difficulty: i64, _height: i64) {}
    fn prune_expired_tx(&mut self, _height: i64) {}
}

/// A mixing pool that holds nothing.
struct EmptyMixPool;

impl SyncMixPool for EmptyMixPool {
    type Msg = Hash;
    type Err = String;

    fn mix_hash(&mut self, msg: &Hash) -> Hash {
        *msg
    }
    fn accept_message(&mut self, _msg: &Hash, _source: u64) -> Result<Vec<Hash>, String> {
        unreachable!("no mix message is delivered in these tests")
    }
    fn recent_message(&mut self, _hash: &Hash) -> bool {
        false
    }
    fn remove_spent_prs(&mut self, _txs: &[MsgTx]) {}
    fn expire_messages_in_background(&mut self, _height: u32) {}
}

type Manager = SyncManager<WindowChain, EmptyTxPool, EmptyMixPool>;

/// A manager over the chain as `SyncManager::new` builds it: at dcrd's
/// window.
fn dcrd_manager(chain: WindowChain) -> Manager {
    SyncManager::new(Config {
        chain,
        tx_mem_pool: EmptyTxPool,
        mix_pool: EmptyMixPool,
        min_known_chain_work: None,
        net: CurrencyNet::REG_NET,
        target_time_per_block_secs: 300,
        no_mining_state_sync: false,
        max_outbound_peers: 8,
        max_orphan_txs: 100,
        recently_confirmed_txns: std::sync::Arc::new(std::sync::Mutex::new(apbf::new_filter(
            62500, 0.0000001,
        ))),
    })
}

/// A manager over the chain with the given window.
fn manager(chain: WindowChain, window: BlockWindow) -> Manager {
    dcrd_manager(chain).with_block_window(window)
}

/// The budgeted window the daemon uses on the main network: 3,145,728
/// bytes and 128 blocks.
fn main_net_window() -> BlockWindow {
    BlockWindow::budget(MAX_BLOCK_SIZE as usize, BUDGET_WINDOW_BLOCKS)
}

/// The height of the best header of the manager's chain.
fn best_height(m: &mut Manager) -> i64 {
    m.chain_mut().best_header().1
}

/// The hashes of the chain's blocks at the given indexes.
fn hashes(m: &mut Manager, range: std::ops::Range<usize>) -> Vec<Hash> {
    m.chain_mut().hashes[range].to_vec()
}

fn connect(m: &mut Manager, id: i32) -> Vec<Action> {
    let last_block = best_height(m);
    m.on_peer_connected(Peer::new(
        id,
        format!("10.0.0.{id}:9108"),
        false,
        ServiceFlag::NODE_NETWORK,
        PROTOCOL_VERSION,
        last_block,
    ))
}

/// A headers message from the peer carrying the chain's best header,
/// which completes the initial header sync the first time the sync peer
/// sends it and asks for blocks every time.
fn best_header_from(m: &mut Manager, peer: i32) -> Vec<Action> {
    let chain = m.chain_mut();
    let best = chain.headers[*chain.best_branch.last().expect("a block")];
    m.on_headers(
        peer,
        &MsgHeaders {
            headers: vec![best],
        },
    )
}

/// Connect the sync peer and complete the header sync, returning the
/// actions of the headers message that started the chain sync.
fn start_sync(m: &mut Manager) -> Vec<Action> {
    connect(m, SYNC_PEER);
    let actions = best_header_from(m, SYNC_PEER);
    assert!(m.initial_header_sync_done(), "{actions:?}");
    assert_eq!(m.sync_peer_id(), SYNC_PEER);
    actions
}

/// The block hashes of every getdata queued to the peer, one list per
/// message, in order.
fn get_datas(actions: &[Action], peer_id: i32) -> Vec<Vec<Hash>> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::QueueMessage {
                peer,
                message: Message::GetData(get_data),
            } if *peer == peer_id => {
                assert!(
                    get_data
                        .inv_list
                        .iter()
                        .all(|inv| inv.inv_type == InvType::BLOCK)
                );
                Some(get_data.inv_list.iter().map(|inv| inv.hash).collect())
            }
            _ => None,
        })
        .collect()
}

/// The block hashes of the one getdata queued to the peer.
fn one_get_data(actions: &[Action], peer_id: i32) -> Vec<Hash> {
    let mut found = get_datas(actions, peer_id);
    assert_eq!(found.len(), 1, "expected one getdata in {actions:?}");
    found.remove(0)
}

/// The one getdata queued to the peer, as the message that was queued.
fn one_get_data_message(actions: &[Action], peer_id: i32) -> Message {
    let mut found = actions.iter().filter_map(|action| match action {
        Action::QueueMessage {
            peer,
            message: message @ Message::GetData(_),
        } if *peer == peer_id => Some(message.clone()),
        _ => None,
    });
    let message = found.next().expect("a getdata");
    assert!(
        found.next().is_none(),
        "expected one getdata in {actions:?}"
    );
    message
}

/// The lines the actions log about the width of the download window.
fn window_lines(actions: &[Action]) -> Vec<&str> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Log { level, message } if message.contains("download window") => {
                assert_eq!(*level, LogLevel::Info, "{message}");
                Some(message.as_str())
            }
            _ => None,
        })
        .collect()
}

/// A notfound message for the blocks.
fn not_found(blocks: &[Hash]) -> MsgNotFound {
    MsgNotFound {
        inv_list: blocks
            .iter()
            .map(|hash| InvVect {
                inv_type: InvType::BLOCK,
                hash: *hash,
            })
            .collect(),
    }
}

/// Deliver the chain's block at the index from the peer.
fn deliver(m: &mut Manager, peer: i32, index: usize) -> Vec<Action> {
    let block = MsgBlock {
        header: m.chain_mut().headers[index],
        transactions: Vec::new(),
        stransactions: Vec::new(),
    };
    m.on_block(peer, &block)
}

/// Whether the actions carry dcrd's line for a block that failed
/// validation.
fn logs_a_rejected_block(actions: &[Action]) -> bool {
    actions.iter().any(|action| match action {
        Action::Log { message, .. } => message.starts_with("Rejected block "),
        _ => false,
    })
}

/// How many blocks are requested from the peer and the sum of the sizes
/// their headers carry.
fn outstanding_from(m: &mut Manager, from: i32) -> (usize, u64) {
    let [_, blocks, _] = m.requested_snapshot();
    let chain = m.chain_mut();
    let mut count = 0;
    let mut bytes = 0;
    for (hash, peer) in blocks {
        if peer == from {
            count += 1;
            bytes += u64::from(chain.headers[chain.by_hash[&hash]].size);
        }
    }
    (count, bytes)
}

/// [`outstanding_from`] the sync peer the tests start with.
fn outstanding(m: &mut Manager) -> (usize, u64) {
    outstanding_from(m, SYNC_PEER)
}

/// Add the blocks the actions ask the peer for to the queue of blocks
/// it is to deliver, by index.
fn enqueue(m: &mut Manager, actions: &[Action], peer: i32, queue: &mut VecDeque<usize>) {
    for get_data in get_datas(actions, peer) {
        for hash in get_data {
            queue.push_back(m.chain_mut().by_hash[&hash]);
        }
    }
}

/// Deliver `count` blocks from the peer in the order it was asked for
/// them, queueing what each delivery asks for, and return the lines
/// logged about the width of the window along the way.
fn deliver_in_order(
    m: &mut Manager,
    peer: i32,
    queue: &mut VecDeque<usize>,
    count: usize,
) -> Vec<String> {
    let mut lines = Vec::new();
    for _ in 0..count {
        let index = queue.pop_front().expect("a requested block");
        let actions = deliver(m, peer, index);
        lines.extend(window_lines(&actions).into_iter().map(str::to_string));
        enqueue(m, &actions, peer, queue);
    }
    lines
}

/// A manager built with `SyncManager::new` syncs through dcrd's window:
/// 16 blocks, then nothing until fewer than 10 are requested, then the 7
/// that bring it back to 16.  The dcrd-generated vectors are replayed
/// against a manager built this way, so the budgeted window must be
/// something the daemon asks for, never what the core starts with.
#[test]
fn the_core_defaults_to_dcrds_window() {
    let mut m = dcrd_manager(WindowChain::new(&[1_000; 100]));
    assert_eq!(m.block_window(), BlockWindow::Dcrd);

    let first = one_get_data(&start_sync(&mut m), SYNC_PEER);
    assert_eq!(first, hashes(&mut m, 0..16));
    for index in 0..6 {
        let actions = deliver(&mut m, SYNC_PEER, index);
        assert!(get_datas(&actions, SYNC_PEER).is_empty(), "block {index}");
    }
    let refill = one_get_data(&deliver(&mut m, SYNC_PEER, 6), SYNC_PEER);
    assert_eq!(refill, hashes(&mut m, 16..23));
    assert_eq!(m.requested_block_count(), MAX_IN_FLIGHT_BLOCKS);
}

/// dcrd's window can be put back on a manager that was given the
/// budgeted one, which is what `DCROXIDE_BLOCK_WINDOW=dcrd` does to the
/// daemon's: from then on it asks for exactly what a manager from
/// `SyncManager::new` asks for, from dcrd's list of 512.
#[test]
fn dcrds_window_can_be_put_back() {
    let sizes = [1_000; 100];
    let mut dcrd = dcrd_manager(WindowChain::new(&sizes));
    let mut put_back =
        manager(WindowChain::new(&sizes), main_net_window()).with_block_window(BlockWindow::Dcrd);
    assert_eq!(put_back.block_window(), BlockWindow::Dcrd);

    let first = start_sync(&mut put_back);
    assert_eq!(first, start_sync(&mut dcrd));
    assert_eq!(one_get_data(&first, SYNC_PEER).len(), MAX_IN_FLIGHT_BLOCKS);
    for index in 0..sizes.len() {
        let want = deliver(&mut dcrd, SYNC_PEER, index);
        assert_eq!(
            deliver(&mut put_back, SYNC_PEER, index),
            want,
            "block {index}"
        );
    }
    assert_eq!(put_back.chain_mut().asked, vec![NEXT_BLOCKS_BUF_SIZE]);
    assert_eq!(put_back.chain_mut().asked, dcrd.chain_mut().asked);
}

/// Where blocks are small the count is what limits the window: the
/// first request is for exactly the first 128 needed blocks, in order.
#[test]
fn small_blocks_are_requested_up_to_the_count() {
    let mut m = manager(WindowChain::new(&[1_000; 1_000]), main_net_window());
    assert_eq!(
        m.block_window(),
        BlockWindow::Budget {
            max_bytes: 3_145_728,
            max_blocks: 128,
        }
    );

    let first = one_get_data(&start_sync(&mut m), SYNC_PEER);
    assert_eq!(first, hashes(&mut m, 0..128));
    assert_eq!(m.requested_block_count(), 128);
}

/// Past dcrd's 16 blocks the bytes are what limits the window: a block
/// is requested only while the sizes requested, its own included, stay
/// within the budget, and the budget itself may be reached.  Below 16
/// blocks the budget is not consulted.
#[test]
fn the_byte_budget_stops_the_batch() {
    let first_request = |max_bytes| {
        let mut m = manager(
            WindowChain::new(&[100_000; 300]),
            BlockWindow::Budget {
                max_bytes,
                max_blocks: 128,
            },
        );
        let first = one_get_data(&start_sync(&mut m), SYNC_PEER);
        assert_eq!(first, hashes(&mut m, 0..first.len()));
        first.len()
    };
    assert_eq!(first_request(1_700_000), 17, "exactly the budget fits");
    assert_eq!(first_request(1_699_999), 16, "one byte over does not");
    assert_eq!(first_request(3_100_000), 31);
    assert_eq!(first_request(1_000_000), 16, "the floor is dcrd's window");
    assert_eq!(first_request(0), 16);
}

/// A window built by hand has its count brought into the same bounds as
/// one from `BlockWindow::budget`, so no window can send a getdata that
/// costs ban score or keep fewer blocks requested than dcrd does.
#[test]
fn a_window_built_by_hand_is_clamped() {
    for (asked, want) in [(3, 16), (16, 16), (505, 505), (10_000, 505)] {
        let m = manager(
            WindowChain::new(&[1_000; 4]),
            BlockWindow::Budget {
                max_bytes: 1,
                max_blocks: asked,
            },
        );
        assert_eq!(
            m.block_window(),
            BlockWindow::Budget {
                max_bytes: 1,
                max_blocks: want,
            }
        );
    }
    assert_eq!(MAX_BUDGET_WINDOW_BLOCKS, 505);
}

/// Where every block is the largest the network allows, 16 of them are
/// twice the byte budget, so the floor is all there is and the budgeted
/// window asks for exactly what dcrd's asks for, when dcrd's asks for
/// it: 16, then 7 each time 9 are left, and the last few when 9 are
/// left.
#[test]
fn full_blocks_follow_dcrds_rule() {
    let sizes = [MAX_BLOCK_SIZE; 200];
    let mut dcrd = dcrd_manager(WindowChain::new(&sizes));
    let mut budgeted = manager(WindowChain::new(&sizes), main_net_window());

    assert_eq!(start_sync(&mut dcrd), start_sync(&mut budgeted));
    let mut num_get_datas = 1;
    for index in 0..sizes.len() {
        let want = deliver(&mut dcrd, SYNC_PEER, index);
        let got = deliver(&mut budgeted, SYNC_PEER, index);
        assert_eq!(got, want, "block {index}");
        num_get_datas += get_datas(&got, SYNC_PEER).len();
        assert_eq!(
            budgeted.requested_block_count(),
            dcrd.requested_block_count(),
            "block {index}"
        );
    }
    // 16, then 26 refills of 7, then the last 2.
    assert_eq!(num_get_datas, 28);
    assert_eq!(budgeted.requested_block_count(), 0);
}

/// The budgeted window asks for more as soon as dcrd's refill of 7
/// fits, rather than once fewer than 10 blocks are requested: six
/// delivered blocks ask for nothing, the seventh asks for the next 7,
/// and the window is full again.
#[test]
fn a_refill_goes_out_as_soon_as_dcrds_batch_fits() {
    let mut m = manager(WindowChain::new(&[1_000; 1_000]), main_net_window());
    one_get_data(&start_sync(&mut m), SYNC_PEER);

    let mut next = 128;
    for round in 0..3 {
        for index in round * 7..round * 7 + 6 {
            let actions = deliver(&mut m, SYNC_PEER, index);
            assert!(get_datas(&actions, SYNC_PEER).is_empty(), "block {index}");
        }
        let actions = deliver(&mut m, SYNC_PEER, round * 7 + 6);
        let refill = one_get_data(&actions, SYNC_PEER);
        assert_eq!(refill, hashes(&mut m, next..next + 7), "round {round}");
        next += 7;
        assert_eq!(m.requested_block_count(), 128);
    }
}

/// With fewer than 7 blocks left to ask for, the request waits until
/// fewer than 10 are requested, as dcrd's does: at 10 nothing is sent,
/// at 9 the last 3 are.
#[test]
fn the_last_blocks_are_asked_for_below_dcrds_minimum() {
    let mut m = manager(WindowChain::new(&[1_000; 131]), main_net_window());
    let first = one_get_data(&start_sync(&mut m), SYNC_PEER);
    assert_eq!(first.len(), 128);

    // 118 deliveries leave 10 requested.
    for index in 0..118 {
        let actions = deliver(&mut m, SYNC_PEER, index);
        assert!(get_datas(&actions, SYNC_PEER).is_empty(), "block {index}");
    }
    assert_eq!(m.requested_block_count(), MIN_IN_FLIGHT_BLOCKS);

    let last = one_get_data(&deliver(&mut m, SYNC_PEER, 118), SYNC_PEER);
    assert_eq!(last, hashes(&mut m, 128..131));
    assert_eq!(m.requested_block_count(), 12);
}

/// When the sync peer leaves and nobody else is known to hold what it
/// was asked for, those requests are forgotten.  The next sync peer is
/// asked for the lowest of those blocks first, rather than for the
/// blocks after them, which could only be stored until the missing ones
/// arrived, and for half as many: a window lost with its sync peer is
/// halved.
#[test]
fn a_departed_sync_peers_window_is_asked_for_first() {
    let mut m = manager(WindowChain::new(&[1_000; 1_000]), main_net_window());
    let first = one_get_data(&start_sync(&mut m), SYNC_PEER);
    assert_eq!(first, hashes(&mut m, 0..128));
    connect(&mut m, OTHER_PEER);

    let actions = m.on_peer_disconnected(SYNC_PEER);
    assert_eq!(m.sync_peer_id(), OTHER_PEER);
    assert_eq!(one_get_data(&actions, OTHER_PEER), first[..64]);
    assert_eq!(m.requested_block_count(), 64);
    assert_eq!(m.chain_mut().asked, vec![768, 768]);

    // The rest of the lost window follows in order.
    for index in 0..6 {
        let actions = deliver(&mut m, OTHER_PEER, index);
        assert!(get_datas(&actions, OTHER_PEER).is_empty(), "block {index}");
    }
    let refill = one_get_data(&deliver(&mut m, OTHER_PEER, 6), OTHER_PEER);
    assert_eq!(refill, first[64..71]);
}

/// When another peer is known to hold what the departing sync peer was
/// asked for, the requests move to it and their sizes move with them.
/// As the next sync peer it is asked for nothing more while what moved
/// to it is over the halved budget: with 13 blocks left requested the
/// floor of 16 has room for 3, which is not worth a request, and with 9
/// left it is asked for the 7 that bring it to the floor.  Had the sizes
/// been lost, 10 more blocks would have fitted the budget at 13.
#[test]
fn requests_moved_to_another_peer_keep_their_sizes() {
    let window = BlockWindow::Budget {
        max_bytes: 3_000_000,
        max_blocks: 128,
    };
    let mut m = manager(WindowChain::new(&[150_000; 60]), window);
    let first = one_get_data(&start_sync(&mut m), SYNC_PEER);
    assert_eq!(first, hashes(&mut m, 0..20), "20 blocks fill the budget");
    connect(&mut m, OTHER_PEER);

    // The other peer sends the headers, so it is known to hold the
    // blocks.
    let all = m.chain_mut().headers.clone();
    let actions = m.on_headers(OTHER_PEER, &MsgHeaders { headers: all });
    assert!(get_datas(&actions, SYNC_PEER).is_empty());
    assert!(get_datas(&actions, OTHER_PEER).is_empty());

    let actions = m.on_peer_disconnected(SYNC_PEER);
    assert_eq!(m.sync_peer_id(), OTHER_PEER);
    assert_eq!(
        one_get_data(&actions, OTHER_PEER),
        first,
        "the requests move, and the budget asks for nothing more"
    );
    assert_eq!(m.requested_block_count(), 20);
    assert_eq!(
        m.block_window_in_force(),
        BlockWindow::Budget {
            max_bytes: 1_500_000,
            max_blocks: 64,
        }
    );

    for index in 0..10 {
        let actions = deliver(&mut m, OTHER_PEER, index);
        assert!(get_datas(&actions, OTHER_PEER).is_empty(), "block {index}");
    }
    let refill = one_get_data(&deliver(&mut m, OTHER_PEER, 10), OTHER_PEER);
    assert_eq!(refill, hashes(&mut m, 20..27));
    assert_eq!(m.requested_block_count(), MAX_IN_FLIGHT_BLOCKS);
}

/// Where some of the departing sync peer's requests move to a peer known
/// to hold the blocks and the rest are forgotten, the list of needed
/// blocks is still rebuilt: the forgotten blocks are the next ones asked
/// for, ahead of the blocks after the lost window.
#[test]
fn a_partly_moved_window_still_rebuilds_the_list() {
    let mut m = manager(WindowChain::new(&[1_000; 1_000]), main_net_window());
    one_get_data(&start_sync(&mut m), SYNC_PEER);
    connect(&mut m, OTHER_PEER);

    // The other peer is known to hold the first 64 blocks only.
    let some = m.chain_mut().headers[..64].to_vec();
    let actions = m.on_headers(OTHER_PEER, &MsgHeaders { headers: some });
    assert!(get_datas(&actions, OTHER_PEER).is_empty());

    // Those 64 move to it and fill the halved window; the other 64 are
    // forgotten.
    let actions = m.on_peer_disconnected(SYNC_PEER);
    assert_eq!(m.sync_peer_id(), OTHER_PEER);
    assert_eq!(one_get_data(&actions, OTHER_PEER), hashes(&mut m, 0..64));
    assert_eq!(m.requested_block_count(), 64);

    for index in 0..6 {
        let actions = deliver(&mut m, OTHER_PEER, index);
        assert!(get_datas(&actions, OTHER_PEER).is_empty(), "block {index}");
    }
    let refill = one_get_data(&deliver(&mut m, OTHER_PEER, 6), OTHER_PEER);
    assert_eq!(refill, hashes(&mut m, 64..71));
    assert_eq!(m.chain_mut().asked, vec![768, 768]);
}

/// dcrd's window leaves its list of needed blocks alone when the sync
/// peer leaves (`internal/netsync/manager.go:873-893`, `:938-945`): the
/// next sync peer is asked for the blocks after the forgotten ones, the
/// chain is not asked again, and nothing is narrowed.
#[test]
fn dcrds_window_leaves_the_list_alone_when_the_sync_peer_leaves() {
    let mut m = dcrd_manager(WindowChain::new(&[1_000; 100]));
    let first = one_get_data(&start_sync(&mut m), SYNC_PEER);
    assert_eq!(first, hashes(&mut m, 0..16));
    connect(&mut m, OTHER_PEER);

    let actions = m.on_peer_disconnected(SYNC_PEER);
    assert_eq!(m.sync_peer_id(), OTHER_PEER);
    assert_eq!(one_get_data(&actions, OTHER_PEER), hashes(&mut m, 16..32));
    assert_eq!(m.chain_mut().asked, vec![512]);
    assert!(window_lines(&actions).is_empty(), "{actions:?}");
    assert_eq!(m.block_window_in_force(), BlockWindow::Dcrd);
}

/// Nor is dcrd's window narrowed by a sync peer that leaves with more
/// than 16 blocks requested from it, which the requests made outside the
/// window can come to under dcrd's rule as well
/// (`internal/netsync/manager.go:2086-2120`).  With 20 more requested
/// from the sync peer, its departure logs nothing about the window, and
/// the next sync peer is asked for what dcrd asks it for, from the list
/// as it was.
#[test]
fn dcrds_window_is_not_narrowed_by_more_than_its_count_requested() {
    let mut m = dcrd_manager(WindowChain::new(&[1_000; 100]));
    let first = one_get_data(&start_sync(&mut m), SYNC_PEER);
    assert_eq!(first, hashes(&mut m, 0..16));
    let extra = hashes(&mut m, 50..70);
    m.request_from_peer(SYNC_PEER, &extra, &[], &[]);
    assert_eq!(outstanding(&mut m).0, 36);
    connect(&mut m, OTHER_PEER);

    let actions = m.on_peer_disconnected(SYNC_PEER);
    assert_eq!(m.sync_peer_id(), OTHER_PEER);
    assert!(window_lines(&actions).is_empty(), "{actions:?}");
    assert_eq!(m.block_window_in_force(), BlockWindow::Dcrd);
    assert_eq!(m.block_window(), BlockWindow::Dcrd);
    assert_eq!(one_get_data(&actions, OTHER_PEER), hashes(&mut m, 16..32));
    assert_eq!(m.chain_mut().asked, vec![512]);
}

/// dcrd's window does not rebuild its list for a block reported as not
/// found either: `OnNotFound` only deletes the request
/// (`internal/netsync/manager.go:1803-1828`), so the next refill is for
/// the blocks after the window.
#[test]
fn dcrds_window_leaves_the_list_alone_after_a_notfound() {
    let mut m = dcrd_manager(WindowChain::new(&[1_000; 100]));
    one_get_data(&start_sync(&mut m), SYNC_PEER);

    let missing = hashes(&mut m, 10..13);
    m.on_not_found(SYNC_PEER, &not_found(&missing));
    assert_eq!(m.requested_block_count(), 13);

    // Ten are left requested after three deliveries, nine after four.
    for index in 0..3 {
        let actions = deliver(&mut m, SYNC_PEER, index);
        assert!(get_datas(&actions, SYNC_PEER).is_empty(), "block {index}");
    }
    let refill = one_get_data(&deliver(&mut m, SYNC_PEER, 3), SYNC_PEER);
    assert_eq!(refill, hashes(&mut m, 16..23));
    assert_eq!(m.chain_mut().asked, vec![512]);
}

/// dcrd's refill counts every requested block, whoever it was requested
/// from, and only a block from the sync peer triggers it
/// (`internal/netsync/manager.go:1361-1370`).  With one block requested
/// from another peer, seven deliveries from the sync peer leave ten
/// requested in all and ask for nothing; the other peer's block leaves
/// nine and asks for nothing, of either peer; the sync peer's next block
/// leaves eight and asks for eight.
#[test]
fn dcrds_refill_counts_every_request_and_only_the_sync_peer_triggers_it() {
    let mut m = dcrd_manager(WindowChain::new(&[1_000; 100]));
    one_get_data(&start_sync(&mut m), SYNC_PEER);
    connect(&mut m, OTHER_PEER);
    let elsewhere = hashes(&mut m, 50..51);
    let actions = m.request_from_peer(OTHER_PEER, &elsewhere, &[], &[]);
    assert_eq!(one_get_data(&actions, OTHER_PEER), elsewhere);

    for index in 0..7 {
        let actions = deliver(&mut m, SYNC_PEER, index);
        assert!(get_datas(&actions, SYNC_PEER).is_empty(), "block {index}");
    }
    assert_eq!(m.requested_block_count(), MIN_IN_FLIGHT_BLOCKS);

    let actions = deliver(&mut m, OTHER_PEER, 50);
    assert!(get_datas(&actions, SYNC_PEER).is_empty(), "{actions:?}");
    assert!(get_datas(&actions, OTHER_PEER).is_empty(), "{actions:?}");
    assert_eq!(m.requested_block_count(), 9);

    let refill = one_get_data(&deliver(&mut m, SYNC_PEER, 7), SYNC_PEER);
    assert_eq!(refill, hashes(&mut m, 16..24));
}

/// A block the sync peer reports as not found is forgotten, and is the
/// first block asked for again, ahead of the blocks that build on it.
#[test]
fn a_block_reported_not_found_is_asked_for_again() {
    let mut m = manager(WindowChain::new(&[1_000; 1_000]), main_net_window());
    one_get_data(&start_sync(&mut m), SYNC_PEER);

    let missing = hashes(&mut m, 10..13);
    m.on_not_found(SYNC_PEER, &not_found(&missing));
    assert_eq!(m.requested_block_count(), 125);

    // Three more deliveries make room for dcrd's batch of 7.
    for index in 0..3 {
        let actions = deliver(&mut m, SYNC_PEER, index);
        assert!(get_datas(&actions, SYNC_PEER).is_empty(), "block {index}");
    }
    let refill = one_get_data(&deliver(&mut m, SYNC_PEER, 3), SYNC_PEER);
    let mut want = missing;
    want.extend(hashes(&mut m, 128..132));
    assert_eq!(refill, want);
    assert_eq!(m.requested_block_count(), 128);
}

/// A block another path requested while it waited in the list is passed
/// over when the window reaches it: it is not asked for a second time,
/// and it takes no place in the sync peer's window.
#[test]
fn a_block_requested_elsewhere_is_passed_over() {
    let mut m = manager(WindowChain::new(&[1_000; 1_000]), main_net_window());
    one_get_data(&start_sync(&mut m), SYNC_PEER);
    connect(&mut m, OTHER_PEER);

    let elsewhere = hashes(&mut m, 130..131);
    let actions = m.request_from_peer(OTHER_PEER, &elsewhere, &[], &[]);
    assert_eq!(one_get_data(&actions, OTHER_PEER), elsewhere);

    for index in 0..6 {
        let actions = deliver(&mut m, SYNC_PEER, index);
        assert!(get_datas(&actions, SYNC_PEER).is_empty(), "block {index}");
    }
    let refill = one_get_data(&deliver(&mut m, SYNC_PEER, 6), SYNC_PEER);
    let mut want = hashes(&mut m, 128..130);
    want.extend(hashes(&mut m, 131..136));
    assert_eq!(refill, want);
    assert_eq!(outstanding(&mut m).0, 128);
    assert_eq!(m.requested_block_count(), 129);
}

/// A block delivered by a peer other than the sync peer asks for
/// nothing, of either peer: only the sync peer's deliveries refill the
/// window, so no second window opens on whoever else delivers a block.
#[test]
fn a_block_from_another_peer_opens_no_window_on_it() {
    let mut m = manager(WindowChain::new(&[1_000; 1_000]), main_net_window());
    one_get_data(&start_sync(&mut m), SYNC_PEER);
    connect(&mut m, OTHER_PEER);
    let elsewhere = hashes(&mut m, 130..131);
    let actions = m.request_from_peer(OTHER_PEER, &elsewhere, &[], &[]);
    assert_eq!(one_get_data(&actions, OTHER_PEER), elsewhere);

    let actions = deliver(&mut m, OTHER_PEER, 130);
    assert!(get_datas(&actions, OTHER_PEER).is_empty(), "{actions:?}");
    assert!(get_datas(&actions, SYNC_PEER).is_empty(), "{actions:?}");
    assert_eq!(outstanding(&mut m), (128, 128_000));
    assert_eq!(m.requested_block_count(), 128);
}

/// The minimum below which whatever fits is asked for counts the blocks
/// requested from the sync peer alone, where dcrd's counts every
/// requested block.  With one block requested from another peer and two
/// left to ask for, nine requested from the sync peer are ten in all,
/// and the two are asked for.
#[test]
fn the_minimum_counts_the_sync_peers_requests_alone() {
    let mut m = manager(WindowChain::new(&[1_000; 131]), main_net_window());
    let first = one_get_data(&start_sync(&mut m), SYNC_PEER);
    assert_eq!(first.len(), 128);
    connect(&mut m, OTHER_PEER);
    let elsewhere = hashes(&mut m, 130..131);
    let actions = m.request_from_peer(OTHER_PEER, &elsewhere, &[], &[]);
    assert_eq!(one_get_data(&actions, OTHER_PEER), elsewhere);

    for index in 0..118 {
        let actions = deliver(&mut m, SYNC_PEER, index);
        assert!(get_datas(&actions, SYNC_PEER).is_empty(), "block {index}");
    }
    assert_eq!(outstanding(&mut m).0, MIN_IN_FLIGHT_BLOCKS);

    let last = one_get_data(&deliver(&mut m, SYNC_PEER, 118), SYNC_PEER);
    assert_eq!(last, hashes(&mut m, 128..130));
    assert_eq!(outstanding(&mut m).0, 11);
    assert_eq!(m.requested_block_count(), 12);
}

/// A block that fails validation asks for nothing, as in dcrd, whose
/// handler returns before its refill; its place in the window is free
/// for the next block that is accepted, by count and by bytes.
#[test]
fn a_rejected_block_frees_its_place() {
    // (window, blocks first requested): one limited by its count and
    // one by its bytes.
    let cases = [
        (main_net_window(), 1_000, 128),
        (
            BlockWindow::Budget {
                max_bytes: 3_100_000,
                max_blocks: 128,
            },
            100_000,
            31,
        ),
    ];
    for (window, size, first_len) in cases {
        let mut chain = WindowChain::new(&[size; 400]);
        // The seventh delivery, on which an accepted block asks for 7.
        chain.reject_once.insert(6);
        let mut m = manager(chain, window);
        let first = one_get_data(&start_sync(&mut m), SYNC_PEER);
        assert_eq!(first.len(), first_len);

        for index in 0..6 {
            let actions = deliver(&mut m, SYNC_PEER, index);
            assert!(get_datas(&actions, SYNC_PEER).is_empty(), "block {index}");
        }
        let actions = deliver(&mut m, SYNC_PEER, 6);
        assert!(logs_a_rejected_block(&actions), "{actions:?}");
        assert!(
            get_datas(&actions, SYNC_PEER).is_empty(),
            "a rejected block asks for nothing: {actions:?}"
        );
        assert_eq!(m.requested_block_count(), first_len - 7);

        // The next accepted block finds room for 8: its own place, the
        // rejected block's and the six before it.
        let refill = one_get_data(&deliver(&mut m, SYNC_PEER, 7), SYNC_PEER);
        assert_eq!(refill, hashes(&mut m, first_len..first_len + 8));
        assert_eq!(
            outstanding(&mut m),
            (first_len, first_len as u64 * u64::from(size))
        );
    }
}

/// The list of needed blocks is longer than dcrd's by twice the window,
/// so more than dcrd's 512 blocks are requested before the list next
/// runs short, whatever the window is set to.
#[test]
fn the_lookahead_is_larger_than_the_window() {
    let asked_for = |window: Option<BlockWindow>| {
        let chain = WindowChain::new(&[1_000; 2_000]);
        let mut m = match window {
            Some(window) => manager(chain, window),
            None => dcrd_manager(chain),
        };
        start_sync(&mut m);
        m.chain_mut().asked.clone()
    };
    assert_eq!(NEXT_BLOCKS_BUF_SIZE, 512);
    assert_eq!(asked_for(None), vec![512]);
    assert_eq!(asked_for(Some(main_net_window())), vec![512 + 2 * 128]);
    assert_eq!(
        asked_for(Some(BlockWindow::budget(MAX_BLOCK_SIZE as usize, 16))),
        vec![512 + 2 * 16]
    );
    assert_eq!(
        asked_for(Some(BlockWindow::budget(MAX_BLOCK_SIZE as usize, 505))),
        vec![512 + 2 * 505]
    );
}

/// A list that a whole window emptied is rebuilt.  dcrd's rule rebuilds
/// only a list of one to nine entries, so a list emptied in one request
/// stays empty until the best header moves and the sync stops; its own
/// batches of 16 and 7 never empty a list of 512, and a window whose
/// batches vary can.
///
/// The smallest window (16 blocks, a list of 544) is emptied here by 33
/// whole windows in a row: each window's blocks all fail validation,
/// which asks for nothing, and the next headers message asks for the
/// next 16.
#[test]
fn a_list_emptied_by_a_whole_window_is_rebuilt() {
    let mut chain = WindowChain::new(&[1_000; 1_000]);
    chain.reject_once.extend(0..528);
    let mut m = manager(chain, BlockWindow::budget(MAX_BLOCK_SIZE as usize, 16));

    let mut requested = one_get_data(&start_sync(&mut m), SYNC_PEER);
    assert_eq!(requested, hashes(&mut m, 0..16));
    for round in 0..33 {
        for index in round * 16..round * 16 + 16 {
            let actions = deliver(&mut m, SYNC_PEER, index);
            assert!(get_datas(&actions, SYNC_PEER).is_empty(), "block {index}");
        }
        assert_eq!(m.requested_block_count(), 0);
        requested = one_get_data(&best_header_from(&mut m, SYNC_PEER), SYNC_PEER);
        assert_eq!(
            requested,
            hashes(&mut m, round * 16 + 16..round * 16 + 32),
            "round {round}"
        );
    }
    // The list was built once and has now given out all 544 entries.
    assert_eq!(m.chain_mut().asked, vec![544]);
    assert_eq!(requested, hashes(&mut m, 528..544));

    // The seventh accepted block leaves 9 requested, and the request it
    // makes starts at the lowest block still needed: the ones that
    // failed, which the rebuilt list begins with.
    for index in 528..534 {
        let actions = deliver(&mut m, SYNC_PEER, index);
        assert!(get_datas(&actions, SYNC_PEER).is_empty(), "block {index}");
    }
    let refill = one_get_data(&deliver(&mut m, SYNC_PEER, 534), SYNC_PEER);
    assert_eq!(refill, hashes(&mut m, 0..7));
    assert_eq!(m.chain_mut().asked, vec![544, 544]);
}

/// Once the chain has nothing more to ask for, the list is not rebuilt
/// on every fetch: an empty answer from the chain means the list ran to
/// the best header, until that header changes.
#[test]
fn a_synced_node_does_not_rebuild_the_list_on_every_fetch() {
    let mut chain = WindowChain::new(&[1_000; 20]);
    for index in 0..20 {
        chain.store(index);
    }
    let mut m = manager(chain, main_net_window());

    assert!(get_datas(&start_sync(&mut m), SYNC_PEER).is_empty());
    for _ in 0..3 {
        assert!(get_datas(&best_header_from(&mut m, SYNC_PEER), SYNC_PEER).is_empty());
    }
    assert_eq!(m.chain_mut().asked, vec![768]);
}

/// Nor is it rebuilt when the chain returned exactly as many blocks as
/// it was asked for and the last of them is the best header: the list
/// ran to that header although it came back full.  The smallest window
/// asks for 544 blocks, and a chain of exactly 544 is synced from the
/// one list.
#[test]
fn a_full_list_that_ends_at_the_best_header_is_not_asked_for_again() {
    const NUM_BLOCKS: usize = 544;
    let window = BlockWindow::budget(MAX_BLOCK_SIZE as usize, 16);
    let mut m = manager(WindowChain::new(&[1_000; NUM_BLOCKS]), window);

    let mut queue: VecDeque<usize> = VecDeque::new();
    let mut next_to_ask = 0;
    let mut actions = start_sync(&mut m);
    loop {
        for get_data in get_datas(&actions, SYNC_PEER) {
            queue.extend(next_to_ask..next_to_ask + get_data.len());
            next_to_ask += get_data.len();
        }
        let Some(index) = queue.pop_front() else {
            break;
        };
        actions = deliver(&mut m, SYNC_PEER, index);
    }
    assert_eq!(next_to_ask, NUM_BLOCKS);
    assert!(m.chain_mut().have_data.iter().all(|have| *have));
    assert_eq!(m.chain_mut().asked, vec![NUM_BLOCKS]);
}

/// A block whose header the chain cannot supply has no size to count,
/// so it counts as larger than any budget: it stops the window short,
/// and is requested only once it is within dcrd's 16, with nothing
/// behind it past them.
#[test]
fn a_block_without_a_size_is_requested_within_dcrds_window_only() {
    let mut chain = WindowChain::new(&[1_000; 1_000]);
    chain.no_header.insert(20);
    let mut m = manager(chain, main_net_window());

    let first = one_get_data(&start_sync(&mut m), SYNC_PEER);
    assert_eq!(first, hashes(&mut m, 0..20));

    // With 9 requested, 7 more make 16: the block and the 6 after it.
    for index in 0..10 {
        let actions = deliver(&mut m, SYNC_PEER, index);
        assert!(get_datas(&actions, SYNC_PEER).is_empty(), "block {index}");
    }
    let refill = one_get_data(&deliver(&mut m, SYNC_PEER, 10), SYNC_PEER);
    assert_eq!(refill, hashes(&mut m, 20..27));
    assert_eq!(m.requested_block_count(), MAX_IN_FLIGHT_BLOCKS);
}

/// Selecting a window empties the list of needed blocks, so a list built
/// under dcrd's window, whose entries carry no sizes, is not read by the
/// budgeted one.  The 16 blocks dcrd's window requested count as blocks
/// of no bytes, and 17 blocks of 100,000 bytes fit a budget of
/// 1,700,000 on top of them; with the old list kept, every block would
/// weigh nothing and 112 would be asked for.
#[test]
fn selecting_a_window_empties_the_list() {
    let mut m = dcrd_manager(WindowChain::new(&[100_000; 300]));
    let first = one_get_data(&start_sync(&mut m), SYNC_PEER);
    assert_eq!(first, hashes(&mut m, 0..16));

    let mut m = m.with_block_window(BlockWindow::Budget {
        max_bytes: 1_700_000,
        max_blocks: 128,
    });
    let more = one_get_data(&best_header_from(&mut m, SYNC_PEER), SYNC_PEER);
    assert_eq!(more, hashes(&mut m, 16..33));
    assert_eq!(m.chain_mut().asked, vec![512, 768]);
}

/// A sync peer that leaves with more blocks requested from it than
/// dcrd's window asks of a sync peer halves the window, bytes and count,
/// for the next sync peer, and says so.  Three halvings bring the default
/// down to dcrd's 16 blocks, where a departing sync peer narrows nothing
/// further and the requests follow dcrd's pattern: 16, then 7 each time 9
/// are left.
#[test]
fn a_lost_window_is_halved_down_to_dcrds() {
    let mut m = manager(WindowChain::new(&[1_000; 1_000]), main_net_window());
    let first = one_get_data(&start_sync(&mut m), SYNC_PEER);
    assert_eq!(first.len(), 128);
    assert_eq!(m.block_window_in_force(), main_net_window());

    // (departing sync peer, next sync peer, blocks and bytes in force
    // afterwards)
    let steps = [
        (SYNC_PEER, 8, 64, 1_572_864),
        (8, 9, 32, 786_432),
        (9, 10, 16, 393_216),
    ];
    let mut lost = 128;
    for (leaving, next, max_blocks, max_bytes) in steps {
        connect(&mut m, next);
        let actions = m.on_peer_disconnected(leaving);
        assert_eq!(m.sync_peer_id(), next);
        assert_eq!(
            window_lines(&actions),
            vec![format!(
                "Block download window narrowed to at most {max_blocks} blocks in flight: the \
                 sync peer left with {lost} requested"
            )]
        );
        assert_eq!(
            m.block_window_in_force(),
            BlockWindow::Budget {
                max_bytes,
                max_blocks,
            }
        );
        assert_eq!(
            m.block_window(),
            main_net_window(),
            "the window selected is unchanged"
        );
        assert_eq!(one_get_data(&actions, next), first[..max_blocks]);
        assert_eq!(m.requested_block_count(), max_blocks);
        lost = max_blocks;
    }

    // At dcrd's 16 there is nothing left to halve, even when the sync
    // peer leaves with a block more than the window requested from it.
    let extra = hashes(&mut m, 500..501);
    m.request_from_peer(10, &extra, &[], &[]);
    assert_eq!(outstanding_from(&mut m, 10).0, 17);
    connect(&mut m, 11);
    let actions = m.on_peer_disconnected(10);
    assert_eq!(m.sync_peer_id(), 11);
    assert!(window_lines(&actions).is_empty(), "{actions:?}");
    assert_eq!(
        m.block_window_in_force(),
        BlockWindow::Budget {
            max_bytes: 393_216,
            max_blocks: 16,
        }
    );
    assert_eq!(one_get_data(&actions, 11), first[..16]);
    for index in 0..6 {
        let actions = deliver(&mut m, 11, index);
        assert!(get_datas(&actions, 11).is_empty(), "block {index}");
    }
    let refill = one_get_data(&deliver(&mut m, 11, 6), 11);
    assert_eq!(refill, first[16..23]);
    assert_eq!(m.requested_block_count(), MAX_IN_FLIGHT_BLOCKS);
}

/// The byte budget is halved with the count.  Blocks of 50,000 bytes fill
/// the budget at 62; the next sync peer is asked for the 31 that fill
/// half of it, well under the halved count of 64.
#[test]
fn the_byte_budget_is_halved_with_the_count() {
    let mut m = manager(WindowChain::new(&[50_000; 400]), main_net_window());
    let first = one_get_data(&start_sync(&mut m), SYNC_PEER);
    assert_eq!(first, hashes(&mut m, 0..62));
    connect(&mut m, OTHER_PEER);

    let actions = m.on_peer_disconnected(SYNC_PEER);
    assert_eq!(
        window_lines(&actions),
        vec![
            "Block download window narrowed to at most 64 blocks in flight: the sync peer left \
             with 62 requested"
        ]
    );
    assert_eq!(one_get_data(&actions, OTHER_PEER), first[..31]);
    assert_eq!(outstanding_from(&mut m, OTHER_PEER), (31, 1_550_000));

    // Selecting a window again puts it at its full width.
    let m = m.with_block_window(main_net_window());
    assert_eq!(m.block_window_in_force(), main_net_window());
}

/// A sync peer that leaves with no more requested than dcrd's window has
/// narrows nothing: that is all dcrd would have lost.  Full blocks keep
/// the default window at 16 requested, and a window set to 16 blocks has
/// no more than that requested of any blocks.
#[test]
fn a_sync_peer_leaving_with_dcrds_window_requested_narrows_nothing() {
    let cases = [
        (main_net_window(), MAX_BLOCK_SIZE),
        (BlockWindow::budget(MAX_BLOCK_SIZE as usize, 16), 1_000),
    ];
    for (window, size) in cases {
        let mut m = manager(WindowChain::new(&[size; 200]), window);
        let first = one_get_data(&start_sync(&mut m), SYNC_PEER);
        assert_eq!(first.len(), MAX_IN_FLIGHT_BLOCKS);
        connect(&mut m, OTHER_PEER);

        let actions = m.on_peer_disconnected(SYNC_PEER);
        assert!(window_lines(&actions).is_empty(), "{actions:?}");
        assert_eq!(m.block_window_in_force(), window);
        assert_eq!(one_get_data(&actions, OTHER_PEER), first);
    }
}

/// One block more than dcrd's window asks of a sync peer is enough to
/// narrow.  A window of 17 blocks lost with its sync peer is halved to
/// dcrd's 16.  So is a window of 128 that its bytes held to 17: blocks of
/// 100,000 bytes fill a budget of 1,700,000 at 17, and the next sync peer
/// is asked for the floor of 16, which is already over half that budget.
#[test]
fn a_sync_peer_leaving_with_seventeen_requested_narrows() {
    // (window, block size, blocks and bytes in force afterwards)
    let cases = [
        (
            BlockWindow::budget(MAX_BLOCK_SIZE as usize, 17),
            1_000,
            16,
            1_572_864,
        ),
        (
            BlockWindow::Budget {
                max_bytes: 1_700_000,
                max_blocks: 128,
            },
            100_000,
            64,
            850_000,
        ),
    ];
    for (window, size, max_blocks, max_bytes) in cases {
        let mut m = manager(WindowChain::new(&[size; 200]), window);
        let first = one_get_data(&start_sync(&mut m), SYNC_PEER);
        assert_eq!(first.len(), 17);
        connect(&mut m, OTHER_PEER);

        let actions = m.on_peer_disconnected(SYNC_PEER);
        assert_eq!(
            window_lines(&actions),
            vec![format!(
                "Block download window narrowed to at most {max_blocks} blocks in flight: the \
                 sync peer left with 17 requested"
            )]
        );
        assert_eq!(
            m.block_window_in_force(),
            BlockWindow::Budget {
                max_bytes,
                max_blocks,
            }
        );
        assert_eq!(one_get_data(&actions, OTHER_PEER), first[..16]);
    }
}

/// What narrows the window is what was requested from the sync peer.
/// Full blocks keep 16 requested from it, and 20 more requested from
/// another peer leave the window as it is when the sync peer leaves.
#[test]
fn only_the_sync_peers_requests_count_toward_a_narrowing() {
    let mut m = manager(WindowChain::new(&[MAX_BLOCK_SIZE; 200]), main_net_window());
    let first = one_get_data(&start_sync(&mut m), SYNC_PEER);
    assert_eq!(first.len(), MAX_IN_FLIGHT_BLOCKS);
    connect(&mut m, OTHER_PEER);
    connect(&mut m, THIRD_PEER);
    let elsewhere = hashes(&mut m, 100..120);
    m.request_from_peer(THIRD_PEER, &elsewhere, &[], &[]);
    assert_eq!(m.requested_block_count(), 36);

    let actions = m.on_peer_disconnected(SYNC_PEER);
    assert_eq!(m.sync_peer_id(), OTHER_PEER);
    assert!(window_lines(&actions).is_empty(), "{actions:?}");
    assert_eq!(m.block_window_in_force(), main_net_window());
    assert_eq!(one_get_data(&actions, OTHER_PEER), first);
}

/// A halving is undone once one sync peer has had sixteen times the
/// window's full count of blocks accepted since: 2,048 at the default,
/// after the first narrowing.  The block that completes them widens the
/// window, says so, and is answered with a request that fills the wider
/// window.
#[test]
fn a_narrowed_window_is_widened_after_sixteen_windows_of_blocks() {
    assert_eq!(WINDOW_RECOVERY_WINDOWS * BUDGET_WINDOW_BLOCKS, 2_048);
    let mut m = manager(WindowChain::new(&[1_000; 2_500]), main_net_window());
    start_sync(&mut m);
    connect(&mut m, OTHER_PEER);
    let actions = m.on_peer_disconnected(SYNC_PEER);
    let halved = BlockWindow::Budget {
        max_bytes: 1_572_864,
        max_blocks: 64,
    };
    assert_eq!(m.block_window_in_force(), halved);
    let mut queue = VecDeque::new();
    enqueue(&mut m, &actions, OTHER_PEER, &mut queue);

    let lines = deliver_in_order(&mut m, OTHER_PEER, &mut queue, 2_047);
    assert!(lines.is_empty(), "{lines:?}");
    assert_eq!(m.block_window_in_force(), halved);
    assert!(m.requested_block_count() <= 64);

    let lines = deliver_in_order(&mut m, OTHER_PEER, &mut queue, 1);
    assert_eq!(
        lines,
        vec![
            "Block download window widened to at most 128 blocks in flight after 2048 blocks \
             from the sync peer"
        ]
    );
    assert_eq!(m.block_window_in_force(), main_net_window());
    assert_eq!(m.requested_block_count(), 128);
}

/// The line a window of 17 blocks logs when its one halving is undone.
const WIDENED_TO_17: &str = "Block download window widened to at most 17 blocks in flight after \
                             272 blocks from the sync peer";

/// A manager whose window of 17 blocks was halved to dcrd's 16 when its
/// first sync peer left, and the blocks its next sync peer, `OTHER_PEER`,
/// was asked for.  16 x 17 = 272 blocks from one sync peer undo the
/// halving.
fn narrowed_window_of_17(chain: WindowChain) -> (Manager, VecDeque<usize>) {
    let mut m = manager(chain, BlockWindow::budget(MAX_BLOCK_SIZE as usize, 17));
    start_sync(&mut m);
    connect(&mut m, OTHER_PEER);
    let actions = m.on_peer_disconnected(SYNC_PEER);
    assert_eq!(window_lines(&actions).len(), 1, "{actions:?}");
    assert_eq!(m.sync_peer_id(), OTHER_PEER);
    let mut queue = VecDeque::new();
    enqueue(&mut m, &actions, OTHER_PEER, &mut queue);
    assert_eq!(queue.len(), 16);
    (m, queue)
}

/// A window back at its full width is left alone: as many blocks again
/// as undid its halving, and more, pass without a line.
#[test]
fn a_window_at_full_width_is_not_widened_again() {
    let (mut m, mut queue) = narrowed_window_of_17(WindowChain::new(&[1_000; 1_000]));
    let lines = deliver_in_order(&mut m, OTHER_PEER, &mut queue, 272);
    assert_eq!(lines, vec![WIDENED_TO_17]);

    let lines = deliver_in_order(&mut m, OTHER_PEER, &mut queue, 300);
    assert!(lines.is_empty(), "{lines:?}");
    assert_eq!(
        m.block_window_in_force(),
        BlockWindow::budget(MAX_BLOCK_SIZE as usize, 17)
    );
    assert!(m.requested_block_count() <= 17);
}

/// A sync peer that leaves with more than dcrd's window requested when
/// there is nothing left to halve is not a narrowing: the next widening
/// is no further off for it.
#[test]
fn a_window_lost_at_dcrds_count_is_not_a_narrowing() {
    let (mut m, _) = narrowed_window_of_17(WindowChain::new(&[1_000; 1_000]));

    // The 16 blocks of the window and one asked for outside it.
    let extra = hashes(&mut m, 900..901);
    m.request_from_peer(OTHER_PEER, &extra, &[], &[]);
    assert_eq!(outstanding_from(&mut m, OTHER_PEER).0, 17);
    connect(&mut m, THIRD_PEER);
    let actions = m.on_peer_disconnected(OTHER_PEER);
    assert_eq!(m.sync_peer_id(), THIRD_PEER);
    assert!(window_lines(&actions).is_empty(), "{actions:?}");

    let mut queue = VecDeque::new();
    enqueue(&mut m, &actions, THIRD_PEER, &mut queue);
    let lines = deliver_in_order(&mut m, THIRD_PEER, &mut queue, 271);
    assert!(lines.is_empty(), "{lines:?}");
    let lines = deliver_in_order(&mut m, THIRD_PEER, &mut queue, 1);
    assert_eq!(lines, vec![WIDENED_TO_17]);
}

/// Only a block the chain accepts counts toward a widening.  One that
/// fails validation and one the chain already has are passed over, and
/// neither starts the count again: 274 deliveries are 272 accepted
/// blocks.
#[test]
fn rejected_and_duplicate_blocks_do_not_count_toward_a_widening() {
    let mut chain = WindowChain::new(&[1_000; 1_000]);
    chain.reject_once.insert(100);
    chain.duplicate_once.insert(200);
    let (mut m, mut queue) = narrowed_window_of_17(chain);

    let lines = deliver_in_order(&mut m, OTHER_PEER, &mut queue, 273);
    assert!(lines.is_empty(), "{lines:?}");
    assert_eq!(m.chain_mut().num_stored, 271);
    let lines = deliver_in_order(&mut m, OTHER_PEER, &mut queue, 1);
    assert_eq!(lines, vec![WIDENED_TO_17]);
}

/// A block the chain stores on a side chain is an accepted block, and
/// counts toward a widening like any other: what the count shows is that
/// the path to the sync peer carries the window, whichever branch the
/// block lands on.
#[test]
fn a_block_accepted_onto_a_side_chain_counts_toward_a_widening() {
    let mut chain = WindowChain::new(&[1_000; 1_000]);
    chain.side_chain.insert(100);
    let (mut m, mut queue) = narrowed_window_of_17(chain);
    let lines = deliver_in_order(&mut m, OTHER_PEER, &mut queue, 271);
    assert!(lines.is_empty(), "{lines:?}");
    let lines = deliver_in_order(&mut m, OTHER_PEER, &mut queue, 1);
    assert_eq!(lines, vec![WIDENED_TO_17]);
}

/// Only the sync peer's blocks count toward a widening.  A block another
/// peer delivers is not counted and does not start the count again, and
/// neither does that peer leaving: the sync peer's 272nd block widens
/// the window.
#[test]
fn a_block_from_another_peer_leaves_the_widening_count_alone() {
    let (mut m, mut queue) = narrowed_window_of_17(WindowChain::new(&[1_000; 1_000]));
    let lines = deliver_in_order(&mut m, OTHER_PEER, &mut queue, 100);
    assert!(lines.is_empty(), "{lines:?}");

    connect(&mut m, THIRD_PEER);
    let elsewhere = hashes(&mut m, 900..901);
    m.request_from_peer(THIRD_PEER, &elsewhere, &[], &[]);
    let actions = deliver(&mut m, THIRD_PEER, 900);
    assert!(window_lines(&actions).is_empty(), "{actions:?}");
    assert!(get_datas(&actions, THIRD_PEER).is_empty(), "{actions:?}");
    let actions = m.on_peer_disconnected(THIRD_PEER);
    assert!(window_lines(&actions).is_empty(), "{actions:?}");
    assert_eq!(m.sync_peer_id(), OTHER_PEER);

    let lines = deliver_in_order(&mut m, OTHER_PEER, &mut queue, 171);
    assert!(lines.is_empty(), "{lines:?}");
    let lines = deliver_in_order(&mut m, OTHER_PEER, &mut queue, 1);
    assert_eq!(lines, vec![WIDENED_TO_17]);
}

/// Nothing but selecting a window puts a narrowed one back, and the end
/// of the initial chain sync is no exception: the window stays as it is,
/// and the blocks counted toward its widening still count.  The chain
/// reports itself current with the 101st block from the sync peer, and
/// that peer's 272nd widens the window.
#[test]
fn a_narrowed_window_outlasts_the_end_of_the_sync() {
    let (mut m, mut queue) = narrowed_window_of_17(WindowChain::new(&[1_000; 1_000]));
    let lines = deliver_in_order(&mut m, OTHER_PEER, &mut queue, 100);
    assert!(lines.is_empty(), "{lines:?}");
    assert!(!m.initial_chain_sync_done());

    m.chain_mut().current = true;
    let lines = deliver_in_order(&mut m, OTHER_PEER, &mut queue, 1);
    assert!(m.initial_chain_sync_done());
    assert!(lines.is_empty(), "{lines:?}");
    assert_eq!(
        m.block_window_in_force(),
        BlockWindow::Budget {
            max_bytes: 1_572_864,
            max_blocks: 16,
        }
    );

    let lines = deliver_in_order(&mut m, OTHER_PEER, &mut queue, 170);
    assert!(lines.is_empty(), "{lines:?}");
    let lines = deliver_in_order(&mut m, OTHER_PEER, &mut queue, 1);
    assert_eq!(lines, vec![WIDENED_TO_17]);
}

/// A narrowed window still rebuilds its list of needed blocks by its
/// full count.  Halved to 64, the default window rebuilds the list once
/// fewer than 128 blocks are left in it, not once fewer than 64 are: of
/// the 704 left after the first request, 83 refills of 7 leave 123, and
/// the next block the sync peer delivers asks the chain again.
#[test]
fn a_narrowed_window_rebuilds_the_list_by_its_full_count() {
    let mut m = manager(WindowChain::new(&[1_000; 2_000]), main_net_window());
    start_sync(&mut m);
    connect(&mut m, OTHER_PEER);
    let actions = m.on_peer_disconnected(SYNC_PEER);
    assert_eq!(m.chain_mut().asked, vec![768, 768]);
    let mut queue = VecDeque::new();
    enqueue(&mut m, &actions, OTHER_PEER, &mut queue);
    assert_eq!(queue.len(), 64);

    deliver_in_order(&mut m, OTHER_PEER, &mut queue, 83 * 7);
    assert_eq!(m.chain_mut().asked, vec![768, 768]);
    deliver_in_order(&mut m, OTHER_PEER, &mut queue, 1);
    assert_eq!(m.chain_mut().asked, vec![768, 768, 768]);
}

/// Each narrowing puts the next widening further off.  A window of 32
/// blocks is undone its first halving by 512 blocks from one sync peer
/// and its second by 1,024.  Selecting a window starts the count of
/// narrowings again.
#[test]
fn each_narrowing_puts_the_next_widening_further_off() {
    let window = BlockWindow::budget(MAX_BLOCK_SIZE as usize, 32);
    let narrowed = "Block download window narrowed to at most 16 blocks in flight: the sync peer \
                    left with 32 requested";
    let widened = |num_blocks: usize| {
        vec![format!(
            "Block download window widened to at most 32 blocks in flight after {num_blocks} \
             blocks from the sync peer"
        )]
    };
    let mut m = manager(WindowChain::new(&[1_000; 3_000]), window);
    start_sync(&mut m);
    connect(&mut m, OTHER_PEER);
    let actions = m.on_peer_disconnected(SYNC_PEER);
    assert_eq!(window_lines(&actions), vec![narrowed]);
    let mut queue = VecDeque::new();
    enqueue(&mut m, &actions, OTHER_PEER, &mut queue);

    // The first narrowing is undone by 16 x 32 blocks.
    let lines = deliver_in_order(&mut m, OTHER_PEER, &mut queue, 511);
    assert!(lines.is_empty(), "{lines:?}");
    let lines = deliver_in_order(&mut m, OTHER_PEER, &mut queue, 1);
    assert_eq!(lines, widened(512));

    // The same sync peer leaves with the widened window requested, 7
    // blocks later, and there is nobody else to sync from.
    let lines = deliver_in_order(&mut m, OTHER_PEER, &mut queue, 7);
    assert!(lines.is_empty(), "{lines:?}");
    let actions = m.on_peer_disconnected(OTHER_PEER);
    assert_eq!(window_lines(&actions), vec![narrowed]);
    assert_eq!(m.sync_peer_id(), 0);

    // It connects again.  The second narrowing is undone by twice as
    // many blocks.
    let actions = connect(&mut m, OTHER_PEER);
    assert_eq!(m.sync_peer_id(), OTHER_PEER);
    let mut queue = VecDeque::new();
    enqueue(&mut m, &actions, OTHER_PEER, &mut queue);
    assert_eq!(queue.len(), 16);
    let lines = deliver_in_order(&mut m, OTHER_PEER, &mut queue, 1_023);
    assert!(lines.is_empty(), "{lines:?}");
    let lines = deliver_in_order(&mut m, OTHER_PEER, &mut queue, 1);
    assert_eq!(lines, widened(1_024));
    assert_eq!(m.block_window_in_force(), window);

    // The window selected again has never been narrowed: its first
    // narrowing is undone by 512 blocks.
    let mut m = m.with_block_window(window);
    connect(&mut m, THIRD_PEER);
    let actions = m.on_peer_disconnected(OTHER_PEER);
    assert_eq!(m.sync_peer_id(), THIRD_PEER);
    assert_eq!(window_lines(&actions).len(), 1, "{actions:?}");
    let mut queue = VecDeque::new();
    enqueue(&mut m, &actions, THIRD_PEER, &mut queue);
    let lines = deliver_in_order(&mut m, THIRD_PEER, &mut queue, 511);
    assert!(lines.is_empty(), "{lines:?}");
    let lines = deliver_in_order(&mut m, THIRD_PEER, &mut queue, 1);
    assert_eq!(lines, widened(512));
}

/// Halvings are undone one at a time, each by its own blocks, counted
/// from the last change of the window.  A window of 64 blocks halved
/// twice is widened to 32 by 2,048 blocks from one sync peer (16 x 64
/// for each of the two narrowings) and to 64 by 2,048 more.  The 105
/// blocks accepted between the two narrowings count for nothing
/// afterwards, even for a peer that connects under the same id.
#[test]
fn halvings_are_undone_one_at_a_time() {
    let window = BlockWindow::budget(MAX_BLOCK_SIZE as usize, 64);
    let mut m = manager(WindowChain::new(&[1_000; 4_500]), window);
    start_sync(&mut m);
    connect(&mut m, OTHER_PEER);
    let actions = m.on_peer_disconnected(SYNC_PEER);
    let mut queue = VecDeque::new();
    enqueue(&mut m, &actions, OTHER_PEER, &mut queue);
    let lines = deliver_in_order(&mut m, OTHER_PEER, &mut queue, 105);
    assert!(lines.is_empty(), "{lines:?}");

    let actions = m.on_peer_disconnected(OTHER_PEER);
    assert_eq!(
        window_lines(&actions),
        vec![
            "Block download window narrowed to at most 16 blocks in flight: the sync peer left \
             with 32 requested"
        ]
    );
    assert_eq!(
        m.block_window_in_force(),
        BlockWindow::Budget {
            max_bytes: 786_432,
            max_blocks: 16,
        }
    );
    let actions = connect(&mut m, OTHER_PEER);
    let mut queue = VecDeque::new();
    enqueue(&mut m, &actions, OTHER_PEER, &mut queue);

    for max_blocks in [32, 64] {
        let lines = deliver_in_order(&mut m, OTHER_PEER, &mut queue, 2_047);
        assert!(lines.is_empty(), "{lines:?}");
        let lines = deliver_in_order(&mut m, OTHER_PEER, &mut queue, 1);
        assert_eq!(
            lines,
            vec![format!(
                "Block download window widened to at most {max_blocks} blocks in flight after \
                 2048 blocks from the sync peer"
            )]
        );
    }
    assert_eq!(m.block_window_in_force(), window);
}

/// A peer that is not the sync peer narrows nothing by leaving, however
/// many blocks were requested from it: the window is the sync peer's.
#[test]
fn a_peer_that_is_not_the_sync_peer_narrows_nothing() {
    let mut m = manager(WindowChain::new(&[1_000; 1_000]), main_net_window());
    one_get_data(&start_sync(&mut m), SYNC_PEER);
    connect(&mut m, OTHER_PEER);
    let elsewhere = hashes(&mut m, 200..220);
    m.request_from_peer(OTHER_PEER, &elsewhere, &[], &[]);
    assert_eq!(outstanding_from(&mut m, OTHER_PEER).0, 20);

    let actions = m.on_peer_disconnected(OTHER_PEER);
    assert!(window_lines(&actions).is_empty(), "{actions:?}");
    assert_eq!(m.block_window_in_force(), main_net_window());
    assert_eq!(m.sync_peer_id(), SYNC_PEER);
    assert_eq!(m.requested_block_count(), 128);
}

/// The blocks that widen a narrowed window are one sync peer's: what
/// they show is that the path to that peer carries the window as it is.
/// A sync peer that leaves with dcrd's window requested narrows nothing,
/// and the count starts again with the next one.
#[test]
fn the_blocks_that_widen_a_window_come_from_one_sync_peer() {
    // Small blocks to lose a wide window with, then full blocks, which
    // keep no more than 16 requested.
    let mut sizes = vec![1_000; 300];
    sizes.extend([MAX_BLOCK_SIZE; 2_300]);
    let mut m = manager(WindowChain::new(&sizes), main_net_window());
    start_sync(&mut m);
    connect(&mut m, OTHER_PEER);
    let actions = m.on_peer_disconnected(SYNC_PEER);
    let halved = BlockWindow::Budget {
        max_bytes: 1_572_864,
        max_blocks: 64,
    };
    assert_eq!(m.block_window_in_force(), halved);
    let mut queue = VecDeque::new();
    enqueue(&mut m, &actions, OTHER_PEER, &mut queue);

    // 400 blocks from one sync peer, which then leaves.
    let lines = deliver_in_order(&mut m, OTHER_PEER, &mut queue, 400);
    assert!(lines.is_empty(), "{lines:?}");
    assert!(outstanding_from(&mut m, OTHER_PEER).0 <= MAX_IN_FLIGHT_BLOCKS);
    connect(&mut m, THIRD_PEER);
    let actions = m.on_peer_disconnected(OTHER_PEER);
    assert_eq!(m.sync_peer_id(), THIRD_PEER);
    assert!(window_lines(&actions).is_empty(), "{actions:?}");
    assert_eq!(m.block_window_in_force(), halved);
    let mut queue = VecDeque::new();
    enqueue(&mut m, &actions, THIRD_PEER, &mut queue);

    // The next sync peer's 1,648th block would be the 2,048th in all.
    let lines = deliver_in_order(&mut m, THIRD_PEER, &mut queue, 2_047);
    assert!(lines.is_empty(), "{lines:?}");
    assert_eq!(m.block_window_in_force(), halved);
    let lines = deliver_in_order(&mut m, THIRD_PEER, &mut queue, 1);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(m.block_window_in_force(), main_net_window());
}

/// The best header moves to another branch while a window is requested.
/// The next request lists the new branch from its first missing block,
/// nothing is asked for twice, and the blocks of the old branch that
/// were already requested still make room for more as they arrive.
#[test]
fn a_best_header_on_another_branch_is_followed_without_asking_twice() {
    let mut chain = WindowChain::new(&[1_000; 400]);
    let branch = chain.fork(100, &[1_000; 200]);
    assert_eq!(branch, 400..600);
    let mut m = manager(chain, main_net_window());
    let first = one_get_data(&start_sync(&mut m), SYNC_PEER);
    assert_eq!(first, hashes(&mut m, 0..128));

    // The sync peer announces the other branch, which becomes the best.
    m.chain_mut().follow(100, branch.clone());
    let headers = m.chain_mut().headers[branch.clone()].to_vec();
    let actions = m.on_headers(SYNC_PEER, &MsgHeaders { headers });
    assert!(get_datas(&actions, SYNC_PEER).is_empty(), "{actions:?}");

    // Every block of the first request arrives, the 28 that are no
    // longer on the best branch included.
    let mut asked = first.clone();
    let mut next_on_branch = branch.start;
    for index in 0..128 {
        let actions = deliver(&mut m, SYNC_PEER, index);
        let refills = get_datas(&actions, SYNC_PEER);
        assert_eq!(refills.len(), usize::from(index % 7 == 6), "block {index}");
        for refill in refills {
            assert_eq!(
                refill,
                hashes(&mut m, next_on_branch..next_on_branch + 7),
                "block {index}"
            );
            next_on_branch += 7;
            asked.extend(refill);
        }
    }
    assert_eq!(next_on_branch, branch.start + 126);
    assert_eq!(m.requested_block_count(), 126);
    assert_eq!(
        asked.iter().collect::<HashSet<_>>().len(),
        asked.len(),
        "no block is asked for twice"
    );
    // One list for the first branch and one for the second.
    assert_eq!(m.chain_mut().asked, vec![768, 768]);
}

/// A peer that is not the sync peer leaves with a block requested from
/// it that nobody else is known to hold.  The request is forgotten, the
/// window is not narrowed, and the block heads the sync peer's next
/// request although the window had already passed it over.
#[test]
fn a_request_forgotten_with_another_peer_is_asked_for_next() {
    let mut m = manager(WindowChain::new(&[1_000; 1_000]), main_net_window());
    one_get_data(&start_sync(&mut m), SYNC_PEER);
    connect(&mut m, OTHER_PEER);
    let elsewhere = hashes(&mut m, 130..131);
    m.request_from_peer(OTHER_PEER, &elsewhere, &[], &[]);

    // The window passes the block over.
    for index in 0..6 {
        deliver(&mut m, SYNC_PEER, index);
    }
    let refill = one_get_data(&deliver(&mut m, SYNC_PEER, 6), SYNC_PEER);
    let mut want = hashes(&mut m, 128..130);
    want.extend(hashes(&mut m, 131..136));
    assert_eq!(refill, want);

    let actions = m.on_peer_disconnected(OTHER_PEER);
    assert!(get_datas(&actions, SYNC_PEER).is_empty(), "{actions:?}");
    assert!(window_lines(&actions).is_empty(), "{actions:?}");
    assert_eq!(m.sync_peer_id(), SYNC_PEER);
    assert_eq!(m.block_window_in_force(), main_net_window());
    assert_eq!(m.requested_block_count(), 128);

    for index in 7..13 {
        let actions = deliver(&mut m, SYNC_PEER, index);
        assert!(get_datas(&actions, SYNC_PEER).is_empty(), "block {index}");
    }
    let refill = one_get_data(&deliver(&mut m, SYNC_PEER, 13), SYNC_PEER);
    let mut want = elsewhere;
    want.extend(hashes(&mut m, 136..142));
    assert_eq!(refill, want);
    assert_eq!(m.chain_mut().asked, vec![768, 768]);
}

/// A refill the outbound queue refused, with the rest of the window
/// still requested, is given back and forgotten.  The sync peer keeps
/// the chain sync, nothing is narrowed, and the next block it delivers
/// asks for the same blocks again with the one its own place allows.
#[test]
fn a_refused_refill_is_asked_for_again_with_the_next_block() {
    let mut m = manager(WindowChain::new(&[1_000; 1_000]), main_net_window());
    one_get_data(&start_sync(&mut m), SYNC_PEER);
    connect(&mut m, OTHER_PEER);
    for index in 0..6 {
        deliver(&mut m, SYNC_PEER, index);
    }
    let actions = deliver(&mut m, SYNC_PEER, 6);
    assert_eq!(one_get_data(&actions, SYNC_PEER), hashes(&mut m, 128..135));
    let refused = one_get_data_message(&actions, SYNC_PEER);

    let actions = m.on_request_not_sent(SYNC_PEER, &refused, &BTreeSet::from([SYNC_PEER]));
    assert!(get_datas(&actions, SYNC_PEER).is_empty(), "{actions:?}");
    assert!(get_datas(&actions, OTHER_PEER).is_empty(), "{actions:?}");
    assert_eq!(m.sync_peer_id(), SYNC_PEER);
    assert_eq!(m.requested_block_count(), 121);

    let again = one_get_data(&deliver(&mut m, SYNC_PEER, 7), SYNC_PEER);
    assert_eq!(again, hashes(&mut m, 128..136));
    assert_eq!(m.requested_block_count(), 128);
    assert_eq!(m.block_window_in_force(), main_net_window());
}

/// A first window the outbound queue refused leaves the sync peer with
/// nothing requested, so the chain sync is handed to the next candidate,
/// which is asked for the same window: the lowest missing blocks, at the
/// full width, since no peer left.
#[test]
fn a_refused_first_window_goes_to_the_next_candidate() {
    let mut m = manager(WindowChain::new(&[1_000; 1_000]), main_net_window());
    connect(&mut m, SYNC_PEER);
    connect(&mut m, OTHER_PEER);
    let actions = best_header_from(&mut m, SYNC_PEER);
    assert_eq!(m.sync_peer_id(), SYNC_PEER);
    assert_eq!(one_get_data(&actions, SYNC_PEER), hashes(&mut m, 0..128));
    let refused = one_get_data_message(&actions, SYNC_PEER);

    let actions = m.on_request_not_sent(SYNC_PEER, &refused, &BTreeSet::from([SYNC_PEER]));
    assert_eq!(m.sync_peer_id(), OTHER_PEER);
    assert_eq!(one_get_data(&actions, OTHER_PEER), hashes(&mut m, 0..128));
    assert!(get_datas(&actions, SYNC_PEER).is_empty(), "{actions:?}");
    assert!(window_lines(&actions).is_empty(), "{actions:?}");
    assert_eq!(m.block_window_in_force(), main_net_window());
    assert_eq!(m.chain_mut().asked, vec![768, 768]);
}

/// Once the chain is current a block announced by header is asked of the
/// peer that announced it, as in dcrd, and the fetch that ends the
/// handler asks the sync peer for nothing: the block is already
/// requested.  Its delivery by the announcer asks for nothing either.
#[test]
fn an_announced_block_is_asked_of_its_announcer_once_current() {
    let mut chain = WindowChain::new(&[1_000; 21]);
    // The last block is not known yet; the 20 before it are all stored.
    chain.best_branch.pop();
    for index in 0..20 {
        chain.store(index);
    }
    chain.current = true;
    let mut m = manager(chain, main_net_window());
    assert!(get_datas(&start_sync(&mut m), SYNC_PEER).is_empty());
    assert!(m.initial_chain_sync_done());
    connect(&mut m, OTHER_PEER);

    let tip = m.chain_mut().headers[20];
    let actions = m.on_headers(OTHER_PEER, &MsgHeaders { headers: vec![tip] });
    assert_eq!(m.chain_mut().best_header().0, tip.block_hash());
    assert_eq!(one_get_data(&actions, OTHER_PEER), hashes(&mut m, 20..21));
    assert!(get_datas(&actions, SYNC_PEER).is_empty(), "{actions:?}");
    assert_eq!(m.requested_block_count(), 1);

    let actions = deliver(&mut m, OTHER_PEER, 20);
    assert!(get_datas(&actions, OTHER_PEER).is_empty(), "{actions:?}");
    assert!(get_datas(&actions, SYNC_PEER).is_empty(), "{actions:?}");
    assert_eq!(m.requested_block_count(), 0);
}

/// Every block requested from the sync peer counts toward a narrowing,
/// whichever path asked for it.  A node that is current is announced 20
/// headers by its sync peer and asks it for all 20 blocks at once, as
/// dcrd does (`internal/netsync/manager.go:1751-1776`); the window asked
/// for none of them.  The sync peer leaves, and the window is halved for
/// the next one, which is asked for the same blocks.
#[test]
fn blocks_the_sync_peer_announced_count_toward_a_narrowing() {
    let mut chain = WindowChain::new(&[1_000; 40]);
    // The last 20 blocks are not known yet; the 20 before them are all
    // stored.
    chain.best_branch.truncate(20);
    for index in 0..20 {
        chain.store(index);
    }
    chain.current = true;
    let mut m = manager(chain, main_net_window());
    assert!(get_datas(&start_sync(&mut m), SYNC_PEER).is_empty());

    let announced = m.chain_mut().headers[20..40].to_vec();
    let actions = m.on_headers(SYNC_PEER, &MsgHeaders { headers: announced });
    assert_eq!(one_get_data(&actions, SYNC_PEER), hashes(&mut m, 20..40));
    assert_eq!(m.block_window_in_force(), main_net_window());
    connect(&mut m, OTHER_PEER);

    let actions = m.on_peer_disconnected(SYNC_PEER);
    assert_eq!(m.sync_peer_id(), OTHER_PEER);
    assert_eq!(
        window_lines(&actions),
        vec![
            "Block download window narrowed to at most 64 blocks in flight: the sync peer left \
             with 20 requested"
        ]
    );
    assert_eq!(
        m.block_window_in_force(),
        BlockWindow::Budget {
            max_bytes: 1_572_864,
            max_blocks: 64,
        }
    );
    assert_eq!(one_get_data(&actions, OTHER_PEER), hashes(&mut m, 20..40));
}

/// A sync peer that answers its whole window with notfound has nothing
/// left requested and is not asked again by the notfound itself, as in
/// dcrd.  The next headers message asks it for the same blocks, in one
/// request, at the full width: no peer left.
///
/// This is the manager for a notfound it is told about.  The server bans
/// a peer whose notfound takes its ban score past the threshold, at 20
/// points a block and so with six blocks at the default of 100, without
/// passing the message on, as dcrd's does (`server.go:1890-1896`).  The
/// manager is therefore told of a notfound for 128 blocks only with
/// banning disabled or for a whitelisted peer.  Any other sync peer that
/// sends one leaves with its window requested, and that narrows the
/// window like any other departure.
#[test]
fn a_window_answered_not_found_is_asked_for_again_on_the_next_headers() {
    let mut m = manager(WindowChain::new(&[1_000; 1_000]), main_net_window());
    let first = one_get_data(&start_sync(&mut m), SYNC_PEER);
    assert_eq!(first.len(), 128);

    m.on_not_found(SYNC_PEER, &not_found(&first));
    assert_eq!(m.requested_block_count(), 0);
    assert_eq!(m.sync_peer_id(), SYNC_PEER);

    let again = one_get_data(&best_header_from(&mut m, SYNC_PEER), SYNC_PEER);
    assert_eq!(again, first);
    assert_eq!(m.block_window_in_force(), main_net_window());
    assert_eq!(m.chain_mut().asked, vec![768, 768]);
}

/// The sizes of a chain that mixes runs of tiny, medium and full
/// blocks, from a fixed generator.
fn mixed_sizes(count: usize) -> Vec<u32> {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut sizes = Vec::with_capacity(count);
    while sizes.len() < count {
        let run = 1 + (next() % 60) as usize;
        let kind = next() % 4;
        for _ in 0..run {
            let size = match kind {
                0 => 300 + (next() % 3_000) as u32,
                1 => 20_000 + (next() % 60_000) as u32,
                2 => 150_000 + (next() % 150_000) as u32,
                _ => MAX_BLOCK_SIZE - (next() % 30_000) as u32,
            };
            sizes.push(size);
        }
    }
    sizes.truncate(count);
    sizes
}

/// A whole sync stays inside the window.  Every block is delivered in
/// the order it was asked for, and after every delivery:
///
/// - each getdata asks for the lowest blocks not yet asked for, in
///   order, so no block is asked for twice or passed over;
/// - at most 128 blocks are requested, and past dcrd's 16 their sizes
///   are within the budget;
/// - no getdata is larger than the window, so none costs ban score, and
///   none but the last is smaller than dcrd's refill of 7;
/// - a block accepted with fewer than 10 left requested, and more to ask
///   for, asks for more, as dcrd's rule does.
///
/// The sync ends with every block asked for and delivered, the best
/// header never having moved, and with no more getdata messages than
/// dcrd's window needs for as many blocks: one of 16 and then one for
/// every 7.
#[test]
fn a_whole_sync_stays_inside_the_window() {
    const NUM_BLOCKS: usize = 2_000;
    let sizes = mixed_sizes(NUM_BLOCKS);
    assert!(sizes.iter().any(|size| *size < 1_000));
    assert!(sizes.iter().any(|size| *size > 380_000));
    let BlockWindow::Budget {
        max_bytes,
        max_blocks,
    } = main_net_window()
    else {
        unreachable!("the main network window is budgeted")
    };

    let mut m = manager(WindowChain::new(&sizes), main_net_window());
    let all = hashes(&mut m, 0..NUM_BLOCKS);
    let mut next_to_ask = 0;
    let mut queue = VecDeque::new();
    let mut num_get_datas = 0;
    let mut widest = 0;

    let mut actions = start_sync(&mut m);
    let mut delivered = 0;
    loop {
        let asked = get_datas(&actions, SYNC_PEER);
        assert!(asked.len() <= 1, "one getdata at most: {actions:?}");
        for get_data in &asked {
            num_get_datas += 1;
            assert!(get_data.len() <= max_blocks, "{} items", get_data.len());
            assert_eq!(
                get_data[..],
                all[next_to_ask..next_to_ask + get_data.len()],
                "after {delivered} blocks"
            );
            queue.extend(next_to_ask..next_to_ask + get_data.len());
            next_to_ask += get_data.len();
            assert!(
                get_data.len() >= 7 || next_to_ask == NUM_BLOCKS,
                "{} items after {delivered} blocks",
                get_data.len()
            );
        }

        let (count, bytes) = outstanding(&mut m);
        assert_eq!(count, queue.len());
        assert_eq!(count, m.requested_block_count());
        assert!(count <= max_blocks, "{count} blocks requested");
        assert!(
            count <= MAX_IN_FLIGHT_BLOCKS || bytes <= max_bytes,
            "{count} blocks of {bytes} bytes requested after {delivered} blocks"
        );
        widest = widest.max(count);
        assert!(
            count >= MIN_IN_FLIGHT_BLOCKS || next_to_ask == NUM_BLOCKS,
            "{count} blocks requested after {delivered} blocks and nothing asked for"
        );

        let Some(index) = queue.pop_front() else {
            break;
        };
        actions = deliver(&mut m, SYNC_PEER, index);
        delivered += 1;
    }
    assert_eq!(delivered, NUM_BLOCKS);
    assert_eq!(next_to_ask, NUM_BLOCKS);
    assert!(m.chain_mut().have_data.iter().all(|have| *have));
    assert_eq!(widest, max_blocks, "the tiny runs fill the count");
    // The list of 768 was rebuilt along the way, without the best header
    // moving.
    assert!(m.chain_mut().asked.len() >= 3, "{:?}", m.chain_mut().asked);
    assert!(
        num_get_datas <= 1 + (NUM_BLOCKS - MAX_IN_FLIGHT_BLOCKS).div_ceil(7),
        "{num_get_datas} getdata messages"
    );
}

/// What the next sync peer is known to hold of the blocks requested from
/// a sync peer that leaves.
#[derive(Clone, Copy, Debug)]
enum Holds {
    /// None of them: every request is forgotten.
    Nothing,
    /// The lower half of their heights: those requests move to it, and
    /// the rest are forgotten.
    Half,
    /// All of them: every request moves to it.
    All,
}

/// When a sync peer leaves: at the first point after it has delivered
/// `after` blocks at which it has more than dcrd's 16 blocks requested
/// from it (`wide`), or no more than those 16.
#[derive(Clone, Copy, Debug)]
struct Departure {
    after: usize,
    wide: bool,
}

/// What a sync through departures came to.
#[derive(Debug, Default)]
struct Seen {
    /// Departures that narrowed the window, and those that did not.
    narrowings: usize,
    quiet_departures: usize,
    widenings: usize,
    /// The fewest blocks a window in force allowed, and the most that
    /// were requested from a sync peer after a request by the window.
    narrowest: usize,
    widest: usize,
    /// Requests that moved to the next sync peer, and requests that
    /// were forgotten.
    moved: usize,
    forgotten: usize,
}

/// A sync from a succession of sync peers.  Each delivers the blocks it
/// was asked for, in the order it was asked, and then leaves.  The rule
/// that narrows and widens the window is kept here beside the manager's,
/// and every event is held to it and to what the window allows.
struct DepartureSync {
    m: Manager,
    all: Vec<Hash>,
    full_bytes: u64,
    full_blocks: usize,
    /// The sync peer, and the blocks requested from it in the order it
    /// is to deliver them.
    sync: i32,
    queue: VecDeque<usize>,
    /// How many times the window is halved at present, how many times it
    /// has been narrowed, and how many blocks the sync peer has had
    /// accepted since the window last changed.
    halvings: u32,
    narrowings: usize,
    accepted: usize,
    seen: Seen,
}

impl DepartureSync {
    /// Start the sync of a chain of the sizes from its first sync peer.
    fn start(window: BlockWindow, sizes: &[u32]) -> DepartureSync {
        let BlockWindow::Budget {
            max_bytes: full_bytes,
            max_blocks: full_blocks,
        } = window
        else {
            unreachable!("dcrd's window is never narrowed")
        };
        let mut m = manager(WindowChain::new(sizes), window);
        let all = hashes(&mut m, 0..sizes.len());
        let actions = start_sync(&mut m);
        let mut sync = DepartureSync {
            m,
            all,
            full_bytes,
            full_blocks,
            sync: SYNC_PEER,
            queue: VecDeque::new(),
            halvings: 0,
            narrowings: 0,
            accepted: 0,
            seen: Seen {
                narrowest: full_blocks,
                ..Seen::default()
            },
        };
        sync.absorb(&actions, &BTreeSet::new(), &[], "the first request");
        sync
    }

    /// The bytes and the blocks of the window in force by the rule.
    fn in_force(&self) -> (u64, usize) {
        (
            self.full_bytes >> self.halvings,
            (self.full_blocks >> self.halvings).max(MAX_IN_FLIGHT_BLOCKS),
        )
    }

    /// Hold the actions of one event to the rule and to the window, and
    /// queue what they ask the sync peer for.  `moved` are the requests
    /// expected to move to the sync peer, and `lines` what is expected
    /// to be logged about the window.
    fn absorb(
        &mut self,
        actions: &[Action],
        moved: &BTreeSet<usize>,
        lines: &[String],
        event: &str,
    ) {
        assert_eq!(window_lines(actions), lines, "{event}");
        let (max_bytes, max_blocks) = self.in_force();
        assert_eq!(
            self.m.block_window_in_force(),
            BlockWindow::Budget {
                max_bytes,
                max_blocks,
            },
            "{event}"
        );
        assert!(max_blocks >= MAX_IN_FLIGHT_BLOCKS, "{event}");
        self.seen.narrowest = self.seen.narrowest.min(max_blocks);

        // Only the sync peer is asked for blocks.
        for action in actions {
            if let Action::QueueMessage {
                peer,
                message: Message::GetData(_),
            } = action
            {
                assert_eq!(*peer, self.sync, "{event}");
            }
        }
        let mut asked = get_datas(actions, self.sync).into_iter();

        // The requests that moved come first and whole, in one message
        // that is not held to the window.
        if !moved.is_empty() {
            let get_data = asked.next().expect("the requests that moved");
            let chain = self.m.chain_mut();
            let indexes: Vec<usize> = get_data.iter().map(|hash| chain.by_hash[hash]).collect();
            assert_eq!(indexes.len(), moved.len(), "{event}");
            assert_eq!(
                indexes.iter().copied().collect::<BTreeSet<_>>(),
                *moved,
                "{event}"
            );
            self.queue.extend(indexes);
        }

        // Then one request by the window at most: for the lowest blocks
        // that are neither stored nor requested, in order, and within
        // the count and the bytes in force together with what the peer
        // already has requested from it.
        if let Some(get_data) = asked.next() {
            let requested: HashSet<usize> = self.queue.iter().copied().collect();
            let chain = self.m.chain_mut();
            let lowest: Vec<usize> = (0..self.all.len())
                .filter(|index| !chain.have_data[*index] && !requested.contains(index))
                .take(get_data.len())
                .collect();
            let wanted: Vec<Hash> = lowest.iter().map(|index| self.all[*index]).collect();
            assert_eq!(get_data, wanted, "{event}");
            assert!(
                self.queue.len() + get_data.len() <= max_blocks,
                "{event}: {} more blocks asked for with {} requested and {max_blocks} allowed",
                get_data.len(),
                self.queue.len()
            );
            self.queue.extend(lowest);
            let (count, bytes) = outstanding_from(&mut self.m, self.sync);
            assert!(
                count <= MAX_IN_FLIGHT_BLOCKS || bytes <= max_bytes,
                "{event}: {count} blocks of {bytes} bytes requested with {max_bytes} allowed"
            );
            self.seen.widest = self.seen.widest.max(count);
        }
        assert!(asked.next().is_none(), "{event}: {actions:?}");

        // Every request is the sync peer's.  A fetch has just run for
        // it, so either it has dcrd's minimum requested from it or no
        // block is left to ask for.
        let count = self.queue.len();
        assert_eq!(outstanding_from(&mut self.m, self.sync).0, count, "{event}");
        assert_eq!(self.m.requested_block_count(), count, "{event}");
        let num_stored = self.m.chain_mut().num_stored;
        assert!(
            count >= MIN_IN_FLIGHT_BLOCKS || num_stored + count == self.all.len(),
            "{event}: {count} blocks requested with {num_stored} stored"
        );
    }

    /// The sync peer delivers the next block it was asked for.
    fn deliver_next(&mut self) {
        let index = self.queue.pop_front().expect("a requested block");
        let mut lines = Vec::new();
        if self.halvings > 0 {
            self.accepted += 1;
            let num_needed = WINDOW_RECOVERY_WINDOWS * self.full_blocks * self.narrowings;
            if self.accepted == num_needed {
                self.halvings -= 1;
                self.accepted = 0;
                self.seen.widenings += 1;
                lines.push(format!(
                    "Block download window widened to at most {} blocks in flight after \
                     {num_needed} blocks from the sync peer",
                    self.in_force().1
                ));
            }
        }
        let actions = deliver(&mut self.m, self.sync, index);
        self.absorb(
            &actions,
            &BTreeSet::new(),
            &lines,
            &format!("block {index}"),
        );
    }

    /// The next sync peer announces the headers of the blocks at the
    /// indexes, so it is known to hold them.
    fn announce(&mut self, peer: i32, indexes: std::ops::RangeInclusive<usize>) {
        let headers = self.m.chain_mut().headers[indexes].to_vec();
        let actions = self.m.on_headers(peer, &MsgHeaders { headers });
        // The handler ends with a fetch for the sync peer.
        self.absorb(
            &actions,
            &BTreeSet::new(),
            &[],
            "headers from the next sync peer",
        );
    }

    /// The sync peer leaves and the next one takes over.
    fn sync_peer_leaves(&mut self, holds: Holds) {
        let next = self.sync + 1;
        let actions = connect(&mut self.m, next);
        self.absorb(
            &actions,
            &BTreeSet::new(),
            &[],
            "the next sync peer connects",
        );

        let range = |queue: &VecDeque<usize>| {
            let lowest = *queue.iter().min().expect("a requested block");
            let highest = *queue.iter().max().expect("a requested block");
            (lowest, highest)
        };
        match holds {
            Holds::Nothing => {}
            Holds::Half => {
                let (lowest, highest) = range(&self.queue);
                self.announce(next, lowest..=lowest + (highest - lowest) / 2);
            }
            Holds::All => {
                // Announcing may make room for a request to the sync
                // peer, whose blocks are then announced as well.
                let (lowest, highest) = range(&self.queue);
                self.announce(next, lowest..=highest);
                let (lowest, highest) = range(&self.queue);
                self.announce(next, lowest..=highest);
            }
        }
        let moved: BTreeSet<usize> = self
            .queue
            .iter()
            .copied()
            .filter(|index| {
                let inv = InvVect {
                    inv_type: InvType::BLOCK,
                    hash: self.all[*index],
                };
                self.m.peer_holds(next, &inv)
            })
            .collect();

        // The rule: more than dcrd's 16 requested from the sync peer
        // that leaves halves a window that is above 16, and the blocks
        // counted toward a widening were the departed peer's.
        let num_requested = self.queue.len();
        let mut lines = Vec::new();
        if num_requested > MAX_IN_FLIGHT_BLOCKS && self.in_force().1 > MAX_IN_FLIGHT_BLOCKS {
            self.halvings += 1;
            self.narrowings += 1;
            self.seen.narrowings += 1;
            lines.push(format!(
                "Block download window narrowed to at most {} blocks in flight: the sync peer \
                 left with {num_requested} requested",
                self.in_force().1
            ));
        } else {
            self.seen.quiet_departures += 1;
        }
        self.accepted = 0;
        self.seen.moved += moved.len();
        self.seen.forgotten += num_requested - moved.len();

        let leaving = std::mem::replace(&mut self.sync, next);
        self.queue.clear();
        let actions = self.m.on_peer_disconnected(leaving);
        assert_eq!(self.m.sync_peer_id(), next);
        self.absorb(&actions, &moved, &lines, &format!("peer {leaving} leaves"));
    }
}

/// Sync a chain of the sizes through the departures, the last sync peer
/// delivering what is left, and return what the sync came to.  Every
/// block is stored at the end and nothing is left requested.
fn sync_through_departures(
    window: BlockWindow,
    sizes: &[u32],
    departures: &[Departure],
    holds: Holds,
) -> Seen {
    let mut sync = DepartureSync::start(window, sizes);
    for departure in departures {
        let mut num_delivered = 0;
        while num_delivered < departure.after
            || (sync.queue.len() > MAX_IN_FLIGHT_BLOCKS) != departure.wide
        {
            sync.deliver_next();
            num_delivered += 1;
        }
        sync.sync_peer_leaves(holds);
    }
    while !sync.queue.is_empty() {
        sync.deliver_next();
    }
    assert!(sync.m.chain_mut().have_data.iter().all(|have| *have));
    assert_eq!(sync.m.requested_block_count(), 0);
    sync.seen
}

/// A departure once the sync peer has delivered `after` blocks and has
/// more than 16 requested from it.
fn wide(after: usize) -> Departure {
    Departure { after, wide: true }
}

/// A departure once the sync peer has delivered `after` blocks and has
/// no more than 16 requested from it.
fn quiet(after: usize) -> Departure {
    Departure { after, wide: false }
}

/// A chain that begins with a run of small blocks, so that the first
/// request fills the count of any window, and goes on with mixed runs.
fn small_then_mixed_sizes(num_small: usize, num_mixed: usize) -> Vec<u32> {
    let mut sizes = vec![1_000; num_small];
    sizes.extend(mixed_sizes(num_mixed));
    sizes
}

/// A whole sync through sync peers that leave stays inside the window in
/// force and ends with every block stored.  The window is one block
/// wider than dcrd's, so 16 x 17 blocks undo its first narrowing and
/// twice as many its second.  After every event:
///
/// - the lines logged about the window, and the window in force, are
///   what the rule gives, and the window never allows fewer than 16
///   blocks;
/// - the requests of a departed sync peer that the next one is known to
///   hold move to it whole, and no other peer is asked for a block;
/// - each request by the window is for the lowest blocks that are
///   neither stored nor requested, in order, and brings the blocks
///   requested from the sync peer to no more than the count in force
///   and, past dcrd's 16, their sizes to no more than the bytes in force;
/// - the sync peer has at least dcrd's minimum of 10 blocks requested
///   from it, unless no block is left to ask for.
///
/// Where nothing moves, the window is narrowed three times and widened
/// twice, and the last departure finds it at 16 blocks with nothing to
/// narrow.  Where half or all of the requests move, on a shorter chain,
/// it is narrowed twice and widened once.
#[test]
fn a_sync_through_departures_stays_inside_a_window_of_17() {
    let window = BlockWindow::budget(MAX_BLOCK_SIZE as usize, 17);
    let seen = sync_through_departures(
        window,
        &small_then_mixed_sizes(30, 1_070),
        &[wide(7), wide(272), wide(544), quiet(20)],
        Holds::Nothing,
    );
    assert_eq!(
        (seen.narrowings, seen.widenings, seen.quiet_departures),
        (3, 2, 1),
        "{seen:?}"
    );
    assert_eq!((seen.narrowest, seen.widest), (16, 17), "{seen:?}");
    assert_eq!(seen.moved, 0, "{seen:?}");

    for holds in [Holds::Half, Holds::All] {
        let seen = sync_through_departures(
            window,
            &small_then_mixed_sizes(30, 420),
            &[wide(7), wide(272), quiet(20)],
            holds,
        );
        assert_eq!(
            (seen.narrowings, seen.widenings, seen.quiet_departures),
            (2, 1, 1),
            "{holds:?}: {seen:?}"
        );
        assert_eq!(
            (seen.narrowest, seen.widest),
            (16, 17),
            "{holds:?}: {seen:?}"
        );
        assert!(seen.moved > 0, "{holds:?}: {seen:?}");
        assert_eq!(
            seen.forgotten == 0,
            matches!(holds, Holds::All),
            "{holds:?}: {seen:?}"
        );
    }
}

/// The same for the default window, over a chain that mixes runs of
/// tiny, medium and full blocks after its first 150, so that its bytes
/// limit the window as well as its count.  The first sync peer leaves
/// with a wide window requested.  The second has the 2,048 blocks
/// accepted that undo the halving and then leaves with a wide window
/// requested, and so do the next two after a few blocks each, which
/// brings the window to dcrd's 16 blocks.  The fifth leaves with no more
/// than 16 requested and narrows nothing.
#[test]
fn a_sync_through_departures_stays_inside_the_default_window() {
    let seen = sync_through_departures(
        main_net_window(),
        &small_then_mixed_sizes(150, 2_150),
        &[wide(20), wide(2_048), wide(10), wide(10), quiet(20)],
        Holds::Nothing,
    );
    assert_eq!(
        (seen.narrowings, seen.widenings, seen.quiet_departures),
        (4, 1, 1),
        "{seen:?}"
    );
    assert_eq!((seen.narrowest, seen.widest), (16, 128), "{seen:?}");
}

/// The same for the default window where the requests of a departing
/// sync peer move to the next one, half of them or all: three departures
/// bring the window to dcrd's 16 blocks while the next sync peer still
/// has requests from wider windows to deliver, and is asked for nothing
/// more until it is under the window in force.
#[test]
fn a_sync_through_departures_moves_requests_within_the_default_window() {
    for holds in [Holds::Half, Holds::All] {
        let seen = sync_through_departures(
            main_net_window(),
            &small_then_mixed_sizes(150, 450),
            &[wide(20), wide(10), wide(10), quiet(20)],
            holds,
        );
        assert_eq!(
            (seen.narrowings, seen.widenings, seen.quiet_departures),
            (3, 0, 1),
            "{holds:?}: {seen:?}"
        );
        assert_eq!(
            (seen.narrowest, seen.widest),
            (16, 128),
            "{holds:?}: {seen:?}"
        );
        assert!(seen.moved > 0, "{holds:?}: {seen:?}");
        assert_eq!(
            seen.forgotten == 0,
            matches!(holds, Holds::All),
            "{holds:?}: {seen:?}"
        );
    }
}

/// The same for the widest window, 505 blocks, which five departures
/// halve to 252, 126, 63, 31 and 16.  The chain begins with 600 small
/// blocks, so the first request is for all 505.
#[test]
fn a_sync_through_departures_stays_inside_a_window_of_505() {
    let sizes = small_then_mixed_sizes(600, 100);
    let window = BlockWindow::budget(MAX_BLOCK_SIZE as usize, MAX_BUDGET_WINDOW_BLOCKS);
    for holds in [Holds::Nothing, Holds::Half, Holds::All] {
        let seen = sync_through_departures(
            window,
            &sizes,
            &[wide(60), wide(40), wide(40), wide(40), wide(40), quiet(30)],
            holds,
        );
        assert_eq!(
            (seen.narrowings, seen.widenings, seen.quiet_departures),
            (5, 0, 1),
            "{holds:?}: {seen:?}"
        );
        assert_eq!(
            (seen.narrowest, seen.widest),
            (16, 505),
            "{holds:?}: {seen:?}"
        );
        assert_eq!(
            seen.moved > 0,
            !matches!(holds, Holds::Nothing),
            "{holds:?}: {seen:?}"
        );
        assert_eq!(
            seen.forgotten == 0,
            matches!(holds, Holds::All),
            "{holds:?}: {seen:?}"
        );
    }
}
