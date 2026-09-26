// SPDX-License-Identifier: ISC
//! A request the daemon's bounded outbound queue refuses is handed back
//! to the sync manager (`SyncManager::on_request_not_sent`), so nothing
//! stays recorded against a peer that was never asked.
//!
//! dcrd's `QueueMessage` cannot refuse: a recorded request is always
//! sent, and a peer that never answers is disconnected by its stall
//! handler, whereupon `OnPeerDisconnected` re-requests the data from
//! another announcer.  A refused request is never written, so it arms no
//! stall deadline; before the hand-back it stayed attributed to the peer
//! until the peer left, and every other peer's announcement of the same
//! block, transaction or mix message was skipped as already requested.

use std::collections::BTreeSet;

use dcroxide_chainhash::Hash;
use dcroxide_containers::apbf;
use dcroxide_netsync::manager::MAX_IN_FLIGHT_BLOCKS;
use dcroxide_netsync::{
    Action, BestSnapshot, Config, Peer, ProcessBlockFailure, ProcessTxFailure, SyncChain,
    SyncManager, SyncMixPool, SyncTxPool,
};
use dcroxide_wire::{
    BlockHeader, CurrencyNet, InvType, InvVect, Message, MsgBlock, MsgHeaders, MsgInv, MsgTx,
    PROTOCOL_VERSION, ServiceFlag,
};

/// A chain that accepts every header, knows only the zero hash, and has
/// no block data, with a scripted best header and needed-blocks list.
struct StubChain {
    current: bool,
    best: (Hash, i64),
    next_blocks: Vec<Hash>,
}

impl SyncChain for StubChain {
    fn best_header(&mut self) -> (Hash, i64) {
        self.best
    }
    fn header_by_hash(&mut self, _hash: &Hash) -> Option<BlockHeader> {
        None
    }
    fn block_locator_from_hash(&mut self, _hash: &Hash) -> Vec<Hash> {
        vec![Hash::ZERO]
    }
    fn put_next_needed_blocks(&mut self, _max_results: usize) -> Vec<Hash> {
        self.next_blocks.clone()
    }
    fn best_snapshot(&mut self) -> BestSnapshot {
        BestSnapshot {
            hash: Hash::ZERO,
            height: 0,
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
        *hash == Hash::ZERO
    }
    fn have_block(&mut self, _hash: &Hash) -> bool {
        false
    }
    fn process_block_header(&mut self, _header: &BlockHeader) -> Result<(), ProcessBlockFailure> {
        Ok(())
    }
    fn process_block(&mut self, _block: &MsgBlock) -> Result<i64, ProcessBlockFailure> {
        Err(ProcessBlockFailure {
            is_duplicate_block: false,
            is_rule_error: true,
            is_corruption: false,
            message: "stub".to_string(),
        })
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

type Manager = SyncManager<StubChain, EmptyTxPool, EmptyMixPool>;

fn manager(chain: StubChain) -> Manager {
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

fn connect(m: &mut Manager, id: i32, last_block: i64) -> Vec<Action> {
    m.on_peer_connected(Peer::new(
        id,
        format!("10.0.0.{id}:9108"),
        false,
        ServiceFlag::NODE_NETWORK,
        PROTOCOL_VERSION,
        last_block,
    ))
}

/// The messages queued to a peer, in order.
fn queued_to(actions: &[Action], peer_id: i32) -> Vec<Message> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::QueueMessage { peer, message } if *peer == peer_id => Some(message.clone()),
            _ => None,
        })
        .collect()
}

/// The single getdata among the messages, with its inventory.
fn get_data(messages: &[Message]) -> (Message, Vec<InvVect>) {
    let found: Vec<&Message> = messages
        .iter()
        .filter(|m| matches!(m, Message::GetData(_)))
        .collect();
    assert_eq!(found.len(), 1, "expected one getdata in {messages:?}");
    match found[0] {
        Message::GetData(msg) => (found[0].clone(), msg.inv_list.clone()),
        _ => unreachable!(),
    }
}

fn exclude(ids: &[i32]) -> BTreeSet<i32> {
    ids.iter().copied().collect()
}

/// A header whose parent is the zero hash the stub chain knows.
fn connecting_header(height: u32) -> BlockHeader {
    let (mut header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header");
    header.prev_block = Hash::ZERO;
    header.height = height;
    header
}

/// A header whose parent no chain knows.
fn orphan_header(height: u32) -> BlockHeader {
    let mut header = connecting_header(height);
    header.prev_block = Hash([0x77; 32]);
    header
}

/// With no other peer known to hold the data, a refused request is
/// forgotten, so the next peer to announce it is asked instead of being
/// skipped as already requested.
#[test]
fn a_refused_request_with_no_other_holder_is_forgotten() {
    let mut m = manager(StubChain {
        current: true,
        best: (Hash::ZERO, 0),
        next_blocks: Vec::new(),
    });
    connect(&mut m, 1, 0);
    connect(&mut m, 2, 0);
    let tx = InvVect {
        inv_type: InvType::TX,
        hash: Hash([0x11; 32]),
    };
    let mix = InvVect {
        inv_type: InvType::MIX,
        hash: Hash([0x12; 32]),
    };
    let announce = MsgInv {
        inv_list: vec![tx, mix],
    };

    let (refused, inv_list) = get_data(&queued_to(&m.on_inv(1, &announce), 1));
    assert_eq!(inv_list, vec![tx, mix]);

    // Peer 1's queue refused the getdata.
    assert!(
        m.on_request_not_sent(1, &refused, &exclude(&[1]))
            .is_empty()
    );
    let [txns, _, mix_msgs] = m.requested_snapshot();
    assert!(
        txns.is_empty() && mix_msgs.is_empty(),
        "nothing stays requested"
    );

    // Peer 2 announces the same data and is asked for it.
    let (_, inv_list) = get_data(&queued_to(&m.on_inv(2, &announce), 2));
    assert_eq!(inv_list, vec![tx, mix]);
}

/// A peer already known to hold the data is asked in the refusing peer's
/// place, and a peer that refused too is never chosen, so the retries
/// end once no untried holder remains.
#[test]
fn a_refused_request_moves_to_another_holder() {
    let mut m = manager(StubChain {
        current: true,
        best: (Hash::ZERO, 0),
        next_blocks: Vec::new(),
    });
    connect(&mut m, 1, 0);
    connect(&mut m, 2, 0);
    connect(&mut m, 3, 0);
    let tx = InvVect {
        inv_type: InvType::TX,
        hash: Hash([0x21; 32]),
    };
    let announce = MsgInv { inv_list: vec![tx] };

    let (refused, _) = get_data(&queued_to(&m.on_inv(1, &announce), 1));
    // Peer 2 announces while the request to peer 1 is pending, so it is
    // skipped but recorded as holding the transaction.
    assert!(queued_to(&m.on_inv(2, &announce), 2).is_empty());

    let retry = m.on_request_not_sent(1, &refused, &exclude(&[1]));
    let (retried, inv_list) = get_data(&queued_to(&retry, 2));
    assert_eq!(inv_list, vec![tx]);
    assert_eq!(m.requested_snapshot()[0], vec![(tx.hash, 2)]);

    // A second hand-back for peer 1 finds the request reassigned and
    // leaves it alone.
    assert!(
        m.on_request_not_sent(1, &refused, &exclude(&[1]))
            .is_empty()
    );
    assert_eq!(m.requested_snapshot()[0], vec![(tx.hash, 2)]);

    // Peer 2 refuses as well; peer 1 is excluded, and nobody else holds
    // it, so the request is forgotten.
    assert!(
        m.on_request_not_sent(2, &retried, &exclude(&[1, 2]))
            .is_empty()
    );
    assert!(m.requested_snapshot()[0].is_empty());
}

/// A refused getheaders is not remembered as the previous request, so
/// the identical request is sent the next time it is made instead of
/// being filtered as a duplicate.
#[test]
fn a_refused_getheaders_is_not_filtered_as_a_duplicate() {
    let mut m = manager(StubChain {
        current: true,
        best: (Hash::ZERO, 0),
        next_blocks: Vec::new(),
    });
    let initial = queued_to(&connect(&mut m, 7, 1), 7);
    let refused = initial
        .into_iter()
        .find(|m| matches!(m, Message::GetHeaders(_)))
        .expect("the initial header sync request");
    let synced = m.on_headers(
        7,
        &MsgHeaders {
            headers: vec![connecting_header(1)],
        },
    );
    assert!(m.initial_header_sync_done(), "{synced:?}");

    // An announcement that does not connect asks for headers from the
    // best known header, which is the request already made, so it is
    // filtered as a duplicate.
    let announce = MsgHeaders {
        headers: vec![orphan_header(5)],
    };
    assert!(
        !queued_to(&m.on_headers(7, &announce), 7)
            .iter()
            .any(|m| matches!(m, Message::GetHeaders(_)))
    );

    // Had that request been refused, the same announcement asks again.
    assert!(
        m.on_request_not_sent(7, &refused, &exclude(&[7]))
            .is_empty()
    );
    let again = queued_to(&m.on_headers(7, &announce), 7);
    assert!(
        again.contains(&refused),
        "the refused request must be sent again: {again:?}"
    );
}

/// Blocks a refused getdata asked the sync peer for are forgotten and
/// fetched again on the next download round, in order, rather than
/// counted as in flight forever.
#[test]
fn refused_blocks_are_fetched_again() {
    let needed = vec![Hash([0x31; 32]), Hash([0x32; 32]), Hash([0x33; 32])];
    let mut m = manager(StubChain {
        current: false,
        best: (Hash([0x39; 32]), 3),
        next_blocks: needed.clone(),
    });
    connect(&mut m, 7, 3);
    let actions = m.on_headers(
        7,
        &MsgHeaders {
            headers: vec![connecting_header(1)],
        },
    );
    let (refused, inv_list) = get_data(&queued_to(&actions, 7));
    let block_invs: Vec<InvVect> = needed
        .iter()
        .map(|hash| InvVect {
            inv_type: InvType::BLOCK,
            hash: *hash,
        })
        .collect();
    assert_eq!(inv_list, block_invs);

    assert!(
        m.on_request_not_sent(7, &refused, &exclude(&[7]))
            .is_empty()
    );
    assert_eq!(m.requested_block_count(), 0, "nothing stays in flight");

    // The next download round asks for them again.
    let actions = m.on_headers(
        7,
        &MsgHeaders {
            headers: vec![connecting_header(2)],
        },
    );
    let (_, inv_list) = get_data(&queued_to(&actions, 7));
    assert_eq!(inv_list, block_invs);
}

/// Block inventory vectors for the hashes, in order.
fn block_invs(hashes: &[Hash]) -> Vec<InvVect> {
    hashes
        .iter()
        .map(|hash| InvVect {
            inv_type: InvType::BLOCK,
            hash: *hash,
        })
        .collect()
}

/// A manager whose headers are synced from sync peer 7, with blocks
/// still needed and the chain not current, so blocks are fetched from
/// the sync peer alone; returns the getdata the sync peer was sent, for
/// as many of the needed blocks as may be in flight from one peer.
fn syncing_from_7(needed: &[Hash], others: &[(i32, i64)]) -> (Manager, Message) {
    let mut m = manager(StubChain {
        current: false,
        best: (Hash([0x49; 32]), 3),
        next_blocks: needed.to_vec(),
    });
    connect(&mut m, 7, 3);
    for (id, last_block) in others {
        connect(&mut m, *id, *last_block);
    }
    let actions = m.on_headers(
        7,
        &MsgHeaders {
            headers: vec![connecting_header(1)],
        },
    );
    let (refused, inv_list) = get_data(&queued_to(&actions, 7));
    assert_eq!(
        inv_list,
        block_invs(&needed[..needed.len().min(MAX_IN_FLIGHT_BLOCKS)])
    );
    assert_eq!(m.sync_peer_id(), 7);
    (m, refused)
}

/// A sync peer that refuses every block it was asked for stalls the
/// chain sync: until the chain is current nothing else fetches blocks,
/// and only a block the sync peer delivers asks for more.  dcrd disconnects
/// a sync peer that never delivers once its stall deadline passes and
/// starts the chain sync with the next candidate; the chain sync moves
/// there at once, and the refusing peer stays connected.
#[test]
fn a_stalled_sync_peer_hands_the_chain_sync_to_another_candidate() {
    let needed = vec![Hash([0x41; 32]), Hash([0x42; 32]), Hash([0x43; 32])];
    // Peer 9 is behind the best header, so it is no candidate.
    let (mut m, refused) = syncing_from_7(&needed, &[(8, 3), (9, 2)]);

    let retry = m.on_request_not_sent(7, &refused, &exclude(&[7]));
    assert_eq!(m.sync_peer_id(), 8, "the chain sync moves to the candidate");
    let (_, inv_list) = get_data(&queued_to(&retry, 8));
    assert_eq!(inv_list, block_invs(&needed));
    assert!(queued_to(&retry, 7).is_empty() && queued_to(&retry, 9).is_empty());
    assert!(
        !retry
            .iter()
            .any(|action| matches!(action, Action::Disconnect { .. })),
        "the refusing peer is not disconnected: {retry:?}"
    );
    assert!(m.peer(7).is_some_and(Peer::connected));
}

/// The same holds when every refused block is re-requested from another
/// peer known to hold it: only a block the sync peer delivers asks for
/// more, so the blocks still needed after those would wait for the next
/// headers message, which asks the refusing sync peer again.  dcrd's
/// `OnPeerDisconnected` starts the chain sync with the next candidate
/// whether the departing sync peer's blocks were re-requested or
/// forgotten, and the new sync peer is asked for the rest at once.
#[test]
fn a_stalled_sync_peer_hands_over_the_chain_sync_when_its_blocks_move() {
    let needed: Vec<Hash> = (0..MAX_IN_FLIGHT_BLOCKS + 10)
        .map(|i| Hash([0x70 + i as u8; 32]))
        .collect();
    let (asked, rest) = needed.split_at(MAX_IN_FLIGHT_BLOCKS);
    // Peer 9 is known to hold every block peer 7 was asked for; peer 8,
    // the lower id at the same height, is the candidate.
    let (mut m, refused) = syncing_from_7(&needed, &[(8, 3), (9, 3)]);
    for inv in block_invs(asked) {
        m.peer_mut(9).expect("connected").add_known_inventory(inv);
    }

    let retry = m.on_request_not_sent(7, &refused, &exclude(&[7]));
    let (_, moved) = get_data(&queued_to(&retry, 9));
    assert_eq!(moved, block_invs(asked), "the blocks move to their holder");
    assert_eq!(m.sync_peer_id(), 8, "the chain sync moves to the candidate");
    let (_, fetched) = get_data(&queued_to(&retry, 8));
    assert_eq!(
        fetched,
        block_invs(rest),
        "the candidate is asked for the rest"
    );
    assert!(queued_to(&retry, 7).is_empty());
    assert_eq!(m.requested_block_count(), needed.len());
}

/// A peer that refused in the same dispatch is never handed the chain
/// sync, and with no other candidate the sync peer is kept, so the next
/// download round asks it again.
#[test]
fn a_stalled_sync_peer_is_kept_without_an_untried_candidate() {
    let needed = vec![Hash([0x51; 32]), Hash([0x52; 32])];
    let (mut m, refused) = syncing_from_7(&needed, &[(8, 3)]);

    assert!(
        m.on_request_not_sent(7, &refused, &exclude(&[7, 8]))
            .is_empty()
    );
    assert_eq!(m.sync_peer_id(), 7);
}

/// A sync peer with blocks still in flight has not stalled: the next
/// block it delivers asks for more, so it stays the sync peer, as dcrd's
/// does while it keeps answering.
#[test]
fn a_sync_peer_with_blocks_in_flight_keeps_the_chain_sync() {
    let needed = vec![Hash([0x61; 32]), Hash([0x62; 32]), Hash([0x63; 32])];
    let (mut m, _) = syncing_from_7(&needed, &[(8, 3)]);

    // Only the first block's request was refused.
    let refused = Message::GetData(dcroxide_wire::MsgGetData {
        inv_list: block_invs(&needed[..1]),
    });
    assert!(
        m.on_request_not_sent(7, &refused, &exclude(&[7]))
            .is_empty()
    );
    assert_eq!(m.sync_peer_id(), 7);
    assert_eq!(m.requested_block_count(), 2);
}

/// The once-per-peer initial state request is recorded as made when it
/// is queued.  A refused one was never sent, so it is made again with the
/// peer's next inventory message, where the flag had kept the peer from
/// ever being asked; once sent, it is not made again.
#[test]
fn a_refused_initial_state_request_is_made_again() {
    let mut m = manager(StubChain {
        current: true,
        best: (Hash::ZERO, 0),
        next_blocks: Vec::new(),
    });
    connect(&mut m, 7, 1);
    // The headers sync completes with the chain current, which requests
    // the initial state from every peer.
    let synced = queued_to(
        &m.on_headers(
            7,
            &MsgHeaders {
                headers: vec![connecting_header(1)],
            },
        ),
        7,
    );
    let request = synced
        .into_iter()
        .find(|message| matches!(message, Message::GetInitState(_)))
        .expect("the initial state request");

    assert!(
        m.on_request_not_sent(7, &request, &exclude(&[7]))
            .is_empty()
    );
    let empty = MsgInv {
        inv_list: Vec::new(),
    };
    assert_eq!(queued_to(&m.on_inv(7, &empty), 7), vec![request]);
    assert!(queued_to(&m.on_inv(7, &empty), 7).is_empty());
}

/// Transaction inventory vectors with distinct hashes.
fn tx_invs(count: u32) -> Vec<InvVect> {
    (0..count)
        .map(|i| {
            let mut hash = [0x5a; 32];
            hash[..4].copy_from_slice(&i.to_le_bytes());
            InvVect {
                inv_type: InvType::TX,
                hash: Hash(hash),
            }
        })
        .collect()
}

/// What each peer is asked for, by peer id.
type AskedOf = std::collections::BTreeMap<i32, Vec<InvVect>>;

/// Peer 1 is asked for `txs`, some of which peers 2, 3 and 4 are known
/// to hold, and its queue refuses the request in the given pieces with
/// peers 1 and 2 excluded.  Returns what each peer is asked for instead
/// and the transaction requests left.
fn refuse_in_pieces(txs: &[InvVect], piece: usize) -> (AskedOf, Vec<(Hash, i32)>) {
    let mut m = manager(StubChain {
        current: true,
        best: (Hash::ZERO, 0),
        next_blocks: Vec::new(),
    });
    for id in 1..=4 {
        connect(&mut m, id, 0);
    }
    let (_, inv_list) = get_data(&queued_to(
        &m.on_inv(
            1,
            &MsgInv {
                inv_list: txs.to_vec(),
            },
        ),
        1,
    ));
    assert_eq!(inv_list, txs);
    for (peer, i) in [(2, 10), (3, 10), (3, 1400), (2, 20), (4, 20), (4, 1499)] {
        m.peer_mut(peer)
            .expect("connected")
            .add_known_inventory(txs[i]);
    }

    let mut asked = AskedOf::new();
    for chunk in txs.chunks(piece) {
        let refused = Message::GetData(dcroxide_wire::MsgGetData {
            inv_list: chunk.to_vec(),
        });
        for action in m.on_request_not_sent(1, &refused, &exclude(&[1, 2])) {
            if let Action::QueueMessage {
                peer,
                message: Message::GetData(get_data),
            } = action
            {
                asked.entry(peer).or_default().extend(get_data.inv_list);
            }
        }
    }
    let [txns, _, _] = m.requested_snapshot();
    (asked, txns)
}

/// A refusal larger than one known-inventory cache finds each item's
/// holder by walking every candidate's cache once, where probing every
/// peer for every item cost items x peers lookups under the manager lock.
/// It picks exactly the holders the per-item probe picks: the first
/// peer in ascending id order known to hold the item, never an excluded
/// one, with everything else forgotten.
#[test]
fn a_large_refusal_picks_the_holders_the_probe_picks() {
    let txs = tx_invs(1500);
    // One 1,500-item refusal takes the walk; 500-item pieces take the
    // probe.
    let walked = refuse_in_pieces(&txs, txs.len());
    let probed = refuse_in_pieces(&txs, 500);
    assert_eq!(walked, probed);

    let (asked, txns) = walked;
    assert_eq!(
        asked,
        [(3, vec![txs[10], txs[1400]]), (4, vec![txs[20], txs[1499]])]
            .into_iter()
            .collect()
    );
    let mut want = vec![
        (txs[10].hash, 3),
        (txs[1400].hash, 3),
        (txs[20].hash, 4),
        (txs[1499].hash, 4),
    ];
    want.sort_unstable_by_key(|e| e.0.0);
    assert_eq!(txns, want);
}
