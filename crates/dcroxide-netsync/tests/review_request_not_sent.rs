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
    fn process_transaction(
        &mut self,
        _tx: &MsgTx,
        _allow_orphan: bool,
        _allow_high_fees: bool,
        _tag: u64,
    ) -> Result<Vec<Hash>, String> {
        unreachable!("no transaction is delivered in these tests")
    }
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
