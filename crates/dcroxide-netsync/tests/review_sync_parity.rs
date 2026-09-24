// SPDX-License-Identifier: ISC
//! Sync manager behaviour the review found missing against dcrd's
//! `internal/netsync/manager.go`:
//!
//! - the peer height rises that dcrd's embedded `*peer.Peer` shares
//!   with `getpeerinfo` (`maybeUpdateBestAnnouncedBlock` and the
//!   orphan-header path both call `UpdateLastBlockHeight`);
//! - the error-level lines dcrd logs when processing a transaction, a
//!   header or a block fails for a reason other than a rule violation,
//!   and its critical-failure line for corruption;
//! - the header linkage check on a peer-supplied height, which wraps
//!   like Go's `uint32` instead of panicking;
//! - the transaction and mix intake split around the pool call, so a
//!   caller can release the manager's lock across the validation the
//!   way dcrd's `OnTx` and `OnMixMsg` hold only `requestMtx`.

use dcroxide_chainhash::Hash;
use dcroxide_containers::apbf;
use dcroxide_netsync::{
    Action, BestSnapshot, Config, LogLevel, Peer, ProcessBlockFailure, ProcessTxFailure, SyncChain,
    SyncManager, SyncMixPool, SyncTxPool,
};
use dcroxide_wire::{
    BlockHeader, CurrencyNet, InvType, InvVect, Message, MsgBlock, MsgHeaders, MsgTx,
    PROTOCOL_VERSION, ServiceFlag,
};

/// A chain that knows only the zero hash, credits every header with
/// some work, and fails header and block processing as scripted.
struct StubChain {
    current: bool,
    best: (Hash, i64),
    next_blocks: Vec<Hash>,
    header_failure: Option<ProcessBlockFailure>,
    block_failure: Option<ProcessBlockFailure>,
}

impl StubChain {
    fn new() -> StubChain {
        StubChain {
            current: true,
            best: (Hash::ZERO, 0),
            next_blocks: Vec::new(),
            header_failure: None,
            block_failure: None,
        }
    }
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
        Some(dcroxide_uint256::Uint256::from(1u64))
    }
    fn have_header(&mut self, hash: &Hash) -> bool {
        *hash == Hash::ZERO
    }
    fn have_block(&mut self, _hash: &Hash) -> bool {
        false
    }
    fn process_block_header(&mut self, _header: &BlockHeader) -> Result<(), ProcessBlockFailure> {
        match &self.header_failure {
            Some(failure) => Err(failure.clone()),
            None => Ok(()),
        }
    }
    fn process_block(&mut self, _block: &MsgBlock) -> Result<i64, ProcessBlockFailure> {
        match &self.block_failure {
            Some(failure) => Err(failure.clone()),
            None => Ok(0),
        }
    }
}

/// A pool that fails every transaction as scripted.
struct FailingTxPool {
    failure: ProcessTxFailure,
}

impl SyncTxPool for FailingTxPool {
    fn process_transaction(
        &mut self,
        _tx: &MsgTx,
        _allow_orphan: bool,
        _allow_high_fees: bool,
        _tag: u64,
    ) -> Result<Vec<Hash>, String> {
        Err(self.failure.message.clone())
    }
    fn process_transaction_accepted(
        &mut self,
        _tx: &MsgTx,
        _allow_orphan: bool,
        _allow_high_fees: bool,
        _tag: u64,
    ) -> Result<Vec<(Hash, MsgTx)>, ProcessTxFailure> {
        Err(self.failure.clone())
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

type Manager = SyncManager<StubChain, FailingTxPool, EmptyMixPool>;

fn manager_with(chain: StubChain, tx_failure: ProcessTxFailure) -> Manager {
    SyncManager::new(Config {
        chain,
        tx_mem_pool: FailingTxPool {
            failure: tx_failure,
        },
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

fn manager(chain: StubChain) -> Manager {
    manager_with(
        chain,
        ProcessTxFailure {
            is_rule_error: true,
            message: "unused".to_string(),
        },
    )
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

/// A header whose parent is the zero hash the stub chain knows.
fn connecting_header(height: u32) -> BlockHeader {
    let (mut header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header");
    header.prev_block = Hash::ZERO;
    header.height = height;
    header
}

/// The height rises the manager emitted, in order.
fn height_updates(actions: &[Action]) -> Vec<(i32, i64)> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::UpdateLastBlockHeight { peer, height } => Some((*peer, *height)),
            _ => None,
        })
        .collect()
}

/// The error-level log lines, in order.
fn error_lines(actions: &[Action]) -> Vec<String> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Log {
                level: LogLevel::Error,
                message,
            } => Some(message.clone()),
            _ => None,
        })
        .collect()
}

fn disconnected(actions: &[Action], peer_id: i32) -> bool {
    actions
        .iter()
        .any(|action| matches!(action, Action::Disconnect { peer } if *peer == peer_id))
}

/// Headers that connect raise the announcing peer's height for the
/// daemon (dcrd `maybeUpdateBestAnnouncedBlock` calling the embedded
/// peer's `UpdateLastBlockHeight`), so `getpeerinfo`'s `currentheight`
/// moves past `startingheight`.
#[test]
fn announced_headers_raise_the_peer_height_for_the_daemon() {
    let mut m = manager(StubChain::new());
    connect(&mut m, 7, 5);

    let actions = m.on_headers(
        7,
        &MsgHeaders {
            headers: vec![connecting_header(10)],
        },
    );
    assert_eq!(height_updates(&actions), vec![(7, 10)], "{actions:?}");
    assert_eq!(m.peer(7).expect("peer").last_block(), 10);
}

/// A lower height never reaches the daemon: dcrd's
/// `UpdateLastBlockHeight` ignores it.
#[test]
fn a_lower_announced_height_is_not_emitted() {
    let mut m = manager(StubChain::new());
    connect(&mut m, 7, 50);

    let actions = m.on_headers(
        7,
        &MsgHeaders {
            headers: vec![connecting_header(10)],
        },
    );
    assert!(height_updates(&actions).is_empty(), "{actions:?}");
    assert_eq!(m.peer(7).expect("peer").last_block(), 50);
}

/// Headers that do not connect during the initial header sync raise
/// the height too (dcrd `OnHeaders`' orphan path).
#[test]
fn orphan_headers_during_the_initial_sync_raise_the_peer_height() {
    let mut m = manager(StubChain::new());
    connect(&mut m, 7, 5);

    let mut orphan = connecting_header(40);
    orphan.prev_block = Hash([0x77; 32]);
    let actions = m.on_headers(
        7,
        &MsgHeaders {
            headers: vec![orphan],
        },
    );
    assert_eq!(height_updates(&actions), vec![(7, 40)], "{actions:?}");
}

/// A transaction that fails for a reason other than a rule violation
/// gets dcrd's error-level line (`OnTx`); a plain rejection does not
/// (dcrd logs that at the debug level, which the port does not carry).
/// Either way the hash joins the rejected filter.
#[test]
fn an_internal_transaction_failure_is_logged_as_an_error() {
    let tx = MsgTx::default();
    let tx_hash = tx.tx_hash();

    let mut m = manager_with(
        StubChain::new(),
        ProcessTxFailure {
            is_rule_error: false,
            message: "no block data for tip".to_string(),
        },
    );
    connect(&mut m, 7, 0);
    let (accepted, actions) = m.on_tx(7, &tx);
    assert!(accepted.is_empty());
    assert_eq!(
        error_lines(&actions),
        vec![format!(
            "Failed to process transaction {tx_hash}: no block data for tip"
        )]
    );
    assert!(m.rejected_txns_contains(&tx_hash));

    let mut m = manager_with(
        StubChain::new(),
        ProcessTxFailure {
            is_rule_error: true,
            message: "transaction already exists".to_string(),
        },
    );
    connect(&mut m, 7, 0);
    let (_, actions) = m.on_tx(7, &tx);
    assert!(error_lines(&actions).is_empty(), "{actions:?}");
    assert!(m.rejected_txns_contains(&tx_hash));
}

/// A header that fails for a reason other than a rule violation gets
/// dcrd's `Failed to process block header` error line, and a corrupt
/// database adds its (misspelled) `Criticial failure` line; the peer is
/// disconnected either way.  A rejected header logs neither.
#[test]
fn an_internal_header_failure_is_logged_as_an_error() {
    let header = connecting_header(10);
    let header_hash = header.block_hash();

    let mut chain = StubChain::new();
    chain.header_failure = Some(ProcessBlockFailure {
        is_duplicate_block: false,
        is_rule_error: false,
        is_corruption: true,
        message: "checksum mismatch".to_string(),
    });
    let mut m = manager(chain);
    connect(&mut m, 7, 5);
    let actions = m.on_headers(
        7,
        &MsgHeaders {
            headers: vec![header],
        },
    );
    assert_eq!(
        error_lines(&actions),
        vec![
            format!(
                "Failed to process block header {header_hash} from peer 10.0.0.7:9108 \
                 (outbound): checksum mismatch -- disconnecting"
            ),
            "Criticial failure: checksum mismatch".to_string(),
        ]
    );
    assert!(disconnected(&actions, 7));

    let mut chain = StubChain::new();
    chain.header_failure = Some(ProcessBlockFailure {
        is_duplicate_block: false,
        is_rule_error: true,
        is_corruption: false,
        message: "bad difficulty".to_string(),
    });
    let mut m = manager(chain);
    connect(&mut m, 7, 5);
    let actions = m.on_headers(
        7,
        &MsgHeaders {
            headers: vec![header],
        },
    );
    assert!(error_lines(&actions).is_empty(), "{actions:?}");
    assert!(disconnected(&actions, 7));
}

/// A block that fails on a corrupt store gets dcrd's `Critical failure`
/// line after its `Failed to process block` line (`OnBlock`).
#[test]
fn a_corrupt_block_failure_logs_the_critical_failure() {
    let block = MsgBlock {
        header: connecting_header(1),
        transactions: Vec::new(),
        stransactions: Vec::new(),
    };
    let block_hash = block.header.block_hash();

    let mut chain = StubChain::new();
    chain.current = false;
    chain.best = (Hash([0x39; 32]), 3);
    chain.next_blocks = vec![block_hash];
    chain.block_failure = Some(ProcessBlockFailure {
        is_duplicate_block: false,
        is_rule_error: false,
        is_corruption: true,
        message: "corrupt spend information".to_string(),
    });
    let mut m = manager(chain);
    connect(&mut m, 7, 3);

    // The initial header sync completes and the block is requested
    // from the sync peer.
    let actions = m.on_headers(
        7,
        &MsgHeaders {
            headers: vec![connecting_header(1)],
        },
    );
    let requested = actions.iter().any(|action| {
        matches!(action, Action::QueueMessage { peer: 7, message: Message::GetData(msg) }
            if msg.inv_list.contains(&InvVect { inv_type: InvType::BLOCK, hash: block_hash }))
    });
    assert!(requested, "{actions:?}");

    let actions = m.on_block(7, &block);
    assert_eq!(
        error_lines(&actions),
        vec![
            format!("Failed to process block {block_hash}: corrupt spend information"),
            "Critical failure: corrupt spend information".to_string(),
        ]
    );
}

/// The linkage check adds one to a height the peer chose before any
/// validation.  Go's `uint32` addition wraps, so a header at
/// `u32::MAX` followed by one at height 0 links, and one at any other
/// height disconnects the peer.  A checked `+` panicked instead, under
/// the manager lock, in every build with overflow checks.
#[test]
fn the_header_linkage_height_wraps_like_go() {
    let first = connecting_header(u32::MAX);
    let mut second = connecting_header(5);
    second.prev_block = first.block_hash();

    let mut m = manager(StubChain::new());
    connect(&mut m, 7, 5);
    let actions = m.on_headers(
        7,
        &MsgHeaders {
            headers: vec![first, second],
        },
    );
    assert!(disconnected(&actions, 7), "{actions:?}");

    second.height = 0;
    let mut m = manager(StubChain::new());
    connect(&mut m, 7, 5);
    let actions = m.on_headers(
        7,
        &MsgHeaders {
            headers: vec![first, second],
        },
    );
    assert!(!disconnected(&actions, 7), "{actions:?}");
}

/// The halves of the transaction intake a caller runs around its own
/// pool call keep `on_tx`'s bookkeeping: the peer is recorded as holding
/// the transaction, a failure joins the rejected filter, and a rejected
/// or shut-down intake never reaches the pool again.
#[test]
fn the_split_transaction_intake_keeps_on_txs_bookkeeping() {
    let tx = MsgTx::default();
    let tx_hash = tx.tx_hash();
    let mut m = manager(StubChain::new());
    connect(&mut m, 7, 0);

    assert_eq!(
        m.begin_tx(7, &tx_hash),
        Some(true),
        "admitted, with orphans allowed under a nonzero orphan limit"
    );
    assert!(m.peer_holds(
        7,
        &InvVect {
            inv_type: InvType::TX,
            hash: tx_hash,
        }
    ));
    let (accepted, actions) = m.finish_tx(
        &tx_hash,
        Err(ProcessTxFailure {
            is_rule_error: true,
            message: "rejected".to_string(),
        }),
    );
    assert!(accepted.is_empty());
    assert!(error_lines(&actions).is_empty(), "{actions:?}");
    assert!(m.rejected_txns_contains(&tx_hash));
    assert_eq!(
        m.begin_tx(7, &tx_hash),
        None,
        "a rejected transaction is ignored"
    );

    m.request_shutdown();
    assert_eq!(
        m.begin_tx(7, &Hash([9u8; 32])),
        None,
        "nothing is admitted after shutdown"
    );
}

/// The halves of the mix intake keep `on_mix_msg`'s bookkeeping the same
/// way, passing the pool's result through.
#[test]
fn the_split_mix_intake_keeps_on_mix_msgs_bookkeeping() {
    let msg = Hash([5u8; 32]);
    let mut m = manager(StubChain::new());
    connect(&mut m, 7, 0);

    assert_eq!(m.begin_mix_msg(7, &msg), Some(msg));
    assert!(m.peer_holds(
        7,
        &InvVect {
            inv_type: InvType::MIX,
            hash: msg,
        }
    ));
    assert_eq!(
        m.finish_mix_msg(&msg, Err("bad".to_string())),
        Err("bad".to_string())
    );
    assert!(m.rejected_mix_msgs_contains(&msg));
    assert_eq!(
        m.begin_mix_msg(7, &msg),
        None,
        "a rejected message is ignored"
    );

    let fresh = Hash([6u8; 32]);
    assert_eq!(m.begin_mix_msg(7, &fresh), Some(fresh));
    assert_eq!(m.finish_mix_msg(&fresh, Ok(vec![fresh])), Ok(vec![fresh]));
    assert!(!m.rejected_mix_msgs_contains(&fresh));
}
