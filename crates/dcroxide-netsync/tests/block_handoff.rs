// SPDX-License-Identifier: ISC
//! How a block travels through the sync manager to the chain.
//!
//! dcrd's `OnBlock` and `ProcessBlock` pass one `*dcrutil.Block` from
//! the peer to the chain, which keeps that pointer.  The manager takes a
//! peer's block shared by reference count and hands the chain that very
//! allocation, so nothing between the peer and the chain copies the
//! block.  A block from a local source (the RPC server, the CPU miner)
//! is borrowed, and the chain is handed a copy of it.
//!
//! dcrd's `OnBlock` also reads the block's hash from that
//! `dcrutil.Block` (`internal/netsync/manager.go:1222`).  The manager
//! asks the chain for the hash of a block of its type, so a type that
//! carries the hash computed from the block saves hashing the header
//! again.

use std::sync::Arc;

use dcroxide_chainhash::Hash;
use dcroxide_containers::apbf;
use dcroxide_netsync::{
    Action, BestSnapshot, Config, Peer, ProcessBlockFailure, ProcessTxFailure, SyncChain,
    SyncManager, SyncMixPool, SyncTxPool,
};
use dcroxide_wire::{
    BlockHeader, CurrencyNet, InvType, InvVect, Message, MsgBlock, MsgHeaders, MsgTx,
    PROTOCOL_VERSION, ServiceFlag, TxOut,
};

/// A chain's own block type: the shared block, a note of how it came to
/// be, and the hash it carries, if it carries one.
struct Carried {
    block: Arc<MsgBlock>,
    /// Whether the manager wrapped the block itself, with `From`.
    wrapped_by_the_manager: bool,
    /// The hash the chain answers for this block, in place of hashing
    /// its header.
    hash: Option<Hash>,
}

impl std::ops::Deref for Carried {
    type Target = MsgBlock;

    fn deref(&self) -> &MsgBlock {
        &self.block
    }
}

impl From<Arc<MsgBlock>> for Carried {
    fn from(block: Arc<MsgBlock>) -> Carried {
        Carried {
            block,
            wrapped_by_the_manager: true,
            hash: None,
        }
    }
}

/// A chain that knows only the zero hash and keeps every block it is
/// handed, as the allocation it was handed, with where the value it
/// arrived in lives and how that value came to be.
struct KeepingChain {
    next_blocks: Vec<Hash>,
    kept: Vec<Arc<MsgBlock>>,
    carried_at: Vec<*const Carried>,
    wrapped_by_the_manager: Vec<bool>,
}

impl SyncChain for KeepingChain {
    type Block = Carried;

    fn block_hash(block: &Carried) -> Hash {
        match block.hash {
            Some(hash) => hash,
            None => block.header.block_hash(),
        }
    }

    fn best_header(&mut self) -> (Hash, i64) {
        (Hash([0x39; 32]), 3)
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
        false
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
        Ok(())
    }
    fn process_block(&mut self, block: &Carried) -> Result<i64, ProcessBlockFailure> {
        self.kept.push(Arc::clone(&block.block));
        self.carried_at.push(std::ptr::from_ref(block));
        self.wrapped_by_the_manager
            .push(block.wrapped_by_the_manager);
        Ok(0)
    }
}

/// A pool that holds nothing and accepts nothing.
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

type Manager = SyncManager<KeepingChain, EmptyTxPool, EmptyMixPool>;

/// A manager over a chain that needs `next_blocks`.
fn manager(next_blocks: Vec<Hash>) -> Manager {
    SyncManager::new(Config {
        chain: KeepingChain {
            next_blocks,
            kept: Vec::new(),
            carried_at: Vec::new(),
            wrapped_by_the_manager: Vec::new(),
        },
        tx_mem_pool: EmptyTxPool,
        mix_pool: EmptyMixPool,
        min_known_chain_work: None,
        net: CurrencyNet::REG_NET,
        target_time_per_block_secs: 300,
        no_mining_state_sync: false,
        max_outbound_peers: 8,
        max_orphan_txs: 100,
        recently_confirmed_txns: Arc::new(std::sync::Mutex::new(apbf::new_filter(
            62500, 0.0000001,
        ))),
    })
}

/// A block at height one over the zero hash the chain knows, with one
/// transaction in each tree so that a copy of it would own other lists.
fn block() -> MsgBlock {
    let (mut header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("zero header");
    header.prev_block = Hash::ZERO;
    header.height = 1;
    let tx = MsgTx {
        tx_out: vec![TxOut {
            value: 1,
            version: 0,
            pk_script: vec![0x51],
        }],
        ..MsgTx::default()
    };
    MsgBlock {
        header,
        transactions: vec![tx.clone()],
        stransactions: vec![tx],
    }
}

/// Connect a sync peer and have the manager request the block from it.
fn request_from_sync_peer(m: &mut Manager, block: &MsgBlock) {
    m.on_peer_connected(Peer::new(
        7,
        "10.0.0.7:9108".to_string(),
        false,
        ServiceFlag::NODE_NETWORK,
        PROTOCOL_VERSION,
        3,
    ));
    let actions = m.on_headers(
        7,
        &MsgHeaders {
            headers: vec![block.header],
        },
    );
    let wanted = InvVect {
        inv_type: InvType::BLOCK,
        hash: block.header.block_hash(),
    };
    let requested = actions.iter().any(|action| {
        matches!(action, Action::QueueMessage { peer: 7, message: Message::GetData(msg) }
            if msg.inv_list.contains(&wanted))
    });
    assert!(requested, "{actions:?}");
}

/// The chain is handed the very value the peer's block arrived in, with
/// whatever the chain's block type carries, and so the allocation of the
/// block itself, not a copy of it.  The caller's `Arc` stays usable
/// beside the chain's.
#[test]
fn a_peers_block_reaches_the_chain_as_the_same_allocation() {
    let block = Arc::new(block());
    let mut m = manager(vec![block.header.block_hash()]);
    request_from_sync_peer(&mut m, &block);

    let regular_at = block.transactions.as_ptr();
    let stake_at = block.stransactions.as_ptr();
    let carried = Carried {
        block: Arc::clone(&block),
        wrapped_by_the_manager: false,
        hash: None,
    };
    let actions = m.on_block(7, &carried);
    assert!(
        !actions
            .iter()
            .any(|action| matches!(action, Action::Disconnect { .. })),
        "{actions:?}"
    );

    let chain = m.chain_mut();
    assert_eq!(chain.kept.len(), 1, "the chain was handed the block once");
    assert_eq!(
        chain.carried_at,
        vec![std::ptr::from_ref(&carried)],
        "the chain was handed another value than the one that arrived"
    );
    assert_eq!(chain.wrapped_by_the_manager, vec![false]);
    assert!(
        Arc::ptr_eq(&chain.kept[0], &block),
        "the chain was handed a copy of the block"
    );
    assert_eq!(chain.kept[0].transactions.as_ptr(), regular_at);
    assert_eq!(chain.kept[0].stransactions.as_ptr(), stake_at);
    // The caller's, the one in the value it arrived in and the chain's:
    // the manager kept none.
    assert_eq!(Arc::strong_count(&block), 3);
}

/// The manager takes a delivered block's hash from the chain's block
/// type and hashes no header itself: a block that carries its hash goes
/// through `on_block` without a header being hashed, and one that does
/// not has its header hashed once, by the chain's answer.  Either way
/// the block is the one that was requested and reaches the chain.
#[test]
fn a_delivered_blocks_hash_is_the_one_its_type_carries() {
    for carries_its_hash in [true, false] {
        let block = Arc::new(block());
        let hash = block.header.block_hash();
        let mut m = manager(vec![hash]);
        request_from_sync_peer(&mut m, &block);

        let carried = Carried {
            block: Arc::clone(&block),
            wrapped_by_the_manager: false,
            hash: carries_its_hash.then_some(hash),
        };
        let before = dcroxide_wire::header_hashes_on_this_thread();
        let actions = m.on_block(7, &carried);
        assert_eq!(
            dcroxide_wire::header_hashes_on_this_thread() - before,
            u64::from(!carries_its_hash),
            "carries its hash: {carries_its_hash}"
        );
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, Action::Disconnect { .. })),
            "{actions:?}"
        );
        assert_eq!(
            m.chain_mut().kept.len(),
            1,
            "the chain was handed the block"
        );
    }
}

/// The hash the chain's block type answers is the block's identity to
/// the manager, for every use it makes of it: a block whose type
/// answers another hash than the one requested is an unrequested block,
/// named by that hash, and is not handed to the chain.
#[test]
fn the_manager_knows_a_delivered_block_by_the_hash_its_type_answers() {
    let block = Arc::new(block());
    let mut m = manager(vec![block.header.block_hash()]);
    request_from_sync_peer(&mut m, &block);

    let other = Hash([0x5a; 32]);
    let carried = Carried {
        block: Arc::clone(&block),
        wrapped_by_the_manager: false,
        hash: Some(other),
    };
    let actions = m.on_block(7, &carried);
    assert!(
        actions.iter().any(|action| matches!(
            action,
            Action::Log { message, .. }
                if message.starts_with(&format!("Got unrequested block {other} from "))
        )),
        "{actions:?}"
    );
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, Action::Disconnect { peer: 7 })),
        "{actions:?}"
    );
    assert!(m.chain_mut().kept.is_empty());
}

/// A block from a local source is borrowed: the manager wraps a copy of
/// it in the chain's block type, with the same contents, and the
/// caller's block is left alone.
#[test]
fn a_local_block_is_wrapped_for_the_chain() {
    let block = block();
    let mut m = manager(Vec::new());

    m.process_block(&block).expect("the chain accepts it");

    assert_eq!(m.chain_mut().wrapped_by_the_manager, vec![true]);
    let kept = &m.chain_mut().kept;
    assert_eq!(kept.len(), 1, "the chain was handed the block once");
    assert_eq!(*kept[0], block);
    assert!(!std::ptr::eq(Arc::as_ptr(&kept[0]), &raw const block));
    assert_ne!(kept[0].transactions.as_ptr(), block.transactions.as_ptr());
    // The chain's `Arc` is the only one: the manager kept none.
    assert_eq!(Arc::strong_count(&kept[0]), 1);
}
