// SPDX-License-Identifier: ISC
//! What the node says of a block or header the chain refused while a
//! commit of the metadata store is under way on a thread of its own
//! (`Options::background_commit`).
//!
//! The chain renders a persistence failure as a rule error, and the node
//! tells the two apart by asking the store whether a durable write has
//! failed.  A commit on its own thread fails in two steps: redb refuses
//! reads from its first failed write on, and the store is latched only
//! once the commit has returned.  A block that fails in between, on a
//! read, must not be put down to the peer that sent it, so the node waits
//! for the commit before it asks (`Database::is_fatal_settled`).
//!
//! These tests hold such a commit at its first write, with the power
//! already gone, and hand the chain something it refuses for a reason of
//! its own, which a healthy store classifies as a rule violation: a
//! block, a header, and a block an operator asks it to reconsider.  The
//! answer must wait for the held commit and then name storage.
//!
//! It must wait with the chain released.  The wait is for the database's
//! writer as well as for the commit, and the thread that holds the writer
//! may be one that wants the chain next.
//!
//! Only a refusal waits.  A block the chain accepts is answered while the
//! commit is still under way, which is what a commit on a thread of its
//! own is for: were every block to ask, every block would wait.

// Test-harness arithmetic over short waits.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::mpsc;
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options, SharedBackend};
use dcroxide_netsync::manager::SyncChain;
use dcroxide_node::rpcrun::NodeRpcChain;
use dcroxide_node::sync::NodeSyncChain;
use dcroxide_rpc::server::RpcChain;
use dcroxide_testutil::gate::GateBackend;
use dcroxide_testutil::powerloss::PowerLossBackend;
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgBlock;

/// Longer than anything here takes.
const NEVER: Duration = Duration::from_secs(60);

/// How long a call that must be waiting is watched for a return.
const WATCH: Duration = Duration::from_millis(300);

/// How long the chain is given to come free once a call is known to be
/// waiting.  It is free at once when the call waits with it released,
/// and not before the held commit is let go when it does not.
const CHAIN_FREE: Duration = Duration::from_secs(10);

/// A chain at its genesis block over a store whose commits can be held
/// and whose power can fail.
struct Node {
    _dir: tempfile::TempDir,
    db: Database,
    chain: Arc<Mutex<Chain>>,
    params: dcroxide_chaincfg::Params,
    power: Arc<PowerLossBackend>,
    gate: Arc<GateBackend>,
}

impl Node {
    fn new() -> Node {
        let params = dcroxide_chaincfg::regnet_params();
        let dir = tempfile::tempdir().expect("temp dir");
        let db_dir = dir.path().join("blocks");
        std::fs::create_dir_all(&db_dir).expect("mkdir");
        let power = PowerLossBackend::create(&db_dir.join("metadata.redb"), true);
        let gate = GateBackend::new(Arc::clone(&power) as SharedBackend);
        let mut opts = Options::new(&db_dir, params.net.0);
        opts.backend = Some(Arc::clone(&gate) as SharedBackend);
        opts.background_commit = true;
        // Small enough that one commit of filler arms the next commit's
        // flush.
        opts.cache_max_size = 64 * 1024;
        let db = Database::create(&opts).expect("create database");
        let chain = Arc::new(Mutex::new(
            Chain::open(db.clone(), &params, params.assume_valid, false, 0).expect("open chain"),
        ));
        Node {
            _dir: dir,
            db,
            chain,
            params,
            power,
            gate,
        }
    }

    fn sync_chain(&self) -> NodeSyncChain {
        NodeSyncChain::new(Arc::clone(&self.chain), self.params.clone())
    }

    fn rpc_chain(&self) -> NodeRpcChain {
        NodeRpcChain::new(Arc::clone(&self.chain), self.params.clone())
    }

    /// Whether the chain's lock comes free within [`CHAIN_FREE`].
    fn chain_comes_free(&self) -> bool {
        let deadline = Instant::now() + CHAIN_FREE;
        loop {
            match self.chain.try_lock() {
                Ok(_) => return true,
                Err(TryLockError::Poisoned(_)) => panic!("chain mutex poisoned"),
                Err(TryLockError::WouldBlock) => {}
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Leave a flush's commit held at its first write on its own thread,
    /// with the power gone: the commit fails the moment it is let go.
    fn hold_a_commit_that_will_fail(&self) {
        // Whatever opening the chain left in the write cache goes first,
        // so the filler alone arms the flush.
        self.db.flush().expect("flush");
        self.db
            .update(|tx| {
                let meta = tx.metadata();
                for i in 0..48u32 {
                    let mut key = b"filler".to_vec();
                    key.extend_from_slice(&i.to_be_bytes());
                    meta.put(&key, &[0x5au8; 1024])?;
                }
                Ok(())
            })
            .expect("the filler");
        self.gate.arm();
        self.db
            .update(|tx| tx.metadata().put(b"filler-trip", b"x"))
            .expect("the commit that trips the flush");
        assert!(
            self.gate.wait_held(NEVER),
            "the flush's commit is under way on a thread of its own"
        );
        assert!(
            !self.gate.holds_a_length_change(),
            "the commit was stopped growing the file, where no transaction can begin beside it"
        );
        self.power.power_fails_after(0);
        assert!(!self.db.is_fatal(), "nothing has failed yet");
    }

    /// Let the held commit go, wait for it, and let go of the store.
    fn finish(self) {
        self.gate.open();
        let _ = self.db.wait_background_commit();
    }
}

/// Run `call` on a thread of its own and check that, a moment after it
/// has started, it is still waiting and is not holding the chain while
/// it waits.  Returns where its answer will arrive.
fn waiting_with_the_chain_released<T: Send + 'static>(
    node: &Node,
    what: &str,
    call: impl FnOnce() -> T + Send + 'static,
) -> mpsc::Receiver<T> {
    let (started, has_started) = mpsc::channel();
    let (done, result) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = started.send(());
        let _ = done.send(call());
    });
    has_started.recv_timeout(NEVER).expect("the call started");
    assert!(
        matches!(
            result.recv_timeout(WATCH),
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "{what} was classified while the commit that decides it was held"
    );
    assert!(
        node.chain_comes_free(),
        "{what} holds the chain while it waits for the commit"
    );
    result
}

/// Run `call` on a thread of its own, check that it waits for the held
/// commit with the chain released, let that commit fail, and return what
/// the call answered.
fn answered_after_the_commit<T: Send + 'static>(
    node: &Node,
    what: &str,
    call: impl FnOnce() -> T + Send + 'static,
) -> T {
    let result = waiting_with_the_chain_released(node, what, call);
    node.gate.open();
    let answer = result.recv_timeout(NEVER).expect("the call returns");
    assert!(node.db.is_fatal(), "the held commit failed");
    answer
}

/// The block of the first row of dcrd's full block battery that carries
/// `tag`, the chain's verdict on a block that builds on genesis: `accept`
/// for the first block of the battery's chain, `reject` for one in its
/// place that pays the wrong amount.
fn battery_block(tag: &str) -> MsgBlock {
    let rows = include_str!("../../dcroxide-blockchain/tests/data/fullblock_vectors.txt");
    let row = rows
        .lines()
        .map(|line| line.split(' ').collect::<Vec<_>>())
        .find(|fields| fields[0] == tag)
        .expect("the battery has such a row");
    // accept <name> <mainchain> <orphan> <blockhex>, reject <name> <kind>
    // <blockhex>.
    let hex = row.last().expect("a block");
    MsgBlock::from_bytes(&unhex(hex)).expect("block").0
}

/// A header the chain refuses for breaking a rule: the genesis header
/// again, as the block after it, with a proof of work target no network
/// allows.
fn refused_header(params: &dcroxide_chaincfg::Params) -> dcroxide_wire::BlockHeader {
    let mut header = params.genesis_block.header;
    header.prev_block = params.genesis_hash;
    header.height = 1;
    header.bits = 0x0100_0000;
    header
}

/// A block that fails while a commit that is about to fail is under way
/// is reported as a storage failure: the node waits for the commit
/// before it classifies, where the latch read at once would have said a
/// peer sent a bad block.
#[test]
fn a_block_refused_during_a_failing_commit_is_not_blamed_on_the_peer() {
    let node = Node::new();
    let genesis = Arc::new(node.params.genesis_block.clone());

    // On a healthy store a duplicate block is a rule error, and nothing
    // waits.
    let failure = node
        .sync_chain()
        .process_block(&Arc::clone(&genesis).into())
        .expect_err("genesis is already present");
    assert!(failure.is_duplicate_block && failure.is_rule_error);

    node.hold_a_commit_that_will_fail();
    let mut sync_chain = node.sync_chain();
    let failure = answered_after_the_commit(&node, "a refused block", move || {
        sync_chain
            .process_block(&genesis.into())
            .expect_err("genesis is already present")
    });
    assert!(failure.is_duplicate_block, "{}", failure.message);
    assert!(
        !failure.is_rule_error,
        "a block that failed beside a failing commit was put down to its peer: {}",
        failure.message
    );
    node.finish();
}

/// The same for a header.
#[test]
fn a_header_refused_during_a_failing_commit_is_not_blamed_on_the_peer() {
    let node = Node::new();
    let header = refused_header(&node.params);

    let failure = node
        .sync_chain()
        .process_block_header(&header)
        .expect_err("the header breaks a rule");
    assert!(
        failure.is_rule_error,
        "the header must fail as a rule violation for this test to show anything: {}",
        failure.message
    );

    node.hold_a_commit_that_will_fail();
    let mut sync_chain = node.sync_chain();
    let failure = answered_after_the_commit(&node, "a refused header", move || {
        sync_chain
            .process_block_header(&header)
            .expect_err("the header breaks a rule")
    });
    assert!(
        !failure.is_rule_error,
        "a header that failed beside a failing commit was put down to its peer: {}",
        failure.message
    );
    node.finish();
}

/// A read does not wait for a commit under way, and a refusal beside a
/// commit that then lands is the rule error it always was, classified
/// once that commit has ended.
#[test]
fn a_refusal_beside_a_commit_that_lands_is_still_a_rule_error() {
    let node = Node::new();
    let genesis = Arc::new(node.params.genesis_block.clone());
    node.hold_a_commit_that_will_fail();
    // The power comes back before the commit is let go.
    node.power.power_fails_after(u64::MAX);

    // Reads go on while the commit is held: nothing here waits for it.
    assert!(node.sync_chain().have_block(&node.params.genesis_hash));

    let mut sync_chain = node.sync_chain();
    let result = waiting_with_the_chain_released(&node, "a refused block", move || {
        sync_chain
            .process_block(&genesis.into())
            .expect_err("genesis is already present")
    });
    node.gate.open();
    let failure = result.recv_timeout(NEVER).expect("the call returns");
    assert!(!node.db.is_fatal(), "the commit landed");
    assert!(failure.is_duplicate_block && failure.is_rule_error);
    node.finish();
}

/// A block the chain accepts is answered while a commit is still under
/// way: only a refusal has to know whether storage failed, and only a
/// refusal waits.  The first block of the full block battery is connected
/// beside a held commit, and the call returns with that commit still
/// held.
#[test]
fn an_accepted_block_does_not_wait_for_the_commit_under_way() {
    let node = Node::new();
    let block = Arc::new(battery_block("accept"));
    // A tip less than a day old makes the chain current, and a chain that
    // becomes current asks for a durable flush, which waits for the
    // commit under way as it must.  The battery's blocks are older.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs();
    assert!(
        u64::from(block.header.timestamp) + 2 * 24 * 60 * 60 < now,
        "the battery was generated within the last two days: its blocks would bring the chain \
         current, and this test would wait for the flush that asks for"
    );
    node.hold_a_commit_that_will_fail();
    // The power comes back: the held commit will land.
    node.power.power_fails_after(u64::MAX);

    let mut sync_chain = node.sync_chain();
    let (done, result) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = done.send(
            sync_chain
                .process_block(&block.into())
                .map_err(|failure| failure.message),
        );
    });
    let outcome = result
        .recv_timeout(NEVER / 3)
        .expect("an accepted block waited for the commit under way");
    assert_eq!(
        outcome,
        Ok(0),
        "the battery's first block extends the chain"
    );
    assert!(node.gate.is_held(), "the commit is still held");
    assert!(!node.db.is_fatal());
    assert_eq!(node.sync_chain().best_snapshot().height, 1);
    node.finish();
}

/// `reconsiderblock` classifies its failure the same way.  A block that
/// failed validation fails it again when it is reconsidered, which a
/// healthy store reports as a rule violation in every part.  Beside a
/// commit that is about to fail the answer waits for that commit, with
/// the chain released, and then does not put the failure down to the
/// block.
#[test]
fn a_block_reconsidered_during_a_failing_commit_is_not_called_a_rule_violation() {
    let node = Node::new();
    let block = Arc::new(battery_block("reject"));
    let hash = block.header.block_hash();
    let failure = node
        .sync_chain()
        .process_block(&Arc::clone(&block).into())
        .expect_err("the block pays the wrong amount");
    assert!(failure.is_rule_error, "{}", failure.message);

    // On a healthy store, and with nothing to wait for.
    let failure = node
        .rpc_chain()
        .reconsider_block(&hash)
        .expect_err("the block fails validation again");
    assert!(
        !failure.is_unknown_block && failure.all_rule_errs,
        "reconsidering the block must fail as a rule violation for this test to show \
         anything: {}",
        failure.message
    );

    node.hold_a_commit_that_will_fail();
    let rpc_chain = node.rpc_chain();
    let failure = answered_after_the_commit(&node, "a reconsidered block", move || {
        rpc_chain
            .reconsider_block(&hash)
            .expect_err("the block fails validation again")
    });
    assert!(!failure.is_unknown_block, "{}", failure.message);
    assert!(
        !failure.all_rule_errs,
        "a block reconsidered beside a failing commit was called a rule violation: {}",
        failure.message
    );
    node.finish();
}
