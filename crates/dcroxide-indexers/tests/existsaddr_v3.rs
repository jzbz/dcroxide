// SPDX-License-Identifier: ISC
//! The exists address index's layout 3 against a reference model with
//! dcrd's semantics, and its lifecycle: restart, catch-up, the version
//! refusal, the rows an older build adds, the drops, a damaged run row,
//! and store read errors.
//!
//! The model is dcrd's index reduced to its two sets: the bucket, which a
//! connect adds the block's keys and the drained mempool map to and
//! nothing removes, and the mempool map (`mpExistsAddr`).  An address
//! exists when either holds it.  Random sequences of connects, reorgs,
//! mempool transactions, flushes, restarts and drops run under tiny merge
//! limits, so every journal, merge and garbage-collection path runs, and
//! after every step every address the run touched and a thousand absent
//! ones are looked up both singly and in one batch.  A seed that fails is
//! printed; `DCROXIDE_TEST_SEED` replays it.
//!
//! The unsupported-address error path of `addr_to_key` cannot be reached
//! from here: every `Address` this port can build folds onto one of the
//! four key types, as every address dcrd's `stdaddr` decodes does.  The
//! whole-call failure it would cause is pinned at the RPC handler by the
//! dcrd-generated `rpchandlers6` vectors.

// Test-harness arithmetic over bounded counts and heights.
#![allow(clippy::arithmetic_side_effects)]

#[macro_use]
#[path = "support/chain.rs"]
mod chain;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chain::{
    Key, PUBKEYS, TestChain, address_of, block_on, p2pk_address, script_of, tx_paying,
    tx_redeeming_multisig, unsupported_scripts,
};
use dcroxide_chaincfg::{Params, simnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options, SharedBackend, StorageBackend};
use dcroxide_indexers::{
    CONNECT_NTFN, DISCONNECT_NTFN, EXISTS_ADDR_INDEX_KEY, EXISTS_ADDRESS_INDEX_NAME,
    ExistsAddrIndex, ExistsAddrPolicy, IdxError, IndexNtfn, IndexSubscriber, Indexer, Interrupt,
    LogLevel, LogSink, NO_PREREQS, addr_to_key, exists_addr_partition_of,
};
use dcroxide_testutil::SplitMix64;
use dcroxide_wire::MsgBlock;
use tempfile::TempDir;

impl_chain_queryer!(dcroxide_indexers::ChainQueryer, chain::TestChain);

fn params() -> &'static Params {
    static PARAMS: std::sync::OnceLock<Params> = std::sync::OnceLock::new();
    PARAMS.get_or_init(simnet_params)
}

// ---------------------------------------------------------------------
// The reference model
// ---------------------------------------------------------------------

/// dcrd's index as two sets.
#[derive(Default, Clone)]
struct Model {
    /// The bucket: every key a connect wrote.  Nothing removes from it.
    bucket: HashSet<Key>,
    /// `mpExistsAddr`.
    mempool: HashSet<Key>,
}

impl Model {
    fn connect(&mut self, keys: &[Key]) {
        self.bucket.extend(keys.iter().copied());
        self.bucket.extend(self.mempool.drain());
    }

    fn exists(&self, key: &Key) -> bool {
        self.bucket.contains(key) || self.mempool.contains(key)
    }
}

// ---------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------

/// An open database with its subscriber and live index.  Every handle
/// of the database must be gone before the file can be opened again: the
/// index holds one, and the database holds the index's store.
struct Live {
    db: Arc<Database>,
    subber: IndexSubscriber,
    idx: Arc<Mutex<ExistsAddrIndex>>,
}

/// A live index over a test chain, with the model beside it.
struct Harness {
    _dir: TempDir,
    opts: Options,
    chain: Arc<TestChain>,
    live: Option<Live>,
    policy: ExistsAddrPolicy,
    model: Model,
    /// The keys of every block built, by hash.
    block_keys: HashMap<Hash, Vec<Key>>,
    /// Every key the run has used, mined or not.
    touched: BTreeSet<Key>,
    /// Keys of recent blocks, newest last, for reuse.
    recent: Vec<Key>,
    salt: u32,
}

fn new_subber() -> IndexSubscriber {
    IndexSubscriber::new(Arc::new(AtomicBool::new(false)), None)
}

fn open_index(
    subber: &mut IndexSubscriber,
    db: &Arc<Database>,
    chain: &Arc<TestChain>,
    policy: ExistsAddrPolicy,
) -> Result<Arc<Mutex<ExistsAddrIndex>>, IdxError> {
    ExistsAddrIndex::new_with_policy(
        subber,
        Arc::clone(db),
        Arc::clone(chain) as Arc<dyn dcroxide_indexers::ChainQueryer>,
        NO_PREREQS,
        policy,
    )
}

impl Harness {
    fn new(policy: ExistsAddrPolicy) -> Harness {
        Harness::with_opts(policy, |_| {})
    }

    fn with_opts(policy: ExistsAddrPolicy, tune: impl FnOnce(&mut Options)) -> Harness {
        let dir = TempDir::new().expect("tempdir");
        let mut opts = Options::new(dir.path().join("db"), params().net.0);
        tune(&mut opts);
        let db = Arc::new(Database::create(&opts).expect("create"));
        let chain = TestChain::new(params());
        let mut subber = new_subber();
        let idx = open_index(&mut subber, &db, &chain, policy).expect("index");
        Harness {
            _dir: dir,
            opts,
            chain,
            live: Some(Live { db, subber, idx }),
            policy,
            model: Model::default(),
            block_keys: HashMap::new(),
            touched: BTreeSet::new(),
            recent: Vec::new(),
            salt: 0,
        }
    }

    fn live(&self) -> &Live {
        self.live.as_ref().expect("open")
    }

    fn live_mut(&mut self) -> &mut Live {
        self.live.as_mut().expect("open")
    }

    fn db(&self) -> &Arc<Database> {
        &self.live().db
    }

    fn idx(&self) -> &Arc<Mutex<ExistsAddrIndex>> {
        &self.live().idx
    }

    fn subber(&mut self) -> &mut IndexSubscriber {
        &mut self.live_mut().subber
    }

    /// Close the database cleanly and release every handle of it.
    fn close(&mut self) {
        let live = self.live.take().expect("open");
        live.db.close().expect("close");
    }

    /// Open the database again with a new index over it, caught up.
    fn open(&mut self) {
        assert!(self.live.is_none());
        let db = Arc::new(Database::open(&self.opts).expect("reopen"));
        let mut subber = new_subber();
        let idx = open_index(&mut subber, &db, &self.chain, self.policy).expect("reopen index");
        subber.catch_up(&*self.chain).expect("catch up");
        self.live = Some(Live { db, subber, idx });
    }

    /// Build a block on the tip from `rng`: new keys of every type,
    /// keys reused from recent blocks and from long ago, pay-to-pubkey
    /// outputs, a multisig redemption, and outputs no key comes from.
    fn random_block(&mut self, rng: &mut SplitMix64) -> Arc<MsgBlock> {
        let mut scripts = Vec::new();
        let mut keys = Vec::new();
        for _ in 0..rng.below(7) + 1 {
            let key = match rng.below(10) {
                0..=5 => random_key(rng),
                6 | 7 if !self.recent.is_empty() => {
                    let from = self.recent.len().saturating_sub(40);
                    self.recent[from + rng.below((self.recent.len() - from) as u64) as usize]
                }
                _ if !self.touched.is_empty() => *self
                    .touched
                    .iter()
                    .nth(rng.below(self.touched.len() as u64) as usize)
                    .expect("touched key"),
                _ => random_key(rng),
            };
            scripts.push(script_of(&key, params()));
            keys.push(key);
        }
        if rng.below(4) == 0 {
            let pk = &PUBKEYS[rng.below(3) as usize];
            let addr = p2pk_address(pk, params());
            scripts.push(addr.payment_script().1);
            keys.push(addr_to_key(&addr).expect("p2pk key"));
        }
        if rng.below(4) == 0 {
            scripts.extend(unsupported_scripts());
        }
        let mut txs = vec![tx_paying(&scripts)];
        if rng.below(6) == 0 {
            txs.push(tx_redeeming_multisig(&PUBKEYS[..2]));
            for pk in &PUBKEYS[..2] {
                keys.push(addr_to_key(&p2pk_address(pk, params())).expect("multisig key"));
            }
        }
        self.salt += 1;
        let tip = self.chain.at(self.chain.tip().0);
        let block = block_on(&tip, self.salt, txs);
        keys.sort_unstable();
        keys.dedup();
        self.touched.extend(keys.iter().copied());
        self.recent.extend(keys.iter().copied());
        self.block_keys.insert(block.header.block_hash(), keys);
        block
    }

    fn connect(&mut self, block: &Arc<MsgBlock>) {
        let parent = self.chain.at(self.chain.tip().0);
        self.chain.add(block);
        self.subber()
            .notify(&IndexNtfn {
                ntfn_type: CONNECT_NTFN,
                block: Arc::clone(block),
                parent,
                is_treasury_enabled: false,
            })
            .expect("connect");
        let keys = self.block_keys[&block.header.block_hash()].clone();
        self.model.connect(&keys);
    }

    fn disconnect(&mut self) {
        let block = self.chain.remove_tip();
        let parent = self.chain.at(self.chain.tip().0);
        self.subber()
            .notify(&IndexNtfn {
                ntfn_type: DISCONNECT_NTFN,
                block,
                parent,
                is_treasury_enabled: false,
            })
            .expect("disconnect");
    }

    /// A mempool transaction paying `keys`.
    fn unconfirmed(&mut self, keys: &[Key]) {
        let scripts: Vec<Vec<u8>> = keys.iter().map(|k| script_of(k, params())).collect();
        self.idx()
            .lock()
            .expect("index")
            .add_unconfirmed_tx(&tx_paying(&scripts));
        self.model.mempool.extend(keys.iter().copied());
        self.touched.extend(keys.iter().copied());
    }

    /// Close the database cleanly and open it again with a new index,
    /// as a restart does.  The mempool map is memory only and is gone.
    fn restart(&mut self) {
        self.close();
        self.open();
        self.model.mempool.clear();
        // What the restart rebuilt in memory is exactly the journal's
        // pending keys.
        let check = dcroxide_indexers::check_layout(self.db())
            .expect("layout invariants")
            .expect("the index exists");
        assert_eq!(
            self.idx().lock().expect("index").memtable_keys(),
            check.pending,
            "the rebuilt memtable must equal the journal's pending keys"
        );
    }

    /// Drop the live index and build it again from genesis.
    fn drop_and_recreate(&mut self) {
        let interrupt: Interrupt = Arc::new(AtomicBool::new(false));
        self.idx()
            .lock()
            .expect("index")
            .drop_index(&interrupt, self.db(), None)
            .expect("drop");
        assert!(
            self.raw_rows().is_empty(),
            "the drop left rows under the bucket"
        );
        let chain = Arc::clone(&self.chain);
        let policy = self.policy;
        let live = self.live_mut();
        live.subber.stop(EXISTS_ADDRESS_INDEX_NAME).expect("stop");
        live.idx = open_index(&mut live.subber, &live.db, &chain, policy).expect("recreate");
        live.subber.catch_up(&*chain).expect("catch up");
        // The rebuilt index holds the main chain's keys only.
        self.model = Model::default();
        for height in 1..=self.chain.tip().0 {
            let hash = self.chain.at(height).header.block_hash();
            let keys = self.block_keys[&hash].clone();
            self.model.connect(&keys);
        }
    }

    /// Every row under the index's bucket id, raw.
    fn raw_rows(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        raw_rows(self.db())
    }

    /// Compare the index with the model over every touched key and
    /// `absent` random keys, singly and in one batch, and the tip.
    fn check(&self, rng: &mut SplitMix64, absent: usize, context: &str) {
        let idx = self.idx().lock().expect("index");
        assert_eq!(idx.tip().expect("tip"), self.chain.tip(), "{context}: tip");
        let query = idx.query();
        drop(idx);
        let mut keys: Vec<Key> = self.touched.iter().copied().collect();
        for _ in 0..absent {
            keys.push(random_key(rng));
        }
        let addrs: Vec<_> = keys.iter().map(|k| address_of(k, params())).collect();
        let want: Vec<bool> = keys.iter().map(|k| self.model.exists(k)).collect();
        let got = query.exists_addresses(&addrs).expect("exists_addresses");
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(
                got[i],
                want[i],
                "{context}: existsaddresses of {} ({} keys in the bucket model, {} in the mempool)",
                hex(key),
                self.model.bucket.len(),
                self.model.mempool.len()
            );
        }
        for (key, addr) in keys.iter().zip(&addrs).take(self.touched.len() + 20) {
            assert_eq!(
                query.exists_address(addr).expect("exists_address"),
                self.model.exists(key),
                "{context}: existsaddress of {}",
                hex(key)
            );
        }
        // A pay-to-pubkey address answers as its pubkey-hash twin.
        for pk in &PUBKEYS {
            let p2pk = p2pk_address(pk, params());
            let key = addr_to_key(&p2pk).expect("key");
            let twin = address_of(&key, params());
            assert_eq!(key[0], 0, "folds onto the secp256k1 pubkey-hash type");
            let a = query.exists_address(&p2pk).expect("p2pk");
            let b = query.exists_address(&twin).expect("twin");
            assert_eq!(
                (a, b),
                (self.model.exists(&key), self.model.exists(&key)),
                "{context}"
            );
        }
        if let Some(check) = dcroxide_indexers::check_layout(self.db()).expect("layout invariants")
        {
            // Nothing the store holds is unknown to the model.
            for key in check.runs.iter().chain(&check.pending) {
                assert!(
                    self.model.bucket.contains(key),
                    "{context}: the store holds {} the model never wrote",
                    hex(key)
                );
            }
        }
    }
}

fn random_key(rng: &mut SplitMix64) -> Key {
    let mut key = [0u8; 21];
    key[0] = rng.below(4) as u8;
    for chunk in key[1..].chunks_mut(8) {
        let r = rng.next_u64().to_le_bytes();
        chunk.copy_from_slice(&r[..chunk.len()]);
    }
    key
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn bucket_id(db: &Database) -> Option<[u8; 4]> {
    let tx = db.begin(false).expect("begin");
    let id = tx
        .metadata()
        .bucket(EXISTS_ADDR_INDEX_KEY)
        .map(|b| b.raw_id());
    tx.rollback().expect("rollback");
    id
}

fn raw_rows(db: &Database) -> Vec<(Vec<u8>, Vec<u8>)> {
    let Some(id) = bucket_id(db) else {
        return Vec::new();
    };
    raw_rows_under(db, &id)
}

fn raw_rows_under(db: &Database, id: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let tx = db.begin(false).expect("begin");
    let rows = tx.try_scan_after(id, None, usize::MAX).expect("scan");
    tx.rollback().expect("rollback");
    rows
}

/// Run a random sequence of `steps` under `policy` and hold the index to
/// the model after each one.
fn differential(policy: ExistsAddrPolicy, rng: &mut SplitMix64, steps: usize) {
    let mut h = Harness::new(policy);
    h.check(rng, 1000, "start");
    for step in 0..steps {
        let action = rng.below(100);
        let context = format!("step {step} (action {action})");
        match action {
            0..=49 => {
                let block = h.random_block(rng);
                h.connect(&block);
            }
            50..=59 if h.chain.tip().0 > 0 => {
                // A reorg: the tip out, one or two siblings in.
                h.disconnect();
                for _ in 0..rng.below(2) + 1 {
                    let block = h.random_block(rng);
                    h.connect(&block);
                }
            }
            60..=64 if h.chain.tip().0 > 0 => h.disconnect(),
            65..=79 => {
                let mut keys = Vec::new();
                for _ in 0..rng.below(4) + 1 {
                    keys.push(if rng.below(3) == 0 && !h.touched.is_empty() {
                        *h.touched
                            .iter()
                            .nth(rng.below(h.touched.len() as u64) as usize)
                            .expect("touched")
                    } else {
                        random_key(rng)
                    });
                }
                h.unconfirmed(&keys);
            }
            80..=89 => h.db().flush().expect("flush"),
            90..=96 => h.restart(),
            97..=99 => h.drop_and_recreate(),
            _ => {
                let block = h.random_block(rng);
                h.connect(&block);
            }
        }
        let absent = if step % 10 == 0 { 1000 } else { 100 };
        h.check(rng, absent, &context);
    }
    h.restart();
    h.check(rng, 1000, "after the final restart");
}

#[test]
fn layout_3_answers_as_dcrds_index_under_tiny_limits() {
    let mut rng = SplitMix64::from_entropy("layout_3_answers_as_dcrds_index_under_tiny_limits");
    differential(ExistsAddrPolicy::tiny(), &mut rng, 400);
}

#[test]
fn layout_3_answers_as_dcrds_index_merging_everything_at_every_flush() {
    let mut rng = SplitMix64(0x6578_6973_7473_0001);
    let policy = ExistsAddrPolicy {
        k0: 0,
        k0_hard: 0,
        ..ExistsAddrPolicy::tiny()
    };
    differential(policy, &mut rng, 300);
}

#[test]
fn layout_3_answers_as_dcrds_index_at_the_default_limits() {
    let mut rng = SplitMix64(0x6578_6973_7473_0002);
    differential(ExistsAddrPolicy::default(), &mut rng, 200);
}

/// A larger run whose keys crowd a few partitions, so bases grow and the
/// delta path, the budget stop and the hard bound all run.  The keys are
/// found for their partitions under the policy's fixed partition key, as
/// nobody could find them under a node's secret one.
#[test]
fn crowded_partitions_run_every_merge_path() {
    let pkey = *b"crowded the four";
    let policy = ExistsAddrPolicy {
        k0: 20,
        k0_hard: 40,
        budget_pages: 1,
        u_max: 30,
        partition_key: Some(pkey),
    };
    let work = Arc::new(Mutex::new([0u64; 3]));
    let seen = Arc::clone(&work);
    let mut h = Harness::with_opts(policy, move |opts| {
        opts.flush_observer = Some(Arc::new(
            move |obs: &dcroxide_database::FlushObservation| {
                if let Some(p) = obs.participant {
                    let mut w = seen.lock().expect("work");
                    w[0] += p.merges;
                    w[1] += p.base_rewrites;
                    w[2] += p.rows_removed;
                }
            },
        ));
    });
    let mut rng = SplitMix64(0x6578_6973_7473_0003);
    for round in 0..120u32 {
        let mut keys = Vec::new();
        for _ in 0..12 {
            // Four partitions only.
            let p = (rng.below(4) as u8) * 64;
            let key = loop {
                let key = random_key(&mut rng);
                if exists_addr_partition_of(&pkey, &key) == p {
                    break key;
                }
            };
            keys.push(key);
        }
        let scripts: Vec<Vec<u8>> = keys.iter().map(|k| script_of(k, params())).collect();
        h.salt += 1;
        let tip = h.chain.at(h.chain.tip().0);
        let block = block_on(&tip, h.salt, vec![tx_paying(&scripts)]);
        keys.sort_unstable();
        keys.dedup();
        h.touched.extend(keys.iter().copied());
        h.block_keys.insert(block.header.block_hash(), keys);
        h.connect(&block);
        if round % 7 == 0 {
            h.db().flush().expect("flush");
        }
    }
    h.db().flush().expect("flush");
    h.check(&mut rng, 1000, "crowded");
    let [merges, base_rewrites, removed] = *work.lock().expect("work");
    assert!(
        base_rewrites > 0 && merges > base_rewrites && removed > 0,
        "merges {merges}, base rewrites {base_rewrites}, rows removed {removed}"
    );
    h.restart();
    h.check(&mut rng, 1000, "crowded, restarted");
}

// ---------------------------------------------------------------------
// The mempool hand-off, single-threaded
// ---------------------------------------------------------------------

/// A connect copies the mempool map and removes exactly the copied keys
/// in its commit hook; a connect that rolls back leaves the map alone,
/// where dcrd's drain would have lost the keys.
#[test]
fn a_connect_moves_exactly_the_copied_mempool_keys() {
    let mut h = Harness::new(ExistsAddrPolicy::tiny());
    let mut rng = SplitMix64(7);
    let early = random_key(&mut rng);
    h.unconfirmed(&[early]);
    let block = h.random_block(&mut rng);
    h.connect(&block);
    h.check(&mut rng, 100, "after the connect");
    // The key is the index's now, not the mempool's.
    let query = h.idx().lock().expect("index").query();
    assert!(
        query
            .exists_address(&address_of(&early, params()))
            .expect("lookup")
    );

    // A connect whose transaction fails rolls back: its hook never runs
    // and the mempool keys stay where they were.
    let late = random_key(&mut rng);
    h.unconfirmed(&[late]);
    let block = h.random_block(&mut rng);
    h.chain.add(&block);
    {
        let mut idx = h.idx().lock().expect("index");
        let tx = h.db().begin(true).expect("begin");
        idx.process_notification(
            &tx,
            &IndexNtfn {
                ntfn_type: CONNECT_NTFN,
                block: Arc::clone(&block),
                parent: h.chain.at(block.header.height as i64 - 1),
                is_treasury_enabled: false,
            },
        )
        .expect("connect");
        tx.rollback().expect("rollback");
    }
    h.chain.remove_tip();
    assert!(
        query
            .exists_address(&address_of(&late, params()))
            .expect("lookup"),
        "the rolled-back connect lost a mempool key"
    );
    for key in &h.block_keys[&block.header.block_hash()] {
        assert_eq!(
            query
                .exists_address(&address_of(key, params()))
                .expect("lookup"),
            h.model.exists(key),
            "a rolled-back connect's key became visible"
        );
    }
    h.check(&mut rng, 100, "after the rollback");
}

// ---------------------------------------------------------------------
// Restart, catch-up, version and options
// ---------------------------------------------------------------------

/// A layout-2 directory -- dcrd's version 2 rows -- is refused with the
/// remedy, and left exactly as it was.
#[test]
fn a_layout_2_index_is_refused_with_the_remedy() {
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("db"), params().net.0);
    let db = Arc::new(Database::create(&opts).expect("create"));
    let chain = TestChain::new(params());
    write_layout_2(&db, &chain, 2);
    let before = all_rows(&db);

    let err = open_index(&mut new_subber(), &db, &chain, ExistsAddrPolicy::default())
        .err()
        .expect("a version 2 index must be refused");
    assert_eq!(
        err.to_string(),
        "exists address index: on-disk version 2 is not supported by this build; run once with \
         --noexistsaddrindex --dropexistsaddrindex, then restart to rebuild it from genesis"
    );
    assert_eq!(all_rows(&db), before, "the refusal changed the store");
    assert!(
        db.clear_flush_participant().is_none(),
        "a refused index registered its store"
    );

    // A tip with no version row is refused the same way.
    db.update(|tx| {
        tx.metadata()
            .bucket(b"idxtips")
            .expect("tips")
            .delete(&[b"v".as_slice(), EXISTS_ADDR_INDEX_KEY].concat())
    })
    .expect("delete the version row");
    let err = open_index(&mut new_subber(), &db, &chain, ExistsAddrPolicy::default())
        .err()
        .expect("an unversioned index must be refused");
    assert!(
        err.to_string()
            .contains("has no version row, is not supported by this build; run once with"),
        "{err}"
    );
}

/// Connect a block on the chain's tip paying `keys`.
fn connect_paying(
    chain: &TestChain,
    subber: &mut IndexSubscriber,
    salt: u32,
    keys: &[Key],
) -> Arc<MsgBlock> {
    let scripts: Vec<Vec<u8>> = keys.iter().map(|k| script_of(k, params())).collect();
    let parent = chain.at(chain.tip().0);
    let block = block_on(&parent, salt, vec![tx_paying(&scripts)]);
    chain.add(&block);
    subber
        .notify(&IndexNtfn {
            ntfn_type: CONNECT_NTFN,
            block: Arc::clone(&block),
            parent,
            is_treasury_enabled: false,
        })
        .expect("connect");
    block
}

/// Drop the index with it off, as `--noexistsaddrindex
/// --dropexistsaddrindex` does, then start it again and catch it up: the
/// remedy every corruption error names.  Returns the rebuilt index.
fn drop_and_rebuild(
    opts: &Options,
    chain: &Arc<TestChain>,
) -> (Arc<Database>, IndexSubscriber, Arc<Mutex<ExistsAddrIndex>>) {
    let db = Arc::new(Database::open(opts).expect("open"));
    let interrupt: Interrupt = Arc::new(AtomicBool::new(false));
    dcroxide_indexers::drop_exists_addr_index(&interrupt, &db, None).expect("drop");
    let mut subber = new_subber();
    let idx = open_index(&mut subber, &db, chain, ExistsAddrPolicy::tiny()).expect("rebuild");
    subber.catch_up(&**chain).expect("catch up");
    (db, subber, idx)
}

/// A build from before layout 3 has no version check.  Run with the index
/// on over a layout-3 index, it puts a bare 21-byte row per new address
/// and moves the tip, and this build never reads such rows.  The next
/// start must refuse with the remedy, leaving every row as it was, rather
/// than open without those addresses: the tip is past their block, so no
/// catch-up would ever revisit it.
#[test]
fn rows_a_build_from_before_layout_3_adds_are_refused_with_the_remedy() {
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("db"), params().net.0);
    let chain = TestChain::new(params());
    let mut rng = SplitMix64(0x646f_776e_0001);
    let (k1, k2) = (random_key(&mut rng), random_key(&mut rng));
    {
        let db = Arc::new(Database::create(&opts).expect("create"));
        let mut subber = new_subber();
        let idx = open_index(&mut subber, &db, &chain, ExistsAddrPolicy::tiny()).expect("index");
        connect_paying(&chain, &mut subber, 1, &[k1]);
        drop(idx);
        drop(subber);
        db.close().expect("close");
    }
    // What the previous build's connect of block 2 writes: the key row
    // and the tip, and no version row, so the version stays 3.
    let block2 = block_on(
        &chain.at(1),
        2,
        vec![tx_paying(&[script_of(&k2, params())])],
    );
    chain.add(&block2);
    {
        let db = Database::open(&opts).expect("open as the previous build");
        db.update(|tx| {
            let meta = tx.metadata();
            meta.bucket(EXISTS_ADDR_INDEX_KEY)
                .expect("bucket")
                .put(&k2, &[])?;
            let mut tip = block2.header.block_hash().0.to_vec();
            tip.extend_from_slice(&2u32.to_le_bytes());
            meta.bucket(b"idxtips")
                .expect("tips")
                .put(EXISTS_ADDR_INDEX_KEY, &tip)
        })
        .expect("the previous build's connect");
        db.close().expect("close");
    }
    {
        let db = Arc::new(Database::open(&opts).expect("reopen"));
        let before = all_rows(&db);
        let err = open_index(&mut new_subber(), &db, &chain, ExistsAddrPolicy::tiny())
            .err()
            .expect("an index holding layout-2 rows must be refused");
        let text = err.to_string();
        assert!(
            text.contains("no layout-3 shape")
                && text.contains(
                    "run once with --noexistsaddrindex --dropexistsaddrindex, then restart to \
                     rebuild the index from genesis"
                ),
            "{text}"
        );
        assert_eq!(all_rows(&db), before, "the refusal changed the store");
        assert!(db.clear_flush_participant().is_none());
        assert!(dcroxide_indexers::check_layout(&db).is_err());
        db.close().expect("close");
    }
    // The remedy rebuilds both blocks' keys.
    let (db, subber, idx) = drop_and_rebuild(&opts, &chain);
    let query = idx.lock().expect("index").query();
    let found = query
        .exists_addresses(&[address_of(&k1, params()), address_of(&k2, params())])
        .expect("lookups");
    assert_eq!(found, vec![true, true]);
    drop(idx);
    drop(subber);
    db.close().expect("close");
}

/// A damaged run row does not stop startup: a start reads the meta and
/// journal rows, never the runs.  The first read of it does find it.  A
/// lookup that probes it fails with the remedy, which the RPC handlers
/// answer as "Could not query address: ...", and lookups elsewhere still
/// answer.  The first flush that merges its partition fails and latches
/// the store, so the node commits no more blocks; every later write names
/// that first failure, the index and the remedy, not only the storage.
#[test]
fn a_damaged_run_row_fails_the_lookups_and_the_merge_that_read_it() {
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("db"), params().net.0);
    let chain = TestChain::new(params());
    let merge_all = ExistsAddrPolicy {
        k0: 0,
        k0_hard: 0,
        ..ExistsAddrPolicy::tiny()
    };
    let mut rng = SplitMix64(0x6461_6d61_6765);
    let keys: Vec<Key> = (0..6).map(|_| random_key(&mut rng)).collect();
    {
        let db = Arc::new(Database::create(&opts).expect("create"));
        let mut subber = new_subber();
        let idx = open_index(&mut subber, &db, &chain, merge_all).expect("index");
        connect_paying(&chain, &mut subber, 1, &keys);
        db.flush().expect("flush: every key into a run");
        drop(idx);
        drop(subber);
        db.close().expect("close");
    }
    // Damage the first run row, with the index off and so no participant
    // guarding its prefix: one byte more than a whole number of keys.
    let damaged: Vec<Key> = {
        let db = Database::open(&opts).expect("open");
        let id = bucket_id(&db).expect("bucket");
        let (row, value) = raw_rows_under(&db, &[&id[..], b"R"].concat())
            .into_iter()
            .next()
            .expect("a run row");
        db.update(|tx| {
            let mut bad = value.clone();
            bad.push(0);
            tx.metadata()
                .bucket(EXISTS_ADDR_INDEX_KEY)
                .expect("bucket")
                .put(&row[4..], &bad)
        })
        .expect("damage");
        db.close().expect("close");
        value
            .chunks(21)
            .map(|k| k.try_into().expect("a key"))
            .collect()
    };
    let intact: Vec<Key> = keys
        .iter()
        .copied()
        .filter(|k| !damaged.contains(k))
        .collect();
    assert!(!intact.is_empty(), "every key in one chunk");

    let db = Arc::new(Database::open(&opts).expect("reopen"));
    let mut subber = new_subber();
    let idx =
        open_index(&mut subber, &db, &chain, merge_all).expect("startup does not read the runs");
    let query = idx.lock().expect("index").query();
    let err = query
        .exists_address(&address_of(&damaged[0], params()))
        .expect_err("a lookup in the damaged row");
    assert!(
        err.to_string()
            .contains("run once with --noexistsaddrindex --dropexistsaddrindex"),
        "{err}"
    );
    assert!(
        query
            .exists_address(&address_of(&intact[0], params()))
            .expect("a lookup elsewhere")
    );
    // A block reusing a key of the damaged row puts that key back in the
    // memtable, and the flush that merges its partition reads the row.
    connect_paying(&chain, &mut subber, 2, &damaged[..1]);
    let err = db.flush().expect_err("the merging flush");
    assert!(err.description.contains("--dropexistsaddrindex"), "{err}");
    assert!(db.is_fatal(), "the store latched");
    let err = db
        .begin(true)
        .and_then(|tx| tx.commit())
        .expect_err("a commit on a latched store");
    assert_eq!(err.kind, dcroxide_database::ErrorKind::Fatal);
    assert!(
        err.description.contains("investigate the storage")
            && err.description.contains("exists address index")
            && err.description.contains("--dropexistsaddrindex"),
        "{err}"
    );
    drop(query);
    drop(idx);
    drop(subber);
    let _ = db.close();
    drop(db);

    // The remedy rebuilds every key of both blocks.
    let (db, subber, idx) = drop_and_rebuild(&opts, &chain);
    let query = idx.lock().expect("index").query();
    let addrs: Vec<_> = keys.iter().map(|k| address_of(k, params())).collect();
    assert!(
        query
            .exists_addresses(&addrs)
            .expect("lookups")
            .iter()
            .all(|&f| f)
    );
    drop(query);
    drop(idx);
    drop(subber);
    db.close().expect("close");
}

/// Write a layout-2 exists address index at the genesis tip: its bucket
/// with `keys` rows, the tip and the version row.
fn write_layout_2(db: &Database, chain: &TestChain, keys: u8) {
    let (_, genesis) = chain.tip();
    db.update(|tx| {
        let meta = tx.metadata();
        let tips = meta.create_bucket_if_not_exists(b"idxtips")?;
        let mut tip = genesis.0.to_vec();
        tip.extend_from_slice(&0u32.to_le_bytes());
        tips.put(EXISTS_ADDR_INDEX_KEY, &tip)?;
        tips.put(
            &[b"v".as_slice(), EXISTS_ADDR_INDEX_KEY].concat(),
            &2u32.to_le_bytes(),
        )?;
        let bucket = meta.create_bucket(EXISTS_ADDR_INDEX_KEY)?;
        for i in 0..keys {
            bucket.put(&[i; 21], &[])?;
        }
        Ok(())
    })
    .expect("layout 2");
}

/// Every row of the metadata store, in order.
fn all_rows(db: &Database) -> Vec<(Vec<u8>, Vec<u8>)> {
    let tx = db.begin(false).expect("begin");
    let rows = tx.try_scan_after(&[], None, usize::MAX).expect("scan");
    tx.rollback().expect("rollback");
    rows
}

/// Lines captured from a [`LogSink`] at info level.
fn capture() -> (LogSink, Arc<Mutex<Vec<String>>>) {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink_lines = Arc::clone(&lines);
    let sink: LogSink = Arc::new(move |level, msg: &str| {
        if level == LogLevel::Info {
            sink_lines.lock().expect("lines").push(msg.to_string());
        }
    });
    (sink, lines)
}

/// The drop removes every row in either layout, with the tip, the version
/// and the drop marker, and its "Deleted" line counts rows.
#[test]
fn the_drop_removes_every_row_of_either_layout() {
    // Layout 2, as an older build left it.
    let dir = TempDir::new().expect("tempdir");
    let opts = Options::new(dir.path().join("db"), params().net.0);
    let db = Database::create(&opts).expect("create");
    let chain = TestChain::new(params());
    write_layout_2(&db, &chain, 9);
    let (sink, lines) = capture();
    let interrupt: Interrupt = Arc::new(AtomicBool::new(false));
    dcroxide_indexers::drop_exists_addr_index(&interrupt, &db, Some(&sink)).expect("drop");
    assert_index_gone(&db);
    assert_eq!(
        *lines.lock().expect("lines"),
        [
            "Dropping all exists address index entries.  This might take a while...",
            "Deleted 9 keys (9 total) from exists address index",
            "Dropped exists address index",
        ]
    );

    // Layout 3, live, after enough blocks for runs and a journal.
    let mut h = Harness::new(ExistsAddrPolicy::tiny());
    let mut rng = SplitMix64(11);
    for _ in 0..30 {
        let block = h.random_block(&mut rng);
        h.connect(&block);
    }
    h.db().flush().expect("flush");
    let rows = h.raw_rows().len();
    let check = dcroxide_indexers::check_layout(h.db())
        .expect("layout")
        .expect("index");
    assert!(check.run_rows > 0 && rows > check.run_rows, "{check:?}");
    let (sink, lines) = capture();
    h.idx()
        .lock()
        .expect("index")
        .drop_index(&interrupt, h.db(), Some(&sink))
        .expect("drop");
    assert_index_gone(h.db());
    assert_eq!(
        *lines.lock().expect("lines"),
        [
            "Dropping all exists address index entries.  This might take a while...".to_string(),
            format!("Deleted {rows} keys ({rows} total) from exists address index"),
            "Dropped exists address index".to_string(),
        ]
    );
    // The dropped index's handles answer from nothing.
    let query = h.idx().lock().expect("index").query();
    for key in h.touched.iter().take(20) {
        assert!(
            !query
                .exists_address(&address_of(key, params()))
                .expect("lookup")
        );
    }
}

fn assert_index_gone(db: &Database) {
    let tx = db.begin(false).expect("begin");
    let meta = tx.metadata();
    assert!(meta.bucket(EXISTS_ADDR_INDEX_KEY).is_none(), "bucket");
    let tips = meta.bucket(b"idxtips").expect("tips");
    for key in [
        EXISTS_ADDR_INDEX_KEY.to_vec(),
        [b"v".as_slice(), EXISTS_ADDR_INDEX_KEY].concat(),
        [b"d".as_slice(), EXISTS_ADDR_INDEX_KEY].concat(),
    ] {
        assert!(
            tips.get(&key).is_none(),
            "{}",
            String::from_utf8_lossy(&key)
        );
    }
    tx.rollback().expect("rollback");
}

/// A drop interrupted after its marker is set resumes at the next start,
/// before the index is created again.
#[test]
fn an_interrupted_drop_resumes_at_the_next_start() {
    let mut h = Harness::new(ExistsAddrPolicy::tiny());
    let mut rng = SplitMix64(12);
    for _ in 0..12 {
        let block = h.random_block(&mut rng);
        h.connect(&block);
    }
    h.db().flush().expect("flush");
    let interrupted: Interrupt = Arc::new(AtomicBool::new(true));
    let err = h
        .idx()
        .lock()
        .expect("index")
        .drop_index(&interrupted, h.db(), None)
        .expect_err("interrupted");
    assert_eq!(err.kind_name(), Some("ErrInterruptRequested"));
    let marker = [b"d".as_slice(), EXISTS_ADDR_INDEX_KEY].concat();
    let has_marker = |db: &Database| {
        let tx = db.begin(false).expect("begin");
        let found = tx
            .metadata()
            .bucket(b"idxtips")
            .is_some_and(|b| b.get(&marker).is_some());
        tx.rollback().expect("rollback");
        found
    };
    assert!(has_marker(h.db()));
    h.subber().stop(EXISTS_ADDRESS_INDEX_NAME).expect("stop");
    let (sink, lines) = capture();
    let mut subber = IndexSubscriber::new(Arc::new(AtomicBool::new(false)), Some(sink));
    let idx = open_index(&mut subber, h.db(), &h.chain, h.policy).expect("resumed");
    assert!(!has_marker(h.db()));
    assert_eq!(
        lines.lock().expect("lines")[..2],
        [
            "Resuming exists address index drop".to_string(),
            "Dropping all exists address index entries.  This might take a while...".to_string(),
        ]
    );
    subber.catch_up(&*h.chain).expect("catch up");
    h.live_mut().idx = idx;
    h.live_mut().subber = subber;
    h.model = Model::default();
    for height in 1..=h.chain.tip().0 {
        let keys = h.block_keys[&h.chain.at(height).header.block_hash()].clone();
        h.model.connect(&keys);
    }
    h.check(&mut rng, 200, "after the resumed drop");
}

/// With the index off its rows sit untouched, byte for byte, however the
/// rest of the store changes; turned on again, it catches up from its
/// stale tip.
#[test]
fn rows_sit_idle_with_the_index_off_and_it_catches_up_when_on() {
    let mut h = Harness::new(ExistsAddrPolicy::tiny());
    let mut rng = SplitMix64(13);
    for _ in 0..20 {
        let block = h.random_block(&mut rng);
        h.connect(&block);
    }
    let stale_tip = h.chain.tip();
    // Close: the index's last keys are journaled by the close's flush.
    h.close();
    let db = Arc::new(Database::open(&h.opts).expect("reopen"));
    let before = raw_rows(&db);
    assert!(!before.is_empty());

    // The node runs on without the index: the chain grows, and other
    // rows commit and flush.
    let mut more = Vec::new();
    for i in 0..10u32 {
        let block = h.random_block(&mut rng);
        h.chain.add(&block);
        more.push(block);
        db.update(|tx| {
            tx.metadata()
                .create_bucket_if_not_exists(b"other")?
                .put(&i.to_be_bytes(), &[7; 300])
        })
        .expect("other rows");
        db.flush().expect("flush");
    }
    assert_eq!(raw_rows(&db), before, "the idle index's rows changed");

    // On again: it recovers nothing and catches up the ten blocks.
    let mut subber = new_subber();
    let idx = open_index(&mut subber, &db, &h.chain, h.policy).expect("index on");
    assert_eq!(idx.lock().expect("index").tip().expect("tip"), stale_tip);
    subber.catch_up(&*h.chain).expect("catch up");
    h.live = Some(Live { db, subber, idx });
    h.model.mempool.clear();
    for block in &more {
        let keys = h.block_keys[&block.header.block_hash()].clone();
        h.model.connect(&keys);
    }
    h.check(&mut rng, 500, "after the catch-up");
}

/// A second instance of the index on the same database retires the
/// first: what the first held in memory is journaled and loaded, not
/// lost.
#[test]
fn a_second_instance_takes_over_the_firsts_memory() {
    let mut h = Harness::new(ExistsAddrPolicy::default());
    let mut rng = SplitMix64(14);
    for _ in 0..10 {
        let block = h.random_block(&mut rng);
        h.connect(&block);
    }
    assert!(
        dcroxide_indexers::check_layout(h.db())
            .expect("layout")
            .expect("index")
            .pending
            .is_empty(),
        "nothing journaled yet"
    );
    let (chain, policy) = (Arc::clone(&h.chain), h.policy);
    let live = h.live_mut();
    live.subber.stop(EXISTS_ADDRESS_INDEX_NAME).expect("stop");
    live.idx = open_index(&mut live.subber, &live.db, &chain, policy).expect("second");
    h.model.mempool.clear();
    h.check(&mut rng, 200, "second instance");
}

/// The drop of a live index clears the participant first, so the flushes
/// its deletions trigger write no index rows, and the participant is
/// never called once the drop has begun.
#[test]
fn flushes_during_a_drop_write_no_index_rows() {
    let calls = Arc::new(AtomicU64::new(0));
    let dropping = Arc::new(AtomicBool::new(false));
    let (seen_calls, seen_dropping) = (Arc::clone(&calls), Arc::clone(&dropping));
    let mut h = Harness::with_opts(ExistsAddrPolicy::tiny(), move |opts| {
        // Small enough that the drop's own commits flush.
        opts.cache_max_size = 4096;
        opts.flush_observer = Some(Arc::new(
            move |obs: &dcroxide_database::FlushObservation| {
                if obs.participant.is_some() && seen_dropping.load(Ordering::SeqCst) {
                    seen_calls.fetch_add(1, Ordering::SeqCst);
                }
            },
        ));
    });
    let mut rng = SplitMix64(15);
    for _ in 0..40 {
        let block = h.random_block(&mut rng);
        h.connect(&block);
    }
    // Keys in memory, unjournaled, when the drop starts.
    let block = h.random_block(&mut rng);
    h.connect(&block);
    let id = bucket_id(h.db()).expect("bucket");
    dropping.store(true, Ordering::SeqCst);
    let interrupt: Interrupt = Arc::new(AtomicBool::new(false));
    h.idx()
        .lock()
        .expect("index")
        .drop_index(&interrupt, h.db(), None)
        .expect("drop");
    h.db().flush().expect("flush");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a flush ran the dropped index"
    );
    assert!(
        raw_rows_under(h.db(), &id).is_empty(),
        "rows came back under the old bucket"
    );
    assert_index_gone(h.db());
}

// ---------------------------------------------------------------------
// Store read errors
// ---------------------------------------------------------------------

/// An in-memory store that serves a set number of reads and fails every
/// later one (the shape of `review_utxo_read_faults.rs`'s).
#[derive(Debug)]
struct FailingStore {
    bytes: Mutex<Vec<u8>>,
    reads_left: AtomicI64,
    refused: AtomicBool,
}

impl FailingStore {
    fn serve(&self, n: i64) {
        self.refused.store(false, Ordering::SeqCst);
        self.reads_left.store(n, Ordering::SeqCst);
    }

    fn range(len: usize, offset: u64, n: usize) -> Result<std::ops::Range<usize>, std::io::Error> {
        let start = usize::try_from(offset)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        match start.checked_add(n) {
            Some(end) if end <= len => Ok(start..end),
            _ => Err(std::io::Error::from(std::io::ErrorKind::InvalidInput)),
        }
    }
}

impl StorageBackend for FailingStore {
    fn len(&self) -> Result<u64, std::io::Error> {
        Ok(self.bytes.lock().expect("store").len() as u64)
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), std::io::Error> {
        let allowed = self
            .reads_left
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| match left {
                0 => None,
                n if n > 0 => Some(n - 1),
                n => Some(n),
            });
        if allowed.is_err() {
            self.refused.store(true, Ordering::SeqCst);
            return Err(std::io::Error::other("injected read failure"));
        }
        let bytes = self.bytes.lock().expect("store");
        let range = Self::range(bytes.len(), offset, out.len())?;
        out.copy_from_slice(&bytes[range]);
        Ok(())
    }

    fn set_len(&self, len: u64) -> Result<(), std::io::Error> {
        let len = usize::try_from(len)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        self.bytes.lock().expect("store").resize(len, 0);
        Ok(())
    }

    fn sync_data(&self) -> Result<(), std::io::Error> {
        Ok(())
    }

    fn write(&self, offset: u64, data: &[u8]) -> Result<(), std::io::Error> {
        let mut bytes = self.bytes.lock().expect("store");
        let range = Self::range(bytes.len(), offset, data.len())?;
        bytes[range].copy_from_slice(data);
        Ok(())
    }
}

/// A store read that fails during a lookup is an error, never `false`:
/// the lookup of a key that lives only in a run is swept over every read
/// at which the store can start failing.  dcrd's ffldb reads a failed
/// `Get` as absence; the RPC handler turns this error into "Could not
/// query address: ..." (PARITY.md).
#[test]
fn a_store_read_error_during_a_lookup_is_an_error_not_false() {
    let mut faulted = 0;
    for served in 0i64..10_000 {
        let store = Arc::new(FailingStore {
            bytes: Mutex::new(Vec::new()),
            reads_left: AtomicI64::new(-1),
            refused: AtomicBool::new(false),
        });
        let backend = Arc::clone(&store);
        let mut h = Harness::with_opts(
            ExistsAddrPolicy {
                k0: 0,
                k0_hard: 0,
                ..ExistsAddrPolicy::tiny()
            },
            move |opts| {
                opts.db_cache_bytes = 0;
                opts.backend = Some(backend as SharedBackend);
            },
        );
        let mut rng = SplitMix64(16);
        // Enough keys that the table's root is a branch page, so a probe
        // reads a page beneath it from the store.
        for _ in 0..60 {
            let block = h.random_block(&mut rng);
            h.connect(&block);
        }
        h.db().flush().expect("flush: every key into a run");
        let key = *h.touched.iter().next().expect("a key");
        let query = h.idx().lock().expect("index").query();
        let addr = address_of(&key, params());
        store.serve(served);
        let single = query.exists_address(&addr);
        let batch = query.exists_addresses(std::slice::from_ref(&addr));
        let refused = store.refused.load(Ordering::SeqCst);
        store.serve(-1);
        for answer in [single.map(|b| vec![b]), batch] {
            match answer {
                Ok(found) => assert_eq!(
                    found,
                    vec![true],
                    "failing after {served} reads, a lookup answered absent"
                ),
                Err(err) => {
                    faulted += 1;
                    assert!(
                        matches!(err, IdxError::Db(_)),
                        "a read fault must be a store error: {err:?}"
                    );
                }
            }
        }
        if !refused {
            assert!(faulted > 0, "no read reached the store");
            return;
        }
    }
    panic!("the lookup never completed");
}

/// What the store alone holds after a clean close -- the key set the
/// benchmark's digest is taken over -- is the model's bucket.
#[test]
fn the_stored_key_set_is_the_model_after_a_clean_close() {
    let mut h = Harness::new(ExistsAddrPolicy::tiny());
    let mut rng = SplitMix64(17);
    for _ in 0..50 {
        let block = h.random_block(&mut rng);
        h.connect(&block);
        if rng.below(5) == 0 {
            let keys = vec![random_key(&mut rng)];
            h.unconfirmed(&keys);
        }
    }
    // One more connect drains the mempool keys into the index.
    let block = h.random_block(&mut rng);
    h.connect(&block);
    let model: BTreeSet<Key> = h.model.bucket.iter().copied().collect();
    h.close();
    let db = Database::open(&h.opts).expect("reopen");
    let stored: BTreeSet<Key> = dcroxide_indexers::stored_keys(&db)
        .expect("stored keys")
        .expect("index")
        .into_iter()
        .collect();
    assert_eq!(stored, model);
}

/// The stored key set of a layout-2 index is its rows' keys, so a digest
/// of either layout compares the address sets alone.
#[test]
fn the_stored_key_set_of_a_layout_2_index_is_its_rows() {
    let dir = TempDir::new().expect("tempdir");
    let db = Database::create(&Options::new(dir.path().join("db"), params().net.0)).expect("db");
    let chain = TestChain::new(params());
    assert_eq!(dcroxide_indexers::stored_keys(&db).expect("keys"), None);
    write_layout_2(&db, &chain, 5);
    let keys = dcroxide_indexers::stored_keys(&db)
        .expect("keys")
        .expect("index");
    assert_eq!(keys, (0..5u8).map(|i| [i; 21]).collect::<Vec<_>>());
}
