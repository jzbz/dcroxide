// SPDX-License-Identifier: ISC
//! Replay of dcrd's indexer behavior generated inside dcrd's
//! internal/blockchain/indexers package over its own test chain and
//! chaingen blocks (`data/indexers_vectors.txt`): the transaction
//! index and exists address index driven through creation, catch-up,
//! connects, disconnects, reorg recovery, drops and re-creation,
//! entry and exists queries, the unconfirmed overlay, independent
//! and dependent subscriptions, and the update state machine error
//! kinds — comparing the index tips and the full contents of every
//! index bucket after each operation against a real redb-backed
//! database.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use dcroxide_chaincfg::{Params, simnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_indexers::{
    CONNECT_NTFN, ChainQueryer, DISCONNECT_NTFN, EXISTS_ADDR_INDEX_KEY, EXISTS_ADDRESS_INDEX_NAME,
    ExistsAddrIndex, HASH_BY_ID_INDEX_BUCKET_NAME, ID_BY_HASH_INDEX_BUCKET_NAME, IndexNtfn,
    IndexNtfnType, IndexSubscriber, Indexer, TX_INDEX_KEY, TX_INDEX_NAME, TxIndex,
};
use dcroxide_testutil::unhex;
use dcroxide_txscript::stdaddr::{Address, decode_address};
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx};

fn leaked_params() -> &'static Params {
    Box::leak(Box::new(simnet_params()))
}

/// A mirror of the dcrd test chain (`testChain`).
struct TestChainState {
    best_height: i64,
    best_hash: Option<Hash>,
    keyed_by_height: HashMap<i64, Arc<MsgBlock>>,
    keyed_by_hash: HashMap<[u8; 32], Arc<MsgBlock>>,
    orphans: HashMap<[u8; 32], Arc<MsgBlock>>,
}

struct TestChain {
    state: Mutex<TestChainState>,
    params: &'static Params,
}

impl TestChain {
    fn new(params: &'static Params) -> TestChain {
        let chain = TestChain {
            state: Mutex::new(TestChainState {
                best_height: 0,
                best_hash: None,
                keyed_by_height: HashMap::new(),
                keyed_by_hash: HashMap::new(),
                orphans: HashMap::new(),
            }),
            params,
        };
        chain.add_block(Arc::new(params.genesis_block.clone()));
        chain
    }

    fn add_block(&self, block: Arc<MsgBlock>) {
        let mut state = self.state.lock().expect("indexer lock poisoned");
        if let Some(best) = &state.best_hash {
            assert_eq!(
                block.header.prev_block,
                *best,
                "block {} is an orphan",
                block.header.block_hash()
            );
        }
        let height = i64::from(block.header.height);
        let hash = block.header.block_hash();
        state.keyed_by_hash.insert(hash.0, block.clone());
        state.keyed_by_height.insert(height, block);
        state.best_height = height;
        state.best_hash = Some(hash);
    }

    fn remove_block(&self, block: &Arc<MsgBlock>) {
        let mut state = self.state.lock().expect("indexer lock poisoned");
        let hash = block.header.block_hash();
        assert_eq!(
            state.best_hash,
            Some(hash),
            "block {hash} is not the current chain tip"
        );
        state.best_hash = Some(block.header.prev_block);
        state.best_height -= 1;
        let height = i64::from(block.header.height);
        state.keyed_by_hash.remove(&hash.0);
        state.keyed_by_height.remove(&height);
        state.orphans.insert(hash.0, block.clone());
    }
}

impl ChainQueryer for TestChain {
    fn main_chain_has_block(&self, hash: &Hash) -> bool {
        self.state
            .lock()
            .expect("indexer lock poisoned")
            .keyed_by_hash
            .contains_key(&hash.0)
    }

    fn chain_params(&self) -> &Params {
        self.params
    }

    fn best(&self) -> (i64, Hash) {
        let state = self.state.lock().expect("indexer lock poisoned");
        (state.best_height, state.best_hash.expect("best hash"))
    }

    fn block_header_by_hash(&self, hash: &Hash) -> Result<BlockHeader, String> {
        let state = self.state.lock().expect("indexer lock poisoned");
        state
            .keyed_by_hash
            .get(&hash.0)
            .or_else(|| state.orphans.get(&hash.0))
            .map(|b| b.header)
            .ok_or_else(|| format!("no block found with hash {hash}"))
    }

    fn block_hash_by_height(&self, height: i64) -> Result<Hash, String> {
        self.state
            .lock()
            .expect("indexer lock poisoned")
            .keyed_by_height
            .get(&height)
            .map(|b| b.header.block_hash())
            .ok_or_else(|| format!("no block found with height {height}"))
    }

    fn block_height_by_hash(&self, hash: &Hash) -> Result<i64, String> {
        self.block_by_hash(hash).map(|b| i64::from(b.header.height))
    }

    fn block_by_hash(&self, hash: &Hash) -> Result<Arc<MsgBlock>, String> {
        let state = self.state.lock().expect("indexer lock poisoned");
        state
            .keyed_by_hash
            .get(&hash.0)
            .or_else(|| state.orphans.get(&hash.0))
            .cloned()
            .ok_or_else(|| format!("no block found with hash {hash}"))
    }

    fn is_treasury_agenda_active(&self, _hash: &Hash) -> Result<bool, String> {
        Ok(false)
    }
}

/// The per-scenario replay state.
struct Scenario {
    _dir: tempfile::TempDir,
    db: Arc<Database>,
    chain: Arc<TestChain>,
    subber: IndexSubscriber,
    tx_idx: Option<Arc<Mutex<TxIndex>>>,
    ex_idx: Option<Arc<Mutex<ExistsAddrIndex>>>,
}

impl Scenario {
    fn new(params: &'static Params) -> Scenario {
        let dir = tempfile::tempdir().expect("tempdir");
        let opts = Options::new(dir.path().join("db"), params.net.0);
        let db = Arc::new(Database::create(&opts).expect("db"));
        Scenario {
            _dir: dir,
            db,
            chain: Arc::new(TestChain::new(params)),
            subber: IndexSubscriber::new(Arc::new(core::sync::atomic::AtomicBool::new(false))),
            tx_idx: None,
            ex_idx: None,
        }
    }

    /// Render the current index tips and full bucket contents in the
    /// dump's state format.
    fn render_state(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for (short, key) in [("tx", TX_INDEX_KEY), ("exists", EXISTS_ADDR_INDEX_KEY)] {
            let tip = match short {
                "tx" => self
                    .tx_idx
                    .as_ref()
                    .map(|idx| idx.lock().expect("indexer lock poisoned").tip()),
                _ => self
                    .ex_idx
                    .as_ref()
                    .map(|idx| idx.lock().expect("indexer lock poisoned").tip()),
            };
            // The dump reads the tip straight from the database so an
            // index object need not exist; mirror through a throwaway
            // read when the index handle is absent.
            let tip = match tip {
                Some(res) => res,
                None => read_tip(&self.db, key),
            };
            match tip {
                Ok((height, hash)) => lines.push(format!("tip {short} {height} {hash}")),
                Err(_) => lines.push(format!("notip {short}")),
            }
        }

        let db_tx = self.db.begin(false).expect("begin");
        for name in [
            b"idxtips" as &[u8],
            TX_INDEX_KEY,
            ID_BY_HASH_INDEX_BUCKET_NAME,
            HASH_BY_ID_INDEX_BUCKET_NAME,
            EXISTS_ADDR_INDEX_KEY,
        ] {
            let name_str = String::from_utf8_lossy(name).to_string();
            let Some(bucket) = db_tx.metadata().bucket(name) else {
                lines.push(format!("nobkt {name_str}"));
                continue;
            };
            let mut cursor = bucket.cursor();
            let mut ok = cursor.first();
            while ok {
                let key = cursor.key().expect("cursor key");
                let value = cursor.value().unwrap_or_default();
                let value_str = if value.is_empty() {
                    "-".to_string()
                } else {
                    raw_hex(&value)
                };
                lines.push(format!("bkt {name_str} {} {value_str}", raw_hex(&key)));
                ok = cursor.next();
            }
        }
        db_tx.rollback().expect("rollback");
        lines
    }
}

/// Read an index tip directly, mirroring the dump's package-level
/// `tip` helper for states captured without a live index handle.
fn read_tip(db: &Database, key: &[u8]) -> Result<(i64, Hash), dcroxide_indexers::IdxError> {
    // The tips bucket layout is pinned by the bucket dumps; reuse the
    // txindex path through a temporary read transaction.
    let db_tx = db.begin(false)?;
    let res = (|| {
        let bucket = db_tx
            .metadata()
            .bucket(b"idxtips")
            .ok_or_else(|| dcroxide_indexers::IdxError::Other("idxtips bucket not found".into()))?;
        let serialized = bucket.get(key).unwrap_or_default();
        if serialized.len() < 36 {
            return Err(dcroxide_indexers::IdxError::Other(
                "no index tip value found".into(),
            ));
        }
        let mut hash = Hash::ZERO;
        hash.0.copy_from_slice(&serialized[..32]);
        let mut height = [0u8; 4];
        height.copy_from_slice(&serialized[32..36]);
        Ok((i64::from(u32::from_le_bytes(height) as i32), hash))
    })();
    db_tx.rollback()?;
    res
}

fn raw_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_block(hex: &str) -> Arc<MsgBlock> {
    let (block, _) = MsgBlock::from_bytes(&unhex(hex)).expect("block");
    Arc::new(block)
}

#[test]
fn indexers_vectors() {
    let params = leaked_params();
    let data = include_str!("data/indexers_vectors.txt");
    let mut lines = data.lines().peekable();

    let mut scenario: Option<Scenario> = None;
    let mut blocks: HashMap<String, Arc<MsgBlock>> = HashMap::new();
    let mut addrs: HashMap<String, Address> = HashMap::new();
    let mut counts = [0usize; 6];

    // Consume the expected state lines up to `endstate` and compare
    // them against the actual rendered state.
    let compare_state =
        |lines: &mut core::iter::Peekable<std::str::Lines<'_>>, sc: &Scenario, context: &str| {
            let mut want = Vec::new();
            for line in lines.by_ref() {
                if line == "endstate" {
                    break;
                }
                want.push(line.to_string());
            }
            let got = sc.render_state();
            assert_eq!(got, want, "state mismatch after {context}");
        };

    let ntfn_for = |blocks: &HashMap<String, Arc<MsgBlock>>,
                    name: &str,
                    parent: &str,
                    ntfn_type: IndexNtfnType|
     -> IndexNtfn {
        let block = blocks.get(name).expect("block").clone();
        // The dump references a placeholder parent name on relay-only
        // rows where dcrd passes nil; the parent is unused there.
        let parent = blocks.get(parent).cloned().unwrap_or_else(|| block.clone());
        IndexNtfn {
            ntfn_type,
            block,
            parent,
            is_treasury_enabled: false,
        }
    };

    while let Some(line) = lines.next() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "scenario" => {
                scenario = Some(Scenario::new(params));
                blocks.clear();
                addrs.clear();
            }
            "block" => {
                blocks.insert(f[1].to_string(), parse_block(f[2]));
            }
            "add" => {
                let sc = scenario.as_ref().expect("scenario");
                sc.chain.add_block(blocks[f[1]].clone());
            }
            "remove" => {
                let sc = scenario.as_ref().expect("scenario");
                sc.chain.remove_block(&blocks[f[1]]);
            }
            "newtx" => {
                let sc = scenario.as_mut().expect("scenario");
                let idx = TxIndex::new(
                    &mut sc.subber,
                    sc.db.clone(),
                    sc.chain.clone() as Arc<dyn ChainQueryer>,
                )
                .expect("new tx index");
                sc.tx_idx = Some(idx);
                compare_state(&mut lines, sc, line);
            }
            "newexists" => {
                let sc = scenario.as_mut().expect("scenario");
                let idx = ExistsAddrIndex::new(
                    &mut sc.subber,
                    sc.db.clone(),
                    sc.chain.clone() as Arc<dyn ChainQueryer>,
                )
                .expect("new exists index");
                sc.ex_idx = Some(idx);
                compare_state(&mut lines, sc, line);
            }
            "newexistsdep" => {
                let sc = scenario.as_mut().expect("scenario");
                let idx = ExistsAddrIndex::new_with_prereq(
                    &mut sc.subber,
                    sc.db.clone(),
                    sc.chain.clone() as Arc<dyn ChainQueryer>,
                    TX_INDEX_NAME,
                )
                .expect("new dependent exists index");
                sc.ex_idx = Some(idx);
                compare_state(&mut lines, sc, line);
            }
            "catchup" => {
                let sc = scenario.as_mut().expect("scenario");
                let chain = sc.chain.clone();
                sc.subber.catch_up(&*chain).expect("catch up");
                compare_state(&mut lines, sc, line);
            }
            "connect" | "disconnect" => {
                let sc = scenario.as_mut().expect("scenario");
                let ntfn_type = if f[0] == "connect" {
                    CONNECT_NTFN
                } else {
                    DISCONNECT_NTFN
                };
                let ntfn = ntfn_for(&blocks, f[1], f[2], ntfn_type);
                sc.subber.notify(&ntfn).expect("notify");
                compare_state(&mut lines, sc, line);
                counts[0] += 1;
            }
            "badntfn" | "lowntfn" => {
                let sc = scenario.as_mut().expect("scenario");
                let ntfn_type = IndexNtfnType(f[3].parse().expect("ntfn type"));
                let target = if f[4] == "tx" {
                    TX_INDEX_NAME
                } else {
                    EXISTS_ADDRESS_INDEX_NAME
                };
                let ntfn = ntfn_for(&blocks, f[1], f[2], ntfn_type);
                let res = sc.subber.update_index(target, &ntfn);
                if f[0] == "badntfn" {
                    let err = res.expect_err("expected notification error");
                    let want_kind = lines.next().expect("err line");
                    assert_eq!(
                        format!("err {}", err.kind_name().expect("kind")),
                        want_kind,
                        "{line}"
                    );
                    counts[1] += 1;
                } else {
                    res.expect("low notification must relay");
                }
                compare_state(&mut lines, sc, line);
            }
            "stop" => {
                let sc = scenario.as_mut().expect("scenario");
                let id = if f[1] == "tx" {
                    TX_INDEX_NAME
                } else {
                    EXISTS_ADDRESS_INDEX_NAME
                };
                sc.subber.stop(id).expect("stop");
            }
            "droptx" => {
                let sc = scenario.as_ref().expect("scenario");
                let interrupt = sc.subber.interrupt();
                let idx = sc.tx_idx.as_ref().expect("tx index");
                idx.lock()
                    .expect("indexer lock poisoned")
                    .drop_index(&interrupt, &sc.db)
                    .expect("drop");
                compare_state(&mut lines, sc, line);
            }
            "dropexists" => {
                let sc = scenario.as_ref().expect("scenario");
                let interrupt = sc.subber.interrupt();
                let idx = sc.ex_idx.as_ref().expect("exists index");
                idx.lock()
                    .expect("indexer lock poisoned")
                    .drop_index(&interrupt, &sc.db)
                    .expect("drop");
                compare_state(&mut lines, sc, line);
            }
            "entry" | "entryhash" => {
                let sc = scenario.as_ref().expect("scenario");
                let hash = if f[0] == "entry" {
                    let block = &blocks[f[1]];
                    let i: usize = f[3].parse().expect("tx index");
                    if f[2] == "r" {
                        block.transactions[i].tx_hash()
                    } else {
                        block.stransactions[i].tx_hash()
                    }
                } else {
                    blocks[f[1]].header.block_hash()
                };
                let entry = sc
                    .tx_idx
                    .as_ref()
                    .expect("tx index")
                    .lock()
                    .expect("indexer lock poisoned")
                    .entry(&hash)
                    .expect("entry query");
                let got = match entry {
                    None => "res none".to_string(),
                    Some(entry) => format!(
                        "res some {} {} {} {}",
                        entry.block_region.hash,
                        entry.block_region.offset,
                        entry.block_region.len,
                        entry.block_index
                    ),
                };
                let want = lines.next().expect("res line");
                assert_eq!(got, want, "{line}");
                counts[2] += 1;
            }
            "addr" => {
                let addr = decode_address(f[2], params).expect("address");
                addrs.insert(f[1].to_string(), addr);
            }
            "unconfirmed" => {
                let sc = scenario.as_ref().expect("scenario");
                let (tx, _) = MsgTx::from_bytes(&unhex(f[1])).expect("tx");
                sc.ex_idx
                    .as_ref()
                    .expect("exists index")
                    .lock()
                    .expect("indexer lock poisoned")
                    .add_unconfirmed_tx(&tx);
                counts[3] += 1;
            }
            "existsq" => {
                let sc = scenario.as_ref().expect("scenario");
                let want: bool = f[2].parse().expect("bool");
                let got = sc
                    .ex_idx
                    .as_ref()
                    .expect("exists index")
                    .lock()
                    .expect("indexer lock poisoned")
                    .exists_address(&addrs[f[1]])
                    .expect("exists query");
                assert_eq!(got, want, "{line}");
                counts[4] += 1;
            }
            "existsmulti" => {
                let sc = scenario.as_ref().expect("scenario");
                let query: Vec<Address> =
                    f[1].split(',').map(|label| addrs[label].clone()).collect();
                let want: Vec<bool> = f[2].split(',').map(|b| b.parse().expect("bool")).collect();
                let got = sc
                    .ex_idx
                    .as_ref()
                    .expect("exists index")
                    .lock()
                    .expect("indexer lock poisoned")
                    .exists_addresses(&query)
                    .expect("exists multi query");
                assert_eq!(got, want, "{line}");
                counts[5] += 1;
            }
            "done" => break,
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [18, 3, 8, 1, 5, 3], "row counts");
}

/// Native coverage for the pieces the dump cannot observe: the sync
/// waiters signalled once an index reaches the chain tip, and the
/// legacy index drop helpers.
#[test]
fn sync_waiters_and_legacy_drops() {
    let params = leaked_params();
    let dir = tempfile::tempdir().expect("tempdir");
    let opts = Options::new(dir.path().join("db"), params.net.0);
    let db = Arc::new(Database::create(&opts).expect("db"));
    let chain = Arc::new(TestChain::new(params));
    let mut subber = IndexSubscriber::new(Arc::new(core::sync::atomic::AtomicBool::new(false)));

    let idx = TxIndex::new(
        &mut subber,
        db.clone(),
        chain.clone() as Arc<dyn ChainQueryer>,
    )
    .expect("tx index");

    // A waiter is signalled once an update leaves the index at the
    // chain tip; the genesis-only chain is already synced so drive
    // one block through.
    let block_hex = include_str!("data/indexers_vectors.txt")
        .lines()
        .find_map(|line| line.strip_prefix("block bk1 "))
        .expect("bk1 hex");
    let block = parse_block(block_hex);
    chain.add_block(block.clone());
    let waiter = idx.lock().expect("indexer lock poisoned").wait_for_sync();
    assert!(
        !waiter.load(core::sync::atomic::Ordering::SeqCst),
        "waiter must start unsignalled"
    );
    let genesis = Arc::new(params.genesis_block.clone());
    let ntfn = IndexNtfn {
        ntfn_type: CONNECT_NTFN,
        block,
        parent: genesis,
        is_treasury_enabled: false,
    };
    subber.notify(&ntfn).expect("notify");
    assert!(
        waiter.load(core::sync::atomic::Ordering::SeqCst),
        "waiter must fire at the chain tip"
    );

    // The legacy drop helpers are no-ops without the tips entry and
    // remove the bucket, tip, version, and drop marker with it.
    let interrupt = subber.interrupt();
    dcroxide_indexers::drop_addr_index(&interrupt, &db).expect("noop addr drop");
    dcroxide_indexers::drop_cf_index(&db).expect("noop cf drop");

    for legacy in [
        dcroxide_indexers::ADDR_INDEX_KEY,
        dcroxide_indexers::CF_INDEX_PARENT_BUCKET_KEY,
    ] {
        let db_tx = db.begin(true).expect("begin");
        let meta = db_tx.metadata();
        let bucket = meta.create_bucket(legacy).expect("legacy bucket");
        bucket.put(b"k1", b"v1").expect("put");
        bucket.put(b"k2", b"v2").expect("put");
        let tips = meta.bucket(b"idxtips").expect("tips bucket");
        tips.put(legacy, &[7u8; 36]).expect("tip");
        db_tx.commit().expect("commit");
    }
    dcroxide_indexers::drop_addr_index(&interrupt, &db).expect("addr drop");
    dcroxide_indexers::drop_cf_index(&db).expect("cf drop");

    let db_tx = db.begin(false).expect("begin");
    let meta = db_tx.metadata();
    for legacy in [
        dcroxide_indexers::ADDR_INDEX_KEY,
        dcroxide_indexers::CF_INDEX_PARENT_BUCKET_KEY,
    ] {
        assert!(meta.bucket(legacy).is_none(), "legacy bucket must be gone");
        let tips = meta.bucket(b"idxtips").expect("tips bucket");
        assert!(tips.get(legacy).is_none(), "legacy tip must be gone");
    }
    db_tx.rollback().expect("rollback");
}

/// The daemon drives the indexes from its own threads, so the index
/// state and the shared handles it hands out must cross thread
/// boundaries.  This pins the conversion off `Rc`/`RefCell`/`Cell` at
/// compile time.
#[test]
fn indexer_state_is_send() {
    fn assert_send<T: Send>() {}
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send::<TxIndex>();
    assert_send::<ExistsAddrIndex>();
    assert_send::<IndexSubscriber>();
    assert_send_sync::<Arc<Mutex<TxIndex>>>();
    assert_send_sync::<Arc<Mutex<ExistsAddrIndex>>>();
    assert_send_sync::<Arc<dyn ChainQueryer>>();
    assert_send_sync::<Arc<Mutex<dyn Indexer>>>();
    assert_send_sync::<dcroxide_indexers::Interrupt>();
    assert_send_sync::<dcroxide_indexers::SyncWaiter>();
}
