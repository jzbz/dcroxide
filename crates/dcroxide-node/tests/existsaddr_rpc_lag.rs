// SPDX-License-Identifier: ISC
//! `existsaddress` and `existsaddresses` over the live layout-3 index
//! while it lags the chain, against dcrd's answers.
//!
//! dcrd's handlers read the index tip once and then (rpcserver.go
//! 1606-1656, 1662-1720):
//!
//! - with the chain best more than five blocks past the tip, answer
//!   `rpcInternalErr` -32603 "exists address index: index not synced";
//! - with the best hash not the tip's, wait up to `syncWait` (3 s) for the
//!   index to sync, then answer from it, or the same error on timeout;
//! - decode every address before that gate, so a bad address is a decode
//!   error however far behind the index is.
//!
//! And a mempool-only address answers true before its block is indexed,
//! from the overlay, and after it, from the index.  Layout 3 moves such a
//! key from the overlay into its memtable in the connect's commit hook;
//! the lookup reads the overlay first, so it answers true during the move
//! as well, where dcrd's drain-then-commit can answer false (PARITY.md).
//!
//! The chain is regnet built from dcrd's own full-block battery; blocks
//! are processed into the chain without notifying the index to make it
//! lag, and the index catches up through its subscriber.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};
use dcroxide_indexers::{ADDR_KEY_SIZE, Interrupt, addr_to_key};
use dcroxide_mempool::UnconfirmedAddrIndexer;
use dcroxide_node::indexes::{
    NodeIndexes, NodeRpcDb, NodeRpcExistsAddresser, NodeUnconfirmedAddrIndexer, start_indexes,
};
use dcroxide_node::rpcrun::{
    NodeRpcChain, NodeRpcConnManager, NodeRpcSyncManager, start_rpc_listener,
};
use dcroxide_node::runtime::ConnectedPeers;
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::server::{Config, RpcExistsAddresser, Server};
use dcroxide_standalone::SubsidyCache;
use dcroxide_testutil::unhex;
use dcroxide_txscript::stdaddr::{Address, new_address_pub_key_hash_ecdsa_secp256k1_v0};
use dcroxide_txscript::stdscript;
use dcroxide_wire::{MsgBlock, MsgTx, PROTOCOL_VERSION, TxOut, TxSerializeType};

/// The leading consecutive main-chain prefix of accepted blocks from
/// dcrd's `fullblocktests.Generate` battery, with its generation time.
fn accepted_prefix(limit: usize) -> (i64, Vec<MsgBlock>) {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcroxide-blockchain/tests/data/fullblock_vectors.txt"
    );
    let data = std::fs::read_to_string(path).expect("fullblock vectors");
    let mut now: i64 = 0;
    let mut tip = dcroxide_chaincfg::regnet_params().genesis_hash;
    let mut blocks = Vec::new();
    for line in data.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("generation time"),
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                if f[2] != "true" || block.header.prev_block != tip {
                    continue;
                }
                tip = block.header.block_hash();
                blocks.push(block);
                if blocks.len() == limit {
                    break;
                }
            }
            _ => {}
        }
    }
    assert_eq!(blocks.len(), limit, "battery must provide the prefix");
    (now, blocks)
}

/// The keys a block gives the index: every output address it can key,
/// ticket commitments included.
fn block_keys(block: &MsgBlock) -> HashSet<[u8; ADDR_KEY_SIZE]> {
    let params = dcroxide_chaincfg::regnet_params();
    let mut keys = HashSet::new();
    for tx in block.transactions.iter().chain(&block.stransactions) {
        let is_sstx = dcroxide_stake::is_sstx(tx);
        for out in &tx.tx_out {
            let (script_type, mut addrs) =
                stdscript::extract_addrs(out.version, &out.pk_script, &params);
            if is_sstx
                && script_type == stdscript::ScriptType::NullData
                && let Ok(addr) =
                    dcroxide_stake::addr_from_sstx_pk_scr_commitment(&out.pk_script, &params)
            {
                addrs.push(addr);
            }
            keys.extend(addrs.iter().filter_map(|a| addr_to_key(a).ok()));
        }
    }
    keys
}

/// A served regnet chain whose index is `lag` blocks behind it.
struct Served {
    _dir: tempfile::TempDir,
    listener: dcroxide_node::rpcrun::RpcListener,
    port: u16,
    chain: Arc<Mutex<Chain>>,
    indexes: NodeIndexes,
    now: i64,
    blocks: Vec<MsgBlock>,
}

/// Process `history` battery blocks, start the indexes (which catch up
/// to them), then process `lag` more without telling the index, and
/// serve RPC over it all.
fn serve(history: usize, lag: usize) -> Served {
    let params = dcroxide_chaincfg::regnet_params();
    let (now, blocks) = accepted_prefix(history + lag + 1);
    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db.clone(), &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    let process = |block: &MsgBlock| {
        let (_, errs) = chain
            .lock()
            .expect("chain")
            .process_block(block, now, &params);
        assert!(errs.is_empty(), "block must accept: {errs:?}");
    };
    for block in &blocks[..history] {
        process(block);
    }
    let interrupt: Interrupt = Arc::new(AtomicBool::new(false));
    let indexes = start_indexes(
        interrupt,
        Arc::new(db.clone()),
        Arc::clone(&chain),
        params.clone(),
        false,
        true,
        &dcroxide_node::indexes::IndexLogs::default(),
    )
    .expect("start indexes");
    for block in &blocks[history..history + lag] {
        process(block);
    }

    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    );
    let sync_manager = Arc::new(Mutex::new(dcroxide_node::sync::new_sync_manager(
        Arc::clone(&chain),
        &params,
        false,
        8,
        1000,
        Arc::clone(&tx_pool),
        dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone(), &tx_pool),
    )));
    let server = Arc::new(Server::new(Config {
        chain: NodeRpcChain::new(Arc::clone(&chain), params.clone()),
        chain_params: params.clone(),
        subsidy_cache: std::sync::Mutex::new(SubsidyCache::new(params.clone())),
        min_relay_tx_fee: 10000,
        max_protocol_version: PROTOCOL_VERSION,
        sync_mgr: Box::new(NodeRpcSyncManager::new(sync_manager, Arc::clone(&tx_pool))),
        conn_mgr: Box::new(NodeRpcConnManager::new(
            ConnectedPeers::new(),
            Arc::new(dcroxide_node::transport::NetByteTotals::new()),
        )),
        client_cert_auth: false,
        tx_mempooler: Box::new(dcroxide_node::txmempool::NodeRpcTxMempooler::new(
            Arc::clone(&tx_pool),
        )),
        clock: Box::new(dcroxide_node::rpcrun::SystemClock),
        interfaces: Box::new(NoInterfaces),
        rand_u64: Box::new(|| 7),
        tx_indexer: None,
        db: Box::new(NodeRpcDb::new(db, Arc::clone(&chain))),
        filterer_v2: Box::new(()),
        exists_addresser: Some(Box::new(NodeRpcExistsAddresser::new(
            Arc::clone(indexes.exists_addr_index.as_ref().expect("exists index")),
            Arc::clone(&indexes.queryer),
        ))),
        log_manager: Box::new(()),
        fee_estimator: Box::new(()),
        block_templater: None,
        sanity_checker: Box::new(()),
        time_source: Box::new(dcroxide_node::rpcrun::SystemTimeSource),
        proxy: String::new(),
        test_net: false,
        runtime_version: String::new(),
        cpu_miner: Box::new(()),
        mix_pooler: Box::new(()),
        profiler_mgr: Box::new(()),
        addr_manager: Box::new(()),
        mining_addrs: Vec::new(),
        user_agent_version: "0.1.0".to_string(),
        net_info: Vec::new(),
        services: 0,
        request_shutdown: Box::new(|| {}),
        allow_unsynced_mining: false,
        rpc_user: "user".to_string(),
        rpc_pass: "pass".to_string(),
        rpc_limit_user: String::new(),
        rpc_limit_pass: String::new(),
    }));
    let listener = start_rpc_listener(
        &["127.0.0.1:0".to_string()],
        server,
        dcroxide_node::rpcrun::RpcTransport::Plain,
        dcroxide_node::websocket::NodeNtfnMgr::new(),
        128,
    )
    .expect("start rpc listener");
    let port = listener.bound_addrs()[0].port();
    Served {
        _dir: dir,
        listener,
        port,
        chain,
        indexes,
        now,
        blocks,
    }
}

/// One authenticated raw HTTP POST; the response.
fn post(port: u16, body: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let auth = format!(
        "Authorization: Basic {}\r\n",
        dcroxide_rpc::http::base64_std_encode(b"user:pass")
    );
    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    response
}

fn exists_address(port: u16, addr: &str) -> String {
    post(
        port,
        &format!(r#"{{"jsonrpc":"1.0","method":"existsaddress","params":["{addr}"],"id":1}}"#),
    )
}

fn exists_addresses(port: u16, addrs: &[&str]) -> String {
    let list: Vec<String> = addrs.iter().map(|a| format!("\"{a}\"")).collect();
    post(
        port,
        &format!(
            r#"{{"jsonrpc":"1.0","method":"existsaddresses","params":[[{}]],"id":2}}"#,
            list.join(",")
        ),
    )
}

const NOT_SYNCED: &str = r#""code":-32603,"message":"exists address index: index not synced""#;

/// A key the blocks `from..to` give the index that no block before
/// `from` does, as a regnet address.
fn new_key_between(blocks: &[MsgBlock], from: usize, to: usize) -> Option<String> {
    let params = dcroxide_chaincfg::regnet_params();
    let before: HashSet<_> = blocks[..from].iter().flat_map(block_keys).collect();
    let key = blocks[from..to]
        .iter()
        .flat_map(block_keys)
        .find(|k| !before.contains(k))?;
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&key[1..]);
    let addr = match key[0] {
        0 => new_address_pub_key_hash_ecdsa_secp256k1_v0(&hash, &params),
        1 => dcroxide_txscript::stdaddr::new_address_pub_key_hash_ed25519_v0(&hash, &params),
        2 => dcroxide_txscript::stdaddr::new_address_pub_key_hash_schnorr_secp256k1_v0(
            &hash, &params,
        ),
        _ => dcroxide_txscript::stdaddr::new_address_script_hash_v0_from_hash(&hash, &params),
    };
    Some(addr.expect("address").encode())
}

/// History long enough that a block in the next `lag` brings a key no
/// earlier block has, found by search so the battery can change.
fn history_with_a_new_key(lag: usize) -> (usize, String) {
    let (_, blocks) = accepted_prefix(150);
    for history in 0..150 - lag {
        if let Some(addr) = new_key_between(&blocks, history, history + lag) {
            return (history, addr);
        }
    }
    panic!("no battery block brings a new key");
}

/// Six or more blocks behind, both handlers answer dcrd's not-synced
/// error at once; a bad address is still a decode error, which dcrd
/// checks before the gate.
#[test]
fn six_blocks_behind_is_not_synced_at_once() {
    let s = serve(2, 6);
    let dev = "RcQR65gasxuzf7mUeBXeAux6Z37joPuUwUN";
    let started = Instant::now();
    let response = exists_address(s.port, dev);
    assert!(response.contains(NOT_SYNCED), "{response}");
    let response = exists_addresses(s.port, &[dev, dev]);
    assert!(response.contains(NOT_SYNCED), "{response}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the error must not wait: {:?}",
        started.elapsed()
    );
    let response = exists_address(s.port, "notanaddress");
    assert!(
        response.contains(r#""code":-5"#) && response.contains("Could not decode address"),
        "{response}"
    );
    let response = exists_addresses(s.port, &[dev, "notanaddress"]);
    assert!(
        response.contains(r#""code":-5"#) && response.contains("Could not decode address"),
        "{response}"
    );
    s.listener.shutdown();
}

/// Within five blocks the handler waits; a second thread catches the
/// index up, and the answer comes from the caught-up index: true for a
/// key only the lagging blocks hold.
#[test]
fn up_to_five_behind_waits_and_answers_from_the_caught_up_index() {
    let lag = 5;
    let (history, addr) = history_with_a_new_key(lag);
    let s = serve(history, lag);
    {
        let params = dcroxide_chaincfg::regnet_params();
        let decoded = dcroxide_txscript::stdaddr::decode_address(&addr, &params).expect("addr");
        let query = s
            .indexes
            .exists_addr_index
            .as_ref()
            .expect("index")
            .lock()
            .expect("index")
            .query();
        assert!(
            !query.exists_address(&decoded).expect("lookup"),
            "the lagging index must not know {addr} yet"
        );
    }
    let subscriber = Arc::clone(&s.indexes.subscriber);
    let queryer = Arc::clone(&s.indexes.queryer);
    let catcher = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(500));
        subscriber
            .lock()
            .expect("subscriber")
            .catch_up(&*queryer)
            .expect("catch up");
    });
    let started = Instant::now();
    let response = exists_address(s.port, &addr);
    let waited = started.elapsed();
    catcher.join().expect("catch-up thread");
    assert!(response.contains(r#""result":true"#), "{response}");
    assert!(
        waited >= Duration::from_millis(400) && waited < Duration::from_secs(3),
        "the handler answered after {waited:?}"
    );
    let response = exists_addresses(s.port, &[&addr]);
    assert!(response.contains(r#""result":"01""#), "{response}");
    s.listener.shutdown();
}

/// A lag that never closes times out after dcrd's three seconds with the
/// not-synced error.
#[test]
fn a_lag_that_never_closes_times_out_after_three_seconds() {
    let s = serve(2, 2);
    let dev = "RcQR65gasxuzf7mUeBXeAux6Z37joPuUwUN";
    let started = Instant::now();
    let response = exists_addresses(s.port, &[dev]);
    let waited = started.elapsed();
    assert!(response.contains(NOT_SYNCED), "{response}");
    assert!(
        waited >= Duration::from_secs(3) && waited < Duration::from_secs(10),
        "timed out after {waited:?}"
    );
    s.listener.shutdown();
}

/// A mempool-only address answers true before the connect that indexes
/// it, during it -- while the commit hook moves it from the overlay to
/// the memtable -- and after it.
#[test]
fn a_mempool_only_address_answers_true_before_during_and_after_its_connect() {
    let s = serve(2, 0);
    let params = dcroxide_chaincfg::regnet_params();
    let index = Arc::clone(s.indexes.exists_addr_index.as_ref().expect("index"));
    let addr: Address =
        new_address_pub_key_hash_ecdsa_secp256k1_v0(&[0x5a; 20], &params).expect("addr");
    let encoded = addr.encode();
    let response = exists_address(s.port, &encoded);
    assert!(response.contains(r#""result":false"#), "{response}");

    let (version, pk_script) = addr.payment_script();
    let mut hook = NodeUnconfirmedAddrIndexer::new(Arc::clone(&index));
    hook.add_unconfirmed_tx(&MsgTx {
        ser_type: TxSerializeType::Full,
        version: 1,
        tx_in: Vec::new(),
        tx_out: vec![TxOut {
            value: 1,
            version,
            pk_script,
        }],
        lock_time: 0,
        expiry: 0,
    });
    let response = exists_address(s.port, &encoded);
    assert!(response.contains(r#""result":true"#), "before: {response}");

    let seam = NodeRpcExistsAddresser::new(Arc::clone(&index), Arc::clone(&s.indexes.queryer));
    let stop = Arc::new(AtomicBool::new(false));
    let falses = Arc::new(AtomicUsize::new(0));
    let lookups = Arc::new(AtomicUsize::new(0));
    let reader = {
        let (stop, falses, lookups, addr) = (
            Arc::clone(&stop),
            Arc::clone(&falses),
            Arc::clone(&lookups),
            addr.clone(),
        );
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                if !seam.exists_address(&addr).expect("lookup") {
                    falses.fetch_add(1, Ordering::SeqCst);
                }
                if seam
                    .exists_addresses(std::slice::from_ref(&addr))
                    .expect("lookups")
                    != [true]
                {
                    falses.fetch_add(1, Ordering::SeqCst);
                }
                lookups.fetch_add(2, Ordering::SeqCst);
            }
        })
    };
    // Let the reader start, then connect the next block through the
    // index's subscriber: its commit hook moves the key.
    while lookups.load(Ordering::SeqCst) < 20 {
        std::thread::yield_now();
    }
    let (_, errs) = s
        .chain
        .lock()
        .expect("chain")
        .process_block(&s.blocks[2], s.now, &params);
    assert!(errs.is_empty(), "{errs:?}");
    s.indexes
        .subscriber
        .lock()
        .expect("subscriber")
        .catch_up(&*s.indexes.queryer)
        .expect("connect");
    let target = lookups.load(Ordering::SeqCst) + 20;
    while lookups.load(Ordering::SeqCst) < target {
        std::thread::yield_now();
    }
    stop.store(true, Ordering::SeqCst);
    reader.join().expect("reader");
    assert_eq!(
        falses.load(Ordering::SeqCst),
        0,
        "of {} lookups",
        lookups.load(Ordering::SeqCst)
    );
    let response = exists_address(s.port, &encoded);
    assert!(response.contains(r#""result":true"#), "after: {response}");
    let response = exists_addresses(s.port, &[&encoded]);
    assert!(response.contains(r#""result":"01""#), "after: {response}");
    s.listener.shutdown();
}
