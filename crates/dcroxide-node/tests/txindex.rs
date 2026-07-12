// SPDX-License-Identifier: ISC
//! End-to-end checks for the daemon's indexes: a regnet chain built
//! from dcrd's own full-block battery backs a live `TxIndex` and
//! `ExistsAddrIndex` sharing one subscriber — both catch up at
//! startup, follow a block connected through the chain handler's
//! drain, and serve `getrawtransaction`, `existsaddress`, and
//! `existsaddresses` over the RPC listener with dcrd's exact result
//! shapes and errors.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use dcroxide_blockchain::process::Chain;
use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, Options};
use dcroxide_indexers::Interrupt;
use dcroxide_netsync::manager::SyncChain;
use dcroxide_node::indexes::{
    NodeIndexes, NodeRpcDb, NodeRpcExistsAddresser, NodeRpcTxIndexer, start_indexes,
};
use dcroxide_node::rpcrun::{
    NodeRpcChain, NodeRpcConnManager, NodeRpcSyncManager, start_rpc_listener,
};
use dcroxide_node::runtime::ConnectedPeers;
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::server::{Config, RpcSubsidyParams, Server};
use dcroxide_standalone::SubsidyCache;
use dcroxide_testutil::unhex;
use dcroxide_wire::{MsgBlock, PROTOCOL_VERSION};

/// The leading consecutive main-chain prefix of accepted blocks from
/// dcrd's `fullblocktests.Generate` battery (fully signed regnet
/// blocks), with the battery's recorded generation time.
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
            // accept <name> <mainchain> <orphan> <blockhex>
            "accept" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                // Only the linear main-chain prefix: an accepted block
                // extending anything else is a side chain or orphan.
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

/// Start an RPC listener over a regnet chain with `history` processed
/// blocks and a caught-up live transaction index, handing back the
/// shared pieces so the test can connect more blocks.
#[allow(clippy::type_complexity)]
fn serve_txindex_rpc(
    history: usize,
) -> (
    tempfile::TempDir,
    dcroxide_node::rpcrun::RpcListener,
    u16,
    Arc<Mutex<Chain>>,
    NodeIndexes,
    dcroxide_node::sync::NodeSyncChain,
    i64,
    Vec<MsgBlock>,
) {
    let params = dcroxide_chaincfg::regnet_params();
    let (now, blocks) = accepted_prefix(history + 1);

    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db.clone(), &params, params.assume_valid, false, 0).expect("open chain"),
    ));

    // The pre-index history the startup catch-up must cover.
    for block in &blocks[..history] {
        let (_, errs) = chain
            .lock()
            .expect("chain")
            .process_block(block, now, &params);
        assert!(errs.is_empty(), "history block must accept: {errs:?}");
    }

    // Create both indexes and catch them up over one shared
    // subscriber (the daemon's startup path).
    let interrupt: Interrupt = Arc::new(core::sync::atomic::AtomicBool::new(false));
    let indexes = start_indexes(
        interrupt,
        Arc::new(db.clone()),
        Arc::clone(&chain),
        params.clone(),
        true,
        true,
    )
    .expect("start indexes");

    // The chain handler wiring the daemon installs: the callback
    // queues block events and the sync chain drains them into the
    // mempool maintenance and the index subscriber.
    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    );
    let mut handler = dcroxide_node::chainntfns::ChainNtfnHandler::new(
        Some(dcroxide_node::websocket::NodeNtfnMgr::new()),
        params.clone(),
        false,
        Arc::clone(&tx_pool),
        dcroxide_node::dispatch::SyncPeers::new(),
        dcroxide_node::dispatch::new_recently_advertised(),
    );
    handler.set_index_subscriber(Arc::clone(&indexes.subscriber));
    {
        let callback_handler = handler.clone();
        chain
            .lock()
            .expect("chain")
            .set_notification_callback(Box::new(move |n| callback_handler.handle(n)));
    }
    let mut sync_chain =
        dcroxide_node::sync::NodeSyncChain::new(Arc::clone(&chain), params.clone());
    sync_chain.set_chain_ntfn_handler(handler);

    let sync_manager = Arc::new(Mutex::new(dcroxide_node::sync::new_sync_manager(
        Arc::clone(&chain),
        &params,
        false,
        8,
        1000,
        Arc::clone(&tx_pool),
    )));

    let server = Arc::new(Mutex::new(Server::new(Config {
        chain: NodeRpcChain::new(Arc::clone(&chain), params.clone()),
        chain_params: params.clone(),
        subsidy_cache: SubsidyCache::new(RpcSubsidyParams(params.clone())),
        min_relay_tx_fee: 10000,
        max_protocol_version: PROTOCOL_VERSION,
        sync_mgr: Box::new(NodeRpcSyncManager::new(sync_manager, Arc::clone(&tx_pool))),
        conn_mgr: Box::new(NodeRpcConnManager::new(
            ConnectedPeers::new(),
            Arc::new(dcroxide_node::transport::NetByteTotals::new()),
        )),
        tx_mempooler: Box::new(dcroxide_node::txmempool::NodeRpcTxMempooler::new(
            Arc::clone(&tx_pool),
        )),
        clock: Box::new(dcroxide_node::rpcrun::SystemClock),
        interfaces: Box::new(NoInterfaces),
        rand_u64: Box::new(|| 7),
        tx_indexer: Some(Box::new(NodeRpcTxIndexer::new(
            Arc::clone(indexes.tx_index.as_ref().expect("tx index enabled")),
            Arc::clone(&indexes.queryer),
        ))),
        db: Box::new(NodeRpcDb::new(db)),
        filterer_v2: Box::new(()),
        exists_addresser: Some(Box::new(NodeRpcExistsAddresser::new(
            Arc::clone(
                indexes
                    .exists_addr_index
                    .as_ref()
                    .expect("exists index enabled"),
            ),
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
    })));

    let listener = start_rpc_listener(
        &["127.0.0.1:0".to_string()],
        server,
        dcroxide_node::rpcrun::RpcTransport::Plain,
        dcroxide_node::websocket::NodeNtfnMgr::new(),
        128,
    )
    .expect("start rpc listener");
    let port = listener.bound_addrs()[0].port();
    (dir, listener, port, chain, indexes, sync_chain, now, blocks)
}

/// Send one authenticated raw HTTP POST and return the response body.
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

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn serves_getrawtransaction_over_the_live_txindex() {
    let (_dir, listener, port, _chain, indexes, mut sync_chain, _now, blocks) =
        serve_txindex_rpc(2);

    // The startup catch-up indexed the processed history for both
    // indexes over the one shared subscriber.
    {
        use dcroxide_indexers::{ChainQueryer, Indexer};
        let (best_height, best_hash) = indexes.queryer.best();
        assert_eq!(best_height, 2);
        let idx = indexes.tx_index.as_ref().expect("tx index enabled");
        let idx = idx.lock().expect("tx index");
        assert_eq!(idx.tip().expect("index tip"), (2, best_hash));
        let exists = indexes
            .exists_addr_index
            .as_ref()
            .expect("exists index enabled");
        let exists = exists.lock().expect("exists index");
        assert_eq!(exists.tip().expect("index tip"), (2, best_hash));
    }

    // Connect the next battery block through the live path: the chain
    // callback queues the event and the sync-chain drain feeds the
    // index subscriber, exactly like a block arriving from a peer.
    let live = &blocks[2];
    let fork_len = sync_chain.process_block(live).expect("live block accepts");
    assert_eq!(fork_len, 0, "extends the main chain");
    let live_hash = live.header.block_hash();

    // The coinbase of the live block serves over the index: the
    // non-verbose hex is the exact serialization out of the stored
    // block region.
    let coinbase = &live.transactions[0];
    let txid = coinbase.tx_hash();
    let response = post(
        port,
        &format!(r#"{{"jsonrpc":"1.0","method":"getrawtransaction","params":["{txid}"],"id":1}}"#),
    );
    let expected_hex = hex_encode(&coinbase.serialize());
    assert!(
        response.contains(&format!(r#""result":"{expected_hex}""#)),
        "non-verbose hex must match the stored region: {response}"
    );

    // The verbose form carries the block fields out of the index
    // entry: the block hash, height, index, and one confirmation.
    let response = post(
        port,
        &format!(
            r#"{{"jsonrpc":"1.0","method":"getrawtransaction","params":["{txid}",1],"id":2}}"#
        ),
    );
    assert!(
        response.contains(&format!(r#""txid":"{txid}""#)),
        "verbose txid: {response}"
    );
    assert!(
        response.contains(&format!(r#""blockhash":"{live_hash}""#)),
        "verbose blockhash: {response}"
    );
    assert!(
        response.contains(r#""blockheight":3"#),
        "verbose blockheight: {response}"
    );
    // dcrd's TxRawResult marshals BlockIndex with omitempty, so the
    // coinbase's index 0 is absent from the verbose result (the only
    // blockindex present is the vin's no-block sentinel).
    assert!(
        !response.contains(r#""blockindex":0"#),
        "verbose blockindex 0 must be omitted: {response}"
    );
    assert!(
        response.contains(r#""confirmations":1"#),
        "verbose confirmations: {response}"
    );

    // A transaction the index has never seen answers dcrd's
    // no-information error.
    let unknown = Hash([7u8; 32]);
    let response = post(
        port,
        &format!(
            r#"{{"jsonrpc":"1.0","method":"getrawtransaction","params":["{unknown}"],"id":3}}"#
        ),
    );
    assert!(
        response.contains(r#""code":-5"#)
            && response.contains(&format!(
                "No information available about transaction {unknown}"
            )),
        "unknown transaction: {response}"
    );

    // getinfo reports the enabled index.
    let response = post(
        port,
        r#"{"jsonrpc":"1.0","method":"getinfo","params":[],"id":4}"#,
    );
    assert!(
        response.contains(r#""txindex":true"#),
        "getinfo txindex flag: {response}"
    );

    listener.shutdown();
}

#[test]
fn serves_existsaddress_over_the_live_index() {
    let (_dir, listener, port, _chain, _indexes, mut sync_chain, _now, blocks) =
        serve_txindex_rpc(2);

    // Connect the next battery block through the live path so the
    // exists index records its coinbase addresses through the drain.
    let live = &blocks[2];
    sync_chain.process_block(live).expect("live block accepts");

    // The dev-subsidy and pay-to-OP_TRUE script-hash addresses from
    // the live block's coinbase, and a premine pay-to-pubkey-hash
    // payout the startup catch-up indexed.
    let dev = "RcQR65gasxuzf7mUeBXeAux6Z37joPuUwUN";
    let op_true = "RcdEQX5ee4HPsRTrNxyTApHPVgEgDcyMSEv";
    let premine = "RsKrWb7Vny1jnzL1sDLgKTAteh9RZcRr5g6";
    for addr in [dev, op_true, premine] {
        let response = post(
            port,
            &format!(r#"{{"jsonrpc":"1.0","method":"existsaddress","params":["{addr}"],"id":1}}"#),
        );
        assert!(
            response.contains(r#""result":true"#),
            "{addr} must exist: {response}"
        );
    }

    // A valid address the chain has never seen answers false.
    let params = dcroxide_chaincfg::regnet_params();
    let unused = dcroxide_txscript::stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(
        &[0x77u8; 20],
        &params,
    )
    .expect("unused address")
    .encode();
    let response = post(
        port,
        &format!(r#"{{"jsonrpc":"1.0","method":"existsaddress","params":["{unused}"],"id":2}}"#),
    );
    assert!(
        response.contains(r#""result":false"#),
        "unused address: {response}"
    );

    // The batch form packs the answers into dcrd's LSB-first bitset
    // hex: [true, false, true, true] -> 0b00001101 -> "0d".
    let response = post(
        port,
        &format!(
            r#"{{"jsonrpc":"1.0","method":"existsaddresses","params":[["{dev}","{unused}","{op_true}","{premine}"]],"id":3}}"#
        ),
    );
    assert!(
        response.contains(r#""result":"0d""#),
        "batch bitset: {response}"
    );

    // A malformed address answers dcrd's decode error.
    let response = post(
        port,
        r#"{"jsonrpc":"1.0","method":"existsaddress","params":["notanaddress"],"id":4}"#,
    );
    assert!(
        response.contains(r#""code":-5"#) && response.contains("Could not decode address"),
        "bad address: {response}"
    );

    listener.shutdown();
}

/// The chain handler drives the index and mempool maintenance without
/// a websocket manager (the daemon under --norpc; dcrd maintains the
/// indexes regardless of whether the RPC server runs).
#[test]
fn indexes_follow_blocks_without_the_rpc_stack() {
    let params = dcroxide_chaincfg::regnet_params();
    let (now, blocks) = accepted_prefix(2);

    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db.clone(), &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    for block in &blocks[..1] {
        let (_, errs) = chain
            .lock()
            .expect("chain")
            .process_block(block, now, &params);
        assert!(errs.is_empty(), "history block must accept: {errs:?}");
    }
    let interrupt: Interrupt = Arc::new(core::sync::atomic::AtomicBool::new(false));
    let indexes = start_indexes(
        interrupt,
        Arc::new(db),
        Arc::clone(&chain),
        params.clone(),
        true,
        true,
    )
    .expect("start indexes");

    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    );
    let mut handler = dcroxide_node::chainntfns::ChainNtfnHandler::new(
        None,
        params.clone(),
        false,
        tx_pool,
        dcroxide_node::dispatch::SyncPeers::new(),
        dcroxide_node::dispatch::new_recently_advertised(),
    );
    handler.set_index_subscriber(Arc::clone(&indexes.subscriber));
    {
        let callback_handler = handler.clone();
        chain
            .lock()
            .expect("chain")
            .set_notification_callback(Box::new(move |n| callback_handler.handle(n)));
    }
    let mut sync_chain =
        dcroxide_node::sync::NodeSyncChain::new(Arc::clone(&chain), params.clone());
    sync_chain.set_chain_ntfn_handler(handler);

    sync_chain.process_block(&blocks[1]).expect("live block");

    use dcroxide_indexers::Indexer;
    let live_hash = blocks[1].header.block_hash();
    for index in [
        Arc::clone(indexes.tx_index.as_ref().expect("tx index")) as Arc<Mutex<dyn Indexer>>,
        Arc::clone(indexes.exists_addr_index.as_ref().expect("exists index"))
            as Arc<Mutex<dyn Indexer>>,
    ] {
        let index = index.lock().expect("index");
        assert_eq!(index.tip().expect("tip"), (2, live_hash));
    }
}
