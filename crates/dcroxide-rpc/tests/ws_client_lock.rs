// SPDX-License-Identifier: ISC
//! A websocket request must not hold the client's lock for its duration
//! (RVW-014).
//!
//! dcrd's `wsClient` embeds one mutex and takes it a field at a time
//! (`rpcwebsocket.go:1331`, `:303`, `:2333-2340`, `:2354-2356`). The port
//! held it across the whole request, and the notification delivery
//! thread locks each target client's state to build a notification —
//! `MempoolTx` targets every connected client — so one client's long
//! call stalled fan-out to all of them. A rescan, a `generate`, and
//! `getwork`'s unbounded template wait all run on that path.
//!
//! The delivery thread is modelled here by a second thread simply taking
//! the lock, because that is all it does with it. Wrap a handler body in
//! a single guard again and this times out.

// Test-harness arithmetic over a fixed block count.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use dcroxide_chaincfg::mainnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_dcrjson::GoValue;
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::server::{Config, RpcBestState, RpcChain, RpcSubsidyParams, Server};
use dcroxide_rpc::websocket::{WsClient, WsClientFilter, handle_rescan, lock_client};
use dcroxide_standalone::SubsidyCache;
use dcroxide_wire::{BlockHeader, MsgBlock};

/// How long the rescan is parked inside the chain seam.
const PARK: Duration = Duration::from_millis(1500);

/// The lock must be available *while* the scan is parked, not merely
/// once it finishes -- a request holding one guard across the whole call
/// still releases it eventually, so a generous deadline alone would pass
/// against the very bug this pins.
const PROMPT: Duration = Duration::from_millis(400);

/// For the setup handshakes, where only a hang is interesting.
const DEADLINE: Duration = Duration::from_secs(10);

fn header(height: u32, prev: Hash) -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_block: prev,
        merkle_root: Hash::ZERO,
        stake_root: Hash::ZERO,
        vote_bits: 1,
        final_state: [0u8; 6],
        voters: 0,
        fresh_stake: 0,
        revocations: 0,
        pool_size: 0,
        bits: 0x2000_0000,
        sbits: 1,
        height,
        size: 0,
        timestamp: 1,
        nonce: 0,
        extra_data: [0u8; 32],
        stake_version: 0,
    }
}

/// A chain whose treasury-agenda query parks, standing in for any slow
/// seam a request reaches while scanning.
struct ParkingChain {
    blocks: Vec<MsgBlock>,
    entered: mpsc::Sender<()>,
    calls: AtomicUsize,
}

impl RpcChain for ParkingChain {
    fn best_snapshot(&self) -> RpcBestState {
        let h = self.blocks[0].header;
        RpcBestState {
            hash: h.block_hash(),
            prev_hash: h.prev_block,
            height: 1,
            bits: h.bits,
            next_stake_diff: 1,
            total_subsidy: 0,
            block_size: 0,
            num_txns: 0,
        }
    }

    fn block_by_hash(&self, hash: &Hash) -> Result<MsgBlock, String> {
        self.blocks
            .iter()
            .find(|b| b.header.block_hash() == *hash)
            .cloned()
            .ok_or_else(|| "no such block".to_string())
    }

    fn is_treasury_agenda_active(&self, _prev_blk_hash: &Hash) -> Result<bool, String> {
        // Park once, on the first block of the scan, with no client lock
        // held by this thread if the fix is in place.
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            let _ = self.entered.send(());
            std::thread::sleep(PARK);
        }
        Ok(true)
    }
}

fn server_with(chain: ParkingChain) -> Server<ParkingChain> {
    let params = mainnet_params();
    Server::new(Config {
        chain,
        chain_params: params.clone(),
        subsidy_cache: Mutex::new(SubsidyCache::new(RpcSubsidyParams(params.clone()))),
        min_relay_tx_fee: 10000,
        max_protocol_version: dcroxide_wire::PROTOCOL_VERSION,
        sync_mgr: Box::new(()),
        conn_mgr: Box::new(()),
        client_cert_auth: false,
        tx_mempooler: Box::new(()),
        clock: Box::new(()),
        interfaces: Box::new(NoInterfaces),
        rand_u64: Box::new(|| 0),
        tx_indexer: None,
        db: Box::new(()),
        filterer_v2: Box::new(()),
        exists_addresser: None,
        log_manager: Box::new(()),
        fee_estimator: Box::new(()),
        block_templater: None,
        sanity_checker: Box::new(()),
        time_source: Box::new(()),
        proxy: String::new(),
        test_net: false,
        runtime_version: String::new(),
        cpu_miner: Box::new(()),
        mix_pooler: Box::new(()),
        profiler_mgr: Box::new(()),
        addr_manager: Box::new(()),
        mining_addrs: Vec::new(),
        user_agent_version: String::new(),
        net_info: Vec::new(),
        services: 0,
        request_shutdown: Box::new(|| {}),
        allow_unsynced_mining: false,
        rpc_user: String::new(),
        rpc_pass: String::new(),
        rpc_limit_user: String::new(),
        rpc_limit_pass: String::new(),
    })
}

#[test]
fn a_parked_rescan_does_not_hold_the_client_lock() {
    let params = mainnet_params();

    // Two chained blocks, so the rescan loop runs more than once.
    let h1 = header(1, Hash::ZERO);
    let h2 = header(2, h1.block_hash());
    let blocks: Vec<MsgBlock> = [h1, h2]
        .into_iter()
        .map(|header| MsgBlock {
            header,
            transactions: Vec::new(),
            stransactions: Vec::new(),
        })
        .collect();
    let hashes: Vec<String> = blocks
        .iter()
        .map(|b| b.header.block_hash().to_string())
        .collect();

    let (entered_tx, entered_rx) = mpsc::channel::<()>();
    let server = Arc::new(server_with(ParkingChain {
        blocks,
        entered: entered_tx,
        calls: AtomicUsize::new(0),
    }));

    // A client with a filter loaded, which rescan requires.
    let wsc = Arc::new(Mutex::new(WsClient::new(1)));
    lock_client(&wsc).filter_data = Some(WsClientFilter::new(&[], &[], &params));

    let cmd = GoValue::Struct(vec![GoValue::Array(
        hashes.into_iter().map(GoValue::String).collect(),
    )]);

    let scanner = {
        let server = Arc::clone(&server);
        let wsc = Arc::clone(&wsc);
        std::thread::spawn(move || {
            let _ = handle_rescan(&server, &wsc, &cmd);
        })
    };

    // Once the scan is parked inside the chain seam, the client's lock
    // must still be available.
    entered_rx
        .recv_timeout(DEADLINE)
        .expect("the rescan must reach the chain seam");
    let (got_tx, got_rx) = mpsc::channel::<()>();
    let taker = {
        let wsc = Arc::clone(&wsc);
        std::thread::spawn(move || {
            let guard = lock_client(&wsc);
            let _ = guard.session_id;
            drop(guard);
            let _ = got_tx.send(());
        })
    };

    let waited = std::time::Instant::now();
    got_rx
        .recv_timeout(DEADLINE)
        .expect("the taker thread must finish");
    let waited = waited.elapsed();
    assert!(
        waited < PROMPT,
        "the delivery thread waited {waited:?} to lock a client whose rescan was parked \
         for {PARK:?}: the request is holding the client's lock across its whole call",
    );

    taker.join().expect("taker thread");
    scanner.join().expect("scanner thread");
}
