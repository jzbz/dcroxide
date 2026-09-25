// SPDX-License-Identifier: ISC
//! A getwork submission holds the work state only for the template
//! lookup, as dcrd's `handleGetWorkSubmission` does: it locks
//! `workState`, reads `templatePool` and unlocks before
//! `SyncMgr.SubmitBlock` (`internal/rpcserver/rpcserver.go`).  Holding it
//! through the submission instead would park every websocket work
//! notification -- and so the whole notification delivery thread -- for
//! the length of a block validation.

// Index arithmetic over the pinned fixture's hex.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::thread::JoinHandle;
use std::time::Duration;

use dcroxide_chaincfg::mainnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_dcrjson::{GoValue, Registry, parse_params};
use dcroxide_rpc::handlers;
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::server::{
    Config, RpcBestState, RpcChain, RpcConnManager, RpcCpuMiner, RpcSyncManager, Server,
    SubmitBlockFailure,
};
use dcroxide_rpc::websocket::{TemplateUpdateReason, WsClient, notify_work};
use dcroxide_rpctypes::{method, register_all};
use dcroxide_standalone::SubsidyCache;
use dcroxide_wire::{BlockHeader, MsgBlock, PROTOCOL_VERSION};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The chain: block 432,100 is the tip and its parent is known.
struct TipChain {
    header: BlockHeader,
}

impl RpcChain for TipChain {
    fn best_snapshot(&self) -> RpcBestState {
        RpcBestState {
            hash: self.header.block_hash(),
            prev_hash: self.header.prev_block,
            height: 0,
            bits: self.header.bits,
            next_stake_diff: 0,
            total_subsidy: 0,
            block_size: u64::from(self.header.size),
            num_txns: 0,
        }
    }
    fn best_header(&self) -> (Hash, i64) {
        (self.header.block_hash(), 0)
    }
    fn is_current(&self) -> bool {
        true
    }
    fn header_by_hash(&self, _hash: &Hash) -> Result<BlockHeader, String> {
        Ok(self.header)
    }
    fn is_blake3_pow_agenda_active(&self, _prev_blk_hash: &Hash) -> Result<bool, String> {
        Ok(false)
    }
}

/// The server as the sync manager sees it, set once it is built.
type ServerSlot = Arc<OnceLock<Weak<Server<TipChain>>>>;

/// A sync manager whose block submission checks, from another thread,
/// whether a websocket work notification can take the work state while
/// the block is being processed.
struct ProbingSyncMgr {
    server: ServerSlot,
    submitted: Arc<AtomicBool>,
    work_state_free: Arc<AtomicBool>,
    notifier: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl RpcSyncManager for ProbingSyncMgr {
    fn submit_block(&self, block: &MsgBlock) -> Result<(), SubmitBlockFailure> {
        self.submitted.store(true, Ordering::SeqCst);
        let server = self
            .server
            .get()
            .and_then(Weak::upgrade)
            .expect("the server outlives its submissions");
        let block = block.clone();
        let (done_tx, done_rx) = mpsc::channel();
        let notifier = std::thread::spawn(move || {
            let mut client = WsClient::new(2);
            let _ = notify_work(
                &server,
                &[&mut client],
                &block,
                TemplateUpdateReason::NewTxns,
            );
            let _ = done_tx.send(());
        });
        // The notification completes at once unless the submission is
        // still holding the work state; give up waiting after a while
        // and let it finish once the submission returns.
        let free = done_rx.recv_timeout(Duration::from_secs(5)).is_ok();
        self.work_state_free.store(free, Ordering::SeqCst);
        *self.notifier.lock().expect("notifier slot") = Some(notifier);
        Ok(())
    }
}

struct Connected;

impl RpcConnManager for Connected {
    fn connected_count(&self) -> i32 {
        1
    }
}

struct NotMining;

impl RpcCpuMiner for NotMining {
    fn is_mining(&self) -> bool {
        false
    }
}

#[test]
fn getwork_submission_releases_the_work_state_before_submitting() {
    let params = mainnet_params();
    let mut registry = Registry::new();
    register_all(&mut registry);

    // Real block 432,100: its header carries a valid proof of work.
    let block: MsgBlock = include_str!("data/rpchandlers8_vectors.txt")
        .lines()
        .find_map(|line| {
            let f: Vec<&str> = line.split('|').collect();
            (f[0] == "blk").then(|| MsgBlock::from_bytes(&unhex(f[1])).unwrap().0)
        })
        .expect("block fixture");
    let mining_addr =
        dcroxide_txscript::stdaddr::decode_address("DsRah84zx6jdA4nMYboMfLERA5V3KhBr4ru", &params)
            .unwrap();

    let slot: ServerSlot = Arc::new(OnceLock::new());
    let submitted = Arc::new(AtomicBool::new(false));
    let work_state_free = Arc::new(AtomicBool::new(false));
    let notifier = Arc::new(Mutex::new(None));
    let server = Arc::new(Server::new(Config {
        chain: TipChain {
            header: block.header,
        },
        chain_params: params.clone(),
        subsidy_cache: Mutex::new(SubsidyCache::new(params.clone())),
        min_relay_tx_fee: 10000,
        max_protocol_version: PROTOCOL_VERSION,
        sync_mgr: Box::new(ProbingSyncMgr {
            server: Arc::clone(&slot),
            submitted: Arc::clone(&submitted),
            work_state_free: Arc::clone(&work_state_free),
            notifier: Arc::clone(&notifier),
        }),
        conn_mgr: Box::new(Connected),
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
        cpu_miner: Box::new(NotMining),
        mix_pooler: Box::new(()),
        profiler_mgr: Box::new(()),
        addr_manager: Box::new(()),
        mining_addrs: vec![mining_addr],
        user_agent_version: String::new(),
        net_info: Vec::new(),
        services: 0,
        request_shutdown: Box::new(|| {}),
        allow_unsynced_mining: true,
        rpc_user: String::new(),
        rpc_pass: String::new(),
        rpc_limit_user: String::new(),
        rpc_limit_pass: String::new(),
    }));
    assert!(slot.set(Arc::downgrade(&server)).is_ok());

    // A work notification puts the template in the pool, as it does
    // for a subscribed miner.
    let mut subscriber = WsClient::new(1);
    let sent = notify_work(
        &server,
        &[&mut subscriber],
        &block,
        TemplateUpdateReason::NewVotes,
    );
    assert_eq!(sent.len(), 1, "the work notification is built");

    // Submit the solved header: the serialized header padded to the
    // blake256 getwork data length.
    let mut data = block.header.serialize().to_vec();
    data.resize(192, 0);
    let data_hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
    let param = format!("\"{data_hex}\"");
    let cmd = GoValue::Struct(
        parse_params(&registry, &method("getwork"), &[param.as_str()])
            .expect("parse params")
            .fields,
    );
    let accepted = handlers::handle_get_work(&server, &cmd).expect("the submission is handled");
    if let Some(handle) = notifier.lock().expect("notifier slot").take() {
        handle.join().expect("the probing notification finishes");
    }

    assert_eq!(accepted, GoValue::Bool(true), "the block is accepted");
    assert!(
        submitted.load(Ordering::SeqCst),
        "the block reached the sync manager"
    );
    assert!(
        work_state_free.load(Ordering::SeqCst),
        "a work notification had to wait for the submitted block's processing"
    );
}
