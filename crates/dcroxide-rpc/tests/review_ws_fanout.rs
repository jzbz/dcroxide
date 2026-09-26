// SPDX-License-Identifier: ISC
//! The filtered notification fan-out matches every client against one
//! extraction of each output, as dcrd's per-client loop would
//! (`subscribedClients`, `notifyBlockConnected` and
//! `notifyRelevantTxAccepted` in `internal/rpcserver/rpcwebsocket.go`).
//!
//! The port used to extract each output's addresses, hash the
//! transaction and encode it once for every matching client; it now does
//! each once per transaction and shares the result.  These cases pin the
//! behaviour that sharing must keep: every matching client gets the same
//! transaction hex, a matched output is watched under the transaction's
//! own hash in every matching filter, a ticket commitment match is not
//! watched, and a client without a match or without a filter gets none.

// Index arithmetic over the fixture hex.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::Mutex;

use dcroxide_chaincfg::mainnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::server::{Config, RpcBestState, RpcChain, Server};
use dcroxide_rpc::websocket::{
    WsClient, WsClientFilter, notify_block_connected, notify_relevant_tx_accepted,
};
use dcroxide_standalone::SubsidyCache;
use dcroxide_txscript::stdscript;
use dcroxide_wire::{MsgBlock, MsgTx, OutPoint, PROTOCOL_VERSION, TxIn};

/// A chain answering only the best-state query.
struct StubChain;

impl RpcChain for StubChain {
    fn best_snapshot(&self) -> RpcBestState {
        RpcBestState {
            hash: Hash([0x11; 32]),
            prev_hash: Hash([0x22; 32]),
            height: 1,
            bits: 0x1d00_ffff,
            next_stake_diff: 1,
            total_subsidy: 0,
            block_size: 0,
            num_txns: 0,
        }
    }
}

fn server() -> Server<StubChain> {
    let params = mainnet_params();
    Server::new(Config {
        chain: StubChain,
        chain_params: params.clone(),
        subsidy_cache: Mutex::new(SubsidyCache::new(params)),
        min_relay_tx_fee: 10000,
        max_protocol_version: PROTOCOL_VERSION,
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

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Real mainnet block 432,100 (the slice 8 fixture).
fn block() -> MsgBlock {
    include_str!("data/rpchandlers8_vectors.txt")
        .lines()
        .find_map(|line| {
            let f: Vec<&str> = line.split('|').collect();
            (f[0] == "blk").then(|| MsgBlock::from_bytes(&unhex(f[1])).unwrap().0)
        })
        .expect("block fixture")
}

/// A client with a filter over the given addresses (or none at all).
fn client(session_id: u64, addrs: Option<&[String]>) -> WsClient {
    let mut wsc = WsClient::new(session_id);
    if let Some(addrs) = addrs {
        wsc.filter_data = Some(WsClientFilter::new(addrs, &[], &mainnet_params()));
    }
    wsc
}

fn watches(wsc: &mut WsClient, hash: Hash, index: u32, tree: i8) -> bool {
    wsc.filter_data
        .as_mut()
        .expect("filter")
        .exists_unspent_out_point(&OutPoint { hash, index, tree })
}

#[test]
fn filtered_clients_share_one_extraction_and_encoding() {
    let params = mainnet_params();
    let block = block();

    // The first regular transaction output paying a single address, and
    // the first ticket's first commitment address.
    let (tx, out_index, addr) = block.transactions[1..]
        .iter()
        .find_map(|tx| {
            tx.tx_out.iter().enumerate().find_map(|(i, out)| {
                let (_, addrs) = stdscript::extract_addrs(out.version, &out.pk_script, &params);
                (addrs.len() == 1).then(|| (tx, i as u32, addrs[0].to_string()))
            })
        })
        .expect("a regular output paying an address");
    let ticket = block
        .stransactions
        .iter()
        .find(|tx| dcroxide_stake::is_sstx(tx))
        .expect("a ticket");
    let commitment =
        dcroxide_stake::addr_from_sstx_pk_scr_commitment(&ticket.tx_out[1].pk_script, &params)
            .expect("commitment")
            .to_string();
    let (tx_hash, ticket_hash) = (tx.tx_hash(), ticket.tx_hash());
    let (tx_hex, ticket_hex) = (hex(&tx.serialize()), hex(&ticket.serialize()));

    let server = server();
    let addr_filter = [addr.clone()];
    let commitment_filter = [commitment];
    let mut clients = [
        client(1, Some(&addr_filter)),
        client(2, Some(&addr_filter)),
        client(3, None),
        client(4, Some(&commitment_filter)),
        client(5, Some(&[])),
    ];
    let notifications = {
        let mut refs: Vec<&mut WsClient> = clients.iter_mut().collect();
        notify_block_connected(&server, &mut refs, &block)
    };
    let sessions: Vec<u64> = notifications.iter().map(|(id, _)| *id).collect();
    assert_eq!(sessions, [1, 2, 3, 4, 5], "every block client is notified");
    let ntfn = |i: usize| notifications[i].1.as_str();

    // Both address clients get the same notification, carrying the
    // transaction's own serialization, and both now watch its output.
    assert_eq!(ntfn(0), ntfn(1));
    assert!(ntfn(0).contains(&tx_hex), "{}", ntfn(0));
    for wsc in &mut clients[..2] {
        assert!(watches(wsc, tx_hash, out_index, 0));
    }

    // The commitment client gets the ticket, whose commitment output
    // is not watched.
    assert!(ntfn(3).contains(&ticket_hex), "{}", ntfn(3));
    assert!(!ntfn(3).contains(&tx_hex));
    assert!(!watches(&mut clients[3], ticket_hash, 1, 1));

    // The unfiltered and the empty-filter clients get no transactions.
    assert_eq!(ntfn(2), ntfn(4));
    assert!(!ntfn(2).contains(&tx_hex) && !ntfn(2).contains(&ticket_hex));

    // A mempool transaction spending the watched output and paying the
    // address again reaches exactly the two address clients, with one
    // shared encoding, and its own output is watched under its hash.
    let mut spend = MsgTx {
        version: 1,
        ..MsgTx::default()
    };
    spend.tx_in.push(TxIn {
        previous_out_point: OutPoint {
            hash: tx_hash,
            index: out_index,
            tree: 0,
        },
        ..TxIn::default()
    });
    spend.tx_out.push(tx.tx_out[out_index as usize].clone());
    let spend_hash = spend.tx_hash();
    let spend_hex = hex(&spend.serialize());
    let notifications = {
        let mut refs: Vec<&mut WsClient> = clients.iter_mut().collect();
        notify_relevant_tx_accepted(&server, &mut refs, &spend, 0)
    };
    let sessions: Vec<u64> = notifications.iter().map(|(id, _)| *id).collect();
    assert_eq!(sessions, [1, 2]);
    assert_eq!(notifications[0].1, notifications[1].1);
    assert!(notifications[0].1.contains(&spend_hex));
    for wsc in &mut clients[..2] {
        assert!(watches(wsc, spend_hash, 0, 0));
    }
    assert!(!watches(&mut clients[3], spend_hash, 0, 0));
}
