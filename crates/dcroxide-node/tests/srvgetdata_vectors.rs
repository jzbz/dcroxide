// SPDX-License-Identifier: ISC
//! Replay of frozen server getblocks and getheaders vectors generated
//! by an in-package dump that built a real regnet chain from dcrd's
//! own fullblocktests generator and drove dcrd's real OnGetBlocks and
//! OnGetHeaders over a live piped serverPeer at release-v2.1.5.  The
//! chain queries (LocateBlocks/LocateHeaders/ChainWork) are pinned
//! separately; the rows freeze their outputs as inputs and this
//! replay checks the server-specific wrapping — the known-inventory
//! filter and the continue-hash for getblocks, and the
//! empty-headers-on-low-work gate for getheaders — reproduces dcrd's
//! peer-visible response.  The block hashes differ per generation
//! (the generator stamps timestamps), so each row is self-contained.

// Index arithmetic over pinned vector rows and hex parsing.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_chainhash::Hash;
use dcroxide_node::server::{
    GetBlocksResponse, GetHeadersResponse, build_get_blocks_response, build_get_headers_response,
};
use dcroxide_wire::{BlockHeader, InvType, InvVect};

const VECTORS: &str = include_str!("data/srvgetdata_vectors.txt");

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn parse_hash(s: &str) -> Hash {
    let bytes = hex_decode(s);
    // dcrd prints hashes in reverse byte order.
    let mut h = [0u8; 32];
    for (i, b) in bytes.iter().rev().enumerate() {
        h[i] = *b;
    }
    Hash(h)
}

/// A placeholder block header; the getheaders wrapping decision is
/// opaque to header contents and only carries the located count.
fn zero_header() -> BlockHeader {
    BlockHeader {
        version: 0,
        prev_block: Hash([0u8; 32]),
        merkle_root: Hash([0u8; 32]),
        stake_root: Hash([0u8; 32]),
        vote_bits: 0,
        final_state: [0u8; 6],
        voters: 0,
        fresh_stake: 0,
        revocations: 0,
        pool_size: 0,
        bits: 0,
        sbits: 0,
        height: 0,
        size: 0,
        timestamp: 0,
        nonce: 0,
        extra_data: [0u8; 32],
        stake_version: 0,
    }
}

fn parse_hashes(s: &str) -> Vec<Hash> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(',').map(parse_hash).collect()
}

fn block_inv(hashes: &[Hash]) -> Vec<InvVect> {
    hashes
        .iter()
        .map(|h| InvVect {
            inv_type: InvType::BLOCK,
            hash: *h,
        })
        .collect()
}

#[test]
fn server_getblocks_matches_dcrd() {
    for line in VECTORS.lines() {
        let f: Vec<&str> = line.split('|').collect();
        if f[0] != "gb" {
            continue;
        }
        let name = f[1];
        let located = parse_hashes(f[2]);
        let known = parse_hashes(f[3]);
        let sent = parse_hashes(f[4]);
        let continue_hash = if f[5] == "none" {
            None
        } else {
            Some(parse_hash(f[5]))
        };

        let known_set: std::collections::HashSet<Hash> = known.iter().copied().collect();
        let out = build_get_blocks_response(&located, |iv| known_set.contains(&iv.hash));

        let want = GetBlocksResponse {
            inv: block_inv(&sent),
            continue_hash,
        };
        assert_eq!(out, want, "gb row {name}");
    }
}

#[test]
fn server_getheaders_matches_dcrd() {
    for line in VECTORS.lines() {
        let f: Vec<&str> = line.split('|').collect();
        if f[0] != "gh" {
            continue;
        }
        let name = f[1];
        let located_count: usize = f[2].parse().unwrap();
        let chain_work_errored: bool = f[3].parse().unwrap();
        let below_min: bool = f[4].parse().unwrap();
        let sent_count: usize = f[5].parse().unwrap();
        let sent_empty: bool = f[6].parse().unwrap();

        // The located headers are opaque to the wrapping decision; a
        // vector of the right length reproduces the observable count.
        let located: Vec<BlockHeader> = (0..located_count).map(|_| zero_header()).collect();
        let out = build_get_headers_response(chain_work_errored, below_min, located);

        match out {
            GetHeadersResponse::Empty => {
                assert!(sent_empty, "gh row {name}: expected non-empty");
                assert_eq!(sent_count, 0, "gh row {name}");
            }
            GetHeadersResponse::Headers(headers) => {
                assert_eq!(headers.len(), sent_count, "gh row {name}");
                assert_eq!(headers.is_empty(), sent_empty, "gh row {name}");
            }
        }
    }
}

/// The continue hash is set when the response fills an entire message;
/// fullblocktests does not reach a 500-block response, so this pins
/// that branch directly.
#[test]
fn getblocks_continue_hash_on_full_message() {
    let located: Vec<Hash> = (0..dcroxide_node::server::MAX_BLOCKS_PER_MSG)
        .map(|i| {
            let mut h = [0u8; 32];
            h[0] = i as u8;
            h[1] = (i >> 8) as u8;
            Hash(h)
        })
        .collect();
    let out = build_get_blocks_response(&located, |_| false);
    assert_eq!(out.inv.len(), dcroxide_node::server::MAX_BLOCKS_PER_MSG);
    assert_eq!(out.continue_hash, Some(located[located.len() - 1]));
}

// ---------------------------------------------------------------------
// Security regressions for the getdata serve path (blocker B-2): the
// non-truncating ban score, the live pending-request counters, and the
// per-item chain lock.  Each of these fails if the corresponding fix is
// reverted; none of them relaxes the frozen dcrd parity above.
// ---------------------------------------------------------------------

use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};
use dcroxide_node::dispatch::ServerContext;
use dcroxide_node::peerconn::NodePeerEnv;
use dcroxide_node::runtime::{ConnectedPeers, ListenerRuntime, PeerTemplate, inbound_peer_handler};
use dcroxide_node::server::{
    MAX_INV_PER_MSG, MAX_PENDING_GETDATA_ITEM_REQS, MAX_PENDING_SEND, MESSAGE_HEADER_SIZE,
    OnGetDataOutcome, SendPipeline, ServerPeerAddrState, getdata_ban_score_increase, on_get_data,
};
use dcroxide_node::transport::WireTransport;
use dcroxide_peer::{Config, MAX_PROTOCOL_VERSION, MsgTransport, Peer, PeerGlobals};
use dcroxide_wire::{CurrencyNet, Message, MsgGetData, ServiceFlag};

const SERVE_NET: CurrencyNet = CurrencyNet::TEST_NET3;
const BAN_THRESHOLD: u32 = 100;
const SCORE_NOW_UNIX: i64 = 1_700_000_000;

/// The getdata ban score reproduces dcrd's truncating arithmetic
/// exactly, including the consequence that small batches are free.
///
/// dcrd computes `numNewReqs*99/wire.MaxInvPerMsg` in Go integer
/// division, so any batch of 505 items or fewer scores zero and only the
/// size of each individual request is ever charged. An earlier version
/// of this port carried the truncated remainder so that looping
/// 505-item batches was no longer free. That is a regression rather than
/// a hardening, and this test pins the arithmetic that avoids it:
///
/// At 99 points per full inventory message the rate is 0.00198 points
/// per item, and against dcrd's 60-second half-life and threshold of 100
/// the equilibrium is reached at ~583 items/second sustained. Both dcrd
/// and this port request blocks in batches of `maxInFlightBlocks` (16),
/// which truncates to zero — so dcrd charges an honestly syncing peer
/// nothing at all, where a carry would charge it the full per-item rate.
/// Early-chain blocks are ~1 KiB, so 583 blocks/s is ~0.6 MB/s of
/// upload: a peer bootstrapping from us over an ordinary link would be
/// banned partway through the small-block window.
///
/// What actually bounds this path is the pending-batch and pending-item
/// gates plus the send pipeline, pinned by the tests below. The audit
/// finding was that those counters were passed as literal zeroes.
#[test]
fn the_getdata_ban_score_matches_dcrds_truncating_rate() {
    // dcrd's expression, evaluated the same way Go does.
    for items in [0u32, 1, 15, 16, 505, 506, 1_000, 25_000, MAX_INV_PER_MSG] {
        let want = items.saturating_mul(99) / MAX_INV_PER_MSG;
        assert_eq!(
            getdata_ban_score_increase(items),
            want,
            "{items} items must score exactly dcrd's {want}"
        );
    }

    // The boundary dcrd's truncation puts the free/charged line at.
    assert_eq!(getdata_ban_score_increase(505), 0);
    assert_eq!(getdata_ban_score_increase(506), 1);

    // A full inventory message costs 99 — one short of the default ban
    // threshold, so a single maximal request never bans on its own.
    assert_eq!(getdata_ban_score_increase(MAX_INV_PER_MSG), 99);
    assert!(getdata_ban_score_increase(MAX_INV_PER_MSG) < BAN_THRESHOLD);

    // The property the truncation protects: the batch size both dcrd's
    // netsync and this port's actually use for block requests costs an
    // honestly syncing peer nothing, however many batches it sends.
    const MAX_IN_FLIGHT_BLOCKS: u32 = 16;
    assert_eq!(getdata_ban_score_increase(MAX_IN_FLIGHT_BLOCKS), 0);
    let mut state = ServerPeerAddrState::new(false);
    for _ in 0..10_000 {
        let out = on_get_data(
            &mut state,
            MAX_IN_FLIGHT_BLOCKS,
            0,
            0,
            false,
            BAN_THRESHOLD,
            SCORE_NOW_UNIX,
        );
        assert_ne!(
            out,
            OnGetDataOutcome::BanScore,
            "an honest peer requesting {MAX_IN_FLIGHT_BLOCKS} blocks per getdata \
             must never be banned for it, as in dcrd"
        );
    }
}

/// The pending-request counters the two disconnect gates read must be
/// the live ones.  Unknown inventory types are skipped by
/// `handleServeGetData` without decrementing
/// `numPendingGetDataItemReqs` (dcrd's `default` arm `continue`s), so
/// two full inventory messages of unknown-type items peg the counter at
/// exactly [`MAX_PENDING_GETDATA_ITEM_REQS`] and the third request must
/// trip the limit and drop the peer.
///
/// Reverting the wiring — passing literal `0, 0` for the pending counts
/// — makes the third request enqueue like the others, the peer stays
/// connected, and this test fails waiting for the registry to drain.
#[test]
fn pending_getdata_item_requests_disconnect_the_peer() {
    let (_dir, runtime, connected, mut transport, _chain) = serve_genesis_chain();

    assert_eq!(
        MAX_PENDING_GETDATA_ITEM_REQS,
        2 * MAX_INV_PER_MSG,
        "two full inventory messages is the limit"
    );
    let unknown_batch = |seed: u32| MsgGetData {
        inv_list: (0..MAX_INV_PER_MSG)
            .map(|i| InvVect {
                // A type no serve path recognizes, skipped without a
                // notfound entry and without a pending decrement.
                inv_type: InvType(0xdcd0_u32),
                hash: seeded_hash(seed, i),
            })
            .collect(),
    };

    transport
        .write_message(&Message::GetData(unknown_batch(1)))
        .expect("send the first full getdata");
    transport
        .write_message(&Message::GetData(unknown_batch(2)))
        .expect("send the second full getdata");
    // Let the serve worker drain both batches; neither can decrement
    // the pending item count, so it stays pegged at the limit.
    std::thread::sleep(Duration::from_millis(500));
    // The third request cannot fit under the limit, so the peer is
    // disconnected before it is queued.  The write itself may fail if
    // the server tears the connection down mid-write, which is the
    // same outcome.
    let _ = transport.write_message(&Message::GetData(unknown_batch(3)));

    let deadline = Instant::now() + Duration::from_secs(30);
    while !connected.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        connected.is_empty(),
        "exceeding the pending getdata item limit must disconnect the peer"
    );

    runtime.shutdown();
}

/// The serve path must not hold the node-wide chain lock across a
/// batch: it is the lock netsync, the miner, the template generator and
/// every chain RPC contend for, so an attacker-sized batch that held it
/// would stall the whole node.  A full inventory message of items that
/// need no chain access is served to completion while this thread owns
/// the chain lock outright.
///
/// Reverting to the batch-wide guard — one `chain.lock()` around the
/// whole inventory walk, which also reads `best_snapshot()`
/// unconditionally — blocks the serve worker on the lock this thread
/// holds, no response arrives, and the read below fails on its timeout
/// rather than hanging.
#[test]
fn a_large_getdata_does_not_hold_the_chain_lock() {
    let (_dir, runtime, _connected, mut transport, chain) = serve_genesis_chain();

    let inv_list: Vec<InvVect> = (0..MAX_INV_PER_MSG)
        .map(|i| InvVect {
            inv_type: InvType::TX,
            hash: seeded_hash(7, i),
        })
        .collect();

    // Take the chain lock and keep it for the whole exchange.
    let held = chain.lock().expect("chain mutex poisoned");
    transport
        .write_message(&Message::GetData(MsgGetData {
            inv_list: inv_list.clone(),
        }))
        .expect("send a full getdata");
    let served = transport.read_message();
    drop(held);

    match served {
        Ok(Message::NotFound(not_found)) => assert_eq!(
            not_found.inv_list, inv_list,
            "every item misses into the consolidated notfound"
        ),
        Ok(other) => panic!("expected the consolidated notfound, got {other:?}"),
        Err(e) => panic!(
            "a getdata needing no chain access must be served while another \
             thread holds the chain lock, but nothing arrived: {e:?}"
        ),
    }

    runtime.shutdown();
}

/// dcrd loads at most `maxPendingSend` getdata payloads from the
/// database and queues them for send at once, releasing a slot as each
/// write completes ("keeping the memory usage bounded to reasonable
/// limits").  The port derives the completion signal from the peer's
/// cumulative send accounting; this pins that bookkeeping.
///
/// Reverting the bound — queueing every fetched payload regardless of
/// what has been written — makes `has_room` always true and the
/// saturation assertions below fail.
#[test]
fn the_send_pipeline_bounds_queued_but_unsent_payloads() {
    let mut pipeline = SendPipeline::new();
    assert_eq!(pipeline.pending(), 0);
    assert!(pipeline.has_room(MAX_PENDING_SEND));

    // Fill every slot; nothing has been written yet.
    for queued in 1..=MAX_PENDING_SEND {
        pipeline.record_queued(1_000);
        assert_eq!(pipeline.pending(), queued);
    }
    assert!(
        !pipeline.has_room(MAX_PENDING_SEND),
        "a full pipeline must make the serve wait rather than queue more"
    );

    // The output loop reports the first payload written, framing
    // included, which frees exactly one slot.
    pipeline.record_sent(1_000 + MESSAGE_HEADER_SIZE);
    assert_eq!(pipeline.pending(), MAX_PENDING_SEND - 1);
    assert!(pipeline.has_room(MAX_PENDING_SEND));

    // A partial write of the next payload frees nothing.
    pipeline.record_queued(1_000);
    pipeline.record_sent(500);
    assert_eq!(pipeline.pending(), MAX_PENDING_SEND);

    // Draining everything empties the pipeline and never underflows.
    pipeline.record_sent(u64::MAX);
    assert_eq!(pipeline.pending(), 0);
    assert!(pipeline.has_room(MAX_PENDING_SEND));
}

/// A distinct hash per (seed, index) pair.
fn seeded_hash(seed: u32, index: u32) -> Hash {
    let mut h = [0u8; 32];
    h[0..4].copy_from_slice(&seed.to_le_bytes());
    h[4..8].copy_from_slice(&index.to_le_bytes());
    Hash(h)
}

/// The serving rig these tests drive: a genesis-state testnet chain in
/// a temporary database served through the listener runtime, plus a
/// negotiated client transport talking to it.  Banning is disabled so
/// the decaying request score cannot pre-empt the capacity gates under
/// test.
fn serve_genesis_chain() -> (
    tempfile::TempDir,
    ListenerRuntime,
    ConnectedPeers,
    WireTransport<TcpStream>,
    Arc<Mutex<Chain>>,
) {
    let params = dcroxide_chaincfg::testnet3_params();

    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));

    let addr_manager = Arc::new(Mutex::new(dcroxide_addrmgr::AddrManager::new(dir.path())));
    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    );
    let server = Arc::new(ServerContext {
        target_outbound: 8,
        chain: Arc::clone(&chain),
        min_known_work: params.min_known_chain_work,
        params: params.clone(),
        disable_banning: true,
        ban_threshold: BAN_THRESHOLD,
        whitelists: Vec::new(),
        banned_hosts: Mutex::new(std::collections::BTreeMap::new()),
        ban_duration_nanos: 24 * 60 * 60 * 1_000_000_000,
        addr_manager: Arc::clone(&addr_manager),
        sim_or_reg_net: false,
        stake_validation_height: params.stake_validation_height,
        blocks_only: false,
        sync_manager: Arc::new(Mutex::new(dcroxide_node::sync::new_sync_manager(
            Arc::clone(&chain),
            &params,
            false,
            8,
            1000,
            Arc::clone(&tx_pool),
            dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone(), &tx_pool),
        ))),
        sync_peers: dcroxide_node::dispatch::SyncPeers::new(),
        next_peer_id: std::sync::atomic::AtomicI32::new(1),
        net_totals: Arc::new(dcroxide_node::transport::NetByteTotals::new()),
        disable_listen: false,
        tx_pool: Arc::clone(&tx_pool),
        ntfn: None,
        recently_advertised: dcroxide_node::dispatch::new_recently_advertised(),
        mix_pool: dcroxide_node::mixnode::shared_mix_pool(
            Arc::clone(&chain),
            params.clone(),
            &tx_pool,
        ),
    });

    let template = PeerTemplate {
        net: SERVE_NET,
        protocol_version: 0,
        services: ServiceFlag(1),
        user_agent_name: "dcroxide".to_string(),
        user_agent_version: "0.1.0".to_string(),
        idle_timeout: Duration::from_secs(3600),
        ping_interval: Duration::from_secs(3600),
        newest_block: None,
    };
    let connected = ConnectedPeers::new();
    let runtime = ListenerRuntime::start(
        &[("tcp4", ":0".to_string())],
        inbound_peer_handler(template, connected.clone(), Some(Arc::clone(&server)), None),
    )
    .expect("start serving runtime");
    let port = runtime.bound_addrs()[0].port();

    let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to the server");
    // Bounded so a serve that never happens fails the read rather than
    // hanging the test.
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("set read timeout");
    let mut transport = WireTransport::new(stream, MAX_PROTOCOL_VERSION, SERVE_NET);
    let mut env = NodePeerEnv::new();
    let globals = PeerGlobals::new();
    let config = Config {
        net: SERVE_NET,
        protocol_version: 0,
        ..Config::default()
    };
    let mut peer = Peer::new_outbound(config, &format!("127.0.0.1:{port}")).expect("outbound");
    peer.negotiate_outbound_protocol(&mut transport, &mut env, &globals, None)
        .expect("negotiate");
    assert_eq!(
        transport.read_message().expect("read sendheaders"),
        Message::SendHeaders
    );

    (dir, runtime, connected, transport, chain)
}
