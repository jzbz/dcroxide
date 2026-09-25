// SPDX-License-Identifier: ISC
//! Handler regressions from the 2026-09-23 review, each driven through
//! the ported request pipeline (`process_request`, or the websocket
//! service path) the way a client reaches it:
//!
//! - an explicit JSON `null` for a map or slice parameter is Go's nil
//!   map or slice, which dcrd reads as empty; the port's accessors
//!   panicked on it, and under `panic = "abort"` that killed the node
//!   (createrawtransaction, createrawsstx, rescan);
//! - ticketfeeinfo/txfeeinfo with a block count past the genesis block
//!   answer dcrd's height -1 error without walking the whole chain;
//! - a result holding a non-finite float fails to marshal, and the
//!   reply is dropped as dcrd's `processRequest` drops it (getvoteinfo);
//! - getrawmempool reports the pool's cached transaction hash;
//! - getrawtransaction's deserialization failure carries Go's error
//!   text, not a Rust Debug rendering;
//! - the two recorded divergences stay what PARITY.md says they are:
//!   sendrawtransaction reads an explicit null `allowhighfees` as false,
//!   and submitblock hands on only the block, not trailing bytes.

use std::sync::Mutex;

use dcroxide_chaincfg::{ConsensusDeployment, mainnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_dcrjson::{GoValue, Registry, RpcId, parse_params};
use dcroxide_rpc::dispatch::process_request;
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::helpers::threshold::State;
use dcroxide_rpc::server::{
    Config, RpcBestState, RpcChain, RpcConnManager, RpcDb, RpcMempoolTx, RpcSyncManager,
    RpcTxIndexEntry, RpcTxIndexer, RpcTxMempooler, RpcVerboseMempoolTx, RpcVoteCounts,
    SendTxFailure, Server, SubmitBlockFailure, VoteInfoFailure,
};
use dcroxide_rpc::websocket::{WsClient, WsClientFilter, handle_rescan, lock_client};
use dcroxide_rpctypes::{method, register_all};
use dcroxide_standalone::SubsidyCache;
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint, TxIn, TxOut, TxSerializeType};

// ---------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------

const BEST_HEIGHT: i64 = 10;

fn best_hash() -> Hash {
    Hash([0xbb; 32])
}

fn header(height: u32) -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_block: Hash::ZERO,
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

fn sample_tx() -> MsgTx {
    MsgTx {
        ser_type: TxSerializeType::Full,
        version: 1,
        tx_in: vec![TxIn {
            previous_out_point: OutPoint {
                hash: Hash([0x42; 32]),
                index: 3,
                tree: 0,
            },
            sequence: 0xffff_ffff,
            value_in: 5_000_000,
            block_height: 0,
            block_index: 0xffff_ffff,
            signature_script: vec![0x51],
        }],
        tx_out: vec![TxOut {
            value: 4_000_000,
            version: 0,
            pk_script: vec![0x51],
        }],
        lock_time: 0,
        expiry: 0,
    }
}

/// The mainnet agenda set of one vote version, for getvoteinfo.
fn first_deployments() -> (u32, Vec<ConsensusDeployment>) {
    mainnet_params().deployments[0].clone()
}

/// A scripted chain: a main chain of `BEST_HEIGHT + 1` empty blocks,
/// with every height lookup recorded, plus a started agenda that has no
/// votes of its version yet.
#[derive(Default)]
struct MockChain {
    heights_loaded: Mutex<Vec<i64>>,
}

impl RpcChain for MockChain {
    fn best_snapshot(&self) -> RpcBestState {
        RpcBestState {
            hash: best_hash(),
            prev_hash: Hash::ZERO,
            height: BEST_HEIGHT,
            bits: 0,
            next_stake_diff: 0,
            total_subsidy: 0,
            block_size: 0,
            num_txns: 0,
        }
    }

    fn block_by_height(&self, height: i64) -> Result<MsgBlock, String> {
        self.heights_loaded.lock().unwrap().push(height);
        if !(0..=BEST_HEIGHT).contains(&height) {
            return Err(format!("no block at height {height} exists"));
        }
        Ok(MsgBlock {
            header: header(height as u32),
            transactions: Vec::new(),
            stransactions: Vec::new(),
        })
    }

    fn block_height_by_hash(&self, _hash: &Hash) -> Result<i64, String> {
        Ok(5)
    }

    fn get_vote_info(
        &self,
        _hash: &Hash,
        version: u32,
    ) -> Result<Vec<ConsensusDeployment>, VoteInfoFailure> {
        let (want, deployments) = first_deployments();
        assert_eq!(version, want);
        Ok(deployments)
    }

    fn count_vote_version(&self, _version: u32) -> Result<u32, String> {
        Ok(0)
    }

    fn next_threshold_state(&self, _prev: &Hash, _id: &str) -> Result<State, String> {
        Ok(State::Started)
    }

    fn get_vote_counts(&self, _version: u32, id: &str) -> Result<RpcVoteCounts, String> {
        // dcrd's getVoteCounts counts only votes of the requested
        // version, so the totals are zero once voters have moved on.
        let (_, deployments) = first_deployments();
        let choices = deployments
            .iter()
            .find(|d| d.vote.id == id)
            .map_or(0, |d| d.vote.choices.len());
        Ok(RpcVoteCounts {
            total: 0,
            total_abstain: 0,
            vote_choices: vec![0; choices],
        })
    }
}

/// A pool whose descriptors carry a cached hash that is deliberately
/// not the transaction's own, so a handler that rehashes shows.
struct MockMempool {
    cached_hash: Hash,
}

impl RpcTxMempooler for MockMempool {
    fn tx_descs(&self) -> Vec<RpcMempoolTx> {
        vec![RpcMempoolTx {
            serialize_size: sample_tx().serialize_size(),
            tx_hash: self.cached_hash,
            tx_type: dcroxide_stake::TxType::Regular,
            fee: 1_000_000,
        }]
    }

    fn verbose_tx_descs(&self) -> Vec<RpcVerboseMempoolTx> {
        vec![RpcVerboseMempoolTx {
            serialize_size: sample_tx().serialize_size(),
            tx_hash: self.cached_hash,
            tx_type: dcroxide_stake::TxType::Regular,
            added_unix: 1,
            height: BEST_HEIGHT,
            fee: 1_000_000,
            depends: Vec::new(),
        }]
    }
}

/// Records what the handlers hand the sync manager.
#[derive(Default)]
struct MockSync {
    allow_high_fees: Mutex<Vec<bool>>,
    submitted: Mutex<Vec<MsgBlock>>,
}

impl RpcSyncManager for &'static MockSync {
    fn process_transaction(
        &self,
        tx: &MsgTx,
        _allow_orphan: bool,
        allow_high_fees: bool,
        _tag: u64,
    ) -> Result<Vec<Hash>, SendTxFailure> {
        self.allow_high_fees.lock().unwrap().push(allow_high_fees);
        Ok(vec![tx.tx_hash()])
    }

    fn submit_block(&self, block: &MsgBlock) -> Result<(), SubmitBlockFailure> {
        self.submitted.lock().unwrap().push(block.clone());
        Ok(())
    }
}

struct NullConnManager;

impl RpcConnManager for NullConnManager {
    fn relay_transactions(&self, _tx_hashes: &[Hash]) {}
    fn add_rebroadcast_inventory(&self, _tx_hash: &Hash, _tx: &MsgTx) {}
}

/// A tx index whose one entry points at a region the database returns
/// truncated.
struct MockTxIndex;

impl RpcTxIndexer for MockTxIndex {
    fn name(&self) -> String {
        "transaction index".to_string()
    }
    fn tip(&self) -> Result<(i64, Hash), String> {
        Ok((BEST_HEIGHT, best_hash()))
    }
    fn entry(&self, _tx_hash: &Hash) -> Result<Option<RpcTxIndexEntry>, String> {
        Ok(Some(RpcTxIndexEntry {
            block_hash: best_hash(),
            offset: 0,
            len: 3,
            block_index: 1,
        }))
    }
}

struct TruncatedDb;

impl RpcDb for TruncatedDb {
    fn fetch_block_region(&self, _hash: &Hash, _offset: u32, len: u32) -> Result<Vec<u8>, String> {
        Ok(sample_tx().serialize()[..len as usize].to_vec())
    }
}

fn server_with(sync: &'static MockSync) -> Server<MockChain> {
    let params = mainnet_params();
    Server::new(Config {
        chain: MockChain::default(),
        chain_params: params.clone(),
        subsidy_cache: Mutex::new(SubsidyCache::new(params.clone())),
        min_relay_tx_fee: 10000,
        max_protocol_version: dcroxide_wire::PROTOCOL_VERSION,
        sync_mgr: Box::new(sync),
        conn_mgr: Box::new(NullConnManager),
        client_cert_auth: false,
        tx_mempooler: Box::new(MockMempool {
            cached_hash: Hash([0x11; 32]),
        }),
        clock: Box::new(()),
        interfaces: Box::new(NoInterfaces),
        rand_u64: Box::new(|| 0),
        tx_indexer: Some(Box::new(MockTxIndex)),
        db: Box::new(TruncatedDb),
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

fn server() -> Server<MockChain> {
    server_with(Box::leak(Box::default()))
}

/// Run one request through the HTTP pipeline, as the limited user
/// unless `admin`.
fn request(
    server: &Server<MockChain>,
    method: &str,
    params: &[&str],
    admin: bool,
) -> Option<String> {
    process_request(server, "1.0", method, params, &RpcId::Int(1), admin)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------
// Explicit null for a map or slice parameter.
// ---------------------------------------------------------------------

/// dcrd ranges over the nil `Amounts` map and returns the input-only
/// transaction, the same reply an empty map gets.  A limited user can
/// send this, and the port used to abort the process on it.
#[test]
fn createrawtransaction_null_amounts_is_an_empty_map() {
    let server = server();
    let with_null =
        request(&server, "createrawtransaction", &["[]", "null"], false).expect("a reply");
    let with_empty =
        request(&server, "createrawtransaction", &["[]", "{}"], false).expect("a reply");
    assert_eq!(with_null, with_empty);
    assert!(with_null.contains("\"error\":null"), "{with_null}");

    // And with inputs, the null amounts still just mean no outputs.
    let input = r#"[{"amount":0,"txid":"4242424242424242424242424242424242424242424242424242424242424242","vout":3,"tree":0}]"#;
    let with_null =
        request(&server, "createrawtransaction", &[input, "null"], false).expect("a reply");
    let with_empty =
        request(&server, "createrawtransaction", &[input, "{}"], false).expect("a reply");
    assert_eq!(with_null, with_empty);
}

/// dcrd's `len(c.Amount) != 1` check sees the nil map as length zero.
#[test]
fn createrawsstx_null_amount_is_dcrds_length_error() {
    let server = server();
    let reply = request(&server, "createrawsstx", &["[]", "null", "[]"], false).expect("a reply");
    assert!(
        reply.contains(
            r#""error":{"code":-8,"message":"Only one SSGen tagged output is allowed per sstx; len ssgenout 0"}"#
        ),
        "{reply}"
    );
    // Null inputs and commitment outputs are empty slices too.
    let reply =
        request(&server, "createrawsstx", &["null", "null", "null"], false).expect("a reply");
    assert!(reply.contains("len ssgenout 0"), "{reply}");
}

/// A null `BlockHashes` is a nil slice: dcrd's rescan decodes no hashes
/// and returns an empty result.
#[test]
fn rescan_null_block_hashes_is_an_empty_rescan() {
    let server = server();
    let mut registry = Registry::new();
    register_all(&mut registry);
    let cmd = GoValue::Struct(
        parse_params(&registry, &method("rescan"), &["null"])
            .expect("rescan parses")
            .fields,
    );
    assert_eq!(cmd, GoValue::Struct(vec![GoValue::Null]));

    let wsc = Mutex::new(WsClient::new(1));
    lock_client(&wsc).filter_data = Some(WsClientFilter::new(&[], &[], &mainnet_params()));
    let result = handle_rescan(&server, &wsc, &cmd).expect("rescan succeeds");
    assert_eq!(result, GoValue::Struct(vec![GoValue::Array(Vec::new())]));
}

// ---------------------------------------------------------------------
// Fee info block counts past the genesis block.
// ---------------------------------------------------------------------

/// A count reaching below genesis gets dcrd's height -1 error from a
/// single lookup instead of loading every block first.
#[test]
fn fee_info_past_genesis_fails_without_walking_the_chain() {
    for method in ["ticketfeeinfo", "txfeeinfo"] {
        let server = server();
        let reply = request(&server, method, &["4294967295"], false).expect("a reply");
        assert!(
            reply.contains(r#""error":{"code":-32603,"message":"no block at height -1 exists"}"#),
            "{method}: {reply}"
        );
        assert_eq!(
            *server.cfg.chain.heights_loaded.lock().unwrap(),
            vec![-1],
            "{method} must not load the main chain before failing"
        );
    }

    // One past genesis is the first count that fails.
    let server = server();
    let reply = request(&server, "ticketfeeinfo", &["12"], false).expect("a reply");
    assert!(reply.contains("no block at height -1 exists"), "{reply}");
    assert_eq!(*server.cfg.chain.heights_loaded.lock().unwrap(), vec![-1]);
}

/// A count that ends exactly at genesis is served, block by block.
#[test]
fn fee_info_down_to_genesis_still_walks_every_block() {
    let server = server();
    let reply = request(&server, "ticketfeeinfo", &["11"], false).expect("a reply");
    assert!(reply.contains("\"error\":null"), "{reply}");
    assert_eq!(
        *server.cfg.chain.heights_loaded.lock().unwrap(),
        (0..=BEST_HEIGHT).rev().collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------
// A result Go's encoder refuses.
// ---------------------------------------------------------------------

/// getvoteinfo's choice progress is `0/0 = NaN` for a started agenda
/// with no votes of the version yet.  Go's `json.Marshal` fails on it,
/// so dcrd's `processRequest` logs and returns no reply at all; the
/// port used to answer `"progress":null`.
#[test]
fn getvoteinfo_nan_progress_drops_the_reply() {
    let server = server();
    let (version, _) = first_deployments();
    let version = version.to_string();
    assert_eq!(request(&server, "getvoteinfo", &[&version], true), None);

    // The websocket service path drops it the same way.
    let cmd = GoValue::Struct(vec![GoValue::Uint(first_deployments().0.into())]);
    let wsc = Mutex::new(WsClient::new(1));
    assert_eq!(
        dcroxide_rpc::websocket::ws_service_request(
            &server,
            &wsc,
            "1.0",
            "getvoteinfo",
            &cmd,
            &RpcId::Int(1)
        ),
        None
    );
}

/// The marshal failure carries Go's error text.
#[test]
fn create_marshalled_reply_fails_with_gos_unsupported_value_text() {
    let err = dcroxide_rpc::dispatch::create_marshalled_reply(
        "1.0",
        &RpcId::Int(1),
        Some((
            &dcroxide_dcrjson::GoType::Float64,
            &GoValue::Float64(f64::NAN),
        )),
        None,
    )
    .expect_err("NaN does not marshal");
    assert_eq!(err, "json: unsupported value: NaN");
}

// ---------------------------------------------------------------------
// The pool's cached transaction hash.
// ---------------------------------------------------------------------

/// dcrd reads the hash cached on the pool's `dcrutil.Tx`; the port now
/// takes the one the pool cached at admission instead of serializing
/// and hashing every pool transaction per call.
#[test]
fn getrawmempool_reports_the_cached_hash() {
    let server = server();
    let cached = Hash([0x11; 32]).to_string();
    assert_ne!(cached, sample_tx().tx_hash().to_string());

    let reply = request(&server, "getrawmempool", &[], false).expect("a reply");
    assert!(
        reply.contains(&format!("\"result\":[\"{cached}\"]")),
        "{reply}"
    );

    let reply = request(&server, "getrawmempool", &["true"], false).expect("a reply");
    assert!(
        reply.contains(&format!("\"result\":{{\"{cached}\":{{")),
        "{reply}"
    );
}

// ---------------------------------------------------------------------
// Go error text on getrawtransaction's deserialization failure.
// ---------------------------------------------------------------------

/// dcrd returns `rpcInternalErr(err, ...)`, whose message is the
/// deserialization error's own text: `unexpected EOF` for a truncated
/// region.
#[test]
fn getrawtransaction_deserialize_failure_carries_gos_text() {
    let server = server();
    let txid = sample_tx().tx_hash().to_string();
    let reply = request(
        &server,
        "getrawtransaction",
        &[&format!("\"{txid}\""), "1"],
        false,
    )
    .expect("a reply");
    assert!(
        reply.contains(r#""error":{"code":-32603,"message":"unexpected EOF"}"#),
        "{reply}"
    );
}

// ---------------------------------------------------------------------
// Recorded divergences.
// ---------------------------------------------------------------------

/// dcrd dereferences the nil `AllowHighFees` an explicit null leaves
/// and panics; the port reads it as false and processes the
/// transaction (PARITY.md, deliberate divergences).
#[test]
fn sendrawtransaction_null_allowhighfees_reads_as_false() {
    let sync: &'static MockSync = Box::leak(Box::default());
    let server = server_with(sync);
    let tx = sample_tx();
    let tx_hex = format!("\"{}\"", hex(&tx.serialize()));
    let reply = request(&server, "sendrawtransaction", &[&tx_hex, "null"], false).expect("a reply");
    assert!(
        reply.contains(&format!("\"result\":\"{}\"", tx.tx_hash())),
        "{reply}"
    );
    assert_eq!(*sync.allow_high_fees.lock().unwrap(), vec![false]);
}

/// dcrd keeps bytes trailing a submitted block and stores them; the
/// port hands the sync manager only the block (PARITY.md, deliberate
/// divergences).
#[test]
fn submitblock_trailing_bytes_are_not_kept() {
    let sync: &'static MockSync = Box::leak(Box::default());
    let server = server_with(sync);
    let block = MsgBlock {
        header: header(11),
        transactions: vec![sample_tx()],
        stransactions: Vec::new(),
    };
    let canonical = block.serialize();
    let submitted = format!("\"{}00ff\"", hex(&canonical));
    let reply = request(&server, "submitblock", &[&submitted], true).expect("a reply");
    assert!(reply.contains("\"result\":null,\"error\":null"), "{reply}");

    let got = sync.submitted.lock().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].serialize(), canonical);
}
