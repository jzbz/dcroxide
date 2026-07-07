// SPDX-License-Identifier: ISC
//! Replay of frozen submission/control RPC handler vectors generated
//! by an in-package dump test running inside dcrd's
//! internal/rpcserver package at release-v2.1.5: 30 cases across
//! sendrawtransaction (the rule/duplicate/recently-confirmed error
//! ladder), submitblock (rejections as string results and Go's exact
//! hex error text), invalidateblock, reconsiderblock, regentemplate,
//! debuglevel, and estimatesmartfee, each carrying the marshalled
//! request params (parsed here through the ported dcrjson pipeline),
//! the mock seam facts, and the marshalled result or the exact error
//! code and message.

// Index arithmetic over pinned vector rows.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_chaincfg::mainnet_params;
use dcroxide_chainhash::Hash;
use dcroxide_dcrjson::{GoType, GoValue, RPCError, Registry, gojson, parse_params};
use dcroxide_rpc::handlers;
use dcroxide_rpc::helpers::NoInterfaces;
use dcroxide_rpc::server::{
    Config, InvalidateBlockFailure, ReconsiderBlockFailure, RpcBlockTemplater, RpcChain,
    RpcConnManager, RpcFeeEstimator, RpcLogManager, RpcSubsidyParams, RpcSyncManager,
    SendTxFailure, Server,
};
use dcroxide_rpctypes::chainsvrresults as results;
use dcroxide_rpctypes::{method, register_all};
use dcroxide_standalone::SubsidyCache;
use dcroxide_wire::{MsgBlock, MsgTx, PROTOCOL_VERSION};

const VECTORS: &str = include_str!("data/rpchandlers7_vectors.txt");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn utf8(hex: &str) -> String {
    String::from_utf8(unhex(hex)).unwrap()
}

/// Split a JSON array into the raw JSON text of its elements.
fn split_json_array(data: &str) -> Vec<String> {
    let bytes = data.as_bytes();
    assert_eq!(bytes.first(), Some(&b'['), "params must be an array");
    let mut elems = Vec::new();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    let mut start = None;
    for (i, &b) in bytes.iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => {
                in_string = true;
                if start.is_none() {
                    start = Some(i);
                }
            }
            b'[' | b'{' => {
                if depth > 0 && start.is_none() {
                    start = Some(i);
                }
                depth += 1;
            }
            b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(s) = start {
                        elems.push(data[s..i].trim().to_string());
                    }
                    break;
                }
            }
            b',' if depth == 1 => {
                if let Some(s) = start {
                    elems.push(data[s..i].trim().to_string());
                }
                start = None;
            }
            b' ' | b'\t' | b'\n' | b'\r' => {}
            _ => {
                if depth == 1 && start.is_none() {
                    start = Some(i);
                }
            }
        }
    }
    elems
}

/// The scripted sync manager.
struct MockSyncMgr7 {
    process: Result<Vec<Hash>, SendTxFailure>,
    recently_confirmed: bool,
    submit: Result<(), String>,
}

impl RpcSyncManager for MockSyncMgr7 {
    fn process_transaction(
        &mut self,
        _tx: &MsgTx,
        _allow_orphan: bool,
        _allow_high_fees: bool,
        _tag: u64,
    ) -> Result<Vec<Hash>, SendTxFailure> {
        self.process.clone()
    }
    fn recently_confirmed_txn(&mut self, _hash: &Hash) -> bool {
        self.recently_confirmed
    }
    fn submit_block(&mut self, _block: &MsgBlock) -> Result<(), String> {
        self.submit.clone()
    }
}

/// The scripted connection manager (relay/rebroadcast are
/// unobservable in the vectors).
struct MockConnMgr7;

impl RpcConnManager for MockConnMgr7 {
    fn relay_transactions(&mut self, _tx_hashes: &[Hash]) {}
    fn add_rebroadcast_inventory(&mut self, _tx_hash: &Hash, _tx: &MsgTx) {}
}

/// The scripted chain seam.
struct MockChain7 {
    invalidate: Result<(), InvalidateBlockFailure>,
    reconsider: Result<(), ReconsiderBlockFailure>,
}

impl RpcChain for MockChain7 {
    fn invalidate_block(&mut self, _hash: &Hash) -> Result<(), InvalidateBlockFailure> {
        self.invalidate.clone()
    }
    fn reconsider_block(&mut self, _hash: &Hash) -> Result<(), ReconsiderBlockFailure> {
        self.reconsider.clone()
    }
}

/// The scripted log manager, fee estimator, and templater.
struct MockLogMgr {
    set_err: Option<String>,
}

impl RpcLogManager for MockLogMgr {
    fn supported_subsystems(&mut self) -> Vec<String> {
        ["DCRD", "PEER", "RPCS", "SYNC"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }
    fn parse_and_set_debug_levels(&mut self, _spec: &str) -> Result<(), String> {
        match &self.set_err {
            Some(err) => Err(err.clone()),
            None => Ok(()),
        }
    }
}

struct MockFeeEstimator {
    fee: Result<i64, String>,
}

impl RpcFeeEstimator for MockFeeEstimator {
    fn estimate_fee(&mut self, _target: i32) -> Result<i64, String> {
        self.fee.clone()
    }
}

struct MockTemplater;

impl RpcBlockTemplater for MockTemplater {
    fn force_regen(&mut self) {}
}

fn dispatch(
    server: &mut Server<MockChain7>,
    method_name: &str,
    cmd: &GoValue,
) -> Result<(GoValue, GoType), RPCError> {
    let (result, typ) = match method_name {
        "sendrawtransaction" => (
            handlers::handle_send_raw_transaction(server, cmd)?,
            GoType::String,
        ),
        "submitblock" => {
            let value = handlers::handle_submit_block(server, cmd)?;
            (value, GoType::String.ptr())
        }
        "invalidateblock" => (
            handlers::handle_invalidate_block(server, cmd)?,
            GoType::Int64.ptr(),
        ),
        "reconsiderblock" => (
            handlers::handle_reconsider_block(server, cmd)?,
            GoType::Int64.ptr(),
        ),
        "regentemplate" => (
            handlers::handle_regen_template(server, cmd)?,
            GoType::Int64.ptr(),
        ),
        "debuglevel" => (handlers::handle_debug_level(server, cmd)?, GoType::String),
        "estimatesmartfee" => (
            handlers::handle_estimate_smart_fee(server, cmd)?,
            results::estimate_smart_fee_result(),
        ),
        other => panic!("unknown method {other}"),
    };
    Ok((result, typ))
}

#[test]
fn submission_handler_slice_matches_dcrd() {
    let params = mainnet_params();
    let mut registry = Registry::new();
    register_all(&mut registry);

    // The accepted-transaction fixture hash.
    let tx_hash: Hash = VECTORS
        .lines()
        .find_map(|line| {
            let f: Vec<&str> = line.split('|').collect();
            (f[0] == "txfix").then(|| {
                let (tx, _) = MsgTx::from_bytes(&unhex(f[1])).unwrap();
                tx.tx_hash()
            })
        })
        .expect("tx fixture");

    let lines: Vec<&str> = VECTORS
        .lines()
        .filter(|l| l.starts_with("case|") || l.starts_with("mock7|") || l.starts_with("result|"))
        .collect();
    let mut cases = 0;
    let mut i = 0;
    while i < lines.len() {
        let case: Vec<&str> = lines[i].split('|').collect();
        let mock: Vec<&str> = lines[i + 1].split('|').collect();
        let result: Vec<&str> = lines[i + 2].split('|').collect();
        assert_eq!(case[0], "case");
        assert_eq!(mock[0], "mock7");
        assert_eq!(result[0], "result");
        i += 3;
        cases += 1;

        let name = case[2];
        let method_name = case[3];
        let params_json = utf8(case[4]);

        // Parse the command through the ported pipeline.
        let raw_params = split_json_array(&params_json);
        let param_refs: Vec<&str> = raw_params.iter().map(|s| s.as_str()).collect();
        let cmd_instance = parse_params(&registry, &method(method_name), &param_refs)
            .unwrap_or_else(|e| panic!("{name}: parse params: {e:?}"));
        let cmd = GoValue::Struct(cmd_instance.fields);

        // The process-transaction outcome: OK, a rule error with the
        // duplicate flag, or a plain failure.
        let process = match mock[2] {
            "OK" => Ok(vec![tx_hash]),
            other => match other.strip_prefix("RULE:") {
                Some(rest) => {
                    let (dup, msg) = rest.split_once(':').unwrap();
                    Err(SendTxFailure {
                        is_rule_error: true,
                        is_duplicate: dup == "true",
                        message: msg.to_string(),
                    })
                }
                None => Err(SendTxFailure {
                    is_rule_error: false,
                    is_duplicate: false,
                    message: other.strip_prefix("ERR:").unwrap().to_string(),
                }),
            },
        };
        let invalidate = match mock[5] {
            "OK" => Ok(()),
            "ERRUB" => Err(InvalidateBlockFailure {
                is_unknown_block: true,
                is_invalidate_genesis: false,
                message: String::new(),
            }),
            other => match other.strip_prefix("ERRGEN:") {
                Some(msg) => Err(InvalidateBlockFailure {
                    is_unknown_block: false,
                    is_invalidate_genesis: true,
                    message: msg.to_string(),
                }),
                None => Err(InvalidateBlockFailure {
                    is_unknown_block: false,
                    is_invalidate_genesis: false,
                    message: other.strip_prefix("ERR:").unwrap().to_string(),
                }),
            },
        };
        let reconsider = match mock[6] {
            "OK" => Ok(()),
            "ERRUB" => Err(ReconsiderBlockFailure {
                is_unknown_block: true,
                all_rule_errs: false,
                message: String::new(),
            }),
            other => match other.strip_prefix("RULE:") {
                Some(msg) => Err(ReconsiderBlockFailure {
                    is_unknown_block: false,
                    all_rule_errs: true,
                    message: msg.to_string(),
                }),
                None => Err(ReconsiderBlockFailure {
                    is_unknown_block: false,
                    all_rule_errs: false,
                    message: other.strip_prefix("ERR:").unwrap().to_string(),
                }),
            },
        };

        let chain = MockChain7 {
            invalidate,
            reconsider,
        };
        let sync_mgr = MockSyncMgr7 {
            process,
            recently_confirmed: mock[3] == "true",
            submit: match mock[4].strip_prefix("ERR:") {
                Some(err) => Err(err.to_string()),
                None => Ok(()),
            },
        };
        let block_templater: Option<Box<dyn RpcBlockTemplater>> = if mock[9] == "true" {
            None
        } else {
            Some(Box::new(MockTemplater))
        };
        let mut server = Server::new(Config {
            chain,
            chain_params: params.clone(),
            subsidy_cache: SubsidyCache::new(RpcSubsidyParams(params.clone())),
            min_relay_tx_fee: 10000,
            max_protocol_version: PROTOCOL_VERSION,
            sync_mgr: Box::new(sync_mgr),
            conn_mgr: Box::new(MockConnMgr7),
            tx_mempooler: Box::new(()),
            clock: Box::new(()),
            interfaces: Box::new(NoInterfaces),
            rand_u64: Box::new(|| 0),
            tx_indexer: None,
            db: Box::new(()),
            filterer_v2: Box::new(()),
            exists_addresser: None,
            log_manager: Box::new(MockLogMgr {
                set_err: mock[7].strip_prefix("ERR:").map(|e| e.to_string()),
            }),
            fee_estimator: Box::new(MockFeeEstimator {
                fee: match mock[8].strip_prefix("ERR:") {
                    Some(err) => Err(err.to_string()),
                    None => Ok(mock[8].parse().unwrap()),
                },
            }),
            block_templater,
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
        });

        match dispatch(&mut server, method_name, &cmd) {
            Ok((value, typ)) => {
                assert_eq!(result[2], "ok", "{name}: expected an error");
                let got = gojson::encode(&typ, &value);
                assert_eq!(got, utf8(result[3]), "{name}: result");
            }
            Err(err) => {
                assert_eq!(result[2], "err", "{name}: unexpected error {err:?}");
                assert_eq!(
                    i64::from(err.code),
                    result[3].parse::<i64>().unwrap(),
                    "{name}: error code ({})",
                    err.message
                );
                assert_eq!(err.message, utf8(result[4]), "{name}: error message");
            }
        }
    }
    assert_eq!(cases, 30, "unexpected case count");
}
