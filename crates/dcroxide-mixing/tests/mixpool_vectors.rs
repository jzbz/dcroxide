// SPDX-License-Identifier: ISC
//! Replay of dcrd's mixpool behavior generated inside dcrd's
//! mixing/mixpool package (`data/mixpool_vectors.txt`): message
//! acceptance across every rule rejection, orphan flows with
//! reconsideration cascades, pair request UTXO validation over a
//! mocked fetcher, expiry with the max-session-expiry quirk,
//! removals (sessions, confirmed sessions and mixes, spent and
//! rejected and unresponsive pair requests), the pairing queries,
//! the receive collection semantics, and two observer strike rounds
//! against a timing-out peer — comparing the full pool state
//! (pair requests, pool entries with types, orphans, sessions with
//! their expiries and message counts, outpoint and latest-KE index
//! sizes) and the strike table after every operation.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::HashMap;
use std::sync::Arc;

use dcroxide_chaincfg::{Params, simnet_params, testnet3_params};
use dcroxide_chainhash::Hash;
use dcroxide_mixing::{
    MixBlockChain, MixUtxoEntry, MixUtxoFetcher, Pool, PoolError, PoolMessage, Received, RuleKind,
};
use dcroxide_testutil::unhex;
use dcroxide_wire::{MIX_VERSION, Message, MsgTx, OutPoint, decode_message_payload};

fn leaked_params(name: &str) -> &'static Params {
    match name {
        "testnet3" => Box::leak(Box::new(testnet3_params())),
        "simnet" => Box::leak(Box::new(simnet_params())),
        other => panic!("unknown network {other}"),
    }
}

/// Parse a hash from dcrd's reversed-hex display form.
fn hash_from_str(s: &str) -> Hash {
    let mut bytes = unhex(s);
    bytes.reverse();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Hash(hash)
}

fn hash32_from_hex(s: &str) -> [u8; 32] {
    let bytes = unhex(s);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn raw_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn csv_or_dash(mut items: Vec<String>) -> String {
    items.sort();
    if items.is_empty() {
        "-".to_string()
    } else {
        items.join(",")
    }
}

struct DumpChain {
    params: &'static Params,
    height: i64,
}

impl MixBlockChain for DumpChain {
    fn chain_params(&self) -> &Params {
        self.params
    }
    fn current_tip(&self) -> (Hash, i64) {
        (
            Hash([0x01; 1].iter().fold([0u8; 32], |mut acc, _| {
                acc[0] = 0x01;
                acc
            })),
            self.height,
        )
    }
}

struct DumpUtxo {
    pk_script: Vec<u8>,
    script_ver: u16,
    height: i64,
    amount: i64,
    spent: bool,
}

impl MixUtxoEntry for DumpUtxo {
    fn is_spent(&self) -> bool {
        self.spent
    }
    fn pk_script(&self) -> &[u8] {
        &self.pk_script
    }
    fn script_version(&self) -> u16 {
        self.script_ver
    }
    fn block_height(&self) -> i64 {
        self.height
    }
    fn amount(&self) -> i64 {
        self.amount
    }
}

type UtxoRow = (Vec<u8>, u16, i64, i64, bool);

#[derive(Default)]
struct DumpFetcher {
    utxos: std::sync::Mutex<HashMap<([u8; 32], u32), UtxoRow>>,
}

impl MixUtxoFetcher for DumpFetcher {
    fn fetch_utxo_entry(&self, op: &OutPoint) -> Result<Box<dyn MixUtxoEntry>, String> {
        match self
            .utxos
            .lock()
            .expect("utxo map")
            .get(&(op.hash.0, op.index))
        {
            Some((script, ver, height, amount, spent)) => Ok(Box::new(DumpUtxo {
                pk_script: script.clone(),
                script_ver: *ver,
                height: *height,
                amount: *amount,
                spent: *spent,
            })),
            None => Err("no utxo entry".to_string()),
        }
    }
}

fn decode_pool_message(cmd: &str, payload: &[u8]) -> PoolMessage {
    match decode_message_payload(cmd, payload, MIX_VERSION).expect("decode") {
        Message::MixPairReq(m) => PoolMessage::PR(m),
        Message::MixKeyExchange(m) => PoolMessage::KE(m),
        Message::MixCiphertexts(m) => PoolMessage::CT(m),
        Message::MixSlotReserve(m) => PoolMessage::SR(m),
        Message::MixFactoredPoly(m) => PoolMessage::FP(m),
        Message::MixDCNet(m) => PoolMessage::DC(m),
        Message::MixConfirm(m) => PoolMessage::CM(m),
        Message::MixSecrets(m) => PoolMessage::RS(m),
        _ => panic!("not a mix message"),
    }
}

fn err_code(err: &PoolError) -> String {
    match err {
        PoolError::Rule(kind) => match kind {
            RuleKind::ChangeDust => "changedust".into(),
            RuleKind::MixDust => "mixdust".into(),
            RuleKind::LowInput => "lowinput".into(),
            RuleKind::HighFee => "highfee".into(),
            RuleKind::InvalidMessageCount => "msgcount".into(),
            RuleKind::InvalidScript => "invalidscript".into(),
            RuleKind::InvalidSessionID => "sessionid".into(),
            RuleKind::InvalidSignature => "signature".into(),
            RuleKind::InvalidTotalMixAmount => "totalmix".into(),
            RuleKind::InvalidUTXOProof => "utxoproof".into(),
            RuleKind::MissingUTXOs => "missingutxos".into(),
            RuleKind::PeerPositionOutOfBounds => "posbounds".into(),
            RuleKind::Other(msg) => format!("rule:{msg}"),
        },
        PoolError::MissingOwnPR(_) => "missingownpr".into(),
        PoolError::SecretsRevealed => "secretsrevealed".into(),
        PoolError::MessageNotFound => "err:message not found".into(),
        PoolError::UtxoFetch(msg) | PoolError::Other(msg) => format!("err:{msg}"),
    }
}

struct Scenario {
    pool: Pool<DumpChain>,
    fetcher: Arc<DumpFetcher>,
    msgs: HashMap<[u8; 32], PoolMessage>,
}

impl Scenario {
    fn render_state(&self) -> Vec<String> {
        let (prs, pool, orphans, sessions, out_points, latest_ke) = self.pool.state_snapshot();
        let prs_line = csv_or_dash(prs.iter().map(|h| format!("{}", Hash(*h))).collect());
        let pool_line = csv_or_dash(
            pool.iter()
                .map(|(h, t, _)| format!("{}:{t}", Hash(*h)))
                .collect(),
        );
        let orphans_line = csv_or_dash(orphans.iter().map(|h| format!("{}", Hash(*h))).collect());
        let sessions_line = csv_or_dash(
            sessions
                .iter()
                .map(|(sid, expiry, counts, nhashes)| {
                    let counts: Vec<String> = counts.iter().map(|c| c.to_string()).collect();
                    format!("{}:{expiry}:{nhashes}:{}", raw_hex(sid), counts.join("."))
                })
                .collect(),
        );
        vec![
            format!("prs {prs_line}"),
            format!("pool {pool_line}"),
            format!("orphans {orphans_line}"),
            format!("sessions {sessions_line}"),
            format!("counts {out_points} {latest_ke}"),
        ]
    }

    fn render_strikes(&self) -> String {
        let strikes = csv_or_dash(
            self.pool
                .strike_counts()
                .iter()
                .map(|(op, count)| format!("{}:{}:{count}", op.hash, op.index))
                .collect(),
        );
        format!("strikes {strikes}")
    }

    fn pr_by_hash(&self, hash: &Hash) -> dcroxide_wire::MsgMixPairReq {
        match self.msgs.get(&hash.0) {
            Some(PoolMessage::PR(pr)) => pr.clone(),
            _ => panic!("no PR recorded for hash {hash}"),
        }
    }
}

#[test]
fn mixpool_vectors() {
    let data = include_str!("data/mixpool_vectors.txt");
    let mut lines = data.lines().peekable();

    let mut scenario: Option<Scenario> = None;
    let mut counts = [0usize; 6];

    macro_rules! check_state {
        ($sc:expr, $ctx:expr) => {
            let got = $sc.render_state();
            for want in got {
                let line = lines.next().expect("state line");
                assert_eq!(want, line, "state after {}", $ctx);
            }
            assert_eq!(lines.next(), Some("endstate"), "state end after {}", $ctx);
        };
    }

    while let Some(line) = lines.next() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "scenario" => {
                let params = leaked_params(f[2]);
                let has_fetcher = f[3] == "1";
                let height: i64 = f[4].parse().expect("height");
                let now_unix: i64 = f[5].parse().expect("now");
                let chain = DumpChain { params, height };
                let fetcher = Arc::new(DumpFetcher::default());
                let clock: dcroxide_containers::lru::Clock = {
                    let nanos = now_unix.wrapping_mul(1_000_000_000);
                    std::sync::Arc::new(move || nanos)
                };
                let pool = Pool::new_with_clock(
                    chain,
                    if has_fetcher {
                        Some(fetcher.clone() as Arc<dyn MixUtxoFetcher + Send + Sync>)
                    } else {
                        None
                    },
                    clock,
                );
                scenario = Some(Scenario {
                    pool,
                    fetcher,
                    msgs: HashMap::new(),
                });
            }
            "utxo" => {
                let sc = scenario.as_ref().expect("scenario");
                let hash = hash_from_str(f[1]);
                let index: u32 = f[2].parse().expect("index");
                let script = unhex(f[3]);
                let height: i64 = f[4].parse().expect("height");
                let amount: i64 = f[5].parse().expect("amount");
                let spent: bool = f[6].parse().expect("spent");
                let ver: u16 = f[7].parse().expect("ver");
                sc.fetcher
                    .utxos
                    .lock()
                    .expect("utxo map")
                    .insert((hash.0, index), (script, ver, height, amount, spent));
            }
            "accept" => {
                let sc = scenario.as_mut().expect("scenario");
                let msg = decode_pool_message(f[1], &unhex(f[2]));
                let src: u64 = f[3].parse().expect("src");
                let hash = msg.mix_hash().expect("hash");
                sc.msgs.insert(hash.0, msg.clone());
                let res = sc.pool.accept_message(&msg, src);
                let want = lines.next().expect("res line");
                let got = match &res {
                    Ok(accepted) => {
                        let hashes = accepted
                            .iter()
                            .map(|m| format!("{}", m.mix_hash().expect("hash")))
                            .collect();
                        format!("res ok {}", csv_or_dash(hashes))
                    }
                    Err(err) => format!("res err {}", err_code(err)),
                };
                assert_eq!(got, want, "accept {} {}", f[1], hash);
                check_state!(sc, line);
                counts[0] += 1;
            }
            "expire" => {
                let sc = scenario.as_mut().expect("scenario");
                let height: u32 = f[1].parse().expect("height");
                sc.pool.expire_messages(height);
                check_state!(sc, line);
                counts[1] += 1;
            }
            "havemessage" => {
                let sc = scenario.as_ref().expect("scenario");
                let want: bool = f[2].parse().expect("bool");
                assert_eq!(sc.pool.have_message(&hash_from_str(f[1])), want, "{line}");
            }
            "message" => {
                let sc = scenario.as_ref().expect("scenario");
                let want_code = line.splitn(3, ' ').nth(2).unwrap_or("");
                let got = match sc.pool.message(&hash_from_str(f[1])) {
                    Ok(_) => String::new(),
                    Err(err) => err_code(&err),
                };
                assert_eq!(got, want_code, "{line}");
            }
            "recentmessage" => {
                let sc = scenario.as_mut().expect("scenario");
                let want: bool = f[2].parse().expect("bool");
                let got = sc.pool.recent_message(&hash_from_str(f[1])).is_some();
                assert_eq!(got, want, "{line}");
            }
            "receivekes" => {
                let sc = scenario.as_ref().expect("scenario");
                let pairing = unhex(f[1]);
                let epoch: u64 = f[2].parse().expect("epoch");
                let hashes = sc
                    .pool
                    .receive_kes_by_pairing(&pairing, epoch)
                    .iter()
                    .map(|ke| format!("{}", ke.mix_hash().expect("hash")))
                    .collect();
                assert_eq!(csv_or_dash(hashes), f[3], "{line}");
            }
            "compatibleprs" => {
                let sc = scenario.as_ref().expect("scenario");
                let pairing = unhex(f[1]);
                // Ordered output: do not re-sort.
                let hashes: Vec<String> = sc
                    .pool
                    .compatible_prs(&pairing)
                    .iter()
                    .map(|pr| format!("{}", pr.mix_hash().expect("hash")))
                    .collect();
                let got = if hashes.is_empty() {
                    "-".to_string()
                } else {
                    hashes.join(",")
                };
                assert_eq!(got, f[2], "{line}");
                counts[2] += 1;
            }
            "mixprs" => {
                let sc = scenario.as_mut().expect("scenario");
                let hashes = sc
                    .pool
                    .mix_prs()
                    .iter()
                    .map(|pr| format!("{}", pr.mix_hash().expect("hash")))
                    .collect();
                assert_eq!(csv_or_dash(hashes), f[1], "{line}");
            }
            "nonmix" => {
                let sc = scenario.as_ref().expect("scenario");
                let (tx, _) = MsgTx::from_bytes(&unhex(f[1])).expect("tx");
                let want: bool = f[2].parse().expect("bool");
                assert_eq!(sc.pool.non_mix_spends_pr(&tx), want, "{line}");
            }
            "removespentprs" => {
                let sc = scenario.as_mut().expect("scenario");
                let (tx, _) = MsgTx::from_bytes(&unhex(f[1])).expect("tx");
                sc.pool.remove_spent_prs(&[tx]);
                check_state!(sc, line);
                counts[3] += 1;
            }
            "removesession" => {
                let sc = scenario.as_mut().expect("scenario");
                sc.pool.remove_session(hash32_from_hex(f[1]));
                check_state!(sc, line);
            }
            "removemessage" => {
                let sc = scenario.as_mut().expect("scenario");
                let hash = hash_from_str(f[1]);
                let msg = sc.msgs.get(&hash.0).expect("recorded message").clone();
                sc.pool.remove_message(&msg).expect("remove message");
                check_state!(sc, line);
            }
            "removeconfirmedmixes" => {
                let sc = scenario.as_mut().expect("scenario");
                sc.pool.remove_confirmed_mixes(&[hash_from_str(f[1])]);
                check_state!(sc, line);
            }
            "removeconfirmedsessions" => {
                let sc = scenario.as_mut().expect("scenario");
                sc.pool.remove_confirmed_sessions();
                check_state!(sc, line);
            }
            "removeunresponsive" => {
                let sc = scenario.as_mut().expect("scenario");
                let epoch: u64 = f[1].parse().expect("epoch");
                let prs: Vec<_> = f[2]
                    .split(',')
                    .map(|h| sc.pr_by_hash(&hash_from_str(h)))
                    .collect();
                sc.pool.remove_unresponsive_during_epoch(&prs, epoch);
                check_state!(sc, line);
            }
            "receive" => {
                let sc = scenario.as_ref().expect("scenario");
                let sid = hash32_from_hex(f[1]);
                let kind = f[2];
                let want_code = line.splitn(4, ' ').nth(3).unwrap_or("");
                let mut r = match kind {
                    "all" => Received {
                        sid,
                        kes: Some(Vec::new()),
                        cts: Some(Vec::new()),
                        srs: Some(Vec::new()),
                        dcs: Some(Vec::new()),
                        cms: Some(Vec::new()),
                        fps: Some(Vec::new()),
                        rss: Some(Vec::new()),
                        receive_all: true,
                    },
                    "kes" | "unknown" => Received {
                        sid,
                        kes: Some(Vec::new()),
                        cts: None,
                        srs: None,
                        dcs: None,
                        cms: None,
                        fps: None,
                        rss: None,
                        receive_all: false,
                    },
                    "rss" => Received {
                        sid,
                        kes: None,
                        cts: None,
                        srs: None,
                        dcs: None,
                        cms: None,
                        fps: None,
                        rss: Some(Vec::new()),
                        receive_all: false,
                    },
                    "twocaps" => Received {
                        sid,
                        kes: Some(Vec::new()),
                        cts: Some(Vec::new()),
                        srs: None,
                        dcs: None,
                        cms: None,
                        fps: None,
                        rss: None,
                        receive_all: false,
                    },
                    other => panic!("unknown receive kind {other}"),
                };
                let got_code = match sc.pool.receive(&mut r) {
                    Ok(()) => String::new(),
                    Err(err) => err_code(&err),
                };
                assert_eq!(got_code, want_code, "{line}");

                let render = |hashes: Vec<String>| -> String { csv_or_dash(hashes) };
                let expect_rcv = |lines: &mut core::iter::Peekable<std::str::Lines<'_>>,
                                  tag: &str,
                                  got: String| {
                    let want = lines.next().expect("rcv line");
                    assert_eq!(format!("rcv{tag} {got}"), want, "{tag} for {}", f[1]);
                };
                expect_rcv(
                    &mut lines,
                    "kes",
                    render(
                        r.kes
                            .as_deref()
                            .unwrap_or_default()
                            .iter()
                            .map(|m| format!("{}", m.mix_hash().expect("hash")))
                            .collect(),
                    ),
                );
                expect_rcv(
                    &mut lines,
                    "cts",
                    render(
                        r.cts
                            .as_deref()
                            .unwrap_or_default()
                            .iter()
                            .map(|m| format!("{}", m.mix_hash().expect("hash")))
                            .collect(),
                    ),
                );
                expect_rcv(
                    &mut lines,
                    "srs",
                    render(
                        r.srs
                            .as_deref()
                            .unwrap_or_default()
                            .iter()
                            .map(|m| format!("{}", m.mix_hash().expect("hash")))
                            .collect(),
                    ),
                );
                expect_rcv(
                    &mut lines,
                    "dcs",
                    render(
                        r.dcs
                            .as_deref()
                            .unwrap_or_default()
                            .iter()
                            .map(|m| format!("{}", m.mix_hash().expect("hash")))
                            .collect(),
                    ),
                );
                expect_rcv(
                    &mut lines,
                    "cms",
                    render(
                        r.cms
                            .as_deref()
                            .unwrap_or_default()
                            .iter()
                            .map(|m| format!("{}", m.mix_hash().expect("hash")))
                            .collect(),
                    ),
                );
                expect_rcv(
                    &mut lines,
                    "fps",
                    render(
                        r.fps
                            .as_deref()
                            .unwrap_or_default()
                            .iter()
                            .map(|m| format!("{}", m.mix_hash().expect("hash")))
                            .collect(),
                    ),
                );
                expect_rcv(
                    &mut lines,
                    "rss",
                    render(
                        r.rss
                            .as_deref()
                            .unwrap_or_default()
                            .iter()
                            .map(|m| format!("{}", m.mix_hash().expect("hash")))
                            .collect(),
                    ),
                );
                counts[4] += 1;
            }
            "checkprevepoch" => {
                let sc = scenario.as_mut().expect("scenario");
                let epoch: u64 = f[1].parse().expect("epoch");
                sc.pool.check_prev_epoch(epoch).expect("check prev epoch");
                let want = lines.next().expect("strikes line");
                assert_eq!(sc.render_strikes(), want, "{line}");
                counts[5] += 1;
            }
            "strikes" => {
                let sc = scenario.as_ref().expect("scenario");
                assert_eq!(sc.render_strikes(), line, "standalone strikes");
            }
            "misbehavingtx" => {
                let sc = scenario.as_ref().expect("scenario");
                let (tx, _) = MsgTx::from_bytes(&unhex(f[1])).expect("tx");
                let want: bool = f[2].parse().expect("bool");
                assert_eq!(sc.pool.misbehaving_tx(&tx), want, "{line}");
            }
            "excludeprs" => {
                let sc = scenario.as_ref().expect("scenario");
                let inputs: Vec<_> = f[1]
                    .split(',')
                    .map(|h| sc.pr_by_hash(&hash_from_str(h)))
                    .collect();
                let excluded = sc
                    .pool
                    .exclude_prs(&inputs)
                    .iter()
                    .map(|pr| format!("{}", pr.mix_hash().expect("hash")))
                    .collect();
                assert_eq!(csv_or_dash(excluded), f[2], "{line}");
            }
            "done" => break,
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [110, 3, 1, 2, 6, 2], "row counts");
}
