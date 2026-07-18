// SPDX-License-Identifier: ISC
//! Differential replay of dcrd `internal/connmgr` behavior vectors.
//!
//! The vectors were dumped by a throwaway white-box exporter run
//! inside the dcrd clone at master 452c1a6c (the 2.2 parity target),
//! driving dcrd's real `ConnManager` with a stub dialer and a
//! scripted csprng: the New() defaults and backoff scaling-bit
//! derivation (including the upstream overflow when a 1ns retry
//! duration shifts by the full 63 bits, which the wrapping port
//! reproduces), the Connect/AddPersistent/Disconnect/Remove state
//! machine with map sizes and semaphore counts after every step,
//! `pickOutboundAddr` acceptance/exhaustion counts, the outbound and
//! inbound group hashes under fixed SipHash keys (with the flood
//! coarsening collapse), a 90-row probe ladder over the S-curve drop
//! probability, and the flood-window advance mechanics captured at a
//! second-stable wall instant replayed at the same absolute second.
//!
//! The Connect rows replay through the port's split entry points
//! (`connect_begin` → `begin_dial` → `dial_succeeded` →
//! `conn_closed`), which is the same decision sequence dcrd runs
//! inside `Connect`/`dial` with the socket work removed.

use dcroxide_addrmgr::{NetAddress, NetAddressType, new_net_address_from_params};
use dcroxide_connmgr::manager::{
    ClosePlan, ConnManager, DisconnectAction, ManagerConfig, NO_SUITABLE_ADDR_MSG,
};
use dcroxide_connmgr::{
    ConnectionType, Csprng, InboundRateLimiter, OutboundGroupInfo, conn_type_string,
};
use dcroxide_wire::ServiceFlag;

/// A csprng returning scripted values at the interface level and
/// recording the bounds passed to `uint64n`, like the exporter's.
#[derive(Default)]
struct ScriptedRng {
    u64s: Vec<u64>,
    u64ns: Vec<u64>,
    f64s: Vec<f64>,
    last_n: Vec<u64>,
}

impl Csprng for ScriptedRng {
    fn uint64(&mut self) -> u64 {
        self.u64s.remove(0)
    }
    fn uint64n(&mut self, n: u64) -> u64 {
        self.last_n.push(n);
        self.u64ns.remove(0)
    }
    fn float64(&mut self) -> f64 {
        self.f64s.remove(0)
    }
}

fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> NetAddress {
    new_net_address_from_params(NetAddressType::IPv4, &[a, b, c, d], port, 0, ServiceFlag(0))
        .expect("v4 addr")
}

fn v6(bytes: [u8; 16], port: u16) -> NetAddress {
    new_net_address_from_params(NetAddressType::IPv6, &bytes, port, 0, ServiceFlag(0))
        .expect("v6 addr")
}

fn mgr(max_normal: u32, max_per_host: u32, whitelisted_192_0_2: bool) -> ConnManager {
    let mut rng = ScriptedRng {
        u64s: vec![11, 22, 33, 44],
        ..ScriptedRng::default()
    };
    ConnManager::new(
        ManagerConfig {
            max_normal_conns: max_normal,
            max_conns_per_host: max_per_host,
            is_whitelisted: if whitelisted_192_0_2 {
                Box::new(|addr: &NetAddress| addr.ip.starts_with(&[192, 0, 2]))
            } else {
                Box::new(|_| false)
            },
            ..ManagerConfig::default()
        },
        &mut rng,
    )
}

fn mgr_with_retry(retry_nanos: i64) -> ConnManager {
    let mut rng = ScriptedRng {
        u64s: vec![11, 22, 33, 44],
        ..ScriptedRng::default()
    };
    ConnManager::new(
        ManagerConfig {
            retry_duration_nanos: retry_nanos,
            ..ManagerConfig::default()
        },
        &mut rng,
    )
}

/// A tiny expectation of a manager's shared state against the
/// exporter's `sizes` field: `p,pend,act,idbyaddr,perhost|sems=T,O`.
fn assert_sizes(m: &ConnManager, want: &str, tag: &str) {
    let (p, pend, act, byaddr, perhost) = m.map_sizes();
    let got = format!(
        "{},{},{},{},{}|sems={},{}",
        p,
        pend,
        act,
        byaddr,
        perhost,
        m.total_normal_conns_sem.used(),
        m.active_outbounds_sem.used(),
    );
    assert_eq!(got, want, "{tag}: state sizes");
}

/// Replay `Connect` through the split port entry points, returning
/// the exporter's error string plus the assigned ID on success.
fn replay_connect(m: &mut ConnManager, addr: &NetAddress) -> (String, Option<u64>) {
    let plan = match m.connect_begin(addr) {
        Ok(plan) => plan,
        Err(e) => return (format!("{}:{}", e.kind.kind_name(), e.description), None),
    };
    let id = match m.begin_dial(addr, None) {
        Ok(id) => id,
        Err(e) => {
            m.connect_unwind(addr, &plan);
            return (format!("{}:{}", e.kind.kind_name(), e.description), None);
        }
    };
    let record = m
        .dial_succeeded(id, addr, ConnectionType::Manual, plan)
        .expect("stub dial success is never canceled");
    ("ok".to_string(), Some(record.id))
}

#[test]
fn dcrd_connmgr_v2_vectors() {
    let data = include_str!("data/connmgr_v2_vectors.txt");
    let mut rows = 0usize;

    // Managers for the multi-row scenarios, matched to the exporter's.
    let mut cm_a: Option<ConnManager> = None;
    let mut a_first_id = 0u64;
    let mut cm_b: Option<ConnManager> = None;
    let mut cm_c: Option<ConnManager> = None;
    let mut c_pid = 0u64;
    let mut cm_d: Option<ConnManager> = None;
    let mut e2_call_count = 0usize;

    for (lineno, line) in data.lines().enumerate() {
        let lineno = lineno + 1;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split('|').collect();
        match f[0] {
            "scalingbits" => {
                let retry: i64 = f[1].parse().expect("retry");
                let bits: u8 = f[2].parse().expect("bits");
                let target: u32 = f[3].parse().expect("target");
                let max_normal: u32 = f[4].parse().expect("max");
                let m = if target == 3 {
                    // The forced-down row: TargetOutbound 9 vs
                    // MaxNormalConns 3.
                    let mut rng = ScriptedRng {
                        u64s: vec![1, 2, 3, 4],
                        ..ScriptedRng::default()
                    };
                    ConnManager::new(
                        ManagerConfig {
                            max_normal_conns: 3,
                            target_outbound: 9,
                            ..ManagerConfig::default()
                        },
                        &mut rng,
                    )
                } else {
                    mgr_with_retry(retry)
                };
                assert_eq!(
                    m.max_retry_scaling_bits_snapshot(),
                    bits,
                    "line {lineno}: scaling bits for retry {retry}"
                );
                assert_eq!(m.target_outbound(), target, "line {lineno}: target");
                assert_eq!(m.max_normal_conns(), max_normal, "line {lineno}: max");
                rows += 1;
            }
            "backoff" => {
                let retry: i64 = f[1].parse().expect("retry");
                let retries: u32 = f[2].parse().expect("retries");
                let jitter: u64 = f[3].parse().expect("jitter");
                let want_n: u64 = f[4].parse().expect("n");
                let want: i64 = f[5].parse().expect("result");
                let m = mgr_with_retry(retry);
                let mut rng = ScriptedRng {
                    u64ns: vec![jitter],
                    ..ScriptedRng::default()
                };
                let got = m.backoff_with_jitter(retries, &mut rng);
                assert_eq!(got, want, "line {lineno}: backoff({retry}, {retries})");
                let got_n = rng.last_n.first().copied().unwrap_or(0);
                assert_eq!(got_n, want_n, "line {lineno}: jitter bound");
                rows += 1;
            }
            "conntype" => {
                let raw: u8 = f[1].parse().expect("raw");
                assert_eq!(conn_type_string(raw), f[2], "line {lineno}: conntype");
                rows += 1;
            }
            "connect" => {
                let tag = f[1];
                let want_err = f[2];
                let want_sizes = format!("{}|{}", f[3], f[4]);
                let (m, addr) = match tag {
                    "A1" | "A2" | "A6" => {
                        if cm_a.is_none() {
                            cm_a = Some(mgr(2, 0, false));
                        }
                        (cm_a.as_mut().expect("A"), v4(192, 0, 2, 10, 9108))
                    }
                    "A3" => (cm_a.as_mut().expect("A"), v4(192, 0, 2, 11, 9108)),
                    "A4" => (cm_a.as_mut().expect("A"), v4(192, 0, 2, 12, 9108)),
                    "B1" | "B2" | "B3" => {
                        if cm_b.is_none() {
                            cm_b = Some(mgr(0, 2, true));
                        }
                        let port = 7000 + (tag[1..].parse::<u16>().expect("b idx") - 1);
                        (cm_b.as_mut().expect("B"), v4(203, 0, 113, 5, port))
                    }
                    "B4-wl" => (cm_b.as_mut().expect("B"), v4(192, 0, 2, 5, 7100)),
                    "B5-wl" => (cm_b.as_mut().expect("B"), v4(192, 0, 2, 5, 7101)),
                    "B6-wl" => (cm_b.as_mut().expect("B"), v4(192, 0, 2, 5, 7102)),
                    "B7-lo" | "B8-lo" | "B9-lo" => {
                        let idx: u16 = tag[1..2].parse().expect("lo idx");
                        (
                            cm_b.as_mut().expect("B"),
                            v4(127, 0, 0, 1, 7200 + (idx - 7)),
                        )
                    }
                    "C3" => (cm_c.as_mut().expect("C"), v4(198, 51, 100, 7, 9108)),
                    other => panic!("line {lineno}: unknown connect tag {other}"),
                };
                let (got_err, got_id) = replay_connect(m, &addr);
                assert_eq!(got_err, want_err, "line {lineno}: connect {tag}");
                assert_sizes(m, &want_sizes, &format!("line {lineno}: connect {tag}"));
                if tag == "A1" {
                    a_first_id = got_id.expect("A1 succeeds");
                }
                rows += 1;
            }
            "connid" => {
                let want_id: u64 = f[2].parse().expect("id");
                assert_eq!(a_first_id, want_id, "line {lineno}: first conn id");
                let record = cm_a
                    .as_ref()
                    .expect("A")
                    .active_conn(want_id)
                    .expect("still active");
                assert_eq!(record.conn_type.to_string(), f[3], "line {lineno}: type");
                rows += 1;
            }
            "close" => {
                let want_sizes = format!("{}|{}", f[2], f[3]);
                let m = cm_a.as_mut().expect("A");
                m.conn_closed(a_first_id).expect("close A1");
                assert_sizes(m, &want_sizes, &format!("line {lineno}: close"));
                rows += 1;
            }
            "addpers" => {
                let tag = f[1];
                let want_err = f[3];
                let want_sizes = format!("{}|{}", f[4], f[5]);
                let (m, addr) = match tag {
                    "C1" | "C2" => {
                        if cm_c.is_none() {
                            cm_c = Some(mgr(0, 2, false));
                        }
                        (cm_c.as_mut().expect("C"), v4(198, 51, 100, 7, 9108))
                    }
                    "C4" => (cm_c.as_mut().expect("C"), v4(198, 51, 100, 7, 9109)),
                    "C5" => (cm_c.as_mut().expect("C"), v4(198, 51, 100, 7, 9110)),
                    "D1" => {
                        if cm_d.is_none() {
                            let mut m = mgr(0, 0, false);
                            for i in 0..8u8 {
                                m.add_persistent(&v4(198, 51, 100, 20 + i, 9108))
                                    .expect("persistent fits");
                            }
                            cm_d = Some(m);
                        }
                        (cm_d.as_mut().expect("D"), v4(198, 51, 100, 99, 9108))
                    }
                    other => panic!("line {lineno}: unknown addpers tag {other}"),
                };
                // dcrd checks capacity before conversion; the replay's
                // addresses are pre-converted so the combined call
                // covers the same order.
                let res = m.add_persistent(&addr);
                let got = match &res {
                    Ok(id) => {
                        if tag == "C1" {
                            c_pid = *id;
                            assert_eq!(f[2].parse::<u64>().expect("pid"), *id, "line {lineno}");
                        }
                        "ok".to_string()
                    }
                    Err(e) => format!("{}:{}", e.kind.kind_name(), e.description),
                };
                assert_eq!(got, want_err, "line {lineno}: addpers {tag}");
                assert_sizes(m, &want_sizes, &format!("line {lineno}: addpers {tag}"));
                rows += 1;
            }
            "dial" => {
                // C6/C8: the persistent re-dial with the entry ID.
                let want_err = f[2];
                let want_sizes = format!("{}|{}", f[3], f[4]);
                let m = cm_c.as_mut().expect("C");
                let addr = v4(198, 51, 100, 7, 9108);
                let got = match m.begin_dial(&addr, Some(c_pid)) {
                    Ok(id) => {
                        m.dial_succeeded(id, &addr, ConnectionType::Manual, ClosePlan::default())
                            .expect("stub success");
                        "ok".to_string()
                    }
                    Err(e) => format!("{}:{}", e.kind.kind_name(), e.description),
                };
                assert_eq!(got, want_err, "line {lineno}: dial {}", f[1]);
                assert_sizes(m, &want_sizes, &format!("line {lineno}: dial {}", f[1]));
                rows += 1;
            }
            "discon" => {
                let tag = f[1];
                let m = cm_c.as_mut().expect("C");
                if tag == "C7" {
                    let want_sizes = format!("{}|{}", f[4], f[5]);
                    let action = m.disconnect(c_pid).expect("disconnect");
                    assert!(
                        matches!(action, DisconnectAction::CloseConn),
                        "line {lineno}"
                    );
                    m.conn_closed(c_pid).expect("close");
                    assert_eq!(f[2], "ok", "line {lineno}");
                    assert_eq!(
                        m.is_persistent(c_pid).to_string(),
                        f[3],
                        "line {lineno}: still persistent"
                    );
                    assert_sizes(m, &want_sizes, &format!("line {lineno}: discon"));
                } else {
                    // C12: unknown id.
                    let want_sizes = format!("{}|{}", f[3], f[4]);
                    let err = m.disconnect(12345).expect_err("unknown id");
                    assert_eq!(
                        format!("{}:{}", err.kind.kind_name(), err.description),
                        f[2],
                        "line {lineno}: discon {tag}"
                    );
                    assert_sizes(m, &want_sizes, &format!("line {lineno}: discon {tag}"));
                }
                rows += 1;
            }
            "remove" => {
                let tag = f[1];
                let m = cm_c.as_mut().expect("C");
                if tag == "C9" {
                    let want_sizes = format!("{}|{}", f[4], f[5]);
                    let action = m.remove(c_pid).expect("remove");
                    match action {
                        DisconnectAction::CancelPersistentAndClose(rec) => {
                            m.run_close_plan(&rec);
                        }
                        other => panic!("line {lineno}: unexpected action {other:?}"),
                    }
                    assert_eq!(f[2], "ok", "line {lineno}");
                    assert_eq!(m.is_persistent(c_pid).to_string(), f[3], "line {lineno}");
                    assert_sizes(m, &want_sizes, &format!("line {lineno}: remove"));
                } else {
                    // C11: already removed.
                    let want_sizes = format!("{}|{}", f[3], f[4]);
                    let err = m.remove(c_pid).expect_err("already removed");
                    assert_eq!(
                        format!("{}:{}", err.kind.kind_name(), err.description),
                        f[2],
                        "line {lineno}: remove {tag}"
                    );
                    assert_sizes(m, &want_sizes, &format!("line {lineno}: remove {tag}"));
                }
                rows += 1;
            }
            "postremove" => {
                let want_sizes = format!("{}|{}", f[2], f[3]);
                assert_sizes(
                    cm_c.as_ref().expect("C"),
                    &want_sizes,
                    &format!("line {lineno}: postremove"),
                );
                rows += 1;
            }
            "pick" => {
                let tag = f[1];
                let now_nanos = 1_700_000_000_000_000_000i64;
                let now_secs = 1_700_000_000i64;
                let old = (now_secs - 660) * 1_000_000_000;
                let recent = (now_secs - 60) * 1_000_000_000;
                match tag {
                    "E1" => {
                        let mut rng = ScriptedRng {
                            u64s: vec![11, 22, 33, 44],
                            ..ScriptedRng::default()
                        };
                        let mut m = ConnManager::new(
                            ManagerConfig {
                                default_port: 9108,
                                ..ManagerConfig::default()
                            },
                            &mut rng,
                        );
                        let feed = [
                            (v4(192, 0, 2, 1, 19108), old),
                            (v4(192, 0, 2, 2, 9108), recent),
                            (v4(192, 0, 2, 3, 9108), old),
                        ];
                        let mut idx = 0usize;
                        let picked = m
                            .pick_outbound_addr(
                                &mut || {
                                    let row = &feed[idx % feed.len()];
                                    idx += 1;
                                    Ok((row.0.clone(), row.1))
                                },
                                now_nanos,
                            )
                            .expect("E1 picks");
                        assert_eq!(picked.key(), f[3], "line {lineno}: E1 pick");
                        assert_eq!(idx.to_string(), f[4], "line {lineno}: E1 calls");
                        // E2 continues on the same manager: the
                        // picked group is now full.
                        let mut idx2 = 0usize;
                        let err = m
                            .pick_outbound_addr(
                                &mut || {
                                    idx2 += 1;
                                    Ok((v4(192, 0, 2, 200, 9108), old))
                                },
                                now_nanos,
                            )
                            .expect_err("E2 exhausts");
                        assert_eq!(err, NO_SUITABLE_ADDR_MSG, "line {lineno}: E2 error");
                        // The E2 row's own fields are checked when it
                        // arrives; stash the count.
                        e2_call_count = idx2;
                    }
                    "E2" => {
                        assert_eq!(
                            f[2],
                            format!("plain:{NO_SUITABLE_ADDR_MSG}"),
                            "line {lineno}: E2 error field"
                        );
                        assert_eq!(
                            e2_call_count.to_string(),
                            f[3],
                            "line {lineno}: E2 call count"
                        );
                    }
                    "F1" | "G1" => {
                        let mut rng = ScriptedRng {
                            u64s: vec![11, 22, 33, 44],
                            ..ScriptedRng::default()
                        };
                        let mut m = ConnManager::new(
                            ManagerConfig {
                                default_port: 9108,
                                ..ManagerConfig::default()
                            },
                            &mut rng,
                        );
                        let (addr, last) = if tag == "F1" {
                            (v4(203, 0, 113, 9, 19108), old)
                        } else {
                            (v4(203, 0, 113, 10, 9108), recent)
                        };
                        let mut calls = 0usize;
                        let picked = m
                            .pick_outbound_addr(
                                &mut || {
                                    calls += 1;
                                    Ok((addr.clone(), last))
                                },
                                now_nanos,
                            )
                            .expect("picks");
                        assert_eq!(picked.key(), f[3], "line {lineno}: {tag} pick");
                        assert_eq!(calls.to_string(), f[4], "line {lineno}: {tag} calls");
                    }
                    "H1" => {
                        let mut m = mgr(0, 0, false);
                        let err = m
                            .pick_outbound_addr(
                                &mut || Err("no valid connect address".to_string()),
                                now_nanos,
                            )
                            .expect_err("source error");
                        assert_eq!(
                            format!("plain:{err}"),
                            f[2],
                            "line {lineno}: H1 passthrough"
                        );
                    }
                    other => panic!("line {lineno}: unknown pick tag {other}"),
                }
                rows += 1;
            }
            "ogroup" => {
                let og = OutboundGroupInfo::with_key([0x0706050403020100, 0x0f0e0d0c0b0a0908]);
                let addr = addr_from_key(f[1]);
                assert_eq!(addr.key(), f[1], "line {lineno}: addr round-trip");
                assert_eq!(addr.group_key(), f[2], "line {lineno}: addrmgr group key");
                let want = u64::from_str_radix(f[3], 16).expect("hash");
                assert_eq!(og.group_key(&addr), want, "line {lineno}: outbound hash");
                rows += 1;
            }
            "ingroup" => {
                let mut il = InboundRateLimiter::with_key_and_capacity(
                    [0x0706050403020100, 0x0f0e0d0c0b0a0908],
                    16,
                );
                let flooding: bool = f[2].parse().expect("flooding");
                il.force_flood_state(0, &[], 0, flooding);
                let addr = addr_from_key(f[1]);
                let key = il.group_key(&addr);
                let want0 = u64::from_str_radix(f[3], 16).expect("h0");
                let want1 = u64::from_str_radix(f[4], 16).expect("h1");
                assert_eq!(
                    (key.hash0, key.hash1),
                    (want0, want1),
                    "line {lineno}: inbound group {} flooding {flooding}",
                    f[1],
                );
                rows += 1;
            }
            "sdp" => {
                let total: u64 = f[1].parse().expect("total");
                let bits = u64::from_str_radix(f[2], 16).expect("bits");
                let want: bool = f[3].parse().expect("decision");
                let mut il = InboundRateLimiter::with_key_and_capacity([1, 2], 16);
                il.force_flood_state(0, &[], total, true);
                let mut rng = ScriptedRng {
                    f64s: vec![f64::from_bits(bits)],
                    ..ScriptedRng::default()
                };
                let got = il.should_drop_probabilistic(&mut rng);
                assert_eq!(
                    got, want,
                    "line {lineno}: sdp total {total} bits {bits:016x}"
                );
                rows += 1;
            }
            "sdp-noflood" => {
                let mut il = InboundRateLimiter::with_key_and_capacity([1, 2], 16);
                il.force_flood_state(0, &[], 5000, false);
                let mut rng = ScriptedRng::default();
                assert!(
                    !il.should_drop_probabilistic(&mut rng),
                    "line {lineno}: no draw when not flooding"
                );
                rows += 1;
            }
            "window" => {
                // window|wi|now|startDelta|rateLimited|nonzero|total|flooding
                let now: i64 = f[2].parse().expect("now");
                let start_delta: i64 = f[3].parse().expect("delta");
                let rate_limited: bool = f[4].parse().expect("limited");
                let want_total: u64 = f[6].parse().expect("total");
                let want_flooding: bool = f[7].parse().expect("flooding");
                let wi: usize = f[1].parse().expect("wi");
                // The exporter's pre-state per scenario index.
                let pre: (&[(i64, u32)], u64) = match wi {
                    0 => (&[], 0),
                    1 => (&[], 0),
                    2 => (&[(-5, 7), (-4, 8), (-3, 9)], 24),
                    3 => (&[(-59, 100), (-1, 250)], 350),
                    4 => (&[(-60, 9), (-30, 9)], 18),
                    5 => (&[(-1, 400)], 400),
                    6 => (&[(0, 3)], 3),
                    7 => (&[(-1, 200), (0, 150)], 350),
                    other => panic!("line {lineno}: unknown window scenario {other}"),
                };
                let mut il = InboundRateLimiter::with_key_and_capacity([1, 2], 16);
                let entries: Vec<(usize, u32)> = pre
                    .0
                    .iter()
                    .map(|&(d, v)| (usize::try_from(((now + d) % 60 + 60) % 60).expect("idx"), v))
                    .collect();
                il.force_flood_state(now - start_delta, &entries, pre.1, false);
                il.record_attempt_probe(rate_limited, now);
                let (start, nonzero, total, flooding) = il.window_snapshot();
                assert_eq!(start, now, "line {lineno}: window head");
                assert_eq!(total, want_total, "line {lineno}: window total");
                assert_eq!(flooding, want_flooding, "line {lineno}: window flooding");
                let got: Vec<String> = nonzero.iter().map(|(i, v)| format!("{i}:{v}")).collect();
                assert_eq!(got.join(","), f[5], "line {lineno}: window buckets");
                rows += 1;
            }
            other => panic!("line {lineno}: unknown section {other}"),
        }
    }
    assert!(rows > 160, "suspiciously few vector rows: {rows}");
}

/// Rebuild a NetAddress from the exporter's `Key()` rendering.
// Test-only parsing of fixed vector literals; index arithmetic is
// bounded by the literal shapes.
#[allow(clippy::arithmetic_side_effects)]
fn addr_from_key(key: &str) -> NetAddress {
    if let Some(rest) = key.strip_prefix('[') {
        // [v6]:port
        let end = rest.find(']').expect("bracket");
        let host = &rest[..end];
        let port: u16 = rest[end + 2..].parse().expect("port");
        let ip = parse_v6(host);
        return v6(ip, port);
    }
    let (host, port) = key.rsplit_once(':').expect("host:port");
    let port: u16 = port.parse().expect("port");
    let parts: Vec<u8> = host.split('.').map(|p| p.parse().expect("octet")).collect();
    v4(parts[0], parts[1], parts[2], parts[3], port)
}

/// A minimal RFC 4291 parser for the exporter's fixed v6 literals.
#[allow(clippy::arithmetic_side_effects)]
fn parse_v6(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    let (head, tail) = match s.split_once("::") {
        Some((h, t)) => (h, Some(t)),
        None => (s, None),
    };
    let head_groups: Vec<u16> = head
        .split(':')
        .filter(|g| !g.is_empty())
        .map(|g| u16::from_str_radix(g, 16).expect("group"))
        .collect();
    for (i, g) in head_groups.iter().enumerate() {
        out[i * 2..i * 2 + 2].copy_from_slice(&g.to_be_bytes());
    }
    if let Some(tail) = tail {
        let tail_groups: Vec<u16> = tail
            .split(':')
            .filter(|g| !g.is_empty())
            .map(|g| u16::from_str_radix(g, 16).expect("group"))
            .collect();
        let start = 16 - tail_groups.len() * 2;
        for (i, g) in tail_groups.iter().enumerate() {
            out[start + i * 2..start + i * 2 + 2].copy_from_slice(&g.to_be_bytes());
        }
    }
    out
}
