// SPDX-License-Identifier: ISC
//! Replay of the frozen HTTPS-seeder and Tor-DNS vectors, generated
//! by an in-package dump test inside dcrd's connmgr package at
//! release-v2.1.5 and relocated here alongside dcrd 2.2's move of
//! `seed.go` and `tordns.go` into addrmgr.  The relocated Go sources
//! are byte-identical apart from the package rename, so the rows
//! remain authoritative; the one behavioral consequence — the
//! reflected JSON node type in decode errors now reads
//! `addrmgr.node` — is applied to the affected row.
//!
//! The tor rows replay scripted SOCKS exchanges including the request
//! bytes dcrd sent; the seed rows pin the host acceptance matrix, the
//! streaming JSON parse, and the request URL construction.

// Test scaffolding uses bounded counters and mock plumbing.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_addrmgr::{
    HttpsSeederFilters, SeedEnv, SeederTransport, TorTransport, seed_addrs, seeder_url,
    tor_lookup_ip,
};
use dcroxide_testutil::unhex;
use std::collections::HashMap;

const VECTORS: &str = include_str!("data/seed_tor_vectors.txt");

fn utf8(hex: &str) -> String {
    String::from_utf8(unhex(hex)).expect("utf8 payload")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A scripted SOCKS transport: replies are consumed in write-sized
/// chunks matching the dump's server script, and everything written
/// is recorded.
struct ScriptedTor {
    written: Vec<u8>,
    replies: Vec<Vec<u8>>,
    next: usize,
}

impl ScriptedTor {
    fn new(replies: Vec<Vec<u8>>) -> ScriptedTor {
        ScriptedTor {
            written: Vec::new(),
            replies,
            next: 0,
        }
    }
}

impl TorTransport for ScriptedTor {
    fn write(&mut self, data: &[u8]) -> Result<(), dcroxide_addrmgr::AddrError> {
        self.written.extend_from_slice(data);
        Ok(())
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, dcroxide_addrmgr::AddrError> {
        let reply = self.replies.get(self.next).cloned().unwrap_or_default();
        self.next += 1;
        let n = reply.len().min(buf.len());
        buf[..n].copy_from_slice(&reply[..n]);
        Ok(n)
    }
}

/// The scripted replies for each tor row label, mirroring the dump's
/// fake proxy.  The auth acknowledgement is always the first reply.
fn tor_script(label: &str) -> Vec<Vec<u8>> {
    let auth = vec![0x05, 0x00];
    let mut replies = vec![auth];
    match label {
        "ok-v4" => {
            replies.push(vec![5, 0, 0, 1]);
            replies.push(vec![192, 0, 2, 33, 0x23, 0x8d]);
        }
        "ok-v6" => {
            replies.push(vec![5, 0, 0, 4]);
            let mut ip = unhex("20010db8000000000000000000000068");
            ip.extend_from_slice(&[0x23, 0x8d]);
            replies.push(ip);
        }
        "v6-odd-len" => {
            replies.push(vec![5, 0, 0, 4]);
            replies.push(vec![1, 2, 3, 4, 5, 6, 7, 8, 0, 0]);
        }
        "v6-too-short" => {
            replies.push(vec![5, 0, 0, 4]);
            replies.push(vec![1, 2, 3, 4, 0, 0]);
        }
        "v4-wrong-len" => {
            replies.push(vec![5, 0, 0, 1]);
            replies.push(vec![1, 2, 3, 0, 0]);
        }
        "bad-atype" => replies.push(vec![5, 0, 0, 3]),
        "unknown-status" => replies.push(vec![5, 0x99, 0, 1]),
        _ => {
            let status: u8 = label
                .strip_prefix("status-")
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| panic!("unknown tor label {label}"));
            replies.push(vec![5, status, 0, 1]);
        }
    }
    replies
}

struct ScriptedSeeder {
    status: u32,
    body: Vec<u8>,
    url: Option<String>,
}

impl SeederTransport for ScriptedSeeder {
    fn get(&mut self, url: &str) -> Result<(u32, Vec<u8>), String> {
        self.url = Some(url.to_string());
        Ok((self.status, self.body.clone()))
    }
}

struct FixedEnv;

impl SeedEnv for FixedEnv {
    fn now_nanos(&mut self) -> i64 {
        1_700_000_000 * 1_000_000_000
    }

    fn rand_duration(&mut self, _max: i64) -> i64 {
        0
    }
}

/// The JSON payloads for each seedjson row label, mirroring the dump.
fn seed_payload(label: &str) -> String {
    match label {
        "two" => concat!(
            r#"{"host":"1.2.3.4:9108","services":13,"pver":10}"#,
            r#"{"host":"[2001:db8::68]:9108","services":5,"pver":11}"#
        )
        .to_string(),
        "whitespace" => " {\"host\":\"1.2.3.4:9108\",\"services\":13,\"pver\":10} \n {\"host\":\"5.6.7.8:9108\",\"services\":1,\"pver\":9} ".to_string(),
        "empty" => String::new(),
        "unknown-fields" => {
            r#"{"host":"1.2.3.4:9108","bogus":true,"services":13,"pver":10,"extra":"x"}"#
                .to_string()
        }
        "case-fold" => r#"{"HOST":"1.2.3.4:9108","Services":13,"PVER":10}"#.to_string(),
        "array" => r#"[{"host":"1.2.3.4:9108","services":13,"pver":10}]"#.to_string(),
        "truncated" => r#"{"host":"1.2.3.4:9108","services":13"#.to_string(),
        "bad-type" => r#"{"host":5,"services":13,"pver":10}"#.to_string(),
        "garbage" => "xyzzy".to_string(),
        "many" => (0..20)
            .map(|i| format!(r#"{{"host":"10.0.0.{i}:9108","services":{i},"pver":10}}"#))
            .collect(),
        "limited" => (0..40)
            .map(|i| {
                format!(
                    r#"{{"host":"10.0.0.{i}:9108","services":{i},"pver":10,"pad":"{}"}}"#,
                    "a".repeat(90)
                )
            })
            .collect(),
        "limited-truncated" => (0..10)
            .map(|i| {
                format!(
                    r#"{{"host":"10.0.0.{i}:9108","services":{i},"pver":10,"pad":"{}"}}"#,
                    "a".repeat(600)
                )
            })
            .collect(),
        other => panic!("unknown seedjson label {other}"),
    }
}

/// Run the streaming node parse the way `seed_addrs` does, but over a
/// payload whose nodes should be observed directly.  This goes
/// through the public API with hosts that never validate, so the
/// parse outcome is observed via a full call plus a parallel
/// hand-parse for the node list itself.
fn parse_nodes(payload: &str) -> Result<Vec<([u8; 16], u16, u64)>, String> {
    let mut transport = ScriptedSeeder {
        status: 200,
        body: payload.as_bytes().to_vec(),
        url: None,
    };
    let mut env = FixedEnv;
    let filters = HttpsSeederFilters::default();
    let addrs = seed_addrs("seed.example.org", &mut transport, &mut env, &filters)?;
    Ok(addrs.iter().map(|a| (a.ip, a.port, a.services.0)).collect())
}

#[test]
fn seed_tor_vectors() {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for line in VECTORS.lines() {
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('|').collect();
        *counts.entry(parts[0]).or_insert(0) += 1;
        match parts[0] {
            "tor" => {
                let mut transport = ScriptedTor::new(tor_script(parts[1]));
                let result = tor_lookup_ip("dcrd.example.org", &mut transport);
                assert_eq!(hex(&transport.written), parts[2], "request for {line}");
                match result {
                    Ok(ips) => {
                        assert_eq!(parts[3], "ok", "{line}");
                        let joined: Vec<String> = ips.iter().map(|ip| hex(ip)).collect();
                        assert_eq!(joined.join(","), parts[4], "{line}");
                    }
                    Err(err) => {
                        assert_eq!(parts[3], "err", "{line}");
                        assert_eq!(err.kind.kind_name(), parts[4], "{line}");
                        assert_eq!(err.description, utf8(parts[5]), "{line}");
                    }
                }
            }
            "torauth" => {
                let first = match parts[1] {
                    "bad-proxy-version" => vec![0x04, 0x00],
                    "bad-auth-method" => vec![0x05, 0x02],
                    other => panic!("unknown torauth label {other}"),
                };
                let mut transport = ScriptedTor::new(vec![first]);
                let err = tor_lookup_ip("dcrd.example.org", &mut transport)
                    .expect_err("expected auth failure");
                assert_eq!(err.kind.kind_name(), parts[2], "{line}");
                assert_eq!(err.description, utf8(parts[3]), "{line}");
            }
            "seedhost" => {
                let host_port = utf8(parts[1]);
                let payload = format!("{{\"host\":{:?},\"services\":13,\"pver\":10}}", host_port);
                let nodes = parse_nodes(&payload).unwrap_or_else(|e| panic!("{line}: {e}"));
                if parts[2] == "ok" {
                    assert_eq!(nodes.len(), 1, "{line}");
                    assert_eq!(hex(&nodes[0].0), parts[3], "{line}");
                    let want_port: u16 = parts[4].parse().unwrap();
                    assert_eq!(nodes[0].1, want_port, "{line}");
                } else {
                    // The host fails one of the conversion steps and
                    // the address is skipped.
                    assert!(nodes.is_empty(), "{line}");
                }
            }
            "seedjson" => {
                let payload = seed_payload(parts[1]);
                match parse_nodes(&payload) {
                    Ok(nodes) => {
                        assert_eq!(parts[2], "ok", "{line}");
                        let want_count: usize = parts[3].parse().unwrap();
                        // Hosts that fail validation are dropped from
                        // the address list; every payload here uses
                        // valid IP hosts, so the counts line up.
                        assert_eq!(nodes.len(), want_count, "{line}");
                    }
                    Err(err) => {
                        assert_eq!(parts[2], "err", "{line}");
                        assert_eq!(err, utf8(parts[3]), "{line}");
                    }
                }
            }
            "seedurl" => {
                let filters = match parts[1] {
                    "none" => HttpsSeederFilters::default(),
                    "ipv4" => HttpsSeederFilters::default().ip_version(4),
                    "all" => HttpsSeederFilters::default()
                        .ip_version(6)
                        .protocol_version(10)
                        .services(13),
                    "services" => HttpsSeederFilters::default().services(1),
                    other => panic!("unknown seedurl label {other}"),
                };
                assert_eq!(
                    seeder_url("seed.example.org", &filters),
                    utf8(parts[2]),
                    "{line}"
                );
            }
            other => panic!("unknown vector op {other}"),
        }
    }

    let expected: &[(&str, usize)] = &[
        ("tor", 15),
        ("torauth", 2),
        ("seedhost", 15),
        ("seedjson", 12),
        ("seedurl", 4),
    ];
    for (op, want) in expected {
        assert_eq!(counts.get(op), Some(want), "row count for {op}");
    }
}
