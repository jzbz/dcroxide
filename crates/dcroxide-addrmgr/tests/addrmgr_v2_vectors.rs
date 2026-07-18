// SPDX-License-Identifier: ISC
//! Replay of `data/addrmgr_v2_vectors.txt`: every row was dumped
//! mechanically inside dcrd's addrmgr package at master commit
//! 452c1a6c (the 2.2 pre-release parity target) by driving the real
//! Tor v3 onion rendering (`Key`), `EncodeHost`, the per-bucket type
//! statistics bookkeeping under a fixed bucket key, and the filtered
//! `GetAddress` selection.

// Test scaffolding uses bounded counters and scripted randomness.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::{Arc, Mutex};

use dcroxide_addrmgr::{
    AddrManager, AddrRng, NetAddress, NetAddressType, encode_host, new_net_address_from_params,
};
use dcroxide_testutil::unhex;
use dcroxide_wire::ServiceFlag;

const VECTORS: &str = include_str!("data/addrmgr_v2_vectors.txt");

/// The exporter's canonical timestamp, in the port's Unix nanoseconds.
const TS_NANOS: i64 = 0x495f_ab29 * 1_000_000_000;

fn utf8(hex: &str) -> String {
    String::from_utf8(unhex(hex)).expect("utf8 payload")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// dcrd's integer value for each address type (TorV2's value 3 is
/// retired, so TorV3 is 4).
fn type_code(t: NetAddressType) -> u8 {
    t as u8
}

/// A scripted random source; values are consumed in order and reduced
/// into range, with zeroes once the script is exhausted.
struct ScriptRng {
    values: Vec<usize>,
    pos: usize,
}

impl AddrRng for ScriptRng {
    fn int_n(&mut self, n: usize) -> usize {
        let v = self.values.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        if n == 0 { 0 } else { v % n }
    }

    fn read(&mut self, buf: &mut [u8]) {
        buf.fill(0);
    }
}

/// The exporter's deterministic 32-byte "public key" for a seed.
fn mk_pubkey(seed: u8) -> Vec<u8> {
    (0..32u8).map(|i| seed.wrapping_add(i)).collect()
}

fn mk_v4(o3: u8, o4: u8, port: u16) -> NetAddress {
    new_net_address_from_params(
        NetAddressType::IPv4,
        &[8, 8, o3, o4],
        port,
        TS_NANOS,
        ServiceFlag::NODE_NETWORK,
    )
    .expect("v4 address")
}

fn mk_v6(last: u8, port: u16) -> NetAddress {
    let mut ip = [0u8; 16];
    ip[0] = 0x20;
    ip[1] = 0x01;
    ip[2] = 0x48;
    ip[3] = 0x60;
    ip[15] = last;
    new_net_address_from_params(
        NetAddressType::IPv6,
        &ip,
        port,
        TS_NANOS,
        ServiceFlag::NODE_NETWORK,
    )
    .expect("v6 address")
}

/// The exporter's `mkIP`: any host through `encode_host` and the
/// params constructor.
fn mk_ip(host: &str) -> NetAddress {
    let (addr_type, addr_bytes) = encode_host(host);
    new_net_address_from_params(
        addr_type,
        &addr_bytes,
        9108,
        TS_NANOS,
        ServiceFlag::NODE_NETWORK,
    )
    .expect("ip address")
}

fn mk_tor(seed: u8, port: u16) -> NetAddress {
    new_net_address_from_params(
        NetAddressType::TorV3,
        &mk_pubkey(seed),
        port,
        TS_NANOS,
        ServiceFlag::NODE_NETWORK,
    )
    .expect("tor address")
}

/// Rebuild the exporter's manager scenario: a fixed bucket key, three
/// IPv4, two IPv6, and one Tor v3 address added from a single source,
/// with one of each type later promoted to tried.
fn scenario_manager(rng_values: Vec<usize>) -> AddrManager {
    let dir = tempfile::tempdir().expect("temp dir");
    let rng = Arc::new(Mutex::new(ScriptRng {
        values: rng_values,
        pos: 0,
    }));
    let mut am = AddrManager::new_with_hooks(dir.path(), Arc::new(|| TS_NANOS), rng);
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = i as u8;
    }
    am.set_key(key);

    let src = mk_v4(0, 1, 9108);
    let addrs = [
        mk_v4(1, 1, 9108),
        mk_v4(2, 2, 9108),
        mk_v4(3, 3, 9108),
        mk_v6(0x11, 9108),
        mk_v6(0x22, 9108),
        mk_tor(0x10, 9108),
    ];
    am.add_addresses(&addrs, &src);
    am
}

/// Promote the exporter's chosen one-per-type addresses to tried.
fn promote(am: &mut AddrManager) {
    for na in [mk_v4(1, 1, 9108), mk_v6(0x11, 9108), mk_tor(0x10, 9108)] {
        am.good(&na).expect("good");
    }
}

/// Parse a stats row's bucket entries into new/tried lists.
type StatRows = Vec<(usize, u16, u16, u16)>;

fn parse_stat_entries(parts: &[&str]) -> (StatRows, StatRows) {
    let mut new_rows = Vec::new();
    let mut tried_rows = Vec::new();
    for entry in parts {
        let f: Vec<&str> = entry.split(',').collect();
        let row = (
            f[1].parse::<usize>().expect("bucket"),
            f[2].parse::<u16>().expect("ipv4"),
            f[3].parse::<u16>().expect("ipv6"),
            f[4].parse::<u16>().expect("tor"),
        );
        match f[0] {
            "new" => new_rows.push(row),
            "tried" => tried_rows.push(row),
            other => panic!("unknown stats table {other}"),
        }
    }
    (new_rows, tried_rows)
}

#[test]
fn addrmgr_v2_vectors() {
    for line in VECTORS.lines() {
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('|').collect();
        match parts[0] {
            "onionkey" => {
                let pubkey = unhex(parts[1]);
                let na = new_net_address_from_params(
                    NetAddressType::TorV3,
                    &pubkey,
                    9108,
                    TS_NANOS,
                    ServiceFlag::NODE_NETWORK,
                )
                .expect("tor address");
                assert_eq!(na.key(), parts[2], "{line}");
            }
            "encodehost" => {
                let host = utf8(parts[1]);
                let want_type: u8 = parts[2].parse().expect("type");
                let (addr_type, addr_bytes) = encode_host(&host);
                assert_eq!(type_code(addr_type), want_type, "{line}");
                assert_eq!(hex(&addr_bytes), parts[3], "{line}");
            }
            "stats" => {
                let label = parts[1];
                let want_new: usize = parts[2].parse().expect("nNew");
                let want_tried: usize = parts[3].parse().expect("nTried");
                let (want_new_rows, want_tried_rows) = parse_stat_entries(&parts[4..]);

                let mut am = scenario_manager(Vec::new());
                if label == "after-good" {
                    promote(&mut am);
                }
                let (n_new, n_tried, new_rows, tried_rows) = am.bucket_stats_snapshot();
                assert_eq!(n_new, want_new, "{line}");
                assert_eq!(n_tried, want_tried, "{line}");
                assert_eq!(new_rows, want_new_rows, "{line}");
                assert_eq!(tried_rows, want_tried_rows, "{line}");
            }
            "reachtor" => {
                let by_name = |name: &str| match name {
                    "tor-a" => mk_tor(0x10, 9108),
                    "tor-b" => mk_tor(0x30, 9108),
                    "v4-pub" => mk_ip("8.8.8.8"),
                    "v4-priv" => mk_ip("10.1.2.3"),
                    "v6-pub" => mk_ip("2001:4860::68"),
                    "v6-teredo" => mk_ip("2001::1"),
                    other => panic!("unknown reach addr {other}"),
                };
                let want: u8 = parts[3].parse().expect("reach");
                let am = scenario_manager(Vec::new());
                let (_, reach) =
                    am.is_external_addr_candidate(&by_name(parts[1]), &by_name(parts[2]));
                assert_eq!(reach as u8, want, "{line}");
            }
            "getaddress" => match parts[1] {
                "onlytor" => {
                    // One Tor address in one tried bucket: the bucket
                    // and nth draws reduce to zero and a low accept
                    // draw returns it, mirroring dcrd's guaranteed
                    // termination.
                    let mut am = scenario_manager(vec![0, 0, 0]);
                    promote(&mut am);
                    let picked = am
                        .get_address(|t| t == NetAddressType::TorV3)
                        .expect("tor candidate");
                    let key = picked.lock().expect("known address").net_address().key();
                    assert_eq!(key, parts[2], "{line}");
                }
                "none" => {
                    let mut am = scenario_manager(Vec::new());
                    promote(&mut am);
                    assert!(am.get_address(|_| false).is_none(), "{line}");
                }
                other => panic!("unknown getaddress label {other}"),
            },
            other => panic!("unknown row kind {other}"),
        }
    }
}
