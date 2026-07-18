// SPDX-License-Identifier: ISC
//! Replay of frozen server address relay and ban vectors generated
//! by an in-package dump driving dcrd's real handlers over piped
//! peers at release-v2.1.5: the getaddr gating (simnet, outbound,
//! the empty cache no-op, the once-per-connection flag, and the
//! pushed subset fed back as the replay's cache), the addr handling
//! (known-address tracking, simnet gating, and the empty-list ban),
//! the ban score ladder, and BanPeer — compared row for row.

// Index arithmetic over pinned vector rows.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use dcroxide_node::server::{
    GetAddrFacts, OnAddrFacts, OnAddrOutcome, PushAddrOutcome, ServerPeerAddrState, add_ban_score,
    ban_peer, on_addr, on_get_addr, wire_to_addrmgr_net_address,
};
use dcroxide_peer::{Peer, PeerEnv};
use dcroxide_wire::{Message, NetAddress, ServiceFlag};

const VECTORS: &str = include_str!("data/srvrelay_vectors.txt");

struct FixedEnv;

impl PeerEnv for FixedEnv {
    fn now_nanos(&mut self) -> i64 {
        1_700_000_000 * 1_000_000_000
    }
    fn rand_u64(&mut self) -> u64 {
        0x1234_5678_9abc_def0
    }
    fn shuffle_addrs(&mut self, _addrs: &mut [NetAddress]) {}
    fn shuffle_addrs_v2(&mut self, _addrs: &mut [dcroxide_wire::NetAddressV2]) {}
}

fn wire_addr(ip: &str, port: u16, timestamp: u32) -> NetAddress {
    let mut bytes = [0u8; 16];
    match ip.parse::<std::net::IpAddr>().unwrap() {
        std::net::IpAddr::V4(v4) => {
            bytes[10] = 0xff;
            bytes[11] = 0xff;
            bytes[12..16].copy_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => bytes.copy_from_slice(&v6.octets()),
    }
    NetAddress {
        timestamp,
        services: ServiceFlag::NODE_NETWORK,
        ip: bytes,
        port,
    }
}

fn new_peer() -> Peer {
    // The rows were dumped at protocol version 11; pinning the peer
    // keeps the dispatcher on the legacy addr path they encode.
    Peer::new_inbound(dcroxide_peer::Config {
        protocol_version: 11,
        ..dcroxide_peer::Config::default()
    })
}

/// The banned map rendered like the dump's sorted host join.
fn banned_hosts(banned: &BTreeMap<String, i64>) -> String {
    banned.keys().cloned().collect::<Vec<_>>().join(",")
}

#[test]
fn server_address_relay_matches_dcrd() {
    let now_nanos: i64 = 1_700_000_000 * 1_000_000_000;
    let now_secs: u32 = 1_700_000_000;
    let ban_threshold: u32 = 100;
    let ban_duration_nanos: i64 = 24 * 3600 * 1_000_000_000;
    let peer_addr = "10.0.0.2:34567";
    let peer_na = wire_addr("10.0.0.2", 34567, now_secs);

    // The addr scenario addresses mirror the dump.
    let sent_a = wire_addr("52.91.7.8", 9108, now_secs);
    let sent_b = wire_addr("2620:1a0::22", 9108, now_secs);
    let future = wire_addr("52.91.9.9", 9108, now_secs + 48 * 3600);
    let unsent = wire_addr("52.91.200.200", 9108, now_secs);

    // Long-lived state for the ban score ladder rows.
    let mut bs_state = ServerPeerAddrState::new(false);
    let mut bs_banned: BTreeMap<String, i64> = BTreeMap::new();

    // State for the getaddr session rows (populated + secondrequest
    // share one connection in the dump).
    let mut ga_state = ServerPeerAddrState::new(false);
    let mut ga_peer = new_peer();

    for line in VECTORS.lines() {
        let fields: Vec<&str> = line.split('|').collect();
        match (fields[0], fields[1]) {
            ("ga", "simnet") => {
                let mut state = ServerPeerAddrState::new(false);
                let mut peer = new_peer();
                let out = on_get_addr(
                    &mut state,
                    &mut peer,
                    &mut FixedEnv,
                    &GetAddrFacts {
                        sim_or_reg_net: true,
                        inbound: true,
                    },
                    &[],
                );
                assert!(out.is_none(), "simnet pushes nothing");
                assert_eq!(state.addrs_sent.to_string(), fields[3]);
            }
            ("ga", "outbound") => {
                let mut state = ServerPeerAddrState::new(false);
                let mut peer = new_peer();
                let out = on_get_addr(
                    &mut state,
                    &mut peer,
                    &mut FixedEnv,
                    &GetAddrFacts {
                        sim_or_reg_net: false,
                        inbound: false,
                    },
                    &[],
                );
                assert!(out.is_none(), "outbound pushes nothing");
                assert_eq!(state.addrs_sent.to_string(), fields[3]);
            }
            ("ga", "emptycache") => {
                let mut state = ServerPeerAddrState::new(false);
                let mut peer = new_peer();
                let out = on_get_addr(
                    &mut state,
                    &mut peer,
                    &mut FixedEnv,
                    &GetAddrFacts {
                        sim_or_reg_net: false,
                        inbound: true,
                    },
                    &[],
                );
                assert_eq!(out, Some(PushAddrOutcome::Nothing), "empty cache");
                assert_eq!(state.addrs_sent.to_string(), fields[3]);
                // fields[4] pins that dcrd keeps the peer connected.
                assert_eq!(fields[4], "true");
            }
            ("ga", "populated") => {
                // Feed the exact pushed subset back as the cache
                // (dcrd's cache pick is random; the push logic is
                // what this row pins).
                let keys: Vec<&str> = fields[6].split(',').collect();
                let cache: Vec<_> = keys
                    .iter()
                    .map(|k| {
                        let (host, port) = k.rsplit_once(':').unwrap();
                        wire_to_addrmgr_net_address(&wire_addr(
                            host.trim_matches(['[', ']']),
                            port.parse().unwrap(),
                            now_secs,
                        ))
                    })
                    .collect();
                let out = on_get_addr(
                    &mut ga_state,
                    &mut ga_peer,
                    &mut FixedEnv,
                    &GetAddrFacts {
                        sim_or_reg_net: false,
                        inbound: true,
                    },
                    &cache,
                );
                let Some(PushAddrOutcome::Queued(queued)) = out else {
                    panic!("expected a queued addr message");
                };
                let Message::Addr(msg) = *queued else {
                    panic!("expected an addr message");
                };
                assert_eq!(msg.addr_list.len().to_string(), fields[4], "count");
                let mut pushed: Vec<String> = msg
                    .addr_list
                    .iter()
                    .map(|wa| wire_to_addrmgr_net_address(wa).key())
                    .collect();
                pushed.sort();
                assert_eq!(pushed.join(","), fields[6], "pushed keys");
                assert_eq!(ga_state.addrs_sent.to_string(), fields[3]);
                // Every pushed address is now known to the peer.
                for na in &cache {
                    assert!(ga_state.address_known(na), "pushed marked known");
                }
            }
            ("ga", "secondrequest") => {
                let out = on_get_addr(
                    &mut ga_state,
                    &mut ga_peer,
                    &mut FixedEnv,
                    &GetAddrFacts {
                        sim_or_reg_net: false,
                        inbound: true,
                    },
                    &[],
                );
                assert!(out.is_none(), "second request ignored");
                assert_eq!(ga_state.addrs_sent.to_string(), fields[3]);
            }
            ("oa", "tracked") => {
                let mut state = ServerPeerAddrState::new(false);
                let mut amgr =
                    dcroxide_addrmgr::AddrManager::new(tempfile::tempdir().unwrap().path());
                let out = on_addr(
                    &mut state,
                    &mut amgr,
                    &OnAddrFacts {
                        sim_or_reg_net: false,
                        connected: true,
                        peer_na: wire_to_addrmgr_net_address(&peer_na),
                    },
                    &[sent_a, sent_b, future],
                    now_nanos,
                );
                assert_eq!(out, OnAddrOutcome::Processed);
                let known = |wa: &NetAddress| {
                    state
                        .address_known(&wire_to_addrmgr_net_address(wa))
                        .to_string()
                };
                assert_eq!(known(&sent_a), fields[2]);
                assert_eq!(known(&sent_b), fields[3]);
                assert_eq!(known(&future), fields[4]);
                assert_eq!(known(&unsent), fields[5]);
                assert_eq!(fields[6], "", "no bans");
            }
            ("oa", "simnet") => {
                let mut state = ServerPeerAddrState::new(false);
                let mut amgr =
                    dcroxide_addrmgr::AddrManager::new(tempfile::tempdir().unwrap().path());
                let out = on_addr(
                    &mut state,
                    &mut amgr,
                    &OnAddrFacts {
                        sim_or_reg_net: true,
                        connected: true,
                        peer_na: wire_to_addrmgr_net_address(&peer_na),
                    },
                    &[sent_a],
                    now_nanos,
                );
                assert_eq!(out, OnAddrOutcome::Ignored);
                let known = state
                    .address_known(&wire_to_addrmgr_net_address(&sent_a))
                    .to_string();
                assert_eq!(known, fields[2]);
                assert_eq!(fields[3], "", "no bans");
            }
            ("oa", "emptylist") => {
                let mut state = ServerPeerAddrState::new(false);
                let mut amgr =
                    dcroxide_addrmgr::AddrManager::new(tempfile::tempdir().unwrap().path());
                let out = on_addr(
                    &mut state,
                    &mut amgr,
                    &OnAddrFacts {
                        sim_or_reg_net: false,
                        connected: true,
                        peer_na: wire_to_addrmgr_net_address(&peer_na),
                    },
                    &[],
                    now_nanos,
                );
                assert_eq!(out, OnAddrOutcome::BanEmptyList);
                // The caller bans the sender exactly as dcrd does.
                let mut banned = BTreeMap::new();
                ban_peer(
                    &mut banned,
                    peer_addr,
                    false,
                    false,
                    ban_duration_nanos,
                    now_nanos,
                );
                assert_eq!(banned_hosts(&banned), fields[2]);
            }
            ("bs", name) => {
                // dcrd 2.2 accumulates whitelisted peers' scores (the
                // whitelisted row contributes 60), so the warn-only row
                // adds 30 to sit between the warn and ban thresholds.
                let (disable, whitelisted, persistent) = match name {
                    "disabled" => (true, false, 60),
                    "whitelisted" => (false, true, 60),
                    "zeroscores" => (false, false, 0),
                    "warnonly" => (false, false, 30),
                    "banned" => (false, false, 60),
                    other => panic!("unknown bs row {other}"),
                };
                bs_state.is_whitelisted = whitelisted;
                let banned = add_ban_score(
                    &mut bs_state,
                    persistent,
                    0,
                    disable,
                    ban_threshold,
                    now_nanos / 1_000_000_000,
                );
                bs_state.is_whitelisted = false;
                if banned {
                    // dcrd's addBanScore bans through BanPeer.
                    ban_peer(
                        &mut bs_banned,
                        peer_addr,
                        false,
                        false,
                        ban_duration_nanos,
                        now_nanos,
                    );
                }
                assert_eq!(banned.to_string(), fields[2], "{name}");
                assert_eq!(banned_hosts(&bs_banned), fields[3], "{name}");
            }
            ("bp", name) => {
                let mut banned = BTreeMap::new();
                let whitelisted = name == "whitelisted";
                ban_peer(
                    &mut banned,
                    peer_addr,
                    whitelisted,
                    false,
                    ban_duration_nanos,
                    now_nanos,
                );
                assert_eq!(banned_hosts(&banned), fields[2], "{name}");
            }
            other => panic!("unknown row {other:?}"),
        }
    }
}
