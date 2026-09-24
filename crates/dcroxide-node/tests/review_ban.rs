// SPDX-License-Identifier: ISC
//! Ban and whitelist keys and ban-score guards pinned against dcrd's
//! `server.go`:
//!
//! - A ban on an IPv6 link-local peer is keyed on the bare IP that the
//!   pre-handshake check looks up, and the peer matches a link-local
//!   whitelist.  dcrd derives both from the zone-free address manager
//!   `NetAddress`; the daemon's inbound address string is Rust's
//!   `SocketAddr` rendering, which carries the interface scope.
//! - The ban expiry saturates the way Go's `time.Now().Add` does, so an
//!   enormous `--banduration` bans for good instead of wrapping to a time
//!   in the past.
//! - A zero ban-score increase does nothing (dcrd `addBanScore`'s early
//!   return), even for a peer whose decaying score already exceeds the
//!   threshold.

use std::collections::BTreeMap;
use std::net::{SocketAddr, SocketAddrV6};

use dcroxide_node::config::IpPrefix;
use dcroxide_node::server::{
    BanPeerOutcome, ServerPeerAddrState, add_ban_score, ban_peer, handle_banned_conn,
    is_whitelisted,
};

/// A fixed clock in late 2026, in Unix nanoseconds.
const NOW_NANOS: i64 = 1_790_000_000 * 1_000_000_000;
const HOUR_NANOS: i64 = 3_600 * 1_000_000_000;

/// An inbound link-local peer as `accept` reports it: on interface
/// index 2, so its `SocketAddr` carries a scope.
fn link_local_peer() -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(
        "fe80::1".parse().expect("link-local address"),
        9108,
        0,
        2,
    ))
}

#[test]
fn a_link_local_ban_is_found_by_the_pre_handshake_check() {
    let addr = link_local_peer();
    // The daemon hands `ban_peer` the peer's address string.
    let remote_addr = addr.to_string();
    assert_eq!(remote_addr, "[fe80::1%2]:9108");

    let mut banned = BTreeMap::new();
    let outcome = ban_peer(
        &mut banned,
        &remote_addr,
        false,
        false,
        HOUR_NANOS,
        NOW_NANOS,
    );
    assert_eq!(
        outcome,
        BanPeerOutcome::Banned {
            host: "fe80::1".to_string(),
            until_nanos: NOW_NANOS + HOUR_NANOS,
        }
    );

    // The reconnection is checked against the bare IP (`runtime`'s
    // `addr.ip().to_string()`, dcrd `net.IP(remoteAddr.IP).String()`).
    let check = handle_banned_conn(&mut banned, &addr.ip().to_string(), NOW_NANOS + 1);
    assert!(check.banned, "the banned link-local peer must be refused");
}

#[test]
fn a_link_local_peer_matches_a_link_local_whitelist() {
    // --whitelist=fe80::/10
    let mut ip = vec![0u8; 16];
    ip[0] = 0xfe;
    ip[1] = 0x80;
    let whitelists = vec![IpPrefix { ip, ones: 10 }];
    assert!(is_whitelisted(&whitelists, &link_local_peer().to_string()));
}

#[test]
fn an_enormous_ban_duration_bans_for_good() {
    // 2,500,000h, and the largest duration Go parses.
    for duration in [2_500_000 * HOUR_NANOS, i64::MAX] {
        let mut banned = BTreeMap::new();
        let outcome = ban_peer(
            &mut banned,
            "10.0.0.2:9108",
            false,
            false,
            duration,
            NOW_NANOS,
        );
        assert_eq!(
            outcome,
            BanPeerOutcome::Banned {
                host: "10.0.0.2".to_string(),
                until_nanos: i64::MAX,
            }
        );
        let check = handle_banned_conn(&mut banned, "10.0.0.2", NOW_NANOS + HOUR_NANOS);
        assert!(check.banned, "the ban must not lift ({duration}ns)");
    }
}

#[test]
fn a_zero_ban_score_increase_does_nothing() {
    let now_unix = NOW_NANOS / 1_000_000_000;
    let mut state = ServerPeerAddrState::new(false);
    // A score already past the threshold, as a peer being torn down for
    // it carries.
    let score = state
        .ban_score
        .lock()
        .expect("ban score")
        .increase_at(150, 0, now_unix);
    assert_eq!(score, 150);

    // A getdata of fewer than 506 items scores nothing.
    assert!(!add_ban_score(
        &mut state, 0, 0, "getdata", false, 100, now_unix
    ));
}
