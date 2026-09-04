// SPDX-License-Identifier: ISC
//! What the peer environment must and must not carry.
//!
//! Two structural facts do the work here, and between them they rule
//! out every per-environment design: the type is zero-sized, so it
//! cannot hold a generator; and `entropy_policy.rs` fails if
//! `peerconn.rs` reads the kernel at all, so it cannot draw one per
//! call. What is left is a shared process-wide stream, which is dcrd's
//! shape — `peer/peer.go` holds no generator and calls `crypto/rand`'s
//! package functions.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::HashSet;

use dcroxide_node::peerconn::NodePeerEnv;
use dcroxide_peer::PeerEnv;
use dcroxide_wire::{NetAddress, NetAddressType, NetAddressV2, ServiceFlag};

fn addr(port: u16) -> NetAddress {
    NetAddress {
        timestamp: 0,
        services: ServiceFlag(0),
        ip: [0u8; 16],
        port,
    }
}

fn addr_v2(port: u16) -> NetAddressV2 {
    NetAddressV2 {
        timestamp: 0,
        services: ServiceFlag(0),
        addr_type: NetAddressType::IPV4,
        encoded_addr: vec![0u8; 4],
        port,
    }
}

/// The environment carries no generator.
///
/// This is the property that keeps `NodePeerEnv::new()` free at
/// runtime.rs:350, :363, :396 and :413, which build one purely to read
/// the clock and drop it. It fails for every design that holds a
/// generator: by value, behind an `Arc<Mutex<..>>`, or as a lazily
/// seeded `Option<Prng>`.
#[test]
fn the_environment_carries_no_generator() {
    assert_eq!(
        std::mem::size_of::<NodePeerEnv>(),
        0,
        "NodePeerEnv must stay zero-sized: runtime.rs:350, :363, :396 \
         and :413 construct one only to read the clock, and start \
         paying for a generator the moment it holds one"
    );
}

/// Two environments never repeat a value, because there is one stream.
///
/// What this does not discriminate, stated rather than implied: a
/// per-environment generator seeded from the kernel would also pass,
/// since two kernel seeds do not collide either. The pin against that
/// is `entropy_policy.rs`, which fails if `peerconn.rs` contains a
/// kernel read at all. What this catches is the likelier regression —
/// a per-environment generator seeded from a constant, which is the
/// shape three of the four `PeerEnv` test doubles use.
#[test]
fn two_environments_never_repeat_a_value() {
    let mut a = NodePeerEnv::new();
    let mut b = NodePeerEnv::new();
    let mut seen = HashSet::new();

    for _ in 0..256 {
        assert!(
            seen.insert(a.rand_u64()),
            "a repeated draw means two streams"
        );
        assert!(
            seen.insert(b.rand_u64()),
            "a repeated draw means two streams"
        );
    }
}

/// The largest shuffle the daemon can be made to perform permutes, and
/// loses nothing.
///
/// 2500 is the ceiling: `push_addr_msg` shuffles only above
/// `MAX_ADDR_PER_MSG` (1000) and the address cache is capped at
/// `GET_KNOWN_ADDRESS_LIMIT` (2500). The "not ascending" assertion is
/// the one that bites — every `PeerEnv` test double in the workspace
/// implements `shuffle_addrs` with an empty body, so "compiles and
/// preserves the multiset" is satisfied by doing nothing at all.
#[test]
fn the_largest_reachable_addr_shuffle_permutes_and_loses_nothing() {
    let mut env = NodePeerEnv::new();

    let original: Vec<u16> = (0..2500u16).collect();
    let mut first: Vec<NetAddress> = original.iter().map(|p| addr(*p)).collect();
    let mut second = first.clone();

    env.shuffle_addrs(&mut first);
    env.shuffle_addrs(&mut second);

    let ports = |v: &[NetAddress]| -> Vec<u16> { v.iter().map(|a| a.port).collect() };
    let (p1, p2) = (ports(&first), ports(&second));

    let mut sorted = p1.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, original, "the shuffle must lose and invent nothing");
    assert_ne!(p1, original, "the shuffle must actually reorder");
    assert_ne!(p1, p2, "two shuffles must not produce the same order");

    // `shuffle_addrs_v2` is a separate trait method, so it is a separate
    // chance to leave an empty body.
    let original_v2: Vec<u16> = (0..1001u16).collect();
    let mut v2: Vec<NetAddressV2> = original_v2.iter().map(|p| addr_v2(*p)).collect();
    env.shuffle_addrs_v2(&mut v2);
    let mut got: Vec<u16> = v2.iter().map(|a| a.port).collect();
    assert_ne!(got, original_v2, "the v2 shuffle must actually reorder");
    got.sort_unstable();
    assert_eq!(got, original_v2, "the v2 shuffle must lose nothing");
}
