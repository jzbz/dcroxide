// SPDX-License-Identifier: ISC
//! The daemon's peer environment and connection glue.
//!
//! The ported peer module drives the version handshake and the per-peer
//! message loops over two injected seams: the [`PeerEnv`] trait (the
//! clock and randomness dcrd takes from the standard library) and the
//! [`WireTransport`](crate::transport::WireTransport) framing.  This
//! module supplies the daemon's concrete [`PeerEnv`] — the real system
//! clock, and the nonce and address-shuffle draws routed to the port of
//! dcrd's `crypto/rand` package global, which is what dcrd's own peer
//! module reaches — and the conversion from an accepted socket address
//! into the wire network address a peer is associated with.
//!
//! With these in hand a [`Peer`](dcroxide_peer::Peer) negotiates the
//! version exchange straight over a
//! [`WireTransport`](crate::transport::WireTransport); the verack
//! exchange and the steady-state message loops arrive with the per-peer
//! loop piece.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use dcroxide_peer::{PeerAddr, PeerEnv, new_net_address};
use dcroxide_wire::{NetAddress, ServiceFlag};

/// The daemon's [`PeerEnv`]: the wall clock, and the randomness dcrd's
/// peer package takes from the `crypto/rand` package global, standing
/// in for `time.Now`, `rand.Uint64` and `rand.ShuffleSlice`.
///
/// A unit struct, and deliberately so.  dcrd's peer module holds no
/// generator either -- it imports `crypto/rand` and calls the package
/// functions (`peer/peer.go:1813`, `:2186`, `:842`, `:873`) -- and a
/// zero-sized environment is what keeps `NodePeerEnv::new()` free at
/// `runtime.rs:350`, `:363`, `:396` and `:413`, which build one only to
/// read the clock and drop it.  Pinned by
/// `tests/peerenv_rand.rs::the_environment_carries_no_generator`.
#[derive(Debug, Default)]
pub struct NodePeerEnv;

impl NodePeerEnv {
    /// A fresh peer environment.
    pub fn new() -> NodePeerEnv {
        NodePeerEnv
    }
}

impl PeerEnv for NodePeerEnv {
    fn now_nanos(&mut self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0)
    }

    fn rand_u64(&mut self) -> u64 {
        // The process-wide generator, not one held here: dcrd's peer
        // module imports `crypto/rand` and calls the package function
        // for both nonces it draws (`peer/peer.go:1813` ping, `:2186`
        // version).  It cannot fail, which matters because the version
        // nonce is drawn on every accepted connection and this
        // workspace's release profile aborts on panic.
        dcroxide_crypto::rand::uint64()
    }

    fn shuffle_addrs(&mut self, addrs: &mut [NetAddress]) {
        // dcrd `rand.ShuffleSlice(msg.AddrList)` in `PushAddrMsg`
        // (`peer/peer.go:842`).  Reached only when the list exceeds
        // `MAX_ADDR_PER_MSG`, on a getaddr an unauthenticated peer
        // sends; the loop this replaced read the kernel once per swap
        // and reduced by a raw modulo, where dcrd reduces through the
        // bias-free `Uint64N`.
        dcroxide_crypto::rand::shuffle_slice(addrs);
    }

    fn shuffle_addrs_v2(&mut self, addrs: &mut [dcroxide_wire::NetAddressV2]) {
        // dcrd `rand.ShuffleSlice(addrs)` in `PushAddrV2Msg`
        // (`peer/peer.go:873`).
        dcroxide_crypto::rand::shuffle_slice(addrs);
    }
}

/// Convert an accepted socket address into the peer address form the
/// wire network address is built from (dcrd wraps `net.TCPAddr`).
pub fn peer_addr_from_socket(addr: SocketAddr) -> PeerAddr {
    let ip = match addr {
        SocketAddr::V4(v4) => v4.ip().octets().to_vec(),
        SocketAddr::V6(v6) => v6.ip().octets().to_vec(),
    };
    PeerAddr::Tcp {
        ip,
        port: addr.port(),
    }
}

/// Build the wire network address for a peer reached at `addr`,
/// advertising `services` (dcrd `newNetAddress(conn.RemoteAddr(),
/// services)`).
pub fn net_address_from_socket(
    addr: SocketAddr,
    services: ServiceFlag,
) -> Result<NetAddress, String> {
    new_net_address(&peer_addr_from_socket(addr), services)
}

/// Build the v2 network address for a connected socket (dcrd 2.2's
/// `newNetAddress` returning a `wire.NetAddressV2`).
pub fn net_address_v2_from_socket(
    addr: SocketAddr,
    services: ServiceFlag,
) -> Result<dcroxide_wire::NetAddressV2, String> {
    let legacy = new_net_address(&peer_addr_from_socket(addr), services)?;
    Ok(dcroxide_wire::NetAddressV2::from_ip_port(
        legacy.ip,
        legacy.port,
        services,
        0,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_nanos_is_a_recent_positive_time() {
        let mut env = NodePeerEnv::new();
        let now = env.now_nanos();
        // Comfortably after the year 2020 (in unix nanoseconds).
        assert!(now > 1_577_836_800_000_000_000, "now_nanos: {now}");
    }

    #[test]
    fn rand_u64_varies_between_calls() {
        let mut env = NodePeerEnv::new();
        let draws: std::collections::HashSet<u64> = (0..8).map(|_| env.rand_u64()).collect();
        // Eight draws colliding down to a single value is astronomically
        // unlikely; a couple of distinct values is enough to show the
        // source is live.
        assert!(draws.len() > 1, "rand_u64 produced no variation");
    }

    #[test]
    fn shuffle_preserves_the_address_multiset() {
        let mut env = NodePeerEnv::new();
        let make = |port: u16| NetAddress {
            timestamp: 0,
            services: ServiceFlag(0),
            ip: [0u8; 16],
            port,
        };
        let original: Vec<NetAddress> = (0..16).map(make).collect();
        let mut shuffled = original.clone();
        env.shuffle_addrs(&mut shuffled);

        let mut a: Vec<u16> = original.iter().map(|n| n.port).collect();
        let mut b: Vec<u16> = shuffled.iter().map(|n| n.port).collect();
        a.sort_unstable();
        b.sort_unstable();
        assert_eq!(a, b, "shuffle changed the set of addresses");
    }

    #[test]
    fn peer_addr_from_socket_uses_the_raw_ip_bytes() {
        let v4: SocketAddr = "127.0.0.1:9108".parse().unwrap();
        match peer_addr_from_socket(v4) {
            PeerAddr::Tcp { ip, port } => {
                assert_eq!(ip, vec![127, 0, 0, 1]);
                assert_eq!(port, 9108);
            }
            other => panic!("expected Tcp, got {other:?}"),
        }

        let v6: SocketAddr = "[::1]:9108".parse().unwrap();
        match peer_addr_from_socket(v6) {
            PeerAddr::Tcp { ip, port } => {
                assert_eq!(ip.len(), 16);
                assert_eq!(ip[15], 1);
                assert_eq!(port, 9108);
            }
            other => panic!("expected Tcp, got {other:?}"),
        }
    }
}
