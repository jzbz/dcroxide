// SPDX-License-Identifier: ISC
//! dcrd measures a ping's round trip as `nowFn().Sub(lastPingTime)` and
//! getpeerinfo's pingwait as `Clock.Since(LastPingTime)` (peer/peer.go
//! `handlePongMsg`, internal/rpcserver `handleGetPeerInfo`).  `time.Now`
//! carries a monotonic reading and both use it, so a wall-clock step
//! while a ping is outstanding changes neither.  The port measured both
//! on the wall clock alone: a step back of two seconds between ping and
//! pong reported a pingtime of about -2,000,000 microseconds.

use std::time::{Duration, Instant};

use dcroxide_peer::{Config, Peer, PeerEnv};
use dcroxide_wire::{MsgPing, MsgPong, NetAddress, NetAddressV2};

/// A scripted clock: a wall time and an optional monotonic reading,
/// either of which the test moves independently.
struct SteppedEnv {
    wall_nanos: i64,
    instant: Option<Instant>,
}

impl PeerEnv for SteppedEnv {
    fn now_nanos(&mut self) -> i64 {
        self.wall_nanos
    }

    fn now_instant(&mut self) -> Option<Instant> {
        self.instant
    }

    fn rand_u64(&mut self) -> u64 {
        1
    }

    fn shuffle_addrs(&mut self, _addrs: &mut [NetAddress]) {}
    fn shuffle_addrs_v2(&mut self, _addrs: &mut [NetAddressV2]) {}
}

/// A scripted wall clock that leaves `now_instant` to the trait's
/// default, as the in-tree vector environments do.
struct WallOnlyEnv {
    wall_nanos: i64,
}

impl PeerEnv for WallOnlyEnv {
    fn now_nanos(&mut self) -> i64 {
        self.wall_nanos
    }

    fn rand_u64(&mut self) -> u64 {
        1
    }

    fn shuffle_addrs(&mut self, _addrs: &mut [NetAddress]) {}
    fn shuffle_addrs_v2(&mut self, _addrs: &mut [NetAddressV2]) {}
}

const WALL: i64 = 1_700_000_000 * 1_000_000_000;

#[test]
fn round_trip_is_monotonic_across_a_wall_clock_step() {
    let base = Instant::now();
    let mut env = SteppedEnv {
        wall_nanos: WALL,
        instant: Some(base),
    };
    let mut peer = Peer::new_inbound(Config::default());
    peer.record_sent_ping(&mut env, &MsgPing { nonce: 5 });

    // 1.5 ms pass on the monotonic clock while the wall clock steps
    // back two seconds.
    env.wall_nanos = WALL - 2_000_000_000;
    env.instant = Some(base + Duration::from_micros(1500));
    peer.handle_pong_msg(&mut env, &MsgPong { nonce: 5 });

    assert_eq!(peer.last_ping_nonce(), 0);
    assert_eq!(peer.last_ping_micros(), 1500);
}

/// Without monotonic readings (a scripted clock, like a Go `time.Time`
/// built with `time.Unix`) the round trip falls back to the wall times.
#[test]
fn round_trip_falls_back_to_the_wall_clock_without_readings() {
    let mut env = SteppedEnv {
        wall_nanos: WALL,
        instant: None,
    };
    let mut peer = Peer::new_inbound(Config::default());
    peer.record_sent_ping(&mut env, &MsgPing { nonce: 5 });
    env.wall_nanos = WALL + 2_500_000;
    peer.handle_pong_msg(&mut env, &MsgPong { nonce: 5 });
    assert_eq!(peer.last_ping_micros(), 2500);
}

/// An environment that does not supply monotonic readings gets the
/// wall-clock fallback by default, so a scripted clock's round trip is
/// the scripted interval rather than the real time the test took.
#[test]
fn a_scripted_clock_is_wall_only_by_default() {
    let mut env = WallOnlyEnv { wall_nanos: WALL };
    assert_eq!(env.now_instant(), None);
    let mut peer = Peer::new_inbound(Config::default());
    peer.record_sent_ping(&mut env, &MsgPing { nonce: 5 });
    assert_eq!(peer.stats_snapshot().last_ping_instant, None);
    env.wall_nanos = WALL + 7_000_000_000;
    peer.handle_pong_msg(&mut env, &MsgPong { nonce: 5 });
    assert_eq!(peer.last_ping_micros(), 7_000_000);
}

/// The snapshot restates the outstanding ping against the wall clock
/// from its monotonic age, reading both clocks together, so a
/// wall-clock `since` of it is the monotonic wait whatever the wall
/// clock did meanwhile.
#[test]
fn pingwait_is_measured_on_the_monotonic_clock() {
    let sent = Instant::now();
    let mut env = SteppedEnv {
        wall_nanos: WALL,
        instant: Some(sent),
    };
    let mut peer = Peer::new_inbound(Config::default());
    peer.record_sent_ping(&mut env, &MsgPing { nonce: 9 });
    let snap = peer.stats_snapshot();
    assert_eq!(snap.last_ping_time_nanos, WALL);
    assert_eq!(snap.last_ping_instant, Some(sent));

    // Three milliseconds on, the wall clock reads two seconds before
    // the ping was sent.
    env.wall_nanos = WALL - 2_000_000_000;
    env.instant = Some(sent + Duration::from_millis(3));
    let restated = snap.last_ping_time_on_wall_clock(&mut env);
    assert_eq!(env.wall_nanos - restated, 3_000_000);

    // Without a monotonic reading now, or with the ping lacking one,
    // the wall stamp is used as is.
    env.instant = None;
    assert_eq!(snap.last_ping_time_on_wall_clock(&mut env), WALL);
    let mut wall_only = WallOnlyEnv { wall_nanos: WALL };
    peer.record_sent_ping(&mut wall_only, &MsgPing { nonce: 10 });
    let snap = peer.stats_snapshot();
    env.instant = Some(sent + Duration::from_millis(3));
    assert_eq!(snap.last_ping_time_on_wall_clock(&mut env), WALL);
}
