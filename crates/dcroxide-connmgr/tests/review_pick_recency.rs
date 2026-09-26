// SPDX-License-Identifier: ISC
//! dcrd's `pickOutboundAddr` skips, for its first 30 tries, an address
//! whose `lastTry.Add(10*time.Minute).After(now)`, where `lastTry` is the
//! address manager's `LastAttempt()` and `now` is `time.Now()`.  For an
//! address attempted in this process both carry a monotonic reading, so
//! the window is ten minutes of running time whatever the wall clock
//! does.  The port compared wall-clock nanoseconds: a forward step let an
//! address that had just failed straight back in, and a backward one kept
//! every address tried in the step's span out.

// Test arithmetic over fixed, small offsets.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_addrmgr::{GoTime, NetAddress, NetAddressType, new_net_address_from_params};
use dcroxide_connmgr::SystemCsprng;
use dcroxide_connmgr::manager::{ConnManager, ManagerConfig};
use dcroxide_wire::ServiceFlag;

const MINUTE: i64 = 60_000_000_000;

/// When the candidate was last attempted: in this process, with both
/// of `time.Now`'s readings.
const TRIED: GoTime = GoTime {
    wall: 1_700_000_000_000_000_000,
    mono: Some(7_200_000_000_000),
};

fn v4(a: u8) -> NetAddress {
    new_net_address_from_params(NetAddressType::IPv4, &[a, 1, 2, 3], 9108, 0, ServiceFlag(0))
        .expect("v4 addr")
}

/// Whether the first try claims the candidate at `now`.
fn claimed_at(last_try: GoTime, now: GoTime) -> bool {
    let mut manager = ConnManager::new(ManagerConfig::default(), &mut SystemCsprng::default());
    manager.claim_outbound_candidate(0, &v4(8), last_try, now)
}

/// `now` after `wall` of wall-clock change and `mono` of running time.
fn later(wall: i64, mono: i64) -> GoTime {
    GoTime {
        wall: TRIED.wall + wall,
        mono: TRIED.mono.map(|m| m + mono),
    }
}

#[test]
fn recency_is_running_time_for_an_address_tried_in_this_process() {
    // A minute later, after the wall clock jumped 15 minutes forward:
    // still recent.
    assert!(!claimed_at(TRIED, later(15 * MINUTE, MINUTE)));
    // Eleven minutes later, after the wall clock stepped an hour back:
    // no longer recent.
    assert!(claimed_at(TRIED, later(-60 * MINUTE, 11 * MINUTE)));
    // Exactly ten minutes is not recent, as `After` is strict.
    assert!(claimed_at(TRIED, later(0, 10 * MINUTE)));
    assert!(!claimed_at(TRIED, later(0, 10 * MINUTE - 1)));
}

/// An attempt time loaded from `peers.json` has no monotonic reading, so
/// the wall clock decides, in dcrd as here; and a never-attempted
/// address (the zero time) is never recent.
#[test]
fn recency_is_wall_time_for_a_loaded_attempt() {
    let loaded = GoTime::wall(TRIED.wall);
    assert!(claimed_at(loaded, later(15 * MINUTE, MINUTE)));
    assert!(!claimed_at(loaded, later(-60 * MINUTE, 11 * MINUTE)));
    assert!(claimed_at(GoTime::default(), later(0, 0)));
}
