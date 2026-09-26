// SPDX-License-Identifier: ISC
//! dcrd stamps an address's attempt and success times with `time.Now()`
//! (`Attempt`, `Good`) and tests them against `time.Now()` in `chance`
//! and `isBad`.  Go compares two such times by their monotonic readings,
//! so a wall-clock step moves none of those tests for an address
//! attempted in this process.  The port stamped and tested wall-clock
//! nanoseconds: after a forward step an address that had just failed
//! regained full chance, and after a backward one every address tried in
//! the step's span looked recent.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use dcroxide_addrmgr::{
    AddrManager, AddrRng, GoTime, NetAddress, NetAddressType, new_net_address_from_params,
};
use dcroxide_wire::ServiceFlag;

const NANOS_PER_SEC: i64 = 1_000_000_000;
const MINUTE: i64 = 60 * NANOS_PER_SEC;
const DAY: i64 = 24 * 60 * MINUTE;
const WALL: i64 = 1_700_000_000 * NANOS_PER_SEC;

struct StubRng;

impl AddrRng for StubRng {
    fn int_n(&mut self, _n: usize) -> usize {
        0
    }
    fn read(&mut self, buf: &mut [u8]) {
        buf.fill(0);
    }
}

/// A manager whose wall clock and monotonic clock the test moves apart.
struct Clocks {
    wall: Arc<AtomicI64>,
    mono: Arc<AtomicI64>,
}

impl Clocks {
    fn manager(&self, dir: &tempfile::TempDir) -> AddrManager {
        let wall = Arc::clone(&self.wall);
        let mono = Arc::clone(&self.mono);
        AddrManager::new_with_clocks(
            dir.path(),
            Arc::new(move || wall.load(Ordering::Relaxed)),
            Arc::new(move || mono.load(Ordering::Relaxed)),
            Arc::new(Mutex::new(StubRng)),
        )
    }

    /// Step the wall clock by `wall` and let `mono` of running time pass.
    fn step(&self, wall: i64, mono: i64) {
        self.wall.fetch_add(wall, Ordering::Relaxed);
        self.mono.fetch_add(mono, Ordering::Relaxed);
    }

    /// What `time.Now()` reads.
    fn now(&self) -> GoTime {
        GoTime {
            wall: self.wall.load(Ordering::Relaxed),
            mono: Some(self.mono.load(Ordering::Relaxed)),
        }
    }
}

fn fresh_clocks() -> Clocks {
    Clocks {
        wall: Arc::new(AtomicI64::new(WALL)),
        mono: Arc::new(AtomicI64::new(5 * NANOS_PER_SEC)),
    }
}

fn v4(ip: [u8; 4], timestamp: i64) -> NetAddress {
    new_net_address_from_params(
        NetAddressType::IPv4,
        &ip,
        9108,
        timestamp,
        ServiceFlag::NODE_NETWORK,
    )
    .expect("v4 address")
}

/// An address attempted a minute of running time ago has minimum chance
/// however far the wall clock jumped forward meanwhile, and one tried
/// eleven minutes of running time ago has its full chance back however
/// far the wall clock stepped back.
#[test]
fn chance_measures_running_time_since_an_attempt() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clocks = fresh_clocks();
    let mut am = clocks.manager(&dir);
    let na = v4([8, 8, 8, 8], WALL);
    am.add_addresses(core::slice::from_ref(&na), &v4([8, 8, 4, 4], WALL));
    am.attempt(&na).expect("attempt");
    let ka = am.known_address("8.8.8.8:9108").expect("known");

    let stamped = ka.lock().expect("lock").last_attempt().expect("attempted");
    assert_eq!(stamped, clocks.now(), "both of time.Now's readings");

    // The wall clock resyncs 15 minutes forward a minute later.
    clocks.step(15 * MINUTE, MINUTE);
    assert_eq!(ka.lock().expect("lock").chance(clocks.now()), 0.01);

    // Ten more minutes pass while the wall clock steps back an hour.
    clocks.step(-60 * MINUTE, 10 * MINUTE);
    assert_eq!(
        ka.lock().expect("lock").chance(clocks.now()),
        1.0 / 1.5,
        "one failed attempt, not a recent one"
    );
}

/// `isBad`'s one-minute grace after an attempt and its week since the
/// last success are running time for an address attempted in this
/// process, which `AddressCache` (getaddr replies) and the new-bucket
/// eviction both go by.
#[test]
fn is_bad_measures_running_time_since_an_attempt_and_a_success() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clocks = fresh_clocks();
    let mut am = clocks.manager(&dir);

    // Three failed attempts, then the wall clock steps back an hour two
    // minutes later: the grace minute is over, and an address that
    // never succeeded in three tries is bad.  On the wall clock the
    // last attempt lay in the future and read as within the minute.
    let failing = v4([8, 8, 8, 8], WALL - 2 * 60 * MINUTE);
    am.add_addresses(core::slice::from_ref(&failing), &v4([8, 8, 4, 4], WALL));
    for _ in 0..3 {
        am.attempt(&failing).expect("attempt");
    }
    clocks.step(-60 * MINUTE, 2 * MINUTE);
    let ka = am.known_address("8.8.8.8:9108").expect("known");
    assert!(ka.lock().expect("lock").is_bad(clocks.now()));

    // A success, five failures a moment later, and then the wall clock
    // jumps eight days forward: the success is minutes old in running
    // time, so the address is not bad and is still served.
    let dir = tempfile::tempdir().expect("tempdir");
    let clocks = fresh_clocks();
    let mut am = clocks.manager(&dir);
    let good = v4([9, 9, 9, 9], WALL);
    am.add_addresses(core::slice::from_ref(&good), &v4([8, 8, 4, 4], WALL));
    am.good(&good).expect("good");
    for _ in 0..5 {
        am.attempt(&good).expect("attempt");
    }
    clocks.step(8 * DAY, 2 * MINUTE);
    let ka = am.known_address("9.9.9.9:9108").expect("known");
    assert!(!ka.lock().expect("lock").is_bad(clocks.now()));
    assert_eq!(
        am.address_cache(|_| true)
            .iter()
            .map(NetAddress::key)
            .collect::<Vec<_>>(),
        vec!["9.9.9.9:9108".to_string()]
    );
}

/// A time loaded from `peers.json` has no monotonic reading (dcrd's
/// `time.Unix`), so the wall clock decides for it, in dcrd as here.
#[test]
fn a_loaded_attempt_time_is_tested_on_the_wall_clock() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clocks = fresh_clocks();
    let mut am = clocks.manager(&dir);
    let key = (0..32).map(|_| "0").collect::<Vec<_>>().join(",");
    let last_attempt = WALL / NANOS_PER_SEC - 60;
    am.deserialize_peers(&format!(
        r#"{{"Version":1,"Key":[{key}],"Addresses":[{{"Addr":"1.2.3.4:9108","Src":"1.2.3.4:9108","Attempts":1,"TimeStamp":0,"LastAttempt":{last_attempt},"LastSuccess":0}}],"NewBuckets":[["1.2.3.4:9108"]],"TriedBuckets":[]}}"#
    ))
    .expect("loads");
    let ka = am.known_address("1.2.3.4:9108").expect("loaded");
    let ka = ka.lock().expect("lock");
    assert_eq!(
        ka.last_attempt(),
        Some(GoTime::wall(last_attempt * NANOS_PER_SEC))
    );
    assert_eq!(ka.chance(clocks.now()), 0.01, "a minute ago on the wall");
    clocks.step(10 * MINUTE, 0);
    assert_eq!(ka.chance(clocks.now()), 1.0 / 1.5, "eleven minutes ago");
}
