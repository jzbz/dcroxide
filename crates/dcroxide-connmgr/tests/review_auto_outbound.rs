// SPDX-License-Identifier: ISC
//! The automatic outbound reservation sequence (dcrd
//! `targetOutboundHandler`) in the core.  It used to be written out in
//! the daemon's fill loop, with a hand-built unwind in each failure
//! branch, where one missed release would shrink outbound capacity for
//! good and no test in this crate could see it.  The semaphores and the
//! outbound groups cannot be written directly outside the core now, so
//! these tests reserve permits through the manager's own gates as the
//! daemon must: `auto_outbound_acquire`, the pick, then
//! `auto_outbound_reserve`.  A one-call pass that gave the outbound
//! permit back when the total one was full, where dcrd's handler blocks
//! holding it, had no caller outside these tests and is gone.

use dcroxide_addrmgr::{GoTime, NetAddress, NetAddressType, new_net_address_from_params};
use dcroxide_connmgr::manager::{ClosePlan, ConnManager, ConnRecord, ManagerConfig};
use dcroxide_connmgr::{AutoBegin, AutoPermits, ConnectionType, SystemCsprng};
use dcroxide_wire::ServiceFlag;

/// An arbitrary current time: every candidate below was never tried
/// (the zero time), well outside the ten-minute recent-attempt window.
const NOW: GoTime = GoTime {
    wall: 1_700_000_000_000_000_000,
    mono: Some(3_600_000_000_000),
};

fn v4(a: u8, b: u8, c: u8, d: u8) -> NetAddress {
    new_net_address_from_params(NetAddressType::IPv4, &[a, b, c, d], 9108, 0, ServiceFlag(0))
        .expect("v4 addr")
}

fn manager(cfg: ManagerConfig) -> ConnManager {
    ConnManager::new(cfg, &mut SystemCsprng::default())
}

/// A source that offers `addr` every time, never tried before.
fn offering(addr: &NetAddress) -> impl FnMut() -> Result<(NetAddress, GoTime), String> + use<> {
    let addr = addr.clone();
    move || Ok((addr.clone(), GoTime::default()))
}

/// One pass of dcrd `targetOutboundHandler`'s sequence as the daemon
/// runs it, with both permits free: the two permits, `pickOutboundAddr`
/// over the source, then the host permit and the dial registration.
fn attempt(
    manager: &mut ConnManager,
    source: &mut dyn FnMut() -> Result<(NetAddress, GoTime), String>,
) -> AutoBegin {
    assert_eq!(manager.auto_outbound_acquire(), AutoPermits::Held);
    let picked = manager.pick_outbound_addr(source, NOW);
    manager.auto_outbound_reserve(picked)
}

/// Nothing is held: no permit, no group entry for `addr`, no pending
/// dial and no host permit.
fn assert_nothing_held(manager: &ConnManager, addr: &NetAddress, tag: &str) {
    assert_eq!(
        manager.active_outbounds_sem().used(),
        0,
        "{tag}: outbound permit"
    );
    assert_eq!(
        manager.total_normal_conns_sem().used(),
        0,
        "{tag}: total permit"
    );
    assert_eq!(
        manager.outbound_groups().group_count(addr),
        0,
        "{tag}: group entry"
    );
    let (_, pending, _, _, per_host) = manager.map_sizes();
    assert_eq!(pending, 0, "{tag}: pending dial");
    assert_eq!(per_host, 0, "{tag}: host permit");
}

/// With no active-outbounds permit free the attempt takes nothing.  With
/// the total-connections semaphore full it parks holding the outbound
/// permit it drew first, as dcrd's handler blocks in its second acquire
/// still holding the first (`connmanager.go:2156-2163`), and picks no
/// address until a release hands it the total permit.
#[test]
fn an_attempt_without_a_free_permit_waits_as_dcrd_blocks() {
    let addr = v4(192, 0, 2, 1);

    // Another automatic attempt holds the only active-outbounds permit
    // (and a total one).
    let mut full_outbound = manager(ManagerConfig {
        target_outbound: 1,
        ..ManagerConfig::default()
    });
    assert_eq!(full_outbound.auto_outbound_acquire(), AutoPermits::Held);
    assert_eq!(
        full_outbound.auto_outbound_acquire(),
        AutoPermits::Exhausted
    );
    assert!(!full_outbound.auto_outbound_parked());
    assert_eq!(full_outbound.active_outbounds_sem().used(), 1);
    assert_eq!(full_outbound.total_normal_conns_sem().used(), 1);
    assert_eq!(full_outbound.outbound_groups().group_count(&addr), 0);

    // A manual connection to a loopback address, whose outbound group
    // (`local`) is not the documentation address's (`unroutable`), holds
    // the only total-connections permit.
    let mut full_total = manager(ManagerConfig {
        max_normal_conns: 1,
        ..ManagerConfig::default()
    });
    full_total
        .connect_begin(&v4(127, 0, 0, 1))
        .expect("the only total permit");
    assert_eq!(full_total.auto_outbound_acquire(), AutoPermits::Parked);
    assert!(full_total.auto_outbound_parked());
    assert_eq!(full_total.active_outbounds_sem().used(), 1, "kept");
    assert_eq!(full_total.total_normal_conns_sem().used(), 1);
    assert_eq!(full_total.outbound_groups().group_count(&addr), 0);
}

/// Every way an attempt can fail after taking its permits gives back
/// everything it reserved.
#[test]
fn every_failed_automatic_attempt_releases_its_reservations() {
    let mut manager = manager(ManagerConfig {
        max_conns_per_host: 1,
        ..ManagerConfig::default()
    });
    let addr = v4(192, 0, 2, 1);

    // The address source fails.
    let mut failing =
        || Err::<(NetAddress, GoTime), String>("no valid connect address".to_string());
    assert_eq!(attempt(&mut manager, &mut failing), AutoBegin::Failed);
    assert_nothing_held(&manager, &addr, "source failure");

    // The host is at its connection limit: the picked address's group
    // entry goes back with the permits.
    assert!(
        manager
            .maybe_reserve_host_permit(&addr)
            .expect("the host's only permit"),
        "the host permit applies to a routable address"
    );
    assert_eq!(
        attempt(&mut manager, &mut offering(&addr)),
        AutoBegin::Failed
    );
    manager.release_host_permit(&addr);
    assert_nothing_held(&manager, &addr, "host limit");

    // The address is already being dialed: the host permit the attempt
    // took goes back too.
    let pending = manager.begin_dial(&addr, None).expect("pending dial");
    assert_eq!(
        attempt(&mut manager, &mut offering(&addr)),
        AutoBegin::Failed
    );
    manager.dial_failed(pending);
    assert_nothing_held(&manager, &addr, "duplicate dial");
}

/// A registered dial holds both permits, the group entry and the host
/// permit, and the close plan it hands the daemon gives all of them
/// back, whether the dial fails or the connection later closes.
#[test]
fn a_registered_automatic_dial_releases_through_its_close_plan() {
    let mut manager = manager(ManagerConfig {
        max_conns_per_host: 1,
        ..ManagerConfig::default()
    });
    let addr = v4(198, 51, 100, 1);

    // The dial fails.
    let AutoBegin::Dial {
        id,
        addr: dialed,
        host_permit_reserved,
    } = attempt(&mut manager, &mut offering(&addr))
    else {
        panic!("expected a registered dial");
    };
    assert_eq!(dialed, addr);
    assert!(host_permit_reserved);
    assert_eq!(manager.active_outbounds_sem().used(), 1);
    assert_eq!(manager.total_normal_conns_sem().used(), 1);
    assert_eq!(manager.outbound_groups().group_count(&addr), 1);
    assert_eq!(manager.map_sizes().4, 1, "the host permit is held");
    manager.dial_failed(id);
    manager.run_close_plan(&ConnRecord {
        id,
        conn_type: ConnectionType::Outbound,
        remote_addr: dialed,
        close_plan: ClosePlan::auto_outbound(host_permit_reserved),
    });
    assert_nothing_held(&manager, &addr, "failed dial");

    // The dial succeeds and the connection closes later.
    let AutoBegin::Dial {
        id,
        addr: dialed,
        host_permit_reserved,
    } = attempt(&mut manager, &mut offering(&addr))
    else {
        panic!("expected a registered dial");
    };
    manager
        .dial_succeeded(
            id,
            &dialed,
            ConnectionType::Outbound,
            ClosePlan::auto_outbound(host_permit_reserved),
        )
        .expect("the dial is still pending");
    manager.conn_closed(id).expect("the connection is active");
    assert_nothing_held(&manager, &addr, "closed connection");
}

/// The daemon's fill runs the same sequence in phases, so it can draw
/// candidates with its lock on the manager released: the permits
/// through `auto_outbound_acquire`, which parks on a full
/// total-connections semaphore still holding the outbound permit (dcrd's
/// handler blocking in its second acquire; `auto_outbound_parked`
/// reports the wait and `auto_outbound_take_grant` collects the permit a
/// release hands over), and the rest through
/// `auto_outbound_reserve`, which unwinds a failure and registers the
/// dial under the same close plan.
#[test]
fn a_parked_attempt_resumes_and_reserves_through_the_core() {
    let mut manager = manager(ManagerConfig {
        max_normal_conns: 1,
        max_conns_per_host: 1,
        ..ManagerConfig::default()
    });
    let addr = v4(203, 0, 113, 1);

    // A manual connection holds the only total permit: the attempt parks
    // with its outbound permit, and the manual dial's unwind hands it the
    // total one, which it collects exactly once.
    let manual = v4(198, 51, 100, 1);
    let plan = manager
        .connect_begin(&manual)
        .expect("the only total permit");
    assert!(!manager.auto_outbound_parked());
    assert_eq!(manager.auto_outbound_acquire(), AutoPermits::Parked);
    assert!(manager.auto_outbound_parked());
    assert_eq!(
        manager.active_outbounds_sem().used(),
        1,
        "outbound permit kept"
    );
    assert!(
        !manager.auto_outbound_take_grant(),
        "nothing handed over yet"
    );
    manager.connect_unwind(&manual, &plan);
    assert!(!manager.auto_outbound_parked());
    assert_eq!(
        manager.total_normal_conns_sem().used(),
        1,
        "the release goes to the parked attempt"
    );
    assert!(manager.auto_outbound_take_grant());
    assert!(!manager.auto_outbound_take_grant());
    assert_eq!(manager.total_normal_conns_sem().used(), 1);

    // A failed pick gives both permits back.
    assert_eq!(
        manager.auto_outbound_reserve(Err("no valid connect address".to_string())),
        AutoBegin::Failed
    );
    assert_nothing_held(&manager, &addr, "failed pick");

    // With both permits free the attempt holds them at once, and a
    // claimed candidate is registered as a dial.
    assert_eq!(manager.auto_outbound_acquire(), AutoPermits::Held);
    assert!(manager.claim_outbound_candidate(0, &addr, GoTime::default(), NOW));
    let AutoBegin::Dial {
        id,
        addr: dialed,
        host_permit_reserved,
    } = manager.auto_outbound_reserve(Ok(addr.clone()))
    else {
        panic!("expected a registered dial");
    };
    assert!(host_permit_reserved);
    manager.dial_failed(id);
    manager.run_close_plan(&ConnRecord {
        id,
        conn_type: ConnectionType::Outbound,
        remote_addr: dialed,
        close_plan: ClosePlan::auto_outbound(host_permit_reserved),
    });
    assert_nothing_held(&manager, &addr, "failed dial");

    // A dial that cannot be registered (the address is already being
    // dialed) unwinds its group entry and host permit with the permits.
    let pending = manager.begin_dial(&addr, None).expect("pending dial");
    assert_eq!(manager.auto_outbound_acquire(), AutoPermits::Held);
    assert!(manager.claim_outbound_candidate(0, &addr, GoTime::default(), NOW));
    assert_eq!(
        manager.auto_outbound_reserve(Ok(addr.clone())),
        AutoBegin::Failed
    );
    manager.dial_failed(pending);
    assert_nothing_held(&manager, &addr, "duplicate dial");
}
