// SPDX-License-Identifier: ISC
//! The automatic outbound reservation sequence (dcrd
//! `targetOutboundHandler`) as a core method.  It used to be written out
//! in the daemon's fill loop, with a hand-built unwind in each failure
//! branch, where one missed release would shrink outbound capacity for
//! good and no test in this crate could see it.

use dcroxide_addrmgr::{NetAddress, NetAddressType, new_net_address_from_params};
use dcroxide_connmgr::manager::{ClosePlan, ConnManager, ConnRecord, ManagerConfig};
use dcroxide_connmgr::{AutoBegin, AutoPermits, ConnectionType, SystemCsprng};
use dcroxide_wire::ServiceFlag;

/// An arbitrary current time: every candidate below was last tried at
/// 0, well outside the ten-minute recent-attempt window.
const NOW: i64 = 1_700_000_000_000_000_000;

fn v4(a: u8, b: u8, c: u8, d: u8) -> NetAddress {
    new_net_address_from_params(NetAddressType::IPv4, &[a, b, c, d], 9108, 0, ServiceFlag(0))
        .expect("v4 addr")
}

fn manager(cfg: ManagerConfig) -> ConnManager {
    ConnManager::new(cfg, &mut SystemCsprng::default())
}

/// A source that offers `addr` every time, never tried before.
fn offering(addr: &NetAddress) -> impl FnMut() -> Result<(NetAddress, i64), String> + use<> {
    let addr = addr.clone();
    move || Ok((addr.clone(), 0))
}

/// Nothing is held: no permit, no group entry for `addr`, no pending
/// dial and no host permit.
fn assert_nothing_held(manager: &ConnManager, addr: &NetAddress, tag: &str) {
    assert_eq!(
        manager.active_outbounds_sem.used(),
        0,
        "{tag}: outbound permit"
    );
    assert_eq!(
        manager.total_normal_conns_sem.used(),
        0,
        "{tag}: total permit"
    );
    assert_eq!(
        manager.outbound_groups.group_count(addr),
        0,
        "{tag}: group entry"
    );
    let (_, pending, _, _, per_host) = manager.map_sizes();
    assert_eq!(pending, 0, "{tag}: pending dial");
    assert_eq!(per_host, 0, "{tag}: host permit");
}

/// A pass that finds no free permit holds nothing afterwards, whichever
/// of the two semaphores was full.
#[test]
fn an_attempt_without_a_free_permit_holds_nothing() {
    let addr = v4(192, 0, 2, 1);

    // The active-outbounds permit is taken.
    let mut full_outbound = manager(ManagerConfig {
        target_outbound: 1,
        ..ManagerConfig::default()
    });
    assert!(full_outbound.active_outbounds_sem.try_acquire());
    assert_eq!(
        full_outbound.auto_outbound_begin(&mut offering(&addr), NOW),
        AutoBegin::PermitsExhausted
    );
    assert_eq!(full_outbound.active_outbounds_sem.used(), 1);
    assert_eq!(full_outbound.total_normal_conns_sem.used(), 0);

    // The total-connections permit is taken: the outbound permit the
    // pass drew first goes back.
    let mut full_total = manager(ManagerConfig {
        max_normal_conns: 1,
        ..ManagerConfig::default()
    });
    assert!(full_total.total_normal_conns_sem.try_acquire());
    assert_eq!(
        full_total.auto_outbound_begin(&mut offering(&addr), NOW),
        AutoBegin::PermitsExhausted
    );
    assert_eq!(full_total.active_outbounds_sem.used(), 0);
    assert_eq!(full_total.total_normal_conns_sem.used(), 1);
    assert_eq!(full_total.outbound_groups.group_count(&addr), 0);
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
    let mut failing = || Err::<(NetAddress, i64), String>("no valid connect address".to_string());
    assert_eq!(
        manager.auto_outbound_begin(&mut failing, NOW),
        AutoBegin::Failed
    );
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
        manager.auto_outbound_begin(&mut offering(&addr), NOW),
        AutoBegin::Failed
    );
    manager.release_host_permit(&addr);
    assert_nothing_held(&manager, &addr, "host limit");

    // The address is already being dialed: the host permit the attempt
    // took goes back too.
    let pending = manager.begin_dial(&addr, None).expect("pending dial");
    assert_eq!(
        manager.auto_outbound_begin(&mut offering(&addr), NOW),
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
    } = manager.auto_outbound_begin(&mut offering(&addr), NOW)
    else {
        panic!("expected a registered dial");
    };
    assert_eq!(dialed, addr);
    assert!(host_permit_reserved);
    assert_eq!(manager.active_outbounds_sem.used(), 1);
    assert_eq!(manager.total_normal_conns_sem.used(), 1);
    assert_eq!(manager.outbound_groups.group_count(&addr), 1);
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
    } = manager.auto_outbound_begin(&mut offering(&addr), NOW)
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
/// handler blocking in its second acquire), and the rest through
/// `auto_outbound_reserve`, which unwinds a failure as
/// `auto_outbound_begin` does and registers the dial under the same
/// close plan.
#[test]
fn a_parked_attempt_resumes_and_reserves_through_the_core() {
    let mut manager = manager(ManagerConfig {
        max_normal_conns: 1,
        max_conns_per_host: 1,
        ..ManagerConfig::default()
    });
    let addr = v4(203, 0, 113, 1);

    // Another connection holds the only total permit: the attempt parks
    // with its outbound permit, and the release hands it the total one.
    assert!(manager.total_normal_conns_sem.try_acquire());
    assert_eq!(manager.auto_outbound_acquire(), AutoPermits::Parked);
    assert_eq!(
        manager.active_outbounds_sem.used(),
        1,
        "outbound permit kept"
    );
    assert!(manager.total_normal_conns_sem.is_waiting());
    assert!(
        manager.total_normal_conns_sem.release(),
        "the release goes to the parked attempt"
    );
    assert!(manager.total_normal_conns_sem.take_grant());
    assert_eq!(manager.total_normal_conns_sem.used(), 1);

    // A failed pick gives both permits back.
    assert_eq!(
        manager.auto_outbound_reserve(Err("no valid connect address".to_string())),
        AutoBegin::Failed
    );
    assert_nothing_held(&manager, &addr, "failed pick");

    // With both permits free the attempt holds them at once, and a
    // claimed candidate is registered as a dial.
    assert_eq!(manager.auto_outbound_acquire(), AutoPermits::Held);
    assert!(manager.claim_outbound_candidate(0, &addr, 0, NOW));
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
    assert!(manager.claim_outbound_candidate(0, &addr, 0, NOW));
    assert_eq!(
        manager.auto_outbound_reserve(Ok(addr.clone())),
        AutoBegin::Failed
    );
    manager.dial_failed(pending);
    assert_nothing_held(&manager, &addr, "duplicate dial");
}
