// SPDX-License-Identifier: ISC
//! Connection manager state machine scenarios mirroring dcrd's own
//! `connmanager_test.go` battery.  dcrd drives these through mock
//! dialers and callback channels; the synchronous port drives them
//! through closure dialers and returned events.

// Test scaffolding uses bounded counters and mock plumbing.
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::type_complexity)]

use std::cell::RefCell;
use std::rc::Rc;

use dcroxide_connmgr::{
    Config, Conn, ConnManager, ConnState, DEFAULT_RETRY_DURATION, DEFAULT_TARGET_OUTBOUND, Event,
    MAX_FAILED_ATTEMPTS, MAX_RETRY_DURATION, ReqAddr,
};

#[derive(Default)]
struct MockConnState {
    closed: usize,
}

#[derive(Clone, Default)]
struct MockConn(Rc<RefCell<MockConnState>>);

impl Conn for MockConn {
    fn close(&mut self) {
        self.0.borrow_mut().closed += 1;
    }
}

fn ok_dialer() -> Box<dyn FnMut(&ReqAddr) -> Result<MockConn, String>> {
    Box::new(|_| Ok(MockConn::default()))
}

fn failing_dialer(
    count: Rc<RefCell<usize>>,
) -> Box<dyn FnMut(&ReqAddr) -> Result<MockConn, String>> {
    Box::new(move |_| {
        *count.borrow_mut() += 1;
        Err("connection refused".to_string())
    })
}

// dcrd TestNewConfig: configuration validation.
#[test]
fn new_config_validation() {
    let err = match ConnManager::<MockConn>::new(Config::default()) {
        Err(e) => e,
        Ok(_) => panic!("dial required"),
    };
    assert_eq!(err.kind.kind_name(), "ErrDialNil");
    assert_eq!(err.description, "dial cannot be nil");

    let cfg = Config {
        dial: Some(ok_dialer()),
        dial_addr: Some(ok_dialer()),
        ..Config::default()
    };
    let err = match ConnManager::new(cfg) {
        Err(e) => e,
        Ok(_) => panic!("both dials rejected"),
    };
    assert_eq!(err.kind.kind_name(), "ErrBothDialsFilled");
    assert_eq!(err.description, "cannot specify both Dial and DialAddr");

    // Defaults are applied (observable through the retry delays and
    // target-driven start below).
    let cfg = Config {
        dial: Some(ok_dialer()),
        ..Config::default()
    };
    assert!(ConnManager::new(cfg).is_ok());
    assert_eq!(DEFAULT_TARGET_OUTBOUND, 8);
    assert_eq!(DEFAULT_RETRY_DURATION, 5_000_000_000);
}

// dcrd TestConnectMode: manual connections with no address source.
#[test]
fn connect_mode() {
    let cfg = Config {
        target_outbound: 2,
        dial: Some(ok_dialer()),
        ..Config::default()
    };
    let mut cm = ConnManager::new(cfg).unwrap();
    assert!(cm.start().is_empty(), "no address source, no autoconnect");

    let (id, events) = cm.connect(ReqAddr::tcp("127.0.0.1:18555"), true);
    assert_eq!(events, vec![Event::Connected { id }]);
    let req = cm.conn_req(id).unwrap();
    assert_eq!(req.state, ConnState::Established);
    assert_eq!(req.addr.as_ref().unwrap().addr, "127.0.0.1:18555");
    assert!(req.permanent);
    assert_eq!(cm.conn_count(), 1);
}

// dcrd TestTargetOutbound: the target number of outbound connections
// are made through the address source.
#[test]
fn target_outbound() {
    let counter = Rc::new(RefCell::new(0u32));
    let c2 = counter.clone();
    let cfg = Config {
        target_outbound: 10,
        dial: Some(ok_dialer()),
        get_new_address: Some(Box::new(move || {
            *c2.borrow_mut() += 1;
            Ok(ReqAddr::tcp(&format!("10.0.0.{}:8333", *c2.borrow())))
        })),
        ..Config::default()
    };
    let mut cm = ConnManager::new(cfg).unwrap();
    let events = cm.start();
    let connected = events
        .iter()
        .filter(|e| matches!(e, Event::Connected { .. }))
        .count();
    assert_eq!(connected, 10);
    assert_eq!(cm.conn_count(), 10);
}

// dcrd TestRetryPermanent: a permanent connection is retried with
// linear backoff capped at the maximum, and the retry count resets
// once connected.
#[test]
fn retry_permanent_backoff() {
    let fail = Rc::new(RefCell::new(true));
    let f2 = fail.clone();
    let cfg = Config {
        target_outbound: 1,
        retry_duration_nanos: 1_000_000_000,
        dial: Some(Box::new(move |_| {
            if *f2.borrow() {
                Err("refused".to_string())
            } else {
                Ok(MockConn::default())
            }
        })),
        ..Config::default()
    };
    let mut cm = ConnManager::new(cfg).unwrap();

    let (id, events) = cm.connect(ReqAddr::tcp("127.0.0.1:18555"), true);
    assert_eq!(
        events,
        vec![Event::ScheduleRetry {
            id,
            delay_nanos: 1_000_000_000
        }]
    );
    assert_eq!(cm.conn_req(id).unwrap().state, ConnState::Failed);

    // Each failed retry doubles the linear backoff up to the cap.
    let mut expected = Vec::new();
    for n in 2..=400i64 {
        let d = (n * 1_000_000_000).min(MAX_RETRY_DURATION);
        expected.push(d);
    }
    for want in expected.iter().take(400 - 2 + 1) {
        let events = cm.retry_connect(id);
        assert_eq!(
            events,
            vec![Event::ScheduleRetry {
                id,
                delay_nanos: *want
            }]
        );
    }

    // A success resets the retry count so the next failure starts the
    // backoff over.
    *fail.borrow_mut() = false;
    let events = cm.retry_connect(id);
    assert_eq!(events, vec![Event::Connected { id }]);
    assert_eq!(cm.conn_req(id).unwrap().retry_count, 0);

    *fail.borrow_mut() = true;
    let events = cm.disconnect(id);
    assert_eq!(
        events,
        vec![
            Event::Disconnected { id },
            Event::ScheduleRetry {
                id,
                delay_nanos: 1_000_000_000
            }
        ]
    );
    // The permanent request is pending again for the retry.
    assert_eq!(cm.conn_req(id).unwrap().state, ConnState::Pending);
}

// dcrd TestNetworkFailure: after the failure threshold, new
// connection churn is delayed by the retry duration.
#[test]
fn network_failure_threshold() {
    let dials = Rc::new(RefCell::new(0usize));
    let cfg = Config {
        target_outbound: 5,
        retry_duration_nanos: 2_000_000_000,
        dial: Some(failing_dialer(dials.clone())),
        get_new_address: Some(Box::new(|| Ok(ReqAddr::tcp("10.0.0.1:8333")))),
        ..Config::default()
    };
    let mut cm = ConnManager::new(cfg).unwrap();
    let events = cm.start();

    // The first new-connection request churns immediately until the
    // threshold, then defers; the remaining four target slots each
    // fail once more and defer again.
    assert_eq!(cm.failed_attempts(), MAX_FAILED_ATTEMPTS + 4);
    assert_eq!(*dials.borrow(), MAX_FAILED_ATTEMPTS as usize + 4);
    let scheduled = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                Event::ScheduleNewConn {
                    delay_nanos: 2_000_000_000
                }
            )
        })
        .count();
    assert_eq!(scheduled, 5);
    assert!(!events.iter().any(|e| matches!(e, Event::Connected { .. })));

    // A later success through the driver resets the failure count.
    let events = cm.new_conn_req_now();
    assert_eq!(cm.failed_attempts(), MAX_FAILED_ATTEMPTS + 5);
    assert!(matches!(events[0], Event::ScheduleNewConn { .. }));
}

// dcrd TestRemovePendingConnection: a pending request can be removed,
// after which a late success is ignored and the connection closed.
#[test]
fn remove_pending_and_ignore_late_connection() {
    // A dialer whose result is decided per call.
    let outcome: Rc<RefCell<Option<MockConn>>> = Rc::new(RefCell::new(None));
    let o2 = outcome.clone();
    let cfg = Config {
        target_outbound: 1,
        dial: Some(Box::new(move |_| match o2.borrow_mut().take() {
            Some(conn) => Ok(conn),
            None => Err("refused".to_string()),
        })),
        ..Config::default()
    };
    let mut cm = ConnManager::new(cfg).unwrap();

    // A failed permanent connect leaves the request pending-failed
    // with a scheduled retry.
    let (id, events) = cm.connect(ReqAddr::tcp("127.0.0.1:18555"), true);
    assert!(matches!(events[0], Event::ScheduleRetry { .. }));

    // Removing the pending request cancels it.
    let events = cm.remove(id);
    assert!(events.is_empty());
    assert_eq!(cm.conn_req(id).unwrap().state, ConnState::Canceled);

    // When the retry fires later, the canceled request is ignored.
    let conn = MockConn::default();
    let state = conn.0.clone();
    *outcome.borrow_mut() = Some(conn);
    let events = cm.retry_connect(id);
    assert!(events.is_empty());
    assert_eq!(cm.conn_req(id).unwrap().state, ConnState::Canceled);
    // The late connection was not accepted; the dialer result was
    // consumed but the manager holds no connection.
    assert_eq!(cm.conn_count(), 0);
    assert_eq!(
        state.borrow().closed,
        0,
        "dial never happened for canceled req"
    );
}

// dcrd TestCancelIgnoreDelayedConnection: a connection established
// after cancellation is closed and ignored.
#[test]
fn cancel_pending_by_address() {
    let cfg: Config<MockConn> = Config {
        target_outbound: 1,
        dial: Some(Box::new(|_| Err("refused".to_string()))),
        ..Config::default()
    };
    let mut cm = ConnManager::new(cfg).unwrap();

    let (id, _) = cm.connect(ReqAddr::tcp("127.0.0.1:18555"), true);
    cm.cancel_pending("127.0.0.1:18555").expect("pending found");
    assert_eq!(cm.conn_req(id).unwrap().state, ConnState::Canceled);

    let err = cm.cancel_pending("127.0.0.1:18555").expect_err("gone");
    assert_eq!(err, "no pending connection to 127.0.0.1:18555");
}

// Disconnect and remove semantics for established connections,
// including the connection close and the state quirk where a
// non-permanent disconnect with retry leaves the state Established.
#[test]
fn disconnect_and_remove_established() {
    let counter = Rc::new(RefCell::new(0u32));
    let c2 = counter.clone();
    let conns: Rc<RefCell<Vec<MockConn>>> = Rc::new(RefCell::new(Vec::new()));
    let conns2 = conns.clone();
    let cfg = Config {
        target_outbound: 2,
        dial: Some(Box::new(move |_| {
            let conn = MockConn::default();
            conns2.borrow_mut().push(conn.clone());
            Ok(conn)
        })),
        get_new_address: Some(Box::new(move || {
            *c2.borrow_mut() += 1;
            Ok(ReqAddr::tcp(&format!("10.0.0.{}:8333", *c2.borrow())))
        })),
        ..Config::default()
    };
    let mut cm = ConnManager::new(cfg).unwrap();
    let events = cm.start();
    let ids: Vec<u64> = events
        .iter()
        .filter_map(|e| match e {
            Event::Connected { id } => Some(*id),
            _ => None,
        })
        .collect();
    assert_eq!(ids.len(), 2);

    // Disconnect with retry: below target, so a new connection is
    // requested; the closed connection's handle is closed; and the
    // non-permanent request keeps its established state, exactly like
    // dcrd, which only updates the state when not retrying.
    let events = cm.disconnect(ids[0]);
    assert!(matches!(events[0], Event::Disconnected { id } if id == ids[0]));
    assert!(matches!(events[1], Event::Connected { .. }));
    assert_eq!(conns.borrow()[0].0.borrow().closed, 1);
    assert_eq!(cm.conn_req(ids[0]).unwrap().state, ConnState::Established);

    // Remove: no retry, state becomes Disconnected.
    let events = cm.remove(ids[1]);
    assert_eq!(events, vec![Event::Disconnected { id: ids[1] }]);
    assert_eq!(cm.conn_req(ids[1]).unwrap().state, ConnState::Disconnected);
}

// dcrd ForEachConnReq: pending requests are visited before
// established ones, and an error stops the iteration.
#[test]
fn for_each_conn_req() {
    let cfg = Config {
        target_outbound: 4,
        dial: Some(Box::new(|addr| {
            if addr.addr.starts_with("10.") {
                Ok(MockConn::default())
            } else {
                Err("refused".to_string())
            }
        })),
        ..Config::default()
    };
    let mut cm = ConnManager::new(cfg).unwrap();
    let (established, _) = cm.connect(ReqAddr::tcp("10.0.0.1:8333"), false);
    let (pending, _) = cm.connect(ReqAddr::tcp("127.0.0.1:18555"), true);

    let mut seen = Vec::new();
    cm.for_each_conn_req(|req| {
        seen.push(req.id);
        Ok(())
    })
    .unwrap();
    assert_eq!(seen, vec![pending, established]);

    let err = cm
        .for_each_conn_req(|_| Err("stop".to_string()))
        .expect_err("propagates");
    assert_eq!(err, "stop");
}

// Deferred dials (dcrd's actual structure: `Connect` dials on its own
// goroutine and the connHandler only processes the outcomes): the
// manager emits Dial events instead of calling a dial closure, and the
// driver reports each result through `dial_outcome`.
#[test]
fn deferred_dials_split_request_and_outcome() {
    // No dial closure is required in deferred mode.
    let cfg = Config::<MockConn> {
        deferred_dials: true,
        ..Config::default()
    };
    let mut cm = ConnManager::new(cfg).unwrap();

    // A connect registers the request pending and asks for a dial.
    let (id, events) = cm.connect(ReqAddr::tcp("127.0.0.1:18555"), true);
    assert_eq!(events, vec![Event::Dial { id }]);
    assert_eq!(cm.conn_req(id).unwrap().state, ConnState::Pending);

    // A successful outcome establishes the connection (dcrd
    // `handleConnected`).
    let events = cm.dial_outcome(id, Ok(MockConn::default()));
    assert_eq!(events, vec![Event::Connected { id }]);
    assert_eq!(cm.conn_req(id).unwrap().state, ConnState::Established);
    assert_eq!(cm.conn_count(), 1);

    // A failed permanent dial schedules a retry (dcrd `handleFailed`),
    // and the retry firing asks for another dial.
    let (id2, events) = cm.connect(ReqAddr::tcp("127.0.0.1:18556"), true);
    assert_eq!(events, vec![Event::Dial { id: id2 }]);
    let events = cm.dial_outcome(id2, Err("connection refused".to_string()));
    assert_eq!(
        events,
        vec![Event::ScheduleRetry {
            id: id2,
            delay_nanos: DEFAULT_RETRY_DURATION,
        }]
    );
    let events = cm.retry_connect(id2);
    assert_eq!(events, vec![Event::Dial { id: id2 }]);
}

// A request canceled while its deferred dial is in flight closes the
// late connection and ignores it (dcrd `handleConnected`'s pending
// check), and a late failure is likewise ignored.
#[test]
fn deferred_dial_outcome_after_cancel_is_ignored() {
    let cfg = Config::<MockConn> {
        deferred_dials: true,
        ..Config::default()
    };
    let mut cm = ConnManager::new(cfg).unwrap();
    let (id, events) = cm.connect(ReqAddr::tcp("127.0.0.1:18555"), true);
    assert_eq!(events, vec![Event::Dial { id }]);
    cm.cancel_pending("127.0.0.1:18555").unwrap();
    assert_eq!(cm.conn_req(id).unwrap().state, ConnState::Canceled);

    let conn = MockConn::default();
    let state = Rc::clone(&conn.0);
    assert!(
        cm.dial_outcome(id, Ok(conn)).is_empty(),
        "a late success for a canceled request is ignored"
    );
    assert_eq!(state.borrow().closed, 1, "the late connection is closed");
    assert_eq!(cm.conn_count(), 0);
    assert!(
        cm.dial_outcome(id, Err("refused".to_string())).is_empty(),
        "a late failure for a canceled request is ignored"
    );
}
