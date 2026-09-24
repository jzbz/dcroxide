// SPDX-License-Identifier: ISC
//! The automatic outbound fill's permits and lock scope.
//!
//! A total-connections permit freed while the fill waits on it goes to
//! the fill at once.  dcrd's `targetOutboundHandler` blocks in
//! `totalNormalConnsSem.Acquire` while holding an outbound permit, and
//! the Go runtime hands a blocked channel send the slot inside the very
//! receive (`Release`) that frees it, so an inbound close gives the slot
//! to outbound maintenance before any later inbound connection can take
//! it.  The driver used to give its outbound permit back and poll again
//! only after the retry duration, leaving every slot freed meanwhile to
//! whichever inbound peer arrived first.
//!
//! The fill's address source runs without the connection manager's
//! lock.  dcrd's `pickOutboundAddr` holds only the outbound groups' own
//! mutex while it calls `GetNewAddress`, which takes the address
//! manager's lock, so inbound admission never waits on the address
//! manager; the driver used to call the source under the one lock
//! inbound admission takes.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dcroxide_connmgr::{ConnManager, InboundDecision, ManagerConfig, SystemCsprng};
use dcroxide_node::outbound::{
    OutboundConfig, outbound_channel, socket_addr_to_net_address, start_outbound,
};
use dcroxide_node::runtime::{ConnectedPeers, PeerTemplate};
use dcroxide_wire::{CurrencyNet, ServiceFlag};

/// Poll `cond` until it holds or the timeout elapses.
fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    cond()
}

#[test]
fn a_freed_permit_wakes_the_parked_outbound_fill() {
    // One total permit, one outbound target, and a retry interval far
    // longer than the test, so only a direct wake can resume the fill.
    let mut csprng = SystemCsprng::default();
    let manager = Arc::new(Mutex::new(ConnManager::new(
        ManagerConfig {
            max_normal_conns: 1,
            target_outbound: 1,
            retry_duration_nanos: 60 * 1_000_000_000,
            ..Default::default()
        },
        &mut csprng,
    )));

    // An inbound peer holds the only permit.
    let inbound = socket_addr_to_net_address(&"127.0.0.1:40000".parse().expect("addr"));
    let inbound_id = {
        let mut m = manager.lock().expect("connmgr");
        match m.admit_inbound(
            &inbound,
            1_700_000_000,
            1_700_000_000_000_000_000,
            0,
            &mut csprng,
        ) {
            InboundDecision::Admit {
                require_permit,
                host_permit_reserved,
            } => {
                m.register_inbound(&inbound, require_permit, host_permit_reserved)
                    .id
            }
            other => panic!("unexpected decision {other:?}"),
        }
    };

    // The address source counts the picks; its address refuses
    // connections, so no peer is ever served.
    let dead = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let dead_addr = socket_addr_to_net_address(&dead.local_addr().expect("addr"));
    drop(dead);
    let picks = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&picks);
    let connector = start_outbound(
        OutboundConfig {
            template: PeerTemplate {
                net: CurrencyNet::REG_NET,
                protocol_version: 0,
                services: ServiceFlag::NODE_NETWORK,
                user_agent_name: "dialer".to_string(),
                user_agent_version: "0.1.0".to_string(),
                idle_timeout: Duration::from_secs(3600),
                ping_interval: Duration::from_secs(3600),
                disable_relay_tx: false,
                proxy: String::new(),
                newest_block: None,
            },
            connected: ConnectedPeers::new(),
            server: None,
            manager: Arc::clone(&manager),
            dial_timeout: Duration::from_millis(500),
            dialer: dcroxide_node::socks::NodeDialer::direct(),
            persistent: Vec::new(),
            get_new_address: Some(Box::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok((dead_addr.clone(), 0))
            })),
            addr_manager: None,
        },
        outbound_channel(),
    );

    // The fill takes its outbound permit and parks on the total one.
    assert!(
        wait_until(Duration::from_secs(5), || {
            manager
                .lock()
                .expect("connmgr")
                .total_normal_conns_sem
                .is_waiting()
        }),
        "the fill parks on the exhausted total permit"
    );
    assert_eq!(
        picks.load(Ordering::SeqCst),
        0,
        "no address without a permit"
    );

    // The inbound peer leaves.  Its permit goes to the fill, not back to
    // the pool: a new inbound connection finds no slot.
    {
        let mut m = manager.lock().expect("connmgr");
        m.conn_closed(inbound_id).expect("close");
        let other = socket_addr_to_net_address(&"127.0.0.2:40001".parse().expect("addr"));
        match m.admit_inbound(
            &other,
            1_700_000_000,
            1_700_000_000_000_000_000,
            0,
            &mut csprng,
        ) {
            InboundDecision::Drop { reason } => {
                assert_eq!(reason, "a maximum of 1 connection is allowed");
            }
            other => panic!("the freed slot went to an inbound peer: {other:?}"),
        }
    }

    // And the driver resumes the fill at once rather than a retry
    // interval later.
    assert!(
        wait_until(Duration::from_secs(5), || picks.load(Ordering::SeqCst) > 0),
        "the parked fill must resume when handed the permit"
    );

    connector.shutdown();
}

#[test]
fn the_address_source_runs_without_the_connmgr_lock() {
    let mut csprng = SystemCsprng::default();
    let manager = Arc::new(Mutex::new(ConnManager::new(
        ManagerConfig {
            retry_duration_nanos: 60 * 1_000_000_000,
            ..Default::default()
        },
        &mut csprng,
    )));

    // The first draw reports that it started and then blocks, standing
    // in for an address manager lock held across a peers.json save;
    // later draws find no address.
    let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let mut first = true;
    let connector = start_outbound(
        OutboundConfig {
            template: PeerTemplate {
                net: CurrencyNet::REG_NET,
                protocol_version: 0,
                services: ServiceFlag::NODE_NETWORK,
                user_agent_name: "dialer".to_string(),
                user_agent_version: "0.1.0".to_string(),
                idle_timeout: Duration::from_secs(3600),
                ping_interval: Duration::from_secs(3600),
                disable_relay_tx: false,
                proxy: String::new(),
                newest_block: None,
            },
            connected: ConnectedPeers::new(),
            server: None,
            manager: Arc::clone(&manager),
            dial_timeout: Duration::from_millis(500),
            dialer: dcroxide_node::socks::NodeDialer::direct(),
            persistent: Vec::new(),
            get_new_address: Some(Box::new(move || {
                if std::mem::take(&mut first) {
                    let _ = entered_tx.send(());
                    let _ = release_rx.recv();
                }
                Err("no valid connect address".to_string())
            })),
            addr_manager: None,
        },
        outbound_channel(),
    );

    entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the fill draws an address");

    // While the draw is blocked, inbound admission gets the lock.
    let inbound = socket_addr_to_net_address(&"127.0.0.1:40000".parse().expect("addr"));
    let admitted = wait_until(Duration::from_secs(2), || {
        let Ok(mut m) = manager.try_lock() else {
            return false;
        };
        matches!(
            m.admit_inbound(
                &inbound,
                1_700_000_000,
                1_700_000_000_000_000_000,
                0,
                &mut csprng,
            ),
            InboundDecision::Admit { .. }
        )
    });
    let _ = release_tx.send(());
    assert!(
        admitted,
        "inbound admission must not wait on the address source"
    );

    connector.shutdown();
}
