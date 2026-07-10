// SPDX-License-Identifier: ISC
//! Checks for the seeder bootstrap driver: a scripted seeder response
//! lands its discovered addresses in the address manager, and a failing
//! seeder round retries with backoff until shutdown.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dcroxide_addrmgr::{AddrManager, NetAddressType};
use dcroxide_connmgr::SeederTransport;
use dcroxide_node::seeding::start_seeding;

/// A transport answering every request with the scripted body.
struct ScriptedTransport {
    status: u32,
    body: Vec<u8>,
    calls: Arc<AtomicUsize>,
}

impl SeederTransport for ScriptedTransport {
    fn get(&mut self, _url: &str) -> Result<(u32, Vec<u8>), String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok((self.status, self.body.clone()))
    }
}

#[test]
fn seeded_addresses_land_in_the_manager() {
    let dir = tempfile::tempdir().expect("temp dir");
    let addr_manager = Arc::new(Mutex::new(AddrManager::new(dir.path())));

    // Two routable nodes in the seeder's JSON stream shape.
    let body = br#"{"host":"8.8.8.5:19108","services":1,"pver":6}
{"host":"8.8.7.5:19108","services":1,"pver":6}"#
        .to_vec();
    let calls = Arc::new(AtomicUsize::new(0));
    let transport_calls = Arc::clone(&calls);

    let boot = start_seeding(
        vec!["192.0.2.10".to_string()],
        Arc::clone(&addr_manager),
        1,
        move || ScriptedTransport {
            status: 200,
            body: body.clone(),
            calls: Arc::clone(&transport_calls),
        },
    );

    // The discovered addresses appear in the manager and the round
    // finishes without retrying.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut known = 0;
    while known < 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
        // One lock per statement: both guards alive in one expression
        // would self-deadlock on the non-reentrant mutex.
        let mgr = addr_manager.lock().expect("addrmgr");
        known = mgr.known_address("8.8.8.5:19108").is_some() as usize
            + mgr.known_address("8.8.7.5:19108").is_some() as usize;
    }
    assert_eq!(known, 2, "both seeded addresses should be known");

    boot.shutdown();
    assert_eq!(calls.load(Ordering::SeqCst), 1, "one successful round");
    let _ = NetAddressType::IPv4;
}

#[test]
fn failing_seeders_retry_until_shutdown() {
    let dir = tempfile::tempdir().expect("temp dir");
    let addr_manager = Arc::new(Mutex::new(AddrManager::new(dir.path())));

    let calls = Arc::new(AtomicUsize::new(0));
    let transport_calls = Arc::clone(&calls);
    let boot = start_seeding(
        vec!["192.0.2.10".to_string()],
        Arc::clone(&addr_manager),
        1,
        move || ScriptedTransport {
            status: 500,
            body: Vec::new(),
            calls: Arc::clone(&transport_calls),
        },
    );

    // The failing round retries on the backoff; after a bit more than
    // a second at least a second attempt has run.
    let deadline = Instant::now() + Duration::from_secs(5);
    while calls.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(calls.load(Ordering::SeqCst) >= 2, "the round should retry");

    // Shutdown interrupts the backoff wait promptly.
    let start = Instant::now();
    boot.shutdown();
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "shutdown should interrupt the backoff"
    );
}
