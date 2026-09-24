// SPDX-License-Identifier: ISC
//! The seeded addresses take their source from the seeder host resolved
//! through the daemon's lookup routing.
//!
//! dcrd's `querySeeders` resolves the seeder with `dcrdLookup(seeder)`,
//! which under `--proxy` (without `--noonion`) is a Tor RESOLVE through
//! the proxy.  The port resolved it with the system resolver whatever
//! the routing, so every seeding round of a proxied node sent the
//! seeder names out as clear DNS queries from the node's own address.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use dcroxide_addrmgr::{AddrManager, PEERS_FILENAME, SeederTransport};
use dcroxide_node::seeding::start_seeding_with_lookup;

/// A transport answering every request with the scripted body.
struct ScriptedTransport {
    body: Vec<u8>,
    calls: Arc<AtomicUsize>,
}

impl SeederTransport for ScriptedTransport {
    fn get(&mut self, _url: &str) -> Result<(u32, Vec<u8>), String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok((200, self.body.clone()))
    }
}

#[test]
fn seeded_addresses_take_the_routed_lookup_as_their_source() {
    let dir = tempfile::tempdir().expect("temp dir");
    let addr_manager = Arc::new(Mutex::new(AddrManager::new(dir.path())));
    let body = br#"{"host":"8.8.8.5:19108","services":1,"pver":6}"#.to_vec();
    let calls = Arc::new(AtomicUsize::new(0));
    let transport_calls = Arc::clone(&calls);

    // A `.invalid` seeder never resolves through a real resolver, so
    // the source below can only come from the routed lookup.
    let (asked, asked_rx) = mpsc::channel();
    let boot = start_seeding_with_lookup(
        vec!["seed.dcroxide.invalid".to_string()],
        Arc::clone(&addr_manager),
        1,
        move || ScriptedTransport {
            body: body.clone(),
            calls: Arc::clone(&transport_calls),
        },
        move |host: &str| {
            let _ = asked.send(host.to_string());
            Ok(vec!["192.0.2.44".parse().expect("ip")])
        },
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let known = addr_manager
            .lock()
            .expect("addrmgr")
            .known_address("8.8.8.5:19108")
            .is_some();
        if known {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    boot.shutdown();
    assert_eq!(calls.load(Ordering::SeqCst), 1, "one successful round");
    assert_eq!(
        asked_rx.recv_timeout(Duration::from_secs(1)).as_deref(),
        Ok("seed.dcroxide.invalid"),
        "the seeder host resolves through the given lookup"
    );

    // The source is the lookup's answer on the HTTPS port, not the
    // fallback to the first seeded address.
    addr_manager
        .lock()
        .expect("addrmgr")
        .save_peers()
        .expect("save peers");
    let peers = std::fs::read_to_string(dir.path().join(PEERS_FILENAME)).expect("peers file");
    assert!(
        peers.contains("\"Src\":\"192.0.2.44:443\""),
        "the seeded address's source must be the resolved seeder: {peers}"
    );
}
