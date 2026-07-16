// SPDX-License-Identifier: ISC
//! Seeder bootstrap — the daemon driver for the ported HTTPS seeder
//! (dcrd `server.querySeeders` over `connmgr.SeedAddrs`).
//!
//! Each configured seeder is queried on its own thread through a
//! TLS-capable HTTP transport, and the discovered addresses land in the
//! shared address manager with the seeder's resolved IP as their
//! source, giving the automatic dialer its bootstrap candidates.  When
//! every seeder fails and the manager still needs addresses, the round
//! is retried with dcrd's one-to-ten-second backoff until shutdown.

use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dcroxide_addrmgr::AddrManager;
use std::io::Read;

use dcroxide_connmgr::{HttpsSeederFilters, MAX_RESP_SIZE, SeedEnv, SeederTransport, seed_addrs};

/// The TLS-capable seeder transport over `ureq` (dcrd's `dcrdDial`
/// behind Go's `http.Client`; the proxy configuration plugs in with the
/// Tor/proxy piece).
pub struct UreqTransport {
    agent: ureq::Agent,
}

impl UreqTransport {
    /// A transport with dcrd's one-minute per-seeder timeout.
    pub fn new() -> UreqTransport {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(60)))
            // The seeder logic inspects the status itself.
            .http_status_as_error(false)
            .build();
        UreqTransport {
            agent: config.new_agent(),
        }
    }
}

impl Default for UreqTransport {
    fn default() -> Self {
        UreqTransport::new()
    }
}

impl SeederTransport for UreqTransport {
    fn get(&mut self, url: &str) -> Result<(u32, Vec<u8>), String> {
        let mut response = self
            .agent
            .get(url)
            .call()
            .map_err(|e| format!("seeder request failed: {e}"))?;
        let status = u32::from(response.status().as_u16());
        // Read at most the connmgr's response cap off the wire from an
        // untrusted seeder (dcrd's `io.LimitReader(resp.Body,
        // maxNodes*maxAddrLen)`), rather than ureq's 10 MiB default; a
        // larger body is truncated to the cap, not rejected.  `seed_addrs`
        // truncates to the same cap again as a safety net.
        let mut body = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(MAX_RESP_SIZE as u64)
            .read_to_end(&mut body)
            .map_err(|e| format!("seeder response read failed: {e}"))?;
        Ok((status, body))
    }
}

/// The system clock and randomness stamping discovered addresses (the
/// seeder backdates each between three and seven days).
pub struct SystemSeedEnv;

impl SeedEnv for SystemSeedEnv {
    fn now_nanos(&mut self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0)
    }

    fn rand_duration(&mut self, max_nanos: i64) -> i64 {
        let mut buf = [0u8; 8];
        getrandom::fill(&mut buf).expect("system random source");
        u64::from_le_bytes(buf)
            .checked_rem(max_nanos.max(1) as u64)
            .unwrap_or(0) as i64
    }
}

/// The running seeder bootstrap; dropping it (or calling
/// [`SeederBoot::shutdown`]) stops the retry loop.
pub struct SeederBoot {
    stop: mpsc::Sender<()>,
    thread: Option<JoinHandle<()>>,
}

impl SeederBoot {
    /// Stop the bootstrap and wait for its round to finish.
    pub fn shutdown(mut self) {
        self.stop_thread();
    }

    fn stop_thread(&mut self) {
        let (closed, _) = mpsc::channel();
        self.stop = closed;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for SeederBoot {
    fn drop(&mut self) {
        self.stop_thread();
    }
}

/// Query the network's seeders and feed the discovered addresses into
/// the address manager (dcrd `querySeeders` launched from `Run` when
/// seeding is enabled).  `transport_factory` builds the per-seeder
/// transport, letting tests script the responses.
pub fn start_seeding<T, F>(
    seeders: Vec<String>,
    addr_manager: Arc<Mutex<AddrManager>>,
    required_services: u64,
    transport_factory: F,
) -> SeederBoot
where
    T: SeederTransport,
    F: Fn() -> T + Send + Sync + 'static,
{
    let (stop, stopped) = mpsc::channel::<()>();
    let thread = thread::spawn(move || {
        let filters = HttpsSeederFilters::default().services(required_services);
        let factory = Arc::new(transport_factory);
        // dcrd retries the whole round with a growing backoff while
        // every seeder fails and the manager still needs addresses.
        let mut backoff = Duration::from_secs(1);
        loop {
            let mut err_count = 0usize;
            let mut rounds = Vec::new();
            for seeder in &seeders {
                let seeder = seeder.clone();
                let filters = filters.clone();
                let factory = Arc::clone(&factory);
                rounds.push(thread::spawn(move || {
                    let mut transport = factory();
                    let mut env = SystemSeedEnv;
                    seed_addrs(&seeder, &mut transport, &mut env, &filters)
                        .map(|addrs| (seeder, addrs))
                }));
            }
            for round in rounds {
                match round.join() {
                    Ok(Ok((seeder, addrs))) => {
                        if addrs.is_empty() {
                            continue;
                        }
                        add_seeded(&addr_manager, &seeder, addrs);
                    }
                    _ => err_count = err_count.saturating_add(1),
                }
            }

            let need_more = addr_manager
                .lock()
                .expect("addrmgr mutex poisoned")
                .need_more_addresses();
            if err_count < seeders.len() || !need_more {
                return;
            }

            // Wait out the backoff unless shutdown arrives first.
            match stopped.recv_timeout(backoff) {
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
            }
            if backoff < Duration::from_secs(10) {
                backoff = backoff.saturating_add(Duration::from_secs(1));
            }
        }
    });
    SeederBoot {
        stop,
        thread: Some(thread),
    }
}

/// Add a seeder's discovered addresses with the seeder's resolved IP
/// as their source, falling back to the first returned address when
/// the lookup fails right after succeeding (dcrd `querySeeders`'s
/// source selection).
fn add_seeded(
    addr_manager: &Arc<Mutex<AddrManager>>,
    seeder: &str,
    addrs: Vec<dcroxide_wire::NetAddress>,
) {
    const HTTPS_PORT: u16 = 443;
    let addresses = crate::server::wire_to_addrmgr_net_addresses(&addrs);
    let src = (seeder, HTTPS_PORT)
        .to_socket_addrs()
        .ok()
        .and_then(|mut ips| ips.next())
        .and_then(|socket| {
            crate::peerconn::net_address_from_socket(socket, Default::default()).ok()
        })
        .map(|wire| crate::server::wire_to_addrmgr_net_address(&wire))
        .unwrap_or_else(|| addresses[0].clone());
    addr_manager
        .lock()
        .expect("addrmgr mutex poisoned")
        .add_addresses(&addresses, &src);
}

/// The interval between periodic address-book dumps (dcrd addrmgr
/// `dumpAddressInterval`).
pub const DUMP_ADDRESS_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// The running address-book dump ticker; dropping the stop sender
/// through [`AddressDump::shutdown`] ends the loop.
pub struct AddressDump {
    stop: mpsc::Sender<()>,
    join: Option<JoinHandle<()>>,
}

impl AddressDump {
    /// Stop the ticker and wait for it (the daemon's final `savePeers`
    /// runs separately at shutdown, like dcrd's address handler saving
    /// once more after its loop breaks).
    pub fn shutdown(mut self) {
        let _ = self.stop.send(());
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Start the periodic address-book dump (the ticker half of dcrd
/// addrmgr's `addressHandler`): every interval the shared manager
/// saves its peers file — a no-op when nothing changed, exactly
/// dcrd's `savePeers` dirty gate.
pub fn start_address_dump(
    addr_manager: Arc<Mutex<AddrManager>>,
    interval: Duration,
) -> AddressDump {
    let (stop, stopped) = mpsc::channel::<()>();
    let join = thread::spawn(move || {
        // A stop signal or a dropped sender ends the loop; a timeout
        // is the tick.
        while let Err(mpsc::RecvTimeoutError::Timeout) = stopped.recv_timeout(interval) {
            if let Err(e) = addr_manager
                .lock()
                .expect("addr manager mutex poisoned")
                .save_peers()
            {
                // dcrd's savePeers logs and carries on.
                println!("[ERR] AMGR: Unable to save peers: {e}");
            }
        }
    });
    AddressDump {
        stop,
        join: Some(join),
    }
}
