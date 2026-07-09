// SPDX-License-Identifier: ISC
//! Replay of dcrd's address manager behavior generated inside dcrd's
//! addrmgr package (`data/addrmgr_vectors.txt`): the address key,
//! group key, routability, and reachability grids, the bucket
//! derivations under a pinned key, manager state transitions through
//! adds, attempts, connections, and good promotions including the
//! tried-bucket eviction path, the address cache filtering, the
//! chance and isBad viability values bit for bit through crafted
//! serialized state, `peers.json` cross-loading from dcrd's own
//! serialized output, and the deserialization error cases —
//! comparing the full per-address state (source, attempts, tried
//! flag, references, and bucket placements) after every operation.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use dcroxide_addrmgr::{
    AddrManager, AddrRng, AddressPriority, NetAddress, NetAddressType, encode_host,
    new_net_address_from_params,
};
use dcroxide_testutil::unhex;
use dcroxide_wire::ServiceFlag;

const NANOS_PER_SEC: i64 = 1_000_000_000;

/// A fixed-sequence RNG; the dump only exercises deterministic paths
/// so the values are never consumed except by the reset key fill.
struct StubRng;

impl AddrRng for StubRng {
    fn int_n(&mut self, _n: usize) -> usize {
        0
    }
    fn read(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = 0;
        }
    }
}

fn dump_na(host: &str, port: u16, ts_unix: i64) -> NetAddress {
    let (addr_type, addr_bytes) = encode_host(host);
    new_net_address_from_params(
        addr_type,
        &addr_bytes,
        port,
        ts_unix * NANOS_PER_SEC,
        ServiceFlag::NODE_NETWORK,
    )
    .expect("dump address")
}

fn render_state(am: &AddrManager) -> Vec<String> {
    let (addrs, n_new, n_tried, _) = am.state_snapshot();
    let rows: Vec<String> = addrs
        .iter()
        .map(
            |(key, src, attempts, tried, refs, new_buckets, tried_bucket)| {
                let nb = if new_buckets.is_empty() {
                    "-".to_string()
                } else {
                    new_buckets
                        .iter()
                        .map(|b| b.to_string())
                        .collect::<Vec<_>>()
                        .join(".")
                };
                let tb = tried_bucket.map(|b| b as i64).unwrap_or(-1);
                format!("{key}|{src}|{attempts}|{tried}|{refs}|{nb}|{tb}")
            },
        )
        .collect();
    let addrs_line = if rows.is_empty() {
        "addrs -".to_string()
    } else {
        format!("addrs {}", rows.join(","))
    };
    vec![addrs_line, format!("nums {n_new} {n_tried}")]
}

fn err_kind_or_dash(res: Result<(), dcroxide_addrmgr::AddrError>) -> String {
    match res {
        Ok(()) => "-".to_string(),
        Err(err) => err.kind.kind_name().to_string(),
    }
}

#[test]
fn addrmgr_vectors() {
    let data = include_str!("data/addrmgr_vectors.txt");
    let mut lines = data.lines().peekable();

    let dir = tempfile::tempdir().expect("tempdir");
    let mut now_unix = 0i64;
    let clock_cell = Arc::new(AtomicI64::new(0));
    let clock: dcroxide_addrmgr::Clock = {
        let cell = clock_cell.clone();
        Arc::new(move || cell.load(Ordering::Relaxed))
    };
    let mut am =
        AddrManager::new_with_hooks(dir.path(), clock.clone(), Arc::new(Mutex::new(StubRng)));
    let mut counts = [0usize; 7];

    macro_rules! check_state {
        ($am:expr, $ctx:expr) => {
            for want in render_state($am) {
                let line = lines.next().expect("state line");
                assert_eq!(want, line, "state after {}", $ctx);
            }
            assert_eq!(lines.next(), Some("endstate"), "state end after {}", $ctx);
        };
    }

    let all_filter = |_: NetAddressType| true;
    let v4_filter = |t: NetAddressType| t == NetAddressType::IPv4;

    while let Some(line) = lines.next() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "naprops" => {
                let port: u16 = f[2].parse().expect("port");
                let na = dump_na(f[1], port, now_unix);
                let got = format!(
                    "naprops {} {} {} {} {} {}",
                    f[1],
                    port,
                    na.addr_type as u8,
                    na.key(),
                    na.group_key(),
                    na.is_routable()
                );
                assert_eq!(got, line, "address properties");
                counts[0] += 1;
            }
            "reach" => {
                let local = dump_na(f[1], 9108, now_unix);
                let remote = dump_na(f[2], 9108, now_unix);
                let (good, reach) = am.is_external_addr_candidate(&local, &remote);
                let got = format!(
                    "reach {} {} {} {} {}",
                    f[1], f[2], reach as u8, good, reach as u8
                );
                assert_eq!(got, line, "reachability");
                counts[1] += 1;
            }
            "scenario" => {
                now_unix = f[3].parse().expect("now");
                clock_cell.store(now_unix * NANOS_PER_SEC, Ordering::Relaxed);
                am = AddrManager::new_with_hooks(
                    dir.path(),
                    clock.clone(),
                    Arc::new(Mutex::new(StubRng)),
                );
                let mut key = [0u8; 32];
                key.copy_from_slice(&unhex(f[1]));
                am.set_key(key);
                am.set_tried_bucket_size(f[2].parse().expect("size"));
            }
            "buckets" => {
                let port: u16 = f[2].parse().expect("port");
                let na = dump_na(f[1], port, now_unix);
                let src = dump_na("204.124.8.100", 9108, now_unix);
                let got = format!(
                    "buckets {} {} {} {}",
                    f[1],
                    port,
                    am.new_bucket_index(&na, &src),
                    am.tried_bucket_index(&na)
                );
                assert_eq!(got, line, "bucket derivation");
                counts[2] += 1;
            }
            "add" => {
                let port: u16 = f[2].parse().expect("port");
                let ts: i64 = f[3].parse().expect("ts");
                let na = dump_na(f[1], port, ts);
                let src = dump_na(f[4], 9108, now_unix);
                am.add_addresses(&[na], &src);
                check_state!(&am, line);
                counts[3] += 1;
            }
            "attempt" | "connected" | "good" | "setservices" => {
                let na = na_from_key(f[1], now_unix);
                let res = match f[0] {
                    "attempt" => am.attempt(&na),
                    "connected" => am.connected(&na),
                    "good" => am.good(&na),
                    _ => am.set_services(&na, ServiceFlag(f[2].parse().expect("services"))),
                };
                let want_err = if f[0] == "setservices" { f[3] } else { f[2] };
                assert_eq!(err_kind_or_dash(res), want_err, "{line}");
                // Rows with errors have no state block; peek ahead.
                if lines.peek().is_some_and(|l| l.starts_with("addrs ")) {
                    check_state!(&am, line);
                }
                counts[4] += 1;
            }
            "needmore" => {
                let want: bool = f[1].parse().expect("bool");
                assert_eq!(am.need_more_addresses(), want, "{line}");
            }
            "addrcache" => {
                // The cache is a random subset; only the size is
                // deterministic (dcrd shuffles with crypto/rand).
                let filter = if f[1] == "v4" { v4_filter } else { all_filter };
                let keys: Vec<String> =
                    am.address_cache(filter).iter().map(|na| na.key()).collect();
                let want_count = if f[2] == "-" {
                    0
                } else {
                    f[2].split(',').count()
                };
                assert_eq!(keys.len(), want_count, "{line}");
            }
            "peersjson" => {
                // Load dcrd's own serialized state into a fresh
                // manager and compare against the state emitted for
                // the original manager and the reload.
                let contents = String::from_utf8(unhex(f[1])).expect("utf8 peers file");
                check_state!(&am, line);
                assert_eq!(lines.next(), Some("reload"), "reload marker");
                let mut reloaded = AddrManager::new_with_hooks(
                    dir.path(),
                    clock.clone(),
                    Arc::new(Mutex::new(StubRng)),
                );
                reloaded
                    .deserialize_peers(&contents)
                    .expect("load dcrd peers file");
                check_state!(&reloaded, "reload");

                // The reloaded state must survive this port's own
                // save/load round trip.
                reloaded.save_peers().expect("save peers");
                let saved =
                    std::fs::read_to_string(dir.path().join("peers.json")).expect("read saved");
                let mut round = AddrManager::new_with_hooks(
                    dir.path(),
                    clock.clone(),
                    Arc::new(Mutex::new(StubRng)),
                );
                round.deserialize_peers(&saved).expect("round trip");
                assert_eq!(
                    render_state(&round),
                    render_state(&reloaded),
                    "round trip state"
                );
                counts[5] += 1;
            }
            "viability" => {
                // Craft the serialized state exactly as the dump did
                // and compare the viability values.
                let name = f[1];
                let mut key = [0u8; 32];
                key.copy_from_slice(&unhex(f[2]));
                let attempts: i32 = f[3].parse().expect("attempts");
                let ts_off: i64 = f[4].parse().expect("ts off");
                let la_off: i64 = f[5].parse().expect("lastattempt off");
                let ls_off: i64 = f[6].parse().expect("lastsuccess off");
                let want_chance = u64::from_str_radix(f[7], 16).expect("chance bits");
                let want_bad: bool = f[8].parse().expect("bad");

                let mut amc = AddrManager::new_with_hooks(
                    dir.path(),
                    clock.clone(),
                    Arc::new(Mutex::new(StubRng)),
                );
                amc.set_key(key);
                let na = dump_na("1.2.3.4", 9108, now_unix);
                let src = dump_na("204.124.8.100", 9108, now_unix);
                let bucket = amc.new_bucket_index(&na, &src);
                let mut new_buckets = vec![Vec::new(); bucket + 1];
                new_buckets[bucket] = vec!["1.2.3.4:9108".to_string()];
                let blob = serde_json::json!({
                    "Version": 1,
                    "Key": key.to_vec(),
                    "Addresses": [{
                        "Addr": "1.2.3.4:9108",
                        "Src": "204.124.8.100:9108",
                        "Attempts": attempts,
                        "TimeStamp": now_unix + ts_off,
                        "LastAttempt": now_unix + la_off,
                        "LastSuccess": now_unix + ls_off,
                    }],
                    "NewBuckets": new_buckets,
                    "TriedBuckets": [],
                });
                amc.deserialize_peers(&blob.to_string())
                    .expect("crafted state");
                let ka = amc.known_address("1.2.3.4:9108").expect("crafted address");
                let ka = ka.lock().expect("addr lock poisoned");
                let now = clock_cell.load(Ordering::Relaxed);
                assert_eq!(ka.chance(now).to_bits(), want_chance, "{name}: chance bits");
                assert_eq!(ka.is_bad(now), want_bad, "{name}: isBad");
                counts[6] += 1;
            }
            "deserialize" => {
                let want_err = f[2] == "err";
                let contents = String::from_utf8(unhex(f[3])).expect("utf8 blob");
                let mut amc = AddrManager::new_with_hooks(
                    dir.path(),
                    clock.clone(),
                    Arc::new(Mutex::new(StubRng)),
                );
                assert_eq!(
                    amc.deserialize_peers(&contents).is_err(),
                    want_err,
                    "deserialize {}",
                    f[1]
                );
            }
            "localscenario" => {
                now_unix = f[1].parse().expect("now");
                clock_cell.store(now_unix * NANOS_PER_SEC, Ordering::Relaxed);
                am = AddrManager::new_with_hooks(
                    dir.path(),
                    clock.clone(),
                    Arc::new(Mutex::new(StubRng)),
                );
            }
            "localadd" => {
                let port: u16 = f[2].parse().expect("port");
                let prio = match f[3] {
                    "0" => AddressPriority::Interface,
                    "1" => AddressPriority::Bound,
                    "2" => AddressPriority::Upnp,
                    "3" => AddressPriority::Http,
                    "4" => AddressPriority::Manual,
                    other => panic!("unknown priority {other}"),
                };
                let na = dump_na(f[1], port, now_unix);
                let res = match am.add_local_address(&na, prio) {
                    Ok(()) => "-",
                    Err(_) => "err",
                };
                assert_eq!(res, f[4], "{line}");
            }
            "haslocal" => {
                let na = na_from_key(f[1], now_unix);
                let want: bool = f[2].parse().expect("bool");
                assert_eq!(am.has_local_address(&na), want, "{line}");
            }
            "locals" => {
                let mut locals: Vec<String> = am
                    .local_addresses()
                    .iter()
                    .map(|la| format!("{}|{}", la.address, la.port))
                    .collect();
                locals.sort();
                assert_eq!(locals.join(","), f[1], "{line}");
            }
            "bestlocal" => {
                let remote = dump_na(f[1], 9108, now_unix);
                let best = am.get_best_local_address(&remote, all_filter);
                assert_eq!(best.key(), f[2], "{line}");
            }
            "done" => break,
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [27, 13, 10, 5, 7, 1, 7], "row counts");
}

/// Reconstruct a network address from its "host:port" key form.
fn na_from_key(key: &str, now_unix: i64) -> NetAddress {
    let idx = key.rfind(':').expect("port separator");
    let (host, port) = (&key[..idx], &key[idx + 1..]);
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    dump_na(host, port.parse().expect("port"), now_unix)
}

/// A scripted RNG returning a fixed sequence of values.
struct SeqRng {
    values: Vec<usize>,
    pos: usize,
}

impl AddrRng for SeqRng {
    fn int_n(&mut self, n: usize) -> usize {
        let v = self.values.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        v % n
    }
    fn read(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = 0;
        }
    }
}

/// Native coverage for the randomized paths the dump cannot pin:
/// address selection and the 2N add likelihood.
#[test]
fn randomized_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock: dcroxide_addrmgr::Clock = Arc::new(|| 1_700_000_000 * NANOS_PER_SEC);
    let rng = Arc::new(Mutex::new(SeqRng {
        values: Vec::new(),
        pos: 0,
    }));
    let mut am = AddrManager::new_with_hooks(dir.path(), clock, rng.clone());
    am.set_key([7u8; 32]);

    let src = dump_na("204.124.8.100", 9108, 1_700_000_000);
    let na = dump_na("1.2.3.4", 9108, 1_700_000_000 - 600);
    am.add_addresses(std::slice::from_ref(&na), &src);

    // Re-adding the same address consults the 2N likelihood; a
    // nonzero draw skips the additional bucket placement.
    let src2 = dump_na("64.1.2.3", 9108, 1_700_000_000);
    rng.lock().expect("addr lock poisoned").values = vec![1];
    rng.lock().expect("addr lock poisoned").pos = 0;
    am.add_addresses(std::slice::from_ref(&na), &src2);
    let (addrs, _, _, _) = am.state_snapshot();
    assert_eq!(addrs[0].4, 1, "nonzero draw keeps a single reference");

    // A zero draw adds the address to the second source group's
    // bucket.
    rng.lock().expect("addr lock poisoned").values = vec![0];
    rng.lock().expect("addr lock poisoned").pos = 0;
    am.add_addresses(std::slice::from_ref(&na), &src2);
    let (addrs, _, _, _) = am.state_snapshot();
    assert_eq!(addrs[0].4, 2, "zero draw adds a second reference");

    // get_address walks random buckets until it finds an entry and
    // accepts it against its chance; a never-attempted address has
    // chance 0.01, so script a low accept draw after locating the
    // populated bucket.
    let bucket = am.new_bucket_index(&na, &src);
    rng.lock().expect("addr lock poisoned").values = vec![bucket, 0, 0];
    rng.lock().expect("addr lock poisoned").pos = 0;
    let picked = am.get_address().expect("selected address");
    assert_eq!(
        picked
            .lock()
            .expect("addr lock poisoned")
            .net_address()
            .key(),
        "1.2.3.4:9108"
    );
}

/// The address manager must be `Send` so the daemon can hold it in its
/// shared server state across the peer threads.  Compile-time only.
#[test]
fn addr_manager_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<AddrManager>();
}
