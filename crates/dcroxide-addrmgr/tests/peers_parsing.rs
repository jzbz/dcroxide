// SPDX-License-Identifier: ISC
//! Address parsing and scoring against Go's (RVW-039, 041, 042, 043).
//!
//! Every rejection in `deserialize_peers` deletes `peers.json` and
//! starts the manager empty, so accepting an address Go rejects, or
//! failing where Go succeeds, is not a cosmetic difference -- it decides
//! what the node comes up knowing.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use dcroxide_addrmgr::{AddrManager, AddrRng};

struct StubRng;

impl AddrRng for StubRng {
    fn int_n(&mut self, _n: usize) -> usize {
        0
    }
    fn read(&mut self, buf: &mut [u8]) {
        buf.fill(0);
    }
}

fn manager(dir: &tempfile::TempDir) -> AddrManager {
    let cell = Arc::new(AtomicI64::new(1_700_000_000));
    let clock: dcroxide_addrmgr::Clock = Arc::new(move || cell.load(Ordering::Relaxed));
    AddrManager::new_with_hooks(dir.path(), clock, Arc::new(Mutex::new(StubRng)))
}

/// A peers.json blob naming one address.
///
/// `bucket_ref` is what the bucket lists, which the manager resolves
/// against the address it reconstructs after parsing. For a malformed
/// address it is deliberately the *normalized* form, so a parser that
/// wrongly accepts the input resolves the reference and succeeds --
/// otherwise the reference simply fails to resolve and the blob is
/// rejected for a reason that has nothing to do with the parse.
fn blob(addr: &str, bucket_ref: &str, last_success: i64) -> String {
    format!(
        r#"{{"Version":1,"Key":[{key}],"Addresses":[{{"Addr":"{addr}","Src":"1.2.3.4:9108",
           "Attempts":0,"TimeStamp":1700000000,"LastAttempt":1700000000,
           "LastSuccess":{last_success}}}],"NewBuckets":[["{bucket_ref}"]],"TriedBuckets":[]}}"#,
        key = (0..32).map(|_| "0").collect::<Vec<_>>().join(","),
    )
}

/// Go's `net.SplitHostPort` rejects an unbracketed host with more than
/// one colon, and its `ParseUint` rejects a signed port. The manager
/// carried a second, hand-rolled splitter that accepted both.
#[test]
fn addresses_go_rejects_are_rejected_here() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Each pairs the malformed address with the address a parser that
    // wrongly accepted it would reconstruct.
    for (addr, normalized) in [
        ("::1:9108", "[::1]:9108"),
        ("1.2.3.4:+9108", "1.2.3.4:9108"),
    ] {
        let mut am = manager(&dir);
        assert!(
            am.deserialize_peers(&blob(addr, normalized, 1_700_000_000))
                .is_err(),
            "{addr} must be rejected: Go's SplitHostPort/ParseUint reject it",
        );
    }
}

/// And a well-formed one is still accepted, so the check above is not
/// simply rejecting everything.
#[test]
fn a_well_formed_address_is_still_accepted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut am = manager(&dir);
    am.deserialize_peers(&blob("1.2.3.4:9108", "1.2.3.4:9108", 1_700_000_000))
        .expect("a plain host:port parses");
    assert!(am.known_address("1.2.3.4:9108").is_some());

    let mut am = manager(&dir);
    am.deserialize_peers(&blob("[::1]:9108", "[::1]:9108", 1_700_000_000))
        .expect("a bracketed IPv6 host parses");
}

/// The stored timestamps are attacker-adjacent only in the sense that
/// they come off disk, but an extreme one must not take the process
/// down: the seconds-to-nanoseconds conversion is an unguarded multiply
/// where Go's `time.Unix` keeps the two apart.
#[test]
fn an_extreme_stored_timestamp_does_not_overflow() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut am = manager(&dir);
    // Panics under `cargo test` before the fix; wraps silently in
    // release, which is worse.
    let _ = am.deserialize_peers(&blob("1.2.3.4:9108", "1.2.3.4:9108", i64::MAX));
}
