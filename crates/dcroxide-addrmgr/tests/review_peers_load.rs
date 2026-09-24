// SPDX-License-Identifier: ISC
//! Loading `peers.json` the way dcrd's `loadPeers` and
//! `deserializePeers` do (addrmgr/addrmanager.go): Go's `encoding/json`
//! decoder semantics, the counts a failed load leaves behind, what the
//! load reports for logging, and `chance` on timestamps off disk.
//!
//! The decoder rows were checked against Go's `json.NewDecoder(r).Decode`
//! into dcrd's `serializedAddrManager` types, and the filesystem rows
//! against dcrd's `os.Stat`/`os.Open`/`os.Remove` sequence, all built
//! with Go 1.26.5, the toolchain dcrd's release image uses.  (Go 1.27's
//! `encoding/json`, built on its v2 implementation, words several syntax
//! errors differently.)

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use dcroxide_addrmgr::{AddrManager, AddrRng, PeersLoad};

const NANOS_PER_SEC: i64 = 1_000_000_000;
const NOW_UNIX: i64 = 1_700_000_000;

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
    let cell = Arc::new(AtomicI64::new(NOW_UNIX * NANOS_PER_SEC));
    let clock: dcroxide_addrmgr::Clock = Arc::new(move || cell.load(Ordering::Relaxed));
    AddrManager::new_with_hooks(dir.path(), clock, Arc::new(Mutex::new(StubRng)))
}

fn key_json() -> String {
    (0..32).map(|_| "0").collect::<Vec<_>>().join(",")
}

fn address_json(addr: &str, attempts: &str, last_attempt: i64) -> String {
    format!(
        r#"{{"Addr":"{addr}","Src":"1.2.3.4:9108","Attempts":{attempts},"TimeStamp":{NOW_UNIX},"LastAttempt":{last_attempt},"LastSuccess":{NOW_UNIX}}}"#
    )
}

/// A dcrd-shaped file naming `1.2.3.4:9108` once, in new bucket 0.
fn one_address(attempts: &str, last_attempt: i64) -> String {
    format!(
        r#"{{"Version":1,"Key":[{}],"Addresses":[{}],"NewBuckets":[["1.2.3.4:9108"]],"TriedBuckets":[]}}"#,
        key_json(),
        address_json("1.2.3.4:9108", attempts, last_attempt),
    )
}

// ---------------------------------------------------------------------
// chance() on a far-past LastAttempt (dcrd `time.Since` saturates).
// ---------------------------------------------------------------------

/// Any `LastAttempt` before about 1734 CE, other than Go's zero-time
/// sentinel, puts `now - lastattempt` past `i64::MAX` nanoseconds.
/// dcrd's `time.Since` saturates at its maximum duration, so the address
/// is not recent and scores `1/1.5^attempts`; the port's subtraction
/// panicked here under `cargo test` and wrapped to "recent" (0.01) in
/// release.
#[test]
fn a_far_past_last_attempt_is_not_recent() {
    let dir = tempfile::tempdir().expect("tempdir");
    for (last_attempt, attempts, want) in [
        (-62_135_596_799, "0", 1.0),
        (-62_135_596_799, "2", 1.0 / 1.5f64.powf(2.0)),
        // Saturated by the load's seconds-to-nanoseconds multiply.
        (i64::MIN, "0", 1.0),
    ] {
        let mut am = manager(&dir);
        am.deserialize_peers(&one_address(attempts, last_attempt))
            .expect("loads");
        let ka = am.known_address("1.2.3.4:9108").expect("loaded");
        let ka = ka.lock().expect("lock");
        assert_eq!(
            ka.chance(NOW_UNIX * NANOS_PER_SEC).to_bits(),
            f64::to_bits(want),
            "LastAttempt {last_attempt}, Attempts {attempts}"
        );
    }
}

// ---------------------------------------------------------------------
// The counts a failed load leaves behind (dcrd `reset` keeps them).
// ---------------------------------------------------------------------

/// dcrd's `deserializePeers` raises `nNew`/`nTried` while it walks the
/// bucket lists and can still fail at the sanity checks after; the
/// `reset` that `loadPeers` then runs rebuilds the index and buckets but
/// never touches the two counters.  So `NeedMoreAddresses` -- which gates
/// dcrd's getaddr on each outbound handshake and its seeder retries --
/// answers from the counts of a file it threw away.
#[test]
fn a_failed_load_keeps_the_counts_dcrd_keeps() {
    let dir = tempfile::tempdir().expect("tempdir");
    // 1000 addresses in new buckets, the first also in a tried bucket:
    // the sanity check rejects it as both new and tried.
    let addrs: Vec<String> = (0..1000)
        .map(|i| format!("10.{}.{}.1:9108", i / 256, i % 256))
        .collect();
    let entries: Vec<String> = addrs
        .iter()
        .map(|a| address_json(a, "0", NOW_UNIX))
        .collect();
    let new_bucket: Vec<String> = addrs.iter().map(|a| format!("\"{a}\"")).collect();
    let file = format!(
        r#"{{"Version":1,"Key":[{}],"Addresses":[{}],"NewBuckets":[[{}]],"TriedBuckets":[["{}"]]}}"#,
        key_json(),
        entries.join(","),
        new_bucket.join(","),
        addrs[0],
    );
    std::fs::write(dir.path().join("peers.json"), file).expect("write peers.json");

    let mut am = manager(&dir);
    match am.load_peers() {
        PeersLoad::Failed { err, remove_err } => {
            assert_eq!(
                err,
                "address 10.0.0.1:9108 after serialisation which is both new and tried"
            );
            assert_eq!(remove_err, None);
        }
        other => panic!("the file must be rejected: {other:?}"),
    }
    assert!(
        !dir.path().join("peers.json").exists(),
        "the corrupt file is removed"
    );
    let (addrs_left, n_new, n_tried, _) = am.state_snapshot();
    assert!(addrs_left.is_empty(), "the index is reset");
    assert_eq!((n_new, n_tried), (1000, 1), "dcrd keeps nNew and nTried");
    assert!(
        !am.need_more_addresses(),
        "1001 counted addresses: dcrd stops asking for more"
    );
}

// ---------------------------------------------------------------------
// What load_peers reports (dcrd's three loadPeers log lines).
// ---------------------------------------------------------------------

/// dcrd logs `Loaded %d addresses from file '%s'` with `numAddresses()`,
/// or the parse error and a failed removal.  The port discarded both, and
/// the daemon logged a random 23% `address_cache` sample instead.
#[test]
fn load_peers_reports_what_dcrd_logs() {
    // No file: nothing to load, and nothing wrong.
    let dir = tempfile::tempdir().expect("tempdir");
    let mut am = manager(&dir);
    assert_eq!(am.load_peers(), PeersLoad::Loaded(0));

    // Two addresses, neither ever succeeded (so address_cache would
    // report none of them): both count.
    let file = format!(
        r#"{{"Version":1,"Key":[{}],"Addresses":[{},{}],"NewBuckets":[["1.2.3.4:9108"],["5.6.7.8:9108"]],"TriedBuckets":[]}}"#,
        key_json(),
        address_json("1.2.3.4:9108", "0", NOW_UNIX).replace(
            &format!(r#""LastSuccess":{NOW_UNIX}"#),
            r#""LastSuccess":-62135596800"#
        ),
        address_json("5.6.7.8:9108", "0", NOW_UNIX).replace(
            &format!(r#""LastSuccess":{NOW_UNIX}"#),
            r#""LastSuccess":-62135596800"#
        ),
    );
    std::fs::write(dir.path().join("peers.json"), &file).expect("write");
    let mut am = manager(&dir);
    assert_eq!(am.load_peers(), PeersLoad::Loaded(2));
    assert!(dir.path().join("peers.json").exists(), "a good file stays");

    // A bad version: the error text dcrd logs, and the file is gone.
    std::fs::write(
        dir.path().join("peers.json"),
        file.replace(r#""Version":1"#, r#""Version":2"#),
    )
    .expect("write");
    let mut am = manager(&dir);
    assert_eq!(
        am.load_peers(),
        PeersLoad::Failed {
            err: "unknown version 2 in serialized addrmanager".to_string(),
            remove_err: None,
        }
    );
    assert!(!dir.path().join("peers.json").exists());

    // A decode failure names the file, as dcrd's `error reading %s: %w`.
    std::fs::write(dir.path().join("peers.json"), "{\"Version\":1,").expect("write");
    let mut am = manager(&dir);
    let path = dir.path().join("peers.json").display().to_string();
    assert_eq!(
        am.load_peers(),
        PeersLoad::Failed {
            err: format!("error reading {path}: unexpected EOF"),
            remove_err: None,
        }
    );
    assert_eq!(am.peers_file(), dir.path().join("peers.json"));
}

// ---------------------------------------------------------------------
// Go encoding/json decoding (dcrd json.NewDecoder(r).Decode(&sam)).
// ---------------------------------------------------------------------

/// Files Go's decoder loads and serde's strict derive rejected -- each
/// rejection deleting `peers.json` and starting the node empty.
#[test]
fn files_go_decodes_are_loaded() {
    let base = one_address("0", NOW_UNIX);
    let cases: Vec<(&str, String)> = vec![
        // Decode reads the first value and never looks past it.
        ("trailing garbage", format!("{base}\ngarbage{{")),
        ("a second value", format!("{base}{base}")),
        // A null slice is a nil slice.
        (
            "null TriedBuckets",
            base.replace(r#""TriedBuckets":[]"#, r#""TriedBuckets":null"#),
        ),
        // A missing field keeps its zero value.
        (
            "missing TriedBuckets",
            base.replace(r#","TriedBuckets":[]"#, ""),
        ),
        // Field names match case-insensitively.
        (
            "lower-case names",
            base.replace("\"Version\"", "\"version\"")
                .replace("\"Addresses\"", "\"addresses\"")
                .replace("\"NewBuckets\"", "\"newbuckets\"")
                .replace("\"Addr\"", "\"addr\""),
        ),
        // The last duplicate key wins.
        (
            "duplicate Version",
            base.replace(r#""Version":1"#, r#""Version":7,"Version":1"#),
        ),
        // Attempts is a Go int, 64 bits wide.
        ("Attempts past i32", one_address("4294967296", NOW_UNIX)),
        // A null bucket inside the fixed array ranges over nothing.
        (
            "null inner bucket",
            base.replace(
                r#""NewBuckets":[["1.2.3.4:9108"]]"#,
                r#""NewBuckets":[null,["1.2.3.4:9108"]]"#,
            ),
        ),
    ];
    for (name, file) in cases {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut am = manager(&dir);
        am.deserialize_peers(&file)
            .unwrap_or_else(|err| panic!("{name}: Go loads this file: {err}"));
        assert!(
            am.known_address("1.2.3.4:9108").is_some(),
            "{name}: the address is known"
        );
    }
}

/// `Key [32]byte` takes a JSON array of any length: a short one is
/// zero-filled and a long one truncated.  The key is the file's own.
#[test]
fn the_key_array_is_zero_filled_or_truncated() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut am = manager(&dir);
    am.deserialize_peers(
        r#"{"Version":1,"Key":[1,2],"Addresses":[],"NewBuckets":[],"TriedBuckets":[]}"#,
    )
    .expect("a 2-element key loads");
    let mut want = [0u8; 32];
    want[0] = 1;
    want[1] = 2;
    assert_eq!(am.state_snapshot().3, want);

    let mut long: Vec<String> = (1..=33).map(|b| b.to_string()).collect();
    long[31] = "5".to_string();
    let mut am = manager(&dir);
    am.deserialize_peers(&format!(
        r#"{{"Version":1,"Key":[{}],"Addresses":[],"NewBuckets":[],"TriedBuckets":[]}}"#,
        long.join(",")
    ))
    .expect("a 33-element key loads");
    let key = am.state_snapshot().3;
    assert_eq!((key[0], key[30], key[31]), (1, 31, 5));
}

/// A 64-bit `Attempts` survives the save a later dump performs.
#[test]
fn a_wide_attempts_count_round_trips() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut am = manager(&dir);
    am.deserialize_peers(&one_address("4294967296", NOW_UNIX))
        .expect("loads");
    let (addrs, _, _, _) = am.state_snapshot();
    assert_eq!(addrs[0].2, 4_294_967_296);
    am.save_peers().expect("save");
    let saved = std::fs::read_to_string(dir.path().join("peers.json")).expect("read");
    assert!(saved.contains(r#""Attempts":4294967296"#), "{saved}");
}

/// What Go's decoder rejects stays rejected, with Go's message.
#[test]
fn files_go_rejects_are_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("peers.json").display().to_string();
    let base = one_address("0", NOW_UNIX);
    for (name, file, want) in [
        ("empty", String::new(), "EOF".to_string()),
        ("whitespace", " \n".to_string(), "EOF".to_string()),
        (
            "stray closer",
            "]".to_string(),
            "invalid character ']' looking for beginning of value".to_string(),
        ),
        (
            "truncated",
            "{\"Version\":1,".to_string(),
            "unexpected EOF".to_string(),
        ),
        (
            "string key",
            base.replace(&format!(r#""Key":[{}]"#, key_json()), r#""Key":"AAAA""#),
            "json: cannot unmarshal string into Go struct field serializedAddrManager.Key \
             of type [32]uint8"
                .to_string(),
        ),
    ] {
        let mut am = manager(&dir);
        let err = am.deserialize_peers(&file).expect_err(name);
        assert_eq!(err, format!("error reading {path}: {want}"), "{name}");
    }

    // Attempts is a Go `int`: past 64 bits it is a type error.  (How Go
    // names the nested field in the message varies by Go release.)
    let mut am = manager(&dir);
    let err = am
        .deserialize_peers(&one_address("9223372036854775808", NOW_UNIX))
        .expect_err("Attempts past int64");
    assert!(
        err.starts_with(&format!(
            "error reading {path}: json: cannot unmarshal number 9223372036854775808 \
             into Go struct field "
        )),
        "{err}"
    );

    // dcrd dereferences a null `Addresses` entry and panics at startup;
    // the port rejects the file instead of crashing.
    let mut am = manager(&dir);
    assert_eq!(
        am.deserialize_peers(r#"{"Version":1,"Addresses":[null]}"#),
        Err("address entry 0 after serialisation is null".to_string())
    );
}

/// What `json.Decoder.Decode` makes of a file that is not one good value,
/// byte for byte (Go 1.26, dcrd's release toolchain).  The decoder scans
/// as it reads, so a syntax error inside the first value is reported at
/// the byte that breaks it, even when the brackets never balance.  A file
/// that ends partway through a value is `unexpected EOF`, whatever the
/// scanner was in the middle of.  A complete value is decoded without
/// what follows it, which for a number or a literal starts at the first
/// byte that cannot continue it.  The port framed the value by counting
/// brackets: an unbalanced value was always `unexpected EOF`, a leading
/// `,` was `unexpected end of JSON input`, and a primitive ran on to the
/// next space or comma.
#[test]
fn decode_errors_carry_gos_text() {
    enum Want {
        Loads,
        Version(i64),
        Decode(&'static str),
    }
    use Want::*;

    let cases: [(&[u8], Want); 45] = [
        (
            &b"{\"Version\":1,\"Key\":[1,2}"[..],
            Decode("invalid character '}' after array element"),
        ),
        (
            &b",{\"Version\":1}"[..],
            Decode("invalid character ',' looking for beginning of value"),
        ),
        (
            &b"  ,"[..],
            Decode("invalid character ',' looking for beginning of value"),
        ),
        (
            &b"{\"Addresses\":[{\"Addr\":\"ab\ncd"[..],
            Decode("invalid character '\\n' in string literal"),
        ),
        (
            &b"{\"Addresses\":[{\"Addr\":\"ab\\qcd"[..],
            Decode("invalid character 'q' in string escape code"),
        ),
        (
            &b"{\"Addresses\":[{\"Addr\":\"abcd"[..],
            Decode("unexpected EOF"),
        ),
        (&b"{\"Version\":-"[..], Decode("unexpected EOF")),
        (
            &b"{\"Version\":- 1"[..],
            Decode("invalid character ' ' in numeric literal"),
        ),
        (&b"{\"Version\":tru"[..], Decode("unexpected EOF")),
        (&b"{\"Version\":1"[..], Decode("unexpected EOF")),
        (&b"-"[..], Decode("unexpected EOF")),
        (&b"nul"[..], Decode("unexpected EOF")),
        (
            &b"123"[..],
            Decode(
                "json: cannot unmarshal number into Go value of type addrmgr.serializedAddrManager",
            ),
        ),
        (
            &b"123abc"[..],
            Decode(
                "json: cannot unmarshal number into Go value of type addrmgr.serializedAddrManager",
            ),
        ),
        (
            &b"123-4"[..],
            Decode(
                "json: cannot unmarshal number into Go value of type addrmgr.serializedAddrManager",
            ),
        ),
        (
            &b"-0.5e+3x"[..],
            Decode(
                "json: cannot unmarshal number into Go value of type addrmgr.serializedAddrManager",
            ),
        ),
        (&b"null"[..], Version(0)),
        (&b"nullx"[..], Version(0)),
        (
            &b"truex"[..],
            Decode(
                "json: cannot unmarshal bool into Go value of type addrmgr.serializedAddrManager",
            ),
        ),
        (
            &b"false,"[..],
            Decode(
                "json: cannot unmarshal bool into Go value of type addrmgr.serializedAddrManager",
            ),
        ),
        (
            &b"\"abc\"x"[..],
            Decode(
                "json: cannot unmarshal string into Go value of type addrmgr.serializedAddrManager",
            ),
        ),
        (
            &b"\"a\\\"bc\"x"[..],
            Decode(
                "json: cannot unmarshal string into Go value of type addrmgr.serializedAddrManager",
            ),
        ),
        (&b"\"abc"[..], Decode("unexpected EOF")),
        (
            &b"\"ab\ncd"[..],
            Decode("invalid character '\\n' in string literal"),
        ),
        (
            &b"[1,2}"[..],
            Decode("invalid character '}' after array element"),
        ),
        (&b"{\"Version\":1}}"[..], Loads),
        (
            &b"\xef\xbb\xbf{}"[..],
            Decode("invalid character 'ï' looking for beginning of value"),
        ),
        (
            &b"\x0c{}"[..],
            Decode("invalid character '\\f' looking for beginning of value"),
        ),
        (
            &b"x"[..],
            Decode("invalid character 'x' looking for beginning of value"),
        ),
        (
            &b"{\"Version\":1,}"[..],
            Decode("invalid character '}' looking for beginning of object key string"),
        ),
        (&b"1."[..], Decode("unexpected EOF")),
        (
            &b"1.x"[..],
            Decode("invalid character 'x' after decimal point in numeric literal"),
        ),
        (
            &b"{\"Version\":1 \"Key\":[]}"[..],
            Decode("invalid character '\"' after object key:value pair"),
        ),
        (
            &b"{\"Version\":1,\"Key\":[1,2]"[..],
            Decode("unexpected EOF"),
        ),
        (&b"{\"Version\":\"\\u12"[..], Decode("unexpected EOF")),
        (&b"{\"Version\":\"\\"[..], Decode("unexpected EOF")),
        (&b"\"\\u12"[..], Decode("unexpected EOF")),
        (&b"1e"[..], Decode("unexpected EOF")),
        (&b"{\"Version\":1}x"[..], Loads),
        (&b"[[["[..], Decode("unexpected EOF")),
        (
            &b"{\"a\":[1,2]]"[..],
            Decode("invalid character ']' after object key:value pair"),
        ),
        (
            &b"[1,2]x"[..],
            Decode(
                "json: cannot unmarshal array into Go value of type addrmgr.serializedAddrManager",
            ),
        ),
        (
            &b"{\"Version\":\"\xff\"}"[..],
            Decode(
                "json: cannot unmarshal string into Go struct field serializedAddrManager.Version of type int",
            ),
        ),
        (
            &b"{\"Version\":1,\"Key\":[1,2}\xff"[..],
            Decode("invalid character '}' after array element"),
        ),
        (
            &b"\xff"[..],
            Decode("invalid character 'ÿ' looking for beginning of value"),
        ),
    ];
    for (file, want) in cases {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("peers.json");
        std::fs::write(&path, file).expect("write peers.json");
        let mut am = manager(&dir);
        let got = am.load_peers();
        let name = String::from_utf8_lossy(file);
        match want {
            Loads => assert_eq!(got, PeersLoad::Loaded(0), "{name}"),
            Version(v) => assert_eq!(
                got,
                PeersLoad::Failed {
                    err: format!("unknown version {v} in serialized addrmanager"),
                    remove_err: None,
                },
                "{name}"
            ),
            Decode(err) => assert_eq!(
                got,
                PeersLoad::Failed {
                    err: format!("error reading {}: {err}", path.display()),
                    remove_err: None,
                },
                "{name}"
            ),
        }
    }
}

/// dcrd opens the peers file with `os.Open`, reads it through the
/// decoder and removes a bad one with `os.Remove`; each failure is a
/// `*os.PathError` whose text names the operation and the path.
/// `os.Remove` falls back to rmdir, so a `peers.json` that is an empty
/// directory is removed.  The port printed Rust's `io::Error` text, and
/// its `remove_file` could not remove the directory, which then stayed
/// in the way of every later save.
#[cfg(unix)]
#[test]
fn filesystem_failures_read_as_dcrds() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("peers.json");
    let p = path.display().to_string();
    let is_a_directory = format!("error reading {p}: read {p}: is a directory");

    // An empty directory reads as one and is removed.
    std::fs::create_dir(&path).expect("mkdir");
    assert_eq!(
        manager(&dir).load_peers(),
        PeersLoad::Failed {
            err: is_a_directory.clone(),
            remove_err: None,
        }
    );
    assert!(!path.exists(), "os.Remove removes an empty directory");

    // A directory with something in it stays, with rmdir's error.
    std::fs::create_dir_all(path.join("x")).expect("mkdir");
    assert_eq!(
        manager(&dir).load_peers(),
        PeersLoad::Failed {
            err: is_a_directory,
            remove_err: Some(format!("remove {p}: directory not empty")),
        }
    );
    std::fs::remove_dir_all(&path).expect("clean up");

    // Permissions bind only a non-root user.
    std::fs::write(&path, "{}").expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    let root = std::fs::read(&path).is_ok();
    if !root {
        assert_eq!(
            manager(&dir).load_peers(),
            PeersLoad::Failed {
                err: format!("{p} error opening file: open {p}: permission denied"),
                remove_err: None,
            }
        );
        assert!(!path.exists(), "an unreadable file is removed");

        // A corrupt file in a directory that cannot be written to stays,
        // with unlink's error (rmdir's is ENOTDIR).
        std::fs::write(&path, "x").expect("write");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555))
            .expect("chmod");
        let got = manager(&dir).load_peers();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
        assert_eq!(
            got,
            PeersLoad::Failed {
                err: format!(
                    "error reading {p}: invalid character 'x' looking for beginning of value"
                ),
                remove_err: Some(format!("remove {p}: permission denied")),
            }
        );
    }
}
