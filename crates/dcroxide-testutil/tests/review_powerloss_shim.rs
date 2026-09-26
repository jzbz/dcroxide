// SPDX-License-Identifier: ISC
//! `tools/powerloss`, the `LD_PRELOAD` undo-log shim ADR-0009's durability
//! gate rests on, checked end to end: build the shim, run writes under it
//! through the same std entry points the node uses, replay the undo log,
//! and compare every file with its state at its last sync.
//!
//! Five files each isolate one way the undo log used to be incomplete, so
//! the replay left the file as the killed process wrote it instead of as
//! a power cut would have:
//!
//! - `big.bin`: an overwrite longer than one 64 KiB record was dropped.
//! - `trunc.bin`: `File::set_len` calls `ftruncate64`, which the shim did
//!   not interpose, and a shrink kept no bytes, so even a recorded one
//!   came back as zeros.
//! - `grow.bin`: an unrecorded growing `set_len` became the length every
//!   later write was undone to.
//! - `vec.bin`: `write_vectored` is `writev`, which was not interposed.
//! - `new.bin`: the shim asked whether an `O_CREAT` open created its file
//!   only after the open, when the file always exists, so no file was
//!   ever recorded as created and a never-synced new one came back empty
//!   instead of being removed.
//!
//! The other two pin what already held.  `synced.bin`: a synced write
//! survives replay.  `edge.bin`: an overwrite six bytes longer than one
//! record holds, which the shim now splits across two records at exactly
//! the boundary.  The old shim wrote that record whole, overrunning its
//! buffer by six bytes under the miscounted bound, but the replay came
//! out right regardless, so `edge.bin` passes against it too; the overrun
//! itself shows only under a sanitizer.
//!
//! Linux only, and skipped where `cc` or `python3` is missing, unless
//! `DCROXIDE_REQUIRE_FAULT_INJECTION` is set (CI sets it): this is the only
//! automated check of the shim, and like the ENOSPC test in
//! `dcroxide-database` it must fail rather than go green having checked
//! nothing.

// Test-harness arithmetic over small, fixed sizes.
#![allow(clippy::arithmetic_side_effects)]
#![cfg(target_os = "linux")]

use std::fs::{self, File, OpenOptions};
use std::io::{IoSlice, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Set by the parent on the copy of this test it runs under the shim.
const DRIVER: &str = "DCROXIDE_POWERLOSS_DRIVER";

/// Turns a skip into a failure, as for `dcroxide-database`'s ENOSPC test.
const REQUIRE: &str = "DCROXIDE_REQUIRE_FAULT_INJECTION";

/// The shim's record buffer and fixed header (`REC_MAX`, `REC_HDR`).
const REC_MAX: usize = 1 << 16;
const REC_HDR: usize = 23;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Deterministic, position-dependent content, so a region restored at
/// the wrong offset does not compare equal by accident.
fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) ^ ((i >> 8) as u8))
        .collect()
}

/// The overwrite length for `edge.bin`: six bytes past what one record
/// holds for its path, inside the window the old bound check let through.
fn edge_len(store: &Path) -> usize {
    let path_len = store.join("edge.bin").as_os_str().len();
    REC_MAX - REC_HDR - path_len + 6
}

fn open_rw(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap_or_else(|e| panic!("open {}: {e}", path.display()))
}

/// The writes, run in the child with the shim preloaded. None is synced
/// except the first write to `synced.bin`.
fn drive(store: &Path) {
    open_rw(&store.join("big.bin"))
        .write_all_at(&[0xbb; 100 * 1024], 4096)
        .expect("big overwrite");

    open_rw(&store.join("edge.bin"))
        .write_all_at(&vec![0xee; edge_len(store)], 1000)
        .expect("edge overwrite");

    open_rw(&store.join("trunc.bin"))
        .set_len(1000)
        .expect("shrink");

    let grow = open_rw(&store.join("grow.bin"));
    grow.set_len(1 << 20).expect("grow");
    grow.write_all_at(&[0x99; 4096], 512 * 1024)
        .expect("write into the grown tail");

    let mut vec = open_rw(&store.join("vec.bin"));
    vec.seek(SeekFrom::Start(100)).expect("seek");
    let (a, b) = ([0xaa; 3000], [0xcc; 5000]);
    let n = vec
        .write_vectored(&[IoSlice::new(&a), IoSlice::new(&b)])
        .expect("writev");
    assert_eq!(n, a.len() + b.len(), "short writev to a regular file");

    let synced = open_rw(&store.join("synced.bin"));
    synced.write_all_at(&[0x11; 512], 0).expect("durable write");
    synced.sync_all().expect("fsync");
    synced.write_all_at(&[0x22; 512], 256).expect("lost write");

    File::create(store.join("new.bin"))
        .and_then(|mut f| f.write_all(&[0x33; 777]))
        .expect("new file");
}

fn available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Skip loudly, or fail if the environment says this must run.
fn skip(why: &str) {
    if std::env::var_os(REQUIRE).is_some() {
        panic!("{REQUIRE} is set but the powerloss shim test cannot run: {why}");
    }
    eprintln!("SKIP: the powerloss shim test {why} (set {REQUIRE} to make this a failure)");
}

#[test]
fn powerloss_replay_restores_each_file_to_its_last_sync() {
    if let Some(store) = std::env::var_os(DRIVER) {
        drive(Path::new(&store));
        return;
    }
    if !available("cc") || !available("python3") {
        skip("needs cc and python3");
        return;
    }

    let work = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("review_powerloss_shim-{}", std::process::id()));
    let _ = fs::remove_dir_all(&work);
    let store = work.join("store");
    fs::create_dir_all(&store).expect("store dir");
    let lib = work.join("libpowerloss.so");
    let log = work.join("undo.log");

    let shim = repo_root().join("tools/powerloss/shim.c");
    let built = Command::new("cc")
        .args(["-shared", "-O2", "-Wall", "-Wextra", "-fPIC", "-o"])
        .arg(&lib)
        .arg(&shim)
        .arg("-ldl")
        .output()
        .expect("run cc");
    assert!(
        built.status.success(),
        "building {}: {}",
        shim.display(),
        String::from_utf8_lossy(&built.stderr)
    );

    // Each file's state at its last sync, which replay must reproduce.
    let mut expected: Vec<(&str, Option<Vec<u8>>)> = Vec::new();
    for (name, len, seed) in [
        ("big.bin", 256 * 1024, 1),
        ("edge.bin", 128 * 1024, 2),
        ("trunc.bin", 200 * 1024, 3),
        ("grow.bin", 4096, 4),
        ("vec.bin", 64 * 1024, 5),
        ("synced.bin", 8192, 6),
    ] {
        let data = pattern(len, seed);
        fs::write(store.join(name), &data).expect("baseline");
        expected.push((name, Some(data)));
    }
    for (name, want) in &mut expected {
        if *name == "synced.bin" {
            let want = want.as_mut().expect("baseline");
            want[..512].copy_from_slice(&[0x11; 512]);
        }
    }
    expected.push(("new.bin", None));
    let baseline_big = fs::read(store.join("big.bin")).expect("read");

    let exe = std::env::current_exe().expect("test binary path");
    let child = Command::new(exe)
        .args([
            "--exact",
            "powerloss_replay_restores_each_file_to_its_last_sync",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(DRIVER, &store)
        .env("LD_PRELOAD", &lib)
        .env("POWERLOSS_DIR", &store)
        .env("POWERLOSS_LOG", &log)
        .output()
        .expect("run the driver");
    assert!(
        child.status.success(),
        "driver under the shim failed: {}{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    // Not vacuous: the writes landed, and the shim logged them.
    assert_ne!(fs::read(store.join("big.bin")).expect("read"), baseline_big);
    assert!(fs::metadata(&log).expect("undo log").len() > 0);

    let replay = Command::new("python3")
        .arg(repo_root().join("tools/powerloss/replay.py"))
        .arg(&log)
        .output()
        .expect("run replay.py");
    assert!(
        replay.status.success(),
        "replay.py: {}",
        String::from_utf8_lossy(&replay.stderr)
    );

    let mut wrong = Vec::new();
    for (name, want) in &expected {
        let got = fs::read(store.join(name)).ok();
        if got != *want {
            wrong.push(format!(
                "{name}: {} after replay, want {}",
                got.map_or("missing".to_string(), |g| format!("{} B", g.len())),
                want.as_ref().map_or("removed".to_string(), |w| format!(
                    "the {} B synced state",
                    w.len()
                )),
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "replay did not rewind to the last sync:\n  {}\nreplay said:\n{}",
        wrong.join("\n  "),
        String::from_utf8_lossy(&replay.stdout)
    );
    let _ = fs::remove_dir_all(&work);
}

/// Without `cc` and `python3` the shim test skips only where fault
/// injection is optional: with `DCROXIDE_REQUIRE_FAULT_INJECTION` set, as
/// CI sets it, the same run fails instead of passing having checked
/// nothing.
#[test]
fn a_missing_toolchain_fails_when_fault_injection_is_required() {
    if std::env::var_os(DRIVER).is_some() {
        return;
    }
    // A PATH naming only an empty directory finds neither tool.
    let empty = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "review_powerloss_shim-nopath-{}",
        std::process::id()
    ));
    fs::create_dir_all(&empty).expect("empty PATH directory");
    let exe = std::env::current_exe().expect("test binary path");
    let run = |require: bool| {
        let mut cmd = Command::new(&exe);
        cmd.args([
            "--exact",
            "powerloss_replay_restores_each_file_to_its_last_sync",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("PATH", &empty)
        .env_remove(DRIVER);
        if require {
            cmd.env(REQUIRE, "1");
        } else {
            cmd.env_remove(REQUIRE);
        }
        let out = cmd.output().expect("run the shim test without its tools");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), text)
    };

    let (passed, text) = run(false);
    assert!(passed, "an optional run skips: {text}");
    assert!(text.contains("SKIP: the powerloss shim test"), "{text}");

    let (passed, text) = run(true);
    assert!(
        !passed,
        "a required run must fail without its tools: {text}"
    );
    assert!(
        text.contains("DCROXIDE_REQUIRE_FAULT_INJECTION is set"),
        "{text}"
    );
    let _ = fs::remove_dir(&empty);
}
