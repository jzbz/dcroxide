// SPDX-License-Identifier: ISC
//! Does a *real* storage failure reach the fatal latch?
//!
//! The latch itself is pinned by unit tests that set it directly, which
//! prove the consequence — once latched, writes refuse — on every
//! platform. What they cannot prove is the cause: that a genuine device
//! failure produces an `Err` out of the flush's redb commit
//! (`DbCache::commit`) rather than a panic, a partial apply, or a silently
//! swallowed error. That wiring is two sites: `flush_locked`, which every
//! durable flush goes through and whose `finish` latches a failure before
//! the writer semaphore is released, or on the thread the commit was
//! handed to; and the latch on `close`'s allocator-state commit. "Two
//! call sites a reader can check" is exactly the kind of assurance this
//! project has been wrong about before.
//!
//! So this fills a two-megabyte filesystem underneath a live database and
//! checks what comes back.
//!
//! It does so twice.  The second run has `Options::background_commit`
//! set, where the write that finds the filesystem full is made by a
//! thread of its own, after the commit that tripped the flush has
//! returned `Ok`: there the failure has no caller to come back to, and
//! what is checked is that it latches the store all the same and is
//! reported by the next thing that asks.
//!
//! **Linux only, and it says so when it skips.** The filesystem is a
//! size-limited `tmpfs` mounted inside a user namespace, which needs no
//! root but does need unprivileged `CLONE_NEWUSER` — absent on macOS and
//! Windows, and disabled by some hardened Linux configurations. A skipped
//! fault-injection test that prints nothing is worse than no test at all,
//! because the suite goes green having checked nothing, so this prints a
//! warning on every skip and can be made a hard failure by setting
//! `DCROXIDE_REQUIRE_FAULT_INJECTION=1`, which CI sets.
//!
//! One thing this measured that is worth knowing: with the latch removed,
//! the write after the failure still fails, but with redb's own message —
//! "Previous I/O error occurred. Please close and re-open the database".
//! redb poisons itself. fjall, in the `write_batch` path, does not. That
//! asymmetry is the whole argument for the latch living in this wrapper
//! rather than being left to whichever engine is underneath: on redb it is
//! belt and braces, and on the engine ADR-0009 measured as a replacement
//! it is the only thing standing between a failed write and a commit that
//! reports success.

#![cfg(target_os = "linux")]
// Test-harness arithmetic over bounded generation counts.
#![allow(clippy::arithmetic_side_effects)]

use std::path::Path;
use std::process::Command;

use dcroxide_database::{Database, ErrorKind, LogLevel, Options};

const NET: u32 = 0x12141c16; // simnet magic
/// Set by the parent when it re-execs itself inside the namespace, to
/// the directory the small filesystem is mounted on.
const INSIDE: &str = "DCROXIDE_ENOSPC_INSIDE";
/// Where the parent mounts the small filesystem for the run whose
/// commits stay on the committing thread.
const MOUNT: &str = "/tmp/dcroxide-enospc";
/// And for the run whose commits are handed to a thread of their own:
/// another directory, so that the two tests can run side by side where
/// the mount is not private to a namespace.
const MOUNT_BACKGROUND: &str = "/tmp/dcroxide-enospc-bg";

#[test]
fn a_real_enospc_reaches_the_fatal_latch() {
    on_a_small_filesystem("a_real_enospc_reaches_the_fatal_latch", MOUNT, || {
        inside_the_namespace(Path::new(MOUNT))
    });
}

/// The same failure met by a commit on a thread of its own.
#[test]
fn a_real_enospc_in_a_background_commit_reaches_the_fatal_latch() {
    on_a_small_filesystem(
        "a_real_enospc_in_a_background_commit_reaches_the_fatal_latch",
        MOUNT_BACKGROUND,
        || inside_the_namespace_in_the_background(Path::new(MOUNT_BACKGROUND)),
    );
}

/// Run `inside` on a two-megabyte filesystem mounted at `mount`: the
/// test named `test` re-executes itself there, and the parent checks
/// that the child ran its assertions.
fn on_a_small_filesystem(test: &str, mount: &str, inside: impl FnOnce()) {
    if std::env::var_os(INSIDE).is_some() {
        inside();
        return;
    }

    // Two ways to get a small filesystem, tried in order, because the
    // two environments this has to run in allow different ones.
    //
    //   1. A user namespace. Needs no privileges but does need
    //      unprivileged CLONE_NEWUSER, which GitHub's hosted runners
    //      refuse -- "write failed /proc/self/uid_map: Operation not
    //      permitted". Works on an ordinary developer machine.
    //   2. Passwordless sudo. The reverse: GitHub's runners grant it,
    //      most developer machines do not (and `sudo -n` fails rather
    //      than prompting, so trying costs nothing).
    //
    // Neither is universal, which is why both are here.
    let exe = std::env::current_exe().expect("test binary path");
    let child = format!("{} --exact {test} --nocapture", exe.display());

    let via_namespace = Command::new("unshare")
        .args(["-U", "-m", "--map-root-user"])
        .arg("sh")
        .arg("-c")
        .arg(format!(
            "mkdir -p {mount} && mount -t tmpfs -o size=2M tmpfs {mount} && exec {child}"
        ))
        .env(INSIDE, "1")
        .output();

    let output = match via_namespace {
        Ok(o) if o.status.success() => o,
        other => {
            let why = match &other {
                Ok(o) => String::from_utf8_lossy(&o.stderr).trim().to_string(),
                Err(e) => e.to_string(),
            };
            // mode=1777 because the mount is made by root and the test
            // runs as the ordinary user.
            let via_sudo = Command::new("sudo")
                .arg("-n")
                .arg("sh")
                .arg("-c")
                .arg(format!(
                    "mkdir -p {mount} && mount -t tmpfs -o size=2M,mode=1777 tmpfs {mount}"
                ))
                .output();
            let mounted = matches!(&via_sudo, Ok(o) if o.status.success());
            if !mounted {
                return skip(&format!(
                    "no way to mount a small filesystem here. user namespace: {why}. \
                     passwordless sudo: {}",
                    match &via_sudo {
                        Ok(o) => String::from_utf8_lossy(&o.stderr).trim().to_string(),
                        Err(e) => e.to_string(),
                    }
                ));
            }
            let run = Command::new("sh")
                .arg("-c")
                .arg(&child)
                .env(INSIDE, "1")
                .output();
            // Unmount whatever happened, so a failure does not leave a
            // mount behind on a developer's machine.
            let _ = Command::new("sudo")
                .arg("-n")
                .args(["umount", mount])
                .output();
            match run {
                Ok(o) => o,
                Err(e) => panic!("could not run the in-namespace half under sudo: {e}"),
            }
        }
    };

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "the fault-injection half failed.\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    // Anti-vacuity guard, and not a hypothetical one: a mistyped filter
    // makes the child run zero tests and exit 0, which the status check
    // above would read as success. Require the marker the assertions
    // print only after they have all passed.
    assert!(
        stdout.contains("ENOSPC reached the latch"),
        "the child exited 0 without running the assertions -- this test would \
         have passed having checked nothing.\n--- stdout ---\n{stdout}\n\
         --- stderr ---\n{stderr}"
    );
    for line in stdout.lines().filter(|l| {
        l.starts_with("first failure") || l.starts_with("store probes") || l.starts_with("ENOSPC")
    }) {
        println!("  {line}");
    }
}

/// Skip loudly, or fail if the environment says this must run.
fn skip(why: &str) {
    if std::env::var_os("DCROXIDE_REQUIRE_FAULT_INJECTION").is_some() {
        panic!("DCROXIDE_REQUIRE_FAULT_INJECTION is set but the test cannot run: {why}");
    }
    eprintln!(
        "WARNING: skipping the ENOSPC fault-injection test -- {why}.\n\
         The fatal latch's *consequence* is still covered by unit tests, but \
         nothing here checked that a real storage failure reaches it. Set \
         DCROXIDE_REQUIRE_FAULT_INJECTION=1 to make this a failure."
    );
}

/// The half that runs on the small filesystem.
fn inside_the_namespace(mount: &Path) {
    let dir = mount.join("db");
    let mut opts = Options::new(&dir, NET);
    // Flush on every commit, so the failure lands inside a commit rather
    // than at some later cache-driven moment.
    opts.cache_max_size = 4 * 1024;
    let db = Database::create(&opts).expect("create on the small filesystem");

    // Write until the filesystem gives out. Each generation is a paired
    // write of the shape Chain::flush uses, plus one metadata row that
    // only that generation writes, for the read probes below.
    let mut fatal_err = None;
    for generation in 0u32..4096 {
        let result = db.update(|tx| {
            let meta = tx.metadata();
            let b = meta.create_bucket_if_not_exists(b"blockidxv3")?;
            for i in 0..64u32 {
                let mut key = [0u8; 8];
                key[..4].copy_from_slice(&generation.to_be_bytes());
                key[4..].copy_from_slice(&i.to_be_bytes());
                b.put(&key, &[0xab; 512])?;
            }
            meta.put(&generation_key(generation), &generation.to_be_bytes())?;
            meta.put(b"utxosetstate", &generation.to_be_bytes())
        });
        if let Err(e) = result {
            fatal_err = Some((generation, e));
            break;
        }
    }

    let (failed_generation, first) = fatal_err.expect(
        "the filesystem never filled -- the injector is not injecting, and this test \
         would have passed having proved nothing",
    );
    println!("first failure: generation {failed_generation}: {first}");

    // The failure must arrive as an error, not a panic: reaching this
    // line at all is half the result.
    //
    // Now the half that matters. The store must have latched, so every
    // later write refuses -- including one that would easily fit, since
    // the point is that the store stops trusting itself rather than that
    // the disk stays full.
    let after = db
        .update(|tx| tx.metadata().put(b"probe", b"x"))
        .expect_err("a write after a failed durable write must not succeed");
    assert_eq!(
        after.kind,
        ErrorKind::Fatal,
        "a real ENOSPC must latch the store fatal, got {after}"
    );

    // And reads still work, which is the deliberate half of the policy.
    //
    // Which layer answers matters. Every commit after the first flushes
    // the window before it (dcrd's `commitTx` order), and a flush that
    // succeeds retires what it wrote from the cache overlay, so once
    // generation g+1 has committed, generation g's rows live in the
    // store alone. The failing commit was flushing generation
    // `failed_generation - 1`, whose layer a failed flush leaves
    // published. Generations up to `failed_generation - 2` are therefore
    // answered by redb and by nothing else, which needs the failure to
    // have come at generation 2 or later.
    assert!(
        failed_generation >= 2,
        "the filesystem filled at generation {failed_generation}, before any \
         generation was flushed and retired to the store, so no probe below \
         would reach redb"
    );
    let newest = failed_generation - 1;
    let (mut served, mut failed) = (0u32, 0u32);
    db.view(|tx| {
        let meta = tx.metadata();
        // Store-resident rows. A page redb can no longer read may fail
        // (redb keeps failing uncached reads after an I/O error), and
        // `try_get` must then say so; a row that was written must never
        // read back as absent.
        for generation in 0..newest {
            match meta.try_get(&generation_key(generation)) {
                Ok(Some(v)) => {
                    assert_eq!(v, generation.to_be_bytes(), "generation {generation}");
                    served += 1;
                }
                Ok(None) => panic!(
                    "generation {generation}'s row, flushed to the store before the \
                     fault, read back as absent"
                ),
                Err(e) => {
                    println!("store read of generation {generation} failed: {e}");
                    failed += 1;
                }
            }
        }
        // The newest committed state is still in the overlay, which the
        // failed flush kept published although the store never took it.
        assert_eq!(
            meta.try_get(b"utxosetstate"),
            Ok(Some(newest.to_be_bytes().to_vec())),
            "the failed flush's window must stay readable from the overlay"
        );
        Ok(())
    })
    .expect("reads must stay available after a write fault");
    println!("store probes after the fault: {served} served, {failed} failed, none absent");

    println!("ENOSPC reached the latch; writes refused, reads still served");
}

/// A metadata key that only one generation writes.
fn generation_key(generation: u32) -> Vec<u8> {
    let mut key = b"generation".to_vec();
    key.extend_from_slice(&generation.to_be_bytes());
    key
}

/// The half that runs on the small filesystem with commits handed to a
/// thread of their own.
///
/// The commit that trips a flush returns `Ok` before the flush's redb
/// commit has written anything, so the full filesystem is met by the
/// committer thread.  It latches the store and logs the failure; the
/// writing loop learns of it from the next commit that reaches a latch
/// check, or from the wait at the end.
fn inside_the_namespace_in_the_background(mount: &Path) {
    use std::sync::{Arc, Mutex};

    let dir = mount.join("db");
    let mut opts = Options::new(&dir, NET);
    opts.cache_max_size = 4 * 1024;
    opts.background_commit = true;
    let background_flushes = Arc::new(Mutex::new(0u32));
    {
        let count = Arc::clone(&background_flushes);
        opts.flush_observer = Some(Arc::new(move |obs| {
            if obs.background {
                *count.lock().expect("count") += 1;
            }
        }));
    }
    let errors: Arc<Mutex<Vec<String>>> = Arc::default();
    {
        let errors = Arc::clone(&errors);
        opts.log = Some(Arc::new(move |level, msg: &str| {
            if level == LogLevel::Error {
                errors.lock().expect("errors").push(msg.to_string());
            }
        }));
    }
    let db = Database::create(&opts).expect("create on the small filesystem");

    // Write until a commit is refused.  The generations that returned
    // `Ok` include any committed while the failing commit was under way.
    let mut refused = None;
    let mut committed = 0u32;
    for generation in 0u32..4096 {
        let result = db.update(|tx| {
            let meta = tx.metadata();
            let b = meta.create_bucket_if_not_exists(b"blockidxv3")?;
            for i in 0..64u32 {
                let mut key = [0u8; 8];
                key[..4].copy_from_slice(&generation.to_be_bytes());
                key[4..].copy_from_slice(&i.to_be_bytes());
                b.put(&key, &[0xab; 512])?;
            }
            meta.put(&generation_key(generation), &generation.to_be_bytes())?;
            meta.put(b"utxosetstate", &generation.to_be_bytes())
        });
        match result {
            Ok(()) => committed = generation,
            Err(e) => {
                refused = Some((generation, e));
                break;
            }
        }
    }
    let (refused_generation, first) = refused.expect(
        "the filesystem never filled -- the injector is not injecting, and this test \
         would have passed having proved nothing",
    );
    println!("first failure: generation {refused_generation}: {first}");

    // The wait for the commit under way reports the latch, and the
    // settled read agrees: no committer is left running.
    let settled = db
        .wait_background_commit()
        .expect_err("the store is latched once the failing commit has ended");
    assert_eq!(settled.kind, ErrorKind::Fatal, "{settled}");
    assert!(db.is_fatal_settled());

    // The failure was the committer's: it logged it, once, and the
    // refusals name it as the first cause.
    let errors = errors.lock().expect("errors").clone();
    assert_eq!(
        errors.len(),
        1,
        "the filesystem filled under the committing thread instead of a commit on its own \
         thread, so this run shows nothing of the background path: {errors:?}, {first}"
    );
    let cause = errors[0]
        .strip_prefix("Background commit of the metadata write cache failed: ")
        .unwrap_or_else(|| panic!("an unexpected error line: {}", errors[0]));
    println!("background failure: {cause}");
    assert!(
        *background_flushes.lock().expect("count") >= 2,
        "the filesystem filled before two commits had landed on a thread of their own"
    );
    assert_eq!(first.kind, ErrorKind::Fatal, "{first}");
    assert!(
        first.description.contains("(the first failure: "),
        "the refusal does not name the failed commit: {first}"
    );

    // Every later write refuses, one that would easily fit included.
    let after = db
        .update(|tx| tx.metadata().put(b"probe", b"x"))
        .expect_err("a write after a failed durable write must not succeed");
    assert_eq!(
        after.kind,
        ErrorKind::Fatal,
        "a real ENOSPC must latch the store fatal, got {after}"
    );
    assert_eq!(db.flush().unwrap_err().kind, ErrorKind::Fatal);

    // And reads still work.  The failed flush's layers stay published
    // with everything committed since, so the newest state is answered
    // by the overlay; a row an earlier flush took to the store is served
    // or fails, as redb decides page by page, and is never absent.
    let (mut served, mut failed) = (0u32, 0u32);
    db.view(|tx| {
        let meta = tx.metadata();
        for generation in 0..=committed {
            match meta.try_get(&generation_key(generation)) {
                Ok(Some(v)) => {
                    assert_eq!(v, generation.to_be_bytes(), "generation {generation}");
                    served += 1;
                }
                Ok(None) => panic!("generation {generation}'s row read back as absent"),
                Err(e) => {
                    println!("store read of generation {generation} failed: {e}");
                    failed += 1;
                }
            }
        }
        assert_eq!(
            meta.try_get(b"utxosetstate"),
            Ok(Some(committed.to_be_bytes().to_vec())),
            "the newest committed state must stay readable from the overlay"
        );
        Ok(())
    })
    .expect("reads must stay available after a write fault");
    println!("store probes after the fault: {served} served, {failed} failed, none absent");
    assert_eq!(db.close().unwrap_err().kind, ErrorKind::Fatal);

    println!("ENOSPC reached the latch; writes refused, reads still served");
}
