// SPDX-License-Identifier: ISC
//! Does a *real* storage failure reach the fatal latch?
//!
//! The latch itself is pinned by unit tests that set it directly, which
//! prove the consequence — once latched, writes refuse — on every
//! platform. What they cannot prove is the cause: that a genuine device
//! failure produces an `Err` out of `DbCache::flush` rather than a panic,
//! a partial apply, or a silently swallowed error. That wiring is three
//! `map_err` calls, and "three call sites a reader can check" is exactly
//! the kind of assurance this project has been wrong about before.
//!
//! So this fills a two-megabyte filesystem underneath a live database and
//! checks what comes back.
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

use std::path::Path;
use std::process::Command;

use dcroxide_database::{Database, ErrorKind, Options};

const NET: u32 = 0x12141c16; // simnet magic
/// Set by the parent when it re-execs itself inside the namespace.
const INSIDE: &str = "DCROXIDE_ENOSPC_INSIDE";
/// Where the parent mounts the small filesystem.
const MOUNT: &str = "/tmp/dcroxide-enospc";

#[test]
fn a_real_enospc_reaches_the_fatal_latch() {
    if std::env::var_os(INSIDE).is_some() {
        inside_the_namespace();
        return;
    }

    // The child is this same test binary, re-executed inside a user
    // namespace so it can mount. Running the assertions in Rust rather
    // than a shell is the whole point: the thing under test is which
    // error kind comes back.
    let exe = std::env::current_exe().expect("test binary path");
    let output = Command::new("unshare")
        .args(["-U", "-m", "--map-root-user"])
        .arg("sh")
        .arg("-c")
        .arg(format!(
            "mkdir -p {MOUNT} && mount -t tmpfs -o size=2M tmpfs {MOUNT} && \
             exec {} --exact a_real_enospc_reaches_the_fatal_latch --nocapture",
            exe.display()
        ))
        .env(INSIDE, "1")
        .output();

    let output = match output {
        Ok(o) => o,
        Err(e) => return skip(&format!("could not run unshare: {e}")),
    };
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success()
        && (stderr.contains("Operation not permitted")
            || stderr.contains("Permission denied")
            || stderr.contains("unshare: unshare failed"))
    {
        return skip(&format!(
            "unprivileged user namespaces are unavailable here: {}",
            stderr.trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "the in-namespace half failed.\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
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
    // Echo it, so a passing run leaves evidence it did something.
    for line in stdout
        .lines()
        .filter(|l| l.starts_with("first failure") || l.starts_with("ENOSPC"))
    {
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
fn inside_the_namespace() {
    let dir = Path::new(MOUNT).join("db");
    let mut opts = Options::new(&dir, NET);
    // Flush on every commit, so the failure lands inside a commit rather
    // than at some later cache-driven moment.
    opts.cache_max_size = 4 * 1024;
    let db = Database::create(&opts).expect("create on the small filesystem");

    // Write until the filesystem gives out. Each generation is a paired
    // write of the shape Chain::flush uses.
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
            meta.put(b"utxosetstate", &generation.to_be_bytes())
        });
        if let Err(e) = result {
            fatal_err = Some(e);
            break;
        }
    }

    let first = fatal_err.expect(
        "the filesystem never filled -- the injector is not injecting, and this test \
         would have passed having proved nothing",
    );
    println!("first failure: {first}");

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
    db.view(|tx| {
        let _ = tx.metadata().bucket(b"blockidxv3");
        Ok(())
    })
    .expect("reads must stay available after a write fault");

    println!("ENOSPC reached the latch; writes refused, reads still served");
}
