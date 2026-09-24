// SPDX-License-Identifier: ISC
//! The descriptor limit against dcrd.  The Go runtime lifts dcrd's soft
//! `RLIMIT_NOFILE` to one below the hard limit before `main` runs
//! (`syscall/rlimit.go`), and dcrd's `main` then calls
//! `limits.SetLimits`, which refuses to start under a hard limit below
//! 1024.  The port did neither: it ran at the inherited soft limit, 1024
//! under systemd, with several descriptors per connection, so a peer and
//! RPC flood could exhaust it.

// The limits are read back through /proc.
#![cfg(target_os = "linux")]
// Test-harness arithmetic over bounded limits and a fixed deadline.
#![allow(clippy::arithmetic_side_effects)]

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The soft and hard "Max open files" limits of a process.
fn nofile_limits(pid: &str) -> Option<(u64, u64)> {
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).ok()?;
    let line = limits
        .lines()
        .find(|line| line.starts_with("Max open files"))?;
    let mut fields = line["Max open files".len()..].split_whitespace();
    let soft = fields.next()?.parse().ok()?;
    let hard = fields.next()?.parse().ok()?;
    Some((soft, hard))
}

/// A hard limit below 1024 stops the daemon before it reads its
/// configuration, with dcrd's message and exit status.
#[test]
fn a_hard_limit_below_1024_refuses_to_start() {
    let out = Command::new("sh")
        .args(["-c", "ulimit -n 512 && exec \"$0\" --version"])
        .arg(env!("CARGO_BIN_EXE_dcroxide"))
        .output()
        .expect("run dcroxide under a 512 descriptor limit");
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "failed to set limits: need at least 1024 file descriptors\n"
    );
    assert!(out.stdout.is_empty(), "the version must not print: {out:?}");
}

/// A daemon started under a low soft limit runs with the one Go would
/// give dcrd: one below the hard limit, or, when that is 2048 or less,
/// what `SetLimits` then settles on.
#[test]
fn the_soft_limit_is_raised_to_just_below_the_hard_limit() {
    let (_, hard) = nofile_limits("self").expect("this process's limits");
    if hard < 1100 {
        eprintln!("hard descriptor limit {hard} leaves no room to lower the soft one; skipped");
        return;
    }
    let expected = if hard > 2049 {
        hard - 1
    } else {
        hard.min(2048)
    };

    let appdata = tempfile::tempdir().expect("appdata");
    let mut child = Command::new("sh")
        .args(["-c", "ulimit -S -n 1000 && exec \"$0\" \"$@\""])
        .arg(env!("CARGO_BIN_EXE_dcroxide"))
        .args(["--simnet", "--noseeders", "--norpc", "--listen=127.0.0.1:0"])
        .arg(format!("--appdata={}", appdata.path().display()))
        .env_remove("DCROXIDE_APPDATA")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dcroxide");
    let pid = child.id().to_string();

    // The first log line comes long after the raise at the top of main.
    let mut out = child.stdout.take().expect("stdout pipe");
    let collected = Arc::new(Mutex::new(Vec::<u8>::new()));
    let sink = Arc::clone(&collected);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = out.read(&mut buf) {
            if n == 0 {
                break;
            }
            sink.lock().expect("sink").extend_from_slice(&buf[..n]);
        }
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    while collected.lock().expect("sink").is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let limits = nofile_limits(&pid);
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        !collected.lock().expect("sink").is_empty(),
        "the daemon logged nothing"
    );
    assert_eq!(limits, Some((expected, hard)), "the daemon's limits");
}
