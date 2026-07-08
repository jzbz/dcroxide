// SPDX-License-Identifier: ISC
//! Internal test utilities for dcroxide differential tests.
//!
//! Provides the harness for `tools/oracle` (the Go shim linking dcrd's own
//! packages at the release-v2.1.5 module versions) plus a deterministic PRNG
//! and hex helpers, so every crate's differential tests share one
//! implementation.
//!
//! This crate is a dev-dependency only and is never published.

// Test-harness arithmetic (PRNG mixing, chunk math) — not consensus code.
#![allow(clippy::arithmetic_side_effects)]

use std::env;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// Encode bytes as lowercase hex.
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Decode a lowercase/uppercase hex string; panics on invalid input (tests).
pub fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "unhex: odd-length string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("unhex: invalid hex"))
        .collect()
}

/// Deterministic PRNG (SplitMix64) so failures reproduce from a printed seed
/// without pulling a rand dependency into the workspace.
pub struct SplitMix64(pub u64);

impl SplitMix64 {
    /// Seed from the wall clock and print the seed for reproduction.
    pub fn from_entropy(label: &str) -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos() as u64;
        println!("{label}: seed {seed:#018x}");
        SplitMix64(seed)
    }

    /// Next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform value in `0..n` (n > 0; modulo bias irrelevant for tests).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    /// Fill a buffer with random bytes.
    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }

    /// A random byte vector with length in `0..=max_len`.
    pub fn bytes(&mut self, max_len: usize) -> Vec<u8> {
        let len = self.below(max_len as u64 + 1) as usize;
        let mut v = vec![0u8; len];
        self.fill(&mut v);
        v
    }
}

/// Returns whether a Go toolchain is available.
pub fn go_available() -> bool {
    Command::new("go")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Skip-or-fail policy shared by all differential tests: without a Go
/// toolchain the test skips (returns None), unless `DCROXIDE_REQUIRE_ORACLE`
/// is set (as in CI), in which case a missing toolchain panics so that
/// differential coverage can never silently vanish from CI.
pub fn oracle_or_skip() -> Option<Oracle> {
    if !go_available() {
        assert!(
            env::var_os("DCROXIDE_REQUIRE_ORACLE").is_none(),
            "DCROXIDE_REQUIRE_ORACLE is set but no Go toolchain was found"
        );
        eprintln!(
            "skipping: Go toolchain not found (set DCROXIDE_REQUIRE_ORACLE to make this an error)"
        );
        return None;
    }
    Some(Oracle::spawn())
}

fn repo_root() -> &'static Path {
    // crates/dcroxide-testutil -> crates -> root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate lives two levels below the repo root")
}

/// Build the oracle into `target/oracle/` and return the binary path.
///
/// Multiple test binaries run concurrently and all build the oracle, so the
/// build goes to a process-unique path first and is then atomically renamed
/// into place — spawning processes always see a complete binary (Go's build
/// cache makes the duplicate builds cheap).
fn build_oracle() -> PathBuf {
    let root = repo_root();
    let out_dir = root.join("target").join("oracle");
    std::fs::create_dir_all(&out_dir).expect("create target/oracle");
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    let bin = out_dir.join(format!("dcrd-oracle{suffix}"));
    // Unique per process *and* per calling thread: tests within one binary
    // run concurrently and share a pid.
    static BUILD_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = BUILD_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = out_dir.join(format!("dcrd-oracle-{}-{seq}{suffix}", std::process::id()));

    let output = Command::new("go")
        .args(["build", "-o"])
        .arg(&tmp)
        .arg(".")
        .current_dir(root.join("tools").join("oracle"))
        .output()
        .expect("run go build");
    assert!(
        output.status.success(),
        "go build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Atomically move the freshly built binary into place.  On Windows a
    // destination that another test process is currently executing cannot
    // be replaced (rename fails with a sharing violation); since every
    // build of the same source is equivalent, fall back to the binary
    // already there and discard our own copy.
    match std::fs::rename(&tmp, &bin) {
        Ok(()) => {}
        Err(_) if bin.exists() => {
            let _ = std::fs::remove_file(&tmp);
        }
        Err(e) => panic!("move oracle binary into place: {e}"),
    }
    bin
}

/// A running `dcrd-oracle` subprocess speaking line-delimited JSON.
pub struct Oracle {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Oracle {
    /// Build (if needed) and spawn the oracle.
    pub fn spawn() -> Self {
        let bin = build_oracle();
        let mut child = Command::new(&bin)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn dcrd-oracle");
        let stdin = child.stdin.take().expect("oracle stdin");
        let stdout = BufReader::new(child.stdout.take().expect("oracle stdout"));
        Oracle {
            child,
            stdin,
            stdout,
        }
    }

    /// Issue a command whose sole argument is `data` (hex-encoded bytes) and
    /// return the raw JSON response object.
    pub fn call(&mut self, cmd: &str, data: &[u8]) -> serde_json::Value {
        writeln!(self.stdin, r#"{{"cmd":"{cmd}","data":"{}"}}"#, hex(data)).expect("write request");
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read response");
        serde_json::from_str(&line).expect("parse oracle response")
    }

    /// Like [`Self::call`], but panics on an error response and returns the
    /// `result` field.
    pub fn call_ok(&mut self, cmd: &str, data: &[u8]) -> String {
        let resp = self.call(cmd, data);
        if let Some(err) = resp.get("error").and_then(|e| e.as_str()) {
            panic!("oracle error for cmd {cmd}: {err}");
        }
        resp["result"]
            .as_str()
            .expect("result field present")
            .to_owned()
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
