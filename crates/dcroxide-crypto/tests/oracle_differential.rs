// SPDX-License-Identifier: ISC
//! Differential test: our BLAKE-256 vs. dcrd's `crypto/blake256`, live.
//!
//! This is the Phase 0 "demo differential test" from the project brief: it
//! builds `tools/oracle` (a Go shim linking the exact dcrd module versions
//! pinned by release-v2.1.5), streams inputs to it over the line-JSON
//! protocol, and byte-compares digests.
//!
//! Requires a Go toolchain. Without one the test skips, unless
//! `DCROXIDE_REQUIRE_ORACLE` is set (as it is in CI), in which case a missing
//! toolchain is a failure — differential coverage must never silently vanish
//! from CI.

use std::env;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use dcroxide_crypto::blake256;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Deterministic PRNG (SplitMix64) so failures reproduce from the printed
/// seed without pulling a rand dependency into the workspace.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

fn repo_root() -> &'static Path {
    // crates/dcroxide-crypto -> crates -> root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate lives two levels below the repo root")
}

fn go_available() -> bool {
    Command::new("go")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Build the oracle into `target/oracle/` and return the binary path.
fn build_oracle() -> PathBuf {
    let root = repo_root();
    let out_dir = root.join("target").join("oracle");
    std::fs::create_dir_all(&out_dir).expect("create target/oracle");
    let bin = out_dir.join(if cfg!(windows) {
        "dcrd-oracle.exe"
    } else {
        "dcrd-oracle"
    });

    let output = Command::new("go")
        .args(["build", "-o"])
        .arg(&bin)
        .arg(".")
        .current_dir(root.join("tools").join("oracle"))
        .output()
        .expect("run go build");
    assert!(
        output.status.success(),
        "go build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    bin
}

struct Oracle {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Oracle {
    fn spawn(bin: &Path) -> Self {
        let mut child = Command::new(bin)
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

    fn blake256(&mut self, data: &[u8]) -> String {
        writeln!(self.stdin, r#"{{"cmd":"blake256","data":"{}"}}"#, hex(data))
            .expect("write request");
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read response");
        let resp: serde_json::Value = serde_json::from_str(&line).expect("parse response");
        if let Some(err) = resp.get("error").and_then(|e| e.as_str()) {
            panic!("oracle error: {err}");
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

#[test]
fn blake256_matches_dcrd_oracle() {
    if !go_available() {
        assert!(
            env::var_os("DCROXIDE_REQUIRE_ORACLE").is_none(),
            "DCROXIDE_REQUIRE_ORACLE is set but no Go toolchain was found"
        );
        eprintln!(
            "skipping: Go toolchain not found (set DCROXIDE_REQUIRE_ORACLE to make this an error)"
        );
        return;
    }

    let bin = build_oracle();
    let mut oracle = Oracle::spawn(&bin);

    // The fixed KAT lengths first: every padding path, deterministically.
    for n in [
        0usize, 1, 32, 54, 55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, 129, 200,
    ] {
        let data: Vec<u8> = (0..n).map(|i| i as u8).collect();
        assert_eq!(
            hex(&blake256::sum256(&data)),
            oracle.blake256(&data),
            "pattern input, len {n}"
        );
    }

    // Then random inputs. Seed is printed so any failure reproduces exactly.
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos() as u64;
    println!("differential seed: {seed:#018x}");
    let mut rng = SplitMix64(seed);

    const CASES: usize = 5_000;
    for i in 0..CASES {
        let len = (rng.next() % 4097) as usize;
        let mut data = vec![0u8; len];
        rng.fill(&mut data);
        assert_eq!(
            hex(&blake256::sum256(&data)),
            oracle.blake256(&data),
            "random input {i}, len {len}, seed {seed:#018x}"
        );
    }
}
