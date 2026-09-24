// SPDX-License-Identifier: ISC
//! Internal test utilities for dcroxide differential tests.
//!
//! Provides the harness for `tools/oracle` (the Go shim linking dcrd's own
//! packages at the parity target, master `b9634e01`; its `go.mod` records how
//! each module is pinned) plus a deterministic PRNG and hex helpers, so every
//! crate's differential tests share one implementation.
//!
//! This crate is a dev-dependency only and is never published.

// Test-harness arithmetic (PRNG mixing, chunk math) — not consensus code.
#![allow(clippy::arithmetic_side_effects)]

use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

/// The directory the oracle is built into: `oracle/` in the running test
/// binary's profile directory, `<target-dir>/<profile>/oracle/`.
///
/// Derived from the test binary's own location rather than the source tree,
/// so the build lands wherever cargo's target directory is configured to be
/// (`CARGO_TARGET_DIR`, `build.target-dir`) and `cargo clean` removes it.
/// Test and bench harnesses run from `<profile>/deps`, one level down.
fn oracle_dir() -> PathBuf {
    let exe = env::current_exe().expect("locate the running test binary");
    let mut dir = exe
        .parent()
        .expect("test binary lives in a directory")
        .to_path_buf();
    if dir.file_name().is_some_and(|name| name == "deps") {
        dir.pop();
    }
    dir.join("oracle")
}

/// How many times this process has run `go build` for the oracle.
static ORACLE_BUILDS: AtomicUsize = AtomicUsize::new(0);

/// The oracle binary path, built on the first call in this process.
///
/// Go's build cache spares the recompile but not the link: every `go build
/// -o` relinks a binary that pulls in most of dcrd's modules, which is
/// seconds each, and every [`Oracle::spawn`] used to pay it. Once per test
/// process is enough, since the source cannot change under a running test.
/// Concurrent first callers wait for the one build rather than each running
/// their own.
fn build_oracle() -> PathBuf {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT.get_or_init(build_oracle_uncached).clone()
}

/// Build the oracle into [`oracle_dir`] and return the binary path.
///
/// Multiple test binaries run concurrently and each builds the oracle once,
/// so the build goes to a process-unique path first and is then atomically
/// renamed into place — spawning processes always see a complete binary.
fn build_oracle_uncached() -> PathBuf {
    ORACLE_BUILDS.fetch_add(1, Ordering::Relaxed);
    let root = repo_root();
    let out_dir = oracle_dir();
    std::fs::create_dir_all(&out_dir).expect("create the oracle build directory");
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    let bin = out_dir.join(format!("dcrd-oracle{suffix}"));
    // Unique per process: `build_oracle` runs this at most once in each.
    let tmp = out_dir.join(format!("dcrd-oracle-{}{suffix}", std::process::id()));

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

/// The dcrd commit this port is a parity port of.  A dcrd binary built from
/// anything else is a different specification, so the interop harness below
/// refuses to run against one.
///
/// At most nine characters: dcrd stamps `revision[:9]` into its version
/// string (`internal/version/version.go`), and a longer prefix could never
/// match it.  CI's `DCRD_COMMIT` and the pin in `tools/oracle/go.mod` must
/// name the same commit; a unit test below holds all three together.
pub const DCRD_PARITY_COMMIT: &str = "b9634e01";

/// A dcrd process running on simnet, for interop tests over a real socket.
///
/// The Go oracle links dcrd's packages in-process, which is the right tool
/// for comparing function results and cannot test the seam where two
/// programs talk to each other: version negotiation over TCP, framing across
/// real reads, and the timing of what each side sends when.  This runs the
/// actual daemon.
///
/// simnet is used because its proof of work is trivial (`PowLimitBits`
/// `0x207fffff`) and `GenerateSupported` is true, so blocks can be produced
/// on demand, and because it has no seeders to reach for.
pub struct DcrdNode {
    child: Child,
    /// The P2P address to dial.
    pub p2p_addr: String,
    /// dcrd's stdout and stderr, inside the data directory.
    log: PathBuf,
    _datadir: TempDir,
}

impl DcrdNode {
    /// Spawn dcrd on simnet with a temporary data directory and an
    /// ephemeral P2P port, waiting until it is listening.
    ///
    /// The binary comes from `DCROXIDE_DCRD_BIN`.  It must have been built
    /// from [`DCRD_PARITY_COMMIT`]: `dcrd --version` reports the VCS
    /// revision that `debug.ReadBuildInfo` recorded, and this checks it, so
    /// a release binary or a stale build fails loudly instead of quietly
    /// testing against the wrong specification.
    pub fn spawn() -> DcrdNode {
        DcrdNode::spawn_inner(None)
    }

    /// Spawn dcrd told to dial `addr` as a persistent peer.
    ///
    /// dcrd takes its connect targets at startup, so the listener has to
    /// exist before the daemon does; this is how the reverse direction (dcrd
    /// initiating to dcroxide) is exercised without an RPC surface.
    pub fn spawn_connecting_to(addr: &str) -> DcrdNode {
        DcrdNode::spawn_inner(Some(addr))
    }

    fn spawn_inner(connect: Option<&str>) -> DcrdNode {
        let bin = env::var("DCROXIDE_DCRD_BIN").expect("DCROXIDE_DCRD_BIN must name a dcrd binary");
        assert_dcrd_revision(&bin);

        let datadir = TempDir::new("dcrd-simnet");
        let port = free_port();
        let p2p_addr = format!("127.0.0.1:{port}");

        let mut cmd = Command::new(&bin);
        cmd.arg("--simnet")
            .arg(format!("--appdata={}", datadir.path().display()))
            .arg(format!("--listen={p2p_addr}"))
            .arg("--norpc")
            // No seeders: this node talks only to what the test names.
            .arg("--nodnsseed")
            .arg("--debuglevel=info");
        if let Some(addr) = connect {
            cmd.arg(format!("--connect={addr}"));
        }
        let log = datadir.path().join("dcrd.log");
        let mut child =
            spawn_logged(&mut cmd, &log).unwrap_or_else(|e| panic!("spawning {bin}: {e}"));

        // Wait for the socket rather than for a log line: the log format is
        // not a stable interface and a bound port is the thing under test.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if TcpStream::connect_timeout(
                &p2p_addr.parse().expect("valid loopback address"),
                Duration::from_millis(200),
            )
            .is_ok()
            {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "dcrd did not listen on {p2p_addr} within 30s\n{}",
                    log_tail(&log)
                );
            }
            if let Ok(Some(status)) = child.try_wait() {
                panic!("dcrd exited before listening: {status}\n{}", log_tail(&log));
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        DcrdNode {
            child,
            p2p_addr,
            log,
            _datadir: datadir,
        }
    }
}

impl Drop for DcrdNode {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // A failing interop test is the one time dcrd's side of the story
        // matters, and the data directory is about to be removed.
        if std::thread::panicking() {
            eprintln!("{}", log_tail(&self.log));
        }
    }
}

/// Spawn `cmd` with its stdout and stderr both written to the file `log`.
///
/// Neither may be a pipe that nobody reads.  dcrd writes every log line
/// synchronously to stdout (`log.go`, `logWriter.Write`), so once a pipe's
/// buffer fills (64 KiB on Linux) every goroutine that logs blocks in
/// write(2) and the node stops answering its peers, which a test would
/// report as an interop timeout.  A file never fills, and it keeps the
/// output for [`log_tail`].
fn spawn_logged(cmd: &mut Command, log: &Path) -> std::io::Result<Child> {
    let out = std::fs::File::create(log)?;
    let err = out.try_clone()?;
    cmd.stdout(out).stderr(err).spawn()
}

/// The last 64 KiB of dcrd's output, headed with where it came from.
fn log_tail(log: &Path) -> String {
    const TAIL: usize = 64 * 1024;
    match std::fs::read(log) {
        Ok(bytes) => {
            let start = bytes.len().saturating_sub(TAIL);
            format!(
                "--- dcrd output ({}, last {} bytes) ---\n{}",
                log.display(),
                bytes.len() - start,
                String::from_utf8_lossy(&bytes[start..])
            )
        }
        Err(e) => format!("--- dcrd output unavailable ({}): {e} ---", log.display()),
    }
}

/// Fail unless the binary was built from the parity commit.
///
/// dcrd stamps its VCS revision into `--version` through
/// `debug.ReadBuildInfo`, printing `2.2.0-pre+<revision>`. When that
/// revision is present it must be the pin: a release binary, or a build from
/// any other commit, is a different specification and would turn this
/// harness into a test of the wrong thing.
///
/// Go only stamps when it can read the repository, which excludes builds
/// from a linked git worktree (`.git` there is a file, not a directory) —
/// those print a bare `2.2.0-pre`. Rather than accept an unidentifiable
/// binary silently, that case demands `DCROXIDE_DCRD_ALLOW_UNSTAMPED`, so a
/// local convenience can never become CI's blind spot. CI builds from a
/// clone and a checkout, which stamps.
fn assert_dcrd_revision(bin: &str) {
    let out = Command::new(bin)
        .arg("--version")
        .output()
        .unwrap_or_else(|e| panic!("running {bin} --version: {e}"));
    let text = String::from_utf8_lossy(&out.stdout);
    let version = text.trim();

    if version.contains(DCRD_PARITY_COMMIT) {
        return;
    }

    // A stamped build carries "+<hex revision>" after the version.
    let stamped = version
        .split_whitespace()
        .any(|w| w.contains('+') && w.rsplit('+').next().is_some_and(|r| r.len() >= 8));
    assert!(
        !stamped,
        "dcrd at {bin} reports a VCS revision that is not the parity commit \
         {DCRD_PARITY_COMMIT}; that is a different specification. Got: {version}"
    );
    assert!(
        env::var_os("DCROXIDE_DCRD_ALLOW_UNSTAMPED").is_some(),
        "dcrd at {bin} carries no VCS revision ({version}), so it cannot be \
         confirmed to be the parity commit {DCRD_PARITY_COMMIT}. Build it from \
         a clone checked out at that commit, or set \
         DCROXIDE_DCRD_ALLOW_UNSTAMPED to accept an unidentified binary."
    );
}

/// An OS-assigned free TCP port.  Racy in principle; the listener is dropped
/// immediately and dcrd binds within milliseconds.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

/// A directory removed when dropped.
pub struct TempDir(PathBuf);

impl TempDir {
    fn new(prefix: &str) -> TempDir {
        let mut base = env::temp_dir();
        let unique = format!(
            "{prefix}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        );
        base.push(unique);
        std::fs::create_dir_all(&base).expect("create temp dir");
        TempDir(base)
    }

    /// The directory path.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A dcrd node, or `None` when `DCROXIDE_DCRD_BIN` is unset.
///
/// Mirrors [`oracle_or_skip`]: absent locally, mandatory in CI.  With
/// `DCROXIDE_REQUIRE_DCRD` set, a missing binary panics rather than skipping,
/// so the interop leg cannot silently stop testing anything.
pub fn dcrd_or_skip() -> Option<DcrdNode> {
    if env::var_os("DCROXIDE_DCRD_BIN").is_none() {
        assert!(
            env::var_os("DCROXIDE_REQUIRE_DCRD").is_none(),
            "DCROXIDE_REQUIRE_DCRD is set but DCROXIDE_DCRD_BIN names no binary"
        );
        eprintln!(
            "skipping: DCROXIDE_DCRD_BIN unset (set DCROXIDE_REQUIRE_DCRD to make this an error)"
        );
        return None;
    }
    Some(DcrdNode::spawn())
}

/// Whether the interop harness can run, applying the same skip-or-fail rule
/// as [`dcrd_or_skip`] without spawning a node — for tests that must bind a
/// listener before dcrd starts.
pub fn dcrd_available() -> bool {
    if env::var_os("DCROXIDE_DCRD_BIN").is_none() {
        assert!(
            env::var_os("DCROXIDE_REQUIRE_DCRD").is_none(),
            "DCROXIDE_REQUIRE_DCRD is set but DCROXIDE_DCRD_BIN names no binary"
        );
        eprintln!(
            "skipping: DCROXIDE_DCRD_BIN unset (set DCROXIDE_REQUIRE_DCRD to make this an error)"
        );
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pin the interop harness enforces is the commit CI builds dcrd
    /// from and the commit the oracle links: the harness once required
    /// `29f17894` while everything else had moved to `b9634e01`, so a dcrd
    /// built at the real pin was refused as "a different specification".
    #[test]
    fn the_dcrd_pin_matches_ci_and_the_oracle() {
        assert!(
            DCRD_PARITY_COMMIT.len() <= 9,
            "dcrd stamps a 9-character revision; a longer pin never matches it"
        );

        let ci_path = repo_root().join(".github").join("workflows").join("ci.yml");
        let ci = std::fs::read_to_string(&ci_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", ci_path.display()));
        let ci_commit = ci
            .lines()
            .find_map(|l| l.trim().strip_prefix("DCRD_COMMIT:"))
            .expect("ci.yml sets DCRD_COMMIT")
            .trim();
        assert!(
            ci_commit.starts_with(DCRD_PARITY_COMMIT),
            "CI builds dcrd at {ci_commit}, but the harness requires {DCRD_PARITY_COMMIT}"
        );

        let gomod_path = repo_root().join("tools").join("oracle").join("go.mod");
        let gomod = std::fs::read_to_string(&gomod_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", gomod_path.display()));
        let oracle_pin: String = gomod
            .split("dcrd master commit ")
            .nth(1)
            .expect("tools/oracle/go.mod names the parity commit")
            .chars()
            .take_while(char::is_ascii_hexdigit)
            .collect();
        assert_eq!(
            oracle_pin, DCRD_PARITY_COMMIT,
            "the oracle links dcrd at {oracle_pin}, but the harness requires {DCRD_PARITY_COMMIT}"
        );
    }

    /// A child that writes far more than a pipe buffer holds, on both
    /// streams, still runs to completion: dcrd blocks in write(2) on a full
    /// pipe that nobody drains.
    #[cfg(unix)]
    #[test]
    fn a_chatty_child_does_not_block_on_its_output() {
        const EACH: u64 = 1024 * 1024;
        let dir = TempDir::new("spawn-logged");
        let log = dir.path().join("out.log");
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(format!(
            "head -c {EACH} /dev/zero; head -c {EACH} /dev/zero >&2"
        ));
        let mut child = spawn_logged(&mut cmd, &log).expect("spawn sh");

        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.try_wait().expect("poll the child") {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the child blocked writing its output");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(status.success(), "sh failed: {status}");
        let written = std::fs::metadata(&log).expect("log exists").len();
        assert_eq!(written, 2 * EACH, "both streams land in the log");
        assert!(log_tail(&log).contains("last 65536 bytes"));
    }

    /// Spawning the oracle repeatedly builds it once per process.
    #[test]
    fn the_oracle_is_built_once_per_process() {
        let Some(first) = oracle_or_skip() else {
            return;
        };
        let second = Oracle::spawn();
        drop((first, second));
        assert_eq!(build_oracle(), build_oracle());
        assert_eq!(
            ORACLE_BUILDS.load(Ordering::Relaxed),
            1,
            "every spawn after the first must reuse the built binary"
        );
    }
}
