// SPDX-License-Identifier: ISC
//! Internal test utilities for dcroxide differential tests.
//!
//! Provides the harness for `tools/oracle` (the Go shim linking dcrd's own
//! packages at the parity pin, master `3360ae4d`; its `go.mod` records how
//! each module is pinned) plus a deterministic PRNG and hex helpers, so every
//! crate's differential tests share one implementation, the power-loss
//! storage rig the crash suites cut power under ([`powerloss`]), and the
//! gate that holds a metadata commit running on a thread of its own
//! ([`gate`]).
//!
//! This crate is a dev-dependency only and is never published.

pub mod gate;
pub mod powerloss;

use std::env;
use std::ffi::OsStr;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Lowercase hex digits, indexed by the value of a nibble.
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Encode bytes as lowercase hex.
pub fn hex(b: &[u8]) -> String {
    let mut out = String::new();
    push_hex(&mut out, b);
    out
}

/// Append the lowercase hex of `b` to `out`, two digits a byte looked up in
/// a 16-entry table, with one reservation up front rather than an allocation
/// per byte.  A caller that builds many lines into one reused `String`, as a
/// client keeping requests in flight does, encodes each without a `String`
/// of its own.
pub fn push_hex(out: &mut String, b: &[u8]) {
    out.reserve(b.len().saturating_mul(2));
    for &byte in b {
        out.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
}

/// Decode a lowercase/uppercase hex string; panics on invalid input (tests).
#[allow(
    clippy::arithmetic_side_effects,
    reason = "i < s.len() <= isize::MAX, so i + 2 cannot overflow usize"
)]
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

/// Replays a printed seed: set to the `0x…` value a failed run printed, it
/// seeds every [`SplitMix64::from_entropy`] in the process in place of the
/// clock.  Each test seeds once, so run the failing test alone by name.
pub const SEED_VAR: &str = "DCROXIDE_TEST_SEED";

impl SplitMix64 {
    /// Seed from the wall clock, or from [`SEED_VAR`] when it is set, and
    /// print the seed for reproduction.
    pub fn from_entropy(label: &str) -> Self {
        let (seed, source) = match env::var_os(SEED_VAR) {
            Some(value) => {
                let value = value.to_string_lossy();
                let seed = parse_seed(&value).unwrap_or_else(|| {
                    panic!("{SEED_VAR}={value:?} is not a hex seed like the ones printed here")
                });
                (seed, " (from DCROXIDE_TEST_SEED)")
            }
            None => {
                let seed = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("clock after epoch")
                    .as_nanos() as u64;
                (seed, "")
            }
        };
        println!("{label}: seed {seed:#018x}{source}");
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
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "callers pass n > 0, and u64 % n cannot overflow"
    )]
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
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "max_len is a test buffer length, far below u64::MAX"
        )]
        let len = self.below(max_len as u64 + 1) as usize;
        let mut v = vec![0u8; len];
        self.fill(&mut v);
        v
    }

    /// The sub-seed of stream `label`, number `index`, under `master`, so
    /// one printed master seed reproduces many independent streams: one for
    /// each class of input, say, and one for each case within a class.  For
    /// more than one index, nest the calls:
    /// `derive(derive(master, "worker", w), "case", i)`.
    ///
    /// A state starting at `master` absorbs, in turn, the label's UTF-8
    /// bytes as little-endian words of eight (the last one zero-padded), the
    /// label's length in bytes, and `index`.  Each word is xored into the
    /// state, which is then replaced by the output of one SplitMix64 step
    /// from it.  Nothing but wrapping `u64` arithmetic and an explicit byte
    /// order goes in, so a sub-seed is the same on every platform.  Every
    /// step is a bijection of the state: with the label and index fixed,
    /// distinct masters give distinct sub-seeds, and with the master and
    /// label fixed, so do distinct indices.  The length keeps a label apart
    /// from the same label with NUL bytes appended, which pads to the same
    /// words.
    ///
    /// Recorded seeds replay only while this construction stays as it is;
    /// a known-answer test pins it.
    pub fn derive(master: u64, label: &str, index: u64) -> u64 {
        let absorb = |state: u64, word: u64| SplitMix64(state ^ word).next_u64();
        let mut state = master;
        for chunk in label.as_bytes().chunks(8) {
            let mut word = [0u8; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            state = absorb(state, u64::from_le_bytes(word));
        }
        state = absorb(state, label.len() as u64);
        absorb(state, index)
    }
}

/// Parse a seed as [`SplitMix64::from_entropy`] prints it: hex, with or
/// without the `0x` prefix, surrounding whitespace ignored.  `None` for
/// anything else, including an empty string and a value wider than 64 bits,
/// so a tool reading a seed from its command line takes the same values
/// [`SEED_VAR`] does.
pub fn parse_seed(value: &str) -> Option<u64> {
    let value = value.trim();
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

/// Returns whether a Go toolchain is available.
pub fn go_available() -> bool {
    Command::new("go")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Names a prebuilt `dcrd-oracle` to run in place of building `tools/oracle`
/// in every test process: an absolute path (each test binary runs in its own
/// crate's directory, where a relative one would name a different file) to a
/// binary built from this checkout's `tools/oracle` with `go build -o`.
/// Every test process, and every job that runs them, can share one build
/// this way, and a run with it set needs no Go toolchain.  Unset or empty,
/// the oracle is built as usual.  The binary is taken as found: one built
/// before a change to `tools/oracle` answers for the old source.
pub const ORACLE_BIN_VAR: &str = "DCROXIDE_ORACLE_BIN";

/// The Go CI takes the oracle's verdicts from, as `runtime.Version()`
/// names it: the reference Go of ADR-0001's 2026-10-26 addendum, which
/// `ci.yml`'s `GO_VERSION` installs.
pub const REFERENCE_GO: &str = "go1.26.2";

/// Under `DCROXIDE_REQUIRE_ORACLE`, as in CI, panic unless `go_version`, the
/// `go_version` an oracle response reports, is [`REFERENCE_GO`]: a test
/// that holds the port to the oracle's verdicts then holds it to the
/// reference Go's.  Without it any Go is taken, so a local run compares
/// with the Go it has.
pub fn require_reference_go(go_version: &str) {
    assert!(
        env::var_os("DCROXIDE_REQUIRE_ORACLE").is_none() || go_version == REFERENCE_GO,
        "DCROXIDE_REQUIRE_ORACLE is set but the oracle runs {go_version:?}, not the \
         reference Go, {REFERENCE_GO}"
    );
}

/// Skip-or-fail policy shared by all differential tests: without an oracle
/// the test skips (returns None), unless `DCROXIDE_REQUIRE_ORACLE` is set
/// (as in CI), in which case a missing oracle panics so that differential
/// coverage can never silently vanish from CI.
///
/// The oracle is the binary [`ORACLE_BIN_VAR`] (`DCROXIDE_ORACLE_BIN`)
/// names, or else `tools/oracle` built with the Go toolchain on `PATH`.  It
/// is missing when that variable names anything but an absolute path to a
/// file, or when it is unset and no Go toolchain is found.
pub fn oracle_or_skip() -> Option<Oracle> {
    oracle_bin_or_skip().map(|bin| Oracle::spawn_at(&bin))
}

/// The oracle binary [`oracle_or_skip`] would spawn, under the same
/// skip-or-fail policy, for a test that runs the oracle itself (several at
/// once, with requests in flight) rather than through [`Oracle`]: `None`
/// where that would skip, a panic where it would fail, and otherwise the
/// path, after building `tools/oracle` once in this process when
/// [`ORACLE_BIN_VAR`] names no binary.
pub fn oracle_bin_or_skip() -> Option<PathBuf> {
    match choose_oracle(env::var_os(ORACLE_BIN_VAR).as_deref(), go_available) {
        Ok(source) => Some(source.path()),
        Err(why) => {
            assert!(
                env::var_os("DCROXIDE_REQUIRE_ORACLE").is_none(),
                "DCROXIDE_REQUIRE_ORACLE is set but {why}"
            );
            eprintln!("skipping: {why} (set DCROXIDE_REQUIRE_ORACLE to make this an error)");
            None
        }
    }
}

/// The oracle binary, as [`oracle_bin_or_skip`] chooses it, for a caller
/// that cannot run without one: where that would skip, this panics.
pub fn oracle_bin() -> PathBuf {
    choose_oracle(env::var_os(ORACLE_BIN_VAR).as_deref(), go_available)
        .unwrap_or_else(|why| panic!("cannot spawn the oracle: {why}"))
        .path()
}

/// Where the oracle binary comes from.
#[derive(Debug, PartialEq, Eq)]
enum OracleSource {
    /// The prebuilt binary [`ORACLE_BIN_VAR`] names.
    Prebuilt(PathBuf),
    /// `tools/oracle`, built by [`build_oracle`].
    Build,
}

impl OracleSource {
    /// The binary's path, building it first if it comes from source.
    fn path(self) -> PathBuf {
        match self {
            OracleSource::Prebuilt(path) => path,
            OracleSource::Build => build_oracle(),
        }
    }
}

/// Choose the oracle given the value of [`ORACLE_BIN_VAR`], or say why there
/// is none.  `go_available` is asked only when no binary is named: a
/// prebuilt oracle needs no Go toolchain.
fn choose_oracle(
    named: Option<&OsStr>,
    go_available: impl FnOnce() -> bool,
) -> Result<OracleSource, String> {
    match named.filter(|value| !value.is_empty()).map(Path::new) {
        Some(path) if !path.is_absolute() => Err(format!(
            "{ORACLE_BIN_VAR} names {}, which is not an absolute path",
            path.display()
        )),
        Some(path) if !path.is_file() => Err(format!(
            "{ORACLE_BIN_VAR} names {}, which is not a file",
            path.display()
        )),
        Some(path) => Ok(OracleSource::Prebuilt(path.to_path_buf())),
        None if go_available() => Ok(OracleSource::Build),
        None => Err("no Go toolchain was found".to_owned()),
    }
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

/// Append an oracle request line, newline included: `{"cmd":…,"data":…}`
/// with `data` hex-encoded.  `cmd` is one of the oracle's command names and
/// goes in unescaped.
fn push_request(line: &mut String, cmd: &str, data: &[u8]) {
    line.push_str(r#"{"cmd":""#);
    line.push_str(cmd);
    line.push_str(r#"","data":""#);
    push_hex(line, data);
    line.push_str("\"}\n");
}

/// A running `dcrd-oracle` subprocess speaking line-delimited JSON.
pub struct Oracle {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    /// The line being written or read, kept across calls for its capacity.
    line: String,
}

impl Oracle {
    /// Spawn the oracle [`oracle_or_skip`] would, building it if needed;
    /// where that would skip, this panics.
    pub fn spawn() -> Self {
        Oracle::spawn_at(&oracle_bin())
    }

    /// Spawn the oracle binary at `bin`.  Panics, naming it, when it cannot
    /// be spawned.
    pub fn spawn_at(bin: &Path) -> Self {
        Oracle::from_command(&mut Command::new(bin))
    }

    /// Spawn `cmd` as the oracle, its stdin and stdout piped and its stderr
    /// as `cmd` leaves it (inherited unless set): a test can stand a script
    /// in for the oracle this way.  Panics, naming the program, when it
    /// cannot be spawned.
    pub fn from_command(cmd: &mut Command) -> Self {
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {}: {e}", Path::new(cmd.get_program()).display()));
        let stdin = child.stdin.take().expect("oracle stdin");
        let stdout = BufReader::new(child.stdout.take().expect("oracle stdout"));
        Oracle {
            child,
            stdin,
            stdout,
            line: String::new(),
        }
    }

    /// Issue a command whose sole argument is `data` (hex-encoded bytes) and
    /// return the raw JSON response object.  Panics, naming `cmd`, when the
    /// oracle does not answer ([`Self::try_call_line`]) or its answer is not
    /// JSON.
    pub fn call(&mut self, cmd: &str, data: &[u8]) -> serde_json::Value {
        let line = self
            .try_call_line(cmd, data)
            .unwrap_or_else(|why| panic!("oracle {cmd}: {why}"));
        serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("oracle {cmd}: parse oracle response {line:?}: {e}"))
    }

    /// [`Self::call`]'s exchange with a failure returned rather than
    /// panicked on: the response line as read, newline included, borrowed
    /// until the next call.  Every failure names the oracle's exit status
    /// when it has one, whether the oracle had exited before the request,
    /// refused its write or closed its output without answering.
    ///
    /// The exit is looked for before the request is written, so a request
    /// to an oracle that has exited is an error even in a process where
    /// writing to a closed pipe ends the process by `SIGPIPE` (a libFuzzer
    /// binary, whose `main` is not Rust's).  An oracle killed from outside
    /// between that look and the write can still end such a process.
    pub fn try_call_line(&mut self, cmd: &str, data: &[u8]) -> Result<&str, String> {
        match self.child.try_wait() {
            Ok(Some(status)) => return Err(format!("the oracle had already exited ({status})")),
            Ok(None) => {}
            Err(e) => return Err(format!("poll the oracle: {e}")),
        }
        // One write for the whole line: `ChildStdin` is unbuffered, so
        // formatting straight into it costs a write(2) a piece.
        self.line.clear();
        push_request(&mut self.line, cmd, data);
        if let Err(e) = self.stdin.write_all(self.line.as_bytes()) {
            return Err(format!("write request: {e}; {}", self.exit_note()));
        }
        self.line.clear();
        match self.stdout.read_line(&mut self.line) {
            Ok(0) => Err(format!(
                "the oracle closed its output without answering; {}",
                self.exit_note()
            )),
            Ok(_) => Ok(&self.line),
            Err(e) => Err(format!("read response: {e}")),
        }
    }

    /// The oracle's exit status, waited for at most 5 s, for the message of
    /// a failed call.  A bounded poll rather than `wait`: an oracle that
    /// closed its output but lives on would block `wait` for ever, since
    /// its stdin is held here, out of the `Child`.
    fn exit_note(&mut self) -> String {
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "now plus 5 seconds is far inside Instant's range"
        )]
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return format!("the oracle exited ({status})"),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => return "the oracle had not exited after 5 s".to_owned(),
                Err(e) => return format!("poll the oracle: {e}"),
            }
        }
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
/// match it.  CI's `DCRD_COMMIT` and the pseudo-versions in
/// `tools/oracle/go.mod` and `tools/fullblockgen/go.mod` must name the same
/// commit; a unit test below holds them all together.
pub const DCRD_PARITY_COMMIT: &str = "3360ae4d";

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
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "now plus 30 seconds is far inside Instant's range"
        )]
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
#[allow(
    clippy::arithmetic_side_effects,
    reason = "start = bytes.len().saturating_sub(TAIL) <= bytes.len()"
)]
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
    /// Create a fresh directory under the system's temporary directory,
    /// named for `prefix`, this process, a count of the directories it has
    /// made and the time, so neither two threads of one test process (on a
    /// clock too coarse to tell their calls apart) nor two processes share
    /// one.  Panics if it cannot be created.
    pub fn new(prefix: &str) -> TempDir {
        static MADE: AtomicUsize = AtomicUsize::new(0);
        let mut base = env::temp_dir();
        let unique = format!(
            "{prefix}-{}-{}-{}",
            std::process::id(),
            MADE.fetch_add(1, Ordering::Relaxed),
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

/// The 12-hex commit a Go pseudo-version names, or `None` for a plain tag
/// (`v5.0.3`) or anything else.  A pseudo-version ends
/// `<14-digit timestamp>-<12-hex commit>`, the timestamp following a `-`
/// (`v0.0.0-…`) or a `.` (`v1.2.4-0.…`, `v1.2.3-pre.0.…`).  It is the rule
/// this crate's pin test applies to the `go.mod` files of the Go tools,
/// shared with tools that check the versions a built oracle reports.
pub fn pseudo_version_commit(version: &str) -> Option<&str> {
    let (rest, commit) = version.rsplit_once('-')?;
    let (sep, stamp) = rest
        .get(rest.len().checked_sub(15)?..)?
        .split_at_checked(1)?;
    let pseudo = commit.len() == 12
        && commit.bytes().all(|b| b.is_ascii_hexdigit())
        && (sep == "-" || sep == ".")
        && stamp.bytes().all(|b| b.is_ascii_digit());
    pseudo.then_some(commit)
}

/// The RSA keys of the test-key fixture, `data/rsa-test-keys.json`, each a
/// name with its modulus length in bits and its public exponent: moduli
/// of 1024, 2040, 2041, 2048, 3072, 4096, 8192 and 8193 bits with
/// e = 65537, and 2048-bit moduli with e = 3, 2^31 - 1, 2^31 + 1,
/// 2^33 - 1 and 2^33 + 1.  They sit at the edges of ring's RSA limits and
/// Go's, which `dcroxide-tlscrypto` holds its RSA verification to
/// (ADR-0015 T5), and serve as RSA keys in its other tests, since Go's key
/// generation is slow at these lengths and, from Go 1.26, never makes the
/// same key twice.
///
/// Test-only keys, made once by the oracle's `rsa_keygen` through the
/// ignored `regenerate_rsa_test_keys` below, and kept as hex components
/// rather than PEM, so no private-key block sits in the tree.  They sign
/// nothing outside the tests and must never be used as real keys.
///
/// `dcroxide-tlscrypto`'s signature parity corpus names these keys and
/// records signatures under them, with ring's verdicts, so new keys make
/// its recorded RSA verdicts wrong: the corpus has to be made again with
/// them, which only a tree that still has ring can do.  Once ring is gone
/// the fixture's keys stay as they are, and a key is added by appending
/// `rsa_keygen`'s answer for it and its entry here.
pub const RSA_TEST_KEYS: &[(&str, u64, u64)] = &[
    ("rsa1024", 1024, 65537),
    ("rsa2040", 2040, 65537),
    ("rsa2041", 2041, 65537),
    ("rsa2048", 2048, 65537),
    ("rsa3072", 3072, 65537),
    ("rsa4096", 4096, 65537),
    ("rsa8192", 8192, 65537),
    ("rsa8193", 8193, 65537),
    ("rsa2048-e3", 2048, 3),
    ("rsa2048-e2147483647", 2048, (1 << 31) - 1),
    ("rsa2048-e2147483649", 2048, (1 << 31) + 1),
    ("rsa2048-e8589934591", 2048, (1 << 33) - 1),
    ("rsa2048-e8589934593", 2048, (1 << 33) + 1),
];

/// A key of the RSA test-key fixture ([`RSA_TEST_KEYS`]): each component
/// big-endian, without leading zeros.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsaTestKey {
    /// The key's name in the fixture.
    pub name: String,
    /// The modulus's length in bits.
    pub bits: u64,
    /// The modulus.
    pub n: Vec<u8>,
    /// The public exponent.
    pub e: Vec<u8>,
    /// The private exponent.
    pub d: Vec<u8>,
    /// The first prime.
    pub p: Vec<u8>,
    /// The second prime.
    pub q: Vec<u8>,
}

impl RsaTestKey {
    /// The key's `RSAPublicKey` (RFC 8017 §A.1.1), as a SubjectPublicKeyInfo
    /// carries it: a SEQUENCE of the modulus and the exponent as INTEGERs,
    /// each with the sign byte DER needs, in lengths of the fewest bytes.
    pub fn rsa_public_key(&self) -> Vec<u8> {
        der_element(0x30, &[der_integer(&self.n), der_integer(&self.e)].concat())
    }

    /// The key's components as the oracle takes an RSA key: an object of
    /// `n`, `e`, `d`, `p` and `q` in hex.
    pub fn oracle_json(&self) -> serde_json::Value {
        serde_json::json!({
            "n": hex(&self.n),
            "e": hex(&self.e),
            "d": hex(&self.d),
            "p": hex(&self.p),
            "q": hex(&self.q),
        })
    }
}

/// A DER INTEGER of the unsigned big-endian `value`: a zero byte ahead of
/// a top bit that is set.
fn der_integer(value: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(value.len().saturating_add(1));
    if value.first().is_none_or(|first| first & 0x80 != 0) {
        content.push(0);
    }
    content.extend_from_slice(value);
    der_element(0x02, &content)
}

/// A DER element: `tag`, its content's length in the fewest bytes, and
/// `content`.
fn der_element(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len().to_be_bytes();
    let digits = &len[len.iter().position(|&b| b != 0).unwrap_or(len.len())..];
    let mut out = vec![tag];
    match digits {
        [] => out.push(0),
        [short] if *short < 0x80 => out.push(*short),
        _ => {
            out.push(0x80 | u8::try_from(digits.len()).expect("at most eight length bytes"));
            out.extend_from_slice(digits);
        }
    }
    out.extend_from_slice(content);
    out
}

/// Where the RSA test-key fixture lives.
fn rsa_test_keys_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("rsa-test-keys.json")
}

/// The RSA test key `name` ([`RSA_TEST_KEYS`]); panics on a name the
/// fixture lacks.  The fixture is read once per process.
pub fn rsa_test_key(name: &str) -> RsaTestKey {
    static KEYS: OnceLock<Vec<RsaTestKey>> = OnceLock::new();
    KEYS.get_or_init(|| {
        let path = rsa_test_keys_path();
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let fixture: serde_json::Value =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
        fixture["keys"]
            .as_array()
            .unwrap_or_else(|| panic!("{}: no keys", path.display()))
            .iter()
            .map(|key| {
                let field = |name: &str| {
                    key[name]
                        .as_str()
                        .unwrap_or_else(|| panic!("{}: a key without {name}", path.display()))
                };
                RsaTestKey {
                    name: field("name").to_owned(),
                    bits: key["bits"]
                        .as_u64()
                        .unwrap_or_else(|| panic!("{}: a key without its bits", path.display())),
                    n: unhex(field("n")),
                    e: unhex(field("e")),
                    d: unhex(field("d")),
                    p: unhex(field("p")),
                    q: unhex(field("q")),
                }
            })
            .collect()
    })
    .iter()
    .find(|key| key.name == name)
    .unwrap_or_else(|| panic!("no RSA test key named {name:?}"))
    .clone()
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    /// The dcrd modules a `go.mod` pins by pseudo-version, each with the
    /// 12-hex commit its version names ([`pseudo_version_commit`]).
    fn dcrd_pseudo_pins(gomod: &str) -> Vec<(&str, &str)> {
        gomod
            .lines()
            .filter_map(|line| {
                let code = line.split("//").next()?.trim();
                let code = code.strip_prefix("require ").unwrap_or(code);
                let mut fields = code.split_whitespace();
                let (module, version) = (fields.next()?, fields.next()?);
                if module != "github.com/decred/dcrd"
                    && !module.starts_with("github.com/decred/dcrd/")
                {
                    return None;
                }
                Some((module, pseudo_version_commit(version)?))
            })
            .collect()
    }

    /// The commit of each pseudo-version form Go writes, and none for tags.
    #[test]
    fn pseudo_version_commit_known_answers() {
        for (version, want) in [
            ("v4.4.2-0.20261019113547-3360ae4dbef8", Some("3360ae4dbef8")),
            ("v0.0.0-20170116200512-5312a6153412", Some("5312a6153412")),
            (
                "v1.2.3-pre.0.20260927225945-6f6cf21bd26d",
                Some("6f6cf21bd26d"),
            ),
            ("v5.0.3", None),
            ("v1.0.6", None),
            ("v1.0.0-rc1", None),
            ("v1.0.0-20170116200512-5312a615341", None),
            ("v1.0.0-2017011620051x-5312a6153412", None),
            ("x\u{e9}0000000000000-5312a6153412", None),
            ("", None),
        ] {
            assert_eq!(pseudo_version_commit(version), want, "{version:?}");
        }
    }

    /// Whether a Go tool (the oracle, or the full block battery generator)
    /// links dcrd at `pin`, judged by what its `go.mod` `require`s rather
    /// than what its comments say: every dcrd module
    /// pinned by pseudo-version names that commit, at least one is (so a
    /// reformat cannot turn this into a check of nothing), and no
    /// `replace` points a dcrd module somewhere else.  The tag-pinned
    /// modules are the ones the header records as byte-identical to their
    /// tag at the pin, which only a diff against the checkout can confirm.
    /// Returns the number of pseudo-pinned modules.
    fn check_oracle_links(gomod: &str, pin: &str) -> Result<usize, String> {
        if let Some(line) = gomod.lines().find(|l| {
            l.split("//")
                .next()
                .and_then(|code| code.split_once("=>"))
                .is_some_and(|(lhs, _)| lhs.contains("github.com/decred/dcrd"))
        }) {
            return Err(format!("`{}` replaces a dcrd module", line.trim()));
        }
        let pins = dcrd_pseudo_pins(gomod);
        if pins.is_empty() {
            return Err("no dcrd module is pinned by pseudo-version".to_string());
        }
        let stale: Vec<String> = pins
            .iter()
            .filter(|(_, commit)| !commit.starts_with(pin))
            .map(|(module, commit)| format!("{module} at {commit}"))
            .collect();
        if !stale.is_empty() {
            return Err(format!(
                "it links {}, but the harness requires {pin}",
                stale.join(", ")
            ));
        }
        Ok(pins.len())
    }

    /// The oracle check reads the `require` lines, not the header comment:
    /// a bump that moved the comment but left a module at the old commit,
    /// one that pins no module by commit, and a `replace` are all caught.
    #[test]
    fn the_oracle_pin_check_reads_the_linked_versions() {
        let good = "// Pinned to the parity target, dcrd master commit 6f6cf21b: ...\n\
                    require (\n\
                    \tgithub.com/decred/base58 v1.0.6\n\
                    \tgithub.com/decred/dcrd/chaincfg/chainhash v1.0.5\n\
                    \tgithub.com/decred/dcrd/wire v1.7.6-0.20260927225945-6f6cf21bd26d\n\
                    )\n\
                    require github.com/decred/dcrd/crypto/rand \
                    v1.0.2-0.20260927225945-6f6cf21bd26d // indirect\n";
        assert_eq!(check_oracle_links(good, "6f6cf21b"), Ok(2));

        let stale = good.replacen("6f6cf21bd26d", "29f178940e5b", 1);
        let err = check_oracle_links(&stale, "6f6cf21b").expect_err("wire left behind");
        assert!(
            err.contains("github.com/decred/dcrd/wire at 29f178940e5b"),
            "{err}"
        );

        let none = "// dcrd master commit 6f6cf21b\nrequire github.com/decred/dcrd/wire v1.7.5\n";
        assert!(check_oracle_links(none, "6f6cf21b").is_err());

        let replaced = format!("{good}replace github.com/decred/dcrd/wire => ../wire\n");
        assert!(check_oracle_links(&replaced, "6f6cf21b").is_err());

        let forms = "\tgithub.com/decred/dcrd/a v0.0.0-20260927225945-6f6cf21bd26d\n\
                     \tgithub.com/decred/dcrd/b/v2 v2.0.0-pre.0.20260927225945-6f6cf21bd26d\n\
                     \tgithub.com/decred/dcrd/c v1.0.0-rc1\n";
        assert_eq!(dcrd_pseudo_pins(forms).len(), 2);
    }

    /// A printed seed replays: with `DCROXIDE_TEST_SEED` set,
    /// `from_entropy` starts from it instead of the clock, and a value that
    /// is not a seed fails rather than being ignored.
    #[test]
    fn a_printed_seed_replays() {
        const CHILD: &str = "DCROXIDE_TESTUTIL_SEED_CHILD";
        if env::var_os(CHILD).is_some() {
            let rng = SplitMix64::from_entropy("replay");
            assert_eq!(rng.0, 0x0123_4567_89ab_cdef);
            return;
        }

        assert_eq!(
            parse_seed("0x0123456789abcdef"),
            Some(0x0123_4567_89ab_cdef)
        );
        assert_eq!(parse_seed("0X00000000000000FF"), Some(0xff));
        assert_eq!(parse_seed("ff"), Some(0xff));
        assert_eq!(parse_seed("0x"), None);
        assert_eq!(parse_seed("+ff"), None);
        assert_eq!(parse_seed("0x1ffffffffffffffff"), None);

        let exe = env::current_exe().expect("test binary path");
        let run = |seed: &str| {
            Command::new(&exe)
                .args(["--exact", "tests::a_printed_seed_replays", "--nocapture"])
                .env(CHILD, "1")
                .env(SEED_VAR, seed)
                .output()
                .expect("run the child")
        };
        let replay = run("0x0123456789abcdef");
        let stdout = String::from_utf8_lossy(&replay.stdout);
        assert!(
            replay.status.success(),
            "{stdout}{}",
            String::from_utf8_lossy(&replay.stderr)
        );
        assert!(
            stdout.contains("replay: seed 0x0123456789abcdef (from DCROXIDE_TEST_SEED)"),
            "{stdout}"
        );
        assert!(!run("not-a-seed").status.success());
    }

    /// A sub-seed depends on the master, the label and the index and on
    /// nothing else: the known answers come from a model of the documented
    /// construction written apart from this one, and none of the labels
    /// below, nor any index, lands on another's sub-seed.
    #[test]
    fn derive_is_deterministic_and_tells_labels_and_indices_apart() {
        const MASTER: u64 = 0x0123_4567_89ab_cdef;
        for (master, label, index, want) in [
            (0, "", 0, 0xa706_dd2f_4d19_7e6f),
            (MASTER, "", 0, 0x021c_88d0_a3fd_73b6),
            (MASTER, "EV-xGEN-true", 7, 0xd694_e2f7_b11c_6b18),
            (MASTER, "a", 0, 0xacc5_f4af_4882_c14e),
            (MASTER, "a\0", 0, 0xdf1e_052c_6e59_7851),
            (u64::MAX, "class/éè", u64::MAX, 0x2c3f_7fc3_15d6_16a1),
        ] {
            assert_eq!(
                SplitMix64::derive(master, label, index),
                want,
                "derive({master:#x}, {label:?}, {index})"
            );
        }

        // Prefixes, NUL padding, word boundaries and near-identical names.
        let labels = [
            "",
            "\0",
            "a",
            "a\0",
            "b",
            "ab",
            "ba",
            "abcdefgh",
            "abcdefgh\0",
            "abcdefghi",
            "EV-xGEN-true",
            "EV-xGEN-false",
        ];
        let mut seen = std::collections::HashSet::new();
        for label in labels {
            for index in 0..512 {
                let seed = SplitMix64::derive(MASTER, label, index);
                assert!(seen.insert(seed), "{label:?} {index} repeats a sub-seed");
                assert_ne!(seed, MASTER, "{label:?} {index} returns the master");
            }
        }
        for bit in 0..64 {
            assert_ne!(
                SplitMix64::derive(MASTER ^ (1 << bit), "a", 0),
                SplitMix64::derive(MASTER, "a", 0),
                "flipping master bit {bit} changes nothing"
            );
        }
    }

    /// The table-driven encoder writes what `{:02x}` does, for every byte.
    #[test]
    fn hex_encodes_every_byte_as_format_does() {
        let all: Vec<u8> = (0..=u8::MAX).collect();
        let want: String = all.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex(&all), want);
        assert_eq!(hex(&[]), "");
        assert_eq!(unhex(&hex(&all)), all);
    }

    /// A request is the line the oracle has always read, built whole for
    /// its one write.
    #[test]
    fn a_request_is_one_json_line() {
        let mut line = String::new();
        push_request(&mut line, "ecdsa_verify", &[0x00, 0xab, 0xff]);
        assert_eq!(line, "{\"cmd\":\"ecdsa_verify\",\"data\":\"00abff\"}\n");
        let parsed: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
        assert_eq!(parsed["cmd"], "ecdsa_verify");
        line.clear();
        push_request(&mut line, "blake256", &[]);
        assert_eq!(line, "{\"cmd\":\"blake256\",\"data\":\"\"}\n");
    }

    /// `DCROXIDE_ORACLE_BIN` names the binary to run, and Go is asked about
    /// only when it names none: an absolute path to a file is taken as it
    /// is, and anything else it names is a reason to skip.
    #[test]
    fn the_oracle_is_chosen_from_dcroxide_oracle_bin() {
        let no_go = || -> bool { panic!("Go was asked about although a binary was named") };
        let exe = env::current_exe().expect("test binary path");
        assert_eq!(
            choose_oracle(Some(exe.as_os_str()), no_go),
            Ok(OracleSource::Prebuilt(exe.clone()))
        );

        let dir = TempDir::new("oracle-bin");
        let absent = dir.path().join("dcrd-oracle");
        for missing in [absent.as_path(), dir.path()] {
            let err = choose_oracle(Some(missing.as_os_str()), no_go).expect_err("not a file");
            assert_eq!(
                err,
                format!(
                    "DCROXIDE_ORACLE_BIN names {}, which is not a file",
                    missing.display()
                )
            );
        }
        let err = choose_oracle(Some(OsStr::new("dcrd-oracle")), no_go).expect_err("relative");
        assert_eq!(
            err,
            "DCROXIDE_ORACLE_BIN names dcrd-oracle, which is not an absolute path"
        );

        // Unset or empty, the oracle is built, given Go.
        for named in [None, Some(OsStr::new(""))] {
            assert_eq!(choose_oracle(named, || true), Ok(OracleSource::Build));
            assert_eq!(
                choose_oracle(named, || false),
                Err("no Go toolchain was found".to_owned())
            );
        }
    }

    /// End to end, in a child with no Go on `PATH`: a named binary that is
    /// missing skips, or fails under `DCROXIDE_REQUIRE_ORACLE`, and a named
    /// oracle runs without one being built.
    #[test]
    fn a_named_oracle_runs_without_go() {
        const CHILD: &str = "DCROXIDE_TESTUTIL_ORACLE_BIN_CHILD";
        match env::var(CHILD).as_deref() {
            Ok("skip") => {
                assert!(oracle_or_skip().is_none());
                return;
            }
            Ok("run") => {
                let mut oracle = oracle_or_skip().expect("the named oracle");
                assert_eq!(
                    oracle.call_ok("blake256", b""),
                    "716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a"
                );
                assert_eq!(ORACLE_BUILDS.load(Ordering::Relaxed), 0);
                return;
            }
            _ => {}
        }

        let exe = env::current_exe().expect("test binary path");
        // An empty directory as `PATH`: no Go toolchain is found there.
        let empty = TempDir::new("no-go");
        let run = |mode: &str, bin: &Path, require: bool| {
            let mut cmd = Command::new(&exe);
            cmd.args([
                "--exact",
                "tests::a_named_oracle_runs_without_go",
                "--nocapture",
            ])
            .env(CHILD, mode)
            .env(ORACLE_BIN_VAR, bin)
            .env("PATH", empty.path());
            if require {
                cmd.env("DCROXIDE_REQUIRE_ORACLE", "1");
            } else {
                cmd.env_remove("DCROXIDE_REQUIRE_ORACLE");
            }
            let out = cmd.output().expect("run the child");
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            (out.status.success(), text)
        };

        let absent = empty.path().join("dcrd-oracle");
        let (ok, text) = run("skip", &absent, false);
        assert!(ok, "{text}");
        assert!(
            text.contains("skipping: DCROXIDE_ORACLE_BIN names"),
            "{text}"
        );
        let (ok, text) = run("skip", &absent, true);
        assert!(!ok, "{text}");
        assert!(
            text.contains("DCROXIDE_REQUIRE_ORACLE is set but DCROXIDE_ORACLE_BIN names"),
            "{text}"
        );

        let Some(oracle) = oracle_or_skip() else {
            return;
        };
        drop(oracle);
        let bin = choose_oracle(env::var_os(ORACLE_BIN_VAR).as_deref(), || true)
            .expect("chosen once already")
            .path();
        let (ok, text) = run("run", &bin, true);
        assert!(ok, "{text}");
    }

    /// `oracle_bin_or_skip` applies `oracle_or_skip`'s policy, in a child
    /// with no Go on `PATH`: a named binary that is missing skips, or fails
    /// under `DCROXIDE_REQUIRE_ORACLE`, and a named binary that exists comes
    /// back as named, with nothing built.
    #[test]
    fn the_oracle_bin_follows_the_skip_policy() {
        const CHILD: &str = "DCROXIDE_TESTUTIL_ORACLE_BIN_PATH_CHILD";
        match env::var(CHILD).as_deref() {
            Ok("skip") => {
                assert_eq!(oracle_bin_or_skip(), None);
                return;
            }
            Ok("named") => {
                let named = env::var_os(ORACLE_BIN_VAR).expect("the parent names a binary");
                assert_eq!(oracle_bin_or_skip(), Some(PathBuf::from(&named)));
                assert_eq!(oracle_bin(), PathBuf::from(named));
                assert_eq!(ORACLE_BUILDS.load(Ordering::Relaxed), 0);
                return;
            }
            Ok("require") => {
                // Panics: the binary is missing and DCROXIDE_REQUIRE_ORACLE is set.
                let _ = oracle_bin_or_skip();
                return;
            }
            _ => {}
        }

        let exe = env::current_exe().expect("test binary path");
        let empty = TempDir::new("no-go-bin");
        let run = |mode: &str, bin: &Path, require: bool| {
            let mut cmd = Command::new(&exe);
            cmd.args([
                "--exact",
                "tests::the_oracle_bin_follows_the_skip_policy",
                "--nocapture",
            ])
            .env(CHILD, mode)
            .env(ORACLE_BIN_VAR, bin)
            .env("PATH", empty.path());
            if require {
                cmd.env("DCROXIDE_REQUIRE_ORACLE", "1");
            } else {
                cmd.env_remove("DCROXIDE_REQUIRE_ORACLE");
            }
            let out = cmd.output().expect("run the child");
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            (out.status.success(), text)
        };

        let absent = empty.path().join("dcrd-oracle");
        let (ok, text) = run("skip", &absent, false);
        assert!(ok, "{text}");
        assert!(
            text.contains("skipping: DCROXIDE_ORACLE_BIN names"),
            "{text}"
        );
        let (ok, text) = run("require", &absent, true);
        assert!(!ok, "{text}");
        assert!(
            text.contains("DCROXIDE_REQUIRE_ORACLE is set but DCROXIDE_ORACLE_BIN names"),
            "{text}"
        );
        // Any existing file will do: the path is handed back, not run.
        let (ok, text) = run("named", &exe, true);
        assert!(ok, "{text}");
    }

    /// The pin the interop harness enforces is the commit CI builds dcrd
    /// from and the commit the oracle and the full block battery generator
    /// link: the harness once required `29f17894` while everything else had
    /// moved to `b9634e01`, so a dcrd built at the real pin was refused as "a
    /// different specification", and `tools/fullblockgen` stayed at
    /// `036b7090` through the whole `b9634e01` bump because nothing read its
    /// `go.mod`.
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

        for tool in ["oracle", "fullblockgen"] {
            let gomod_path = repo_root().join("tools").join(tool).join("go.mod");
            let gomod = std::fs::read_to_string(&gomod_path)
                .unwrap_or_else(|e| panic!("read {}: {e}", gomod_path.display()));
            let header_pin: String = gomod
                .split("dcrd master commit ")
                .nth(1)
                .unwrap_or_else(|| panic!("tools/{tool}/go.mod names the parity commit"))
                .chars()
                .take_while(char::is_ascii_hexdigit)
                .collect();
            assert_eq!(
                header_pin, DCRD_PARITY_COMMIT,
                "tools/{tool}/go.mod's header names {header_pin}, but the harness requires \
                 {DCRD_PARITY_COMMIT}"
            );
            if let Err(why) = check_oracle_links(&gomod, DCRD_PARITY_COMMIT) {
                panic!("tools/{tool}/go.mod: {why}");
            }
        }
    }

    /// The versions a `Cargo.lock` holds of each package, by name; a name
    /// holds several where the build takes several majors.
    fn locked_versions(path: &Path) -> BTreeMap<String, BTreeSet<String>> {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let quoted = |line: &str, key: &str| {
            line.strip_prefix(key)?
                .strip_prefix(" = \"")?
                .strip_suffix('"')
                .map(str::to_owned)
        };
        let mut locked: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for package in text.split("[[package]]").skip(1) {
            let name = package.lines().find_map(|line| quoted(line, "name"));
            let version = package.lines().find_map(|line| quoted(line, "version"));
            let (Some(name), Some(version)) = (name, version) else {
                panic!("{}: a package without a name and version", path.display());
            };
            locked.entry(name).or_default().insert(version);
        }
        locked
    }

    /// `fuzz/` is a workspace of its own, outside the root one, so its lock
    /// moves only when something re-resolves it there, and a bump of the
    /// root lock can leave the fuzz build on versions the node no longer
    /// ships.  Every package both locks hold must be locked at the same
    /// versions in each.  The fuzz build links the node, so the two share
    /// most of the tree.  A package the fuzz lock lacks altogether is not
    /// caught here: cargo adds it, at the newest version it can, the next
    /// time the fuzz build resolves, which the fuzz jobs' `cargo fuzz run`
    /// does without failing; the lint job's `cargo metadata --locked
    /// --manifest-path fuzz/Cargo.toml` is what fails on it.
    #[test]
    fn the_fuzz_lock_matches_the_workspace_lock() {
        let workspace = locked_versions(&repo_root().join("Cargo.lock"));
        let fuzz = locked_versions(&repo_root().join("fuzz").join("Cargo.lock"));
        let mut shared = 0usize;
        for (name, versions) in &fuzz {
            let Some(locked) = workspace.get(name) else {
                continue;
            };
            assert_eq!(
                versions, locked,
                "{name}: fuzz/Cargo.lock locks {versions:?} where Cargo.lock locks \
                 {locked:?}; move it with `cargo update --manifest-path fuzz/Cargo.toml \
                 -p {name} --precise <version>`"
            );
            shared = shared.saturating_add(1);
        }
        assert!(
            shared > 100,
            "only {shared} packages are in both locks; the fuzz build links the node"
        );
    }

    /// [`REFERENCE_GO`] is the release CI installs for every job that runs
    /// the oracle, so a test that requires it there finds it.
    #[test]
    fn the_reference_go_is_the_one_ci_installs() {
        let ci_path = repo_root().join(".github").join("workflows").join("ci.yml");
        let ci = std::fs::read_to_string(&ci_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", ci_path.display()));
        let ci_go = ci
            .lines()
            .find_map(|l| l.trim().strip_prefix("GO_VERSION:"))
            .expect("ci.yml sets GO_VERSION")
            .trim()
            .trim_matches('"');
        assert_eq!(format!("go{ci_go}"), REFERENCE_GO);
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

    /// A shell script standing in for the oracle: nothing executable is
    /// written to disk, so no test meets a file another thread's fork still
    /// holds open for writing.
    #[cfg(unix)]
    fn stand_in(script: &str) -> Oracle {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(script);
        Oracle::from_command(&mut cmd)
    }

    /// An oracle that answers once and exits: the answer is the line as
    /// read, and the next call is an error naming the exit status, whether
    /// the exit is seen before the write, by the write or by the read.
    #[cfg(unix)]
    #[test]
    fn a_stand_in_oracle_answers_then_reports_its_exit() {
        let mut oracle = stand_in(r#"read l; echo '{"result":"ok"}'"#);
        assert_eq!(
            oracle.try_call_line("blake256", b"abc"),
            Ok("{\"result\":\"ok\"}\n")
        );
        let err = oracle
            .try_call_line("blake256", b"abc")
            .expect_err("the oracle has exited");
        assert!(err.contains("exit status: 0"), "{err}");
    }

    /// An oracle that exits on a request without answering it is an error
    /// that says so and names its status.
    #[cfg(unix)]
    #[test]
    fn an_oracle_that_exits_without_answering_is_an_error() {
        let mut oracle = stand_in("read l; exit 3");
        let err = oracle
            .try_call_line("blake256", b"")
            .expect_err("no answer");
        assert!(err.contains("without answering"), "{err}");
        assert!(err.contains("exit status: 3"), "{err}");
    }

    /// A request to an oracle already seen to have exited is refused before
    /// it is written, naming the exit status; in a libFuzzer binary the
    /// write would end the process by `SIGPIPE` instead.
    #[cfg(unix)]
    #[test]
    fn a_request_to_an_oracle_that_has_exited_is_refused() {
        let mut oracle = stand_in("exit 3");
        let deadline = Instant::now() + Duration::from_secs(30);
        while let Ok(None) = oracle.child.try_wait() {
            assert!(Instant::now() < deadline, "the stand-in did not exit");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            oracle.try_call_line("blake256", b""),
            Err("the oracle had already exited (exit status: 3)".to_owned())
        );
    }

    /// `spawn_at` runs the binary it is given: `cat` stands in for the
    /// oracle and answers a request with the request itself.
    #[cfg(unix)]
    #[test]
    fn spawn_at_runs_the_binary_it_is_given() {
        let mut oracle = Oracle::spawn_at(Path::new("cat"));
        let mut request = String::new();
        push_request(&mut request, "blake256", b"abc");
        assert_eq!(
            oracle.try_call_line("blake256", b"abc"),
            Ok(request.as_str())
        );
    }

    /// `call` panics, naming the command, when the oracle does not answer.
    #[cfg(unix)]
    #[test]
    #[should_panic(expected = "oracle blake256:")]
    fn call_panics_naming_the_command() {
        stand_in("exit 0").call("blake256", b"");
    }

    /// Spawning the oracle repeatedly builds it once per process, and one
    /// that `DCROXIDE_ORACLE_BIN` names, never.
    #[test]
    fn the_oracle_is_built_once_per_process() {
        let Some(first) = oracle_or_skip() else {
            return;
        };
        let second = Oracle::spawn();
        drop((first, second));
        if let Ok(OracleSource::Prebuilt(_)) =
            choose_oracle(env::var_os(ORACLE_BIN_VAR).as_deref(), || true)
        {
            assert_eq!(ORACLE_BUILDS.load(Ordering::Relaxed), 0);
            return;
        }
        assert_eq!(build_oracle(), build_oracle());
        assert_eq!(
            ORACLE_BUILDS.load(Ordering::Relaxed),
            1,
            "every spawn after the first must reuse the built binary"
        );
    }

    /// Writes the RSA test-key fixture, `data/rsa-test-keys.json`: each key
    /// of [`RSA_TEST_KEYS`] from the oracle's `rsa_keygen`, under the
    /// reference Go.  Ignored, since the fixture is made once and committed
    /// (the 8192-bit keys take Go a while, and no two runs make the same
    /// keys); run it alone, with
    /// `cargo test -p dcroxide-testutil --lib -- --ignored regenerate_rsa_test_keys`,
    /// and every test that takes its keys from the fixture sees new ones.
    /// The signature parity corpus, which records signatures under the old
    /// ones, must then be made again with `dcroxide-tlscrypto`'s
    /// `regenerate_parity_corpus` while ring is in the tree; once ring is
    /// gone, keys are only appended ([`RSA_TEST_KEYS`]).
    #[test]
    #[ignore = "regenerates the committed RSA test-key fixture"]
    fn regenerate_rsa_test_keys() {
        let mut oracle = Oracle::spawn();
        let mut keys = Vec::new();
        for &(name, bits, e) in RSA_TEST_KEYS {
            let request = serde_json::json!({ "bits": bits, "e": e });
            let response = oracle.call("rsa_keygen", request.to_string().as_bytes());
            let go_version = response["go_version"].as_str().unwrap_or_default();
            assert_eq!(
                go_version, REFERENCE_GO,
                "the fixture is the reference Go's"
            );
            let detail = &response["detail"];
            assert!(detail.is_object(), "{name}: the oracle answered {response}");
            let mut key = serde_json::json!({ "name": name, "bits": bits });
            for component in ["n", "e", "d", "p", "q"] {
                key[component] = detail[component].clone();
            }
            keys.push(key);
        }
        let fixture = serde_json::json!({
            "about": "Test-only RSA keys for dcroxide's tests, never real keys: made once by \
                      the oracle's rsa_keygen under the reference Go through \
                      dcroxide-testutil's regenerate_rsa_test_keys, and read through \
                      dcroxide_testutil::rsa_test_key. Each component is big-endian hex.",
            "go_version": REFERENCE_GO,
            "keys": keys,
        });
        let mut text = serde_json::to_string_pretty(&fixture).expect("serialize the fixture");
        text.push('\n');
        let path = rsa_test_keys_path();
        std::fs::create_dir_all(path.parent().expect("data/")).expect("create data/");
        std::fs::write(&path, text).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    }

    /// The fixture holds every key of [`RSA_TEST_KEYS`] in order, each with
    /// its name, a modulus of its bit length, its exponent, a private
    /// exponent and primes about half its length, and no two share a
    /// modulus; and a key's `RSAPublicKey` is its two INTEGERs, the sign
    /// byte where DER needs one.  (That the values make an RSA key, n = pq
    /// and d inverting e, `dcroxide-tlscrypto`'s RSA tests check, where
    /// there is big-integer arithmetic.)
    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "bit and byte counts of keys at most 8193 bits long"
    )]
    fn the_rsa_test_keys_are_what_they_say() {
        let bits_of = |value: &[u8]| {
            let first = value.first().copied().unwrap_or(0);
            u64::try_from(value.len()).expect("a length") * 8 - u64::from(first.leading_zeros())
        };
        let mut moduli = BTreeSet::new();
        for &(name, bits, e) in RSA_TEST_KEYS {
            let key = rsa_test_key(name);
            assert_eq!(key.name, name);
            assert_eq!(key.bits, bits, "{name}");
            assert_eq!(bits_of(&key.n), bits, "{name}: the modulus");
            assert_eq!(
                key.n.last().map(|b| b & 1),
                Some(1),
                "{name}: an odd modulus"
            );
            let mut exponent = [0u8; 8];
            exponent[8 - key.e.len()..].copy_from_slice(&key.e);
            assert_eq!(u64::from_be_bytes(exponent), e, "{name}: the exponent");
            for (component, value) in [("d", &key.d), ("p", &key.p), ("q", &key.q)] {
                assert_ne!(
                    value.first(),
                    Some(&0),
                    "{name}: {component} without leading zeros"
                );
            }
            assert!(bits_of(&key.d) <= bits, "{name}: d below n");
            assert_eq!(
                bits_of(&key.p) + bits_of(&key.q),
                bits,
                "{name}: two halves"
            );
            assert!(moduli.insert(key.n.clone()), "{name}: a modulus of its own");
        }
        let key = rsa_test_key("rsa2048-e3");
        let public = key.rsa_public_key();
        assert_eq!(
            &public[..9],
            &[0x30, 0x82, 0x01, 0x08, 0x02, 0x82, 0x01, 0x01, 0x00]
        );
        assert!(public.ends_with(&[0x02, 0x01, 0x03]));
        assert_eq!(der_element(0x04, &[0; 0x80])[..3], [0x04, 0x81, 0x80]);
        assert_eq!(der_integer(&[0x7f]), [0x02, 0x01, 0x7f]);
        assert_eq!(der_integer(&[0x80]), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(key.oracle_json()["e"], "03");
    }
}
