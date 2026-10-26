// SPDX-License-Identifier: ISC
//! What a run ran with: the environment probe behind `manifest.json`.
//!
//! The pin a run compared against comes from the oracle itself
//! (`build_info`), held against the version `tools/oracle/go.mod` requires
//! and the harness pin, by the rule the oracle's header states and testutil
//! applies: each signature module sits at the pin's pseudo-version or at a
//! published tag whose source is byte-identical to the pin's.  The compiler
//! is recorded by running `rustc -vV` from the repository root, which
//! resolves the same `rust-toolchain.toml` the build used, rather than by
//! a build script.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use dcroxide_crypto::blake256::Blake256;
use dcroxide_testutil::{DCRD_PARITY_COMMIT, hex, pseudo_version_commit};
use serde_json::{Value, json};

use crate::reply::Reply;

/// The manifest's schema name.
pub const SCHEMA: &str = "dcroxide-sigsoak/1";

/// `tools/oracle/go.mod` as this binary was built against it.
pub const ORACLE_GO_MOD: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tools/oracle/go.mod"
));

/// The workspace `Cargo.lock` as this binary was built against it (a lock
/// change rebuilds the binary).
pub const CARGO_LOCK: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"));

/// The modules `build_info` reports: the signature code compared against.
pub const SIGNATURE_MODULES: [&str; 2] = [
    "github.com/decred/dcrd/dcrec/secp256k1/v4",
    "github.com/decred/dcrd/dcrec/edwards/v2",
];

/// The crates whose locked versions a manifest records: the k256 stack,
/// the Ed25519 and SHA-2 code, and the libsecp bindings, whose presence
/// tells a libsecp baseline from a pure-Rust leg.
pub const LOCKED_CRATES: [&str; 9] = [
    "k256",
    "elliptic-curve",
    "crypto-bigint",
    "primeorder",
    "wnaf",
    "curve25519-dalek",
    "sha2",
    "secp256k1",
    "secp256k1-sys",
];

/// The version `gomod` requires of `module`, from its `require` lines.
pub fn go_mod_version<'a>(gomod: &'a str, module: &str) -> Option<&'a str> {
    gomod.lines().find_map(|line| {
        let code = line.split("//").next()?.trim();
        let code = code.strip_prefix("require ").unwrap_or(code);
        let mut fields = code.split_whitespace();
        (fields.next()? == module).then_some(())?;
        fields.next()
    })
}

/// One signature module's pin, as checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModulePin {
    /// The module path.
    pub module: &'static str,
    /// The version the oracle reports it was built with.
    pub built: Option<String>,
    /// The version `tools/oracle/go.mod` requires.
    pub go_mod: Option<String>,
    /// `pseudo` for a pseudo-version, `tag` for a published tag.
    pub kind: &'static str,
    /// Why it breaks the rule, if it does.
    pub problem: Option<String>,
}

/// The pin check of an oracle's `build_info`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinCheck {
    /// The harness pin (testutil's `DCRD_PARITY_COMMIT`).
    pub harness: String,
    /// Each signature module.
    pub modules: Vec<ModulePin>,
}

impl PinCheck {
    /// Whether every module keeps the rule.
    pub fn consistent(&self) -> bool {
        self.modules.iter().all(|m| m.problem.is_none())
    }

    /// Every problem found, one line each.
    pub fn problems(&self) -> Vec<String> {
        self.modules
            .iter()
            .filter_map(|m| m.problem.as_ref().map(|p| format!("{}: {p}", m.module)))
            .collect()
    }

    /// The manifest's `pin` object.
    pub fn to_json(&self) -> Value {
        let modules: serde_json::Map<String, Value> = self
            .modules
            .iter()
            .map(|m| {
                (
                    m.module.to_owned(),
                    json!({ "built": m.built, "go_mod": m.go_mod, "kind": m.kind, "problem": m.problem }),
                )
            })
            .collect();
        json!({ "harness": self.harness, "oracle_modules": modules, "consistent": self.consistent() })
    }
}

/// Holds an oracle's `build_info` against `gomod` and the harness pin
/// `harness`: for each signature module the built version must equal the
/// version `gomod` requires, carry no replacement (`" => "`), and, when it
/// is a pseudo-version, name a commit starting with `harness`.  A plain tag
/// is accepted, its identity with the pin resting on the record in
/// `go.mod`'s header that every pin move rechecks.
pub fn pin_check(build_info: &Reply, gomod: &str, harness: &str) -> PinCheck {
    let modules = SIGNATURE_MODULES
        .iter()
        .map(|&module| {
            let built = build_info.modules.get(module).cloned();
            let go_mod = go_mod_version(gomod, module).map(str::to_owned);
            let commit = built.as_deref().and_then(pseudo_version_commit);
            let kind = if commit.is_some() { "pseudo" } else { "tag" };
            let problem = match (&built, &go_mod) {
                (None, _) => Some("the oracle reports no version".to_owned()),
                (_, None) => Some("tools/oracle/go.mod requires no version".to_owned()),
                (Some(b), _) if b.contains(" => ") => {
                    Some(format!("built from a replacement: {b}"))
                }
                (Some(b), Some(g)) if b != g => Some(format!(
                    "built at {b}, but tools/oracle/go.mod requires {g}"
                )),
                _ => match commit {
                    Some(c) if !c.starts_with(harness) => Some(format!(
                        "pseudo-version names {c}, but the harness pin is {harness}"
                    )),
                    _ => None,
                },
            };
            ModulePin {
                module,
                built,
                go_mod,
                kind,
                problem,
            }
        })
        .collect();
    PinCheck {
        harness: harness.to_owned(),
        modules,
    }
}

/// [`pin_check`] against the embedded `go.mod` and testutil's pin.
pub fn check_pin(build_info: &Reply) -> PinCheck {
    pin_check(build_info, ORACLE_GO_MOD, DCRD_PARITY_COMMIT)
}

/// The locked versions of `crates` in `lock`, each `None` when absent and
/// comma-separated when the lock holds several.
pub fn lock_versions(lock: &str, crates: &[&str]) -> BTreeMap<String, Option<String>> {
    let mut found: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut name: Option<&str> = None;
    for line in lock.lines() {
        if line == "[[package]]" {
            name = None;
        } else if let Some(n) = line
            .strip_prefix("name = \"")
            .and_then(|s| s.strip_suffix('"'))
        {
            name = Some(n);
        } else if let Some(v) = line
            .strip_prefix("version = \"")
            .and_then(|s| s.strip_suffix('"'))
            && let Some(n) = name.filter(|n| crates.contains(n))
        {
            found.entry(n).or_default().push(v);
        }
    }
    crates
        .iter()
        .map(|&c| ((*c).to_owned(), found.get(c).map(|v| v.join(","))))
        .collect()
}

/// The repository root this crate was built in (two levels above its
/// manifest directory), canonicalized.  An error when it does not
/// canonicalize: the tree was moved or deleted, and neither `--out` nor
/// the binary's source can be checked against it.
pub fn repo_root() -> Result<PathBuf, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/<name> lies two levels below the root");
    std::fs::canonicalize(root).map_err(|e| {
        format!(
            "the repository root {} does not resolve: {e}",
            root.display()
        )
    })
}

/// This crate's directory under a repository root.
pub fn crate_dir(root: &Path) -> PathBuf {
    root.join("crates").join("dcroxide-sigdiff")
}

/// `git rev-parse HEAD` and whether tracked files differ from it, read-only
/// (`--no-optional-locks`, so not even the index is refreshed).
pub fn git_state(root: &Path) -> Value {
    let git = |args: &[&str]| -> Option<String> {
        let out = Command::new("git")
            .arg("--no-optional-locks")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
    };
    let head = git(&["rev-parse", "HEAD"]);
    let dirty = git(&["status", "--porcelain", "--untracked-files=no"]).map(|s| !s.is_empty());
    json!({ "head": head, "dirty": dirty })
}

/// `rustc -vV`, run from `root` so rustup resolves the toolchain file the
/// build used.
pub fn rustc_vv(root: &Path) -> Option<String> {
    let out = Command::new("rustc")
        .arg("-vV")
        .current_dir(root)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// The profile the running binary was built with: the name of the
/// directory holding it (`<target-dir>/soak/sigsoak`), or of the one above
/// for a test binary in `deps/`.
pub fn profile_name() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let mut dir = exe.parent()?;
    if dir.file_name().is_some_and(|n| n == "deps") {
        dir = dir.parent()?;
    }
    Some(dir.file_name()?.to_string_lossy().into_owned())
}

/// The Ed25519 backend `curve25519-dalek` picks, inferred as it decides:
/// `serial` (or `fiat`) when forced through `RUSTFLAGS`; on x86_64,
/// `avx512ifma` when both AVX-512 features were compiled in and the CPU has
/// them, `avx2` when the CPU has AVX2; else `serial`.
#[allow(
    unexpected_cfgs,
    reason = "curve25519_dalek_backend is set only through RUSTFLAGS by the serial-backend soak leg"
)]
pub fn dalek_backend() -> &'static str {
    if cfg!(curve25519_dalek_backend = "serial") {
        return "serial";
    }
    if cfg!(curve25519_dalek_backend = "fiat") {
        return "fiat";
    }
    #[cfg(target_arch = "x86_64")]
    {
        if cfg!(all(
            target_feature = "avx512ifma",
            target_feature = "avx512vl"
        )) && std::arch::is_x86_feature_detected!("avx512ifma")
            && std::arch::is_x86_feature_detected!("avx512vl")
        {
            return "avx512ifma";
        }
        if std::arch::is_x86_feature_detected!("avx2") {
            return "avx2";
        }
    }
    "serial"
}

/// The platform: OS, architecture, CPU model and features, the dalek
/// backend and the available parallelism.
pub fn platform() -> Value {
    let mut cpu_runtime = serde_json::Map::new();
    #[cfg(target_arch = "x86_64")]
    {
        cpu_runtime.insert(
            "avx2".into(),
            std::arch::is_x86_feature_detected!("avx2").into(),
        );
        cpu_runtime.insert(
            "avx512ifma".into(),
            std::arch::is_x86_feature_detected!("avx512ifma").into(),
        );
        cpu_runtime.insert(
            "avx512vl".into(),
            std::arch::is_x86_feature_detected!("avx512vl").into(),
        );
    }
    let compiled: Vec<&str> = [
        ("avx2", cfg!(target_feature = "avx2")),
        ("avx512ifma", cfg!(target_feature = "avx512ifma")),
        ("avx512vl", cfg!(target_feature = "avx512vl")),
        ("bmi2", cfg!(target_feature = "bmi2")),
        ("adx", cfg!(target_feature = "adx")),
    ]
    .into_iter()
    .filter_map(|(name, on)| on.then_some(name))
    .collect();
    let cpu_model = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|info| {
            info.lines().find_map(|l| {
                l.strip_prefix("model name")
                    .map(|r| r.trim_start_matches([' ', '\t', ':']).to_owned())
            })
        });
    json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "pointer_width": usize::BITS,
        "cpu_model": cpu_model,
        "cpu_runtime": cpu_runtime,
        "target_features": compiled,
        "dalek_backend": dalek_backend(),
        "available_parallelism": std::thread::available_parallelism().map(usize::from).ok(),
    })
}

/// BLAKE-256 of a file's contents.
pub fn file_blake256(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut file = std::fs::File::open(path)?;
    let mut h = Blake256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            return Ok(h.finalize());
        }
        h.update(&buf[..n]);
    }
}

/// Seconds since the Unix epoch.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `unix` seconds as an ISO 8601 UTC time, `2026-10-26T12:34:56Z`.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "the civil-from-days algorithm on u64 seconds: days < 2^64 / 86400, \
              every intermediate far inside i64 and u64"
)]
pub fn utc(unix: u64) -> String {
    let days = i64::try_from(unix / 86_400).unwrap_or(i64::MAX / 2);
    let secs = unix % 86_400;
    // Howard Hinnant's days-to-civil, for the proleptic Gregorian calendar.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3_600,
        secs % 3_600 / 60,
        secs % 60
    )
}

/// The manifest's `oracle` object: the binary, its BLAKE-256, the Go
/// version it reports and the environment it runs with.
pub fn oracle_json(bin: &Path, build_info: &Reply, gomaxprocs: u32) -> Value {
    json!({
        "bin": bin.display().to_string(),
        "bin_blake256": file_blake256(bin).ok().map(|d| hex(&d)),
        "go_version": build_info.go_version,
        "env": { "GOMAXPROCS": gomaxprocs.to_string() },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(secp: &str, edwards: &str) -> Reply {
        let mut reply = Reply::default();
        reply
            .modules
            .insert(SIGNATURE_MODULES[0].to_owned(), secp.to_owned());
        reply
            .modules
            .insert(SIGNATURE_MODULES[1].to_owned(), edwards.to_owned());
        reply
    }

    const SECP: &str = "v4.4.2-0.20261019113547-3360ae4dbef8";
    const EDW: &str = "v2.0.5-0.20261019113547-3360ae4dbef8";

    /// The rule accepts pseudo-versions at the pin and tags, and refuses a
    /// version go.mod does not require, a replacement, a pseudo-version at
    /// another commit and a missing module.
    #[test]
    fn the_pin_rule() {
        let gomod = format!(
            "require (\n\t{} {SECP}\n\t{} {EDW} // a comment\n)\n",
            SIGNATURE_MODULES[0], SIGNATURE_MODULES[1]
        );
        let check = pin_check(&info(SECP, EDW), &gomod, "3360ae4d");
        assert!(check.consistent(), "{:?}", check.problems());
        assert_eq!(check.modules[0].kind, "pseudo");

        let tagged = gomod.replace(EDW, "v2.0.4");
        let check = pin_check(&info(SECP, "v2.0.4"), &tagged, "3360ae4d");
        assert!(check.consistent(), "{:?}", check.problems());
        assert_eq!(check.modules[1].kind, "tag");

        for (built_secp, built_edw, harness) in [
            ("v4.4.1", EDW, "3360ae4d"),
            (SECP, &*format!("{EDW} => ../edwards"), "3360ae4d"),
            (SECP, EDW, "6f6cf21b"),
        ] {
            let check = pin_check(&info(built_secp, built_edw), &gomod, harness);
            assert!(!check.consistent(), "{built_secp} {built_edw} {harness}");
        }
        let mut missing = info(SECP, EDW);
        missing.modules.remove(SIGNATURE_MODULES[1]);
        assert!(!pin_check(&missing, &gomod, "3360ae4d").consistent());
        assert!(!pin_check(&info(SECP, EDW), "require x v1\n", "3360ae4d").consistent());
        let json = pin_check(&info(SECP, EDW), &gomod, "3360ae4d").to_json();
        assert_eq!(json["consistent"], true);
        assert_eq!(json["oracle_modules"][SIGNATURE_MODULES[0]]["built"], SECP);
    }

    /// The embedded go.mod requires the signature modules at the harness
    /// pin, so an oracle built from it passes.
    #[test]
    fn the_embedded_go_mod_keeps_the_rule() {
        let mut built = Reply::default();
        for module in SIGNATURE_MODULES {
            let version = go_mod_version(ORACLE_GO_MOD, module).expect("required");
            built.modules.insert(module.to_owned(), version.to_owned());
        }
        let check = check_pin(&built);
        assert!(check.consistent(), "{:?}", check.problems());
    }

    #[test]
    fn locked_versions_are_read() {
        let lock = "[[package]]\nname = \"k256\"\nversion = \"0.14.0\"\n\n[[package]]\nname = \"sha2\"\nversion = \"0.10.9\"\n\n[[package]]\nname = \"sha2\"\nversion = \"0.11.0\"\n";
        let v = lock_versions(lock, &["k256", "sha2", "wnaf"]);
        assert_eq!(v["k256"].as_deref(), Some("0.14.0"));
        assert_eq!(v["sha2"].as_deref(), Some("0.10.9,0.11.0"));
        assert_eq!(v["wnaf"], None);
        let real = lock_versions(CARGO_LOCK, &LOCKED_CRATES);
        assert!(real["k256"].is_some() && real["curve25519-dalek"].is_some());
    }

    #[test]
    fn utc_formats_known_times() {
        assert_eq!(utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(utc(1_792_972_800 + 45_296), "2026-10-26T12:34:56Z");
        assert_eq!(utc(4_107_542_399), "2100-02-28T23:59:59Z");
    }

    #[test]
    fn the_repository_root_resolves() {
        let root = repo_root().expect("the tree this test was built in");
        assert!(root.join("Cargo.toml").is_file());
        assert!(crate_dir(&root).join("Cargo.toml").is_file());
        assert!(profile_name().is_some());
        assert!(["serial", "fiat", "avx2", "avx512ifma"].contains(&dalek_backend()));
    }
}
