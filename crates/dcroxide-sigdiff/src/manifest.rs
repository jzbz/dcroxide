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
//!
//! Beside the generator fingerprint, the manifest records each frozen
//! file's own hash (`tool.frozen_sources`), from which
//! [`model_only_change`] tells two runs whose frozen files differ only
//! under [`MODEL_DIR`] from any others.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use dcroxide_crypto::blake256::Blake256;
use dcroxide_testutil::{DCRD_PARITY_COMMIT, hex, pseudo_version_commit};
use serde_json::{Value, json};

use crate::fingerprint::frozen_hashes;
use crate::reply::Reply;
use crate::run::Mode;

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

/// The name of the directory holding the running binary
/// (`<target-dir>/soak/sigsoak`), or of the one above for a test binary in
/// `deps/`: the profile it was built with while it stays where cargo put
/// it, and whatever directory it was copied to otherwise.
pub fn profile_name() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let mut dir = exe.parent()?;
    if dir.file_name().is_some_and(|n| n == "deps") {
        dir = dir.parent()?;
    }
    Some(dir.file_name()?.to_string_lossy().into_owned())
}

/// How the running binary was built, as far as it can tell without a
/// build script: the name of its directory, which a copy elsewhere loses,
/// and three facts compiled into its code, which hold wherever it is
/// copied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Build {
    /// [`profile_name`].
    pub dir: Option<String>,
    /// `cfg!(debug_assertions)`.
    pub debug_assertions: bool,
    /// Whether arithmetic overflow panics, as probed at run time; `None`
    /// when it could not be probed (a build whose panics abort, where the
    /// probe would end the process).
    pub overflow_checks: Option<bool>,
    /// `cfg!(panic = "unwind")`.
    pub panic_unwind: bool,
}

impl Build {
    /// This binary, with `overflow_checks` as its caller probed it.
    pub fn current(overflow_checks: Option<bool>) -> Build {
        Build {
            dir: profile_name(),
            debug_assertions: cfg!(debug_assertions),
            overflow_checks,
            panic_unwind: cfg!(panic = "unwind"),
        }
    }

    /// The soak profile this binary is: `soak` or `soak-checked` when its
    /// directory has that name and its code has that profile's facts (no
    /// debug assertions, overflow checks off for `soak` and on for
    /// `soak-checked`, panics that unwind); otherwise why not.  A soak
    /// binary copied elsewhere and a dev binary copied into `soak/` are
    /// both refused.
    pub fn soak_profile(&self) -> Result<&'static str, String> {
        let (profile, overflow) = match self.dir.as_deref() {
            Some("soak") => ("soak", false),
            Some("soak-checked") => ("soak-checked", true),
            Some(other) => {
                return Err(format!(
                    "the binary lies in {other}/, not in a soak or soak-checked profile directory"
                ));
            }
            None => return Err("the binary's directory has no name".to_owned()),
        };
        let mut problems = Vec::new();
        if self.debug_assertions {
            problems.push("debug assertions are on".to_owned());
        }
        match self.overflow_checks {
            Some(on) if on == overflow => {}
            Some(on) => problems.push(format!(
                "overflow checks are {}",
                if on { "on" } else { "off" }
            )),
            None => problems.push("overflow checks were not probed".to_owned()),
        }
        if !self.panic_unwind {
            problems.push("panics abort".to_owned());
        }
        if problems.is_empty() {
            Ok(profile)
        } else {
            Err(format!(
                "the binary lies in {profile}/, but {}, which {profile} does not build",
                problems.join(", ")
            ))
        }
    }

    /// The manifest's `rust` fields this describes: `profile` (the
    /// directory's name), `debug_assertions`, `overflow_checks`, `panic`,
    /// and `soak_profile` with `profile_problem`, what [`Self::soak_profile`]
    /// found.
    pub fn to_json(&self) -> serde_json::Map<String, Value> {
        let (soak_profile, problem) = match self.soak_profile() {
            Ok(profile) => (Some(profile), None),
            Err(problem) => (None, Some(problem)),
        };
        let mut out = serde_json::Map::new();
        out.insert("profile".into(), json!(self.dir));
        out.insert("debug_assertions".into(), json!(self.debug_assertions));
        out.insert("overflow_checks".into(), json!(self.overflow_checks));
        out.insert(
            "panic".into(),
            json!(if self.panic_unwind { "unwind" } else { "abort" }),
        );
        out.insert("soak_profile".into(), json!(soak_profile));
        out.insert("profile_problem".into(), json!(problem));
        out
    }
}

/// Whether a run is gate-eligible: the binary is a soak profile
/// ([`Build::soak_profile`]) built from the checkout (`source_differs`
/// empty), the tree is clean (`git`'s `dirty` is false, which it is not
/// when git cannot tell), the oracle keeps the pin rule, the mode is
/// `--floors` at scale 1, and the selection is every class or whole
/// families (not `"partial"`).
pub fn gate_eligible(
    build: &Build,
    source_differs: &[String],
    git: &Value,
    pin: &PinCheck,
    mode: Mode,
    selection: &Value,
) -> bool {
    build.soak_profile().is_ok()
        && source_differs.is_empty()
        && git["dirty"] == json!(false)
        && pin.consistent()
        && mode == (Mode::Floors { scale: 1.0 })
        && *selection != json!("partial")
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

/// The directory below which a frozen file may differ between two runs
/// that `sigsoak compare --allow-model-change` accepts: the soak's models of
/// dcrd.  A soak run consults their view of a case only in two of the
/// comparison's intent checks, but the generators also build requests and
/// intents from the compact-signature constants and the ECDSA branch type
/// defined below it; a digest leaf holds the request bytes, and the case's
/// status every intent check (ADR-0006's 2026-10-30 addendum).
pub const MODEL_DIR: &str = "src/model/";

/// The manifest's `tool.frozen_sources`: each frozen file's path and its
/// [`frozen_hashes`] hash in hex, in path order.
pub fn frozen_sources_json() -> Value {
    let sources: serde_json::Map<String, Value> = frozen_hashes()
        .into_iter()
        .map(|(path, hash)| (path.to_owned(), json!(hex(&hash))))
        .collect();
    Value::Object(sources)
}

/// A manifest's `tool.frozen_sources` read back, path to hash in lowercase
/// hex, or every reason it cannot be: the manifest records none, it is not
/// an object, or an entry's path does not start with `src/` or holds `..`,
/// or its hash is not a string of 64 hex digits.  Paths are kept as the
/// list writes them.
pub fn read_frozen_sources(manifest: &Value) -> Result<BTreeMap<String, String>, Vec<String>> {
    let list = &manifest["tool"]["frozen_sources"];
    let Some(entries) = list.as_object() else {
        return Err(vec![if list.is_null() {
            "records no tool.frozen_sources".to_owned()
        } else {
            "tool.frozen_sources is not an object".to_owned()
        }]);
    };
    let mut sources = BTreeMap::new();
    let mut problems = Vec::new();
    for (path, hash) in entries {
        if !path.starts_with("src/") || path.contains("..") {
            problems.push(format!(
                "tool.frozen_sources names {path:?}, not a path below src/ without .."
            ));
            continue;
        }
        match hash.as_str() {
            Some(h) if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) => {
                sources.insert(path.clone(), h.to_ascii_lowercase());
            }
            _ => problems.push(format!(
                "tool.frozen_sources gives {path} the hash {hash}, not 64 hex digits"
            )),
        }
    }
    if problems.is_empty() {
        Ok(sources)
    } else {
        Err(problems)
    }
}

/// What `sigsoak compare --allow-model-change` makes of two runs whose
/// generator fingerprints differ, `a` and `b` each a run's name and
/// manifest: the frozen files that differ, by hash or by being in one list
/// only, when every one lies below [`MODEL_DIR`]; otherwise every reason
/// not, naming its run or its file.  A list missing or malformed
/// ([`read_frozen_sources`]), each file that differs outside
/// [`MODEL_DIR`], and lists that differ nowhere though the fingerprints
/// do are each a reason.
pub fn model_only_change(a: (&str, &Value), b: (&str, &Value)) -> Result<Vec<String>, Vec<String>> {
    let read = |(name, manifest): (&str, &Value)| {
        read_frozen_sources(manifest).map_err(|problems| {
            problems
                .into_iter()
                .map(|p| format!("{name}: {p}"))
                .collect::<Vec<_>>()
        })
    };
    let (sources_a, sources_b) = match (read(a), read(b)) {
        (Ok(sources_a), Ok(sources_b)) => (sources_a, sources_b),
        (read_a, read_b) => {
            return Err(read_a
                .err()
                .into_iter()
                .chain(read_b.err())
                .flatten()
                .collect());
        }
    };
    let paths: BTreeSet<&String> = sources_a.keys().chain(sources_b.keys()).collect();
    let mut changed = Vec::new();
    let mut outside = Vec::new();
    for path in paths {
        let how = match (sources_a.get(path), sources_b.get(path)) {
            (Some(hash_a), Some(hash_b)) if hash_a == hash_b => continue,
            (Some(_), Some(_)) => "its hash differs".to_owned(),
            (Some(_), None) => format!("only {} records it", a.0),
            (None, _) => format!("only {} records it", b.0),
        };
        if path.starts_with(MODEL_DIR) {
            changed.push(path.clone());
        } else {
            outside.push(format!("{path} differs outside {MODEL_DIR} ({how})"));
        }
    }
    if !outside.is_empty() {
        return Err(outside);
    }
    if changed.is_empty() {
        return Err(vec![
            "tool.frozen_sources differ in no file, though the generator fingerprints differ"
                .to_owned(),
        ]);
    }
    Ok(changed)
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

    fn build(dir: &str, debug_assertions: bool, overflow_checks: bool, unwind: bool) -> Build {
        Build {
            dir: Some(dir.to_owned()),
            debug_assertions,
            overflow_checks: Some(overflow_checks),
            panic_unwind: unwind,
        }
    }

    /// A soak profile takes both its directory's name and its code's
    /// facts: the two soak builds where cargo puts them pass, and each
    /// fact or name that differs refuses the build, naming it.
    #[test]
    fn a_soak_profile_needs_its_directory_and_its_facts() {
        assert_eq!(build("soak", false, false, true).soak_profile(), Ok("soak"));
        assert_eq!(
            build("soak-checked", false, true, true).soak_profile(),
            Ok("soak-checked")
        );
        for (b, why) in [
            // A soak binary copied elsewhere.
            (build("bin", false, false, true), "lies in bin/"),
            (build("release", false, false, true), "lies in release/"),
            // A dev or test binary copied into soak/.
            (build("soak", true, true, true), "debug assertions are on"),
            // Debug assertions with overflow checks off, as CI's
            // test-wrapping job builds.
            (build("soak", true, false, true), "debug assertions are on"),
            // Each soak profile with the other's overflow checks.
            (build("soak", false, true, true), "overflow checks are on"),
            (
                build("soak-checked", false, false, true),
                "overflow checks are off",
            ),
            // A release binary copied into soak/: its panics abort.
            (build("soak", false, false, false), "panics abort"),
        ] {
            let problem = b.soak_profile().expect_err("refused");
            assert!(problem.contains(why), "{b:?}: {problem}");
        }
        let unprobed = Build {
            overflow_checks: None,
            ..build("soak", false, false, true)
        };
        assert!(
            unprobed
                .soak_profile()
                .is_err_and(|p| p.contains("not probed"))
        );
        let nameless = Build {
            dir: None,
            ..build("soak", false, false, true)
        };
        assert!(nameless.soak_profile().is_err());
        let all_wrong = build("soak-checked", true, false, false)
            .soak_profile()
            .expect_err("refused");
        assert!(
            all_wrong.contains("debug assertions are on, overflow checks are off, panics abort"),
            "{all_wrong}"
        );
    }

    /// Gate eligibility takes each of its conditions: with every other one
    /// met, a build that is no soak profile, a binary from another tree, a
    /// dirty tree or one git could not read, an oracle off the pin, another
    /// mode or scale, and a partial selection each refuse it.
    #[test]
    fn gate_eligibility_takes_every_condition() {
        let soak = build("soak", false, false, true);
        let clean = json!({ "head": "c1b6244", "dirty": false });
        let pinned = check_pin(&info(
            go_mod_version(ORACLE_GO_MOD, SIGNATURE_MODULES[0]).expect("required"),
            go_mod_version(ORACLE_GO_MOD, SIGNATURE_MODULES[1]).expect("required"),
        ));
        let floors = Mode::Floors { scale: 1.0 };
        let all = json!("all");
        let eligible = |b: &Build| gate_eligible(b, &[], &clean, &pinned, floors, &all);
        assert!(eligible(&soak));
        assert!(eligible(&build("soak-checked", false, true, true)));
        let ed25519 = json!(["ed25519"]);
        assert!(gate_eligible(&soak, &[], &clean, &pinned, floors, &ed25519));

        for b in [
            build("bin", false, false, true),
            build("soak", true, false, true),
            build("soak", false, true, true),
            build("soak-checked", false, false, true),
            build("soak", false, false, false),
            Build {
                overflow_checks: None,
                ..soak.clone()
            },
        ] {
            assert!(!eligible(&b), "{b:?}");
        }
        let differs = ["src/run.rs".to_owned()];
        assert!(!gate_eligible(
            &soak, &differs, &clean, &pinned, floors, &all
        ));
        for git in [
            json!({ "head": "c1b6244", "dirty": true }),
            json!({ "head": null, "dirty": null }),
        ] {
            assert!(
                !gate_eligible(&soak, &[], &git, &pinned, floors, &all),
                "{git}"
            );
        }
        let off_pin = check_pin(&info("v4.4.1", EDW));
        assert!(!off_pin.consistent());
        assert!(!gate_eligible(&soak, &[], &clean, &off_pin, floors, &all));
        for mode in [
            Mode::Floors { scale: 0.5 },
            Mode::Cases(300),
            Mode::Budget {
                duration: std::time::Duration::from_secs(60),
                min_scale: Some(1.0),
            },
        ] {
            assert!(
                !gate_eligible(&soak, &[], &clean, &pinned, mode, &all),
                "{mode:?}"
            );
        }
        let partial = json!("partial");
        assert!(!gate_eligible(
            &soak,
            &[],
            &clean,
            &pinned,
            floors,
            &partial
        ));
    }

    /// The record names the directory and every fact beside what they
    /// make of the build, and this test binary reports its own build's
    /// facts.
    #[test]
    fn the_build_is_recorded_with_its_facts() {
        let json = build("soak", false, false, true).to_json();
        assert_eq!(json["profile"], "soak");
        assert_eq!(json["soak_profile"], "soak");
        assert_eq!(json["profile_problem"], Value::Null);
        assert_eq!(json["panic"], "unwind");
        let json = build("bin", false, false, true).to_json();
        assert_eq!(json["profile"], "bin");
        assert_eq!(json["soak_profile"], Value::Null);
        assert!(json["profile_problem"].is_string());

        let current = Build::current(Some(true));
        assert_eq!(current.dir, profile_name());
        assert_eq!(current.debug_assertions, cfg!(debug_assertions));
        assert_eq!(current.panic_unwind, cfg!(panic = "unwind"));
        assert_eq!(current.overflow_checks, Some(true));
    }

    /// The list a manifest records reads back whole: every frozen file
    /// once, in path order, with its own hash.
    #[test]
    fn the_frozen_sources_read_back() {
        let manifest = json!({ "tool": { "frozen_sources": frozen_sources_json() } });
        let sources = read_frozen_sources(&manifest).expect("well formed");
        let want: BTreeMap<String, String> = frozen_hashes()
            .into_iter()
            .map(|(path, hash)| (path.to_owned(), hex(&hash)))
            .collect();
        assert_eq!(sources, want);
        assert_eq!(sources.len(), crate::fingerprint::FROZEN.len());
    }

    const MODEL: &str = "src/model/ecdsa.rs";
    const GEN: &str = "src/gen/ecdsa.rs";
    const COMPARE: &str = "src/compare.rs";

    /// A manifest whose `tool.frozen_sources` holds `entries`.
    fn listing(entries: &[(&str, Value)]) -> Value {
        let sources: serde_json::Map<String, Value> = entries
            .iter()
            .map(|(path, hash)| ((*path).to_owned(), hash.clone()))
            .collect();
        json!({ "tool": { "frozen_sources": sources } })
    }

    /// A hash of 64 hex digits, all `digit`.
    fn hash(digit: char) -> Value {
        json!(digit.to_string().repeat(64))
    }

    /// Three frozen files, one under `src/model/`, with `changes` applied:
    /// each path given a hash, or dropped for `None`.
    fn three(changes: &[(&str, Option<char>)]) -> Value {
        let mut entries = vec![(MODEL, hash('1')), (GEN, hash('2')), (COMPARE, hash('3'))];
        for (path, digit) in changes {
            entries.retain(|(p, _)| p != path);
            if let Some(digit) = digit {
                entries.push((*path, hash(*digit)));
            }
        }
        listing(&entries)
    }

    /// Only frozen files under `src/model/` may differ, by hash, by being
    /// added or by being removed; any other that differs is named, with
    /// how, and lists that differ nowhere are refused, since the check is
    /// made only of runs whose fingerprints differ.
    #[test]
    fn a_model_only_change_is_told_from_any_other() {
        let g1 = three(&[]);
        let check = |b: &Value| model_only_change(("G1", &g1), ("G3", b));
        assert_eq!(
            check(&three(&[(MODEL, Some('9'))])),
            Ok(vec![MODEL.to_owned()])
        );
        let added = "src/model/added.rs";
        assert_eq!(
            check(&three(&[(added, Some('4'))])),
            Ok(vec![added.to_owned()])
        );
        assert_eq!(check(&three(&[(MODEL, None)])), Ok(vec![MODEL.to_owned()]));
        assert_eq!(
            check(&three(&[(MODEL, Some('9')), (added, Some('4'))])),
            Ok(vec![added.to_owned(), MODEL.to_owned()])
        );

        for (b, why) in [
            (
                three(&[(GEN, Some('9'))]),
                "src/gen/ecdsa.rs differs outside src/model/ (its hash differs)",
            ),
            (
                three(&[(COMPARE, Some('9')), (MODEL, Some('9'))]),
                "src/compare.rs differs outside src/model/ (its hash differs)",
            ),
            (
                three(&[("src/gen/added.rs", Some('4'))]),
                "src/gen/added.rs differs outside src/model/ (only G3 records it)",
            ),
            (
                three(&[(COMPARE, None)]),
                "src/compare.rs differs outside src/model/ (only G1 records it)",
            ),
            // Not under src/model/, though its name starts the same way.
            (
                three(&[("src/modelx.rs", Some('4'))]),
                "src/modelx.rs differs outside src/model/ (only G3 records it)",
            ),
        ] {
            assert_eq!(check(&b), Err(vec![why.to_owned()]), "{b}");
        }
        // Every file outside is named.
        let both = check(&three(&[(GEN, Some('9')), (COMPARE, None)])).expect_err("refused");
        assert_eq!(both.len(), 2, "{both:?}");
        assert!(
            both[0].starts_with(COMPARE) && both[1].starts_with(GEN),
            "{both:?}"
        );
        assert_eq!(
            check(&three(&[])),
            Err(vec![
                "tool.frozen_sources differ in no file, though the generator fingerprints differ"
                    .to_owned()
            ])
        );
        // Hex digits compare whatever their case.
        let upper = three(&[(MODEL, Some('A'))]);
        let lower = three(&[(MODEL, Some('a'))]);
        assert!(
            model_only_change(("A", &upper), ("B", &lower))
                .is_err_and(|why| why[0].contains("differ in no file"))
        );
    }

    /// A run without the list, or with one that is not an object, a path
    /// that does not start with `src/` or holds `..`, or a hash that is not
    /// a string of 64 hex digits, is refused, naming the run and the entry;
    /// both runs' problems are reported.
    #[test]
    fn a_missing_or_malformed_list_is_refused() {
        let g1 = three(&[]);
        let check = |b: &Value| model_only_change(("G1", &g1), ("G3", b));
        let mut old = json!({ "tool": { "generator_fingerprint": "00" } });
        assert_eq!(
            check(&old),
            Err(vec!["G3: records no tool.frozen_sources".to_owned()])
        );
        old["tool"]["frozen_sources"] = json!([MODEL]);
        assert_eq!(
            check(&old),
            Err(vec!["G3: tool.frozen_sources is not an object".to_owned()])
        );
        for path in [
            "src/model/../gen/ecdsa.rs",
            "src/../src/model/ecdsa.rs",
            "../src/model/ecdsa.rs",
            "model/ecdsa.rs",
            "/src/model/ecdsa.rs",
            "crates/dcroxide-sigdiff/src/model/ecdsa.rs",
            "src",
            "",
        ] {
            assert_eq!(
                check(&three(&[(MODEL, None), (path, Some('9'))])),
                Err(vec![format!(
                    "G3: tool.frozen_sources names {path:?}, not a path below src/ without .."
                )]),
                "{path}"
            );
        }
        for bad in [
            json!(7),
            Value::Null,
            json!("1".repeat(63)),
            json!("1".repeat(65)),
            json!("g".repeat(64)),
            json!(format!("0x{}", "1".repeat(62))),
        ] {
            let b = listing(&[(MODEL, bad.clone()), (GEN, hash('2')), (COMPARE, hash('3'))]);
            assert_eq!(
                check(&b),
                Err(vec![format!(
                    "G3: tool.frozen_sources gives {MODEL} the hash {bad}, not 64 hex digits"
                )]),
                "{bad}"
            );
        }
        let without = json!({});
        assert_eq!(
            model_only_change(("G1", &without), ("G3", &old)),
            Err(vec![
                "G1: records no tool.frozen_sources".to_owned(),
                "G3: tool.frozen_sources is not an object".to_owned(),
            ])
        );
    }
}
