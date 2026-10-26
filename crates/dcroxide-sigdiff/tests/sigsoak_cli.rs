// SPDX-License-Identifier: ISC
//! The `sigsoak` binary end to end against the real oracle: a run writes
//! every file of its record, a replayed case's leaf is the one its run's
//! digest implies, `compare` passes equal runs and fails each kind of
//! difference, a run that completes nothing fails, and `--out` is refused
//! inside the repository or when it holds files.  A canary run writes its
//! record beside a run's, each disagreement it records replays with its
//! canary, and `list` ends quietly when its reader goes away.

use std::path::Path;
use std::process::{Command, Stdio};

use dcroxide_sigdiff::canary::{CANARIES, CANARY_BOUND};
use dcroxide_sigdiff::class::{CLASSES, Family};
use dcroxide_sigdiff::digest::class_digest;
use dcroxide_testutil::{TempDir, hex, oracle_bin_or_skip, unhex};

/// Runs sigsoak; its exit code and everything it printed.
fn sigsoak(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_sigsoak"))
        .args(args)
        .output()
        .expect("run sigsoak");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code().unwrap_or(-1), text)
}

/// The final digest row of `class` in a run's `digests.tsv`.
fn final_digest(dir: &Path, class: &str) -> (u64, String) {
    let text = std::fs::read_to_string(dir.join("digests.tsv")).expect("digests.tsv");
    text.lines()
        .skip(1)
        .map(|l| l.split('\t').collect::<Vec<_>>())
        .find(|f| f[0] == class && f[3] == "true")
        .map(|f| (f[1].parse().expect("a count"), f[2].to_owned()))
        .unwrap_or_else(|| panic!("no final digest for {class}:\n{text}"))
}

#[test]
fn run_replay_and_compare() {
    let Some(oracle) = oracle_bin_or_skip() else {
        return;
    };
    let oracle = oracle.display().to_string();
    let dir = TempDir::new("sigsoak-cli");
    let out = |name: &str| dir.path().join(name).display().to_string();
    let pubkey: Vec<&str> = CLASSES
        .iter()
        .filter(|c| c.family == Family::Pubkey)
        .map(|c| c.name)
        .collect();
    assert!(pubkey.len() >= 2, "two public key classes to tell apart");
    let sampled = CLASSES
        .iter()
        .find(|c| c.family == Family::Pubkey && c.size.finite().is_none())
        .expect("a sampled public key class")
        .name;
    let seed = "0x0123456789abcdef";
    let run_with = |name: &str, seed: &str, classes: &str, size: &[&str]| {
        let out = out(name);
        let mut args = vec![
            "run",
            "--out",
            &out,
            "--seed",
            seed,
            "--classes",
            classes,
            "--workers",
            "2",
            "--oracle",
            &oracle,
            "--progress-every",
            "1h",
        ];
        args.extend(size);
        sigsoak(&args)
    };
    let run = |name: &str, seed: &str, classes: &str, cases: &str| {
        run_with(name, seed, classes, &["--cases", cases])
    };

    // Every public key class, so that every file of the record is written
    // with finite classes run whole.
    let (code, text) = run("a", seed, "K-*", "32");
    assert_eq!(code, 0, "{text}");
    assert!(
        text.contains("sigsoak: master seed 0x0123456789abcdef"),
        "{text}"
    );
    let a = dir.path().join("a");
    for file in [
        "manifest.json",
        "summary.txt",
        "counts.tsv",
        "kinds.tsv",
        "digests.tsv",
        "mix.tsv",
        "progress.tsv",
        "disagreements.jsonl",
        "events.jsonl",
        "oracle-w0.stderr",
    ] {
        assert!(a.join(file).is_file(), "{file} missing:\n{text}");
    }
    assert_eq!(
        std::fs::read_to_string(a.join("disagreements.jsonl")).expect("read"),
        ""
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(a.join("manifest.json")).expect("read"))
            .expect("JSON");
    assert_eq!(manifest["status"], "passed");
    assert_eq!(manifest["pin"]["consistent"], true, "{}", manifest["pin"]);
    assert_eq!(manifest["master_seed"], seed);
    assert_eq!(
        manifest["gate_eligible"], false,
        "a test build is not gate-eligible"
    );
    assert_eq!(manifest["tool"]["source_matches_checkout"], true);
    assert!(manifest["end"]["utc"].is_string());
    let summary = std::fs::read_to_string(a.join("summary.txt")).expect("read");
    assert!(summary.starts_with("status: passed"), "{summary}");

    // The comparisons run on a cheap pair, one sampled class and one
    // finite.  The same seed again: equal, but only exploratory evidence,
    // and a run is never compared with itself.
    let pair = "K-valid,K-length";
    assert_eq!(run("b1", seed, pair, "32").0, 0);
    assert_eq!(run("b2", seed, pair, "32").0, 0);
    let (code, text) = sigsoak(&["compare", "--exploratory", &out("b1"), &out("b2")]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("K-valid: equal at 32"), "{text}");
    assert!(text.contains("exploratory: not gate evidence"), "{text}");
    let (code, text) = sigsoak(&["compare", &out("b1"), &out("b2")]);
    assert_eq!(code, 1, "not gate-eligible:\n{text}");
    let (code, text) = sigsoak(&["compare", "--exploratory", &out("b1"), &out("b1")]);
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("are the same run"), "{text}");

    // A digest that differs at an equal count, with the seed, the classes
    // and the fingerprint equal, fails both kinds of comparison.  b3 is b2
    // with K-valid's final digest edited.
    let b3 = dir.path().join("b3");
    std::fs::create_dir(&b3).expect("create b3");
    for file in ["manifest.json", "digests.tsv"] {
        std::fs::copy(dir.path().join("b2").join(file), b3.join(file)).expect("copy");
    }
    let (n, digest) = final_digest(&b3, "K-valid");
    let edited = format!(
        "{}{}",
        if digest.starts_with('0') { '1' } else { '0' },
        &digest[1..]
    );
    let digests = std::fs::read_to_string(b3.join("digests.tsv")).expect("read");
    let row = format!("K-valid\t{n}\t{digest}\ttrue");
    assert!(digests.contains(&row), "{digests}");
    std::fs::write(
        b3.join("digests.tsv"),
        digests.replace(&row, &format!("K-valid\t{n}\t{edited}\ttrue")),
    )
    .expect("write");
    let (code, text) = sigsoak(&["compare", "--exploratory", &out("b1"), &out("b3")]);
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("K-valid: different at 32"), "{text}");
    assert!(text.contains("K-length: equal at 71"), "{text}");

    // A replay: equal at a count the first run recorded, different where
    // the digest there differs, and a failure at a count it did not record.
    let replay = |b: &str| sigsoak(&["compare", "--replay", "--exploratory", &out("b1"), &out(b)]);
    let (code, text) = replay("b2");
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("replay comparison: equal"), "{text}");
    let (code, text) = replay("b3");
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("K-valid: different at 32"), "{text}");
    assert_eq!(run("b4", seed, pair, "16").0, 0);
    let (code, text) = replay("b4");
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("16 is not a count"), "{text}");

    // Another seed differs.
    assert_eq!(run("c", "0x1", pair, "32").0, 0);
    let (code, text) = sigsoak(&["compare", "--exploratory", &out("b1"), &out("c")]);
    assert_eq!(code, 1, "{text}");

    // A run that completes no case fails, and two such runs compare
    // nothing.
    for name in ["z1", "z2"] {
        let (code, text) = run_with(name, seed, pair, &["--budget", "0s"]);
        assert_eq!(code, 1, "{text}");
        let summary =
            std::fs::read_to_string(dir.path().join(name).join("summary.txt")).expect("read");
        assert!(summary.starts_with("status: failed"), "{summary}");
    }
    let (code, text) = sigsoak(&["compare", "--exploratory", &out("z1"), &out("z2")]);
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("K-valid: nothing compared"), "{text}");

    // A missing class fails unless a subset is allowed; disjoint runs fail
    // either way.
    assert_eq!(run("d", seed, pubkey[0], "32").0, 0);
    assert_eq!(run("e", seed, pubkey[1], "32").0, 0);
    let (code, text) = sigsoak(&["compare", "--exploratory", &out("a"), &out("d")]);
    assert_eq!(code, 1, "{text}");
    let (code, text) = sigsoak(&[
        "compare",
        "--exploratory",
        "--allow-subset",
        &out("a"),
        &out("d"),
    ]);
    assert_eq!(code, 0, "{text}");
    for args in [
        vec!["compare", "--exploratory"],
        vec!["compare", "--exploratory", "--allow-subset"],
    ] {
        let mut args = args;
        let (d, e) = (out("d"), out("e"));
        args.extend([d.as_str(), e.as_str()]);
        let (code, text) = sigsoak(&args);
        assert_eq!(code, 1, "{args:?}:\n{text}");
    }

    // A replayed case prints the leaf its run's digest implies.
    assert_eq!(run("f", seed, sampled, "1").0, 0);
    let (code, text) = sigsoak(&[
        "replay", "--seed", seed, "--class", sampled, "--case", "0", "--oracle", &oracle,
    ]);
    assert_eq!(code, 0, "{text}");
    let leaf = text
        .lines()
        .find_map(|l| l.strip_prefix("leaf "))
        .unwrap_or_else(|| panic!("no leaf:\n{text}"));
    let leaf: [u8; 32] = unhex(leaf).try_into().expect("32 bytes");
    let (n, digest) = final_digest(&dir.path().join("f"), sampled);
    assert_eq!(n, 1);
    assert_eq!(hex(&class_digest(sampled, 1, &leaf)), digest);

    // Where a run may not write.
    let inside = Path::new(env!("CARGO_MANIFEST_DIR")).join("sigsoak-cli-out");
    let (code, text) = run(&inside.display().to_string(), seed, "K-*", "1");
    assert_eq!(code, 2, "{text}");
    assert!(text.contains("inside the repository"), "{text}");
    assert!(!inside.exists());
    let (code, text) = run("a", seed, "K-*", "1");
    assert_eq!(code, 2, "a run's directory holds files:\n{text}");
}

/// The canary run of two canaries, one of each kind: the model baseline
/// over the recovery classes and both canaries pass and leave their
/// record; a run may then share the directory, and a second canary run
/// may not; a disagreement's replay line replays with its canary.
#[test]
fn canary_run_and_replay() {
    let Some(oracle) = oracle_bin_or_skip() else {
        return;
    };
    let oracle = oracle.display().to_string();
    let dir = TempDir::new("sigsoak-canary");
    let leg = dir.path().join("leg");
    let leg_arg = leg.display().to_string();
    let seed = "0x0123456789abcdef";
    let canary = |extra: &[&str]| {
        let mut args = vec![
            "canary",
            "--out",
            &leg_arg,
            "--seed",
            seed,
            "--canary",
            "C9,recover-accepts-infinity",
            "--cases",
            "32",
            "--workers",
            "2",
            "--oracle",
            &oracle,
        ];
        args.extend(extra);
        sigsoak(&args)
    };
    let (code, text) = canary(&[]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("canary run: passed"), "{text}");
    let record = leg.join("canary");
    let tsv = std::fs::read_to_string(record.join("summary.tsv")).expect("summary.tsv");
    let rows: Vec<Vec<&str>> = tsv
        .lines()
        .skip(1)
        .map(|l| l.split('\t').collect())
        .collect();
    assert_eq!(rows.len(), 3, "{tsv}");
    assert_eq!(rows[0][1], "model-baseline", "{tsv}");
    assert_eq!((rows[1][0], rows[1][2]), ("C9", "ES-hashGEN"), "{tsv}");
    assert_eq!((rows[2][0], rows[2][2]), ("C14", "ER-infinity"), "{tsv}");
    for row in &rows {
        assert_eq!(row[7], "pass", "{tsv}");
    }
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(record.join("manifest.json")).expect("read"))
            .expect("JSON");
    assert_eq!(manifest["command"], "canary");
    assert_eq!(manifest["status"], "passed");
    assert_eq!(manifest["pin"]["consistent"], true);
    assert_eq!(
        manifest["mode"],
        serde_json::json!({ "kind": "cases", "cases": 32 })
    );
    // --cases sets the baseline's and the other classes' volume; a
    // primary runs to the canary bound whatever it says.
    let part_cases = |part: &str| {
        let text = std::fs::read_to_string(record.join(part).join("manifest.json")).expect("read");
        let part: serde_json::Value = serde_json::from_str(&text).expect("JSON");
        part["mode"]["cases"].as_u64().expect("a count")
    };
    assert_eq!(part_cases("model-baseline"), 32);
    assert_eq!(part_cases("recover-accepts-infinity/primary"), CANARY_BOUND);
    assert_eq!(part_cases("recover-accepts-infinity/others"), 32);
    let baseline: Vec<&str> = manifest["baseline_classes"]
        .as_array()
        .expect("a list")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    let recover: Vec<&str> = CLASSES
        .iter()
        .filter(|c| c.family == Family::Recover)
        .map(|c| c.name)
        .collect();
    assert_eq!(baseline, recover, "C14 breaks only the recovery model");
    for part in [
        "model-baseline",
        "ecdsa-sign-reduced-hash/primary",
        "ecdsa-sign-reduced-hash/others",
        "recover-accepts-infinity/primary",
        "recover-accepts-infinity/others",
    ] {
        for file in [
            "manifest.json",
            "summary.txt",
            "digests.tsv",
            "disagreements.jsonl",
        ] {
            assert!(record.join(part).join(file).is_file(), "{part}/{file}");
        }
    }

    // The first disagreement C14 recorded replays with C14 in dcroxide's
    // place, and disagrees again; without it, dcroxide agrees.
    let lines = std::fs::read_to_string(
        record.join("recover-accepts-infinity/primary/disagreements.jsonl"),
    )
    .expect("read");
    let first: serde_json::Value =
        serde_json::from_str(lines.lines().next().expect("C14 disagreed")).expect("JSON");
    assert_eq!(first["canary"], "recover-accepts-infinity");
    let replay = first["replay"].as_str().expect("a replay line");
    assert!(
        replay.ends_with("--canary recover-accepts-infinity"),
        "{replay}"
    );
    let mut args: Vec<&str> = replay.split(' ').skip(1).collect();
    args.extend(["--oracle", &oracle]);
    let (code, text) = sigsoak(&args);
    assert_eq!(code, 1, "{text}");
    assert!(
        text.contains("canary recover-accepts-infinity answers in dcroxide's place"),
        "{text}"
    );
    let without: Vec<&str> = args
        .iter()
        .copied()
        .filter(|a| *a != "--canary" && *a != "recover-accepts-infinity")
        .collect();
    let (code, text) = sigsoak(&without);
    assert_eq!(code, 0, "{text}");
    let mut unknown = without.clone();
    unknown.extend(["--canary", "C99"]);
    let (code, text) = sigsoak(&unknown);
    assert_eq!(code, 2, "{text}");

    // A run may write beside a canary run; another canary run may not.
    let (code, text) = sigsoak(&[
        "run",
        "--out",
        &leg_arg,
        "--seed",
        seed,
        "--classes",
        "K-length",
        "--cases",
        "1",
        "--oracle",
        &oracle,
        "--progress-every",
        "1h",
    ]);
    assert_eq!(code, 0, "{text}");
    let (code, text) = canary(&[]);
    assert_eq!(code, 2, "{text}");
    assert!(text.contains("is not empty"), "{text}");
}

/// `list` writes to a reader that has gone away without a panic, and exits
/// 0: the pipe's read end is closed before the binary starts.
#[test]
fn list_ends_quietly_on_a_closed_pipe() {
    for args in [vec!["list"], vec!["list", "--canaries"]] {
        let (reader, writer) = std::io::pipe().expect("a pipe");
        drop(reader);
        let out = Command::new(env!("CARGO_BIN_EXE_sigsoak"))
            .args(&args)
            .stdout(writer)
            .stderr(Stdio::piped())
            .output()
            .expect("run sigsoak");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(0), "{args:?}: {stderr}");
        assert_eq!(stderr, "", "{args:?}");
    }
}

/// Usage errors exit 2, with the help; `help` and `list` exit 0.
#[test]
fn usage() {
    let (code, text) = sigsoak(&["help"]);
    assert_eq!(code, 0);
    assert!(text.contains("sigsoak run --out DIR"), "{text}");
    assert!(text.contains("sigsoak canary --out DIR"), "{text}");
    let (code, text) = sigsoak(&["list"]);
    assert_eq!(code, 0);
    for class in CLASSES {
        assert!(text.contains(class.name), "{text}");
    }
    let (code, text) = sigsoak(&["list", "--canaries"]);
    assert_eq!(code, 0);
    assert!(text.contains("model-baseline"), "{text}");
    for canary in CANARIES {
        assert!(
            text.contains(&format!("{}\t{}\t", canary.id, canary.name)),
            "{text}"
        );
        assert!(
            text.contains(&format!("primary {}", canary.primary)),
            "{text}"
        );
    }
    for args in [
        vec![],
        vec!["frobnicate"],
        vec!["run"],
        vec!["run", "--out", "/nowhere", "--cases", "1", "--floors"],
        vec!["run", "--out", "/nowhere", "--cases", "0"],
        vec!["run", "--out", "/nowhere", "--budget", "10x"],
        vec!["run", "--out", "/nowhere", "--cases", "1", "--cases", "2"],
        vec![
            "run",
            "--out",
            "/nowhere",
            "--cases",
            "1",
            "--classes",
            "Z-none",
        ],
        vec!["replay", "--seed", "zz", "--class", "x", "--case", "0"],
        vec!["compare", "one"],
        vec!["list", "--classes"],
        vec!["list", "--canaries=yes"],
        vec!["canary"],
        vec!["canary", "--out", "/nowhere", "--canary", "C99"],
        vec!["canary", "--out", "/nowhere", "--cases", "0"],
        vec!["canary", "--out", "/nowhere", "--floors"],
    ] {
        let (code, text) = sigsoak(&args);
        assert_eq!(code, 2, "{args:?}:\n{text}");
    }
}
