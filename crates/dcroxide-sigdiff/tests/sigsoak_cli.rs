// SPDX-License-Identifier: ISC
//! The `sigsoak` binary end to end against the real oracle: a run writes
//! every file of its record, a replayed case's leaf is the one its run's
//! digest implies, `compare` passes equal runs and fails each kind of
//! difference, a run that completes nothing fails, `--out` is refused
//! inside the repository or when it holds files, and `--min-scale` judges a
//! budget run's floors at its share, as the nightly soak in CI has it do.
//! A canary run writes its record beside a run's, each disagreement it
//! records replays with its canary, `emit-corpus` writes the witness file
//! `dcroxide-dcrec` keeps, `fuzz-seeds` writes the signature fuzz targets'
//! seed inputs and `fuzz-replay` replays them, starting the oracle again
//! after one that fails, a copy of the binary records its own build
//! wherever it lies, and `list` ends quietly when its reader goes away.

use std::path::Path;
use std::process::{Command, Stdio};

use dcroxide_sigdiff::canary::{CANARIES, CANARY_BOUND};
use dcroxide_sigdiff::class::{CLASSES, Family, find_class};
use dcroxide_sigdiff::digest::class_digest;
use dcroxide_sigdiff::fuzz::{ED25519_MODEL_TARGET, SEED_MASTER, Target, seed_input};
use dcroxide_sigdiff::manifest::repo_root;
use dcroxide_sigdiff::run::{Mode, class_indices};
use dcroxide_sigdiff::witness::{FILE_NAME, vector_lines};
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
    // The soak profile check is recorded beside the build's facts: a
    // profile, or why the build is none.
    let rust = &manifest["rust"];
    assert_ne!(
        rust["soak_profile"].is_null(),
        rust["profile_problem"].is_null(),
        "{rust}"
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

/// A budget run with `--min-scale` judges the floors at that share: a
/// finite class run whole meets its floor, which ends the run long before
/// its budget, while two seconds leave a sampled class short of its full
/// floor and the run failed.  The manifest's mode carries the share.
#[test]
fn min_scale_judges_a_budget_run() {
    let Some(oracle) = oracle_bin_or_skip() else {
        return;
    };
    let oracle = oracle.display().to_string();
    let dir = TempDir::new("sigsoak-min-scale");
    let run = |name: &str, classes: &str, budget: &str| {
        let out = dir.path().join(name).display().to_string();
        let (code, text) = sigsoak(&[
            "run",
            "--out",
            &out,
            "--seed",
            "0x1",
            "--classes",
            classes,
            "--workers",
            "2",
            "--oracle",
            &oracle,
            "--progress-every",
            "1h",
            "--budget",
            budget,
            "--min-scale",
            "1",
        ]);
        let floors = text
            .lines()
            .find(|l| l.trim_start().starts_with("2 floors:"))
            .unwrap_or_else(|| panic!("no floors criterion:\n{text}"))
            .trim()
            .to_owned();
        (code, floors, text)
    };

    let (code, floors, text) = run("whole", "K-length", "60s");
    assert_eq!(code, 0, "{text}");
    assert_eq!(
        floors,
        "2 floors: pass (every class reached its floor times 1 (finite classes whole))"
    );
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join("whole").join("manifest.json")).expect("read"),
    )
    .expect("JSON");
    assert_eq!(
        manifest["mode"],
        serde_json::json!({ "kind": "budget", "seconds": 60, "min_scale": 1.0 })
    );

    let (code, floors, text) = run("short", "K-length,K-valid", "2s");
    assert_eq!(code, 1, "{text}");
    assert!(
        floors.starts_with("2 floors: FAIL (below its floor times 1: ")
            && floors.contains("K-valid "),
        "{text}"
    );
}

/// The nightly soak in CI judges its floors: its one budget run passes a
/// share in (0, 1] as `--min-scale`, without which a budget run judges no
/// floor and a night whose classes ran short would pass.
#[test]
fn the_nightly_soak_judges_its_floors() {
    let root = repo_root().expect("the repository root");
    let ci = std::fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("read ci.yml");
    let (_, job) = ci
        .split_once("\n  nightly-sigsoak:\n")
        .expect("the nightly-sigsoak job");
    let budget: Vec<&str> = job
        .lines()
        .take_while(|l| l.is_empty() || l.starts_with("    "))
        .filter(|l| l.contains("--budget"))
        .collect();
    let [run] = budget[..] else {
        panic!("one budget run in nightly-sigsoak: {budget:?}");
    };
    let share = run
        .split_whitespace()
        .skip_while(|word| *word != "--min-scale")
        .nth(1)
        .unwrap_or_else(|| panic!("the budget run passes no --min-scale: {run}"));
    let share: f64 = share.parse().expect("a number");
    assert!(share > 0.0 && share <= 1.0, "{run}");
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

/// `emit-corpus` at the default seed writes the witness file with the
/// committed file's vector lines, and refuses a directory that holds it
/// or lies inside the repository.
#[test]
fn emit_corpus_writes_the_witness_file() {
    let Some(oracle) = oracle_bin_or_skip() else {
        return;
    };
    let oracle = oracle.display().to_string();
    let dir = TempDir::new("sigsoak-emit");
    let out = dir.path().join("emit").display().to_string();
    let (code, text) = sigsoak(&["emit-corpus", "--out", &out, "--oracle", &oracle]);
    assert_eq!(code, 0, "{text}");
    assert!(
        text.contains("sigsoak: master seed 0x7769746e65737331"),
        "{text}"
    );
    for count in ["  EV-xGEN-true: 4 lines\n", "  SV-rGEN-true: 1 line\n"] {
        assert!(text.contains(count), "{count:?} in:\n{text}");
    }
    let written = std::fs::read_to_string(Path::new(&out).join(FILE_NAME)).expect("the file");
    let committed = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcroxide-dcrec/tests/data/sigdiff_witness_vectors.txt"
    ));
    assert_eq!(
        vector_lines(&written).collect::<Vec<_>>(),
        vector_lines(committed).collect::<Vec<_>>()
    );
    assert!(written.starts_with("# Witness vectors"), "{written}");

    let (code, text) = sigsoak(&["emit-corpus", "--out", &out, "--oracle", &oracle]);
    assert_eq!(code, 2, "the directory holds the file:\n{text}");
    assert!(text.contains("is not empty"), "{text}");
    let inside = Path::new(env!("CARGO_MANIFEST_DIR")).join("sigsoak-emit-out");
    let inside_arg = inside.display().to_string();
    let (code, text) = sigsoak(&["emit-corpus", "--out", &inside_arg, "--oracle", &oracle]);
    assert_eq!(code, 2, "{text}");
    assert!(text.contains("inside the repository"), "{text}");
    assert!(!inside.exists());
}

/// `fuzz-seeds` writes a directory per signature fuzz target, holding the
/// seed input of every case the per-PR plan takes at its count, each the
/// bytes `seed_input` gives under the seed it is given and named by its
/// case index; it needs no oracle, and refuses a directory that holds
/// files or lies inside the repository.
#[test]
fn fuzz_seeds_writes_each_targets_inputs() {
    let dir = TempDir::new("sigsoak-fuzz-seeds");
    let out = dir.path().join("seeds");
    let out_arg = out.display().to_string();
    let (code, text) = sigsoak(&["fuzz-seeds", "--out", &out_arg, "--cases", "2"]);
    assert_eq!(code, 0, "{text}");
    assert!(
        text.contains("sigsoak: master seed 0x66757a7a73656564"),
        "{text}"
    );
    let planned = |target: Target| -> usize {
        target
            .classes()
            .map(|c| class_indices(c, Mode::PerPr { cases: Some(2) }).count())
            .sum()
    };
    let mut targets: Vec<(&str, usize)> = Target::ALL
        .iter()
        .map(|t| (t.name(), planned(*t)))
        .collect();
    targets.push((ED25519_MODEL_TARGET, planned(Target::Ed25519)));
    for (name, want) in &targets {
        let files = std::fs::read_dir(out.join(name))
            .unwrap_or_else(|e| panic!("{name}: {e}"))
            .count();
        assert_eq!(files, *want, "{name}");
    }
    assert_eq!(
        targets.iter().map(|(_, n)| *n).collect::<Vec<_>>(),
        [52, 24, 93, 32, 333, 333]
    );
    assert_eq!(std::fs::read_dir(&out).expect("read").count(), 6);
    let k_length = find_class("K-length").expect("registered");
    for name in [
        "dcrec_diff_pubkey/K-length-0",
        "dcrec_diff_pubkey/K-length-70",
    ] {
        let index = name.rsplit('-').next().and_then(|i| i.parse().ok());
        let want = seed_input(k_length, SEED_MASTER, index.expect("an index"));
        assert_eq!(std::fs::read(out.join(name)).expect("read"), want, "{name}");
    }
    assert_eq!(
        std::fs::read(out.join("dcrec_ed25519_model/DV-torsion-5")).expect("read"),
        std::fs::read(out.join("dcrec_diff_ed25519/DV-torsion-5")).expect("read")
    );
    // A large finite class is taken at a stride, so its second file is
    // named by the case index, not by its place in the list.
    let k_small_x = find_class("K-smallX").expect("registered");
    let second = class_indices(k_small_x, Mode::PerPr { cases: Some(2) })
        .nth(1)
        .expect("two cases");
    assert_ne!(second, 1, "K-smallX is taken at a stride");
    assert_eq!(
        std::fs::read(out.join(format!("dcrec_diff_pubkey/K-smallX-{second}"))).expect("read"),
        seed_input(k_small_x, SEED_MASTER, second)
    );
    // --seed names the master seed the inputs regenerate under.
    let other = dir.path().join("other");
    let (code, text) = sigsoak(&[
        "fuzz-seeds",
        "--out",
        &other.display().to_string(),
        "--seed",
        "0x1",
        "--cases",
        "1",
    ]);
    assert_eq!(code, 0, "{text}");
    assert!(
        text.contains("sigsoak: master seed 0x0000000000000001"),
        "{text}"
    );
    let honest = find_class("EV-honest").expect("registered");
    let at_one = std::fs::read(other.join("dcrec_diff_ecdsa/EV-honest-0")).expect("read");
    assert_eq!(at_one, seed_input(honest, 1, 0));
    assert_ne!(
        at_one,
        std::fs::read(out.join("dcrec_diff_ecdsa/EV-honest-0")).expect("read")
    );

    let (code, text) = sigsoak(&["fuzz-seeds", "--out", &out_arg, "--cases", "2"]);
    assert_eq!(code, 2, "the directory holds the seeds:\n{text}");
    assert!(text.contains("is not empty"), "{text}");
    let inside = Path::new(env!("CARGO_MANIFEST_DIR")).join("sigsoak-seeds-out");
    let inside_arg = inside.display().to_string();
    let (code, text) = sigsoak(&["fuzz-seeds", "--out", &inside_arg]);
    assert_eq!(code, 2, "{text}");
    assert!(text.contains("inside the repository"), "{text}");
    assert!(!inside.exists());
}

/// `fuzz-replay` checks an input as its target does and prints the report:
/// a seed input of each oracle-backed target agrees; a canary standing in
/// for dcroxide fails one; the model target needs no oracle, agrees over
/// DV-torsion's 128 cases and fails where a canary negates the scalar;
/// and `--hex` replays the same bytes as the file.
#[test]
fn fuzz_replay_replays_inputs() {
    let Some(oracle) = oracle_bin_or_skip() else {
        return;
    };
    let oracle = oracle.display().to_string();
    let dir = TempDir::new("sigsoak-fuzz-replay");
    let seeds = dir.path().join("seeds");
    let (code, text) = sigsoak(&[
        "fuzz-seeds",
        "--out",
        &seeds.display().to_string(),
        "--cases",
        "1",
    ]);
    assert_eq!(code, 0, "{text}");
    let file = |target: &str, name: &str| seeds.join(target).join(name).display().to_string();
    let replay = |target: &str, extra: &[&str]| {
        let mut args = vec!["fuzz-replay", "--target", target, "--oracle", &oracle];
        args.extend(extra);
        sigsoak(&args)
    };
    for target in Target::ALL {
        let class = target.classes().next().expect("a class");
        let input = file(target.name(), &format!("{}-0", class.name));
        let (code, text) = replay(target.name(), &[&input]);
        assert_eq!(code, 0, "{text}");
        assert!(
            text.contains(&format!(
                "{}: {} case 0x0000000000000000",
                target.name(),
                class.name
            )),
            "{text}"
        );
        assert!(text.contains("dcroxide and dcrd agree"), "{text}");
    }

    let xgen = file("dcrec_diff_ecdsa", "EV-xGEN-true-0");
    let (code, text) = replay(
        "dcrec_diff_ecdsa",
        &["--canary", "ecdsa-verify-no-rplusn", &xgen],
    );
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("dcroxide and dcrd disagree"), "{text}");

    let (code, from_file) = replay("dcrec_diff_ecdsa", &[&xgen]);
    assert_eq!(code, 0, "{from_file}");
    let bytes = std::fs::read(&xgen).expect("read");
    let (code, from_hex) = replay("dcrec_diff_ecdsa", &["--hex", &hex(&bytes)]);
    assert_eq!(code, 0, "{from_hex}");
    assert_eq!(from_file.replace(&xgen, "--hex"), from_hex);

    // The model target asks no oracle: one that cannot be found is no
    // obstacle.
    let torsion: Vec<String> = (0..128)
        .map(|i| file(ED25519_MODEL_TARGET, &format!("DV-torsion-{i}")))
        .collect();
    let model = |extra: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_sigsoak"))
            .args(["fuzz-replay", "--target", ED25519_MODEL_TARGET])
            .args(extra)
            .args(&torsion)
            .env("DCROXIDE_ORACLE_BIN", "/nonexistent/dcrd-oracle")
            .env("PATH", dir.path())
            .output()
            .expect("run sigsoak");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        (out.status.code().unwrap_or(-1), text)
    };
    let (code, text) = model(&[]);
    assert_eq!(code, 0, "{text}");
    assert_eq!(
        text.matches("dcroxide and the model of dcrd's Ed25519 agree")
            .count(),
        128
    );
    let (code, text) = model(&["--canary", "ed25519-scalar-negation"]);
    assert_eq!(code, 1, "{text}");
    let differ = text
        .matches("dcroxide and the model of dcrd's Ed25519 (src/model/ed25519.rs, frozen) disagree")
        .count();
    assert_eq!(differ, 48, "{text}");
}

/// `fuzz-replay` starts the oracle again after one that fails on an input.
/// A stand-in at `--oracle` answers `build_info` through the real oracle,
/// then exits on the next request, or answers it with a line that is no
/// reply, and so fails the first input; started again, it is the real
/// oracle, which answers the second.
#[cfg(unix)]
#[test]
fn fuzz_replay_restarts_an_oracle_that_fails() {
    use std::os::unix::fs::PermissionsExt;

    let Some(oracle) = oracle_bin_or_skip() else {
        return;
    };
    let dir = TempDir::new("sigsoak-fuzz-replay-restarts");
    let seeds = dir.path().join("seeds");
    let (code, text) = sigsoak(&[
        "fuzz-seeds",
        "--out",
        &seeds.display().to_string(),
        "--cases",
        "1",
    ]);
    assert_eq!(code, 0, "{text}");
    let ecdsa = seeds.join("dcrec_diff_ecdsa");
    let first = ecdsa.join("EV-honest-0").display().to_string();
    let second = ecdsa.join("EV-highS-0").display().to_string();
    for (name, then, failure) in [
        (
            "dies",
            "read -r line\nexit 2\n",
            "oracle-crashed on request 0: the oracle closed its output without answering; \
             the oracle exited (exit status: 2)",
        ),
        (
            "garbles",
            "read -r line\necho garbage\nexec cat > /dev/null\n",
            "protocol on request 0: not JSON",
        ),
    ] {
        let stand_in = dir.path().join(name);
        let script = format!(
            "#!/bin/sh\n\
             if [ -e \"$STAND_IN_STARTED\" ]; then exec \"$STAND_IN_ORACLE\"; fi\n\
             : > \"$STAND_IN_STARTED\"\n\
             read -r line && printf '%s\\n' \"$line\" | \"$STAND_IN_ORACLE\"\n\
             {then}"
        );
        // `--oracle` takes a path, so the stand-in is a file. `sh` writes
        // it, not this process, so that sigsoak never meets a file another
        // thread's fork still holds open for writing.
        let wrote = Command::new("sh")
            .args(["-c", "printf '%s' \"$2\" > \"$1\"", "sh"])
            .arg(&stand_in)
            .arg(&script)
            .status()
            .expect("run sh");
        assert!(
            wrote.success(),
            "{name}: sh did not write the stand-in: {wrote}"
        );
        std::fs::set_permissions(&stand_in, std::fs::Permissions::from_mode(0o755))
            .expect("make the stand-in executable");
        let started = dir.path().join(format!("{name}.started"));
        let out = Command::new(env!("CARGO_BIN_EXE_sigsoak"))
            .args(["fuzz-replay", "--target", "dcrec_diff_ecdsa", "--oracle"])
            .arg(&stand_in)
            .args([&first, &second])
            .env("STAND_IN_ORACLE", &oracle)
            .env("STAND_IN_STARTED", &started)
            .output()
            .expect("run sigsoak");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert_eq!(out.status.code(), Some(1), "{name}:\n{text}");
        let report = |input: &str| {
            let mut lines = text.lines().skip_while(|l| *l != format!("{input}:"));
            let headline = lines
                .nth(1)
                .unwrap_or_else(|| panic!("{name}: no report of {input}:\n{text}"));
            (headline, lines.next().unwrap_or_default())
        };
        let (headline, line) = report(&first);
        assert!(
            headline.starts_with("dcrec_diff_ecdsa: EV-honest case 0x0000000000000000")
                && headline.ends_with(": the oracle failed")
                && line.trim_start().starts_with(failure),
            "{name}:\n{text}"
        );
        assert!(
            text.contains(&format!(
                "sigsoak: the oracle failed on {first}; a fresh one answers the rest"
            )),
            "{name}:\n{text}"
        );
        let (headline, _) = report(&second);
        assert!(
            headline.starts_with("dcrec_diff_ecdsa: EV-highS case 0x0000000000000000")
                && headline.ends_with(": dcroxide and dcrd agree"),
            "{name}:\n{text}"
        );
    }
}

/// Whether this test binary computes with overflow checks, probed as
/// sigsoak probes its own: the same profile builds both.
fn overflow_checks() -> bool {
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the overflow is the probe: it panics exactly when overflow checks are on"
    )]
    let checked =
        std::panic::catch_unwind(|| std::hint::black_box(u8::MAX) + std::hint::black_box(1u8))
            .is_err();
    checked
}

/// The binary copied into a directory named `soak` records that name and,
/// beside it, its own debug assertions, overflow checks and panic
/// strategy, which a copy keeps; it is the soak profile only if those are
/// soak's, so a test build there is refused for its debug assertions.
#[test]
fn a_copied_binary_records_its_own_build() {
    let Some(oracle) = oracle_bin_or_skip() else {
        return;
    };
    let dir = TempDir::new("sigsoak-copied");
    let built = Path::new(env!("CARGO_BIN_EXE_sigsoak"));
    let soak = dir.path().join("soak");
    std::fs::create_dir(&soak).expect("create soak/");
    let copy = soak.join(built.file_name().expect("a file name"));
    std::fs::copy(built, &copy).expect("copy sigsoak");
    let out = dir.path().join("out");
    let run = Command::new(&copy)
        .args(["run", "--out"])
        .arg(&out)
        .args(["--cases", "1", "--classes", "K-valid", "--workers", "1"])
        .args(["--seed", "0x0123456789abcdef", "--progress-every", "1h"])
        .arg("--oracle")
        .arg(&oracle)
        .output()
        .expect("run the copy");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(run.status.code(), Some(0), "{text}");
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("manifest.json")).expect("read"))
            .expect("JSON");
    let rust = &manifest["rust"];
    assert_eq!(rust["profile"], "soak", "{rust}");
    let overflow = overflow_checks();
    assert_eq!(rust["overflow_checks"], overflow, "{rust}");
    assert_eq!(rust["debug_assertions"], cfg!(debug_assertions), "{rust}");
    assert_eq!(rust["panic"], "unwind", "{rust}");
    if !cfg!(debug_assertions) && !overflow {
        assert_eq!(rust["soak_profile"], "soak", "{rust}");
    } else {
        assert!(rust["soak_profile"].is_null(), "{rust}");
    }
    if cfg!(debug_assertions) {
        let problem = rust["profile_problem"].as_str().unwrap_or_default();
        assert!(problem.contains("debug assertions are on"), "{rust}");
    }
    assert_eq!(manifest["gate_eligible"], false);
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
    assert!(text.contains("sigsoak emit-corpus --out DIR"), "{text}");
    assert!(text.contains("sigsoak fuzz-seeds --out DIR"), "{text}");
    assert!(text.contains("sigsoak fuzz-replay --target NAME"), "{text}");
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
        vec!["emit-corpus"],
        vec!["emit-corpus", "--out", "/nowhere", "--seed", "zz"],
        vec!["emit-corpus", "--out", "/nowhere", "--cases", "1"],
        vec!["fuzz-seeds"],
        vec!["fuzz-seeds", "--out", "/nowhere", "--cases", "0"],
        vec!["fuzz-seeds", "--out", "/nowhere", "--seed", "zz"],
        vec!["fuzz-seeds", "--out", "/nowhere", "extra"],
        vec!["fuzz-replay", "--hex", "00"],
        vec!["fuzz-replay", "--target", "dcrec_nothing", "--hex", "00"],
        vec!["fuzz-replay", "--target", "dcrec_ed25519_model"],
        vec![
            "fuzz-replay",
            "--target",
            "dcrec_ed25519_model",
            "--hex",
            "0g",
        ],
        vec![
            "fuzz-replay",
            "--target",
            "dcrec_ed25519_model",
            "--hex",
            "000",
        ],
        vec![
            "fuzz-replay",
            "--target",
            "dcrec_ed25519_model",
            "--hex",
            "00",
            "f",
        ],
        vec![
            "fuzz-replay",
            "--target",
            "dcrec_ed25519_model",
            "--canary",
            "C99",
            "--hex",
            "00",
        ],
        vec![
            "fuzz-replay",
            "--target",
            "dcrec_ed25519_model",
            "/nowhere/crash",
        ],
    ] {
        let (code, text) = sigsoak(&args);
        assert_eq!(code, 2, "{args:?}:\n{text}");
    }
    // --min-scale takes a share of the floors in (0, 1], and only with
    // --budget.
    let needs_budget = "--min-scale needs --budget";
    let share = "--min-scale takes a share of the floors in (0, 1]";
    for (size, min_scale, message) in [
        ("--cases=4", "0.5", needs_budget),
        ("--floors", "0.5", needs_budget),
        ("--budget=1s", "0", share),
        ("--budget=1s", "2", share),
        ("--budget=1s", "nan", share),
        ("--budget=1s", "x", "is not a number"),
    ] {
        let args = ["run", "--out", "/nowhere", size, "--min-scale", min_scale];
        let (code, text) = sigsoak(&args);
        assert_eq!(code, 2, "{args:?}:\n{text}");
        assert!(text.contains(message), "{args:?}:\n{text}");
    }
}
