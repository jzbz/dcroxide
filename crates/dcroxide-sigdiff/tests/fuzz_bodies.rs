// SPDX-License-Identifier: ISC
//! The signature fuzz targets' bodies, run as the targets run them but
//! without libFuzzer: every class's seed inputs and fuzz-shaped inputs
//! agree with dcrd through the oracle and, for the Ed25519 classes, with
//! the Go-free model; every canary standing in for dcroxide trips its
//! primary's target with a side-by-side difference; and the process oracle
//! keeps an input, rejects one that reaches no class and goes on after a
//! finding.  Each test prints the master seed it drew
//! (`DCROXIDE_TEST_SEED` replays it).

use dcroxide_sigdiff::canary::{CANARIES, find_canary};
use dcroxide_sigdiff::class::{CLASSES, ClassSpec};
use dcroxide_sigdiff::compare::Category;
use dcroxide_sigdiff::fuzz::{
    self, Checked, FuzzOracle, Report, Target, check, check_ed25519_model, seed_indices, seed_input,
};
use dcroxide_sigdiff::run::{Mode, class_indices, ours_answerer};
use dcroxide_testutil::{SplitMix64, oracle_bin_or_skip, oracle_or_skip};

/// A length in `lo..=hi`.
fn len_in(rng: &mut SplitMix64, lo: usize, hi: usize) -> usize {
    let span = hi.saturating_sub(lo).saturating_add(1) as u64;
    lo.saturating_add(usize::try_from(rng.below(span)).expect("a short length"))
}

/// The fuzz-shaped inputs of `class`, the shapes a fuzzer's mutations
/// take: its selector, then random bytes of length 0, 1 to 8, 9 to 64, 65
/// to 600 (twice) and 2,200, then 600 bytes of 0xff, and a random 32-byte
/// block repeated to 320 bytes.
fn shaped(class: &ClassSpec, rng: &mut SplitMix64) -> Vec<Vec<u8>> {
    let selector = Target::of_class(class)
        .selector_of(class.name)
        .expect("a slot");
    let mut lengths = vec![0, len_in(rng, 1, 8), len_in(rng, 9, 64)];
    lengths.extend([len_in(rng, 65, 600), len_in(rng, 65, 600), 2_200]);
    let mut inputs: Vec<Vec<u8>> = lengths
        .into_iter()
        .map(|len| {
            let mut bytes = vec![0; len];
            rng.fill(&mut bytes);
            bytes
        })
        .collect();
    inputs.push(vec![0xff; 600]);
    let mut block = [0; 32];
    rng.fill(&mut block);
    inputs.push(block.repeat(10));
    for input in &mut inputs {
        input.insert(0, selector);
    }
    inputs
}

/// Whether a report holds a difference between dcroxide's answer and the
/// reference's, beside any intent it failed.
fn side_by_side(report: &Report) -> bool {
    report.failures.iter().any(|f| {
        matches!(
            f.category,
            Category::Verdict | Category::Value | Category::Flag | Category::Kind | Category::Text
        )
    })
}

/// Fails with the first few reports, if there are any, beside the
/// `agreed` inputs that passed.
fn assert_no_findings(what: &str, agreed: usize, findings: &[Box<Report>]) {
    let shown: Vec<String> = findings.iter().take(5).map(|r| r.to_string()).collect();
    assert!(
        findings.is_empty(),
        "{} of {} {what} failed; the first:\n{}",
        findings.len(),
        agreed.saturating_add(findings.len()),
        shown.join("\n\n")
    );
    println!("{what}: {agreed} agreed");
}

/// Every Ed25519 class's seed inputs and fuzz-shaped inputs, through the
/// model target: dcroxide agrees with the model on every parse and verify
/// request, and every signature it makes verifies under the model.
#[test]
fn the_ed25519_model_half_agrees() {
    let master = SplitMix64::from_entropy("fuzz_bodies model half").0;
    let mut rng = SplitMix64(master);
    let ours = ours_answerer(None);
    let mut findings = Vec::new();
    let mut agreed = 0usize;
    for class in Target::Ed25519.classes() {
        let mut inputs: Vec<Vec<u8>> = seed_indices(class, None)
            .into_iter()
            .map(|index| seed_input(class, master, index))
            .collect();
        inputs.extend(shaped(class, &mut rng));
        for input in inputs {
            match check_ed25519_model(&input, &ours) {
                Ok(Checked::Agreed { .. }) => agreed = agreed.saturating_add(1),
                Ok(Checked::NoClass) => panic!("{}: no class", class.name),
                Err(report) => findings.push(report),
            }
        }
    }
    assert_no_findings("model-half inputs", agreed, &findings);
}

/// The Ed25519 model canaries (C7, C8, C15, C16), standing in for
/// dcroxide over their primary's seed inputs at the canary per-PR test's
/// indices, each trip the model target in their primary.
#[test]
fn the_ed25519_model_half_catches_its_canaries() {
    let master = SplitMix64::from_entropy("fuzz_bodies model canaries").0;
    for id in ["C7", "C8", "C15", "C16"] {
        let canary = find_canary(id).expect("a canary");
        let primary = canary.primary_class();
        let ours = ours_answerer(Some(canary.stand_in()));
        let cases = Some(canary.primary_pr_cases());
        let report = class_indices(primary, Mode::PerPr { cases })
            .find_map(|index| check_ed25519_model(&seed_input(primary, master, index), &ours).err())
            .unwrap_or_else(|| panic!("{id} never tripped the model target in {}", primary.name));
        assert_eq!(report.class, primary.name, "{id}: {report}");
        assert!(side_by_side(&report), "{id}: {report}");
        println!(
            "{id} {}: tripped {} at {} case {}",
            canary.name, report.target, report.class, report.index
        );
    }
}

/// Every class's seed inputs at eight per-PR indices (finite classes of at
/// most 128 whole), through its target against the oracle.
#[test]
fn every_target_agrees_on_seed_inputs() {
    let Some(oracle) = oracle_or_skip() else {
        return;
    };
    let mut oracle = FuzzOracle::new(oracle).expect("the oracle keeps the pin");
    let master = SplitMix64::from_entropy("fuzz_bodies seeds").0;
    let ours = ours_answerer(None);
    let mut findings = Vec::new();
    let mut agreed = 0usize;
    for class in CLASSES {
        for index in seed_indices(class, Some(8)) {
            let input = seed_input(class, master, index);
            let target = Target::of_class(class);
            match check(target, &input, &ours, &mut |r| oracle.answer(r)) {
                Ok(Checked::Agreed { .. }) => agreed = agreed.saturating_add(1),
                Ok(Checked::NoClass) => panic!("{}: no class", class.name),
                Err(report) => findings.push(report),
            }
        }
    }
    assert_no_findings("seed inputs", agreed, &findings);
}

/// Every class's fuzz-shaped inputs through its target against the
/// oracle: under a stream a fuzzer chose, a case that missed its
/// construction is no finding while the two sides agree.
#[test]
fn every_target_agrees_on_fuzz_shaped_inputs() {
    let Some(oracle) = oracle_or_skip() else {
        return;
    };
    let mut oracle = FuzzOracle::new(oracle).expect("the oracle keeps the pin");
    let mut rng = SplitMix64::from_entropy("fuzz_bodies shaped");
    let ours = ours_answerer(None);
    let mut findings = Vec::new();
    let mut agreed = 0usize;
    for class in CLASSES {
        let target = Target::of_class(class);
        for input in shaped(class, &mut rng) {
            match check(target, &input, &ours, &mut |r| oracle.answer(r)) {
                Ok(Checked::Agreed { .. }) => agreed = agreed.saturating_add(1),
                Ok(Checked::NoClass) => panic!("{}: no class", class.name),
                Err(report) => findings.push(report),
            }
        }
    }
    assert_no_findings("fuzz-shaped inputs", agreed, &findings);
}

/// Each canary, C1 to C18, standing in for dcroxide over its primary's
/// seed inputs at the canary per-PR test's indices, trips its primary's
/// target with a difference between the two sides: a planted break in
/// dcroxide's place fails the target body, and rebasing the intents never
/// turns a real disagreement into an intent failure alone.
#[test]
fn every_canary_trips_its_target() {
    let Some(oracle) = oracle_or_skip() else {
        return;
    };
    let mut oracle = FuzzOracle::new(oracle).expect("the oracle keeps the pin");
    let master = SplitMix64::from_entropy("fuzz_bodies canaries").0;
    for canary in CANARIES {
        let primary = canary.primary_class();
        let target = Target::of_class(primary);
        let ours = ours_answerer(Some(canary.stand_in()));
        let cases = Some(canary.primary_pr_cases());
        let report = class_indices(primary, Mode::PerPr { cases })
            .find_map(|index| {
                let input = seed_input(primary, master, index);
                check(target, &input, &ours, &mut |r| oracle.answer(r)).err()
            })
            .unwrap_or_else(|| {
                panic!(
                    "{} never tripped {} in {}",
                    canary.id,
                    target.name(),
                    primary.name
                )
            });
        assert_eq!(report.class, primary.name, "{}: {report}", canary.id);
        assert!(side_by_side(&report), "{}: {report}", canary.id);
        println!(
            "{} {}: tripped {} at {} case {}",
            canary.id,
            canary.name,
            target.name(),
            report.class,
            report.index
        );
    }
}

/// The process oracle, as a target's body uses it: an input that reaches a
/// class is kept, one that reaches none is rejected, and a finding panics
/// with its report, after which the next input is answered as before.
#[test]
fn fuzz_one_keeps_rejects_and_panics() {
    if oracle_bin_or_skip().is_none() {
        return;
    }
    let master = SplitMix64::from_entropy("fuzz_bodies fuzz_one").0;
    let xgen = CLASSES
        .iter()
        .find(|c| c.name == "EV-xGEN-true")
        .expect("registered");
    let input = seed_input(xgen, master, 0);
    let ours = ours_answerer(None);
    assert!(fuzz::fuzz_one(Target::Ecdsa, &input, &ours), "kept");
    let past = u8::try_from(Target::Ecdsa.slots().len()).expect("a short table");
    assert!(
        !fuzz::fuzz_one(Target::Ecdsa, &[past, 0, 1], &ours),
        "rejected"
    );

    let c1 = find_canary("C1").expect("C1");
    assert_eq!(c1.primary, "EV-xGEN-true");
    let broken = ours_answerer(Some(c1.stand_in()));
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fuzz::fuzz_one(Target::Ecdsa, &input, &broken)
    }))
    .expect_err("C1 fails every EV-xGEN-true case");
    let message = caught
        .downcast_ref::<String>()
        .expect("the report as the payload");
    assert!(
        message.starts_with("dcrec_diff_ecdsa: EV-xGEN-true case 0x0000000000000000"),
        "{message}"
    );
    assert!(
        fuzz::fuzz_one(Target::Ecdsa, &input, &ours),
        "answered after the finding"
    );
}
