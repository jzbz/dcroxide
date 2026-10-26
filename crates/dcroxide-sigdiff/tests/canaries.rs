// SPDX-License-Identifier: ISC
//! The canaries against dcrd's own code through the oracle, at their
//! per-PR size: the models with no break agree with dcrd on 16 cases of
//! every class of their commands; each canary disagrees with dcrd in its
//! primary class within its per-PR count; and over 4 cases of every other
//! class of its commands it disagrees only within its declared footprint.
//! The 10^4-case bound and the full sweep are `sigsoak canary`'s.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::thread;

use dcroxide_sigdiff::canary::{CANARIES, Canary, MODEL_BASELINE, find_canary};
use dcroxide_sigdiff::run::{
    CanaryReport, CanaryVolume, RunStatus, baseline_check, baseline_classes, canary_check,
    test_config,
};

/// The model baseline: every class of the five model commands, all of
/// them agreeing with dcrd, every intent and every evaluable mix held.
#[test]
fn the_models_agree_with_dcrd() {
    let Some(base) = test_config("canaries model-baseline") else {
        return;
    };
    let all: Vec<_> = CANARIES.iter().collect();
    let classes = baseline_classes(&all);
    let names = |classes: &[&dcroxide_sigdiff::class::ClassSpec]| -> Vec<&str> {
        classes.iter().map(|c| c.name).collect()
    };
    assert_eq!(
        names(&classes),
        names(&MODEL_BASELINE.classes()),
        "every model command is broken by some canary"
    );
    let summary = baseline_check(&base, classes, CanaryVolume::PerPr).expect("the baseline runs");
    for class in &summary.classes {
        println!(
            "{}: {} cases, statuses {:?}",
            class.name, class.completed, class.statuses
        );
    }
    assert!(
        summary.status == RunStatus::Passed && summary.disagreements == 0,
        "the model baseline disagrees with dcrd (master seed {:#018x}):\n{}",
        summary.master,
        summary.problems().join("\n")
    );
    assert!(summary.classes.iter().all(|c| c.completed > 0));
}

/// Every canary fires in its primary and nowhere outside its footprint.
#[test]
fn every_canary_is_caught_where_it_should_be() {
    let Some(base) = test_config("canaries") else {
        return;
    };
    let next = AtomicUsize::new(0);
    let outcomes = Mutex::new(Vec::new());
    let threads = thread::available_parallelism()
        .map_or(1, usize::from)
        .min(CANARIES.len());
    thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                while let Some(canary) = CANARIES.get(next.fetch_add(1, Ordering::SeqCst)) {
                    let outcome = canary_check(&base, canary, CanaryVolume::PerPr)
                        .unwrap_or_else(|e| panic!("{}: {e}", canary.id));
                    outcomes
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(outcome);
                }
            });
        }
    });
    let mut outcomes = outcomes
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner);
    outcomes.sort_by_key(|o| CANARIES.iter().position(|c| c.id == o.canary.id));
    let report = CanaryReport {
        master: base.master,
        baseline: None,
        outcomes,
    };
    print!("{}", report.render());
    assert_eq!(report.outcomes.len(), CANARIES.len());
    assert!(
        report.pass(),
        "canaries failed (master seed {:#018x}):\n{}",
        base.master,
        report.render()
    );
    for outcome in &report.outcomes {
        assert_eq!(
            outcome.fired.first().map(|(class, _)| *class),
            Some(outcome.canary.primary),
            "{}: its primary is listed first",
            outcome.canary.id
        );
        // Where the first disagreement is fixed by the primary's layout:
        // C4 needs K-hybridMismatch's off-curve stratum (odd i), C7 a
        // DV-torsion point other than the identity (i >= 16), C15
        // DV-zeroS-smallR's first non-canonical stratum (i = 43), C18
        // SV-unequalR's xminusN stratum (i % 3 = 1); C8's depends on the
        // challenge, and every other canary fires on every case.
        let first = match outcome.canary.id {
            "C4" | "C18" => Some(1),
            "C7" => Some(16),
            "C15" => Some(43),
            "C8" => None,
            _ => Some(0),
        };
        if let Some(first) = first {
            assert_eq!(
                outcome.first_index,
                Some(first),
                "{}: the first index caught",
                outcome.canary.id
            );
        }
    }
}

/// A canary that disagrees outside its declared footprint fails: C5 with
/// its footprint taken away still fires in K-XTooBig and K-YTooBig, which
/// the run reports as outside it.
#[test]
fn a_firing_outside_the_footprint_fails() {
    let Some(base) = test_config("canaries footprint") else {
        return;
    };
    let c5 = find_canary("C5").expect("C5");
    let narrowed: &'static Canary = Box::leak(Box::new(Canary {
        footprint: &[],
        ..*c5
    }));
    let outcome = canary_check(&base, narrowed, CanaryVolume::PerPr).expect("the canary runs");
    let unexpected: Vec<&str> = outcome.unexpected.iter().map(|(class, _)| *class).collect();
    assert_eq!(unexpected, ["K-XTooBig", "K-YTooBig"], "{outcome:?}");
    assert_eq!(outcome.notes.len(), 2, "{outcome:?}");
    assert!(outcome.first_index.is_some() && outcome.problems.is_empty());
    assert!(!outcome.pass());
}
