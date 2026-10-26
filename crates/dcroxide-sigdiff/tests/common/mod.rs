// SPDX-License-Identifier: ISC
//! The family tests' runner: every class of a family through
//! `run_class_for_test` against the real oracle, several at once.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::thread;

use dcroxide_sigdiff::class::{CLASSES, Family};
use dcroxide_sigdiff::run::{RunStatus, run_class_for_test};

/// Runs every class of `family` at its per-PR size, at most
/// `available_parallelism` at once, and fails naming every class that did
/// not pass, with its master seed (`DCROXIDE_TEST_SEED` replays it) and
/// what went wrong: a disagreement, an intent that did not hold, a mix or
/// count that failed, or a run that did not complete.  Returns without
/// checking anything when the oracle is unavailable and the policy says
/// skip.  A class added to the family later is covered without an edit.
pub fn run_family(family: Family) {
    let names: Vec<&'static str> = CLASSES
        .iter()
        .filter(|c| c.family == family)
        .map(|c| c.name)
        .collect();
    assert!(!names.is_empty(), "no class in {family:?}");
    let next = AtomicUsize::new(0);
    let skipped = AtomicBool::new(false);
    let failures = Mutex::new(Vec::new());
    let threads = thread::available_parallelism()
        .map_or(1, usize::from)
        .min(names.len());
    thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                while let Some(&name) = names.get(next.fetch_add(1, Ordering::SeqCst)) {
                    let Some(summary) = run_class_for_test(name) else {
                        skipped.store(true, Ordering::SeqCst);
                        return;
                    };
                    let mut problems = summary.problems();
                    if summary.status != RunStatus::Passed && problems.is_empty() {
                        problems.push(format!("status {}", summary.status.name()));
                    }
                    if summary.disagreements != 0 && problems.is_empty() {
                        problems.push(format!("{} disagreements", summary.disagreements));
                    }
                    let class = summary.class(name).expect("the class ran");
                    if class.target != Some(class.completed) {
                        problems.push(format!(
                            "completed {} of {:?} cases",
                            class.completed, class.target
                        ));
                    }
                    println!(
                        "{name}: {} cases, {} requests, statuses {:?}, master seed {:#018x}",
                        class.completed, class.requests, class.statuses, summary.master
                    );
                    if !problems.is_empty() {
                        failures
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .push(format!(
                                "{name} (master seed {:#018x}):\n    {}",
                                summary.master,
                                problems.join("\n    ")
                            ));
                    }
                }
            });
        }
    });
    if skipped.load(Ordering::SeqCst) {
        return;
    }
    let failures = failures
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner);
    assert!(
        failures.is_empty(),
        "{} of {} {family:?} classes failed:\n{}",
        failures.len(),
        names.len(),
        failures.join("\n")
    );
}
