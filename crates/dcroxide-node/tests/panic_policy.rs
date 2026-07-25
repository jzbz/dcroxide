// SPDX-License-Identifier: ISC
//! The panic-containment policy is a deliberate, load-bearing choice, so
//! it is pinned here rather than left to whoever edits `Cargo.toml` next.
//!
//! Rust mutexes poison on panic; Go's `sync.Mutex` does not, so dcrd
//! recovers per goroutine where this port cannot. A panic on one thread
//! poisons every lock it held, and each other consumer dies in turn on
//! `.expect("… poisoned")`. Unwinding additionally let the RPC layer's
//! `catch_unwind` keep the process alive answering canned errors, so a
//! wedged node looked healthy and `Restart=on-failure` never fired.
//!
//! Aborting is the honest choice for a consensus daemon: state a panic
//! left half-mutated cannot be reasoned about, so a supervisor restarting
//! a clean node beats continuing on unknown state.

use std::path::Path;

/// The workspace release profile must abort on panic.
///
/// Deleting `panic = "abort"` silently restores the wedge-while-healthy
/// behaviour, and nothing else in the suite would notice — every test
/// runs under the dev profile, which keeps unwinding on purpose.
#[test]
fn the_release_profile_aborts_on_panic() {
    // tests/ -> crate root -> workspace root.
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("Cargo.toml");
    let text = std::fs::read_to_string(&manifest)
        .unwrap_or_else(|e| panic!("read {}: {e}", manifest.display()));

    let release = text
        .split("[profile.")
        .find(|section| section.starts_with("release]"))
        .expect("the workspace must define [profile.release]");

    assert!(
        release
            .lines()
            .any(|l| l.split('#').next().unwrap_or("").replace(' ', "") == "panic=\"abort\""),
        "[profile.release] must set panic = \"abort\"; without it a panic \
         poisons every lock it held, the RPC catch_unwind keeps the process \
         alive answering canned errors, and the node wedges while looking \
         healthy"
    );
}

/// Test builds must keep unwinding, or the suites that deliberately catch
/// a panic stop testing anything.
#[test]
fn test_builds_still_unwind() {
    let caught = std::panic::catch_unwind(|| panic!("deliberate"));
    assert!(
        caught.is_err(),
        "the test profile must unwind: several suites use #[should_panic] \
         or catch_unwind, and they silently stop testing under abort"
    );
}
