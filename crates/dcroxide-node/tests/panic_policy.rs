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

/// The workspace `Cargo.toml`.
fn workspace_manifest() -> String {
    // tests/ -> crate root -> workspace root.
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("Cargo.toml");
    std::fs::read_to_string(&manifest)
        .unwrap_or_else(|e| panic!("read {}: {e}", manifest.display()))
}

/// The body of `[profile.<name>]`, up to the next section.
fn profile<'a>(manifest: &'a str, name: &str) -> Option<&'a str> {
    let (_, body) = manifest.split_once(&format!("[profile.{name}]"))?;
    body.split("\n[").next()
}

/// A key's value in a section body, comments and spaces stripped.
fn setting(section: &str, key: &str) -> Option<String> {
    section.lines().find_map(|l| {
        let l = l.split('#').next().unwrap_or("").replace(' ', "");
        l.strip_prefix(&format!("{key}=")).map(str::to_string)
    })
}

/// The shipped profiles must wrap on integer overflow, as Go does.
///
/// `overflow-checks = true` beside `panic = "abort"` turns every
/// overflowing `+`, `*` or `<<` into a process abort, some on values a
/// peer supplies, where dcrd wraps -- and the whole suite would pass,
/// because tests run under the dev profile, whose checks are on. `dist`
/// is checked as well: release artifacts are cut from it, and it could
/// override what it inherits.
#[test]
fn the_shipped_profiles_wrap_on_overflow() {
    let text = workspace_manifest();
    let release = profile(&text, "release").expect("the workspace must define [profile.release]");
    let dist = profile(&text, "dist").expect("the workspace must define [profile.dist]");
    assert_eq!(
        setting(dist, "inherits").as_deref(),
        Some("\"release\""),
        "[profile.dist] must inherit from release"
    );
    for (key, want) in [("overflow-checks", "false"), ("panic", "\"abort\"")] {
        assert_eq!(
            setting(release, key).as_deref(),
            Some(want),
            "[profile.release] must set {key} = {want}"
        );
        let effective = setting(dist, key).or_else(|| setting(release, key));
        assert_eq!(
            effective.as_deref(),
            Some(want),
            "[profile.dist] ships with {key} = {effective:?}, not {want}"
        );
    }
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
