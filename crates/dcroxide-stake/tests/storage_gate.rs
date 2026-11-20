// SPDX-License-Identifier: ISC
//! Whether the build under test compiled this crate with its `storage`
//! feature, checked against what the caller asked for.
//!
//! Cargo compiles one copy of the crate per build, with the union of
//! the features every package in that build asks for, dev-dependencies
//! included whenever test targets are built.  A dev-dependency of
//! `dcroxide-gcs`, `dcroxide-fees` or `dcroxide-rpc` that takes this
//! crate with its defaults would therefore turn `storage` back on in
//! CI's storage-gate job, whose `cargo test --no-default-features` would
//! then test the node's configuration while reporting the wallet's.
//! This target is built into that same invocation, so it sees the
//! features that invocation actually resolved.
//!
//! `DCROXIDE_STAKE_EXPECT_STORAGE` set to `0` or `1` makes the test
//! fail unless the feature is off or on, respectively; the storage-gate
//! job sets `0`.  Unset, the test checks nothing, so an ordinary
//! `cargo test` in either configuration passes.

/// The variable that names the expected configuration.
const EXPECT: &str = "DCROXIDE_STAKE_EXPECT_STORAGE";

/// The feature is off or on exactly as the caller asked.
#[test]
fn storage_feature_is_what_the_caller_expects() {
    let Some(expect) = std::env::var_os(EXPECT) else {
        return;
    };
    let want = match expect.to_str() {
        Some("0") => false,
        Some("1") => true,
        _ => panic!("{EXPECT} must be 0 or 1, not {expect:?}"),
    };
    let built = cfg!(feature = "storage");
    let (with, turned) = if built {
        ("with", "on")
    } else {
        ("without", "off")
    };
    assert_eq!(
        built,
        want,
        "dcroxide-stake was compiled {with} its `storage` feature, but {EXPECT}={}: \
         some package in this build turned the feature {turned} (a dev-dependency \
         taking dcroxide-stake with default features turns it on)",
        u8::from(want),
    );
}
