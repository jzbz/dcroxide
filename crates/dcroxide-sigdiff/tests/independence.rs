// SPDX-License-Identifier: ISC
//! The inputs do not depend on the code under test: only `src/ours.rs`
//! names `dcroxide_dcrec`; only `src/run.rs` (and `src/canary.rs`, whose
//! canaries stand in for dcroxide) name the adapter; `src/lib.rs` only
//! declares it; and every other file under `src/` (generators, models, the
//! registry, the arithmetic, the encoders, the comparison, the digest)
//! names neither.  The files scanned must be exactly the ones the
//! fingerprint module classifies, so a new file cannot escape the check.

use std::collections::BTreeSet;
use std::path::Path;

use dcroxide_sigdiff::fingerprint::{all_sources, source_files};

/// The files allowed to call into the adapter.
const MAY_NAME_OURS: [&str; 2] = ["src/run.rs", "src/canary.rs"];

/// Whether `text` names the adapter module: a path through it (`ours::`,
/// `crate::ours`, `super::ours`) or a `use` that imports it.
fn names_ours(text: &str) -> bool {
    if text.contains("ours::") || text.contains("crate::ours") || text.contains("super::ours") {
        return true;
    }
    // Every `use` declaration, which may span lines, up to its `;`.
    let mut rest = text;
    while let Some(at) = rest.find("use ") {
        let before = &rest[..at];
        let starts_item = before
            .rsplit('\n')
            .next()
            .is_some_and(|line| matches!(line.trim(), "" | "pub" | "pub(crate)"));
        let after = &rest[at.saturating_add(4)..];
        let end = after.find(';').unwrap_or(after.len());
        if starts_item
            && after[..end]
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .any(|token| token == "ours")
        {
            return true;
        }
        rest = after;
    }
    false
}

#[test]
fn only_the_adapter_reaches_the_code_under_test() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = source_files(crate_dir).expect("read src/");
    let classified: BTreeSet<String> = all_sources().map(|s| s.path.to_owned()).collect();
    assert_eq!(
        files.iter().cloned().collect::<BTreeSet<_>>(),
        classified,
        "the files under src/ and the fingerprint lists differ"
    );
    for path in &files {
        let text = std::fs::read_to_string(crate_dir.join(path)).expect("read a source file");
        let names_dcrec = text.contains("dcroxide_dcrec");
        match path.as_str() {
            "src/ours.rs" => assert!(names_dcrec, "the adapter calls dcrec"),
            "src/lib.rs" => {
                assert!(!names_dcrec, "{path} names dcroxide_dcrec");
                assert!(
                    text.contains("\npub mod ours;\n"),
                    "lib.rs declares the adapter"
                );
                let without = text.replacen("\npub mod ours;\n", "\n", 1);
                assert!(
                    !names_ours(&without),
                    "lib.rs does more than declare the adapter"
                );
            }
            _ if MAY_NAME_OURS.contains(&path.as_str()) => {
                assert!(!names_dcrec, "{path} names dcroxide_dcrec");
            }
            _ => {
                assert!(!names_dcrec, "{path} names dcroxide_dcrec");
                assert!(!names_ours(&text), "{path} names the adapter");
            }
        }
    }
    assert!(
        names_ours(&std::fs::read_to_string(crate_dir.join("src/run.rs")).expect("read")),
        "the run loop calls the adapter"
    );
}

/// The detector finds each way of naming the adapter, and not words that
/// only contain it.
#[test]
fn the_detector_sees_every_form() {
    for text in [
        "let a = ours::answer(c, d);",
        "use crate::ours;",
        "use crate::{cmd, ours};",
        "use crate::{\n    cmd,\n    ours::answer,\n};",
        "pub use super::ours as adapter;",
        "x(crate::ours::answer)",
    ] {
        assert!(names_ours(text), "{text}");
    }
    for text in [
        "let ours = 1;",
        "use crate::answer::OursAnswer;",
        "fn f(ours: &[u8]) {}",
        "// the adapter, named in prose: ours",
        "because ours is computed, use the pipe; then answer",
    ] {
        assert!(!names_ours(text), "{text}");
    }
}
