// SPDX-License-Identifier: ISC
//! Durability is asserted here, not inherited from whatever the storage
//! engine happens to default to.
//!
//! redb defaults to `Durability::Immediate`, so today setting it
//! explicitly changes no behaviour. That is exactly why this test exists:
//! a property that matters only when it is absent, and that currently
//! holds by luck, is the kind that disappears without a diff to point at.
//!
//! The concrete case is in [ADR-0009]. The engine measured as a
//! replacement, fjall, defaults the *other* way: `Database::batch()` hands
//! back `PersistMode::Buffer`, whose `commit()` returns `Ok` having called
//! no fsync at all. A port relying on an inherited default would have gone
//! silently non-durable on the day it switched engines, and the commit
//! doing it would have looked like a dependency bump. ADR-0009 makes
//! "durability enforced at the wrapper boundary, so no call site can
//! construct a non-durable commit" a condition on any such change; this
//! file is what makes that checkable rather than aspirational.
//!
//! What durability buys: `Chain::flush` writes block index rows, UTXO
//! entries and both state markers in one transaction so a crash cannot
//! leave them disagreeing. That guarantee is worth nothing if the commit
//! was never durable — the node would believe state a restart does not
//! have.
//!
//! [ADR-0009]: ../../../docs/adr/0009-storage-shape.md

use std::path::Path;

/// Every write transaction must be opened by `begin_durable_write`.
///
/// Scanning the source is crude, and it is the only check that actually
/// encodes "no call site can construct a non-durable commit" — a runtime
/// test can only observe the transactions a test happens to create, never
/// the one someone adds next year.
#[test]
fn only_the_durable_helper_opens_a_write_transaction() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    let mut offenders = Vec::new();
    let mut helper_seen = false;
    let mut stack = vec![src.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if entry.file_type().expect("file type").is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read source");
            for (n, line) in text.lines().enumerate() {
                if !line.contains(".begin_write()") {
                    continue;
                }
                // The one sanctioned call lives in the helper, which is
                // recognised by the `set_durability` two lines below it
                // rather than by the function name, so renaming the
                // function cannot quietly widen the exemption.
                let is_helper = text
                    .lines()
                    .skip(n)
                    .take(6)
                    .any(|l| l.contains("set_durability"));
                if is_helper {
                    helper_seen = true;
                } else {
                    offenders.push(format!(
                        "{}:{}: {}",
                        path.file_name().unwrap_or_default().to_string_lossy(),
                        n + 1,
                        line.trim()
                    ));
                }
            }
        }
    }

    assert!(
        helper_seen,
        "no `begin_write()` followed by `set_durability` was found in \
         dcroxide-database/src -- the durable helper has been removed or \
         renamed past recognition, and with it the guarantee that every \
         commit reaches disk"
    );
    assert!(
        offenders.is_empty(),
        "these call sites open a write transaction without setting durability \
         explicitly, so they inherit whatever the engine defaults to (fjall's \
         default fsyncs nothing): {offenders:#?}\n\nRoute them through \
         `begin_durable_write` instead."
    );
}

/// The helper must ask for the strongest durability the engine offers,
/// not merely *a* durability.
///
/// Split from the test above because the two fail for different reasons
/// and want different fixes: that one catches a new call site, this one
/// catches someone weakening the setting in the one place it is made.
#[test]
fn the_durable_helper_asks_for_immediate_durability() {
    let lib = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("lib.rs");
    let text = std::fs::read_to_string(&lib).expect("read lib.rs");
    assert!(
        text.contains("set_durability(redb::Durability::Immediate)"),
        "the write-transaction helper must request Durability::Immediate; \
         redb's other level, Durability::None, does not persist until a \
         later Immediate commit, which would make a returned Ok a promise \
         the store has not kept"
    );
}
