// SPDX-License-Identifier: ISC
//! Map decoding is linear in the number of keys (RVW-016).
//!
//! Go's `encoding/json` decodes an object into a map with one hash
//! insert per key, so a duplicate key costs no more than a fresh one.
//! The port kept its entries in a `Vec` and rescanned it for every key,
//! which is quadratic: an 8 MiB body of distinct keys — the size
//! `createrawtransaction` and `createrawsstx` accept, both reachable
//! with limited credentials — turned into minutes of CPU.
//!
//! The observable semantics must not move with the index: Go keeps the
//! last value for a repeated key, and this port keeps first-seen order
//! because `GoValue` equality and the raw-transaction handlers can see
//! it.  Those are pinned here too, because they are exactly what the
//! fix itself is liable to break.

use std::time::Instant;

use dcroxide_dcrjson::{GoType, GoValue, gojson};

fn amount_map() -> GoType {
    GoType::Map(Box::new(GoType::String), Box::new(GoType::Float64))
}

fn entries(v: &GoValue) -> &Vec<(String, GoValue)> {
    match v {
        GoValue::Map(entries) => entries,
        other => panic!("expected a map, got {other:?}"),
    }
}

/// The discriminator.  Pre-fix this is quadratic and runs for tens of
/// seconds; post-fix it is a fraction of one.  The bound is far enough
/// from both to be immune to a slow machine.
///
/// The keys are equal-length on purpose: mixed lengths let the string
/// comparison short-circuit on the length check and would understate the
/// rescan cost.
#[test]
fn a_wide_object_decodes_in_linear_time() {
    const KEYS: usize = 100_000;
    let mut doc = String::with_capacity(KEYS * 24);
    doc.push('{');
    for i in 0..KEYS {
        if i > 0 {
            doc.push(',');
        }
        doc.push_str(&format!("\"k{i:012}\":1.5"));
    }
    doc.push('}');

    let start = Instant::now();
    let decoded = gojson::decode(&amount_map(), &doc).expect("a wide object decodes");
    let elapsed = start.elapsed();

    assert_eq!(entries(&decoded).len(), KEYS);
    assert!(
        elapsed.as_secs() < 5,
        "decoding {KEYS} keys took {elapsed:?}; the per-key rescan is back",
    );
}

/// Go keeps the last value for a repeated key; this port keeps the
/// entry in the slot where the key was first seen.  Passes before and
/// after the fix by design — it guards the fix, not the defect.  Record
/// the index one slot late and this panics out of bounds; swap the
/// vector for a `HashMap` or `BTreeMap` and the order assertion fails.
#[test]
fn a_repeated_key_takes_the_last_value_in_its_first_slot() {
    let decoded = gojson::decode(
        &amount_map(),
        r#"{"b":1.0,"a":2.0,"b":3.0,"c":4.0,"a":5.0}"#,
    )
    .expect("duplicate keys are legal JSON");

    let got: Vec<(&str, f64)> = entries(&decoded)
        .iter()
        .map(|(k, v)| {
            let f = match v {
                GoValue::Float64(f) => *f,
                other => panic!("expected a float, got {other:?}"),
            };
            (k.as_str(), f)
        })
        .collect();

    assert_eq!(got, vec![("b", 3.0), ("a", 5.0), ("c", 4.0)]);
}

/// The degenerate shapes the index has to survive.
#[test]
fn empty_and_single_key_objects_decode() {
    assert!(entries(&gojson::decode(&amount_map(), "{}").expect("empty")).is_empty());

    let one = gojson::decode(&amount_map(), r#"{"only":0.25}"#).expect("one key");
    assert_eq!(entries(&one).len(), 1);
    assert_eq!(entries(&one)[0].0, "only");
}

/// One key repeated many times must stay one entry — and must not cost
/// what the distinct-key case used to.
#[test]
fn one_key_repeated_collapses_to_a_single_entry() {
    const REPEATS: usize = 50_000;
    let mut doc = String::from("{");
    for i in 0..REPEATS {
        if i > 0 {
            doc.push(',');
        }
        doc.push_str(&format!("\"dup\":{i}.0"));
    }
    doc.push('}');

    let decoded = gojson::decode(&amount_map(), &doc).expect("repeated key decodes");
    assert_eq!(entries(&decoded).len(), 1);
    assert_eq!(entries(&decoded)[0].0, "dup");
}
