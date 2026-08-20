// SPDX-License-Identifier: ISC
//! The map-typed command parameters are reachable, and decode in linear
//! time through the real registry (RVW-016).
//!
//! `crates/dcroxide-dcrjson/tests/gojson_maps.rs` pins the decoder
//! itself.  This pins the reachability half: `createrawtransaction`'s
//! `Amounts` and `createrawsstx`'s `Amount` are `map[string]` parameters
//! that carry an attacker-chosen number of keys straight into that
//! decoder, and both methods are callable with limited credentials.
//! Without these the coverage would silently lapse if either parameter
//! were ever re-typed.

// Test-harness arithmetic over bounded key counts.
#![allow(clippy::arithmetic_side_effects)]

use std::time::Instant;

use dcroxide_dcrjson::Registry;
use dcroxide_rpctypes::{method, register_all};

/// `{"k000000000000":1.5, ...}` — equal-length keys so the pre-fix
/// rescan cannot short-circuit on a length mismatch.
fn wide_amounts(keys: usize, value: &str) -> String {
    let mut doc = String::with_capacity(keys * 24);
    doc.push('{');
    for i in 0..keys {
        if i > 0 {
            doc.push(',');
        }
        doc.push_str(&format!("\"k{i:012}\":{value}"));
    }
    doc.push('}');
    doc
}

fn registry() -> Registry {
    let mut registry = Registry::new();
    register_all(&mut registry);
    registry
}

#[test]
fn createrawtransaction_amounts_decodes_in_linear_time() {
    let registry = registry();
    let amounts = wide_amounts(100_000, "1.5");
    let params = ["[]", amounts.as_str()];

    let start = Instant::now();
    dcroxide_dcrjson::parse_params(&registry, &method("createrawtransaction"), &params)
        .expect("a wide Amounts map parses");
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs() < 5,
        "createrawtransaction with 100000 amounts took {elapsed:?}; \
         the per-key rescan is reachable again",
    );
}

#[test]
fn createrawsstx_amount_decodes_in_linear_time() {
    let registry = registry();
    let amounts = wide_amounts(100_000, "1");
    let params = ["[]", amounts.as_str(), "[]"];

    let start = Instant::now();
    dcroxide_dcrjson::parse_params(&registry, &method("createrawsstx"), &params)
        .expect("a wide Amount map parses");
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs() < 5,
        "createrawsstx with 100000 amounts took {elapsed:?}; \
         the per-key rescan is reachable again",
    );
}
