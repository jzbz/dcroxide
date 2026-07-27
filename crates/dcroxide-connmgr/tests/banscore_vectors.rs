// SPDX-License-Identifier: ISC
//! Differential replay of dcrd `internal/connmgr` `dynamicbanscore.go`
//! vectors, dumped by a throwaway in-package exporter run inside the
//! dcrd clone at master 452c1a6c (the 2.2 parity target).
//!
//! `decay` rows cover the whole reachable input domain of the ban score
//! decay — one row per age 0..=1800 — carrying the decay factor's exact
//! IEEE-754 bit pattern.  Go dispatches `math.Exp` to hand-written
//! assembly on amd64, arm64, loong64 and s390x, and that assembly
//! differs from Go's portable implementation by one ulp on 276 of these
//! 1801 ages, so dcrd's own decayed scores are platform-dependent
//! (QK-0006).  The port follows the portable Go source as the
//! specification, so these rows were emitted from a verbatim copy of
//! Go's portable `exp`/`expmulti`/`ldexp`, cross-checked by running the
//! same exporter compiled for GOARCH=386 — an architecture with no
//! assembly `Exp`, where Go's own `math.Exp` is the portable code — and
//! confirming a byte-identical file.
//!
//! `banscore` rows replay dcrd's own `increase`/`int`/`String`/`Reset`
//! at chosen instants.  Those go through `math.Exp` and so through the
//! platform assembly, and are therefore confined to decay ages where
//! assembly and portable agree (0, 1, 60, 600, 1800), which the
//! byte-identical amd64/386 exporter runs also confirm.

// Test scaffolding uses bounded counters and mock plumbing.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_connmgr::{DynamicBanScore, decay_factor_bits};
use dcroxide_testutil::unhex;
use std::collections::HashMap;

const VECTORS: &str = include_str!("data/banscore_vectors.txt");

fn utf8(hex: &str) -> String {
    String::from_utf8(unhex(hex)).expect("utf8 payload")
}

/// The `banscore` rows keyed by label.
fn banscore_rows() -> HashMap<String, String> {
    let mut expected: HashMap<String, String> = HashMap::new();
    for line in VECTORS.lines() {
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('|').collect();
        if parts[0] == "banscore" {
            assert_eq!(parts.len(), 3, "{line}");
            let prev = expected.insert(parts[1].to_string(), parts[2].to_string());
            assert!(prev.is_none(), "duplicate banscore label in {line}");
        }
    }
    expected
}

#[test]
fn banscore_vectors() {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for line in VECTORS.lines() {
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('|').collect();
        *counts.entry(parts[0]).or_insert(0) += 1;
        match parts[0] {
            // The decay factor for one age, bit for bit.
            "decay" => {
                assert_eq!(parts.len(), 3, "{line}");
                let age: i64 = parts[1].parse().expect("age");
                let want = u64::from_str_radix(parts[2], 16).expect("decay bits");
                assert_eq!(decay_factor_bits(age), want, "{line}");
            }
            // Replayed as whole stateful sequences in
            // `banscore_sequences`; counted here.
            "banscore" => {}
            other => panic!("unknown vector op {other}"),
        }
    }

    let expected: &[(&str, usize)] = &[("decay", 1801), ("banscore", 21)];
    for (op, want) in expected {
        assert_eq!(counts.get(op), Some(want), "row count for {op}");
    }
    assert_eq!(counts.len(), expected.len(), "unexpected ops present");

    // The whole domain is present exactly once, in order.
    let ages: Vec<i64> = VECTORS
        .lines()
        .filter(|l| l.starts_with("decay|"))
        .map(|l| {
            l.split('|')
                .nth(1)
                .expect("age field")
                .parse()
                .expect("age")
        })
        .collect();
    assert!(
        ages.iter().copied().eq(0..=1800),
        "decay rows must cover ages 0..=1800 in order"
    );
}

/// The ban score sequences replay dcrd's unexported `increase`/`int`
/// methods (the ones its exported API calls with the wall clock) at the
/// same instants the exporter used.
#[test]
fn banscore_sequences() {
    let expected = banscore_rows();
    let want = |label: &str| -> u32 {
        expected
            .get(label)
            .unwrap_or_else(|| panic!("missing banscore row {label}"))
            .parse()
            .expect("score")
    };

    let base = 1_700_000_000i64;

    // Sequence 1: transient accumulation with decay between events.
    let mut s1 = DynamicBanScore::new();
    assert_eq!(s1.int_at(base), want("fresh-int"));
    assert_eq!(s1.increase_at(10, 50, base), want("inc1"));
    assert_eq!(s1.int_at(base), want("int-same"));
    assert_eq!(s1.int_at(base + 1), want("int-1"));
    assert_eq!(s1.int_at(base + 60), want("int-60"));
    assert_eq!(s1.int_at(base + 600), want("int-600"));
    assert_eq!(s1.int_at(base + 1800), want("int-1800"));
    // Past the lifetime and before lastUnix both short-circuit to the
    // persistent component.
    assert_eq!(s1.int_at(base + 1801), want("int-1801"));
    assert_eq!(s1.int_at(base - 5), want("int-neg"));
    assert_eq!(s1.increase_at(0, 100, base + 60), want("inc2"));
    assert_eq!(s1.int_at(base + 120), want("int-after"));
    assert_eq!(s1.to_string_at(base + 120), utf8(&expected["str"]));

    // Sequence 2: persistent-only increases never decay, and the
    // persistent component wraps like Go's uint32.
    let mut s2 = DynamicBanScore::new();
    assert_eq!(s2.increase_at(25, 0, base), want("p-inc"));
    assert_eq!(s2.int_at(base + 5000), want("p-int"));
    assert_eq!(s2.increase_at(4294967295, 0, base), want("p-inc2"));
    assert_eq!(s2.int_at(base), want("p-int2"));

    // Sequence 3: transient expiry after the lifetime, and the
    // transient<1 short circuit.
    let mut s3 = DynamicBanScore::new();
    s3.increase_at(0, 100, base);
    assert_eq!(s3.increase_at(0, 40, base + 1801), want("life-inc"));
    assert_eq!(s3.int_at(base + 1801), want("life-int"));
    let mut s4 = DynamicBanScore::new();
    s4.increase_at(0, 1, base);
    assert_eq!(s4.int_at(base + 600), want("tiny-int"));
    assert_eq!(s4.int_at(base + 1), want("tiny-int2"));

    // Sequence 4: reset.
    let mut s5 = DynamicBanScore::new();
    s5.increase_at(500, 500, base);
    s5.reset();
    assert_eq!(s5.int_at(base + 1), want("reset-int"));
}
