// SPDX-License-Identifier: ISC
//! The nine ECDSA pairs of the RPC set give the verdicts the reference Go
//! gave on the frozen vectors of `tests/ecdsa_go` (ADR-0015, T4), with no
//! oracle: the known answers for P-521 and for SHA-512.  Wycheproof's
//! files in the tree cover six of the nine pairs, P-256, P-384 and P-521
//! with SHA-512 among them (`src/wycheproof_tests.rs`), and not P-256
//! with SHA-384 or P-521 with SHA-256 or SHA-384, for which Wycheproof
//! has no file.  `tests/go_differential.rs` asks Go for the same verdicts
//! again where an oracle runs.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

mod ecdsa_go;

use std::collections::BTreeMap;

/// Every frozen case gets Go's recorded verdict from the provider's
/// algorithm of its name, which is the one the RPC set lists for its pair;
/// each class shows on every pair, and Go took exactly the classes
/// `ecdsa_go::CLASSES` says it takes, so a file gone wrong cannot pass on
/// agreement alone.  The file's hash and count are checked as it is read.
#[test]
fn ecdsa_gives_gos_frozen_verdicts() {
    let mut classes: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut pairs: BTreeMap<String, usize> = BTreeMap::new();
    for case in ecdsa_go::cases() {
        let algorithm = ecdsa_go::by_name(&case.algorithm);
        let curve = &ecdsa_go::CURVES[case.curve];
        assert!(
            case.algorithm
                .starts_with(&format!("ECDSA_P{}_", curve.name.trim_start_matches("P-"))),
            "{}: the algorithm is of the key's curve",
            case.label
        );
        let ours = algorithm
            .verify_signature(&case.key, &case.message, &case.signature)
            .is_ok();
        assert_eq!(ours, case.go, "{}: Go's verdict", case.label);
        let counts = classes.entry(case.class.clone()).or_default();
        counts.0 += 1;
        counts.1 += usize::from(case.go);
        if case.class == "go-signature" {
            *pairs.entry(case.algorithm.clone()).or_default() += 1;
        }
    }
    for (class, taken) in ecdsa_go::CLASSES {
        let (count, go_took) = classes
            .get(class)
            .copied()
            .unwrap_or_else(|| panic!("{class}: no case"));
        let per_pair = match class {
            "go-signature" => 4,
            "another-hash" => 2,
            _ => 1,
        };
        assert_eq!(count, 9 * per_pair, "{class}: a case for each pair");
        assert_eq!(go_took, if taken { count } else { 0 }, "{class}: Go took");
    }
    assert_eq!(classes.len(), ecdsa_go::CLASSES.len(), "{classes:?}");
    assert_eq!(
        pairs.len(),
        9,
        "every pair has Go's own signatures: {pairs:?}"
    );
}
