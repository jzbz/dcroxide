// SPDX-License-Identifier: ISC
//! dcrd's proof-of-work test vectors, ported from blockchain/standalone
//! `pow_test.go` at the pinned tag, including the DCP0011 ASERT
//! reference vectors (`data/asert_test_vectors.json`, copied verbatim
//! from dcrd's testdata).

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use core::str::FromStr;

use dcroxide_chainhash::Hash;
use dcroxide_standalone as standalone;
use standalone::{BigInt, ErrorKind};

fn big_hex(s: &str) -> BigInt {
    let (sign, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let digits = digits.strip_prefix("0x").unwrap_or(digits);
    let n = BigInt::parse_bytes(digits.as_bytes(), 16).expect("valid hex big int");
    if sign { -n } else { n }
}

fn big_dec(s: &str) -> BigInt {
    BigInt::parse_bytes(s.as_bytes(), 10).expect("valid decimal big int")
}

/// The mainnet proof of work limit, matching dcrd's mockMainNetPowLimit.
fn mock_mainnet_pow_limit() -> BigInt {
    big_hex("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
}

/// dcrd TestHashToBig.
#[test]
fn hash_to_big_vectors() {
    for s in [
        "000000000000437482b6d47f82f374cde539440ddb108b0a76886f0d87d126b9",
        "000000000000c41019872ff7db8fd2e9bfa05f42d3f8fee8e895e8c1e5b8dcba",
    ] {
        let hash = Hash::from_str(s).expect("valid hash");
        assert_eq!(standalone::hash_to_big(&hash), big_hex(s), "{s}");
    }
}

/// dcrd TestBigToCompact, including the negative-value quirks.
#[test]
fn big_to_compact_vectors() {
    let tests: &[(&str, &str, u32)] = &[
        (
            "mainnet block 1",
            "0x000000000001ffff000000000000000000000000000000000000000000000000",
            0x1b01ffff,
        ),
        (
            "mainnet block 288",
            "0x000000000001330e000000000000000000000000000000000000000000000000",
            0x1b01330e,
        ),
        (
            "higher diff",
            "0x00000000000000005fb28a000000000000000000000000000000000000000000",
            0x185fb28a,
        ),
        ("zero", "0", 0),
        ("-1", "-1", 0x1810000),
        ("-128", "-80", 0x2808000),
        ("-32768", "-8000", 0x3808000),
        ("-8388608", "-800000", 0x4808000),
    ];
    for (name, input, want) in tests {
        assert_eq!(standalone::big_to_compact(&big_hex(input)), *want, "{name}");
    }
}

/// dcrd TestCompactToBig.
#[test]
fn compact_to_big_vectors() {
    let tests: &[(&str, u32, &str)] = &[
        (
            "mainnet block 1",
            0x1b01ffff,
            "0x000000000001ffff000000000000000000000000000000000000000000000000",
        ),
        (
            "mainnet block 288",
            0x1b01330e,
            "0x000000000001330e000000000000000000000000000000000000000000000000",
        ),
        (
            "higher diff",
            0x185fb28a,
            "0x00000000000000005fb28a000000000000000000000000000000000000000000",
        ),
        ("zero", 0, "0"),
        ("-1", 0x1810000, "-1"),
        ("-128", 0x2808000, "-80"),
        ("-32768", 0x3808000, "-8000"),
        ("-8388608", 0x4808000, "-800000"),
    ];
    for (name, input, want) in tests {
        assert_eq!(standalone::compact_to_big(*input), big_hex(want), "{name}");
    }
}

/// dcrd TestCalcWork.
#[test]
fn calc_work_vectors() {
    let tests: &[(&str, u32, &str)] = &[
        (
            "mainnet block 1",
            0x1b01ffff,
            "0x0000000000000000000000000000000000000000000000000000800040002000",
        ),
        (
            "mainnet block 288",
            0x1b01330e,
            "0x0000000000000000000000000000000000000000000000000000d56f2dcbe105",
        ),
        (
            "higher diff (exponent 24)",
            0x185fb28a,
            "0x000000000000000000000000000000000000000000000002acd33ddd458512da",
        ),
        ("zero", 0, "0"),
        ("negative target difficulty", 0x1810000, "0"),
    ];
    for (name, input, want) in tests {
        assert_eq!(standalone::calc_work(*input), big_hex(want), "{name}");
    }
}

/// dcrd TestCheckProofOfWorkRange.
#[test]
fn check_proof_of_work_range_vectors() {
    let tests: &[(&str, u32, Option<ErrorKind>)] = &[
        ("mainnet block 1", 0x1b01ffff, None),
        ("mainnet block 288", 0x1b01330e, None),
        ("smallest allowed", 0x1010000, None),
        ("max allowed (exactly the pow limit)", 0x1d00ffff, None),
        ("zero", 0, Some(ErrorKind::UnexpectedDifficulty)),
        ("negative", 0x1810000, Some(ErrorKind::UnexpectedDifficulty)),
        (
            "pow limit + 1",
            0x1d010000,
            Some(ErrorKind::UnexpectedDifficulty),
        ),
    ];
    let pow_limit = mock_mainnet_pow_limit();
    for (name, bits, want) in tests {
        let got = standalone::check_proof_of_work_range(*bits, &pow_limit);
        assert_eq!(got.err().map(|e| e.kind), *want, "{name}");
    }
}

/// dcrd TestCheckProofOfWorkHash.
#[test]
fn check_proof_of_work_hash_vectors() {
    let tests: &[(&str, &str, u32, Option<ErrorKind>)] = &[
        (
            "mainnet block 1 pow hash",
            "000000000000437482b6d47f82f374cde539440ddb108b0a76886f0d87d126b9",
            0x1b01ffff,
            None,
        ),
        (
            "mainnet block 288 pow hash",
            "000000000000e0ab546b8fc19f6d94054d47ffa5fe79e17611d170662c8b702b",
            0x1b01330e,
            None,
        ),
        (
            "high hash",
            "000000000001ffff000000000000000000000000000000000000000000000001",
            0x1b01ffff,
            Some(ErrorKind::HighHash),
        ),
    ];
    for (name, hash, bits, want) in tests {
        let hash = Hash::from_str(hash).expect("valid hash");
        let got = standalone::check_proof_of_work_hash(&hash, *bits);
        assert_eq!(got.err().map(|e| e.kind), *want, "{name}");
    }
}

/// dcrd TestCheckProofOfWork.
#[test]
fn check_proof_of_work_vectors() {
    let tests: &[(&str, &str, u32, Option<ErrorKind>)] = &[
        (
            "mainnet block 1 pow hash",
            "000000000000437482b6d47f82f374cde539440ddb108b0a76886f0d87d126b9",
            0x1b01ffff,
            None,
        ),
        (
            "mainnet block 288 pow hash",
            "000000000000e0ab546b8fc19f6d94054d47ffa5fe79e17611d170662c8b702b",
            0x1b01330e,
            None,
        ),
        (
            "max allowed (exactly the pow limit)",
            "0000000000001ffff00000000000000000000000000000000000000000000000",
            0x1b01ffff,
            None,
        ),
        (
            "high hash (pow limit + 1)",
            "000000000001ffff000000000000000000000000000000000000000000000001",
            0x1b01ffff,
            Some(ErrorKind::HighHash),
        ),
        (
            "hash satisfies target, but target too high at pow limit + 1",
            "0000000000000000000000000000000000000000000000000000000000000001",
            0x1d010000,
            Some(ErrorKind::UnexpectedDifficulty),
        ),
        (
            "zero target difficulty",
            "0000000000000000000000000000000000000000000000000000000000000001",
            0,
            Some(ErrorKind::UnexpectedDifficulty),
        ),
        (
            "negative target difficulty",
            "0000000000000000000000000000000000000000000000000000000000000001",
            0x1810000,
            Some(ErrorKind::UnexpectedDifficulty),
        ),
    ];
    let pow_limit = mock_mainnet_pow_limit();
    for (name, hash, bits, want) in tests {
        let hash = Hash::from_str(hash).expect("valid hash");
        let got = standalone::check_proof_of_work(&hash, *bits, &pow_limit);
        assert_eq!(got.err().map(|e| e.kind), *want, "{name}");
    }
}

/// dcrd TestCalcASERTDiff: replay the DCP0011 reference test vectors.
#[test]
fn calc_asert_diff_vectors() {
    let data = include_str!("data/asert_test_vectors.json");
    let root: serde_json::Value = serde_json::from_str(data).expect("valid JSON");

    let params = root["params"].as_object().expect("params object");
    let scenarios = root["scenarios"].as_array().expect("scenarios array");
    assert!(!scenarios.is_empty(), "no test scenarios found");

    for scenario in scenarios {
        let desc = scenario["description"].as_str().expect("description");
        let tests = scenario["tests"].as_array().expect("tests array");
        assert!(!tests.is_empty(), "{desc}: no test cases found");

        let net = &params[scenario["params"].as_str().expect("params key")];
        let pow_limit = big_hex(net["powLimit"].as_str().expect("powLimit"));
        let target_secs = net["targetSecsPerBlock"].as_i64().expect("target secs");
        let half_life = net["halfLifeSecs"].as_i64().expect("half life");

        let start_diff_bits = scenario["startDiffBits"].as_u64().expect("bits") as u32;
        let start_height = scenario["startHeight"].as_i64().expect("start height");
        let start_time = scenario["startTime"].as_i64().expect("start time");

        for test in tests {
            let height = test["height"].as_u64().expect("height");
            let timestamp = test["timestamp"].as_i64().expect("timestamp");
            let want = test["expectedDiffBits"].as_u64().expect("want bits") as u32;

            let height_delta = (height as i64).wrapping_sub(start_height);
            let time_delta = timestamp - start_time;
            let got = standalone::calc_asert_diff(
                start_diff_bits,
                &pow_limit,
                target_secs,
                time_delta,
                height_delta,
                half_life,
            );
            assert_eq!(got, want, "{desc}@height {height}");
        }
    }
}

/// dcrd TestCalcASERTDiffPanics.
#[test]
fn calc_asert_diff_panics() {
    const START_DIFF_BITS: u32 = 0x1b00a5a6;
    const POW_LIMIT_BITS: u32 = 0x1d00ffff;
    const TARGET_SECS_PER_BLOCK: i64 = 300;
    const HALF_LIFE_SECS: i64 = 43200;
    let pow_limit = standalone::compact_to_big(POW_LIMIT_BITS);

    // Invalid starting target difficulty of 0.
    let limit = pow_limit.clone();
    assert!(
        std::panic::catch_unwind(move || {
            standalone::calc_asert_diff(0, &limit, TARGET_SECS_PER_BLOCK, 0, 0, HALF_LIFE_SECS)
        })
        .is_err()
    );

    // Starting target difficulty greater than the proof of work limit.
    let limit = pow_limit.clone();
    assert!(
        std::panic::catch_unwind(move || {
            standalone::calc_asert_diff(
                POW_LIMIT_BITS + 1,
                &limit,
                TARGET_SECS_PER_BLOCK,
                0,
                0,
                HALF_LIFE_SECS,
            )
        })
        .is_err()
    );

    // Negative height delta.
    assert!(
        std::panic::catch_unwind(move || {
            standalone::calc_asert_diff(
                START_DIFF_BITS,
                &pow_limit,
                TARGET_SECS_PER_BLOCK,
                0,
                -1,
                HALF_LIFE_SECS,
            )
        })
        .is_err()
    );
}

/// The work-vector decimal helper is exercised for the dump differential;
/// keep a smoke test of its Go-string parity here.
#[test]
fn big_to_string_matches_go() {
    assert_eq!(standalone::big_to_string(&big_dec("-12345")), "-12345");
    assert_eq!(standalone::big_to_string(&BigInt::from(0)), "0");
}
