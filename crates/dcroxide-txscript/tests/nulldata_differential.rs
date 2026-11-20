// SPDX-License-Identifier: ISC
//! `stdscript::is_null_data_script`, the version-taking null data check
//! (dcrd `stdscript.IsNullDataScript`), against dcrd: the upstream cases
//! (`stdscript/scriptv0_test.go:466-538`, run under `script_test.go`'s
//! `testIsX` rule that version 9999 is never null data), a live
//! differential over scripts built around the null data shape through the
//! oracle's `stdscript_is_null_data`, and a frozen battery of dcrd's
//! answers (`data/nulldata_vectors.txt`, line count and BLAKE-256 digest
//! pinned) that needs no Go.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_crypto::blake256;
use dcroxide_testutil::{Oracle, SplitMix64, hex, oracle_or_skip, unhex};
use dcroxide_txscript::stdscript::{is_null_data_script, is_null_data_script_v0};

/// The committed battery.
const COMMITTED: &str = include_str!("data/nulldata_vectors.txt");

/// The number of cases in the battery.
const COMMITTED_CASES: usize = 600;

/// The battery's BLAKE-256 digest; regenerate it with the file through
/// `committed_nulldata_vectors_regenerate`.
const COMMITTED_DIGEST: &str = "ece5e05b4ab178351d4a1239eb94e05b38d1bbb92e1183c0ad06dbbbaf113f67";

/// OP_RETURN.
const RETURN: u8 = 0x6a;

/// The upstream cases: (name, script, whether version 0 calls it null
/// data).
fn upstream_cases() -> Vec<(&'static str, Vec<u8>, bool)> {
    let data60 = unhex(
        "046708afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef3\
         046708afdb0fe5548271967f1a67130b7105cd6a",
    );
    let data12 = unhex("046708afdb0fe5548271967f");
    let cat = |parts: &[&[u8]]| parts.concat();
    vec![
        (
            "almost v0 nulldata -- NOP instead of data push",
            vec![RETURN, 0x61],
            false,
        ),
        (
            "almost v0 nulldata -- non-canonical small int push (DATA_1 vs 12)",
            vec![RETURN, 0x01, 0x0c],
            false,
        ),
        (
            "almost v0 nulldata -- non-canonical small int push (PUSHDATA1 vs 12)",
            vec![RETURN, 0x4c, 0x01, 0x0c],
            false,
        ),
        (
            "almost v0 nulldata -- non-canonical 60-byte push (PUSHDATA1 vs DATA_60)",
            cat(&[&[RETURN, 0x4c, 0x3c], &data60]),
            false,
        ),
        (
            "almost v0 nulldata -- non-canonical 12-byte push (PUSHDATA2)",
            cat(&[&[RETURN, 0x4d, 0x0c, 0x00], &data12]),
            false,
        ),
        (
            "almost v0 nulldata -- non-canonical 12-byte push (PUSHDATA4)",
            cat(&[&[RETURN, 0x4e, 0x0c, 0x00, 0x00, 0x00], &data12]),
            false,
        ),
        (
            "almost v0 nulldata -- exceeds max standard push",
            cat(&[&[RETURN, 0x4d, 0x01, 0x01], &[0x01; 257]]),
            false,
        ),
        (
            "almost v0 nulldata -- trailing opcode",
            vec![RETURN, 0x54, 0x51],
            false,
        ),
        ("v0 nulldata no data push", vec![RETURN], true),
        ("v0 nulldata single zero push", vec![RETURN, 0x00], true),
        ("v0 nulldata small int push", vec![RETURN, 0x51], true),
        ("v0 nulldata max small int push", vec![RETURN, 0x60], true),
        (
            "v0 nulldata small data push",
            cat(&[&[RETURN, 0x08], &unhex("046708afdb0fe554")]),
            true,
        ),
        (
            "v0 nulldata 60-byte push",
            cat(&[&[RETURN, 0x3c], &data60]),
            true,
        ),
        (
            "v0 nulldata max standard push",
            cat(&[&[RETURN, 0x4d, 0x00, 0x01], &[0x01; 256]]),
            true,
        ),
    ]
}

/// The upstream table, with `testIsX`'s rule that an unsupported version
/// (9999) is never null data, and the version 0 form agreeing with the
/// dedicated version 0 function.
#[test]
fn upstream_null_data_cases() {
    for (name, script, want) in upstream_cases() {
        assert_eq!(is_null_data_script(0, &script), want, "{name}");
        assert_eq!(is_null_data_script_v0(&script), want, "{name}");
        assert!(!is_null_data_script(9999, &script), "{name}: version 9999");
    }
}

/// Every version but 0 is refused, whatever the script; version 0 is the
/// version 0 function, on the scripts the generator builds.
#[test]
fn only_version_0_is_null_data() {
    let mut rng = SplitMix64::from_entropy("nulldata versions");
    for _ in 0..5_000 {
        let script = nulldata_like(&mut rng);
        let version = rng.next_u64() as u16;
        assert_eq!(
            is_null_data_script(version, &script),
            version == 0 && is_null_data_script_v0(&script),
            "version {version} script {}",
            hex(&script)
        );
    }
    for version in [1u16, 2, 0x8000, u16::MAX] {
        assert!(!is_null_data_script(version, &[RETURN]));
    }
}

/// A script built around the null data shape: `OP_RETURN` alone, then a
/// small integer, a direct push, or a `PUSHDATA1`/`2`/`4` push of a length
/// on either side of the 256-byte carrier limit and of the canonical
/// boundaries, or random bytes; sometimes with a trailing byte, or with
/// its last byte cut off.
fn nulldata_like(rng: &mut SplitMix64) -> Vec<u8> {
    fn data(rng: &mut SplitMix64, len: usize) -> Vec<u8> {
        let mut d = vec![0u8; len];
        rng.fill(&mut d);
        d
    }
    let mut s = match rng.below(9) {
        0 => vec![RETURN],
        1 => vec![
            RETURN,
            [0x00, 0x4f, 0x51, 0x58, 0x60, 0x61][rng.below(6) as usize],
        ],
        2 => {
            let len = 1 + rng.below(75) as usize;
            let mut s = vec![RETURN, len as u8];
            let mut d = data(rng, len);
            if len == 1 && rng.below(2) == 0 {
                // A one-byte push of a value a small-integer opcode
                // pushes canonically.
                d[0] = rng.below(17) as u8;
            }
            s.extend_from_slice(&d);
            s
        }
        3 => {
            let len = [0, 1, 75, 76, 255][rng.below(5) as usize];
            let mut s = vec![RETURN, 0x4c, len as u8];
            s.extend_from_slice(&data(rng, len));
            s
        }
        4 => {
            let len = [0usize, 75, 76, 255, 256, 257, 300][rng.below(7) as usize];
            let mut s = vec![RETURN, 0x4d];
            s.extend_from_slice(&(len as u16).to_le_bytes());
            s.extend_from_slice(&data(rng, len));
            s
        }
        5 => {
            let len = [0usize, 12, 256, 257, 65536][rng.below(5) as usize];
            let mut s = vec![RETURN, 0x4e];
            s.extend_from_slice(&(len as u32).to_le_bytes());
            s.extend_from_slice(&data(rng, len.min(1024)));
            s
        }
        6 => {
            let mut s = vec![RETURN];
            s.extend_from_slice(&rng.bytes(12));
            s
        }
        7 => rng.bytes(8),
        _ => vec![],
    };
    match rng.below(8) {
        0 => s.push(rng.next_u64() as u8),
        1 => {
            s.pop();
        }
        _ => {}
    }
    s
}

/// A script version: 0 most of the time, else an edge or a random one.
fn random_version(rng: &mut SplitMix64) -> u16 {
    match rng.below(10) {
        0 => [1, 2, 9999, u16::MAX][rng.below(4) as usize],
        1 => rng.next_u64() as u16,
        _ => 0,
    }
}

/// dcrd's answer.
fn theirs(oracle: &mut Oracle, version: u16, script: &[u8]) -> bool {
    let mut req = version.to_be_bytes().to_vec();
    req.extend_from_slice(script);
    match oracle.call_ok("stdscript_is_null_data", &req).as_str() {
        "true" => true,
        "false" => false,
        other => panic!("stdscript_is_null_data answered {other:?}"),
    }
}

/// Live differential over generated scripts and versions.
#[test]
fn is_null_data_script_matches_dcrd() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("nulldata differential");
    let (mut yes, mut no) = (0, 0);
    for case in 0..20_000 {
        let script = nulldata_like(&mut rng);
        let version = random_version(&mut rng);
        let want = theirs(&mut oracle, version, &script);
        assert_eq!(
            is_null_data_script(version, &script),
            want,
            "case {case}: version {version} script {}",
            hex(&script)
        );
        if want {
            yes += 1;
        } else {
            no += 1;
        }
    }
    assert!(yes > 1_000 && no > 1_000, "{yes} null data, {no} not");
}

/// The battery's cases: the upstream table under versions 0, 1 and 9999,
/// then generated scripts from a fixed seed.
fn battery() -> Vec<(u16, Vec<u8>)> {
    let mut cases = Vec::new();
    for (_, script, _) in upstream_cases() {
        for version in [0, 1, 9999] {
            cases.push((version, script.clone()));
        }
    }
    let mut rng = SplitMix64(0x6e75_6c6c_6461_7461);
    while cases.len() < COMMITTED_CASES {
        cases.push((random_version(&mut rng), nulldata_like(&mut rng)));
    }
    cases
}

/// Every committed answer is dcroxide's, and the file is the one pinned.
#[test]
fn committed_nulldata_vectors_hold() {
    assert_eq!(
        hex(&blake256::sum256(COMMITTED.as_bytes())),
        COMMITTED_DIGEST,
        "data/nulldata_vectors.txt is not the committed battery"
    );
    let (mut cases, mut yes) = (0, 0);
    for l in COMMITTED.lines().filter(|l| !l.starts_with('#')) {
        let [version, script, answer] = l.split('|').collect::<Vec<_>>()[..] else {
            panic!("{l}: not three fields");
        };
        let version: u16 = version.parse().expect("version");
        let got = is_null_data_script(version, &unhex(script));
        assert_eq!(got.to_string(), answer, "{l}");
        cases += 1;
        yes += usize::from(got);
    }
    assert_eq!(cases, COMMITTED_CASES);
    assert!(yes >= 50, "{yes} null data cases");
}

/// The committed file is the battery with dcrd's answers, byte for byte.
/// With `DCROXIDE_REGEN_NULLDATA_VECTORS=<path>` set, a differing text is
/// written there, never into the source tree, and the test still fails.
#[test]
fn committed_nulldata_vectors_regenerate() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut text = String::from(
        "# dcrd stdscript.IsNullDataScript at the parity pin 46e9df48, through\n\
         # tools/oracle's stdscript_is_null_data: the upstream cases of\n\
         # stdscript/scriptv0_test.go:466-538 under versions 0, 1 and 9999, then\n\
         # scripts built around the null data shape from a fixed seed.\n\
         # committed_nulldata_vectors_regenerate rebuilds this file and fails on\n\
         # any difference; committed_nulldata_vectors_hold checks it without Go.\n\
         #\n\
         # <script version>|<script hex>|<true or false>\n",
    );
    for (version, script) in battery() {
        let answer = theirs(&mut oracle, version, &script);
        text.push_str(&format!("{version}|{}|{answer}\n", hex(&script)));
    }
    if text != COMMITTED {
        if let Ok(path) = std::env::var("DCROXIDE_REGEN_NULLDATA_VECTORS") {
            std::fs::write(&path, &text).expect("write the regenerated vectors");
            println!("wrote {path}");
        }
        panic!("tests/data/nulldata_vectors.txt differs from its construction");
    }
}
