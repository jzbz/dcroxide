// SPDX-License-Identifier: ISC
//! `Prng`'s integer draws against dcrd's `crypto/rand` itself, through
//! the oracle's `rand_draws`, which keys dcrd's `PRNG` exactly as
//! `Prng::from_seed` keys its own (`tools/oracle/cryptorand.go`), so the
//! two streams are one and every value, panic and stream position must
//! agree.
//!
//! Three parts: random sequences of every operation over adversarial
//! bounds; the 32-bit reductions on seeds whose first draw takes the
//! rejection test, which a random seed reaches with probability below
//! 2^-32 and which `entering_bounds` finds instead; and a frozen battery
//! (`data/rand_uniform_vectors.txt`) of dcrd's answers, with its line
//! count and BLAKE-256 digest pinned, which needs no Go to check.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_crypto::blake256;
use dcroxide_testutil::{Oracle, SplitMix64, hex, oracle_or_skip, unhex};

mod common;
use common::{
    DURATION, INT, INT32, INT32N, INT64, INT64N, INTN, Op, READ, UINT32, UINT32N, UINT64, UINT64N,
    UINTN, ours, reduction_edge_cases, request,
};

/// The committed battery.
const COMMITTED: &str = include_str!("data/rand_uniform_vectors.txt");

/// The number of cases in the battery.
const COMMITTED_CASES: usize = 160;

/// The battery's BLAKE-256 digest, so that an edit to the file which
/// leaves it self-consistent is still noticed.  Regenerate both with
/// `committed_rand_vectors_regenerate`.
const COMMITTED_DIGEST: &str = "04d129280542509d30a497c664a3a3f4eb6f1dddde3394f86925a2ade5245071";

/// An argument chosen to sit on an edge of some reduction: zero, one, the
/// powers of two and their neighbours, the 32- and 64-bit extremes signed
/// and unsigned, the bounds just above 2^63 at which `Uint64N` rejects
/// about half of all draws, or a uniform value.
fn edge_arg(rng: &mut SplitMix64) -> u64 {
    match rng.below(12) {
        0 => rng.below(4),
        1 => 1 << rng.below(64),
        2 => (1u64 << rng.below(64)).wrapping_add(1),
        3 => (1u64 << rng.below(64)).wrapping_sub(1),
        4 => [
            u64::from(u32::MAX),
            i32::MAX as u64,
            i32::MIN as u32 as u64,
            (i32::MAX as u64) - 1,
        ][rng.below(4) as usize],
        5 => [u64::MAX, i64::MAX as u64, i64::MIN as u64, u64::MAX - 1][rng.below(4) as usize],
        6 => (1u64 << 63) + 1 + rng.below(1 << 20),
        7 => u64::MAX - rng.below(1 << 20),
        8 => rng.below(1 << 32),
        9 => rng.next_u64() | (1 << 63),
        10 => rng.below(1000),
        _ => rng.next_u64(),
    }
}

/// A random operation over an edge argument.
fn random_op(rng: &mut SplitMix64) -> Op {
    let code = 1 + rng.below(13) as u8;
    let arg = match code {
        INTN => edge_arg(rng) & (u64::MAX >> 1),
        READ => rng.below(65),
        _ => edge_arg(rng),
    };
    Op { code, arg }
}

/// dcrd's answer to a `rand_draws` request.
fn theirs(oracle: &mut Oracle, seed: &[u8; 32], ops: &[Op]) -> String {
    oracle.call_ok("rand_draws", &request(seed, ops))
}

/// Random sequences of every operation agree with dcrd value for value,
/// panic for panic, and in the stream position they leave.
#[test]
fn random_draw_sequences_match_dcrd() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("rand oracle differential");
    let mut panics = 0;
    for case in 0..1_000 {
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        let len = 1 + rng.below(40) as usize;
        let ops: Vec<Op> = (0..len).map(|_| random_op(&mut rng)).collect();
        let want = theirs(&mut oracle, &seed, &ops);
        panics += want.matches("panic: ").count();
        assert_eq!(
            ours(&seed, &ops),
            want,
            "case {case}: seed {} ops {ops:?}",
            hex(&seed)
        );
    }
    assert!(panics > 0, "the cases must include dcrd's panicking bounds");
}

/// The 32-bit reductions agree with dcrd where Go's `Uint32N` tests a
/// draw against its rejection threshold: on draws it rejects, which cost
/// a second draw, and on draws it tests and keeps.
#[test]
fn uint32n_and_int32n_rejection_edges_match_dcrd() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    for rejected in [true, false] {
        for (seed, n) in reduction_edge_cases(6, 1 << 32, rejected) {
            let ops = [Op {
                code: UINT32N,
                arg: u64::from(n),
            }];
            assert_eq!(
                ours(&seed, &ops),
                theirs(&mut oracle, &seed, &ops),
                "Uint32N({n}) on seed {} (rejected: {rejected})",
                hex(&seed)
            );
        }
        for (seed, n) in reduction_edge_cases(6, 1 << 31, rejected) {
            let ops = [Op {
                code: INT32N,
                arg: u64::from(n),
            }];
            assert_eq!(
                ours(&seed, &ops),
                theirs(&mut oracle, &seed, &ops),
                "Int32N({n}) on seed {} (rejected: {rejected})",
                hex(&seed)
            );
        }
    }
}

/// The battery's cases, in order: the 32-bit reduction edges by seed
/// number, then sequences drawn from a fixed seed.
fn battery() -> Vec<([u8; 32], Vec<Op>)> {
    let mut cases = Vec::new();
    for rejected in [true, false] {
        for (seed, n) in reduction_edge_cases(8, 1 << 32, rejected) {
            cases.push((
                seed,
                vec![Op {
                    code: UINT32N,
                    arg: u64::from(n),
                }],
            ));
        }
        for (seed, n) in reduction_edge_cases(8, 1 << 31, rejected) {
            cases.push((
                seed,
                vec![
                    Op {
                        code: INT32N,
                        arg: u64::from(n),
                    },
                    Op {
                        code: UINT32,
                        arg: 0,
                    },
                ],
            ));
        }
    }
    // Every operation at least once with a panicking bound, then random
    // sequences.
    let mut rng = SplitMix64(0x7261_6e64_7665_6373);
    let mut seed = [0u8; 32];
    rng.fill(&mut seed);
    cases.push((
        seed,
        [
            (INT32N, 0),
            (INT32N, i32::MIN as u32 as u64),
            (INT64N, 0),
            (INT64N, i64::MIN as u64),
            (INTN, 0),
            (DURATION, 0),
            (DURATION, u64::MAX),
            (UINT32N, 0),
            (UINT64N, 0),
            (UINTN, 0),
            (UINT64, 0),
            (INT32, 0),
            (INT64, 0),
            (INT, 0),
            (READ, 3),
        ]
        .map(|(code, arg)| Op { code, arg })
        .to_vec(),
    ));
    while cases.len() < COMMITTED_CASES {
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        let len = 1 + rng.below(24) as usize;
        cases.push((seed, (0..len).map(|_| random_op(&mut rng)).collect()));
    }
    cases
}

/// One battery line: seed, request operations, and the answer with its
/// lines joined by `;`.
fn line(seed: &[u8; 32], ops: &[Op], answer: &str) -> String {
    let ops_hex = hex(&request(seed, ops)[32..]);
    format!("{}|{ops_hex}|{}", hex(seed), answer.replace('\n', ";"))
}

/// The battery's text with dcrd's answers.
fn file_text(oracle: &mut Oracle) -> String {
    let mut s = String::from(
        "# dcrd crypto/rand at the parity pin 46e9df48, through tools/oracle's\n\
         # rand_draws: dcrd's PRNG keyed as dcroxide's Prng::from_seed keys its\n\
         # own, the operations run in order, each answer rendered by\n\
         # cryptorand.go's randDraw, then next= and one more Uint64.\n\
         # committed_rand_vectors_regenerate rebuilds this file and fails on any\n\
         # difference; committed_rand_vectors_hold checks it without Go.\n\
         #\n\
         # <seed hex>|<operations hex: code(1) || argument(8 BE) each>|<answer lines joined by ;>\n",
    );
    for (seed, ops) in battery() {
        let answer = theirs(oracle, &seed, &ops);
        s.push_str(&line(&seed, &ops, &answer));
        s.push('\n');
    }
    s
}

/// Every committed answer is dcroxide's, and the file is the one pinned.
#[test]
fn committed_rand_vectors_hold() {
    assert_eq!(
        hex(&blake256::sum256(COMMITTED.as_bytes())),
        COMMITTED_DIGEST,
        "data/rand_uniform_vectors.txt is not the committed battery"
    );
    let mut cases = 0;
    let mut panics = 0;
    for l in COMMITTED.lines().filter(|l| !l.starts_with('#')) {
        let [seed, ops, answer] = l.split('|').collect::<Vec<_>>()[..] else {
            panic!("{l}: not three fields");
        };
        let seed: [u8; 32] = unhex(seed).try_into().expect("32-byte seed");
        let ops: Vec<Op> = unhex(ops)
            .chunks(9)
            .map(|c| Op {
                code: c[0],
                arg: u64::from_be_bytes(c[1..9].try_into().expect("8 bytes")),
            })
            .collect();
        assert_eq!(ours(&seed, &ops).replace('\n', ";"), answer, "{l}");
        panics += answer.matches("panic: ").count();
        cases += 1;
    }
    assert_eq!(cases, COMMITTED_CASES);
    assert!(panics >= 6, "{panics} panics");
}

/// The committed file is the battery with dcrd's answers, byte for byte.
/// With `DCROXIDE_REGEN_RAND_VECTORS=<path>` set, a differing text is
/// written there, never into the source tree, and the test still fails.
#[test]
fn committed_rand_vectors_regenerate() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let text = file_text(&mut oracle);
    if text != COMMITTED {
        if let Ok(path) = std::env::var("DCROXIDE_REGEN_RAND_VECTORS") {
            std::fs::write(&path, &text).expect("write the regenerated vectors");
            println!("wrote {path}");
        }
        panic!("tests/data/rand_uniform_vectors.txt differs from its construction");
    }
}
