// SPDX-License-Identifier: ISC
//! The fee limits of a reward commitment script (dcrd
//! `calcRewardCommitScriptLimits`, whose exponent is
//! `uint16(math.Ceil(math.Log2(float64(limit))))`), against dcrd through
//! the oracle's `stdaddr_reward_commit_limits`: every limit around every
//! power of two, where the double conversion and the rounding of the
//! logarithm decide the exponent, the extremes and negative limits, and
//! random limits of every magnitude; then a frozen battery of dcrd's
//! answers (`data/reward_commit_limit_vectors.txt`, line count and
//! BLAKE-256 digest pinned) that needs no Go.
//!
//! The stdaddr differential reaches these limits only below 2^40, where
//! no rounding shows.
//!
//! dcrd's answer depends on the architecture it is built for (QK-0037):
//! Go fuses `Log(frac)*(1/Ln2) + float64(exp)` into one multiply-add on
//! arm64, and the single rounding takes a limit whose double has the
//! fraction field 11 up to the next exponent, where amd64 and 386 round
//! it down. dcroxide follows the unfused source on every architecture.
//! On x86 the oracle's answer is compared as it is; on aarch64 it is
//! expected to be one exponent higher on exactly those limits, and at
//! least one such limit must be met; on any other architecture those
//! limits are not compared. The battery is amd64's answers, and is
//! rebuilt only on x86.

// Test-harness arithmetic over bounded values.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_chaincfg::mainnet_params;
use dcroxide_crypto::blake256;
use dcroxide_testutil::{Oracle, SplitMix64, hex, oracle_or_skip, unhex};
use dcroxide_txscript::stdaddr::{self, Address};

/// The committed battery.
const COMMITTED: &str = include_str!("data/reward_commit_limit_vectors.txt");

/// The number of cases in the battery.
const COMMITTED_CASES: usize = 1_200;

/// The battery's BLAKE-256 digest; regenerate it with the file through
/// `committed_reward_commit_limit_vectors_regenerate`.
const COMMITTED_DIGEST: &str = "f3303cec4ce12fafa4d874f55c6d62a954f45e4d615e5fe383e577bfb83e6301";

/// The pairs per oracle request.
const BATCH: usize = 4_096;

/// How Go builds `math.log2` for the architecture the oracle runs on,
/// which is this test's (the oracle is built for the host).
#[derive(Clone, Copy, PartialEq, Eq)]
enum GoLog2 {
    /// Separate multiply and add, as dcroxide computes: amd64, 386.
    Unfused,
    /// One fused multiply-add (go1.27.3 emits `FMADDD` at
    /// `math/log10.go:36`): arm64.
    Fused,
    /// Not modelled here.
    Unknown,
}

/// The oracle's [`GoLog2`].
const GO_LOG2: GoLog2 = if cfg!(any(target_arch = "x86_64", target_arch = "x86")) {
    GoLog2::Unfused
} else if cfg!(target_arch = "aarch64") {
    GoLog2::Fused
} else {
    GoLog2::Unknown
};

/// Whether `limit` is one whose exponent the fused multiply-add rounds
/// up: a positive limit whose double has the fraction field 11, which an
/// integer reaches only at or above 2^52.
fn fused_rounds_up(limit: i64) -> bool {
    limit > 0 && (limit as f64).to_bits() & ((1 << 52) - 1) == 11
}

/// dcrd's answer as this port's would be on an architecture where Go
/// does not fuse, or `None` where it cannot be told; and whether the
/// fused rounding changed it.
fn unfused(vote: i64, revoke: i64, dcrd: [u8; 2]) -> (Option<[u8; 2]>, bool) {
    let rows = [fused_rounds_up(vote), fused_rounds_up(revoke)];
    match GO_LOG2 {
        GoLog2::Unfused => (Some(dcrd), false),
        GoLog2::Fused => {
            let mut back = dcrd;
            for (byte, fused) in back.iter_mut().zip(rows) {
                if fused {
                    *byte -= 1;
                }
            }
            (Some(back), rows.contains(&true))
        }
        GoLog2::Unknown if rows.contains(&true) => (None, false),
        GoLog2::Unknown => (Some(dcrd), false),
    }
}

/// The oracle's fixed address: mainnet P2PKH-ECDSA of the zero hash.
fn address() -> Address {
    stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(&[0; 20], &mainnet_params())
        .expect("20 bytes")
}

/// The two fee limit bytes this port ends the pair's script with.
fn ours(addr: &Address, vote: i64, revoke: i64) -> [u8; 2] {
    let (_, script) = addr
        .reward_commitment_script(0, vote, revoke)
        .expect("stake address");
    script[script.len() - 2..].try_into().expect("two bytes")
}

/// dcrd's fee limit bytes for each pair, in order.
fn theirs(oracle: &mut Oracle, pairs: &[(i64, i64)]) -> Vec<[u8; 2]> {
    let mut out = Vec::with_capacity(pairs.len());
    for chunk in pairs.chunks(BATCH) {
        let mut req = Vec::with_capacity(chunk.len() * 16);
        for &(vote, revoke) in chunk {
            req.extend_from_slice(&vote.to_be_bytes());
            req.extend_from_slice(&revoke.to_be_bytes());
        }
        let limits = unhex(&oracle.call_ok("stdaddr_reward_commit_limits", &req));
        assert_eq!(
            limits.len(),
            chunk.len() * 2,
            "one limit pair per request pair"
        );
        out.extend(limits.chunks(2).map(|c| [c[0], c[1]]));
    }
    out
}

/// The spacing of the integers that are doubles in the binade of 2^k.
fn step(k: u32) -> i64 {
    if k > 52 { 1 << (k - 52) } else { 1 }
}

/// Every limit within `reach` representable steps of each power of two
/// from 2^0 to 2^62, on both sides, and the extremes and negative limits.
fn around_powers_of_two(reach: i64) -> Vec<i64> {
    let mut limits = Vec::new();
    for k in 0..63u32 {
        let base = 1i64 << k;
        for n in 0..=reach {
            limits.push(base + n * step(k));
            // Below 2^k the spacing is that of the binade under it.
            let below = base - n * step(k.saturating_sub(1));
            if below > 0 {
                limits.push(below);
            }
        }
    }
    limits.extend([
        i64::MIN,
        i64::MIN + 1,
        -(1 << 49) - 1,
        -2,
        -1,
        i64::MAX - 1,
        i64::MAX,
    ]);
    limits
}

/// A random limit: any magnitude, sometimes negative.
fn random_limit(rng: &mut SplitMix64) -> i64 {
    let z = rng.next_u64();
    let magnitude = (z >> (z & 63)) as i64;
    if z & (1 << 6) != 0 && z & (1 << 7) != 0 {
        magnitude | i64::MIN
    } else {
        magnitude & i64::MAX
    }
}

/// Each limit as the vote limit and, paired with a neighbour, as the
/// revocation limit, so both bytes see every limit.
fn pairs_of(limits: &[i64]) -> Vec<(i64, i64)> {
    limits
        .iter()
        .enumerate()
        .map(|(i, &vote)| (vote, limits[(i * 7 + 3) % limits.len()]))
        .collect()
}

/// Live differential: every limit within 64 representable steps of each
/// power of two (the fraction fields 0 to 64 at and above 2^32, which
/// hold the 11 and 12 on either side of the rounding), and random limits.
#[test]
fn reward_commit_limits_match_dcrd() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let addr = address();
    let mut limits = around_powers_of_two(64);
    let mut rng = SplitMix64::from_entropy("reward commit limits differential");
    for _ in 0..200_000 {
        limits.push(random_limit(&mut rng));
    }
    let pairs = pairs_of(&limits);
    let want = theirs(&mut oracle, &pairs);
    let (mut rounded_down, mut fused, mut uncompared) = (0, 0, 0);
    for (&(vote, revoke), &dcrd) in pairs.iter().zip(&want) {
        let got = ours(&addr, vote, revoke);
        let (Some(want), was_fused) = unfused(vote, revoke, dcrd) else {
            uncompared += 1;
            continue;
        };
        assert_eq!(
            hex(&got),
            hex(&want),
            "vote limit {vote}, revocation limit {revoke} (dcrd answered {})",
            hex(&dcrd)
        );
        fused += usize::from(was_fused);
        // A positive limit that is not a power of two whose exponent is
        // the floor of its logarithm: the rows the rounding decides.
        if vote > 0 && vote.count_ones() > 1 && u32::from(got[0] & 0x3f) == vote.ilog2() {
            rounded_down += 1;
        }
    }
    // 1 at 2^49, 2 at 2^50, 5 at 2^51 and 11 at each of 2^52 to 2^62
    // among the limits around the powers of two; a random limit rarely
    // adds one. Where Go's rounding is not modelled the 11 rows with the
    // fraction field 11 go uncompared.
    let floor = if GO_LOG2 == GoLog2::Unknown { 118 } else { 129 };
    assert!(rounded_down >= floor, "{rounded_down} rounded-down limits");
    match GO_LOG2 {
        // The limits with the fraction field 11 at 2^52 to 2^62, as vote
        // or revocation limit.
        GoLog2::Fused => assert!(fused >= 11, "{fused} fused-rounding pairs"),
        GoLog2::Unknown => println!("{uncompared} pairs not compared on this architecture"),
        GoLog2::Unfused => {}
    }
}

/// The battery's cases: the fraction fields on either side of the
/// rounding at each power of two, then random pairs from a fixed seed.
fn battery() -> Vec<(i64, i64)> {
    let mut limits = Vec::new();
    for k in 0..63u32 {
        let base = 1i64 << k;
        for n in [0, 1, 7, 8, 10, 11, 12, 13, 16] {
            limits.push(base + n * step(k));
        }
        for n in [1, 11, 12] {
            let below = base - n * step(k.saturating_sub(1));
            if below > 0 {
                limits.push(below);
            }
        }
    }
    limits.extend([i64::MIN, -1, 0, i64::MAX]);
    let mut cases = pairs_of(&limits);
    let mut rng = SplitMix64(0x6665_656c_696d_6974);
    while cases.len() < COMMITTED_CASES {
        cases.push((random_limit(&mut rng), random_limit(&mut rng)));
    }
    cases
}

/// Every committed answer is dcroxide's, and the file is the one pinned.
#[test]
fn committed_reward_commit_limit_vectors_hold() {
    assert_eq!(
        hex(&blake256::sum256(COMMITTED.as_bytes())),
        COMMITTED_DIGEST,
        "data/reward_commit_limit_vectors.txt is not the committed battery"
    );
    let addr = address();
    let mut cases = 0;
    for l in COMMITTED.lines().filter(|l| !l.starts_with('#')) {
        let [vote, revoke, limits] = l.split('|').collect::<Vec<_>>()[..] else {
            panic!("{l}: not three fields");
        };
        let vote: i64 = vote.parse().expect("vote limit");
        let revoke: i64 = revoke.parse().expect("revocation limit");
        assert_eq!(hex(&ours(&addr, vote, revoke)), limits, "{l}");
        cases += 1;
    }
    assert_eq!(cases, COMMITTED_CASES);
}

/// The committed file is the battery with dcrd's answers, byte for byte,
/// on arm64 once the fused rounding is taken back out of them (where Go's
/// rounding is not modelled the test does nothing). With
/// `DCROXIDE_REGEN_REWARD_COMMIT_LIMIT_VECTORS=<path>` set, a differing
/// text is written there, never into the source tree, and the test still
/// fails.
#[test]
fn committed_reward_commit_limit_vectors_regenerate() {
    if GO_LOG2 == GoLog2::Unknown {
        println!("Go's log2 rounding is not modelled on this architecture");
        return;
    }
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut text = String::from(
        "# dcrd stdaddr calcRewardCommitScriptLimits at the parity pin 46e9df48,\n\
         # through tools/oracle's stdaddr_reward_commit_limits (the last two\n\
         # bytes of RewardCommitmentScript) on amd64: limits on either side of\n\
         # the rounding at each power of two, then random pairs from a fixed\n\
         # seed. dcrd built for arm64 answers one exponent higher where the\n\
         # limit's double has the fraction field 11 (QK-0037).\n\
         # committed_reward_commit_limit_vectors_regenerate rebuilds this file and\n\
         # fails on any difference; committed_reward_commit_limit_vectors_hold\n\
         # checks it without Go.\n\
         #\n\
         # <vote fee limit>|<revocation fee limit>|<limit bytes hex, as scripted>\n",
    );
    let cases = battery();
    for (&(vote, revoke), dcrd) in cases.iter().zip(theirs(&mut oracle, &cases)) {
        let (limits, _) = unfused(vote, revoke, dcrd);
        let limits = limits.expect("a modelled architecture");
        text.push_str(&format!("{vote}|{revoke}|{}\n", hex(&limits)));
    }
    if text != COMMITTED {
        if let Ok(path) = std::env::var("DCROXIDE_REGEN_REWARD_COMMIT_LIMIT_VECTORS") {
            std::fs::write(&path, &text).expect("write the regenerated vectors");
            println!("wrote {path}");
        }
        panic!("tests/data/reward_commit_limit_vectors.txt differs from its construction");
    }
}
