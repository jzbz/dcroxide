// SPDX-License-Identifier: ISC
//! Differential tests: our uint256 vs. dcrd's `math/uint256`, live, across
//! every ported operation with boundary-biased operands (all-zero /
//! all-ones words, values straddling word boundaries, shift amounts at the
//! 64/128/192/255/256 edges).

// Test-harness arithmetic over bounded test indices.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_uint256::{OutputBase, Uint256};

use dcroxide_testutil::{Oracle, SplitMix64, hex, oracle_or_skip};

/// A boundary-biased 256-bit operand: each word independently chosen from
/// zero, max, small, or fully random.
fn edgy_uint(rng: &mut SplitMix64) -> Uint256 {
    let mut be = [0u8; 32];
    for word in 0..4 {
        let choice = rng.below(4);
        let bytes: [u8; 8] = match choice {
            0 => [0u8; 8],
            1 => [0xff; 8],
            2 => rng.below(16).to_be_bytes(),
            _ => rng.next_u64().to_be_bytes(),
        };
        be[word * 8..word * 8 + 8].copy_from_slice(&bytes);
    }
    Uint256::from_be_bytes(&be)
}

/// A boundary-biased shift amount / u64 operand.
fn edgy_aux(rng: &mut SplitMix64) -> u64 {
    match rng.below(4) {
        0 => rng.below(8),
        1 => *[63u64, 64, 65, 127, 128, 129, 191, 192, 193, 255, 256, 300]
            .get(rng.below(12) as usize)
            .expect("in range"),
        2 => u64::MAX - rng.below(4),
        _ => rng.next_u64(),
    }
}

fn call_op(oracle: &mut Oracle, op: u8, a: &Uint256, b: &Uint256, aux: u64) -> String {
    let mut req = Vec::with_capacity(73);
    req.push(op);
    req.extend_from_slice(&a.to_be_bytes());
    req.extend_from_slice(&b.to_be_bytes());
    req.extend_from_slice(&aux.to_be_bytes());
    oracle.call_ok("uint256_op", &req)
}

#[test]
fn uint256_ops_match_dcrd_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("uint256 differential");

    for i in 0..6_000 {
        let a = edgy_uint(&mut rng);
        let b = edgy_uint(&mut rng);
        let aux = edgy_aux(&mut rng);
        let op = rng.below(22) as u8;

        // Skip the division-by-zero cases (dcrd panics; ours does too).
        if (op == 3 && b.is_zero()) || (op == 21 && aux == 0) {
            continue;
        }

        let ours: String = match op {
            0 => hex(&{ *a.clone().add(&b) }.to_be_bytes()),
            1 => hex(&{ *a.clone().sub(&b) }.to_be_bytes()),
            2 => hex(&{ *a.clone().mul(&b) }.to_be_bytes()),
            3 => hex(&{ *a.clone().div(&b) }.to_be_bytes()),
            4 => hex(&{ *a.clone().square() }.to_be_bytes()),
            5 => hex(&{ *a.clone().negate() }.to_be_bytes()),
            6 => hex(&{ *a.clone().not() }.to_be_bytes()),
            7 => hex(&{ *a.clone().and(&b) }.to_be_bytes()),
            8 => hex(&{ *a.clone().or(&b) }.to_be_bytes()),
            9 => hex(&{ *a.clone().xor(&b) }.to_be_bytes()),
            10 => hex(&{ *a.clone().lsh(aux as u32) }.to_be_bytes()),
            11 => hex(&{ *a.clone().rsh(aux as u32) }.to_be_bytes()),
            12 => format!("{}", a.bit_len()),
            13 => match a.cmp(&b) {
                core::cmp::Ordering::Less => "-1".into(),
                core::cmp::Ordering::Equal => "0".into(),
                core::cmp::Ordering::Greater => "1".into(),
            },
            14 => a.text(OutputBase::Binary),
            15 => a.text(OutputBase::Octal),
            16 => a.text(OutputBase::Decimal),
            17 => a.text(OutputBase::Hex),
            18 => hex(&{ *a.clone().add_u64(aux) }.to_be_bytes()),
            19 => hex(&{ *a.clone().sub_u64(aux) }.to_be_bytes()),
            20 => hex(&{ *a.clone().mul_u64(aux) }.to_be_bytes()),
            21 => hex(&{ *a.clone().div_u64(aux) }.to_be_bytes()),
            _ => unreachable!(),
        };

        // dcrd's Lsh/Rsh take a uint32; make the oracle see the same
        // truncated amount our u32 cast produced.
        let oracle_aux = if op == 10 || op == 11 {
            u64::from(aux as u32)
        } else {
            aux
        };
        let theirs = call_op(&mut oracle, op, &a, &b, oracle_aux);
        assert_eq!(
            ours,
            theirs,
            "case {i}: op {op}, a {}, b {}, aux {aux}",
            hex(&a.to_be_bytes()),
            hex(&b.to_be_bytes())
        );
    }
}
