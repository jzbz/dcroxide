// SPDX-License-Identifier: ISC
//! The stake crate's amount math on inputs outside the consensus
//! contract, where dcrd's `int64` sums wrap and its `big.Int` return
//! calculation is signed: `Div` is Euclidean and `Rsh` floors
//! (`blockchain/stake/staketx.go` `calculateTicketReturnAmounts`,
//! `CalculateRewards`, `CalculateRevocationRewards`,
//! `SStxNullOutputAmounts` and `CheckSSRtx`).
//!
//! No consensus caller reaches these inputs -- commitments of chain
//! valid tickets are non-negative and sum below `MaxAmount` -- but the
//! functions are public, and unsigned math or a checked `+` answered
//! differently from dcrd or panicked under overflow checks.  Every
//! expected value was produced by dcrd's own package at the parity pin
//! (b9634e01).

use dcroxide_chainhash::Hash;
use dcroxide_stake::{
    ErrorKind, TX_VERSION_AUTO_REVOCATIONS, calculate_revocation_rewards, calculate_rewards,
    check_ssrtx, sstx_null_output_amounts,
};
use dcroxide_testutil::{SplitMix64, oracle_or_skip, unhex};
use dcroxide_txscript::{OP_CHECKSIG, OP_DATA_20, OP_DUP, OP_EQUALVERIFY, OP_HASH160, OP_SSRTX};
use dcroxide_wire::{MsgTx, OutPoint, TX_TREE_STAKE, TxIn, TxOut, TxSerializeType};

const MAX: i64 = i64::MAX;

#[test]
fn rewards_follow_dcrd_signed_big_int_math() {
    // (contributions, purchase amount, vote subsidy, CalculateRewards)
    let rows: [(&[i64], i64, i64, &[i64]); 12] = [
        (&[-1, 4], 10, 0, &[-4, 13]),
        (&[1 << 62, 1 << 62], 100, 5, &[-53, -53]),
        (&[MAX, 1], 1000, 0, &[-1000, 0]),
        (&[5, -3], -7, 2, &[-13, 7]),
        (&[-5, -3], 7, 0, &[4, 2]),
        (&[3, 3, 3], 10, 0, &[3, 3, 3]),
        (
            &[1, 2, 3],
            MAX,
            1,
            &[
                -1537228672809129302,
                -3074457345618258603,
                -4611686018427387904,
            ],
        ),
        (&[MAX, MAX], MAX, 0, &[MAX, MAX]),
        (&[0, 7], 13, 0, &[0, 13]),
        (&[-7, 0], 13, 3, &[16, 0]),
        (&[i64::MIN, 3], 5, 0, &[5, 0]),
        (&[-2, 1, 4], -9, 0, &[6, -3, -12]),
    ];
    for (contribs, purchase, subsidy, want) in rows {
        assert_eq!(
            calculate_rewards(contribs, purchase, subsidy),
            want,
            "CalculateRewards({contribs:?}, {purchase}, {subsidy})"
        );
    }
}

#[test]
fn revocation_rewards_follow_dcrd() {
    let header = [0x01, 0x02, 0x03];
    // (contributions, purchase amount, without and with auto revocations)
    type Row<'a> = (&'a [i64], i64, &'a [i64], &'a [i64]);
    let rows: [Row; 11] = [
        (&[-1, 4], 10, &[-4, 13], &[-4, 14]),
        (&[1 << 62, 1 << 62], 100, &[-50, -50], &[36, 64]),
        (&[5, -3], -7, &[-18, 10], &[-18, 11]),
        (&[-5, -3], 7, &[4, 2], &[4, 3]),
        (&[3, 3, 3], 10, &[3, 3, 3], &[3, 3, 4]),
        (
            &[1, 2, 3],
            MAX,
            &[
                1537228672809129301,
                3074457345618258602,
                4611686018427387903,
            ],
            &[
                1537228672809129301,
                3074457345618258602,
                4611686018427387904,
            ],
        ),
        (&[MAX, MAX], MAX, &[MAX, MAX], &[MAX, MAX]),
        (&[0, 7], 13, &[0, 13], &[0, 13]),
        (&[-7, 0], 13, &[13, 0], &[13, 0]),
        (&[i64::MIN, 3], 5, &[5, 0], &[5, 0]),
        (&[-2, 1, 4], -9, &[6, -3, -12], &[6, -3, -12]),
    ];
    for (contribs, purchase, want_plain, want_auto) in rows {
        let what = format!("CalculateRevocationRewards({contribs:?}, {purchase})");
        assert_eq!(
            calculate_revocation_rewards(contribs, purchase, &header, false),
            want_plain,
            "{what}"
        );
        assert_eq!(
            calculate_revocation_rewards(contribs, purchase, &header, true),
            want_auto,
            "{what} with auto revocations"
        );
    }
}

#[test]
fn null_output_amounts_wrap_like_dcrd() {
    // The contributions sum past i64::MAX and wrap.
    assert_eq!(
        sstx_null_output_amounts(&[MAX, MAX], &[0, 0], 1).expect("ok"),
        (-3, vec![MAX, MAX])
    );
    // MinInt64 - 1 wraps to MaxInt64 before the negativity check.
    assert_eq!(
        sstx_null_output_amounts(&[i64::MIN, 5], &[1, 0], 1).expect("ok"),
        (-9223372036854775805, vec![MAX, 5])
    );
    // MaxInt64 - (-1) wraps negative, which the check rejects.
    let err = sstx_null_output_amounts(&[MAX, 5], &[-1, 0], 1).expect_err("wrapped negative");
    assert_eq!(err.kind, ErrorKind::SStxBadChangeAmts);
    assert_eq!(
        err.description,
        "change at idx 0 spent more coins than allowed (have: 9223372036854775807, spent: -1)"
    );
    assert_eq!(
        sstx_null_output_amounts(&[10, 20], &[3, 4], 15).expect("ok"),
        (8, vec![7, 16])
    );
}

/// An automatic revocation whose output values sum past i64::MAX: Go's
/// sum wraps negative and the zero-fee check rejects it.
#[test]
fn ssrtx_output_sum_wraps_like_dcrd() {
    let mut script = vec![OP_SSRTX, OP_DUP, OP_HASH160, OP_DATA_20];
    script.extend_from_slice(&[0x11; 20]);
    script.extend_from_slice(&[OP_EQUALVERIFY, OP_CHECKSIG]);
    let revocation = |values: &[i64]| MsgTx {
        ser_type: TxSerializeType::Full,
        version: TX_VERSION_AUTO_REVOCATIONS,
        tx_in: vec![TxIn {
            previous_out_point: OutPoint {
                hash: Hash::ZERO,
                index: 0,
                tree: TX_TREE_STAKE,
            },
            sequence: 0xffff_ffff,
            value_in: 5,
            block_height: 0,
            block_index: 0xffff_ffff,
            signature_script: Vec::new(),
        }],
        tx_out: values
            .iter()
            .map(|&value| TxOut {
                value,
                version: 0,
                pk_script: script.clone(),
            })
            .collect(),
        lock_time: 0,
        expiry: 0,
    };

    for values in [[MAX, MAX], [MAX, 1]] {
        let err = check_ssrtx(&revocation(&values)).expect_err("wrapped sum");
        assert_eq!(err.kind, ErrorKind::SSRtxInvalidFee, "{values:?}");
    }
    for values in [[3, 2], [3, 3]] {
        check_ssrtx(&revocation(&values)).expect("zero or negative fee");
    }
}

/// Live against dcrd over arbitrary signed contributions, purchase
/// amounts and subsidies, extremes included, so both signs of every
/// operand of the division and of the shift are drawn.  Automatic
/// revocations are drawn only when the remainder loop is short.
#[test]
fn signed_rewards_match_oracle() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("stake-signed-rewards");
    let draw = |rng: &mut SplitMix64| -> i64 {
        match rng.below(6) {
            0 => [i64::MIN, i64::MIN + 1, -1, 0, 1, MAX - 1, MAX][rng.below(7) as usize],
            1 => -(rng.below(1 << 20) as i64),
            2 => rng.below(1 << 20) as i64,
            3 => rng.below(u64::MAX) as i64,
            _ => rng.below(1 << 44) as i64 - (1 << 43),
        }
    };

    const ROUNDS: usize = 2000;
    let mut compared = 0;
    for round in 0..ROUNDS {
        let n = rng.below(5) as usize + 1;
        let contribs: Vec<i64> = (0..n).map(|_| draw(&mut rng)).collect();
        // A zero sum divides by zero on both sides by design.
        if contribs.iter().fold(0i64, |s, &c| s.wrapping_add(c)) == 0 {
            continue;
        }
        let purchase = draw(&mut rng);
        let subsidy = draw(&mut rng);
        let prev_header = rng.bytes(180);
        let mut mode = rng.below(3) as u8;
        if mode == 2 {
            let base = calculate_revocation_rewards(&contribs, purchase, &prev_header, false);
            let total = base.iter().fold(0i64, |s, &a| s.wrapping_add(a));
            if total < purchase && purchase.wrapping_sub(total) > 4096 {
                mode = 1;
            }
        }

        let ours = match mode {
            0 => calculate_rewards(&contribs, purchase, subsidy),
            1 => calculate_revocation_rewards(&contribs, purchase, &prev_header, false),
            _ => calculate_revocation_rewards(&contribs, purchase, &prev_header, true),
        };
        let ours_text: String = ours.iter().map(|a| format!("{a}\n")).collect();

        let mut req = Vec::new();
        req.push(mode);
        req.extend_from_slice(&(purchase as u64).to_be_bytes());
        req.extend_from_slice(&(subsidy as u64).to_be_bytes());
        req.push(n as u8);
        for c in &contribs {
            req.extend_from_slice(&(*c as u64).to_be_bytes());
        }
        req.extend_from_slice(&prev_header);
        let theirs = oracle.call_ok("stake_calc_rewards", &req);
        let theirs = String::from_utf8(unhex(&theirs)).expect("UTF-8");
        assert_eq!(
            ours_text, theirs,
            "round {round}: mode={mode} purchase={purchase} subsidy={subsidy} \
             contribs={contribs:?}"
        );
        compared += 1;
    }
    assert!(compared > ROUNDS / 2, "too few rounds compared: {compared}");
}
