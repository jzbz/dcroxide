// SPDX-License-Identifier: ISC
//! dcrd's treasury window and transaction identification test vectors,
//! ported from blockchain/standalone `treasury_test.go` and `tx_test.go`
//! at the pinned tag.  The transaction hex vectors were extracted
//! mechanically into `data/tx_vectors.txt`.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_standalone as standalone;
use dcroxide_testutil::unhex;
use dcroxide_wire::MsgTx;
use standalone::ErrorKind;

const MAINNET_TVI: u64 = 288;
const MAINNET_TVI_MUL: u64 = 12;

/// dcrd TestIsTreasuryVoteInterval.
#[test]
fn is_treasury_vote_interval_vectors() {
    let tests: &[(&str, u64, bool)] = &[
        ("0 is never considered a TVI", 0, false),
        ("TVI - 1", MAINNET_TVI - 1, false),
        ("exactly TVI", MAINNET_TVI, true),
        ("TVI + 1", MAINNET_TVI + 1, false),
        ("multiple of TVI", 2 * MAINNET_TVI, true),
    ];
    for (name, height, want) in tests {
        assert_eq!(
            standalone::is_treasury_vote_interval(*height, MAINNET_TVI),
            *want,
            "{name}"
        );
    }
}

/// dcrd TestCalcTSpendWindow.
#[test]
fn calc_tspend_window_vectors() {
    #[allow(clippy::type_complexity)]
    let tests: &[(&str, u32, u64, u64, Option<ErrorKind>, u32, u32)] = &[
        (
            "zero is not a valid expiry",
            0,
            MAINNET_TVI,
            MAINNET_TVI_MUL,
            Some(ErrorKind::InvalidTSpendExpiry),
            0,
            0,
        ),
        (
            "min required expiry - 1",
            (MAINNET_TVI * MAINNET_TVI_MUL + 1) as u32,
            MAINNET_TVI,
            MAINNET_TVI_MUL,
            Some(ErrorKind::InvalidTSpendExpiry),
            0,
            0,
        ),
        (
            "not a TVI + 2",
            (MAINNET_TVI * MAINNET_TVI_MUL + 3) as u32,
            MAINNET_TVI,
            MAINNET_TVI_MUL,
            Some(ErrorKind::InvalidTSpendExpiry),
            0,
            0,
        ),
        (
            "5 is not a valid start or end for a tvi 11, mul 3",
            5,
            11,
            3,
            Some(ErrorKind::InvalidTSpendExpiry),
            0,
            0,
        ),
        (
            "first possible valid mainnet params",
            (MAINNET_TVI * MAINNET_TVI_MUL + 2) as u32,
            MAINNET_TVI,
            MAINNET_TVI_MUL,
            None,
            0,
            (MAINNET_TVI * MAINNET_TVI_MUL) as u32,
        ),
        (
            "second possible valid mainnet params",
            (MAINNET_TVI * MAINNET_TVI_MUL * 2 + 2) as u32,
            MAINNET_TVI,
            MAINNET_TVI_MUL,
            None,
            (MAINNET_TVI * MAINNET_TVI_MUL) as u32,
            (MAINNET_TVI * MAINNET_TVI_MUL * 2) as u32,
        ),
        (
            "5186 for tvi 288, mul 7 is window [3168, 5184)",
            5186,
            288,
            7,
            None,
            5186 - 288 * 7 - 2,
            5186 - 2,
        ),
        // The two hostile-parameter cases below are pinned against real
        // standalone.CalcTSpendWindow runs: the wrapping guards must
        // reproduce Go's uint arithmetic instead of panicking on the
        // expiry - 2 underflow.
        (
            "hostile mul wraps the min-expiry guard and the window wraps",
            0,
            2,
            (1 << 63) - 1,
            None,
            0,
            4294967294,
        ),
        (
            "hostile tvi errors on the wrapped TVI check",
            0,
            u64::MAX,
            2,
            Some(ErrorKind::InvalidTSpendExpiry),
            0,
            0,
        ),
    ];

    for (name, expiry, tvi, tvimul, want_err, want_start, want_end) in tests {
        match standalone::calc_tspend_window(*expiry, *tvi, *tvimul) {
            Ok((start, end)) => {
                assert_eq!(*want_err, None, "{name}: expected error");
                assert_eq!(start, *want_start, "{name}: start");
                assert_eq!(end, *want_end, "{name}: end");
            }
            Err(e) => assert_eq!(Some(e.kind), *want_err, "{name}: error kind"),
        }
    }
}

/// dcrd TestCalcTSpendExpiry.
#[test]
fn calc_tspend_expiry_vectors() {
    let tests: &[(&str, i64, u64, u64, u32)] = &[
        ("mul 1, tvi 288, first block in first tvi", 0, 288, 1, 578),
        ("mul 1, tvi 288, last block in first tvi", 287, 288, 1, 578),
        (
            "mul 1, tvi 288, first block in second tvi",
            288,
            288,
            1,
            866,
        ),
        ("mul 2, tvi 288, first block in first tvi", 0, 288, 2, 866),
        ("mul 2, tvi 288, last block in first tvi", 287, 288, 2, 866),
        (
            "mul 2, tvi 288, first block in second tvi",
            288,
            288,
            2,
            1154,
        ),
        (
            "mul 60, tvi 4, block in middle of 13th tvi",
            810,
            60,
            4,
            1082,
        ),
        (
            "mul 7, tvi 288, first block in 10th tvi",
            2880,
            288,
            7,
            5186,
        ),
    ];
    for (name, height, tvi, tvimul, want) in tests {
        assert_eq!(
            standalone::calc_tspend_expiry(*height, *tvi, *tvimul),
            *want,
            "{name}"
        );
    }
}

/// dcrd TestInsideTSpendWindow.
#[test]
fn inside_tspend_window_vectors() {
    let tests: &[(&str, i64, u32, bool)] = &[
        ("invalid expiry but otherwise correct", 3167, 5185, false),
        ("one block before window start", 3167, 5186, false),
        ("exactly window start", 3168, 5186, true),
        ("last block of window", 5184, 5186, true),
        ("one block after window", 5185, 5186, false),
    ];
    for (name, height, expiry, want) in tests {
        assert_eq!(
            standalone::inside_tspend_window(*height, *expiry, 288, 7),
            *want,
            "{name}"
        );
    }
}

/// dcrd TestIsCoinbaseTx and TestIsTreasurybaseTx, replayed from the
/// mechanically extracted transaction vectors.
#[test]
fn coinbase_and_treasury_base_identification() {
    let data = include_str!("data/tx_vectors.txt");
    let mut coinbase_rows = 0usize;
    let mut treasury_base_rows = 0usize;
    for line in data.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        match fields[0] {
            "cb" => {
                let want_pre: bool = fields[1].parse().expect("bool");
                let want_post: bool = fields[2].parse().expect("bool");
                let (tx, _) = MsgTx::from_bytes(&unhex(fields[3])).expect("valid tx");
                assert_eq!(
                    standalone::is_coin_base_tx(&tx, false),
                    want_pre,
                    "{line}: pre treasury"
                );
                assert_eq!(
                    standalone::is_coin_base_tx(&tx, true),
                    want_post,
                    "{line}: post treasury"
                );
                coinbase_rows += 1;
            }
            "tb" => {
                let want: bool = fields[1].parse().expect("bool");
                let (tx, _) = MsgTx::from_bytes(&unhex(fields[2])).expect("valid tx");
                assert_eq!(standalone::is_treasury_base(&tx), want, "{line}");
                treasury_base_rows += 1;
            }
            "sanity_base" => {}
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(coinbase_rows, 9);
    assert_eq!(treasury_base_rows, 12);
}

/// dcrd TestCheckTransactionSanity: mutations of mainnet block 373 tx[5].
#[test]
fn check_transaction_sanity_vectors() {
    const MAX_TX_SIZE: u64 = 393216;
    const MAX_ATOMS: i64 = 21_000_000 * 100_000_000;

    let data = include_str!("data/tx_vectors.txt");
    let base_hex = data
        .lines()
        .find_map(|l| l.strip_prefix("sanity_base "))
        .expect("sanity base tx present");
    let (base_tx, _) = MsgTx::from_bytes(&unhex(base_hex)).expect("valid tx");

    // ok
    assert_eq!(
        standalone::check_transaction_sanity(&base_tx, MAX_TX_SIZE),
        Ok(())
    );

    // transaction has no inputs
    let mut tx = base_tx.clone();
    tx.tx_in.clear();
    assert_eq!(
        standalone::check_transaction_sanity(&tx, MAX_TX_SIZE)
            .unwrap_err()
            .kind,
        ErrorKind::NoTxInputs
    );

    // transaction has no outputs
    let mut tx = base_tx.clone();
    tx.tx_out.clear();
    assert_eq!(
        standalone::check_transaction_sanity(&tx, MAX_TX_SIZE)
            .unwrap_err()
            .kind,
        ErrorKind::NoTxOutputs
    );

    // transaction too big
    let mut tx = base_tx.clone();
    tx.tx_out[0].pk_script = vec![0u8; MAX_TX_SIZE as usize];
    assert_eq!(
        standalone::check_transaction_sanity(&tx, MAX_TX_SIZE)
            .unwrap_err()
            .kind,
        ErrorKind::TxTooBig
    );

    // transaction with negative output amount
    let mut tx = base_tx.clone();
    tx.tx_out[0].value = -1;
    assert_eq!(
        standalone::check_transaction_sanity(&tx, MAX_TX_SIZE)
            .unwrap_err()
            .kind,
        ErrorKind::BadTxOutValue
    );

    // transaction with single output amount > max per tx
    let mut tx = base_tx.clone();
    tx.tx_out[0].value = MAX_ATOMS + 1;
    assert_eq!(
        standalone::check_transaction_sanity(&tx, MAX_TX_SIZE)
            .unwrap_err()
            .kind,
        ErrorKind::BadTxOutValue
    );

    // transaction with outputs sum > max per tx
    let mut tx = base_tx.clone();
    tx.tx_out[0].value = MAX_ATOMS;
    tx.tx_out[1].value = 1;
    assert_eq!(
        standalone::check_transaction_sanity(&tx, MAX_TX_SIZE)
            .unwrap_err()
            .kind,
        ErrorKind::BadTxOutValue
    );

    // transaction spending duplicate input
    let mut tx = base_tx.clone();
    tx.tx_in[1].previous_out_point = tx.tx_in[0].previous_out_point;
    assert_eq!(
        standalone::check_transaction_sanity(&tx, MAX_TX_SIZE)
            .unwrap_err()
            .kind,
        ErrorKind::DuplicateTxInputs
    );
}
