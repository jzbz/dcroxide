// SPDX-License-Identifier: ISC
//! The same-block-stake-spend exceptions, pinned against dcrd's literals.
//!
//! dcrd bars stake transactions from spending an output created in the
//! block they are mined in (`a38c0195`), and grandfathers the handful of
//! utxos already in the historical chains so those chains still
//! validate (`a38c0195` for main, `9b7ab54a` for testnet3).
//!
//! The rejection arm is covered by dcrd's own full block battery, which
//! moved `bmf25` and `bmf35` to `ErrMissingTxOut` for exactly this
//! check.  Nothing in that battery spends a grandfathered utxo, so the
//! exception arm has no coverage there — and it is the arm that cannot
//! fail loudly.  A reversed hash or a mistyped height leaves every test
//! in the repository green and shows up only as an initial mainnet sync
//! stopping at height 1106817, which is a slow and confusing way to
//! learn about a transcription error.

use dcroxide_blockchain::validate::{is_sbss_violation_for, sbss_violation_constants};
use dcroxide_chaincfg::{mainnet_params, regnet_params, simnet_params, testnet3_params};
use dcroxide_chainhash::Hash;

/// dcrd `sbssViolations`, transcribed from `internal/blockchain/validate.go`
/// at the parity pin as height and display string.
const DCRD_MAINNET: &[(i64, &str)] = &[
    (
        1106817,
        "0875ecdc5f12c8aa6ee0d54331fd5b5e786639882a3adb09882de5e3b939613b",
    ),
    (
        1106831,
        "714e71358937cd33480fd2900853d43ea3440ca67b38bacdfeaeb0c37c80ee27",
    ),
    (
        1106837,
        "aeba09a4efa334e3c13e68f27f40bd37cda7643c263f88d69f38a33c2cdacd18",
    ),
    (
        1106854,
        "17228266d9d6dd7084aa2e479319aca6d755c2a9d2dbb3cf28c8151470c7a439",
    ),
    (
        1106860,
        "20d6d3ed1b609f03969474dca1f452c25e035766457dfd58061f9b9270fc4e6d",
    ),
    (
        1107195,
        "5d2e1898fe0c631cb795b1906fb3cf8d9772f1826be8dea64dd3ab85ac0ab2d3",
    ),
];

/// dcrd `sbssViolationsTestnet3`.
const DCRD_TESTNET3: &[(i64, &str)] = &[(
    1980161,
    "451b6eed1a777bc5bbb5c1dbe10a9e444cbeb7d863adb75fc6b7a676b3dcbb58",
)];

/// The stored bytes must render as dcrd's literals.
///
/// `Hash`'s `Display` reverses, matching dcrd's `Hash.String`, so this
/// catches the byte order the constants are written in — the failure
/// mode a hand-built table is most likely to have.
#[test]
fn exception_hashes_match_dcrds_literals() {
    let (mainnet, testnet3) = sbss_violation_constants();
    for (table, want, net) in [
        (mainnet, DCRD_MAINNET, "mainnet"),
        (testnet3, DCRD_TESTNET3, "testnet3"),
    ] {
        assert_eq!(table.len(), want.len(), "{net}: entry count");
        for ((height, hash), (want_height, want_hash)) in table.iter().zip(want) {
            assert_eq!(height, want_height, "{net}: height");
            assert_eq!(
                &hash.to_string(),
                want_hash,
                "{net}: hash at height {height} does not render as dcrd's literal"
            );
        }
    }
}

/// Every recorded pair is recognised on its own network.
#[test]
fn each_exception_is_recognised_on_its_own_network() {
    let main = mainnet_params();
    for (height, hash) in DCRD_MAINNET {
        let h = hash.parse::<Hash>().expect("parse");
        assert!(
            is_sbss_violation_for(&main, *height, &h),
            "mainnet {height} must be grandfathered"
        );
    }
    let test3 = testnet3_params();
    for (height, hash) in DCRD_TESTNET3 {
        let h = hash.parse::<Hash>().expect("parse");
        assert!(
            is_sbss_violation_for(&test3, *height, &h),
            "testnet3 {height} must be grandfathered"
        );
    }
}

/// The exception is keyed on all three of network, height and hash, so a
/// spend that matches only some of them is still rejected.  Without this
/// the table could degenerate into a blanket exemption and the rejection
/// arm would quietly stop applying at those heights.
#[test]
fn the_exception_does_not_leak_across_network_height_or_hash() {
    let (height, hash) = DCRD_MAINNET[0];
    let h = hash.parse::<Hash>().expect("parse");
    let main = mainnet_params();

    // Right pair, wrong network.
    for other in [testnet3_params(), simnet_params(), regnet_params()] {
        assert!(
            !is_sbss_violation_for(&other, height, &h),
            "a mainnet exception must not apply on {}",
            other.name
        );
    }

    // Right network and hash, adjacent heights.
    assert!(!is_sbss_violation_for(&main, height - 1, &h), "height - 1");
    assert!(!is_sbss_violation_for(&main, height + 1, &h), "height + 1");

    // Right network and height, a hash that is not the recorded one --
    // the recorded hash of a different entry, so this also catches a
    // table keyed on height alone.
    let other_hash = DCRD_MAINNET[1].1.parse::<Hash>().expect("parse");
    assert!(
        !is_sbss_violation_for(&main, height, &other_hash),
        "another entry's hash must not be honoured at this height"
    );

    // A hash of the right shape that appears nowhere in the table.
    assert!(
        !is_sbss_violation_for(&main, height, &Hash::ZERO),
        "an unrecorded hash must not be honoured"
    );

    // And the testnet3 pair must not apply on mainnet.
    let (t3_height, t3_hash) = DCRD_TESTNET3[0];
    let t3 = t3_hash.parse::<Hash>().expect("parse");
    assert!(
        !is_sbss_violation_for(&main, t3_height, &t3),
        "the testnet3 exception must not apply on mainnet"
    );
}
