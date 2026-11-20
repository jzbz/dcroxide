// SPDX-License-Identifier: ISC
//! The storage-free surface a wallet links: every identifier dcrwallet
//! imports from dcrd's `blockchain/stake` package, named here by its
//! Rust counterpart, so that this target compiles only while each of
//! them is outside the `storage` feature.  CI's storage-gate job builds
//! and runs it with `--no-default-features`; under the default features
//! it is an ordinary test.
//!
//! The list is dcrwallet's at the commit dcr-purse pins
//! (`decred.org/dcrwallet/v5 v5.0.1-0.20261105142009-54b85b336077`):
//! every `stake.<Name>` its Go files name, tests included.  Go names
//! map to Rust ones by the port's convention (`IsSStx` to `is_sstx`,
//! `TreasuryVoteT` to `TreasuryVote`, `TxTypeSStx` to `TxType::SStx`).
//! Each function is coerced to a function pointer of its full type, so
//! a change of signature fails here too, as it would in the wallet.
//!
//! What this does not check is behaviour, but for
//! `is_stake_commitment_tx_out`, whose one rule nothing else tests:
//! that is the business of the crate's vectors and oracle
//! differentials, which run in the same configuration.

use dcroxide_chainhash::Hash;
use dcroxide_stake::{self as stake, RuleError, SStxOutputInfo, TreasuryVote, TxType, VoteBits};
use dcroxide_txscript::stdaddr::{Address, AddressParamsV0};
use dcroxide_wire::MsgTx;

/// `CheckTSpend`'s result: the signature and public key it found.
type TSpendCheck = Result<(Vec<u8>, Vec<u8>), RuleError>;

/// `SStxNullOutputAmounts`'s result: the fee and the committed amounts.
type NullOutputAmounts = Result<(i64, Vec<i64>), RuleError>;

/// The functions, one per Go identifier, at their full types.
#[test]
fn every_function_dcrwallet_calls_is_in_the_storage_free_part() {
    // stake.AddrFromSStxPkScrCommitment
    let _: fn(&[u8], &dyn AddressParamsV0) -> Result<Address, RuleError> =
        stake::addr_from_sstx_pk_scr_commitment;
    // stake.AmountFromSStxPkScrCommitment
    let _: fn(&[u8]) -> Result<i64, RuleError> = stake::amount_from_sstx_pk_scr_commitment;
    // stake.CalculateRewards
    let _: fn(&[i64], i64, i64) -> Vec<i64> = stake::calculate_rewards;
    // stake.CheckSStx
    let _: fn(&MsgTx) -> Result<(), RuleError> = stake::check_sstx;
    // stake.CheckTSpend
    let _: fn(&MsgTx) -> TSpendCheck = stake::check_tspend;
    // stake.DetermineTxType
    let _: fn(&MsgTx) -> TxType = stake::determine_tx_type;
    // stake.IsSSGen, stake.IsSSRtx, stake.IsSStx, stake.IsTSpend
    let _: fn(&MsgTx) -> bool = stake::is_ssgen;
    let _: fn(&MsgTx) -> bool = stake::is_ssrtx;
    let _: fn(&MsgTx) -> bool = stake::is_sstx;
    let _: fn(&MsgTx) -> bool = stake::is_tspend;
    // stake.IsStakeCommitmentTxOut, and its one rule, dcrd's
    // `(index % 2) != 0` (`staketx.go`), which no oracle command and no
    // other test covers.
    let _: fn(usize) -> bool = stake::is_stake_commitment_tx_out;
    assert_eq!(
        [0, 1, 2, 3, 4, usize::MAX].map(stake::is_stake_commitment_tx_out),
        [false, true, false, true, false, true]
    );
    // stake.SSGenBlockVotedOn
    let _: fn(&MsgTx) -> (Hash, u32) = stake::ssgen_block_voted_on;
    // stake.SStxNullOutputAmounts
    let _: fn(&[i64], &[i64], i64) -> NullOutputAmounts = stake::sstx_null_output_amounts;
    // stake.TxSStxStakeOutputInfo
    let _: fn(&MsgTx) -> SStxOutputInfo = stake::tx_sstx_stake_output_info;
}

/// The types and constants, with the values dcrd gives them.
#[test]
fn every_type_and_constant_dcrwallet_names_is_in_the_storage_free_part() {
    // stake.TreasuryVoteT and its three values (dcrd `treasury.go`).
    let votes: [TreasuryVote; 3] = [
        stake::TREASURY_VOTE_INVALID,
        stake::TREASURY_VOTE_YES,
        stake::TREASURY_VOTE_NO,
    ];
    assert_eq!(votes, [0x00, 0x01, 0x02]);

    // stake.TxType and the four kinds dcrwallet names (dcrd `staketx.go`).
    let kinds = [TxType::Regular, TxType::SStx, TxType::SSGen, TxType::SSRtx];
    assert_eq!(kinds.map(|kind| kind as u8), [0, 1, 2, 3]);

    // stake.VoteBits, a struct of the mandatory bits and the extended ones.
    let vote_bits = VoteBits {
        bits: 1,
        extended_bits: Vec::new(),
    };
    assert_eq!(vote_bits.bits, 1);
    assert!(vote_bits.extended_bits.is_empty());
}
