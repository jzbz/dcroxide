// SPDX-License-Identifier: ISC
//! Decred stake transaction primitives and ticket state, mirroring dcrd's
//! `blockchain/stake` package at the parity pin, master `46e9df48`: stake
//! transaction classification and format rule checks (tickets, votes,
//! revocations, and the treasury transactions),
//! commitment/vote-bits/block-reference extraction, reward calculation,
//! and the deterministic ticket lottery PRNG.  The package's two changes
//! since the 2.2 campaign target `452c1a6c` are carried: `036b7090`
//! (`tickettreap`'s `getByIndex` bound) and `5dd4ca59` (the revocation
//! helper accepting zero-valued outputs).  `7e3dd854`, which prepares
//! the v5.0.3 release, changes only the module's `go.mod` and `go.sum`
//! and one test's copyright line.
//!
//! The live-ticket state machinery lives in the submodules: the ticket
//! treap (`tickettreap`, dcrd `internal/tickettreap`), the ticket
//! database row formats (`ticketdb`, dcrd `internal/ticketdb`), the
//! per-block stake node (`ticketnode`, dcrd `tickets.go`), and the
//! database-coupled `Db*` functions and entry points (`stakedb`); see
//! PARITY.md.
//!
//! # The `storage` feature
//!
//! `stakedb` is the one module that touches storage, and it exists only
//! with the `storage` feature, which is on by default and is the only
//! thing that brings in `dcroxide-database` and, through it, redb.
//! Three crate-private `ticketnode::Node` helpers that only `stakedb`
//! calls (`missed_treap`, `revoked_treap`, `from_database_state`) sit
//! behind the feature with it; no public item outside `stakedb` changes.
//! Built with `default-features = false`, the crate is the storage-free
//! part of dcrd's package, with every other public module and item
//! unchanged: what `dcroxide-gcs`, `dcroxide-fees` and `dcroxide-rpc`
//! take, and what a wallet links without the node's ticket database.  Everything dcrwallet imports
//! from `blockchain/stake` is in that part (PARITY.md, the
//! `blockchain/stake` row).  The node's crates take the feature, so
//! the node's build is the same with it as before it existed.
//!
//! Extraction helpers documented by dcrd as only safe on transactions
//! that already passed the corresponding `Is*` check keep dcrd's exact
//! panic-on-malformed-input behavior rather than adding new error paths.
//!
//! The `no_std` attribute below covers this crate's own code only.
//! With `storage`, `stakedb` reaches the std-only `dcroxide-database`.
//! Without it the crate's own code still needs only `core` and `alloc`,
//! but it takes `dcroxide-txscript` with its default features, whose
//! `precomputed-tables` brings std back in, so the CI no_std job does
//! not list this crate in either configuration (its comment says what
//! listing it takes).

#![cfg_attr(not(test), no_std)]
// This crate holds no hashed containers: every map and set in it is
// ordered.  That is a property worth keeping rather than rediscovering
// -- iteration order over a consensus structure must not depend on a
// per-process hash seed.  Denied here rather than workspace-wide
// because the P2P, RPC and mixing crates legitimately hash (see
// ADR-0008); note the lint fires only on `for` loops.
#![deny(clippy::iter_over_hash_type)]

extern crate alloc;

use alloc::format;
use alloc::vec::Vec;

use dcroxide_chainhash::Hash;
use dcroxide_txscript::stdaddr;
use dcroxide_txscript::{
    OP_0, OP_1, OP_16, OP_CHECKSIG, OP_DATA_2, OP_DATA_20, OP_DATA_30, OP_DATA_36, OP_DUP,
    OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_PUSHDATA1, OP_PUSHDATA4, OP_RETURN, OP_SSGEN,
    OP_SSRTX, OP_SSTX, OP_SSTXCHANGE, OP_TGEN,
};
use dcroxide_uint256::Uint256;
use dcroxide_wire::{MsgBlock, MsgTx, OutPoint, TxIn, TxOut, TxSerializeType};

pub mod error;
pub mod lottery;
#[cfg(feature = "storage")]
pub mod stakedb;
pub mod ticketdb;
pub mod ticketnode;
pub mod tickettreap;
pub mod treasury;

pub use error::{ErrorKind, RuleError};
pub use lottery::{Hash256Prng, calc_hash256_prng_iv, find_ticket_idxs};
pub use treasury::{
    TSPEND_SCRIPT_LEN, TX_VERSION_TREASURY, check_tadd, check_treasury_base, check_tspend, is_tadd,
    is_treasury_base, is_tspend, tspend_signature_and_pub_key,
};

use error::stake_rule_error;

/// The type of a transaction (dcrd stake `TxType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)] // Variants mirror dcrd's documented TxType constants 1:1.
pub enum TxType {
    Regular = 0,
    SStx,
    SSGen,
    SSRtx,
    TAdd,
    TSpend,
    TreasuryBase,
}

impl TxType {
    /// The dcrd constant name, used in differential dumps.
    pub fn go_name(self) -> &'static str {
        match self {
            TxType::Regular => "TxTypeRegular",
            TxType::SStx => "TxTypeSStx",
            TxType::SSGen => "TxTypeSSGen",
            TxType::SSRtx => "TxTypeSSRtx",
            TxType::TAdd => "TxTypeTAdd",
            TxType::TSpend => "TxTypeTSpend",
            TxType::TreasuryBase => "TxTypeTreasuryBase",
        }
    }
}

/// The consensus script version (dcrd stake `consensusVersion`).
pub(crate) const CONSENSUS_VERSION: u16 = 0;

/// The revocation transaction version enabling automatic ticket
/// revocations (dcrd `TxVersionAutoRevocations`).
pub const TX_VERSION_AUTO_REVOCATIONS: u16 = 2;

/// The maximum number of inputs allowed in an SStx (dcrd
/// `MaxInputsPerSStx`).
pub const MAX_INPUTS_PER_SSTX: usize = 64;

/// The maximum number of outputs allowed in an SStx (dcrd
/// `MaxOutputsPerSStx`).
pub const MAX_OUTPUTS_PER_SSTX: usize = MAX_INPUTS_PER_SSTX * 2 + 1;

/// The exact number of inputs for an SSGen (dcrd `NumInputsPerSSGen`).
pub const NUM_INPUTS_PER_SSGEN: usize = 2;

/// The maximum number of outputs in an SSGen (dcrd `MaxOutputsPerSSGen`);
/// per dcrd's note this does NOT account for the optional treasury vote
/// output, which cannot be corrected without a consensus vote.
pub const MAX_OUTPUTS_PER_SSGEN: usize = MAX_INPUTS_PER_SSTX + 2;

/// The exact number of inputs for an SSRtx (dcrd `NumInputsPerSSRtx`).
pub const NUM_INPUTS_PER_SSRTX: usize = 1;

/// The maximum number of outputs in an SSRtx (dcrd `MaxOutputsPerSSRtx`).
pub const MAX_OUTPUTS_PER_SSRTX: usize = MAX_INPUTS_PER_SSTX;

/// The minimum size of an SStx OP_RETURN commitment output (dcrd
/// `SStxPKHMinOutSize`): 20-byte hash + 8-byte amount + 2-byte fee limits.
pub const SSTX_PKH_MIN_OUT_SIZE: usize = 32;

/// The maximum size of an SStx OP_RETURN commitment output (dcrd
/// `SStxPKHMaxOutSize`).
pub const SSTX_PKH_MAX_OUT_SIZE: usize = 77;

/// The size of an SSGen block reference OP_RETURN output (dcrd
/// `SSGenBlockReferenceOutSize`).
pub const SSGEN_BLOCK_REFERENCE_OUT_SIZE: usize = 38;

/// The minimum size for an SSGen VoteBits push (dcrd
/// `SSGenVoteBitsOutputMinSize`).
pub const SSGEN_VOTE_BITS_OUTPUT_MIN_SIZE: usize = 4;

/// The maximum size for an SSGen VoteBits push (dcrd
/// `SSGenVoteBitsOutputMaxSize`).
pub const SSGEN_VOTE_BITS_OUTPUT_MAX_SIZE: usize = 77;

/// The largest single-byte push length for SStx commitments and VoteBits
/// pushes (dcrd `MaxSingleBytePushLength`).
pub const MAX_SINGLE_BYTE_PUSH_LENGTH: u8 = 75;

/// The maximum size for extended vote bits (dcrd
/// `SSGenVoteBitsExtendedMaxSize`).
pub const SSGEN_VOTE_BITS_EXTENDED_MAX_SIZE: usize = MAX_SINGLE_BYTE_PUSH_LENGTH as usize - 2;

/// Mask extracting the vote return fraction from commitment fee limits
/// (dcrd `SStxVoteReturnFractionMask`).
pub const SSTX_VOTE_RETURN_FRACTION_MASK: u16 = 0x003f;

/// Mask extracting the revocation return fraction from commitment fee
/// limits (dcrd `SStxRevReturnFractionMask`).
pub const SSTX_REV_RETURN_FRACTION_MASK: u16 = 0x3f00;

/// Right shift applied after [`SSTX_REV_RETURN_FRACTION_MASK`] (dcrd
/// `SStxRevReturnFractionShift`).
pub const SSTX_REV_RETURN_FRACTION_SHIFT: u16 = 8;

/// Bitflag: apply the fractional fee limit for votes (dcrd
/// `SStxVoteFractionFlag`).
pub const SSTX_VOTE_FRACTION_FLAG: u16 = 0x0040;

/// Bitflag: apply the fractional fee limit for revocations (dcrd
/// `SStxRevFractionFlag`).
pub const SSTX_REV_FRACTION_FLAG: u16 = 0x4000;

/// The vote consensus version for a short votebits read (dcrd
/// `VoteConsensusVersionAbsent`).
pub const VOTE_CONSENSUS_VERSION_ABSENT: u32 = 0;

/// The maximum bytes of pushed data in stake transactions (dcrd stake
/// `MaxDataCarrierSize`).
pub const MAX_DATA_CARRIER_SIZE: usize = 256;

/// The maximum transaction amount in atoms (dcrd `dcrutil.MaxAmount`,
/// defined here until the dcrutil crate lands).
pub const MAX_AMOUNT: i64 = 21_000_000 * 100_000_000;

/// [`MAX_AMOUNT`] as dcrd's messages print it.  `dcrutil.MaxAmount` is
/// an untyped floating-point constant (`dcrutil/const.go:13-16`), so
/// `%v` formats it as a `float64`, in exponent form.
pub const MAX_AMOUNT_TEXT: &str = "2.1e+15";

/// Mandatory 2-byte vote bits with optional extended bits (dcrd
/// `VoteBits`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteBits {
    /// The mandatory vote bits.
    pub bits: u16,
    /// The optional extended vote bits.
    pub extended_bits: Vec<u8>,
}

/// Extracted vote bits and version from a vote (dcrd `VoteVersionTuple`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoteVersionTuple {
    /// The vote's consensus version.
    pub version: u32,
    /// The vote bits.
    pub bits: u16,
}

/// The spent (voted and revoked) tickets of a block (dcrd
/// `SpentTicketsInBlock`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpentTicketsInBlock {
    /// Hashes of the voted tickets.
    pub voted_tickets: Vec<Hash>,
    /// Hashes of the revoked tickets.
    pub revoked_tickets: Vec<Hash>,
    /// Vote version/bits for each voted ticket.
    pub votes: Vec<VoteVersionTuple>,
}

/// A minimally sized output for parsing stake information (dcrd
/// `MinimalOutput`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalOutput {
    /// The public key script.
    pub pk_script: Vec<u8>,
    /// The output value in atoms.
    pub value: i64,
    /// The script version.
    pub version: u16,
}

// ---------------------------------------------------------------------------
// Accessory stake functions
// ---------------------------------------------------------------------------

/// Whether the first input's previous outpoint is null (dcrd
/// `isNullOutpoint`). Panics on inputless transactions like dcrd.
pub(crate) fn is_null_outpoint(tx: &MsgTx) -> bool {
    let null_in_op = &tx.tx_in[0].previous_out_point;
    null_in_op.index == u32::MAX
        && null_in_op.hash == Hash::ZERO
        && null_in_op.tree == dcroxide_wire::TX_TREE_REGULAR
}

/// Whether the first input's fraud proof is null (dcrd
/// `isNullFraudProof`).
fn is_null_fraud_proof(tx: &MsgTx) -> bool {
    let tx_in = &tx.tx_in[0];
    tx_in.block_height == dcroxide_wire::NULL_BLOCK_HEIGHT
        && tx_in.block_index == dcroxide_wire::NULL_BLOCK_INDEX
}

/// Whether the opcode is a small integer (dcrd stake's private
/// `isSmallInt`).
fn is_small_int(op: u8) -> bool {
    op == OP_0 || (OP_1..=OP_16).contains(&op)
}

/// Whether the script is a null data script by the stake package's rules
/// (dcrd stake `IsNullDataScript`).  The pushed data limit is the same
/// 256 bytes stdscript uses, as it is upstream.
pub fn is_null_data_script(script_version: u16, script: &[u8]) -> bool {
    // The only supported script version is 0.
    if script_version != 0 {
        return false;
    }

    // OP_RETURN, optionally followed by a data push up to
    // MaxDataCarrierSize bytes.
    if script.is_empty() || script[0] != OP_RETURN {
        return false;
    }
    if script.len() == 1 {
        return true;
    }

    let mut tokenizer = dcroxide_txscript::ScriptTokenizer::new(script_version, &script[1..]);
    tokenizer.next()
        && tokenizer.done()
        && tokenizer.err().is_none()
        && (is_small_int(tokenizer.opcode()) || tokenizer.opcode() <= OP_PUSHDATA4)
        && tokenizer.data().len() <= MAX_DATA_CARRIER_SIZE
}

/// Whether a transaction has a topically valid stake base (dcrd
/// `IsStakeBase`).
pub fn is_stake_base(tx: &MsgTx) -> bool {
    // A stake base (SSGen) must only have two transaction inputs.
    if tx.tx_in.len() != 2 {
        return false;
    }

    // The previous output must be null with null fraud proofs.
    is_null_outpoint(tx) && is_null_fraud_proof(tx)
}

/// Convert a transaction to its minimal outputs derivative (dcrd
/// `ConvertToMinimalOutputs`).
pub fn convert_to_minimal_outputs(tx: &MsgTx) -> Vec<MinimalOutput> {
    tx.tx_out
        .iter()
        .map(|tx_out| MinimalOutput {
            pk_script: tx_out.pk_script.clone(),
            value: tx_out.value,
            version: tx_out.version,
        })
        .collect()
}

/// Per-commitment data extracted from an SStx's outputs (the six parallel
/// slices dcrd's `SStxStakeOutputInfo` returns).
#[derive(Debug, Clone, Default)]
pub struct SStxOutputInfo {
    /// Whether each commitment is P2SH (vs P2PKH).
    pub is_p2sh: Vec<bool>,
    /// The 20-byte hashes committed to.
    pub addresses: Vec<Vec<u8>>,
    /// The committed amounts.
    pub amounts: Vec<i64>,
    /// The change amounts.
    pub change_amounts: Vec<i64>,
    /// Per commitment: [vote fee limit flag, revocation fee limit flag].
    pub spend_rules: Vec<[bool; 2]>,
    /// Per commitment: [vote fee limit log2, revocation fee limit log2].
    pub spend_limits: Vec<[u16; 2]>,
}

/// Scan an SStx's outputs for commitment hashes, amounts, and fee limits
/// (dcrd `SStxStakeOutputInfo`).
///
/// Only safe on outputs of a transaction that passed [`is_sstx`]; panics
/// on malformed commitments exactly like dcrd.
pub fn sstx_stake_output_info(outs: &[MinimalOutput]) -> SStxOutputInfo {
    let expected_in_len = outs.len() / 2;
    let mut info = SStxOutputInfo {
        is_p2sh: alloc::vec![false; expected_in_len],
        addresses: alloc::vec![Vec::new(); expected_in_len],
        amounts: alloc::vec![0; expected_in_len],
        change_amounts: alloc::vec![0; expected_in_len],
        spend_rules: alloc::vec![[false; 2]; expected_in_len],
        spend_limits: alloc::vec![[0; 2]; expected_in_len],
    };

    for (idx, out) in outs.iter().enumerate() {
        // Odd indexes are the commitment outputs.
        if idx > 0 && idx % 2 != 0 {
            // The MSB of the amount encodes P2SH vs P2PKH.
            let mut amt_encoded = [0u8; 8];
            amt_encoded.copy_from_slice(&out.pk_script[22..30]);
            info.is_p2sh[idx / 2] = amt_encoded[7] & (1 << 7) != 0;
            amt_encoded[7] &= !(1u8 << 7);

            info.addresses[idx / 2] = out.pk_script[2..22].to_vec();
            info.amounts[idx / 2] = i64::from_le_bytes(amt_encoded);

            let fee_limit = u16::from_le_bytes(out.pk_script[30..32].try_into().expect("2 bytes"));
            info.spend_rules[idx / 2] = [
                fee_limit & SSTX_VOTE_FRACTION_FLAG == SSTX_VOTE_FRACTION_FLAG,
                fee_limit & SSTX_REV_FRACTION_FLAG == SSTX_REV_FRACTION_FLAG,
            ];
            info.spend_limits[idx / 2] = [
                fee_limit & SSTX_VOTE_RETURN_FRACTION_MASK,
                (fee_limit & SSTX_REV_RETURN_FRACTION_MASK) >> SSTX_REV_RETURN_FRACTION_SHIFT,
            ];
        }

        // Even indexes (after 0) are the change outputs.
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "idx > 0 and even here, so idx / 2 >= 1"
        )]
        if idx > 0 && idx % 2 == 0 {
            info.change_amounts[(idx / 2) - 1] = out.value;
        }
    }

    info
}

/// [`sstx_stake_output_info`] over a transaction (dcrd
/// `TxSStxStakeOutputInfo`).
pub fn tx_sstx_stake_output_info(tx: &MsgTx) -> SStxOutputInfo {
    sstx_stake_output_info(&convert_to_minimal_outputs(tx))
}

/// Extract the P2SH or P2PKH stake address from a ticket commitment
/// pkScript (dcrd `AddrFromSStxPkScrCommitment`).
pub fn addr_from_sstx_pk_scr_commitment(
    pk_script: &[u8],
    params: &dyn stdaddr::AddressParamsV0,
) -> Result<stdaddr::Address, RuleError> {
    if pk_script.len() < SSTX_PKH_MIN_OUT_SIZE {
        return Err(stake_rule_error(
            ErrorKind::SStxBadCommitAmount,
            "short read of sstx commit pkscript",
        ));
    }

    // The MSB of the little-endian encoded amount marks P2SH.
    let is_p2sh = pk_script[29] & 0x80 != 0;
    let hash_bytes = &pk_script[2..22];

    let addr = if is_p2sh {
        stdaddr::new_address_script_hash_v0_from_hash(hash_bytes, params)
    } else {
        stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(hash_bytes, params)
    };
    addr.map_err(|e| stake_rule_error(ErrorKind::SStxBadCommitAmount, format!("{e}")))
}

/// Extract the commitment amount from a ticket commitment pkScript (dcrd
/// `AmountFromSStxPkScrCommitment`).
pub fn amount_from_sstx_pk_scr_commitment(pk_script: &[u8]) -> Result<i64, RuleError> {
    if pk_script.len() < SSTX_PKH_MIN_OUT_SIZE {
        return Err(stake_rule_error(
            ErrorKind::SStxBadCommitAmount,
            "short read of sstx commit pkscript",
        ));
    }

    let mut amt_encoded = [0u8; 8];
    amt_encoded.copy_from_slice(&pk_script[22..30]);
    amt_encoded[7] &= !(1u8 << 7); // Clear the P2SH flag bit.
    Ok(i64::from_le_bytes(amt_encoded))
}

/// The block hash and height an SSGen votes on (dcrd `SSGenBlockVotedOn`);
/// only safe on transactions that passed [`is_ssgen`].
pub fn ssgen_block_voted_on(tx: &MsgTx) -> (Hash, u32) {
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&tx.tx_out[0].pk_script[2..34]);
    let height = u32::from_le_bytes(tx.tx_out[0].pk_script[34..38].try_into().expect("4 bytes"));
    (Hash(block_hash), height)
}

/// The vote bits of an SSGen (dcrd `SSGenVoteBits`); only safe on
/// transactions that passed [`is_ssgen`].
pub fn ssgen_vote_bits(tx: &MsgTx) -> u16 {
    u16::from_le_bytes(tx.tx_out[1].pk_script[2..4].try_into().expect("2 bytes"))
}

/// The network consensus version from an SSGen's VoteBits output (dcrd
/// `SSGenVersion`); 0 on a short read. Only safe on transactions that
/// passed [`is_ssgen`].
pub fn ssgen_version(tx: &MsgTx) -> u32 {
    if tx.tx_out[1].pk_script.len() < 8 {
        return VOTE_CONSENSUS_VERSION_ABSENT;
    }
    u32::from_le_bytes(tx.tx_out[1].pk_script[4..8].try_into().expect("4 bytes"))
}

/// Calculate the fees and per-input contribution amounts for an SStx
/// (dcrd `SStxNullOutputAmounts`).
pub fn sstx_null_output_amounts(
    amounts: &[i64],
    change_amounts: &[i64],
    amount_ticket: i64,
) -> Result<(i64, Vec<i64>), RuleError> {
    if amounts.len() != change_amounts.len() {
        // dcrd returns a plain (kindless) error here; the closest kind is
        // used so the failure is still typed.
        return Err(stake_rule_error(
            ErrorKind::SStxBadChangeAmts,
            "amounts was not equal in length to change amounts!",
        ));
    }

    if amount_ticket <= 0 {
        return Err(stake_rule_error(
            ErrorKind::SStxBadCommitAmount,
            "committed amount was too small!",
        ));
    }

    // The subtraction and the sum wrap like dcrd's int64 arithmetic.
    let mut contrib_amounts = Vec::with_capacity(amounts.len());
    let mut sum: i64 = 0;
    for i in 0..amounts.len() {
        let contrib = amounts[i].wrapping_sub(change_amounts[i]);
        if contrib < 0 {
            return Err(stake_rule_error(
                ErrorKind::SStxBadChangeAmts,
                format!(
                    "change at idx {i} spent more coins than allowed (have: {}, spent: {})",
                    amounts[i], change_amounts[i]
                ),
            ));
        }
        sum = sum.wrapping_add(contrib);
        contrib_amounts.push(contrib);
    }

    Ok((sum.wrapping_sub(amount_ticket), contrib_amounts))
}

/// The 64.32 fixed point proportional return calculation shared by votes
/// and revocations (dcrd `calculateTicketReturnAmounts`).
///
/// dcrd sums the contributions and the output amount in wrapping int64
/// and does the rest in signed `big.Int`: `Div` is Euclidean and `Rsh`
/// floors.  Consensus callers only pass decoded 63-bit commitments that
/// sum below `MaxAmount`, where none of that matters, but the function is
/// public, so the sign handling is reproduced over 256-bit magnitudes
/// (the numerator stays under 2^158) rather than assumed away.  A zero
/// contribution sum panics on the division, as it does in Go.
fn calculate_ticket_return_amounts(
    contrib_amounts: &[i64],
    ticket_purchase_amount: i64,
    vote_subsidy: i64,
) -> Vec<i64> {
    let total_contrib = contrib_amounts
        .iter()
        .fold(0i64, |sum, &amount| sum.wrapping_add(amount));
    let total_contrib_256 = Uint256::from_u64(total_contrib.unsigned_abs());

    let total_output_amt = ticket_purchase_amount.wrapping_add(vote_subsidy);
    let total_output_256 = Uint256::from_u64(total_output_amt.unsigned_abs());

    let mut return_amounts = Vec::with_capacity(contrib_amounts.len());
    for &contrib_amount in contrib_amounts {
        // return = (total output * contribution) << 32 / total contribs >> 32
        let mut num = Uint256::from_u64(contrib_amount.unsigned_abs());
        num.mul(&total_output_256).lsh(32);
        let num_neg = !num.is_zero() && ((contrib_amount < 0) != (total_output_amt < 0));

        // Euclidean division keeps the remainder non-negative, so a
        // negative numerator that does not divide evenly rounds its
        // quotient's magnitude up.
        let mut quo = num;
        quo.div(&total_contrib_256);
        if num_neg {
            let mut product = quo;
            product.mul(&total_contrib_256);
            if product != num {
                quo.add_u64(1);
            }
        }
        let quo_neg = !quo.is_zero() && (num_neg != (total_contrib < 0));

        // An arithmetic right shift floors, so a negative value with any
        // of the shifted-out bits set rounds its magnitude up.
        let shifted_out = quo.as_u32() != 0;
        quo.rsh(32);
        if quo_neg && shifted_out {
            quo.add_u64(1);
        }

        // Like Go's big.Int Int64: the low 64 bits of the magnitude,
        // negated when the value is negative.
        let low = quo.as_u64() as i64;
        return_amounts.push(if quo_neg { low.wrapping_neg() } else { low });
    }

    return_amounts
}

/// The required return amounts for a vote (dcrd `CalculateRewards`).
pub fn calculate_rewards(
    contrib_amounts: &[i64],
    ticket_purchase_amount: i64,
    vote_subsidy: i64,
) -> Vec<i64> {
    calculate_ticket_return_amounts(contrib_amounts, ticket_purchase_amount, vote_subsidy)
}

/// The required return amounts for a revocation (dcrd
/// `CalculateRevocationRewards`); with the automatic-revocations agenda
/// active, each remainder atom goes to a PRNG-selected output.
pub fn calculate_revocation_rewards(
    contrib_amounts: &[i64],
    ticket_purchase_amount: i64,
    prev_header_bytes: &[u8],
    is_auto_revocations_enabled: bool,
) -> Vec<i64> {
    let mut return_amounts =
        calculate_ticket_return_amounts(contrib_amounts, ticket_purchase_amount, 0);

    if !is_auto_revocations_enabled {
        return return_amounts;
    }

    let total_return_amount = return_amounts
        .iter()
        .fold(0i64, |sum, &amount| sum.wrapping_add(amount));
    if total_return_amount < ticket_purchase_amount {
        let num_return_amounts = return_amounts.len() as u32;
        let remainder = ticket_purchase_amount.wrapping_sub(total_return_amount);
        let mut prng = Hash256Prng::new(prev_header_bytes);
        for _ in 0..remainder {
            let return_index = prng.uniform_random(num_return_amounts) as usize;
            return_amounts[return_index] = return_amounts[return_index].wrapping_add(1);
        }
    }

    return_amounts
}

// ---------------------------------------------------------------------------
// Script type helpers (dcrd stake scripttype.go)
// ---------------------------------------------------------------------------

/// Whether the script is a P2SH script per consensus rules (dcrd stake
/// `isScriptHashScript`).
pub(crate) fn is_script_hash_script(script: &[u8]) -> bool {
    script.len() == 23
        && script[0] == OP_HASH160
        && script[1] == OP_DATA_20
        && script[22] == OP_EQUAL
}

/// Whether the script is a P2PKH script per consensus rules (dcrd stake
/// `isPubKeyHashScript`).
pub(crate) fn is_pub_key_hash_script(script: &[u8]) -> bool {
    script.len() == 25
        && script[0] == OP_DUP
        && script[1] == OP_HASH160
        && script[2] == OP_DATA_20
        && script[23] == OP_EQUALVERIFY
        && script[24] == OP_CHECKSIG
}

/// Whether the script is tagged by the given opcode followed by a P2PKH
/// or P2SH script (dcrd stake `isTaggedScript`).
fn is_tagged_script(version: u16, script: &[u8], op: u8) -> bool {
    // The only supported version is 0.
    if version != 0 {
        return false;
    }
    if script.is_empty() {
        return false;
    }
    if script[0] != op {
        return false;
    }
    is_pub_key_hash_script(&script[1..]) || is_script_hash_script(&script[1..])
}

/// Whether the script is a ticket purchase script (dcrd
/// `IsTicketPurchaseScript`).
pub fn is_ticket_purchase_script(version: u16, script: &[u8]) -> bool {
    is_tagged_script(version, script, OP_SSTX)
}

/// Whether the script is a ticket revocation script (dcrd
/// `IsRevocationScript`).
pub fn is_revocation_script(version: u16, script: &[u8]) -> bool {
    is_tagged_script(version, script, OP_SSRTX)
}

/// Whether the script is a stake change script (dcrd
/// `IsStakeChangeScript`).
pub fn is_stake_change_script(version: u16, script: &[u8]) -> bool {
    is_tagged_script(version, script, OP_SSTXCHANGE)
}

/// Whether the script is a vote script (dcrd `IsVoteScript`).
pub fn is_vote_script(version: u16, script: &[u8]) -> bool {
    is_tagged_script(version, script, OP_SSGEN)
}

/// Whether the script is a treasury generation script (dcrd
/// `IsTreasuryGenScript`).
pub fn is_treasury_gen_script(version: u16, script: &[u8]) -> bool {
    is_tagged_script(version, script, OP_TGEN)
}

// ---------------------------------------------------------------------------
// Stake transaction identification (dcrd staketx.go)
// ---------------------------------------------------------------------------

/// The valid two-byte prefix for an SStx commitment output (dcrd
/// `validSStxAddressOutMinPrefix`).
const VALID_SSTX_ADDRESS_OUT_MIN_PREFIX: [u8; 2] = [OP_RETURN, OP_DATA_30];

/// The valid two-byte prefix for an SSGen block reference output (dcrd
/// `validSSGenReferenceOutPrefix`).
const VALID_SSGEN_REFERENCE_OUT_PREFIX: [u8; 2] = [OP_RETURN, OP_DATA_36];

/// The valid minimum two-byte prefix for an SSGen vote output (dcrd
/// `validSSGenVoteOutMinPrefix`).
const VALID_SSGEN_VOTE_OUT_MIN_PREFIX: [u8; 2] = [OP_RETURN, OP_DATA_2];

/// Returns an error unless the transaction conforms to the SStx (ticket
/// purchase) format (dcrd `CheckSStx`).
pub fn check_sstx(tx: &MsgTx) -> Result<(), RuleError> {
    // Check to make sure there aren't too many inputs.
    if tx.tx_in.len() > MAX_INPUTS_PER_SSTX {
        return Err(stake_rule_error(
            ErrorKind::SStxTooManyInputs,
            "SStx has too many inputs",
        ));
    }

    // Check to make sure there aren't too many outputs.
    if tx.tx_out.len() > MAX_OUTPUTS_PER_SSTX {
        return Err(stake_rule_error(
            ErrorKind::SStxTooManyOutputs,
            "SStx has too many outputs",
        ));
    }

    // Check to make sure there are some outputs.
    if tx.tx_out.is_empty() {
        return Err(stake_rule_error(
            ErrorKind::SStxNoOutputs,
            "SStx has no outputs",
        ));
    }

    // All output scripts must be the consensus version.
    for (idx, tx_out) in tx.tx_out.iter().enumerate() {
        if tx_out.version != CONSENSUS_VERSION {
            return Err(stake_rule_error(
                ErrorKind::SStxInvalidOutputs,
                format!("invalid script version found in txOut idx {idx}"),
            ));
        }
    }

    // The first output must be OP_SSTX tagged.
    if !is_ticket_purchase_script(tx.tx_out[0].version, &tx.tx_out[0].pk_script) {
        return Err(stake_rule_error(
            ErrorKind::SStxInvalidOutputs,
            "first SStx output should have been OP_SSTX tagged, but it was not",
        ));
    }

    // The number of outputs must equal the number of inputs * 2 + 1.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "tx_in.len() <= MAX_INPUTS_PER_SSTX (64), checked above, so at most 129"
    )]
    if tx.tx_in.len() * 2 + 1 != tx.tx_out.len() {
        return Err(stake_rule_error(
            ErrorKind::SStxInOutProportions,
            "the number of inputs in the SStx tx was not the number of outputs/2 - 1",
        ));
    }

    // Odd outputs are commitments, the rest of the even outputs are
    // OP_SSTXCHANGE tagged.
    #[allow(clippy::needless_range_loop)] // dcrd's indexed loop; the index is in the errors too.
    for out_tx_index in 1..tx.tx_out.len() {
        let scr_version = tx.tx_out[out_tx_index].version;
        let raw_script: &[u8] = &tx.tx_out[out_tx_index].pk_script;

        // Check change outputs.
        if out_tx_index % 2 == 0 {
            if !is_stake_change_script(scr_version, raw_script) {
                return Err(stake_rule_error(
                    ErrorKind::SStxInvalidOutputs,
                    format!(
                        "SStx output at output index {out_tx_index} was not an sstx change \
                         output"
                    ),
                ));
            }
            continue;
        }

        // Odd outputs: the script should be a null data output.
        if !is_null_data_script(scr_version, raw_script) {
            return Err(stake_rule_error(
                ErrorKind::SStxInvalidOutputs,
                format!(
                    "SStx output at output index {out_tx_index} was not a null data \
                     (OP_RETURN) push"
                ),
            ));
        }

        // The output script must be between 32 and 77 bytes.
        if raw_script.len() < SSTX_PKH_MIN_OUT_SIZE || raw_script.len() > SSTX_PKH_MAX_OUT_SIZE {
            return Err(stake_rule_error(
                ErrorKind::SStxInvalidOutputs,
                format!(
                    "SStx output at output index {out_tx_index} was a null data (OP_RETURN) \
                     push of the wrong size"
                ),
            ));
        }

        // The prefix must be OP_RETURN plus a valid push length.
        let min_push = VALID_SSTX_ADDRESS_OUT_MIN_PREFIX[1];
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "constants: OP_DATA_30 + (75 - OP_DATA_30) = 75"
        )]
        let max_push =
            VALID_SSTX_ADDRESS_OUT_MIN_PREFIX[1] + (MAX_SINGLE_BYTE_PUSH_LENGTH - min_push);
        let push_len = raw_script[1];
        let push_length_valid = push_len >= min_push && push_len <= max_push;
        if raw_script[0] != VALID_SSTX_ADDRESS_OUT_MIN_PREFIX[0] || !push_length_valid {
            return Err(stake_rule_error(
                ErrorKind::SStxInvalidOutputs,
                format!("sstx commitment at output idx {out_tx_index} had an invalid prefix"),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
std::thread_local! {
    /// How many times a ticket, vote or revocation predicate
    /// ([`is_sstx`], [`is_ssgen`], [`is_ssrtx`]) went on from its shape
    /// test to its check on this thread.  It exists in this crate's
    /// unit-test builds only, where the tests read it to tell that a
    /// predicate that refuses a transaction by its shape does not run
    /// the check.
    static PREDICATE_CHECKS: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

/// Whether the transaction fails one of [`check_sstx`]'s first five
/// tests: too many inputs, too many outputs, no outputs, an output
/// script of another version, or a first output that is not a ticket
/// purchase script (dcrd `CheckSStx`, `staketx.go:717-749`), with no
/// message built.
fn fails_sstx_shape(tx: &MsgTx) -> bool {
    tx.tx_in.len() > MAX_INPUTS_PER_SSTX
        || tx.tx_out.len() > MAX_OUTPUTS_PER_SSTX
        || tx.tx_out.is_empty()
        || tx
            .tx_out
            .iter()
            .any(|tx_out| tx_out.version != CONSENSUS_VERSION)
        || !is_ticket_purchase_script(tx.tx_out[0].version, &tx.tx_out[0].pk_script)
}

/// Whether the transaction is a ticket purchase (dcrd `IsSStx`).
///
/// The answer is that of `check_sstx(tx).is_ok()` (`staketx.go:816-818`).
/// The check builds a message for every transaction it refuses, as it
/// does every regular transaction, vote and revocation of a block, and
/// the message would be dropped here; so the check's first five tests
/// are made first, and only a transaction that passes them goes through
/// the check.
pub fn is_sstx(tx: &MsgTx) -> bool {
    if fails_sstx_shape(tx) {
        return false;
    }
    #[cfg(test)]
    PREDICATE_CHECKS.set(PREDICATE_CHECKS.get().wrapping_add(1));
    check_sstx(tx).is_ok()
}

/// A treasury vote value (dcrd `TreasuryVoteT`).
pub type TreasuryVote = u8;

/// An invalid treasury vote (dcrd `TreasuryVoteInvalid`).
pub const TREASURY_VOTE_INVALID: TreasuryVote = 0x00;
/// A vote in favor of a treasury spend (dcrd `TreasuryVoteYes`).
pub const TREASURY_VOTE_YES: TreasuryVote = 0x01;
/// A vote against a treasury spend (dcrd `TreasuryVoteNo`).
pub const TREASURY_VOTE_NO: TreasuryVote = 0x02;

/// Whether the provided vote is valid (dcrd `IsTreasuryVote` /
/// `CheckTreasuryVote`).
pub fn is_treasury_vote(vote: TreasuryVote) -> bool {
    vote == TREASURY_VOTE_YES || vote == TREASURY_VOTE_NO
}

/// A TSpend hash with its associated vote (dcrd `TreasuryVoteTuple`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreasuryVoteTuple {
    /// The TSpend transaction hash voted on.
    pub hash: Hash,
    /// The vote value.
    pub vote: TreasuryVote,
}

/// Extract treasury votes from an SSGen's final output script (dcrd
/// `GetSSGenTreasuryVotes`): `OP_RETURN DATA_PUSH 'T' 'V' <N hash+vote
/// tuples>`.
pub fn get_ssgen_treasury_votes(pk_script: &[u8]) -> Result<Vec<TreasuryVoteTuple>, RuleError> {
    // Enough length for a discriminator, and a single-byte push opcode.
    if pk_script.len() < 4 || pk_script[1] > OP_PUSHDATA1 {
        return Err(stake_rule_error(
            ErrorKind::SSGenInvalidDiscriminatorLength,
            "final output of a SSGen does not contain a valid type discriminator",
        ));
    }

    // The discriminator starts after the (possibly OP_PUSHDATA1-prefixed)
    // push opcode.
    let start: usize = if pk_script[1] == OP_PUSHDATA1 { 3 } else { 2 };

    #[allow(clippy::arithmetic_side_effects, reason = "start is 2 or 3")]
    if start + 2 > pk_script.len() {
        return Err(stake_rule_error(
            ErrorKind::SSGenInvalidNullScript,
            "final output of a SSGen is not a valid nullscript",
        ));
    }

    // The discriminator must be 'T','V'.
    #[allow(clippy::arithmetic_side_effects, reason = "start is 2 or 3")]
    if &pk_script[start..start + 2] != b"TV" {
        return Err(stake_rule_error(
            ErrorKind::SSGenUnknownDiscriminator,
            format!(
                "last SSGen unknown type discriminator: {:#x} {:#x}",
                pk_script[start],
                pk_script[start + 1]
            ),
        ));
    }

    // Expect N hashes with their vote bits.
    const SIZE: usize = 32 + 1;
    #[allow(clippy::arithmetic_side_effects, reason = "start is 2 or 3")]
    let votes_bytes = &pk_script[start + 2..];
    if votes_bytes.len() < SIZE || !votes_bytes.len().is_multiple_of(SIZE) {
        return Err(stake_rule_error(
            ErrorKind::SSGenInvalidTVLength,
            "SSGen 'T','V' invalid length",
        ));
    }

    let mut votes = Vec::with_capacity(7);
    let mut seen: Vec<Hash> = Vec::with_capacity(7);
    #[allow(clippy::arithmetic_side_effects, reason = "start is 2 or 3")]
    let mut i = start + 2;
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "i starts at start + 2 <= pk_script.len() and advances by SIZE only after \
                  pk_script.len() - i >= SIZE, so i <= pk_script.len() and i + 32 < \
                  pk_script.len() inside the loop"
    )]
    loop {
        if pk_script.len() - i < SIZE {
            break;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&pk_script[i..i + 32]);
        let hash = Hash(hash);
        let vote: TreasuryVote = pk_script[i + 32];
        if !is_treasury_vote(vote) {
            return Err(stake_rule_error(
                ErrorKind::SSGenInvalidTreasuryVote,
                format!("SSGen invalid treasury vote bits {vote:#x}"),
            ));
        }

        // No duplicate TSpend votes.
        if seen.contains(&hash) {
            return Err(stake_rule_error(
                ErrorKind::SSGenDuplicateTreasuryVote,
                format!("SSGen duplicate treasury vote {hash}"),
            ));
        }
        seen.push(hash);

        votes.push(TreasuryVoteTuple { hash, vote });
        i += SIZE;
    }
    Ok(votes)
}

/// Returns the treasury votes (when present) unless the transaction fails
/// to conform to the SSGen (vote) format (dcrd `CheckSSGenVotes`).
pub fn check_ssgen_votes(tx: &MsgTx) -> Result<Vec<TreasuryVoteTuple>, RuleError> {
    // Check to make sure there aren't too many inputs.
    if tx.tx_in.len() != NUM_INPUTS_PER_SSGEN {
        return Err(stake_rule_error(
            ErrorKind::SSGenWrongNumInputs,
            "SSgen tx has an invalid number of inputs",
        ));
    }

    // Check to make sure there aren't too many outputs.
    if tx.tx_out.len() > MAX_OUTPUTS_PER_SSGEN {
        return Err(stake_rule_error(
            ErrorKind::SSGenTooManyOutputs,
            "SSgen tx has too many outputs",
        ));
    }

    // Check to make sure there are enough outputs.
    if tx.tx_out.len() < 2 {
        return Err(stake_rule_error(
            ErrorKind::SSGenNoOutputs,
            "SSgen tx does not have enough outputs",
        ));
    }

    // The first input must be a stake base null input.
    if !is_stake_base(tx) {
        return Err(stake_rule_error(
            ErrorKind::SSGenNoStakebase,
            "SSGen tx did not include a stakebase in the zeroeth input position",
        ));
    }

    // The output used as input must have come from TxTreeStake.
    for (i, txin) in tx.tx_in.iter().enumerate() {
        // Skip the stakebase.
        if i == 0 {
            continue;
        }

        if txin.previous_out_point.index != 0 {
            return Err(stake_rule_error(
                ErrorKind::SSGenWrongIndex,
                format!(
                    "SSGen used an invalid input idx (got {}, want 0)",
                    txin.previous_out_point.index
                ),
            ));
        }

        if txin.previous_out_point.tree != dcroxide_wire::TX_TREE_STAKE {
            return Err(stake_rule_error(
                ErrorKind::SSGenWrongTxTree,
                "SSGen used a non-stake input",
            ));
        }
    }

    // All output scripts must be the consensus version.
    for tx_out in &tx.tx_out {
        if tx_out.version != CONSENSUS_VERSION {
            return Err(stake_rule_error(
                ErrorKind::SSGenBadGenOuts,
                "invalid script version found in txOut",
            ));
        }
    }

    // The first output must be an OP_RETURN push.
    let zeroeth_output_version = tx.tx_out[0].version;
    let zeroeth_output_script: &[u8] = &tx.tx_out[0].pk_script;
    if !is_null_data_script(zeroeth_output_version, zeroeth_output_script) {
        return Err(stake_rule_error(
            ErrorKind::SSGenNoReference,
            "first SSGen output should have been an OP_RETURN data push, but was not",
        ));
    }

    // The first output must be the correct size.
    if zeroeth_output_script.len() != SSGEN_BLOCK_REFERENCE_OUT_SIZE {
        return Err(stake_rule_error(
            ErrorKind::SSGenBadReference,
            format!(
                "first SSGen output has invalid an length (got {}, want {})",
                zeroeth_output_script.len(),
                SSGEN_BLOCK_REFERENCE_OUT_SIZE
            ),
        ));
    }

    // The block reference prefix must conform to the standard.
    if zeroeth_output_script[..2] != VALID_SSGEN_REFERENCE_OUT_PREFIX {
        return Err(stake_rule_error(
            ErrorKind::SSGenBadReference,
            "first SSGen output had an invalid prefix",
        ));
    }

    // The second output must be an OP_RETURN push.
    let first_output_version = tx.tx_out[1].version;
    let first_output_script: &[u8] = &tx.tx_out[1].pk_script;
    if !is_null_data_script(first_output_version, first_output_script) {
        return Err(stake_rule_error(
            ErrorKind::SSGenNoVotePush,
            "second SSGen output should have been an OP_RETURN data push, but was not",
        ));
    }

    // The vote bits push must be between 4 and 77 bytes.
    if first_output_script.len() < SSGEN_VOTE_BITS_OUTPUT_MIN_SIZE
        || first_output_script.len() > SSGEN_VOTE_BITS_OUTPUT_MAX_SIZE
    {
        return Err(stake_rule_error(
            ErrorKind::SSGenBadVotePush,
            "SSGen votebits output at output index 1 was a NullData (OP_RETURN) push of \
             the wrong size",
        ));
    }

    // The vote prefix must conform to the standard.
    let min_push = VALID_SSGEN_VOTE_OUT_MIN_PREFIX[1];
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "constants: OP_DATA_2 + (75 - OP_DATA_2) = 75"
    )]
    let max_push = VALID_SSGEN_VOTE_OUT_MIN_PREFIX[1] + (MAX_SINGLE_BYTE_PUSH_LENGTH - min_push);
    let push_len = first_output_script[1];
    let push_length_valid = push_len >= min_push && push_len <= max_push;
    if first_output_script[0] != VALID_SSGEN_VOTE_OUT_MIN_PREFIX[0] || !push_length_valid {
        return Err(stake_rule_error(
            ErrorKind::SSGenBadVotePush,
            "second SSGen output had an invalid prefix",
        ));
    }

    // When the last output is a null data script it must carry treasury
    // votes, in which case the tx version must be the treasury version.
    let mut tx_out_len = tx.tx_out.len();
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "tx_out.len() >= 2, checked above"
    )]
    let last_tx_out = &tx.tx_out[tx.tx_out.len() - 1];
    let mut votes = Vec::new();
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "tx_out_len = tx_out.len() >= 2, checked above"
    )]
    if is_null_data_script(last_tx_out.version, &last_tx_out.pk_script) {
        tx_out_len -= 1;

        votes = get_ssgen_treasury_votes(&last_tx_out.pk_script)?;

        // If there are votes the tx version must be TxVersionTreasury;
        // this is checked late to allow older version SSGens without
        // votes.
        if votes.is_empty() || tx.version != TX_VERSION_TREASURY {
            return Err(stake_rule_error(
                ErrorKind::SSGenInvalidTxVersion,
                format!("SSGen invalid tx version {}", tx.version),
            ));
        }
    }

    // The remaining outputs must be OP_SSGEN tagged.
    #[allow(clippy::needless_range_loop)] // dcrd's indexed loop; the index is in the errors too.
    for out_tx_index in 2..tx_out_len {
        let scr_version = tx.tx_out[out_tx_index].version;
        let raw_script: &[u8] = &tx.tx_out[out_tx_index].pk_script;

        if !is_vote_script(scr_version, raw_script) {
            return Err(stake_rule_error(
                ErrorKind::SSGenBadGenOuts,
                format!(
                    "SSGen tx output at output index {out_tx_index} was not an OP_SSGEN \
                     tagged output"
                ),
            ));
        }
    }

    Ok(votes)
}

/// Returns an error unless the transaction conforms to the SSGen format
/// (dcrd `CheckSSGen`).
pub fn check_ssgen(tx: &MsgTx) -> Result<(), RuleError> {
    check_ssgen_votes(tx).map(|_| ())
}

/// Whether the transaction fails one of [`check_ssgen_votes`]' first
/// four tests: an input count other than two, too many outputs, fewer
/// than two outputs, or a first input that is not a stakebase (dcrd
/// `CheckSSGenVotes`, `staketx.go:992-1016`), with no message built.
fn fails_ssgen_shape(tx: &MsgTx) -> bool {
    tx.tx_in.len() != NUM_INPUTS_PER_SSGEN
        || tx.tx_out.len() > MAX_OUTPUTS_PER_SSGEN
        || tx.tx_out.len() < 2
        || !is_stake_base(tx)
}

/// Whether the transaction is a vote (dcrd `IsSSGen`).
///
/// The answer is that of `check_ssgen(tx).is_ok()`
/// (`staketx.go:1167-1169`), with the first four tests of
/// [`check_ssgen_votes`], which that check runs, made first for the
/// reason given at [`is_sstx`].
pub fn is_ssgen(tx: &MsgTx) -> bool {
    if fails_ssgen_shape(tx) {
        return false;
    }
    #[cfg(test)]
    PREDICATE_CHECKS.set(PREDICATE_CHECKS.get().wrapping_add(1));
    check_ssgen(tx).is_ok()
}

/// Returns an error unless the transaction conforms to the SSRtx
/// (revocation) format (dcrd `CheckSSRtx`).
pub fn check_ssrtx(tx: &MsgTx) -> Result<(), RuleError> {
    // Check to make sure there is the correct number of inputs.
    if tx.tx_in.len() != NUM_INPUTS_PER_SSRTX {
        return Err(stake_rule_error(
            ErrorKind::SSRtxWrongNumInputs,
            "SSRtx has an invalid number of inputs",
        ));
    }

    // Check to make sure there aren't too many outputs.
    if tx.tx_out.len() > MAX_OUTPUTS_PER_SSRTX {
        return Err(stake_rule_error(
            ErrorKind::SSRtxTooManyOutputs,
            "SSRtx has too many outputs",
        ));
    }

    // Check to make sure there are some outputs.
    if tx.tx_out.is_empty() {
        return Err(stake_rule_error(
            ErrorKind::SSRtxNoOutputs,
            "SSRtx has no outputs",
        ));
    }

    // All output scripts must be the consensus version.
    for tx_out in &tx.tx_out {
        if tx_out.version != CONSENSUS_VERSION {
            return Err(stake_rule_error(
                ErrorKind::SSRtxBadOuts,
                "invalid script version found in txOut",
            ));
        }
    }

    // The output used as input must have come from TxTreeStake.
    for txin in &tx.tx_in {
        if txin.previous_out_point.tree != dcroxide_wire::TX_TREE_STAKE {
            return Err(stake_rule_error(
                ErrorKind::SSRtxWrongTxTree,
                "SSRtx used a non-stake input",
            ));
        }
    }

    // The outputs must be OP_SSRTX tagged.
    for (out_tx_index, tx_out) in tx.tx_out.iter().enumerate() {
        if !is_revocation_script(tx_out.version, &tx_out.pk_script) {
            return Err(stake_rule_error(
                ErrorKind::SSRtxBadOuts,
                format!(
                    "SSRtx output at output index {out_tx_index} was not an OP_SSRTX tagged \
                     output"
                ),
            ));
        }
    }

    // Additional checks for the automatic-revocations transaction version.
    if tx.version >= TX_VERSION_AUTO_REVOCATIONS {
        // The input must have an empty signature script.
        if !tx.tx_in[0].signature_script.is_empty() {
            return Err(stake_rule_error(
                ErrorKind::SSRtxInputHasSigScript,
                "SSRtx input 0 contains a non-empty signature script",
            ));
        }

        // The fee must be zero.
        let output_amt = tx
            .tx_out
            .iter()
            .fold(0i64, |sum, o| sum.wrapping_add(o.value));
        let input_amt = tx.tx_in[0].value_in;
        if output_amt < input_amt {
            return Err(stake_rule_error(
                ErrorKind::SSRtxInvalidFee,
                "SSRtx has a non-zero fee",
            ));
        }
    }

    Ok(())
}

/// Whether the transaction fails one of [`check_ssrtx`]'s first six
/// tests, which are all of them ahead of the rules for the automatic
/// revocations version: an input count other than one, too many
/// outputs, no outputs, an output script of another version, an input
/// from outside the stake tree, or an output that is not a revocation
/// script (dcrd `CheckSSRtx`, `staketx.go:1194-1239`), with no message
/// built.  The sixth is here because it is where a ticket bought with
/// one stake tree output is refused, with a formatted message.
fn fails_ssrtx_shape(tx: &MsgTx) -> bool {
    tx.tx_in.len() != NUM_INPUTS_PER_SSRTX
        || tx.tx_out.len() > MAX_OUTPUTS_PER_SSRTX
        || tx.tx_out.is_empty()
        || tx
            .tx_out
            .iter()
            .any(|tx_out| tx_out.version != CONSENSUS_VERSION)
        || tx
            .tx_in
            .iter()
            .any(|tx_in| tx_in.previous_out_point.tree != dcroxide_wire::TX_TREE_STAKE)
        || tx
            .tx_out
            .iter()
            .any(|tx_out| !is_revocation_script(tx_out.version, &tx_out.pk_script))
}

/// Whether the transaction is a revocation (dcrd `IsSSRtx`).
///
/// The answer is that of `check_ssrtx(tx).is_ok()`
/// (`staketx.go:1266-1268`), with the check's first six tests made
/// first for the reason given at [`is_sstx`].
pub fn is_ssrtx(tx: &MsgTx) -> bool {
    if fails_ssrtx_shape(tx) {
        return false;
    }
    #[cfg(test)]
    PREDICATE_CHECKS.set(PREDICATE_CHECKS.get().wrapping_add(1));
    check_ssrtx(tx).is_ok()
}

/// The type of stake transaction, or regular (dcrd `DetermineTxType`).
pub fn determine_tx_type(tx: &MsgTx) -> TxType {
    if is_sstx(tx) {
        return TxType::SStx;
    }
    if is_ssgen(tx) {
        return TxType::SSGen;
    }
    if is_ssrtx(tx) {
        return TxType::SSRtx;
    }
    if tx.version >= TX_VERSION_TREASURY {
        if is_tadd(tx) {
            return TxType::TAdd;
        }
        if is_tspend(tx) {
            return TxType::TSpend;
        }
        if is_treasury_base(tx) {
            return TxType::TreasuryBase;
        }
    }
    TxType::Regular
}

/// Whether the output index is a ticket commitment output (dcrd
/// `IsStakeCommitmentTxOut`); only safe post-[`is_sstx`].
pub fn is_stake_commitment_tx_out(index: usize) -> bool {
    !index.is_multiple_of(2)
}

/// Information about tickets spent in a block from its stake tree only,
/// with no validation (dcrd `FindSpentTicketsInBlock`). The returned
/// hashes are of the original *tickets*, not the votes/revocations.
pub fn find_spent_tickets_in_block(block: &MsgBlock) -> SpentTicketsInBlock {
    let mut votes = Vec::with_capacity(usize::from(block.header.voters));
    let mut voters = Vec::with_capacity(usize::from(block.header.voters));
    let mut revocations = Vec::with_capacity(usize::from(block.header.revocations));

    for stx in &block.stransactions {
        if is_ssgen(stx) {
            voters.push(stx.tx_in[1].previous_out_point.hash);
            votes.push(VoteVersionTuple {
                version: ssgen_version(stx),
                bits: ssgen_vote_bits(stx),
            });
            continue;
        }
        if is_ssrtx(stx) {
            revocations.push(stx.tx_in[0].previous_out_point.hash);
            continue;
        }
    }

    SpentTicketsInBlock {
        voted_tickets: voters,
        votes,
        revoked_tickets: revocations,
    }
}

/// Create a revocation transaction for the provided ticket (dcrd
/// `CreateRevocationFromTicket`); the fee applies to the first output and
/// must adhere to the ticket's fee limit.
pub fn create_revocation_from_ticket(
    ticket_hash: &Hash,
    ticket_min_outs: &[MinimalOutput],
    revocation_tx_fee: i64,
    revocation_tx_version: u16,
    params: &dyn stdaddr::AddressParamsV0,
    prev_header_bytes: &[u8],
    is_auto_revocations_enabled: bool,
) -> Result<MsgTx, RuleError> {
    // The ticket minimal outputs must be non-empty.
    if ticket_min_outs.is_empty() {
        return Err(stake_rule_error(
            ErrorKind::SStxNoOutputs,
            "no minimal outputs",
        ));
    }

    // With auto revocations active the fee must be 0 and the version 2.
    if is_auto_revocations_enabled {
        if revocation_tx_fee != 0 {
            return Err(stake_rule_error(
                ErrorKind::SSRtxInvalidFee,
                "fee must be zero when auto revocations is active",
            ));
        }
        if revocation_tx_version != TX_VERSION_AUTO_REVOCATIONS {
            return Err(stake_rule_error(
                ErrorKind::SSRtxInvalidTxVersion,
                format!(
                    "version must be {TX_VERSION_AUTO_REVOCATIONS} when auto revocations is \
                     active"
                ),
            ));
        }
    }

    // The single input is the ticket submission (OP_SSTX tagged) output.
    const TICKET_SUBMISSION_OUTPUT: u32 = 0;
    let ticket_submission_amount = ticket_min_outs[0].value;
    let mut revocation_tx = MsgTx {
        ser_type: TxSerializeType::Full,
        version: 1,
        tx_in: alloc::vec![TxIn {
            previous_out_point: OutPoint {
                hash: *ticket_hash,
                index: TICKET_SUBMISSION_OUTPUT,
                tree: dcroxide_wire::TX_TREE_STAKE,
            },
            sequence: dcroxide_wire::MAX_TX_IN_SEQUENCE_NUM,
            value_in: ticket_submission_amount,
            block_height: dcroxide_wire::NULL_BLOCK_HEIGHT,
            block_index: dcroxide_wire::NULL_BLOCK_INDEX,
            signature_script: Vec::new(),
        }],
        tx_out: Vec::new(),
        lock_time: 0,
        expiry: 0,
    };

    // All ticket output scripts must be the consensus version.
    for (i, ticket_min_out) in ticket_min_outs.iter().enumerate() {
        if ticket_min_out.version != CONSENSUS_VERSION {
            return Err(stake_rule_error(
                ErrorKind::SStxInvalidOutputs,
                format!("invalid script version found in ticket minimal outputs idx {i}"),
            ));
        }
    }

    // Get the ticket commitment output details.
    let info = sstx_stake_output_info(ticket_min_outs);

    // Vote fee limit info is index 0, revocation fee limit info index 1.
    const REVOCATION_FEE_LIMIT_INDEX: usize = 1;

    // Calculate the revocation output values.
    let revocation_output_amounts = calculate_revocation_rewards(
        &info.amounts,
        ticket_submission_amount,
        prev_header_bytes,
        is_auto_revocations_enabled,
    );

    // Add all the SSRtx-tagged outputs after validity checks.
    let mut fee_applied = false;
    for (i, pay_to_hash) in info.addresses.iter().enumerate() {
        // The amount must be in the valid monetary range.
        if info.amounts[i] < 0 || info.amounts[i] > MAX_AMOUNT {
            return Err(stake_rule_error(
                ErrorKind::SStxBadCommitAmount,
                format!(
                    "invalid output amount: {} (min: 0, max: {MAX_AMOUNT_TEXT})",
                    info.amounts[i]
                ),
            ));
        }

        // Pay to the address committed to in the original ticket.
        let addr = if info.is_p2sh[i] {
            stdaddr::new_address_script_hash_v0_from_hash(pay_to_hash, params)
        } else {
            stdaddr::new_address_pub_key_hash_ecdsa_secp256k1_v0(pay_to_hash, params)
        }
        .map_err(|e| stake_rule_error(ErrorKind::SStxInvalidOutputs, format!("{e}")))?;
        let (_, ssrtx_out_script) = addr
            .pay_revoke_commitment_script()
            .expect("P2PKH-ECDSA and P2SH are stake addresses");

        // The fee must adhere to the commitment's revocation fee limit.
        let has_fee_limit = info.spend_rules[i][REVOCATION_FEE_LIMIT_INDEX];
        let fee_limit_log2 = info.spend_limits[i][REVOCATION_FEE_LIMIT_INDEX];
        if has_fee_limit {
            // A log2 value >= 63 means the entire amount may be a fee.
            if fee_limit_log2 < 63 {
                let fee_limit = 1i64 << u64::from(fee_limit_log2);
                if !fee_applied && revocation_tx_fee > fee_limit {
                    return Err(stake_rule_error(
                        ErrorKind::SSRtxInvalidFee,
                        format!(
                            "fee {revocation_tx_fee} is higher than the imposed fee limit \
                             {fee_limit}"
                        ),
                    ));
                }
            }
        }

        // The fee must be zero when not encumbered with a fee limit.
        if !has_fee_limit && revocation_tx_fee != 0 {
            return Err(stake_rule_error(
                ErrorKind::SSRtxInvalidFee,
                "fee must be zero when not encumbered with a fee limit",
            ));
        }

        // Apply the fee to the first output that can absorb it.
        let mut amt = revocation_output_amounts[i];
        if !fee_applied && revocation_tx_fee < amt {
            amt = amt.wrapping_sub(revocation_tx_fee);
            fee_applied = true;
        }

        revocation_tx.tx_out.push(TxOut {
            value: amt,
            version: 0,
            pk_script: ssrtx_out_script,
        });
    }

    // Set the version of the revocation transaction.
    revocation_tx.version = revocation_tx_version;

    Ok(revocation_tx)
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic over fixed fixtures and small counts"
)]
mod shape_tests {
    //! The ticket, vote and revocation predicates against the checks
    //! they stand for.
    //!
    //! Each predicate makes its check's leading tests before it runs
    //! the check.  That is the same answer only while the shape test
    //! holds exactly where the check fails at one of those tests, so
    //! both are pinned here over every transaction of
    //! `tests/data/staketx_vectors.txt`, valid tickets, votes and
    //! revocations at the counts the checks draw their lines at, a
    //! regular transaction, a coinbase and a treasurybase, each edited
    //! one field at a time, two at a time, and a few at random.

    use alloc::vec;

    use dcroxide_testutil::{SplitMix64, unhex};
    use dcroxide_txscript::{
        OP_DATA_1, OP_DATA_12, OP_DATA_32, OP_DATA_33, OP_DATA_35, OP_DATA_64, OP_TADD, OP_TRUE,
        OP_TSPEND,
    };
    use dcroxide_wire::{NULL_BLOCK_HEIGHT, NULL_BLOCK_INDEX, TX_TREE_REGULAR, TX_TREE_STAKE};

    use super::*;

    /// How `check_sstx` begins the message of its fourth test, an
    /// output script of another version.
    const SSTX_VERSION_TEXT: &str = "invalid script version found in txOut idx ";

    /// The message of `check_sstx`'s fifth test, the first output's
    /// script.
    const SSTX_FIRST_OUTPUT_TEXT: &str =
        "first SStx output should have been OP_SSTX tagged, but it was not";

    /// `determine_tx_type` with each predicate replaced by its check
    /// with the error dropped, which is what dcrd's predicates are
    /// (dcrd `DetermineTxType`, `staketx.go:1272-1294`).
    fn tx_type_by_checks(tx: &MsgTx) -> TxType {
        if check_sstx(tx).is_ok() {
            return TxType::SStx;
        }
        if check_ssgen(tx).is_ok() {
            return TxType::SSGen;
        }
        if check_ssrtx(tx).is_ok() {
            return TxType::SSRtx;
        }
        if tx.version >= TX_VERSION_TREASURY {
            if check_tadd(tx).is_ok() {
                return TxType::TAdd;
            }
            if check_tspend(tx).is_ok() {
                return TxType::TSpend;
            }
            if check_treasury_base(tx).is_ok() {
                return TxType::TreasuryBase;
            }
        }
        TxType::Regular
    }

    /// An output of script version 0.
    fn out(pk_script: Vec<u8>) -> TxOut {
        TxOut {
            value: 0,
            version: 0,
            pk_script,
        }
    }

    /// A pay-to-script-hash script.
    fn p2sh() -> Vec<u8> {
        let mut script = vec![OP_HASH160, OP_DATA_20];
        script.extend_from_slice(&[0x11; 20]);
        script.push(OP_EQUAL);
        script
    }

    /// A pay-to-pubkey-hash script.
    fn p2pkh() -> Vec<u8> {
        let mut script = vec![OP_DUP, OP_HASH160, OP_DATA_20];
        script.extend_from_slice(&[0x22; 20]);
        script.extend_from_slice(&[OP_EQUALVERIFY, OP_CHECKSIG]);
        script
    }

    /// The script behind the given stake opcode.
    fn tagged(tag: u8, mut script: Vec<u8>) -> Vec<u8> {
        script.insert(0, tag);
        script
    }

    /// An `OP_RETURN` followed by a direct push of `push_op` bytes.
    fn null_data(push_op: u8) -> Vec<u8> {
        let mut script = vec![OP_RETURN, push_op];
        script.resize(2 + usize::from(push_op), 0x5a);
        script
    }

    /// An `OP_RETURN` followed by an `OP_PUSHDATA1` push of `len`
    /// bytes: a null data script whose second byte is no direct push.
    fn long_push_null_data(len: u8) -> Vec<u8> {
        let mut script = vec![OP_RETURN, OP_PUSHDATA1, len];
        script.resize(3 + usize::from(len), 0x5a);
        script
    }

    /// The null data script a vote carries its treasury votes in:
    /// `OP_RETURN`, a direct push, `TV`, and for each vote a hash of
    /// the given byte and the vote.
    fn treasury_votes(votes: &[(u8, TreasuryVote)]) -> Vec<u8> {
        let mut script = vec![OP_RETURN, (2 + 33 * votes.len()) as u8, b'T', b'V'];
        for &(hash, vote) in votes {
            script.extend_from_slice(&[hash; 32]);
            script.push(vote);
        }
        script
    }

    /// An input that spends the first output of a transaction in the
    /// given tree.
    fn input(tree: i8) -> TxIn {
        TxIn {
            previous_out_point: OutPoint {
                hash: Hash([0x77; 32]),
                index: 0,
                tree,
            },
            ..TxIn::default()
        }
    }

    /// The input of a coinbase, a treasurybase and a vote's stakebase:
    /// the null outpoint and the null fraud proof.
    fn null_input() -> TxIn {
        TxIn {
            previous_out_point: OutPoint {
                hash: Hash::ZERO,
                index: u32::MAX,
                tree: TX_TREE_REGULAR,
            },
            block_height: NULL_BLOCK_HEIGHT,
            block_index: NULL_BLOCK_INDEX,
            ..TxIn::default()
        }
    }

    /// A ticket bought with the given number of inputs.  `check_sstx`
    /// sets no least number, so a ticket with none passes it.
    fn ticket(inputs: usize) -> MsgTx {
        let mut tx_out = vec![out(tagged(OP_SSTX, p2pkh()))];
        for _ in 0..inputs {
            tx_out.push(out(null_data(OP_DATA_30)));
            tx_out.push(out(tagged(OP_SSTXCHANGE, p2pkh())));
        }
        MsgTx {
            tx_in: vec![input(TX_TREE_REGULAR); inputs],
            tx_out,
            ..MsgTx::default()
        }
    }

    /// A vote that pays the given number of outputs.
    fn vote(payouts: usize) -> MsgTx {
        let mut tx_out = vec![out(null_data(OP_DATA_36)), out(null_data(OP_DATA_2))];
        tx_out.resize(2 + payouts, out(tagged(OP_SSGEN, p2pkh())));
        MsgTx {
            tx_in: vec![null_input(), input(TX_TREE_STAKE)],
            tx_out,
            ..MsgTx::default()
        }
    }

    /// A revocation of the given version that pays the given number
    /// of outputs.
    fn revocation(version: u16, outputs: usize) -> MsgTx {
        MsgTx {
            version,
            tx_in: vec![input(TX_TREE_STAKE)],
            tx_out: vec![out(tagged(OP_SSRTX, p2pkh())); outputs],
            ..MsgTx::default()
        }
    }

    /// A regular transaction with the given number of inputs.
    fn regular(inputs: usize) -> MsgTx {
        MsgTx {
            tx_in: vec![input(TX_TREE_REGULAR); inputs],
            tx_out: vec![out(p2pkh()), out(p2sh())],
            ..MsgTx::default()
        }
    }

    /// A coinbase of the treasury version: its one input carries a
    /// signature script, and it pays one output after its `OP_RETURN`.
    fn coinbase() -> MsgTx {
        let mut tx_in = null_input();
        tx_in.signature_script = vec![OP_TRUE, OP_TRUE];
        MsgTx {
            version: TX_VERSION_TREASURY,
            tx_in: vec![tx_in],
            tx_out: vec![out(null_data(OP_DATA_12)), out(p2pkh())],
            ..MsgTx::default()
        }
    }

    /// A treasurybase.
    fn treasury_base() -> MsgTx {
        MsgTx {
            version: TX_VERSION_TREASURY,
            tx_in: vec![null_input()],
            tx_out: vec![out(vec![OP_TADD]), out(null_data(OP_DATA_12))],
            ..MsgTx::default()
        }
    }

    /// A treasury add with change.
    fn treasury_add() -> MsgTx {
        MsgTx {
            version: TX_VERSION_TREASURY,
            tx_in: vec![input(TX_TREE_REGULAR)],
            tx_out: vec![out(vec![OP_TADD]), out(tagged(OP_SSTXCHANGE, p2pkh()))],
            ..MsgTx::default()
        }
    }

    /// A treasury spend with one payment.
    fn treasury_spend() -> MsgTx {
        let mut signature_script = vec![OP_DATA_64];
        signature_script.extend_from_slice(&[0x33; 64]);
        signature_script.extend_from_slice(&[OP_DATA_33, 0x02]);
        signature_script.extend_from_slice(&[0x44; 32]);
        signature_script.push(OP_TSPEND);
        let mut tx_in = null_input();
        tx_in.signature_script = signature_script;
        MsgTx {
            version: TX_VERSION_TREASURY,
            tx_in: vec![tx_in],
            tx_out: vec![out(null_data(OP_DATA_32)), out(tagged(OP_TGEN, p2sh()))],
            ..MsgTx::default()
        }
    }

    /// A vote of two outputs alone: its second output is both its vote
    /// bits and its treasury votes.
    fn two_output_vote() -> MsgTx {
        let mut tx = vote(0);
        tx.version = TX_VERSION_TREASURY;
        tx.tx_out[1] = out(treasury_votes(&[(0xa1, TREASURY_VOTE_YES)]));
        tx
    }

    /// A vote with treasury votes after its payouts.
    fn treasury_vote() -> MsgTx {
        let mut tx = vote(2);
        tx.version = TX_VERSION_TREASURY;
        tx.tx_out.push(out(treasury_votes(&[
            (0xa1, TREASURY_VOTE_YES),
            (0xa2, TREASURY_VOTE_NO),
        ])));
        tx
    }

    /// The transactions the edits start from: tickets, votes and
    /// revocations with the fewest and the most inputs and outputs
    /// their checks accept, a regular transaction, a coinbase, a
    /// treasurybase, and every vector of dcrd's `staketx_test.go`.
    fn bases() -> Vec<MsgTx> {
        let mut signed_revocation = revocation(1, 1);
        signed_revocation.tx_in[0].signature_script = vec![OP_TRUE];
        let mut bases = vec![
            ticket(0),
            ticket(1),
            ticket(2),
            ticket(MAX_INPUTS_PER_SSTX),
            two_output_vote(),
            vote(3),
            vote(MAX_OUTPUTS_PER_SSGEN - 2),
            treasury_vote(),
            signed_revocation,
            revocation(TX_VERSION_AUTO_REVOCATIONS, 2),
            revocation(1, MAX_OUTPUTS_PER_SSRTX),
            regular(1),
            coinbase(),
            treasury_base(),
        ];
        assert!(bases[..4].iter().all(|tx| check_sstx(tx).is_ok()));
        assert!(bases[4..8].iter().all(|tx| check_ssgen(tx).is_ok()));
        assert!(bases[8..11].iter().all(|tx| check_ssrtx(tx).is_ok()));
        assert_eq!(tx_type_by_checks(&bases[11]), TxType::Regular);
        assert_eq!(tx_type_by_checks(&bases[12]), TxType::Regular);
        assert_eq!(tx_type_by_checks(&bases[13]), TxType::TreasuryBase);

        let vectors = include_str!("../tests/data/staketx_vectors.txt");
        let before = bases.len();
        for line in vectors.lines() {
            let mut parts = line.split(' ');
            if parts.next() != Some("tx") {
                continue;
            }
            let tx_hex = parts.nth(1).expect("vector tx hex");
            let (tx, _) = MsgTx::from_bytes(&unhex(tx_hex)).expect("vector tx deserializes");
            bases.push(tx);
        }
        assert_eq!(bases.len() - before, 31, "every staketx_test.go vector");
        bases
    }

    /// Bring the transaction to `count` outputs, each new one a copy of
    /// its last.
    fn resize_outputs(tx: &mut MsgTx, count: usize) {
        let last = tx.tx_out.last().cloned().unwrap_or_default();
        tx.tx_out.resize(count, last);
    }

    /// Give the output at `index` the script version.
    fn set_version(tx: &mut MsgTx, index: usize, version: u16) {
        if let Some(tx_out) = tx.tx_out.get_mut(index) {
            tx_out.version = version;
        }
    }

    /// Give the output at `index` the script, at version 0.
    fn set_script(tx: &mut MsgTx, index: usize, pk_script: Vec<u8>) {
        if let Some(tx_out) = tx.tx_out.get_mut(index) {
            tx_out.version = 0;
            tx_out.pk_script = pk_script;
        }
    }

    /// Give the last output the script, at version 0.
    fn set_last_script(tx: &mut MsgTx, pk_script: Vec<u8>) {
        if let Some(last) = tx.tx_out.len().checked_sub(1) {
            set_script(tx, last, pk_script);
        }
    }

    /// Edit the input at `index`.
    fn edit_input(tx: &mut MsgTx, index: usize, edit: impl FnOnce(&mut TxIn)) {
        if let Some(tx_in) = tx.tx_in.get_mut(index) {
            edit(tx_in);
        }
    }

    /// Have the input at `index` spend an output of the given tree.
    fn set_tree(tx: &mut MsgTx, index: usize, tree: i8) {
        edit_input(tx, index, |tx_in| tx_in.previous_out_point.tree = tree);
    }

    /// The sum of the transaction's output values, as `check_ssrtx`
    /// takes it.
    fn output_sum(tx: &MsgTx) -> i64 {
        tx.tx_out
            .iter()
            .fold(0i64, |sum, tx_out| sum.wrapping_add(tx_out.value))
    }

    /// One edit of a transaction.  An edit of a field the transaction
    /// does not have leaves it alone.
    type Edit = fn(&mut MsgTx);

    /// The edits: the transaction versions the checks tell apart, every
    /// count around the ones the checks draw their lines at, and one
    /// edit or more for each later test of each check.
    const EDITS: &[Edit] = &[
        // The version.
        |tx| tx.version = 1,
        |tx| tx.version = TX_VERSION_AUTO_REVOCATIONS,
        |tx| tx.version = TX_VERSION_TREASURY,
        |tx| tx.version = 4,
        // The number of inputs.
        |tx| tx.tx_in.clear(),
        |tx| tx.tx_in.truncate(1),
        |tx| tx.tx_in.truncate(2),
        |tx| tx.tx_in.push(input(TX_TREE_STAKE)),
        |tx| tx.tx_in.insert(0, null_input()),
        |tx| tx.tx_in.resize(MAX_INPUTS_PER_SSTX, input(TX_TREE_REGULAR)),
        |tx| {
            tx.tx_in
                .resize(MAX_INPUTS_PER_SSTX + 1, input(TX_TREE_REGULAR))
        },
        // The number of outputs.
        |tx| tx.tx_out.clear(),
        |tx| tx.tx_out.truncate(1),
        |tx| tx.tx_out.truncate(2),
        |tx| tx.tx_out.push(out(tagged(OP_SSGEN, p2pkh()))),
        |tx| tx.tx_out.push(out(tagged(OP_SSRTX, p2sh()))),
        |tx| tx.tx_out.push(out(tagged(OP_SSTXCHANGE, p2pkh()))),
        |tx| tx.tx_out.push(out(null_data(OP_DATA_30))),
        |tx| resize_outputs(tx, MAX_OUTPUTS_PER_SSRTX),
        |tx| resize_outputs(tx, MAX_OUTPUTS_PER_SSRTX + 1),
        |tx| resize_outputs(tx, MAX_OUTPUTS_PER_SSGEN),
        |tx| resize_outputs(tx, MAX_OUTPUTS_PER_SSGEN + 1),
        |tx| resize_outputs(tx, MAX_OUTPUTS_PER_SSTX),
        |tx| resize_outputs(tx, MAX_OUTPUTS_PER_SSTX + 1),
        // The version of an output's script.
        |tx| set_version(tx, 0, 1),
        |tx| set_version(tx, 1, 1),
        |tx| set_version(tx, 2, 1),
        |tx| {
            if let Some(tx_out) = tx.tx_out.last_mut() {
                tx_out.version = 1;
            }
        },
        // The first output: the tag of each stake form, a vote's block
        // reference, one a byte short, one of the right length behind
        // another push, and scripts of no stake form.
        |tx| set_script(tx, 0, tagged(OP_SSTX, p2pkh())),
        |tx| set_script(tx, 0, tagged(OP_SSTX, p2sh())),
        |tx| set_script(tx, 0, tagged(OP_SSGEN, p2pkh())),
        |tx| set_script(tx, 0, tagged(OP_SSRTX, p2pkh())),
        |tx| set_script(tx, 0, tagged(OP_SSTXCHANGE, p2pkh())),
        |tx| set_script(tx, 0, null_data(OP_DATA_36)),
        |tx| set_script(tx, 0, null_data(OP_DATA_35)),
        |tx| set_script(tx, 0, long_push_null_data(35)),
        |tx| set_script(tx, 0, p2pkh()),
        |tx| set_script(tx, 0, Vec::new()),
        // The second output: a vote's vote bits, a ticket's commitment,
        // a push too short for either, one behind another push,
        // treasury votes, a change script, a revocation script, and
        // scripts of no stake form.
        |tx| set_script(tx, 1, null_data(OP_DATA_2)),
        |tx| set_script(tx, 1, null_data(OP_DATA_30)),
        |tx| set_script(tx, 1, null_data(OP_DATA_1)),
        |tx| set_script(tx, 1, long_push_null_data(30)),
        |tx| set_script(tx, 1, treasury_votes(&[(0xa1, TREASURY_VOTE_YES)])),
        |tx| set_script(tx, 1, tagged(OP_SSTXCHANGE, p2pkh())),
        |tx| set_script(tx, 1, tagged(OP_SSRTX, p2pkh())),
        |tx| set_script(tx, 1, p2sh()),
        |tx| set_script(tx, 1, Vec::new()),
        // The last output: each tag, and treasury votes that are well
        // formed, repeated, of an unknown value, absent, behind another
        // discriminator, cut short, and behind a push that leaves no
        // room for the discriminator.
        |tx| set_last_script(tx, tagged(OP_SSGEN, p2sh())),
        |tx| set_last_script(tx, tagged(OP_SSRTX, p2sh())),
        |tx| set_last_script(tx, tagged(OP_SSTXCHANGE, p2sh())),
        |tx| set_last_script(tx, p2pkh()),
        |tx| set_last_script(tx, Vec::new()),
        |tx| set_last_script(tx, treasury_votes(&[(0xa1, TREASURY_VOTE_YES)])),
        |tx| {
            set_last_script(
                tx,
                treasury_votes(&[(0xa1, TREASURY_VOTE_YES), (0xa2, TREASURY_VOTE_NO)]),
            )
        },
        |tx| {
            set_last_script(
                tx,
                treasury_votes(&[(0xa1, TREASURY_VOTE_YES), (0xa1, TREASURY_VOTE_NO)]),
            )
        },
        |tx| set_last_script(tx, treasury_votes(&[(0xa1, 0x03)])),
        |tx| set_last_script(tx, treasury_votes(&[])),
        |tx| set_last_script(tx, null_data(OP_DATA_2)),
        |tx| set_last_script(tx, vec![OP_RETURN]),
        |tx| set_last_script(tx, long_push_null_data(1)),
        // The first input: a stakebase or not by each field that makes
        // one, its signature script, and its value at, above and below
        // what the outputs pay.
        |tx| edit_input(tx, 0, |tx_in| *tx_in = null_input()),
        |tx| edit_input(tx, 0, |tx_in| tx_in.previous_out_point.hash.0[0] ^= 0x01),
        |tx| edit_input(tx, 0, |tx_in| tx_in.previous_out_point.index = 0),
        |tx| edit_input(tx, 0, |tx_in| tx_in.previous_out_point.index = u32::MAX),
        |tx| set_tree(tx, 0, TX_TREE_STAKE),
        |tx| set_tree(tx, 0, TX_TREE_REGULAR),
        |tx| edit_input(tx, 0, |tx_in| tx_in.block_height = 1),
        |tx| edit_input(tx, 0, |tx_in| tx_in.block_index = 0),
        |tx| edit_input(tx, 0, |tx_in| tx_in.signature_script.clear()),
        |tx| edit_input(tx, 0, |tx_in| tx_in.signature_script = vec![OP_TRUE]),
        |tx| {
            let sum = output_sum(tx);
            edit_input(tx, 0, |tx_in| tx_in.value_in = sum);
        },
        |tx| {
            let sum = output_sum(tx);
            edit_input(tx, 0, |tx_in| tx_in.value_in = sum.wrapping_add(1));
        },
        |tx| {
            let sum = output_sum(tx);
            edit_input(tx, 0, |tx_in| tx_in.value_in = sum.wrapping_sub(1));
        },
        // The second input.
        |tx| edit_input(tx, 1, |tx_in| tx_in.previous_out_point.index = 1),
        |tx| set_tree(tx, 1, TX_TREE_REGULAR),
        |tx| edit_input(tx, 1, |tx_in| *tx_in = input(TX_TREE_STAKE)),
    ];

    /// What the transactions compared so far covered.
    #[derive(Default)]
    struct Seen {
        compared: usize,
        tickets: usize,
        votes: usize,
        revocations: usize,
        kinds: Vec<ErrorKind>,
        /// Transactions `check_sstx` refused for an output's script
        /// version, for the first output's script, and with the same
        /// kind at a later test.
        sstx_version_texts: usize,
        sstx_first_output_texts: usize,
        sstx_later_texts: usize,
    }

    impl Seen {
        fn note(&mut self, kind: Option<ErrorKind>) {
            if let Some(kind) = kind
                && !self.kinds.contains(&kind)
            {
                self.kinds.push(kind);
            }
        }
    }

    /// A predicate, with its name and its shape test.
    type Predicate = (&'static str, fn(&MsgTx) -> bool, fn(&MsgTx) -> bool);

    /// The three predicates.
    const PREDICATES: [Predicate; 3] = [
        ("is_sstx", is_sstx, fails_sstx_shape),
        ("is_ssgen", is_ssgen, fails_ssgen_shape),
        ("is_ssrtx", is_ssrtx, fails_ssrtx_shape),
    ];

    /// The predicate's answer for the transaction, and how many times
    /// it went on from its shape test to its check to give it.
    fn answer_and_checks(predicate: fn(&MsgTx) -> bool, tx: &MsgTx) -> (bool, u64) {
        let before = PREDICATE_CHECKS.get();
        let answer = predicate(tx);
        (answer, PREDICATE_CHECKS.get().wrapping_sub(before))
    }

    /// Hold one transaction's predicates to its checks.
    fn compare(tx: &MsgTx, seen: &mut Seen) {
        let sstx = check_sstx(tx).err();
        let sstx_kind = sstx.as_ref().map(|e| e.kind);
        let ssgen = check_ssgen_votes(tx).err().map(|e| e.kind);
        let ssrtx = check_ssrtx(tx).err().map(|e| e.kind);

        // The predicates answer as the checks do, and so does the type
        // made of them.
        assert_eq!(is_sstx(tx), sstx.is_none(), "is_sstx: {tx:?}");
        assert_eq!(is_ssgen(tx), ssgen.is_none(), "is_ssgen: {tx:?}");
        assert_eq!(
            check_ssgen(tx).is_ok(),
            ssgen.is_none(),
            "check_ssgen: {tx:?}"
        );
        assert_eq!(is_ssrtx(tx), ssrtx.is_none(), "is_ssrtx: {tx:?}");
        assert_eq!(
            determine_tx_type(tx),
            tx_type_by_checks(tx),
            "determine_tx_type: {tx:?}"
        );

        // Each shape test holds exactly where its check fails at one of
        // its leading tests, which are the kinds below and, for the one
        // kind a ticket's later tests share, the two messages: a looser
        // shape test would let the check build a message for the
        // predicate to drop, a tighter one would refuse a transaction
        // the check goes on to judge.
        let sstx_version = sstx.as_ref().is_some_and(|e| {
            e.kind == ErrorKind::SStxInvalidOutputs && e.description.starts_with(SSTX_VERSION_TEXT)
        });
        let sstx_first_output = sstx.as_ref().is_some_and(|e| {
            e.kind == ErrorKind::SStxInvalidOutputs && e.description == SSTX_FIRST_OUTPUT_TEXT
        });
        assert_eq!(
            fails_sstx_shape(tx),
            matches!(
                sstx_kind,
                Some(
                    ErrorKind::SStxTooManyInputs
                        | ErrorKind::SStxTooManyOutputs
                        | ErrorKind::SStxNoOutputs
                )
            ) || sstx_version
                || sstx_first_output,
            "ticket shape: {tx:?}"
        );
        assert_eq!(
            fails_ssgen_shape(tx),
            matches!(
                ssgen,
                Some(
                    ErrorKind::SSGenWrongNumInputs
                        | ErrorKind::SSGenTooManyOutputs
                        | ErrorKind::SSGenNoOutputs
                        | ErrorKind::SSGenNoStakebase
                )
            ),
            "vote shape: {tx:?}"
        );
        assert_eq!(
            fails_ssrtx_shape(tx),
            matches!(
                ssrtx,
                Some(
                    ErrorKind::SSRtxWrongNumInputs
                        | ErrorKind::SSRtxTooManyOutputs
                        | ErrorKind::SSRtxNoOutputs
                        | ErrorKind::SSRtxBadOuts
                        | ErrorKind::SSRtxWrongTxTree
                )
            ),
            "revocation shape: {tx:?}"
        );

        // A predicate runs its check once on a transaction that passes
        // its shape test and not at all on one that fails it, so no
        // message of a leading test is built for the predicate to drop.
        for (name, predicate, fails_shape) in PREDICATES {
            let (_, checks) = answer_and_checks(predicate, tx);
            assert_eq!(
                checks,
                u64::from(!fails_shape(tx)),
                "{name} and its check: {tx:?}"
            );
        }

        seen.compared += 1;
        seen.tickets += usize::from(sstx.is_none());
        seen.votes += usize::from(ssgen.is_none());
        seen.revocations += usize::from(ssrtx.is_none());
        seen.note(sstx_kind);
        seen.note(ssgen);
        seen.note(ssrtx);
        seen.sstx_version_texts += usize::from(sstx_version);
        seen.sstx_first_output_texts += usize::from(sstx_first_output);
        seen.sstx_later_texts += usize::from(
            sstx_kind == Some(ErrorKind::SStxInvalidOutputs) && !sstx_version && !sstx_first_output,
        );
    }

    /// `is_sstx`, `is_ssgen` and `is_ssrtx` answer as `check_sstx`,
    /// `check_ssgen` and `check_ssrtx` do, `determine_tx_type` names the
    /// type the six checks give in dcrd's order, each shape test holds
    /// for exactly the transactions its check refuses at one of its
    /// leading tests, and each predicate runs its check for exactly the
    /// transactions that pass its shape test: over every base, with
    /// each edit, with each ordered pair of edits and with random runs
    /// of three to six, which between them pass each check and fail it
    /// with each of its kinds.
    #[test]
    fn the_stake_predicates_answer_as_their_checks_do() {
        let bases = bases();
        let mut seen = Seen::default();

        // Every base as it is, with one edit, and with every ordered
        // pair of edits.
        for base in &bases {
            compare(base, &mut seen);
            for first in EDITS {
                let mut once = base.clone();
                first(&mut once);
                compare(&once, &mut seen);
                for second in EDITS {
                    let mut twice = once.clone();
                    second(&mut twice);
                    compare(&twice, &mut seen);
                }
            }
        }

        // Longer runs of edits, at random.
        let mut rng = SplitMix64::from_entropy("stake predicates");
        for _ in 0..20_000 {
            let mut tx = bases[rng.below(bases.len() as u64) as usize].clone();
            for _ in 0..3 + rng.below(4) {
                EDITS[rng.below(EDITS.len() as u64) as usize](&mut tx);
            }
            compare(&tx, &mut seen);
        }

        // The transactions reached every outcome of every check, so no
        // comparison above held for want of a case.
        assert!(seen.compared > 100_000, "{}", seen.compared);
        assert!(seen.tickets > 100, "{} tickets", seen.tickets);
        assert!(seen.votes > 100, "{} votes", seen.votes);
        assert!(seen.revocations > 100, "{} revocations", seen.revocations);
        for kind in [
            ErrorKind::SStxTooManyInputs,
            ErrorKind::SStxTooManyOutputs,
            ErrorKind::SStxNoOutputs,
            ErrorKind::SStxInvalidOutputs,
            ErrorKind::SStxInOutProportions,
            ErrorKind::SSGenWrongNumInputs,
            ErrorKind::SSGenTooManyOutputs,
            ErrorKind::SSGenNoOutputs,
            ErrorKind::SSGenNoStakebase,
            ErrorKind::SSGenWrongIndex,
            ErrorKind::SSGenWrongTxTree,
            ErrorKind::SSGenBadGenOuts,
            ErrorKind::SSGenNoReference,
            ErrorKind::SSGenBadReference,
            ErrorKind::SSGenNoVotePush,
            ErrorKind::SSGenBadVotePush,
            ErrorKind::SSGenInvalidDiscriminatorLength,
            ErrorKind::SSGenInvalidNullScript,
            ErrorKind::SSGenUnknownDiscriminator,
            ErrorKind::SSGenInvalidTVLength,
            ErrorKind::SSGenInvalidTreasuryVote,
            ErrorKind::SSGenDuplicateTreasuryVote,
            ErrorKind::SSGenInvalidTxVersion,
            ErrorKind::SSRtxWrongNumInputs,
            ErrorKind::SSRtxTooManyOutputs,
            ErrorKind::SSRtxNoOutputs,
            ErrorKind::SSRtxBadOuts,
            ErrorKind::SSRtxWrongTxTree,
            ErrorKind::SSRtxInputHasSigScript,
            ErrorKind::SSRtxInvalidFee,
        ] {
            assert!(
                seen.kinds.contains(&kind),
                "no transaction failed with {kind:?}"
            );
        }
        assert!(
            seen.sstx_version_texts > 100,
            "{} tickets refused for a script version",
            seen.sstx_version_texts
        );
        assert!(
            seen.sstx_first_output_texts > 100,
            "{} tickets refused for the first output",
            seen.sstx_first_output_texts
        );
        assert!(
            seen.sstx_later_texts > 100,
            "{} tickets refused for a later output",
            seen.sstx_later_texts
        );
    }

    /// A predicate refuses the transactions of the other kinds a block
    /// holds by its shape test and does not go on to its check, the one
    /// place a message is built; it runs the check once, for a
    /// transaction of its own kind.  The transactions are regular ones
    /// with one input, with two, with more than a ticket may have and
    /// with one input that spends a stake tree output; tickets bought
    /// with a regular tree output, with a stake tree output and with
    /// two outputs; votes with and without treasury votes; revocations
    /// of both versions; a coinbase, a treasurybase, a treasury add and
    /// a treasury spend.
    #[test]
    fn a_transaction_of_another_kind_is_refused_without_its_check() {
        let mut stake_funded_ticket = ticket(1);
        stake_funded_ticket.tx_in[0].previous_out_point.tree = TX_TREE_STAKE;
        let mut stake_spend = regular(1);
        stake_spend.tx_in[0].previous_out_point.tree = TX_TREE_STAKE;
        let block = [
            ("a regular transaction", regular(1), TxType::Regular),
            (
                "a regular transaction with two inputs",
                regular(2),
                TxType::Regular,
            ),
            (
                "a regular transaction with 65 inputs",
                regular(MAX_INPUTS_PER_SSTX + 1),
                TxType::Regular,
            ),
            (
                "a regular transaction that spends a stake tree output",
                stake_spend,
                TxType::Regular,
            ),
            ("a ticket", ticket(1), TxType::SStx),
            (
                "a ticket bought with a stake tree output",
                stake_funded_ticket,
                TxType::SStx,
            ),
            ("a ticket with two inputs", ticket(2), TxType::SStx),
            ("a vote", vote(3), TxType::SSGen),
            ("a vote with treasury votes", treasury_vote(), TxType::SSGen),
            ("a revocation", revocation(1, 1), TxType::SSRtx),
            (
                "a revocation of the automatic revocations version",
                revocation(TX_VERSION_AUTO_REVOCATIONS, 2),
                TxType::SSRtx,
            ),
            ("a coinbase", coinbase(), TxType::Regular),
            ("a treasurybase", treasury_base(), TxType::TreasuryBase),
            ("a treasury add", treasury_add(), TxType::TAdd),
            ("a treasury spend", treasury_spend(), TxType::TSpend),
        ];
        for (name, tx, tx_type) in &block {
            assert_eq!(tx_type_by_checks(tx), *tx_type, "{name}");
            for (predicate_name, predicate, fails_shape) in PREDICATES {
                let (answer, checks) = answer_and_checks(predicate, tx);
                assert!(
                    answer || fails_shape(tx),
                    "{name}: {predicate_name} refused it past its shape test"
                );
                assert_eq!(
                    checks,
                    u64::from(answer),
                    "{name}: {predicate_name} went on to its check {checks} time(s)"
                );
            }
        }
    }
}
