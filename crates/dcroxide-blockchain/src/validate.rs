// SPDX-License-Identifier: ISC
//! Context-free transaction and proof validation (the corresponding
//! portions of dcrd internal/blockchain `validate.go`): agenda flags,
//! the transaction context checks layered over the standalone sanity
//! checks, proof-of-stake commitment checks, and the proof-of-work
//! sanity check spanning both hash versions.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_standalone::BigInt;
use dcroxide_wire::{MsgBlock, MsgTx, OutPoint, TxIn};

use crate::agendas::FullChainView;
use crate::ruleerror::{RuleError, RuleErrorKind, rule_error};

/// The minimum length a coinbase (and stakebase) signature script may
/// be (dcrd `MinCoinbaseScriptLen`).
pub const MIN_COINBASE_SCRIPT_LEN: usize = 2;

/// The maximum length a coinbase (and stakebase) signature script may
/// be (dcrd `MaxCoinbaseScriptLen`).
pub const MAX_COINBASE_SCRIPT_LEN: usize = 100;

/// Flags describing which agendas are treated as active during
/// validation (dcrd `AgendaFlags`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct AgendaFlags(pub u32);

impl AgendaFlags {
    /// The treasury agenda is active (dcrd `AFTreasuryEnabled`).
    pub const TREASURY_ENABLED: AgendaFlags = AgendaFlags(1 << 0);
    /// The explicit version upgrades agenda is active (dcrd
    /// `AFExplicitVerUpgrades`).
    pub const EXPLICIT_VER_UPGRADES: AgendaFlags = AgendaFlags(1 << 1);
    /// The automatic ticket revocations agenda is active (dcrd
    /// `AFAutoRevocationsEnabled`).
    pub const AUTO_REVOCATIONS_ENABLED: AgendaFlags = AgendaFlags(1 << 2);
    /// The DCP0010 modified subsidy split agenda is active (dcrd
    /// `AFSubsidySplitEnabled`).
    pub const SUBSIDY_SPLIT_ENABLED: AgendaFlags = AgendaFlags(1 << 3);
    /// The DCP0012 modified subsidy split agenda is active (dcrd
    /// `AFSubsidySplitR2Enabled`).
    pub const SUBSIDY_SPLIT_R2_ENABLED: AgendaFlags = AgendaFlags(1 << 4);

    fn has(self, flag: AgendaFlags) -> bool {
        self.0 & flag.0 != 0
    }

    /// Whether the treasury agenda flag is set (dcrd
    /// `IsTreasuryEnabled`).
    pub fn is_treasury_enabled(self) -> bool {
        self.has(AgendaFlags::TREASURY_ENABLED)
    }

    /// Whether the explicit version upgrades flag is set (dcrd
    /// `IsExplicitVerUpgradesEnabled`).
    pub fn is_explicit_ver_upgrades_enabled(self) -> bool {
        self.has(AgendaFlags::EXPLICIT_VER_UPGRADES)
    }

    /// Whether the automatic revocations flag is set (dcrd
    /// `IsAutoRevocationsEnabled`).
    pub fn is_auto_revocations_enabled(self) -> bool {
        self.has(AgendaFlags::AUTO_REVOCATIONS_ENABLED)
    }

    /// Whether the DCP0010 subsidy split flag is set (dcrd
    /// `IsSubsidySplitEnabled`).
    pub fn is_subsidy_split_enabled(self) -> bool {
        self.has(AgendaFlags::SUBSIDY_SPLIT_ENABLED)
    }

    /// Whether the DCP0012 subsidy split flag is set (dcrd
    /// `IsSubsidySplitR2Enabled`).
    pub fn is_subsidy_split_r2_enabled(self) -> bool {
        self.has(AgendaFlags::SUBSIDY_SPLIT_R2_ENABLED)
    }

    /// Combine flag sets.
    pub fn with(self, other: AgendaFlags) -> AgendaFlags {
        AgendaFlags(self.0 | other.0)
    }
}

/// Whether the outpoint is the null outpoint (dcrd validate.go
/// `isNullOutpoint`: zero hash, max index, regular tree).
pub fn is_null_outpoint(out: &OutPoint) -> bool {
    out.index == u32::MAX && out.hash == Hash::ZERO && out.tree == 0
}

/// Whether the input's fraud proof fields are the null sentinels (dcrd
/// `isNullFraudProof`).
pub fn is_null_fraud_proof(tx_in: &TxIn) -> bool {
    tx_in.block_height == 0 && tx_in.block_index == u32::MAX
}

/// The context-dependent (agenda-driven) transaction checks layered
/// over the standalone sanity checks (dcrd `checkTransactionContext`).
pub fn check_transaction_context(
    tx: &MsgTx,
    params: &Params,
    flags: AgendaFlags,
) -> Result<(), RuleError> {
    let is_treasury_enabled = flags.is_treasury_enabled();
    let explicit_upgrades_active = flags.is_explicit_ver_upgrades_enabled();
    let is_auto_revocations_enabled = flags.is_auto_revocations_enabled();

    // Reject transactions with a version beyond the highest currently
    // defined when the explicit version upgrades agenda is active.
    let max_allowed_tx_ver: u16 = if explicit_upgrades_active {
        3
    } else {
        u16::MAX
    };
    if tx.version > max_allowed_tx_ver {
        return Err(rule_error(
            RuleErrorKind::TxVersionTooHigh,
            format!(
                "transaction version {} is greater than the max allowed version {})",
                tx.version, max_allowed_tx_ver
            ),
        ));
    }

    // Determine the type of the transaction.
    let mut is_coin_base = false;
    let mut is_vote = false;
    let mut is_ticket = false;
    let mut is_revocation = false;
    let mut is_treasury_base = false;
    let mut is_treasury_add = false;
    let mut is_treasury_spend = false;
    match dcroxide_stake::determine_tx_type(tx) {
        dcroxide_stake::TxType::SSGen => is_vote = true,
        dcroxide_stake::TxType::SStx => is_ticket = true,
        dcroxide_stake::TxType::SSRtx => is_revocation = true,
        dcroxide_stake::TxType::TreasuryBase => is_treasury_base = true,
        dcroxide_stake::TxType::TAdd => is_treasury_add = true,
        dcroxide_stake::TxType::TSpend => is_treasury_spend = true,
        _ => is_coin_base = dcroxide_standalone::is_coin_base_tx(tx, is_treasury_enabled),
    }

    let mut fell_through_to_default = false;
    if is_vote {
        // The ticket reference hash in stakebase transactions must not
        // be null.
        let slen = tx.tx_in[0].signature_script.len();
        if !(MIN_COINBASE_SCRIPT_LEN..=MAX_COINBASE_SCRIPT_LEN).contains(&slen) {
            return Err(rule_error(
                RuleErrorKind::BadStakebaseScriptLen,
                format!(
                    "stakebase transaction script length of {slen} is out of range \
                     (min: {MIN_COINBASE_SCRIPT_LEN}, max: {MAX_COINBASE_SCRIPT_LEN})"
                ),
            ));
        }
        if tx.tx_in[0].signature_script != params.stake_base_sig_script {
            return Err(rule_error(
                RuleErrorKind::BadStakebaseScrVal,
                format!(
                    "stakebase transaction signature script was set to disallowed value \
                     (got {:x?}, want {:x?})",
                    tx.tx_in[0].signature_script, params.stake_base_sig_script
                ),
            ));
        }
        if is_null_outpoint(&tx.tx_in[1].previous_out_point) {
            return Err(rule_error(
                RuleErrorKind::BadTxInput,
                "vote ticket input refers to previous output that is null",
            ));
        }
    } else if is_revocation {
        // Auto revocations require the specific transaction version.
        if is_auto_revocations_enabled && tx.version != dcroxide_stake::TX_VERSION_AUTO_REVOCATIONS
        {
            return Err(rule_error(
                RuleErrorKind::InvalidRevocationTxVersion,
                format!(
                    "revocation transaction version is {} instead of {}",
                    tx.version,
                    dcroxide_stake::TX_VERSION_AUTO_REVOCATIONS
                ),
            ));
        }
    } else if is_coin_base {
        let prev_out = &tx.tx_in[0].previous_out_point;
        if !is_null_outpoint(prev_out) {
            return Err(rule_error(
                RuleErrorKind::BadCoinbaseOutpoint,
                "coinbase transaction does not have a null outpoint",
            ));
        }
        if !is_null_fraud_proof(&tx.tx_in[0]) {
            return Err(rule_error(
                RuleErrorKind::BadCoinbaseFraudProof,
                "coinbase transaction fraud proof is non-null",
            ));
        }
        let slen = tx.tx_in[0].signature_script.len();
        if !(MIN_COINBASE_SCRIPT_LEN..=MAX_COINBASE_SCRIPT_LEN).contains(&slen) {
            return Err(rule_error(
                RuleErrorKind::BadCoinbaseScriptLen,
                format!(
                    "coinbase transaction script length of {slen} is out of range \
                     (min: {MIN_COINBASE_SCRIPT_LEN}, max: {MAX_COINBASE_SCRIPT_LEN})"
                ),
            ));
        }
    } else if is_treasury_base {
        if !is_null_outpoint(&tx.tx_in[0].previous_out_point) {
            return Err(rule_error(
                RuleErrorKind::BadTreasurybaseOutpoint,
                "treasurybase transaction does not have a null outpoint",
            ));
        }
        if !is_null_fraud_proof(&tx.tx_in[0]) {
            return Err(rule_error(
                RuleErrorKind::BadTreasurybaseFraudProof,
                "treasurybase transaction fraud proof is non-null",
            ));
        }
        let slen = tx.tx_in[0].signature_script.len();
        if slen != 0 {
            return Err(rule_error(
                RuleErrorKind::BadTreasurybaseScriptLen,
                format!("treasurybase transaction script length is not zero: {slen}"),
            ));
        }
    } else if is_treasury_spend {
        if !is_null_outpoint(&tx.tx_in[0].previous_out_point) {
            return Err(rule_error(
                RuleErrorKind::BadTSpendOutpoint,
                "treasury spend transaction does not have a null outpoint",
            ));
        }
        if !is_null_fraud_proof(&tx.tx_in[0]) {
            return Err(rule_error(
                RuleErrorKind::BadTSpendFraudProof,
                "treasury spend transaction fraud proof is non-null",
            ));
        }
        let slen = tx.tx_in[0].signature_script.len();
        if slen != dcroxide_stake::TSPEND_SCRIPT_LEN {
            return Err(rule_error(
                RuleErrorKind::BadTSpendScriptLen,
                format!(
                    "treasury spend transaction script length of {slen} is invalid \
                     (required: {})",
                    dcroxide_stake::TSPEND_SCRIPT_LEN
                ),
            ));
        }
    } else {
        if is_treasury_add {
            // Verify there is a change output that it is non-zero (a
            // zero-valued change output is disallowed).
            if tx.tx_out.len() == 2 && tx.tx_out[1].value == 0 {
                return Err(rule_error(
                    RuleErrorKind::InvalidTAddChange,
                    "treasury add transaction change cannot be 0",
                ));
            }
            // dcrd falls through to the default arm.
        }
        fell_through_to_default = true;
    }

    if fell_through_to_default {
        // Previous transaction outputs referenced by the inputs to
        // this transaction must not be null.
        for (tx_in_idx, tx_in) in tx.tx_in.iter().enumerate() {
            if is_null_outpoint(&tx_in.previous_out_point) {
                return Err(rule_error(
                    RuleErrorKind::BadTxInput,
                    format!(
                        "transaction input {tx_in_idx} refers to previous output that \
                         is null"
                    ),
                ));
            }
        }
    }

    // Perform additional checks on regular transactions.
    let is_stake_tx = is_vote
        || is_ticket
        || is_revocation
        || is_treasury_add
        || is_treasury_spend
        || is_treasury_base;
    if !is_stake_tx {
        // Reject regular transaction output scripts with a version
        // beyond the highest currently defined when the explicit
        // version upgrades agenda is active.
        let max_allowed_script_ver: u16 = if explicit_upgrades_active {
            0
        } else {
            u16::MAX
        };
        for (tx_out_idx, tx_out) in tx.tx_out.iter().enumerate() {
            if tx_out.version > max_allowed_script_ver {
                return Err(rule_error(
                    RuleErrorKind::ScriptVersionTooHigh,
                    format!(
                        "script version {} is greater than the max allowed version {})",
                        tx_out.version, max_allowed_script_ver
                    ),
                ));
            }

            // Check for stake opcodes in regular transaction outputs.
            match dcroxide_txscript::contains_stake_op_codes(&tx_out.pk_script, is_treasury_enabled)
            {
                Err(e) => {
                    return Err(rule_error(RuleErrorKind::ScriptMalformed, format!("{e}")));
                }
                Ok(true) => {
                    return Err(rule_error(
                        RuleErrorKind::RegTxCreateStakeOut,
                        format!(
                            "non-stake transaction output {tx_out_idx} contains stake \
                             opcode"
                        ),
                    ));
                }
                Ok(false) => {}
            }
        }
    }

    Ok(())
}

/// Map a standalone rule error onto the corresponding chain rule error
/// (dcrd `standaloneToChainRuleError`).
fn standalone_to_chain_rule_error(err: dcroxide_standalone::RuleError) -> RuleError {
    use dcroxide_standalone::ErrorKind as SK;
    let kind = match err.kind {
        SK::UnexpectedDifficulty => RuleErrorKind::UnexpectedDifficulty,
        SK::HighHash => RuleErrorKind::HighHash,
        SK::NoTxInputs => RuleErrorKind::NoTxInputs,
        SK::NoTxOutputs => RuleErrorKind::NoTxOutputs,
        SK::TxTooBig => RuleErrorKind::TxTooBig,
        SK::BadTxOutValue => RuleErrorKind::BadTxOutValue,
        SK::DuplicateTxInputs => RuleErrorKind::DuplicateTxInputs,
        // The standalone tspend expiry kind has no chain counterpart
        // in this mapping; dcrd passes such errors through unchanged,
        // which cannot occur via the sanity checks used here.
        SK::InvalidTSpendExpiry => {
            unreachable!("tspend expiry errors do not flow through sanity checks")
        }
    };
    RuleError {
        kind,
        description: err.description,
    }
}

/// Perform context-free sanity checks plus the agenda-driven context
/// checks on a transaction (dcrd `CheckTransaction`).
pub fn check_transaction(tx: &MsgTx, params: &Params, flags: AgendaFlags) -> Result<(), RuleError> {
    dcroxide_standalone::check_transaction_sanity(tx, params.max_tx_size as u64)
        .map_err(standalone_to_chain_rule_error)?;
    check_transaction_context(tx, params, flags)
}

/// Ensure ticket purchases in the block commit at least the stake
/// difficulty specified by the header and the network minimum (dcrd
/// `CheckProofOfStake`).
pub fn check_proof_of_stake(block: &MsgBlock, pos_limit: i64) -> Result<(), RuleError> {
    for stake_tx in &block.stransactions {
        if dcroxide_stake::is_sstx(stake_tx) {
            let commit_value = stake_tx.tx_out[0].value;

            // Check for underflow.
            if commit_value < block.header.sbits {
                return Err(rule_error(
                    RuleErrorKind::NotEnoughStake,
                    format!(
                        "Stake tx {} has a commitment value less than the minimum stake \
                         difficulty specified in the block ({})",
                        stake_tx.tx_hash(),
                        block.header.sbits
                    ),
                ));
            }

            // Check to make sure they meet the minimum given by the
            // network.
            if commit_value < pos_limit {
                return Err(rule_error(
                    RuleErrorKind::StakeBelowMinimum,
                    format!(
                        "Stake tx {} has a commitment value less than the minimum stake \
                         difficulty for the network ({pos_limit})",
                        stake_tx.tx_hash()
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// Ensure the header's proof of work is sane: in range, and — unless
/// the skip flag is set — meeting the claimed target under either hash
/// version (dcrd `checkProofOfWorkSanity`).  The BLAKE3 hash is only
/// consulted when the BLAKE-256 hash fails, exactly like dcrd, since
/// the header alone cannot say which agenda applies.
pub fn check_proof_of_work_sanity(
    header: &dcroxide_wire::BlockHeader,
    pow_limit: &BigInt,
    skip_pow_check: bool,
) -> Result<(), RuleError> {
    if skip_pow_check {
        return dcroxide_standalone::check_proof_of_work_range(header.bits, pow_limit)
            .map_err(standalone_to_chain_rule_error);
    }

    let pow_hash_v1 = header.pow_hash_v1();
    let mut result = dcroxide_standalone::check_proof_of_work(&pow_hash_v1, header.bits, pow_limit);
    if result.is_err() {
        let pow_hash_v2 = header.pow_hash_v2();
        result = dcroxide_standalone::check_proof_of_work(&pow_hash_v2, header.bits, pow_limit);
    }
    result.map_err(standalone_to_chain_rule_error)
}

/// The maximum number of seconds a block time is allowed to be ahead
/// of the current time (dcrd `MaxTimeOffsetSeconds`).
pub const MAX_TIME_OFFSET_SECONDS: i64 = 2 * 60 * 60;

/// The expected vote bits before stake validation height (dcrd
/// `earlyVoteBitsValue`).
const EARLY_VOTE_BITS_VALUE: u16 = 0x0001;

/// The expected final state before stake validation height (dcrd
/// `earlyFinalState`).
const EARLY_FINAL_STATE: [u8; 6] = [0; 6];

/// Perform context-free sanity checks on a block header (dcrd
/// `checkBlockHeaderSanity`).  The adjusted time replaces dcrd's
/// `MedianTimeSource`; the sub-second timestamp precision check is
/// omitted because the wire timestamp is whole seconds by type.
pub fn check_block_header_sanity(
    header: &dcroxide_wire::BlockHeader,
    adjusted_time_unix: i64,
    skip_pow_check: bool,
    params: &Params,
) -> Result<(), RuleError> {
    let stake_validation_height = params.stake_validation_height as u32;
    let stake_enabled_height = params.stake_enabled_height as u32;
    assert!(
        stake_enabled_height <= stake_validation_height,
        "checkBlockHeaderSanity called with stake enabled height after stake \
         validation height"
    );

    // Ensure the proof of work bits in the block header is in min/max
    // range and the block hash is less than the target value described
    // by the bits.
    let pow_limit = BigInt::from_bytes_be(
        dcroxide_standalone::Sign::Plus,
        &params.pow_limit.to_be_bytes(),
    );
    check_proof_of_work_sanity(header, &pow_limit, skip_pow_check)?;

    // Ensure the block time is not too far in the future.
    let max_timestamp = adjusted_time_unix + MAX_TIME_OFFSET_SECONDS;
    if i64::from(header.timestamp) > max_timestamp {
        return Err(rule_error(
            RuleErrorKind::TimeTooNew,
            format!(
                "block timestamp of {} is too far in the future",
                header.timestamp
            ),
        ));
    }

    // Check that the node is submitting the expected header commitments
    // for the stake data before stake validation height.
    if header.height < stake_validation_height {
        if header.voters > 0 {
            return Err(rule_error(
                RuleErrorKind::InvalidEarlyStakeTx,
                format!(
                    "block at height {} commits to {} votes before stake validation \
                     height {stake_validation_height}",
                    header.height, header.voters
                ),
            ));
        }
        if header.revocations > 0 {
            return Err(rule_error(
                RuleErrorKind::InvalidEarlyStakeTx,
                format!(
                    "block at height {} commits to {} revocations before stake \
                     validation height {stake_validation_height}",
                    header.height, header.revocations
                ),
            ));
        }
        if header.vote_bits != EARLY_VOTE_BITS_VALUE {
            return Err(rule_error(
                RuleErrorKind::InvalidEarlyVoteBits,
                format!(
                    "block at height {} commits to invalid vote bits before stake \
                     validation height {stake_validation_height} (expected {:x}, got {:x})",
                    header.height, EARLY_VOTE_BITS_VALUE, header.vote_bits
                ),
            ));
        }
        if header.final_state != EARLY_FINAL_STATE {
            return Err(rule_error(
                RuleErrorKind::InvalidEarlyFinalState,
                format!(
                    "block at height {} commits to invalid final state before stake \
                     validation height {stake_validation_height}",
                    header.height
                ),
            ));
        }
    }

    // A block must not contain fewer votes than the minimum required
    // to reach majority once stake validation height has been reached.
    if header.height >= stake_validation_height {
        let majority = (params.tickets_per_block / 2) + 1;
        if header.voters < majority {
            return Err(rule_error(
                RuleErrorKind::NotEnoughVotes,
                format!(
                    "block does not commit to enough votes (min: {majority}, got {})",
                    header.voters
                ),
            ));
        }
    }

    // The block header must not claim to contain more votes than the
    // maximum allowed.
    if header.voters > params.tickets_per_block {
        return Err(rule_error(
            RuleErrorKind::TooManyVotes,
            format!(
                "block commits to too many votes (max: {}, got {})",
                params.tickets_per_block, header.voters
            ),
        ));
    }

    // A block must not contain more ticket purchases than the maximum
    // allowed.
    if header.fresh_stake > params.max_fresh_stake_per_block {
        return Err(rule_error(
            RuleErrorKind::TooManySStxs,
            format!(
                "block commits to too many ticket purchases (max: {}, got {})",
                params.max_fresh_stake_per_block, header.fresh_stake
            ),
        ));
    }

    Ok(())
}

/// Perform context-free sanity checks on a block and all of its
/// transactions (dcrd `checkBlockSanity`/`CheckBlockSanity`).
pub fn check_block_sanity(
    block: &MsgBlock,
    adjusted_time_unix: i64,
    skip_pow_check: bool,
    params: &Params,
) -> Result<(), RuleError> {
    let header = &block.header;
    check_block_header_sanity(header, adjusted_time_unix, skip_pow_check, params)?;

    // All ticket purchases via the stake tree must meet both the
    // stake difficulty committed by the header and the network
    // minimum.
    check_proof_of_stake(block, params.minimum_stake_diff)?;

    // A block must have at least one regular transaction.
    if block.transactions.is_empty() {
        return Err(rule_error(
            RuleErrorKind::NoTransactions,
            "block does not contain any transactions",
        ));
    }

    // A block must not exceed the maximum allowed block payload when
    // serialized, and the header commitment to its size must match.
    let serialized_size = block.serialize().len();
    if serialized_size > dcroxide_wire::MAX_BLOCK_PAYLOAD as usize {
        return Err(rule_error(
            RuleErrorKind::BlockTooBig,
            format!(
                "serialized block is too big - got {serialized_size}, max {}",
                dcroxide_wire::MAX_BLOCK_PAYLOAD
            ),
        ));
    }
    if header.size != serialized_size as u32 {
        return Err(rule_error(
            RuleErrorKind::WrongBlockSize,
            format!(
                "serialized block is not size indicated in header - got {}, \
                 expected {serialized_size}",
                header.size
            ),
        ));
    }

    // Perform preliminary sanity checks on each transaction.
    let max_tx_size = params.max_tx_size as u64;
    for tx in &block.transactions {
        dcroxide_standalone::check_transaction_sanity(tx, max_tx_size)
            .map_err(standalone_to_chain_rule_error)?;
    }
    let mut total_tickets: i64 = 0;
    for stx in &block.stransactions {
        dcroxide_standalone::check_transaction_sanity(stx, max_tx_size)
            .map_err(standalone_to_chain_rule_error)?;
        if dcroxide_stake::is_sstx(stx) {
            total_tickets += 1;
        }
    }

    // The number of tickets in the block must match the header
    // commitment.
    if i64::from(header.fresh_stake) != total_tickets {
        return Err(rule_error(
            RuleErrorKind::FreshStakeMismatch,
            format!(
                "block header commitment to {} ticket purchases does not match \
                 {total_tickets} contained in the block",
                header.fresh_stake
            ),
        ));
    }

    // Check for duplicate transactions.
    let mut existing_tx_hashes: alloc::collections::BTreeSet<[u8; 32]> =
        alloc::collections::BTreeSet::new();
    for tx in block.transactions.iter().chain(&block.stransactions) {
        let hash = tx.tx_hash();
        if !existing_tx_hashes.insert(hash.0) {
            return Err(rule_error(
                RuleErrorKind::DuplicateTx,
                format!("block contains duplicate transaction {hash}"),
            ));
        }
    }

    Ok(())
}

/// The vote bit indicating the regular transaction tree of the parent
/// block is valid (dcrd `dcrutil.BlockValid`).
const VOTE_BIT_BLOCK_VALID: u16 = 0x0001;

/// Whether the passed vote bits indicate the regular transaction tree
/// of the parent block should be considered valid (dcrd
/// `voteBitsApproveParent`).
pub fn vote_bits_approve_parent(vote_bits: u16) -> bool {
    vote_bits & VOTE_BIT_BLOCK_VALID != 0
}

/// Whether the vote bits in the passed header indicate the regular
/// transaction tree of the parent block should be considered valid
/// (dcrd `headerApprovesParent`).
pub fn header_approves_parent(header: &dcroxide_wire::BlockHeader) -> bool {
    vote_bits_approve_parent(header.vote_bits)
}

/// Whether the passed transaction is expired according to the given
/// block height (dcrd `IsExpiredTx`/`IsExpired`).
pub fn is_expired_tx(tx: &MsgTx, block_height: i64) -> bool {
    let expiry = tx.expiry;
    expiry != dcroxide_wire::NO_EXPIRY_VALUE && block_height >= i64::from(expiry)
}

/// Whether all of the inputs to a transaction have achieved a relative
/// age surpassing the requirements of the passed sequence lock (dcrd
/// `SequenceLockActive`).
pub fn sequence_lock_active(
    lock: &crate::sequencelock::SequenceLock,
    block_height: i64,
    median_time_unix: i64,
) -> bool {
    // The transaction is not yet mature if it has not yet reached the
    // required minimum time and block height according to its
    // sequence locks.
    !(block_height <= lock.min_height || median_time_unix <= lock.min_time)
}

/// Whether a transaction is finalized (dcrd `IsFinalizedTransaction`).
pub fn is_finalized_transaction(tx: &MsgTx, block_height: i64, block_time_unix: i64) -> bool {
    // Lock time of zero means the transaction is finalized.
    let lock_time = tx.lock_time;
    if lock_time == 0 {
        return true;
    }

    // The lock time field of a transaction is either a block height at
    // which the transaction is finalized or a timestamp depending on
    // if the value is before the txscript lock time threshold.  When
    // it is under the threshold it is a block height.
    let block_time_or_height = if i64::from(lock_time) < dcroxide_txscript::LOCK_TIME_THRESHOLD {
        block_height
    } else {
        block_time_unix
    };
    if i64::from(lock_time) < block_time_or_height {
        return true;
    }

    // At this point, the transaction's lock time hasn't occurred yet,
    // but the transaction might still be finalized if the sequence
    // number for all transaction inputs is maxed out.
    tx.tx_in.iter().all(|tx_in| tx_in.sequence == u32::MAX)
}

/// The five mainnet blocks known to violate DCP0005 and the testnet3
/// maximum-difficulty activation checkpoint, in internal byte order
/// (dcrd `block413762Hash` … `block962928Hash`).
const BLOCK_413762_HASH: Hash = Hash([
    0x7b, 0xc4, 0x08, 0x20, 0x98, 0xfa, 0x7e, 0x09, 0x3f, 0x00, 0x7b, 0x56, 0x3e, 0x8f, 0xfa, 0x3b,
    0x6f, 0x54, 0x2a, 0xf6, 0x61, 0xed, 0x86, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);
const BLOCK_414036_HASH: Hash = Hash([
    0x87, 0x23, 0x59, 0xd9, 0x31, 0xaa, 0xb2, 0xf1, 0xe8, 0xd6, 0x16, 0xc7, 0xe0, 0x3d, 0xb2, 0xec,
    0x88, 0xe9, 0xb9, 0x10, 0x93, 0xa5, 0x4f, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);
const BLOCK_424011_HASH: Hash = Hash([
    0x72, 0xd5, 0x02, 0x2b, 0x73, 0xa3, 0x50, 0x00, 0x62, 0x1d, 0xb8, 0x6e, 0xc9, 0xa9, 0xdf, 0xe7,
    0x8b, 0x57, 0xa6, 0xa8, 0xc7, 0xc6, 0x7f, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);
const BLOCK_428809_HASH: Hash = Hash([
    0xaa, 0x4a, 0xe3, 0x1e, 0x87, 0x9a, 0x80, 0x33, 0x4e, 0x8f, 0x4d, 0x93, 0xc7, 0xb1, 0x0f, 0x42,
    0xaa, 0xec, 0xfc, 0xcf, 0x8c, 0x79, 0x47, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);
const BLOCK_430191_HASH: Hash = Hash([
    0x8e, 0xa8, 0x90, 0x06, 0xbb, 0x88, 0x03, 0x65, 0x42, 0x7e, 0x41, 0x9b, 0x58, 0x44, 0x63, 0x6f,
    0xc1, 0x0c, 0xb3, 0x4c, 0x6d, 0xad, 0x27, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);
const BLOCK_962928_HASH: Hash = Hash([
    0x93, 0x3b, 0xe2, 0x02, 0x60, 0xe5, 0x00, 0x86, 0x16, 0x76, 0x67, 0x6f, 0x8e, 0x53, 0x24, 0x78,
    0x13, 0x57, 0xf5, 0x6f, 0x45, 0x1d, 0x11, 0x39, 0xfd, 0x67, 0xb2, 0xd1, 0x4f, 0x00, 0x00, 0x00,
]);

/// The DCP0005 hash constants in dump order, exposed so the parity
/// vectors can pin the exact bytes against dcrd's literals.
pub fn dcp0005_constants() -> [(&'static str, Hash); 6] {
    [
        ("block413762", BLOCK_413762_HASH),
        ("block414036", BLOCK_414036_HASH),
        ("block424011", BLOCK_424011_HASH),
        ("block428809", BLOCK_428809_HASH),
        ("block430191", BLOCK_430191_HASH),
        ("block962928", BLOCK_962928_HASH),
    ]
}

/// Whether the given block is exempt from the "old block version by
/// majority" rejection due to violating DCP0005 before it activated
/// (dcrd `isDCP0005Violation`).
pub fn is_dcp0005_violation(
    net: dcroxide_wire::CurrencyNet,
    header: &dcroxide_wire::BlockHeader,
    block_hash: &Hash,
) -> bool {
    match net {
        dcroxide_wire::CurrencyNet::MAIN_NET => {
            // All blocks that violated DCP0005 on mainnet are version 6
            // and the height of the last block that violated it is
            // 430191.
            if header.version != 6 || header.height > 430191 {
                return false;
            }

            // Whether the block is any of the five mainnet blocks that
            // are known to violate DCP0005.
            header.height == 413762 && *block_hash == BLOCK_413762_HASH
                || header.height == 414036 && *block_hash == BLOCK_414036_HASH
                || header.height == 424011 && *block_hash == BLOCK_424011_HASH
                || header.height == 428809 && *block_hash == BLOCK_428809_HASH
                || header.height == 430191 && *block_hash == BLOCK_430191_HASH
        }
        dcroxide_wire::CurrencyNet::TEST_NET3 => {
            // All blocks that violated DCP0005 on testnet are version 7
            // and the height of the last block that violated it is
            // 323282; the version check is not enforced until after
            // that point.
            header.version == 7 && header.height <= 323282
        }
        _ => false,
    }
}

/// Whether the block version specified by the provided header should
/// be rejected due to a majority of the network already being upgraded
/// to a newer version (dcrd `isOldBlockVersionByMajority`).
pub fn is_old_block_version_by_majority(
    view: &impl FullChainView,
    header: &dcroxide_wire::BlockHeader,
    block_hash: &Hash,
    prev_height: i64,
    params: &Params,
) -> bool {
    // The latest block version for all networks other than the main
    // network is one higher.
    let mut latest_block_version: i32 = 11;
    if params.net != dcroxide_wire::CurrencyNet::MAIN_NET {
        latest_block_version += 1;
    }

    // Blocks with a version greater than or equal to the latest
    // enforced block version are most certainly not an old version.
    if header.version >= latest_block_version {
        return false;
    }

    // Skip the version check for blocks that are known to violate
    // DCP0005.
    if is_dcp0005_violation(params.net, header, block_hash) {
        return false;
    }

    // The block version is considered old once the majority of the
    // network has upgraded to a more recent version.
    let next_version = header.version + 1;
    crate::stakever::is_majority_version(
        &crate::sequencelock::AsVersionView(view),
        next_version,
        Some(prev_height),
        params.block_reject_num_required,
        params,
    )
}

/// The minimum block version from which the BLAKE3 proof of work
/// agenda (DCP0011) could possibly be active.
fn min_blake3_block_version(params: &Params) -> u32 {
    if params.net == dcroxide_wire::CurrencyNet::MAIN_NET {
        10
    } else {
        11
    }
}

/// Ensure the difficulty specified in the block header matches the
/// calculated difficulty based on the difficulty retarget rules, from
/// the positional point of view (dcrd `checkDifficultyPositional`).
///
/// Whether the BLAKE3 proof of work agenda is active cannot be
/// determined in the general case here, so valid difficulty bits are
/// allowed under both algorithms (rejecting blocks that satisfy
/// neither) and the contextual checks that happen later pin the
/// correct algorithm.  dcrd additionally consults two cached anchors:
/// the confirmed anchor its contextual checks store (an engine fast
/// path that arrives with the chain engine) and a candidate-anchor
/// cache that only short-circuits the successful search below; neither
/// is reproduced here.
pub fn check_difficulty_positional(
    view: &impl FullChainView,
    header: &dcroxide_wire::BlockHeader,
    prev_node: &crate::difficulty::DiffNode,
    params: &Params,
) -> Result<(), RuleError> {
    // Ensure the difficulty matches the calculated difficulty using
    // the algorithm defined in DCP0011 when the BLAKE3 proof of work
    // agenda is always active.
    if crate::agendas::is_blake3_pow_agenda_forced_active(params) {
        let blake3_diff = crate::agendas::calc_next_blake3_diff(view, prev_node, params);
        if header.bits != blake3_diff {
            return Err(rule_error(
                RuleErrorKind::UnexpectedDifficulty,
                format!(
                    "block difficulty of {} is not the expected value of {blake3_diff} \
                     (difficulty algorithm: ASERT)",
                    header.bits
                ),
            ));
        }
        return Ok(());
    }

    // Only the original difficulty algorithm needs to be checked when
    // it is impossible for the BLAKE3 proof of work agenda to be
    // active or the block is not solved for BLAKE3.  Since the always
    // active case is handled above, the only remaining way for the
    // agenda to be active is a vote, which requires the stake
    // validation height, one interval of voting, and one interval of
    // being locked in.
    let is_solved_blake3 = {
        let pow_hash = header.pow_hash_v2();
        dcroxide_standalone::check_proof_of_work_hash(&pow_hash, header.bits).is_ok()
    };
    let rcai = i64::from(params.rule_change_activation_interval);
    let svh = params.stake_validation_height;
    let first_possible_activation_height = svh + rcai * 2;
    let min_blake3_version = min_blake3_block_version(params);
    // Note dcrd converts the signed header version, so negative
    // versions wrap to large values here.
    let is_blake3_possibly_active = header.version as u32 >= min_blake3_version
        && i64::from(header.height) >= first_possible_activation_height;
    if !is_blake3_possibly_active || !is_solved_blake3 {
        let blake256_diff = crate::difficulty::calc_next_blake256_diff(
            view,
            prev_node,
            i64::from(header.timestamp),
            params,
        );
        if header.bits != blake256_diff {
            return Err(rule_error(
                RuleErrorKind::UnexpectedDifficulty,
                format!(
                    "block difficulty of {} is not the expected value of {blake256_diff} \
                     (difficulty algorithm: EMA)",
                    header.bits
                ),
            ));
        }
        return Ok(());
    }

    // The agenda might possibly be active and the block is solved with
    // BLAKE3, so iterate backwards one rule change activation interval
    // at a time through all possible candidate anchors (the final
    // blocks of previous intervals with a sufficient block version)
    // until one of them results in a matching required difficulty.
    let mut candidate_height =
        crate::stakever::calc_want_height(svh, rcai, i64::from(header.height));
    while candidate_height >= 0 && candidate_height <= prev_node.height {
        let (Some(candidate), Some(candidate_vote)) = (
            crate::difficulty::ChainView::node(view, candidate_height),
            view.vote_node(candidate_height),
        ) else {
            break;
        };
        if (candidate_vote.node.block_version as u32) < min_blake3_version
            || candidate.height < first_possible_activation_height - 1
        {
            break;
        }
        let blake3_diff =
            crate::difficulty::calc_next_blake3_diff_from_anchor(prev_node, &candidate, params);
        if header.bits == blake3_diff {
            return Ok(());
        }
        candidate_height -= rcai;
    }

    // None of the possible difficulties for BLAKE3 matched, so the
    // agenda is very likely not actually active and the only remaining
    // valid option is the original difficulty algorithm.
    let blake256_diff = crate::difficulty::calc_next_blake256_diff(
        view,
        prev_node,
        i64::from(header.timestamp),
        params,
    );
    if header.bits != blake256_diff {
        return Err(rule_error(
            RuleErrorKind::UnexpectedDifficulty,
            format!(
                "block difficulty of {} is not the expected value of {blake256_diff} \
                 (difficulty algorithm: EMA)",
                header.bits
            ),
        ));
    }

    Ok(())
}

/// Perform the validation checks on the block header which depend on
/// its position within the block chain and having the headers of all
/// ancestors available (dcrd `checkBlockHeaderPositional`).  A `None`
/// previous height means the genesis block, which is valid by
/// definition.  `fast_add` corresponds to dcrd's `BFFastAdd` flag.
///
/// dcrd's fork rejection checkpoint check is deferred until the block
/// index arrives with the chain engine.
pub fn check_block_header_positional(
    view: &impl FullChainView,
    header: &dcroxide_wire::BlockHeader,
    prev_height: Option<i64>,
    fast_add: bool,
    params: &Params,
) -> Result<(), RuleError> {
    // The genesis block is valid by definition.
    let Some(prev_height) = prev_height else {
        return Ok(());
    };
    let prev_node = crate::difficulty::ChainView::node(view, prev_height).expect("prev node");

    if !fast_add {
        // Ensure the timestamp for the block header is after the
        // median time of the last several blocks.
        let median_time = crate::stakever::calc_past_median_time(
            &crate::sequencelock::AsVersionView(view),
            prev_height,
        );
        if i64::from(header.timestamp) <= median_time {
            return Err(rule_error(
                RuleErrorKind::TimeTooOld,
                format!(
                    "block timestamp of {} is not after expected {median_time}",
                    header.timestamp
                ),
            ));
        }

        // A block on the test network must have a timestamp that is at
        // least one minute after the previous one once the maximum
        // allowed difficulty has been reached.  This rule is only
        // active on the version 3 test network once the max diff
        // activation height has been reached (dcrd only computes the
        // minimum target there as well).
        let block_height = prev_node.height + 1;
        if crate::difficulty::is_testnet3(params) {
            let min_testnet_target = BigInt::from_bytes_be(
                dcroxide_standalone::Sign::Plus,
                &params.pow_limit.to_be_bytes(),
            ) >> 6u32;
            let min_testnet_diff_bits = dcroxide_standalone::big_to_compact(&min_testnet_target);
            if header.bits <= min_testnet_diff_bits
                && block_height >= crate::difficulty::TESTNET3_MAX_DIFF_ACTIVATION_HEIGHT
            {
                let min_time = prev_node.timestamp + 60;
                if i64::from(header.timestamp) < min_time {
                    return Err(rule_error(
                        RuleErrorKind::TimeTooOld,
                        format!(
                            "testnet block timestamp of {} is before required {min_time}",
                            header.timestamp
                        ),
                    ));
                }
            }
        }

        // Ensure the difficulty specified in the block header matches
        // the calculated difficulty based on the retarget rules.
        check_difficulty_positional(view, header, &prev_node, params)?;
    }

    // The height of this block is one more than the referenced
    // previous block, and the header must commit to it.
    let block_height = prev_node.height + 1;
    if i64::from(header.height) != block_height {
        return Err(rule_error(
            RuleErrorKind::BadBlockHeight,
            format!(
                "block header commitment to height {} does not match chain height \
                 {block_height}",
                header.height
            ),
        ));
    }

    // dcrd prevents blocks that fork the main chain before its fork
    // rejection checkpoint here; that check requires the block index
    // and arrives with the chain engine.

    // Reject version 3 test network chains that are not specifically
    // the chain used to activate maximum difficulty semantics.
    let block_hash = header.block_hash();
    if crate::difficulty::is_testnet3(params)
        && block_height == crate::difficulty::TESTNET3_MAX_DIFF_ACTIVATION_HEIGHT
        && block_hash != BLOCK_962928_HASH
    {
        return Err(rule_error(
            RuleErrorKind::BadMaxDiffCheckpoint,
            format!("block at height {block_height} does not match checkpoint hash"),
        ));
    }

    if !fast_add {
        // Reject old version blocks once a majority of the network has
        // upgraded.
        if is_old_block_version_by_majority(view, header, &block_hash, prev_height, params) {
            return Err(rule_error(
                RuleErrorKind::BlockVersionTooOld,
                format!(
                    "new blocks with version {} are no longer valid",
                    header.version
                ),
            ));
        }
    }

    Ok(())
}

/// Perform the validation checks on the block data (not including the
/// header) which depend on its position within the block chain (dcrd
/// `checkBlockDataPositional`).
pub fn check_block_data_positional(
    block: &MsgBlock,
    prev_height: Option<i64>,
    fast_add: bool,
) -> Result<(), RuleError> {
    // The genesis block is valid by definition.
    let Some(prev_height) = prev_height else {
        return Ok(());
    };

    if !fast_add {
        // Ensure all transactions in the block are not expired.
        let block_height = prev_height + 1;
        for tx in &block.transactions {
            if is_expired_tx(tx, block_height) {
                return Err(rule_error(
                    RuleErrorKind::ExpiredTx,
                    format!(
                        "block contains expired regular transaction {} (expiration \
                         height {})",
                        tx.tx_hash(),
                        tx.expiry
                    ),
                ));
            }
        }
        for stx in &block.stransactions {
            if is_expired_tx(stx, block_height) {
                return Err(rule_error(
                    RuleErrorKind::ExpiredTx,
                    format!(
                        "block contains expired stake transaction {} (expiration \
                         height {})",
                        stx.tx_hash(),
                        stx.expiry
                    ),
                ));
            }
        }
    }

    Ok(())
}

/// Perform the validation checks on the block (both its header and
/// data) which depend on its position within the block chain and
/// having the headers of all ancestors available (dcrd
/// `checkBlockPositional`).
pub fn check_block_positional(
    view: &impl FullChainView,
    block: &MsgBlock,
    prev_height: Option<i64>,
    fast_add: bool,
    params: &Params,
) -> Result<(), RuleError> {
    // The genesis block is valid by definition.
    if prev_height.is_none() {
        return Ok(());
    }

    check_block_header_positional(view, &block.header, prev_height, fast_add, params)?;
    check_block_data_positional(block, prev_height, fast_add)
}

/// The maximum number of bytes allowed in the pushed data output of
/// the coinbase output that is used to ensure the coinbase has a
/// unique hash (dcrd `maxUniqueCoinbaseNullDataSize`).
pub const MAX_UNIQUE_COINBASE_NULL_DATA_SIZE: usize = 256;

/// Ensure the proof of work hash is less than the target difficulty
/// indicated by the header difficulty bits, choosing the hash
/// algorithm by the state of the DCP0011 BLAKE3 agenda (dcrd
/// `checkProofOfWorkContext`).  The target range is already handled by
/// the sanity checks.  `no_pow_check` corresponds to dcrd's
/// `BFNoPoWCheck` flag.
pub fn check_proof_of_work_context(
    view: &impl FullChainView,
    header: &dcroxide_wire::BlockHeader,
    prev_height: i64,
    no_pow_check: bool,
    params: &Params,
) -> Result<(), RuleError> {
    // Nothing to do when the flag to avoid proof of work checks is
    // set.
    if no_pow_check {
        return Ok(());
    }

    // Choose the proof of work mining algorithm based on the result of
    // the vote for the blake3 proof of work agenda.
    let is_blake3_active =
        crate::agendas::is_blake3_pow_agenda_active(view, Some(prev_height), params).map_err(
            |_| {
                rule_error(
                    RuleErrorKind::UnknownDeploymentID,
                    "blake3 pow deployment not defined on this network",
                )
            },
        )?;
    let pow_hash = if is_blake3_active {
        header.pow_hash_v2()
    } else {
        header.pow_hash_v1()
    };
    dcroxide_standalone::check_proof_of_work_hash(&pow_hash, header.bits)
        .map_err(standalone_to_chain_rule_error)
}

/// Perform the validation checks on the block header which depend on
/// having the full block data for all of its ancestors available,
/// which includes checks that depend on tallying votes (dcrd
/// `checkBlockHeaderContext`).  A `None` previous height means the
/// genesis block, which is valid by definition.
///
/// The header's pool size and ticket lottery final state commitments
/// are checked against the parent's stake node state, which the
/// caller supplies (dcrd fetches it via `fetchStakeNode`).
#[allow(clippy::too_many_arguments)]
pub fn check_block_header_context(
    view: &impl FullChainView,
    header: &dcroxide_wire::BlockHeader,
    prev_height: Option<i64>,
    fast_add: bool,
    no_pow_check: bool,
    parent_pool_size: u32,
    parent_final_state: [u8; 6],
    params: &Params,
) -> Result<(), RuleError> {
    // The genesis block is valid by definition.
    let Some(prev_height) = prev_height else {
        return Ok(());
    };

    // Ensure the proof of work hash is less than the target value
    // described by the bits using the correct hash algorithm; the bits
    // have already been validated to be in range by the sanity checks.
    check_proof_of_work_context(view, header, prev_height, no_pow_check, params)?;

    if !fast_add {
        let prev_node = crate::difficulty::ChainView::node(view, prev_height).expect("prev node");

        // Ensure the difficulty specified in the block header matches
        // the calculated difficulty based on the previous block and
        // difficulty retarget rules.
        let exp_diff = crate::agendas::calc_next_required_difficulty(
            view,
            &prev_node,
            i64::from(header.timestamp),
            params,
        )
        .map_err(|_| {
            rule_error(
                RuleErrorKind::UnknownDeploymentID,
                "blake3 pow deployment not defined on this network",
            )
        })?;
        if header.bits != exp_diff {
            return Err(rule_error(
                RuleErrorKind::UnexpectedDifficulty,
                format!(
                    "block difficulty of {} is not the expected value of {exp_diff}",
                    header.bits
                ),
            ));
        }

        // Ensure the stake difficulty specified in the block header
        // matches the calculated difficulty based on the previous
        // block and difficulty retarget rules.
        let exp_sdiff =
            crate::agendas::calc_next_required_stake_difficulty(view, Some(&prev_node), params);
        if header.sbits != exp_sdiff {
            return Err(rule_error(
                RuleErrorKind::UnexpectedDifficulty,
                format!(
                    "block stake difficulty of {} is not the expected value of {exp_sdiff}",
                    header.sbits
                ),
            ));
        }

        // Enforce the stake version in the header once a majority of
        // the network has upgraded to version 3 blocks.
        if header.version >= 3
            && crate::stakever::is_majority_version(
                &crate::sequencelock::AsVersionView(view),
                3,
                Some(prev_height),
                params.block_enforce_num_required,
                params,
            )
        {
            let expected_stake_ver = crate::stakever::calc_stake_version(
                &crate::sequencelock::AsVersionView(view),
                prev_height,
                params,
            );
            if header.stake_version != expected_stake_ver {
                return Err(rule_error(
                    RuleErrorKind::BadStakeVersion,
                    format!(
                        "block stake version of {} is not the expected version of \
                         {expected_stake_ver}",
                        header.stake_version
                    ),
                ));
            }
        }

        // Ensure the header commits to the correct pool size based on
        // its position within the chain.
        if header.pool_size != parent_pool_size {
            return Err(rule_error(
                RuleErrorKind::PoolSize,
                format!(
                    "block header commitment to pool size {} does not match expected \
                     size {parent_pool_size}",
                    header.pool_size
                ),
            ));
        }

        // Ensure the header commits to the correct final state of the
        // ticket lottery.
        if header.final_state != parent_final_state {
            return Err(rule_error(
                RuleErrorKind::InvalidFinalState,
                format!(
                    "block header commitment to final state of the ticket lottery \
                     {:x?} does not match expected value {parent_final_state:x?}",
                    header.final_state
                ),
            ));
        }
    }

    Ok(())
}

/// Perform validation of all votes and revocations in the block
/// against the lottery results (dcrd `checkTicketRedeemers`): votes
/// MUST spend winning tickets, revocations MUST spend missed or
/// expired tickets, and under the automatic revocations agenda every
/// newly missed or expired ticket MUST be revoked in the block.
/// `exists_missed_ticket` stands in for the stake node query.
pub fn check_ticket_redeemers(
    vote_ticket_hashes: &[Hash],
    revocation_ticket_hashes: &[Hash],
    winners: &[Hash],
    expiring_next_block: &[Hash],
    exists_missed_ticket: impl Fn(&Hash) -> bool,
    is_auto_revocations_enabled: bool,
) -> Result<(), RuleError> {
    // Determine which of the winning tickets have votes in the block.
    let mut winning_hashes: alloc::collections::BTreeMap<[u8; 32], bool> =
        alloc::collections::BTreeMap::new();
    for ticket_hash in winners {
        winning_hashes.insert(ticket_hash.0, false);
    }
    for vote_ticket_hash in vote_ticket_hashes {
        match winning_hashes.get_mut(&vote_ticket_hash.0) {
            None => {
                return Err(rule_error(
                    RuleErrorKind::TicketUnavailable,
                    format!("block contains vote for ineligible ticket {vote_ticket_hash}"),
                ));
            }
            Some(has_vote) => *has_vote = true,
        }
    }

    // The winning tickets without votes become missed as of this
    // block.
    let missed_ticket_hashes: alloc::collections::BTreeSet<[u8; 32]> = winning_hashes
        .iter()
        .filter(|&(_, &has_vote)| !has_vote)
        .map(|(hash, _)| *hash)
        .collect();
    let expiring_ticket_hashes: alloc::collections::BTreeSet<[u8; 32]> =
        expiring_next_block.iter().map(|h| h.0).collect();

    // Each revocation must spend a ticket that is missed or, under the
    // automatic revocations agenda, becoming missed or expired as of
    // this block.
    let mut revoked_ticket_hashes: alloc::collections::BTreeSet<[u8; 32]> =
        alloc::collections::BTreeSet::new();
    for revocation_ticket_hash in revocation_ticket_hashes {
        let missed_in_block = missed_ticket_hashes.contains(&revocation_ticket_hash.0);
        let expiring_in_block = expiring_ticket_hashes.contains(&revocation_ticket_hash.0);
        let missed_or_expired_in_block = missed_in_block || expiring_in_block;
        let eligible = (is_auto_revocations_enabled && missed_or_expired_in_block)
            || exists_missed_ticket(revocation_ticket_hash);
        if !eligible {
            return Err(rule_error(
                RuleErrorKind::InvalidSSRtx,
                format!(
                    "block contains revocation of ineligible ticket \
                     {revocation_ticket_hash}"
                ),
            ));
        }
        revoked_ticket_hashes.insert(revocation_ticket_hash.0);
    }

    // Under the automatic revocations agenda the block must revoke
    // every ticket becoming missed or expired as of this block.
    if is_auto_revocations_enabled {
        for ticket_hash in &missed_ticket_hashes {
            if !revoked_ticket_hashes.contains(ticket_hash) {
                return Err(rule_error(
                    RuleErrorKind::NoMissedTicketRevocation,
                    format!(
                        "block does not contain a revocation for ticket that is \
                         becoming missed as of this block: {}",
                        Hash(*ticket_hash)
                    ),
                ));
            }
        }
        for ticket_hash in &expiring_ticket_hashes {
            if !revoked_ticket_hashes.contains(ticket_hash) {
                return Err(rule_error(
                    RuleErrorKind::NoExpiredTicketRevocation,
                    format!(
                        "block does not contain a revocation for ticket that is \
                         becoming expired as of this block: {}",
                        Hash(*ticket_hash)
                    ),
                ));
            }
        }
    }

    Ok(())
}

/// Ensure that for all blocks height > 1 the coinbase contains the
/// height encoding to make coinbase hash collisions impossible (dcrd
/// `checkCoinbaseUniqueHeight`).
pub fn check_coinbase_unique_height(
    block_height: i64,
    block: &MsgBlock,
    treasury_enabled: bool,
) -> Result<(), RuleError> {
    // Block 0 and 1 are special and don't need the coinbase height
    // checks.
    if block_height < 2 {
        return Ok(());
    }

    // Prior to activation of the treasury agenda, output 0 is the
    // project subsidy and output 1 encodes the height.  Once the
    // agenda is active, the project subsidy is moved to the
    // treasurybase in the stake tree and thus output 0 then encodes
    // the height.
    let null_data_out_idx = if treasury_enabled { 0 } else { 1 };

    // There must be at least enough outputs to contain the one that
    // encodes the height.
    let coinbase_tx = &block.transactions[0];
    if coinbase_tx.tx_out.len() < null_data_out_idx + 1 {
        return Err(rule_error(
            RuleErrorKind::FirstTxNotCoinbase,
            format!(
                "block is missing required coinbase outputs (num outputs: {}, min \
                 required: {})",
                coinbase_tx.tx_out.len(),
                null_data_out_idx + 1
            ),
        ));
    }

    // Only version 0 scripts are currently valid.
    const SCRIPT_VERSION: u16 = 0;
    let null_data_out = &coinbase_tx.tx_out[null_data_out_idx];
    if null_data_out.version != SCRIPT_VERSION {
        return Err(rule_error(
            RuleErrorKind::FirstTxNotCoinbase,
            format!(
                "coinbase output {null_data_out_idx} script version {} is not the \
                 required version {SCRIPT_VERSION}",
                null_data_out.version
            ),
        ));
    }

    // The nulldata in the coinbase must be a single OP_RETURN followed
    // by a data push up to the maximum unique coinbase null data size,
    // and the first 4 bytes of that data must be the little-endian
    // encoded height of the block.  This intentionally avoids the
    // standardness script type determination functions because this
    // enforces consensus rules.
    let mut null_data: &[u8] = &[];
    let pk_script = &null_data_out.pk_script;
    if pk_script.len() > 1 && pk_script[0] == dcroxide_txscript::OP_RETURN {
        let mut tokenizer =
            dcroxide_txscript::ScriptTokenizer::new(SCRIPT_VERSION, &pk_script[1..]);
        if tokenizer.next()
            && tokenizer.done()
            && tokenizer.opcode() <= dcroxide_txscript::OP_PUSHDATA4
        {
            null_data = tokenizer.data();
        }
    }
    if null_data.len() > MAX_UNIQUE_COINBASE_NULL_DATA_SIZE {
        return Err(rule_error(
            RuleErrorKind::FirstTxNotCoinbase,
            format!(
                "coinbase output {null_data_out_idx} pushes {} bytes which is more \
                 than allowed value of {MAX_UNIQUE_COINBASE_NULL_DATA_SIZE}",
                null_data.len()
            ),
        ));
    }
    if null_data.len() < 4 {
        return Err(rule_error(
            RuleErrorKind::FirstTxNotCoinbase,
            format!(
                "coinbase output {null_data_out_idx} pushes {} bytes which is too \
                 short to encode height",
                null_data.len()
            ),
        ));
    }

    // Check the height and ensure it is correct.
    let cb_height = u32::from_le_bytes([null_data[0], null_data[1], null_data[2], null_data[3]]);
    if cb_height != block_height as u32 {
        return Err(rule_error(
            RuleErrorKind::CoinbaseHeight,
            format!(
                "coinbase output {null_data_out_idx} encodes height {cb_height} instead \
                 of expected height {}",
                block_height as u32
            ),
        ));
    }

    Ok(())
}

/// Ensure that for all blocks height > 1 the treasurybase contains the
/// height encoding to make treasurybase hash collisions impossible
/// (dcrd `checkTreasurybaseUniqueHeight`).  The caller must have
/// already verified the block has at least one stake transaction, as
/// in dcrd (which returns an assertion error there).
pub fn check_treasurybase_unique_height(
    block_height: i64,
    block: &MsgBlock,
) -> Result<(), RuleError> {
    // Block 0 and 1 are special and don't need the treasurybase height
    // checks.
    if block_height < 2 {
        return Ok(());
    }

    assert!(
        !block.stransactions.is_empty(),
        "checkTreasurybaseUniqueHeight must be called with a block that has already \
         been verified to have at least one stake transaction"
    );

    // Treasurybase output 0 is the subsidy and output 1 encodes the
    // height.
    const NULL_DATA_OUT_IDX: usize = 1;
    let trsybase_tx = &block.stransactions[0];
    if trsybase_tx.tx_out.len() < NULL_DATA_OUT_IDX + 1 {
        return Err(rule_error(
            RuleErrorKind::FirstTxNotTreasurybase,
            format!(
                "block is missing required OP_RETURN output (num outputs: {}, min \
                 required: {})",
                trsybase_tx.tx_out.len(),
                NULL_DATA_OUT_IDX + 1
            ),
        ));
    }

    // Only version 0 scripts are currently valid.
    const SCRIPT_VERSION: u16 = 0;
    let null_data_out = &trsybase_tx.tx_out[NULL_DATA_OUT_IDX];
    if null_data_out.version != SCRIPT_VERSION {
        return Err(rule_error(
            RuleErrorKind::FirstTxNotTreasurybase,
            format!(
                "treasurybase output {NULL_DATA_OUT_IDX} script version {} is not the \
                 required version {SCRIPT_VERSION}",
                null_data_out.version
            ),
        ));
    }

    // The nulldata in the treasurybase must be a single OP_RETURN
    // followed by a data push of 12 bytes which encodes the height of
    // the block followed by random data.
    let mut null_data: &[u8] = &[];
    let pk_script = &null_data_out.pk_script;
    if pk_script.len() == 14
        && pk_script[0] == dcroxide_txscript::OP_RETURN
        && pk_script[1] == dcroxide_txscript::OP_DATA_12
    {
        // The encoded height.
        null_data = &pk_script[2..6];
    }
    if null_data.len() != 4 {
        return Err(rule_error(
            RuleErrorKind::TreasurybaseTxNotOpReturn,
            format!("treasurybase output {NULL_DATA_OUT_IDX} is invalid"),
        ));
    }

    // Check the height and ensure it is correct.
    let encoded_height =
        u32::from_le_bytes([null_data[0], null_data[1], null_data[2], null_data[3]]);
    if encoded_height != block_height as u32 {
        return Err(rule_error(
            RuleErrorKind::TreasurybaseHeight,
            format!(
                "treasurybase output {NULL_DATA_OUT_IDX} encodes height {encoded_height} \
                 instead of expected height {}",
                block_height as u32
            ),
        ));
    }

    Ok(())
}

/// Validate the merkle root commitments in the block header against
/// the calculated values, honoring the DCP0005 header commitments
/// agenda for the combined-vs-dual tree behavior (dcrd
/// `checkMerkleRoots`).
pub fn check_merkle_roots(
    view: &impl FullChainView,
    block: &MsgBlock,
    prev_height: i64,
    params: &Params,
) -> Result<(), RuleError> {
    let header = &block.header;

    let hdr_commitments_active =
        crate::agendas::is_header_commitments_agenda_active(view, Some(prev_height), params)
            .map_err(|_| {
                rule_error(
                    RuleErrorKind::UnknownDeploymentID,
                    "header commitments deployment not defined on this network",
                )
            })?;
    if hdr_commitments_active {
        // Build the two merkle trees and use their calculated merkle
        // roots as leaves to another merkle tree and ensure the final
        // calculated merkle root matches the entry in the block
        // header.
        let want_merkle_root = dcroxide_standalone::calc_combined_tx_tree_merkle_root(
            &block.transactions,
            &block.stransactions,
        );
        if header.merkle_root != want_merkle_root {
            return Err(rule_error(
                RuleErrorKind::BadMerkleRoot,
                format!(
                    "block merkle root is invalid - block header indicates {}, but \
                     calculated value is {want_merkle_root}",
                    header.merkle_root
                ),
            ));
        }
        return Ok(());
    }

    // Fall back to the old behavior: check the regular and stake tree
    // merkle roots independently.
    let want_merkle_root = dcroxide_standalone::calc_tx_tree_merkle_root(&block.transactions);
    if header.merkle_root != want_merkle_root {
        return Err(rule_error(
            RuleErrorKind::BadMerkleRoot,
            format!(
                "block merkle root is invalid - block header indicates {}, but \
                 calculated value is {want_merkle_root}",
                header.merkle_root
            ),
        ));
    }

    let want_stake_root = dcroxide_standalone::calc_tx_tree_merkle_root(&block.stransactions);
    if header.stake_root != want_stake_root {
        return Err(rule_error(
            RuleErrorKind::BadMerkleRoot,
            format!(
                "block stake merkle root is invalid - block header indicates {}, but \
                 calculated value is {want_stake_root}",
                header.stake_root
            ),
        ));
    }

    Ok(())
}

/// The offsets of the commitment hash, amount, and fee limits inside a
/// ticket commitment output script (dcrd `commitHashStartIdx` ...).
const COMMIT_HASH_START_IDX: usize = 2;
const COMMIT_HASH_END_IDX: usize = COMMIT_HASH_START_IDX + 20;
const COMMIT_AMOUNT_START_IDX: usize = COMMIT_HASH_END_IDX;
const COMMIT_AMOUNT_END_IDX: usize = COMMIT_AMOUNT_START_IDX + 8;
const COMMIT_FEE_LIMIT_START_IDX: usize = COMMIT_AMOUNT_END_IDX;
const COMMIT_FEE_LIMIT_END_IDX: usize = COMMIT_FEE_LIMIT_START_IDX + 2;

/// The bit in the encoded commitment amount that specifies a P2SH
/// commitment (dcrd `commitP2SHFlag`).
const COMMIT_P2SH_FLAG: u64 = 1 << 63;

/// The output index of a ticket's stake submission (dcrd
/// `submissionOutputIdx`).
const SUBMISSION_OUTPUT_IDX: u32 = 0;

/// Extract a pubkey hash from the passed public key script if it is a
/// standard pay-to-pubkey-hash script tagged with the provided stake
/// opcode (dcrd `extractStakePubKeyHash`).
pub fn extract_stake_pub_key_hash(script: &[u8], stake_opcode: u8) -> Option<&[u8]> {
    if script.len() == 26
        && script[0] == stake_opcode
        && script[1] == dcroxide_txscript::OP_DUP
        && script[2] == dcroxide_txscript::OP_HASH160
        && script[3] == dcroxide_txscript::OP_DATA_20
        && script[24] == dcroxide_txscript::OP_EQUALVERIFY
        && script[25] == dcroxide_txscript::OP_CHECKSIG
    {
        return Some(&script[4..24]);
    }
    None
}

/// Whether the script is a standard pay-to-pubkey-hash script tagged
/// with the provided stake opcode (dcrd `isStakePubKeyHash`).
pub fn is_stake_pub_key_hash(script: &[u8], stake_opcode: u8) -> bool {
    extract_stake_pub_key_hash(script, stake_opcode).is_some()
}

/// Extract a script hash from the passed public key script if it is a
/// standard pay-to-script-hash script tagged with the provided stake
/// opcode (dcrd `extractStakeScriptHash`).
pub fn extract_stake_script_hash(script: &[u8], stake_opcode: u8) -> Option<&[u8]> {
    if script.len() == 24
        && script[0] == stake_opcode
        && script[1] == dcroxide_txscript::OP_HASH160
        && script[2] == dcroxide_txscript::OP_DATA_20
        && script[23] == dcroxide_txscript::OP_EQUAL
    {
        return Some(&script[3..23]);
    }
    None
}

/// Whether the script is a standard pay-to-script-hash script tagged
/// with the provided stake opcode (dcrd `isStakeScriptHash`).
pub fn is_stake_script_hash(script: &[u8], stake_opcode: u8) -> bool {
    extract_stake_script_hash(script, stake_opcode).is_some()
}

/// Whether the script is one of the allowed forms for a ticket input
/// (dcrd `isAllowedTicketInputScriptForm`).
pub fn is_allowed_ticket_input_script_form(script: &[u8]) -> bool {
    crate::compress::extract_pub_key_hash(script).is_some()
        || crate::compress::extract_script_hash(script).is_some()
        || is_stake_pub_key_hash(script, dcroxide_txscript::OP_SSGEN)
        || is_stake_script_hash(script, dcroxide_txscript::OP_SSGEN)
        || is_stake_pub_key_hash(script, dcroxide_txscript::OP_SSRTX)
        || is_stake_script_hash(script, dcroxide_txscript::OP_SSRTX)
        || is_stake_pub_key_hash(script, dcroxide_txscript::OP_SSTXCHANGE)
        || is_stake_script_hash(script, dcroxide_txscript::OP_SSTXCHANGE)
}

/// Extract and decode the amount from a ticket output commitment
/// script (dcrd `extractTicketCommitAmount`).  The caller MUST have
/// already determined the script is a commitment output script.
pub fn extract_ticket_commit_amount(script: &[u8]) -> i64 {
    // The MSB of the encoded amount specifies if the output is P2SH,
    // so it must be cleared to get the decoded amount.
    let mut amt_bytes = [0u8; 8];
    amt_bytes.copy_from_slice(&script[COMMIT_AMOUNT_START_IDX..COMMIT_AMOUNT_END_IDX]);
    let amt_encoded = u64::from_le_bytes(amt_bytes);
    (amt_encoded & !COMMIT_P2SH_FLAG) as i64
}

/// Perform a series of checks on the inputs to a ticket purchase
/// transaction (dcrd `checkTicketPurchaseInputs`).  The caller MUST
/// have already determined the transaction is a ticket purchase.
/// `lookup_entry` stands in for dcrd's `UtxoViewpoint.LookupEntry`.
pub fn check_ticket_purchase_inputs(
    tx: &MsgTx,
    lookup_entry: impl Fn(&OutPoint) -> Option<crate::UtxoEntry>,
) -> Result<(), RuleError> {
    // Assert there are two outputs for each input to the ticket as
    // well as the additional voting rights output.
    assert!(
        tx.tx_in.len() * 2 + 1 == tx.tx_out.len(),
        "attempt to check ticket purchase inputs on tx which does not appear to be \
         a ticket purchase"
    );

    for (tx_in_idx, tx_in) in tx.tx_in.iter().enumerate() {
        let entry = lookup_entry(&tx_in.previous_out_point);
        let entry = match entry {
            Some(e) if !e.is_spent() => e,
            _ => {
                return Err(rule_error(
                    RuleErrorKind::MissingTxOut,
                    format!(
                        "output {:?} referenced from transaction {}:{tx_in_idx} either \
                         does not exist or has already been spent",
                        tx_in.previous_out_point,
                        tx.tx_hash()
                    ),
                ));
            }
        };

        // Ensure the output being spent is one of the allowed script
        // forms: pay-to-pubkey-hash and pay-to-script-hash either in
        // the standard form or their stake-tagged variant.
        let pk_script_ver = entry.script_version();
        if pk_script_ver != 0 {
            return Err(rule_error(
                RuleErrorKind::TicketInputScript,
                format!(
                    "output script version {pk_script_ver} referenced by ticket \
                     {}:{tx_in_idx} is not supported",
                    tx.tx_hash()
                ),
            ));
        }
        let pk_script = entry.pk_script();
        if !is_allowed_ticket_input_script_form(pk_script) {
            return Err(rule_error(
                RuleErrorKind::TicketInputScript,
                format!(
                    "output referenced from ticket {}:{tx_in_idx} is not \
                     pay-to-pubkey-hash or pay-to-script-hash",
                    tx.tx_hash()
                ),
            ));
        }

        // Extract the amount from the commitment output associated
        // with the input and ensure it matches the expected amount
        // calculated from the actual input amount and change.
        let commitment_out_idx = tx_in_idx * 2 + 1;
        let commitment_script = &tx.tx_out[commitment_out_idx].pk_script;
        let commitment_amount = extract_ticket_commit_amount(commitment_script);
        let input_amount = entry.amount();
        let change = tx.tx_out[commitment_out_idx + 1].value;
        let adjusted_amount = commitment_amount.wrapping_add(change);
        if adjusted_amount != input_amount {
            return Err(rule_error(
                RuleErrorKind::TicketCommitment,
                format!(
                    "ticket output {commitment_out_idx} pays a different amount than \
                     the associated input {tx_in_idx} (input: {input_amount}, \
                     commitment: {commitment_amount}, change: {change})"
                ),
            ));
        }
    }

    Ok(())
}

/// Whether the script is a stake submission (an `OP_SSTX`-tagged
/// pay-to-pubkey-hash or pay-to-script-hash script; dcrd
/// `isStakeSubmission`).
pub fn is_stake_submission(script: &[u8]) -> bool {
    is_stake_pub_key_hash(script, dcroxide_txscript::OP_SSTX)
        || is_stake_script_hash(script, dcroxide_txscript::OP_SSTX)
}

/// Extract the commitment hash from a ticket output commitment script
/// (dcrd `extractTicketCommitHash`).  The caller MUST have already
/// determined the script is a commitment output script.
pub fn extract_ticket_commit_hash(script: &[u8]) -> &[u8] {
    &script[COMMIT_HASH_START_IDX..COMMIT_HASH_END_IDX]
}

/// Whether the ticket output commitment script commits to a
/// pay-to-script-hash output (dcrd `isTicketCommitP2SH`).  The caller
/// MUST have already determined the script is a commitment output
/// script.
pub fn is_ticket_commit_p2sh(script: &[u8]) -> bool {
    // The MSB of the little-endian encoded amount is in its final
    // byte.
    script[COMMIT_AMOUNT_END_IDX - 1] & 0x80 != 0
}

/// Calculate the required amounts to return from a ticket for the
/// given original contribution amounts, the ticket purchase price, and
/// the vote subsidy, distributing any revocation remainder via the
/// Hash256PRNG when the automatic revocations agenda is active (dcrd
/// `calcTicketReturnAmounts`).  The vote subsidy must be 0 for
/// revocations.
pub fn calc_ticket_return_amounts(
    ticket_outs: &[dcroxide_stake::MinimalOutput],
    ticket_purchase_amount: i64,
    vote_subsidy: i64,
    prev_header_bytes: &[u8],
    is_vote: bool,
    is_auto_revocations_enabled: bool,
) -> Vec<i64> {
    // Calculate the overall contribution sum, needed to scale the
    // output amounts to the same proportions as the original
    // contributions.  The calculations require more than 64 bits, so
    // arbitrary-precision integers mirror dcrd's use of big.Int.
    let mut contribution_sum: i64 = 0;
    let mut i = 1;
    while i < ticket_outs.len() {
        contribution_sum =
            contribution_sum.wrapping_add(extract_ticket_commit_amount(&ticket_outs[i].pk_script));
        i += 2;
    }
    let contribution_sum_big = BigInt::from(contribution_sum);

    let num_return_amounts = (ticket_outs.len() - 1) / 2;
    let mut return_amounts = vec![0i64; num_return_amounts];

    // 64.32 fixed point:
    // return = (total output amount * contribution << 32) / total
    // contributions >> 32.
    let total_output_amt = ticket_purchase_amount.wrapping_add(vote_subsidy);
    let total_output_amt_big = BigInt::from(total_output_amt);
    let mut total_return_amount: i64 = 0;
    for (i, amount) in return_amounts.iter_mut().enumerate() {
        let ticket_out = &ticket_outs[i * 2 + 1];
        let mut return_amt_big = BigInt::from(extract_ticket_commit_amount(&ticket_out.pk_script));
        return_amt_big *= &total_output_amt_big;
        return_amt_big <<= 32u32;
        return_amt_big /= &contribution_sum_big;
        return_amt_big >>= 32u32;
        *amount = crate::difficulty::lossy_i64(&return_amt_big);
        total_return_amount = total_return_amount.wrapping_add(*amount);
    }

    // For votes, any remainder left over becomes part of the
    // transaction fee.
    if is_vote {
        return return_amounts;
    }

    // For revocations under the automatic ticket revocations agenda,
    // select a uniformly pseudorandom output index to receive each
    // remaining atom.
    if is_auto_revocations_enabled && total_return_amount < total_output_amt {
        let remainder = total_output_amt - total_return_amount;
        let mut prng = dcroxide_stake::Hash256Prng::new(prev_header_bytes);
        for _ in 0..remainder {
            let return_index = prng.uniform_random(num_return_amounts as u32);
            return_amounts[return_index as usize] += 1;
        }
    }

    return_amounts
}

/// Extract the encoded fee limits from a ticket output commitment
/// script (dcrd `extractTicketCommitFeeLimits`).  The caller MUST have
/// already determined the script is a commitment output script.
pub fn extract_ticket_commit_fee_limits(script: &[u8]) -> u16 {
    let mut bytes = [0u8; 2];
    bytes.copy_from_slice(&script[COMMIT_FEE_LIMIT_START_IDX..COMMIT_FEE_LIMIT_END_IDX]);
    u16::from_le_bytes(bytes)
}

/// Ensure the provided unspent transaction output is a supported
/// ticket submission output (dcrd `checkTicketSubmissionInput`).  The
/// returned error is not a rule error; the caller converts it.
pub fn check_ticket_submission_input(ticket_utxo: &crate::UtxoEntry) -> Result<(), String> {
    let submission_script_ver = ticket_utxo.script_version();
    if submission_script_ver != 0 {
        return Err(format!(
            "script version {submission_script_ver} is not supported"
        ));
    }
    let submission_script = ticket_utxo.pk_script();
    if !is_stake_submission(submission_script) {
        let _ = submission_script;
        return Err("not a supported stake submission script".into());
    }

    // Ensure the referenced output is from a ticket, which also proves
    // the form of the transaction and its outputs are as expected.
    if ticket_utxo.transaction_type() != dcroxide_stake::TxType::SStx as u8 {
        return Err("not a submission script".into());
    }

    Ok(())
}

/// Ensure the outputs of the provided vote or revocation adhere to the
/// commitments in the provided ticket outputs (dcrd
/// `checkTicketRedeemerCommitments`).  The vote subsidy MUST be zero
/// for revocations.
#[allow(clippy::too_many_arguments)]
pub fn check_ticket_redeemer_commitments(
    ticket_outs: &[dcroxide_stake::MinimalOutput],
    tx: &MsgTx,
    is_vote: bool,
    vote_subsidy: i64,
    prev_header: &dcroxide_wire::BlockHeader,
    is_treasury_enabled: bool,
    is_auto_revocations_enabled: bool,
) -> Result<(), RuleError> {
    // The outputs that satisfy the commitments of the ticket start at
    // offset 2 for votes and 0 for revocations, the payments must be
    // tagged with the appropriate stake opcode, and the fee limits in
    // the original ticket commitment differ for votes and revocations.
    let (start_idx, req_stake_opcode, has_fee_limit_flag, fee_limit_mask, fee_limit_shift) =
        if is_vote {
            (
                2usize,
                dcroxide_txscript::OP_SSGEN,
                dcroxide_stake::SSTX_VOTE_FRACTION_FLAG,
                dcroxide_stake::SSTX_VOTE_RETURN_FRACTION_MASK,
                0u16,
            )
        } else {
            (
                0usize,
                dcroxide_txscript::OP_SSRTX,
                dcroxide_stake::SSTX_REV_FRACTION_FLAG,
                dcroxide_stake::SSTX_REV_RETURN_FRACTION_MASK,
                dcroxide_stake::SSTX_REV_RETURN_FRACTION_SHIFT,
            )
        };
    let ticket_paid_amt = ticket_outs[SUBMISSION_OUTPUT_IDX as usize].value;

    // Serialize the previous header for the PRNG seed; unlike dcrd,
    // serialization here cannot fail, making ErrSerializeHeader
    // unreachable.
    let prev_header_bytes = prev_header.serialize();

    // Calculate the expected output amounts.
    let expected_out_amts = calc_ticket_return_amounts(
        ticket_outs,
        ticket_paid_amt,
        vote_subsidy,
        &prev_header_bytes,
        is_vote,
        is_auto_revocations_enabled,
    );

    // When the treasury agenda is active and the vote carries treasury
    // votes, the final output is excluded from the commitment checks.
    let mut extra = 0usize;
    if is_treasury_enabled {
        let has_tv = dcroxide_stake::check_ssgen_votes(tx)
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        if has_tv {
            extra = 1;
        }
    }

    for tx_out_idx in start_idx..tx.tx_out.len() - extra {
        // Ensure the output is paying to the address and type
        // specified by the original commitment in the ticket and is a
        // version 0 script.
        let tx_out = &tx.tx_out[tx_out_idx];
        if tx_out.version != 0 {
            return Err(rule_error(
                RuleErrorKind::BadPayeeScriptVersion,
                format!(
                    "output {}:{tx_out_idx} script version {} is not supported",
                    tx.tx_hash(),
                    tx_out.version
                ),
            ));
        }

        let commitment_out_idx = (tx_out_idx - start_idx) * 2 + 1;
        let commitment_script = &ticket_outs[commitment_out_idx].pk_script;
        let payment_hash = if is_ticket_commit_p2sh(commitment_script) {
            extract_stake_script_hash(&tx_out.pk_script, req_stake_opcode).ok_or_else(|| {
                rule_error(
                    RuleErrorKind::BadPayeeScriptType,
                    format!(
                        "output {}:{tx_out_idx} payment script type is not \
                         pay-to-script-hash as required by ticket output commitment \
                         {commitment_out_idx}",
                        tx.tx_hash()
                    ),
                )
            })?
        } else {
            extract_stake_pub_key_hash(&tx_out.pk_script, req_stake_opcode).ok_or_else(|| {
                rule_error(
                    RuleErrorKind::BadPayeeScriptType,
                    format!(
                        "output {}:{tx_out_idx} payment script type is not \
                         pay-to-pubkey-hash as required by ticket output commitment \
                         {commitment_out_idx}",
                        tx.tx_hash()
                    ),
                )
            })?
        };
        let commitment_hash = extract_ticket_commit_hash(commitment_script);
        if payment_hash != commitment_hash {
            return Err(rule_error(
                RuleErrorKind::MismatchedPayeeHash,
                format!(
                    "output {}:{tx_out_idx} does not pay to the hash specified by \
                     ticket output commitment {commitment_out_idx}",
                    tx.tx_hash()
                ),
            ));
        }

        // Determine the fee limit that is imposed.  If the transaction
        // is a revocation, the version is at least 2, and the
        // automatic ticket revocation agenda is active, then the fee
        // MUST be zero; otherwise the encoded fee limit from the
        // ticket commitment applies.
        let mut fee_limits_encoded: u16 = 0;
        let mut has_fee_limit = false;
        if is_vote
            || !is_auto_revocations_enabled
            || tx.version < dcroxide_stake::TX_VERSION_AUTO_REVOCATIONS
        {
            fee_limits_encoded = extract_ticket_commit_fee_limits(commitment_script);
            has_fee_limit = fee_limits_encoded & has_fee_limit_flag != 0;
        }

        // Ensure the amount paid adheres to the commitment while
        // taking into account any fee limits that might be imposed.
        let expected_out_amt = expected_out_amts[tx_out_idx - start_idx];
        if !has_fee_limit {
            // The output amount must exactly match the calculated
            // amount when not encumbered with a fee limit.
            if tx_out.value != expected_out_amt {
                return Err(rule_error(
                    RuleErrorKind::BadPayeeValue,
                    format!(
                        "output {}:{tx_out_idx} does not pay the expected amount per \
                         ticket output commitment {commitment_out_idx} (expected \
                         {expected_out_amt}, output pays {})",
                        tx.tx_hash(),
                        tx_out.value
                    ),
                ));
            }
        } else {
            // Since the fee limit is a log2 value and amounts are
            // 64-bit, anything of 63 or more means the entire amount
            // may be spent as a fee.
            let mut amt_limit_low: i64 = 0;
            let fee_limit_log2 = (fee_limits_encoded & fee_limit_mask) >> fee_limit_shift;
            if fee_limit_log2 < 63 {
                let fee_limit = 1i64 << u64::from(fee_limit_log2);
                if fee_limit < expected_out_amt {
                    amt_limit_low = expected_out_amt - fee_limit;
                }
            }

            // The output must not be less than the minimum amount.
            if tx_out.value < amt_limit_low {
                return Err(rule_error(
                    RuleErrorKind::BadPayeeValue,
                    format!(
                        "output {}:{tx_out_idx} pays less than the expected amount per \
                         ticket output commitment {commitment_out_idx} (lowest allowed \
                         {amt_limit_low}, output pays {})",
                        tx.tx_hash(),
                        tx_out.value
                    ),
                ));
            }

            // The output must not be more than the expected amount.
            if tx_out.value > expected_out_amt {
                return Err(rule_error(
                    RuleErrorKind::BadPayeeValue,
                    format!(
                        "output {}:{tx_out_idx} pays more than the expected amount per \
                         ticket output commitment {commitment_out_idx} (expected \
                         {expected_out_amt}, output pays {})",
                        tx.tx_hash(),
                        tx_out.value
                    ),
                ));
            }
        }
    }

    Ok(())
}

/// Adapter exposing the chain parameters as the subsidy parameters
/// the standalone subsidy cache expects (dcrd wires this up through
/// its `chaincfg.Params` methods directly).
pub struct ChainSubsidyParams<'a>(pub &'a Params);

impl dcroxide_standalone::SubsidyParams for ChainSubsidyParams<'_> {
    fn block_one_subsidy(&self) -> i64 {
        self.0.block_one_subsidy()
    }
    fn base_subsidy_value(&self) -> i64 {
        self.0.base_subsidy
    }
    fn subsidy_reduction_multiplier(&self) -> i64 {
        self.0.mul_subsidy
    }
    fn subsidy_reduction_divisor(&self) -> i64 {
        self.0.div_subsidy
    }
    fn subsidy_reduction_interval_blocks(&self) -> i64 {
        self.0.subsidy_reduction_interval
    }
    fn work_subsidy_proportion(&self) -> u16 {
        self.0.work_reward_proportion
    }
    fn stake_subsidy_proportion(&self) -> u16 {
        self.0.stake_reward_proportion
    }
    fn treasury_subsidy_proportion(&self) -> u16 {
        self.0.block_tax_proportion
    }
    fn stake_validation_begin_height(&self) -> i64 {
        self.0.stake_validation_height
    }
    fn votes_per_block(&self) -> u16 {
        self.0.tickets_per_block
    }
}

/// Perform a series of checks on the inputs to a vote transaction
/// (dcrd `checkVoteInputs`).  The caller MUST have already determined
/// the transaction is a vote.
#[allow(clippy::too_many_arguments)]
pub fn check_vote_inputs<SP: dcroxide_standalone::SubsidyParams>(
    subsidy_cache: &mut dcroxide_standalone::SubsidyCache<SP>,
    tx: &MsgTx,
    tx_height: i64,
    lookup_entry: impl Fn(&OutPoint) -> Option<crate::UtxoEntry>,
    params: &Params,
    prev_header: &dcroxide_wire::BlockHeader,
    is_treasury_enabled: bool,
    is_auto_revocations_enabled: bool,
    subsidy_split_variant: dcroxide_standalone::SubsidySplitVariant,
) -> Result<(), RuleError> {
    let ticket_maturity = i64::from(params.ticket_maturity);
    let vote_hash = tx.tx_hash();

    // Calculate the theoretical stake vote subsidy by extracting the
    // vote height.  dcrd notes this really should use the height of
    // the block containing the vote, but it is now consensus.
    let (_, height_voting_on) = dcroxide_stake::ssgen_block_voted_on(tx);
    let vote_subsidy = subsidy_cache
        .calc_stake_vote_subsidy_v3(i64::from(height_voting_on), subsidy_split_variant);

    // The input amount specified by the stakebase must commit to the
    // subsidy generated by the vote.
    let stakebase = &tx.tx_in[0];
    if stakebase.value_in != vote_subsidy {
        return Err(rule_error(
            RuleErrorKind::BadStakebaseAmountIn,
            format!(
                "vote subsidy input value of {} is not {vote_subsidy}",
                stakebase.value_in
            ),
        ));
    }

    // The second input to a vote must be the first output of the
    // ticket the vote is associated with.
    const TICKET_IN_IDX: usize = 1;
    let ticket_in = &tx.tx_in[TICKET_IN_IDX];
    if ticket_in.previous_out_point.index != SUBMISSION_OUTPUT_IDX {
        return Err(rule_error(
            RuleErrorKind::InvalidVoteInput,
            format!(
                "vote {vote_hash}:{TICKET_IN_IDX} references output {} instead of the \
                 first output",
                ticket_in.previous_out_point.index
            ),
        ));
    }

    // Ensure the referenced ticket is available.
    let ticket_utxo = match lookup_entry(&ticket_in.previous_out_point) {
        Some(e) if !e.is_spent() => e,
        _ => {
            return Err(rule_error(
                RuleErrorKind::MissingTxOut,
                format!(
                    "ticket output {:?} referenced by vote {vote_hash}:{TICKET_IN_IDX} \
                     either does not exist or has already been spent",
                    ticket_in.previous_out_point
                ),
            ));
        }
    };

    // Ensure the referenced output is a supported ticket submission
    // output, which also proves the form of the housing transaction.
    if let Err(e) = check_ticket_submission_input(&ticket_utxo) {
        return Err(rule_error(
            RuleErrorKind::InvalidVoteInput,
            format!(
                "output {:?} referenced by vote {vote_hash}:{TICKET_IN_IDX} consensus \
                 violation: {e}",
                ticket_in.previous_out_point
            ),
        ));
    }

    // A ticket stake submission can only be spent in the block AFTER
    // the entire ticket maturity has passed, hence the +1.
    let origin_height = ticket_utxo.block_height();
    let blocks_since_prev = tx_height - origin_height;
    if blocks_since_prev < ticket_maturity + 1 {
        return Err(rule_error(
            RuleErrorKind::ImmatureTicketSpend,
            format!(
                "tried to spend ticket output from height {origin_height} at height \
                 {tx_height} before required ticket maturity of {ticket_maturity}+1 \
                 blocks"
            ),
        ));
    }

    let ticket_outs_data = ticket_utxo
        .ticket_minimal_outputs_data()
        .expect("missing extra stake data for ticket -- probable database corruption");
    let (ticket_outs, _) = crate::chainio::deserialize_to_minimal_outputs(ticket_outs_data);

    // Ensure the number of payment outputs matches the number of
    // commitments made by the associated ticket: the vote outputs are
    // an OP_RETURN block reference, an OP_RETURN with the vote bits,
    // and one output per ticket commitment (plus an optional treasury
    // vote output).
    let mut extra = 0usize;
    if is_treasury_enabled {
        let has_tv = dcroxide_stake::check_ssgen_votes(tx)
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        if has_tv {
            extra = 1;
        }
    }
    let num_vote_payments = tx.tx_out.len() - 2 - extra;
    if num_vote_payments * 2 != ticket_outs.len() - 1 {
        return Err(rule_error(
            RuleErrorKind::BadNumPayees,
            format!(
                "vote {vote_hash} makes {num_vote_payments} payments when the input \
                 ticket has {} commitments",
                ticket_outs.len() - 1
            ),
        ));
    }

    // Ensure the outputs adhere to the ticket commitments.
    check_ticket_redeemer_commitments(
        &ticket_outs,
        tx,
        true,
        vote_subsidy,
        prev_header,
        is_treasury_enabled,
        is_auto_revocations_enabled,
    )
}

/// Perform a series of checks on the inputs to a revocation
/// transaction (dcrd `checkRevocationInputs`).  The caller MUST have
/// already determined the transaction is a revocation.
pub fn check_revocation_inputs(
    tx: &MsgTx,
    tx_height: i64,
    lookup_entry: impl Fn(&OutPoint) -> Option<crate::UtxoEntry>,
    params: &Params,
    prev_header: &dcroxide_wire::BlockHeader,
    is_treasury_enabled: bool,
    is_auto_revocations_enabled: bool,
) -> Result<(), RuleError> {
    let ticket_maturity = i64::from(params.ticket_maturity);
    let revoke_hash = tx.tx_hash();

    // The first input to a revocation must be the first output of the
    // ticket the revocation is associated with.
    const TICKET_IN_IDX: usize = 0;
    let ticket_in = &tx.tx_in[TICKET_IN_IDX];
    if ticket_in.previous_out_point.index != SUBMISSION_OUTPUT_IDX {
        return Err(rule_error(
            RuleErrorKind::InvalidRevokeInput,
            format!(
                "revocation {revoke_hash}:{TICKET_IN_IDX} references output {} instead \
                 of the first output",
                ticket_in.previous_out_point.index
            ),
        ));
    }

    // Ensure the referenced ticket is available.
    let ticket_utxo = match lookup_entry(&ticket_in.previous_out_point) {
        Some(e) if !e.is_spent() => e,
        _ => {
            return Err(rule_error(
                RuleErrorKind::MissingTxOut,
                format!(
                    "ticket output {:?} referenced from revocation \
                     {revoke_hash}:{TICKET_IN_IDX} either does not exist or has \
                     already been spent",
                    ticket_in.previous_out_point
                ),
            ));
        }
    };

    // Ensure the referenced output is a supported ticket submission
    // output, which also proves the form of the housing transaction.
    if let Err(e) = check_ticket_submission_input(&ticket_utxo) {
        return Err(rule_error(
            RuleErrorKind::InvalidRevokeInput,
            format!(
                "output {:?} referenced by revocation {revoke_hash}:{TICKET_IN_IDX} \
                 consensus violation: {e}",
                ticket_in.previous_out_point
            ),
        ));
    }

    // A ticket can only be revoked a block after it could have voted
    // (+2), or in the same block it is missed or expired under the
    // automatic ticket revocations agenda (+1).
    let origin_height = ticket_utxo.block_height();
    let blocks_since_prev = tx_height - origin_height;
    let revocation_additional_maturity: i64 = if is_auto_revocations_enabled { 1 } else { 2 };
    if blocks_since_prev < ticket_maturity + revocation_additional_maturity {
        return Err(rule_error(
            RuleErrorKind::ImmatureTicketSpend,
            format!(
                "tried to spend ticket output from height {origin_height} at height \
                 {tx_height} before required ticket maturity of \
                 {ticket_maturity}+{revocation_additional_maturity} blocks"
            ),
        ));
    }

    let ticket_outs_data = ticket_utxo
        .ticket_minimal_outputs_data()
        .expect("missing extra stake data for ticket -- probable database corruption");
    let (ticket_outs, _) = crate::chainio::deserialize_to_minimal_outputs(ticket_outs_data);

    // The revocation outputs must consist of one output per ticket
    // commitment.
    let num_revocation_payments = tx.tx_out.len();
    if num_revocation_payments * 2 != ticket_outs.len() - 1 {
        return Err(rule_error(
            RuleErrorKind::BadNumPayees,
            format!(
                "revocation {revoke_hash} makes {num_revocation_payments} payments \
                 when the input ticket has {} commitments",
                ticket_outs.len() - 1
            ),
        ));
    }

    // Zero vote subsidy since revocations do not produce any subsidy.
    check_ticket_redeemer_commitments(
        &ticket_outs,
        tx,
        false,
        0,
        prev_header,
        is_treasury_enabled,
        is_auto_revocations_enabled,
    )
}

/// Verify that the provided schnorr signature and public key were the
/// ones that signed the provided treasury spend transaction (dcrd
/// `verifyTSpendSignature`).  The returned error is not a rule error;
/// the caller converts it.
pub fn verify_tspend_signature(tx: &MsgTx, signature: &[u8], pub_key: &[u8]) -> Result<(), String> {
    // Calculate the signature hash exactly as dcrd does: an empty
    // script, SigHashAll, and input zero.
    let sig_hash =
        dcroxide_txscript::calc_signature_hash_checked(&[], dcroxide_txscript::SIG_HASH_ALL, tx, 0)
            .map_err(|e| format!("CalcSignatureHash: {e:?}"))?;

    // Lift the signature and public PI key from bytes.
    let sig = dcroxide_dcrec::secp256k1::schnorr::parse_signature(signature)
        .map_err(|e| format!("ParseSignature: {e:?}"))?;
    let pk = dcroxide_dcrec::secp256k1::schnorr::parse_pub_key(pub_key)
        .map_err(|e| format!("ParsePubKey: {e:?}"))?;

    // Verify the transaction was properly signed.
    if !sig.verify(&sig_hash, &pk) {
        return Err("Verify failed".into());
    }

    Ok(())
}

/// Perform a series of checks on the inputs to a transaction to ensure
/// they are valid, returning the transaction fee (dcrd
/// `CheckTransactionInputs`).  The transaction MUST have already been
/// sanity checked.  `lookup_entry` stands in for dcrd's
/// `UtxoViewpoint.LookupEntry`.
#[allow(clippy::too_many_arguments)]
pub fn check_transaction_inputs<SP: dcroxide_standalone::SubsidyParams>(
    subsidy_cache: &mut dcroxide_standalone::SubsidyCache<SP>,
    tx: &MsgTx,
    tx_height: i64,
    lookup_entry: impl Fn(&OutPoint) -> Option<crate::UtxoEntry>,
    check_fraud_proof: bool,
    params: &Params,
    prev_header: &dcroxide_wire::BlockHeader,
    is_treasury_enabled: bool,
    is_auto_revocations_enabled: bool,
    subsidy_split_variant: dcroxide_standalone::SubsidySplitVariant,
) -> Result<i64, RuleError> {
    // Coinbase and treasurybase transactions have no inputs.
    if dcroxide_standalone::is_coin_base_tx(tx, is_treasury_enabled) {
        return Ok(0);
    }
    if is_treasury_enabled && dcroxide_standalone::is_treasury_base(tx) {
        return Ok(0);
    }

    // Perform the additional ticket purchase, vote, and revocation
    // input checks, tracking the vote/revocation status since some
    // inputs are skipped or treated specially later.
    let is_ticket = dcroxide_stake::is_sstx(tx);
    if is_ticket {
        check_ticket_purchase_inputs(tx, &lookup_entry)?;
    }
    let is_vote = dcroxide_stake::is_ssgen(tx);
    if is_vote {
        check_vote_inputs(
            subsidy_cache,
            tx,
            tx_height,
            &lookup_entry,
            params,
            prev_header,
            is_treasury_enabled,
            is_auto_revocations_enabled,
            subsidy_split_variant,
        )?;
    }
    let is_revocation = dcroxide_stake::is_ssrtx(tx);
    if is_revocation {
        check_revocation_inputs(
            tx,
            tx_height,
            &lookup_entry,
            params,
            prev_header,
            is_treasury_enabled,
            is_auto_revocations_enabled,
        )?;
    }

    // The required maturity for revocation and vote outputs depends on
    // whether or not the treasury agenda is active.
    let req_stake_out_maturity = if is_treasury_enabled {
        i64::from(params.coinbase_maturity)
    } else {
        i64::from(params.sstx_change_maturity)
    };

    // Perform additional checks on treasury spend transactions such as
    // ensuring they have a valid signature from a sanctioned key.
    let mut is_tspend = false;
    if is_treasury_enabled {
        if let Ok((signature, pub_key)) = dcroxide_stake::check_tspend(tx) {
            is_tspend = true;

            // The public key used to sign the treasury spend must be
            // one of the sanctioned pi keys.
            if !params.pi_key_exists(&pub_key) {
                return Err(rule_error(
                    RuleErrorKind::UnknownPiKey,
                    format!("unknown treasury spend pi key: {pub_key:x?}"),
                ));
            }

            // Verify that the signature is valid and corresponds to
            // the provided public key.
            if let Err(e) = verify_tspend_signature(tx, &signature, &pub_key) {
                return Err(rule_error(
                    RuleErrorKind::InvalidPiSignature,
                    format!("failed to verify treasury spend signature: {e}"),
                ));
            }
        }
    }

    // General transaction testing (and a few stake exceptions).
    let tx_hash = tx.tx_hash();
    let coinbase_maturity = i64::from(params.coinbase_maturity);
    let mut total_atom_in: i64 = 0;
    for (idx, tx_in) in tx.tx_in.iter().enumerate() {
        // Inputs won't exist for the stakebase, so add the reward
        // amount instead.
        if is_vote && idx == 0 {
            let (_, height_voting_on) = dcroxide_stake::ssgen_block_voted_on(tx);
            let stake_vote_subsidy = subsidy_cache
                .calc_stake_vote_subsidy_v3(i64::from(height_voting_on), subsidy_split_variant);
            total_atom_in += stake_vote_subsidy;
            continue;
        }

        // idx can only be 0 in this case but check it anyway.
        if is_tspend && idx == 0 {
            total_atom_in += tx_in.value_in;
            continue;
        }

        let tx_in_outpoint = &tx_in.previous_out_point;
        let utxo_entry = match lookup_entry(tx_in_outpoint) {
            Some(e) if !e.is_spent() => e,
            _ => {
                return Err(rule_error(
                    RuleErrorKind::MissingTxOut,
                    format!(
                        "output {tx_in_outpoint:?} referenced from transaction \
                         {tx_hash}:{idx} either does not exist or has already been spent"
                    ),
                ));
            }
        };

        // Using zero value outputs as inputs is banned.
        if utxo_entry.amount() == 0 {
            return Err(rule_error(
                RuleErrorKind::ZeroValueOutputSpend,
                format!("tried to spend zero value output from input {tx_in_outpoint:?}"),
            ));
        }

        // Check fraud proof witness data.
        if check_fraud_proof {
            if tx_in.value_in != utxo_entry.amount() {
                return Err(rule_error(
                    RuleErrorKind::FraudAmountIn,
                    format!(
                        "bad fraud check value in (expected {}, given {}) for txIn {idx}",
                        utxo_entry.amount(),
                        tx_in.value_in
                    ),
                ));
            }
            if i64::from(tx_in.block_height) != utxo_entry.block_height() {
                return Err(rule_error(
                    RuleErrorKind::FraudBlockHeight,
                    format!(
                        "bad fraud check block height (expected {}, given {}) for txIn \
                         {idx}",
                        utxo_entry.block_height(),
                        tx_in.block_height
                    ),
                ));
            }
            if tx_in.block_index != utxo_entry.block_index() {
                return Err(rule_error(
                    RuleErrorKind::FraudBlockIndex,
                    format!(
                        "bad fraud check block index (expected {}, given {}) for txIn \
                         {idx}",
                        utxo_entry.block_index(),
                        tx_in.block_index
                    ),
                ));
            }
        }

        // Ensure the transaction is not spending coins which have not
        // yet reached the required coinbase maturity.
        if utxo_entry.is_coin_base() {
            let origin_height = utxo_entry.block_height();
            let blocks_since_prev = tx_height - origin_height;
            if blocks_since_prev < coinbase_maturity {
                return Err(rule_error(
                    RuleErrorKind::ImmatureSpend,
                    format!(
                        "tried to spend coinbase transaction from height {origin_height} \
                         at height {tx_height} before required maturity of \
                         {coinbase_maturity} blocks"
                    ),
                ));
            }
        }

        // Transactions that included an expiry may likewise only be
        // spent after coinbase maturity many blocks.
        if utxo_entry.has_expiry() {
            let origin_height = utxo_entry.block_height();
            let blocks_since_prev = tx_height - origin_height;
            if blocks_since_prev < coinbase_maturity {
                return Err(rule_error(
                    RuleErrorKind::ExpiryTxSpentEarly,
                    format!(
                        "tried to spend transaction including an expiry from height \
                         {origin_height} at height {tx_height} before required maturity \
                         of {coinbase_maturity} blocks"
                    ),
                ));
            }
        }

        // OP_TGEN tagged outputs can only be spent after coinbase
        // maturity many blocks.
        let script_ver = utxo_entry.script_version();
        let pk_script = utxo_entry.pk_script();
        if is_treasury_enabled && dcroxide_stake::is_treasury_gen_script(script_ver, pk_script) {
            let origin_height = utxo_entry.block_height();
            let blocks_since_prev = tx_height - origin_height;
            if blocks_since_prev < coinbase_maturity {
                return Err(rule_error(
                    RuleErrorKind::ImmatureSpend,
                    format!(
                        "tried to spend OP_TGEN output from height {origin_height} at \
                         height {tx_height} before required maturity of \
                         {coinbase_maturity} blocks"
                    ),
                ));
            }
        }

        // Only votes and revocations may spend OP_SSTX tagged outputs.
        if !(is_vote || is_revocation)
            && dcroxide_stake::is_ticket_purchase_script(script_ver, pk_script)
        {
            return Err(rule_error(
                RuleErrorKind::TxSStxOutSpend,
                format!(
                    "tried to spend OP_SSTX output {tx_in_outpoint:?} from a transaction \
                     that is not a vote or revocation"
                ),
            ));
        }

        // Treasury adds are never spendable.
        if is_treasury_enabled
            && script_ver == 0
            && pk_script.len() == 1
            && pk_script[0] == dcroxide_txscript::OP_TADD
        {
            return Err(rule_error(
                RuleErrorKind::BadTxInput,
                format!("tried to spend treasury add output {tx_in_outpoint:?}"),
            ));
        }

        // OP_SSGEN and OP_SSRTX tagged outputs can only be spent after
        // the required stake output maturity.
        if dcroxide_stake::is_revocation_script(script_ver, pk_script)
            || dcroxide_stake::is_vote_script(script_ver, pk_script)
        {
            let origin_height = utxo_entry.block_height();
            let blocks_since_prev = tx_height - origin_height;
            if blocks_since_prev < req_stake_out_maturity {
                return Err(rule_error(
                    RuleErrorKind::ImmatureSpend,
                    format!(
                        "tried to spend OP_SSGEN or OP_SSRTX output {tx_in_outpoint:?} \
                         from height {origin_height} at height {tx_height} before \
                         required maturity of {coinbase_maturity} blocks"
                    ),
                ));
            }
        }

        // Ticket change outputs may only be spent after ticket change
        // maturity many blocks.
        if dcroxide_stake::is_stake_change_script(script_ver, pk_script) {
            let origin_height = utxo_entry.block_height();
            let blocks_since_prev = tx_height - origin_height;
            if blocks_since_prev < i64::from(params.sstx_change_maturity) {
                return Err(rule_error(
                    RuleErrorKind::ImmatureSpend,
                    format!(
                        "tried to spend ticket change output {tx_in_outpoint:?} from \
                         height {origin_height} at height {tx_height} before required \
                         maturity of {} blocks",
                        params.sstx_change_maturity
                    ),
                ));
            }
        }

        // Ensure the transaction amounts are in range: not negative
        // and no more than the max allowed per transaction, both for
        // each input and for the running total (with overflow checks).
        let origin_tx_atom = utxo_entry.amount();
        if origin_tx_atom < 0 {
            return Err(rule_error(
                RuleErrorKind::BadTxOutValue,
                format!("transaction output has negative value of {origin_tx_atom}"),
            ));
        }
        if origin_tx_atom > dcroxide_stake::MAX_AMOUNT {
            return Err(rule_error(
                RuleErrorKind::BadTxOutValue,
                format!(
                    "transaction output value of {origin_tx_atom} is higher than max \
                     allowed value of {}",
                    dcroxide_stake::MAX_AMOUNT
                ),
            ));
        }
        let last_atom_in = total_atom_in;
        total_atom_in = total_atom_in.wrapping_add(origin_tx_atom);
        if total_atom_in < last_atom_in || total_atom_in > dcroxide_stake::MAX_AMOUNT {
            return Err(rule_error(
                RuleErrorKind::BadTxOutValue,
                format!(
                    "total value of all transaction inputs is {total_atom_in} which is \
                     higher than max allowed value of {}",
                    dcroxide_stake::MAX_AMOUNT
                ),
            ));
        }
    }

    // Calculate the total output amount; overflow and range problems
    // would already have been caught by the sanity checks.
    let mut total_atom_out: i64 = 0;
    for tx_out in &tx.tx_out {
        total_atom_out = total_atom_out.wrapping_add(tx_out.value);
    }

    // Ensure the transaction does not spend more than its inputs.
    if total_atom_in < total_atom_out {
        return Err(rule_error(
            RuleErrorKind::SpendTooHigh,
            format!(
                "total value of all transaction inputs for transaction {tx_hash} is \
                 {total_atom_in} which is less than the amount spent of {total_atom_out}"
            ),
        ));
    }

    Ok(total_atom_in - total_atom_out)
}

/// The maximum number of signature operations per block (dcrd
/// `MaxSigOpsPerBlock`).
pub const MAX_SIG_OPS_PER_BLOCK: i64 = 1_000_000 / 200;

/// The number of signature operations for all input and output scripts
/// in the provided transaction, using the quicker but imprecise
/// counting mechanism from txscript (dcrd `CountSigOps`).
pub fn count_sig_ops(
    tx: &MsgTx,
    is_coin_base_tx: bool,
    is_ssgen: bool,
    is_treasury_enabled: bool,
) -> i64 {
    let mut total_sig_ops: i64 = 0;

    if is_treasury_enabled && dcroxide_standalone::is_treasury_base(tx) {
        return total_sig_ops;
    }

    if !is_coin_base_tx {
        // Accumulate the signature operations in all inputs, skipping
        // the stakebase.
        for (i, tx_in) in tx.tx_in.iter().enumerate() {
            if is_ssgen && i == 0 {
                continue;
            }
            total_sig_ops = total_sig_ops.wrapping_add(dcroxide_txscript::get_sig_op_count(
                &tx_in.signature_script,
                is_treasury_enabled,
            ) as i64);
        }
    }

    // Accumulate the signature operations in all outputs.
    for tx_out in &tx.tx_out {
        total_sig_ops = total_sig_ops.wrapping_add(dcroxide_txscript::get_sig_op_count(
            &tx_out.pk_script,
            is_treasury_enabled,
        ) as i64);
    }

    total_sig_ops
}

/// The number of signature operations for all input transactions of
/// the pay-to-script-hash type, using the precise counting mechanism
/// from the script engine (dcrd `CountP2SHSigOps`).
pub fn count_p2sh_sig_ops(
    tx: &MsgTx,
    is_coin_base_tx: bool,
    is_stake_base_tx: bool,
    lookup_entry: impl Fn(&OutPoint) -> Option<crate::UtxoEntry>,
    is_treasury_enabled: bool,
) -> Result<i64, RuleError> {
    // Coinbase transactions have no interesting inputs, stakebase
    // (SSGen) transactions have no P2SH inputs, and treasury spends
    // and treasurybases likewise have none once recognized under the
    // active treasury agenda.
    if is_coin_base_tx || is_stake_base_tx {
        return Ok(0);
    }
    if is_treasury_enabled
        && (dcroxide_stake::is_tspend(tx) || dcroxide_standalone::is_treasury_base(tx))
    {
        return Ok(0);
    }

    // Accumulate the signature operations in all inputs.
    let mut total_sig_ops: i64 = 0;
    for (tx_in_index, tx_in) in tx.tx_in.iter().enumerate() {
        // Ensure the referenced input transaction is available.
        let tx_in_outpoint = &tx_in.previous_out_point;
        let utxo_entry = match lookup_entry(tx_in_outpoint) {
            Some(e) if !e.is_spent() => e,
            _ => {
                return Err(rule_error(
                    RuleErrorKind::MissingTxOut,
                    format!(
                        "output {tx_in_outpoint:?} referenced from transaction \
                         {}:{tx_in_index} either does not exist or has already been \
                         spent",
                        tx.tx_hash()
                    ),
                ));
            }
        };

        // Only pay-to-script-hash types are of interest.
        let pk_script = utxo_entry.pk_script();
        if !dcroxide_txscript::is_pay_to_script_hash(pk_script) {
            continue;
        }

        // Count the precise number of signature operations in the
        // referenced public key script.
        let num_sig_ops = dcroxide_txscript::get_precise_sig_op_count(
            &tx_in.signature_script,
            pk_script,
            is_treasury_enabled,
        ) as i64;

        // We could potentially overflow the accumulator so check for
        // overflow.
        let last_sig_ops = total_sig_ops;
        total_sig_ops = total_sig_ops.wrapping_add(num_sig_ops);
        if total_sig_ops < last_sig_ops {
            return Err(rule_error(
                RuleErrorKind::TooManySigOps,
                format!(
                    "the public key script from output {tx_in_outpoint:?} contains too \
                     many signature operations - overflow"
                ),
            ));
        }
    }

    Ok(total_sig_ops)
}

/// Check the number of P2SH signature operations to make sure they
/// don't overflow the limits, accumulating into the passed cumulative
/// count (dcrd `checkNumSigOps`).
pub fn check_num_sig_ops(
    tx: &MsgTx,
    lookup_entry: impl Fn(&OutPoint) -> Option<crate::UtxoEntry>,
    index: usize,
    stake_tree: bool,
    cumulative_sig_ops: i64,
    is_treasury_enabled: bool,
) -> Result<i64, RuleError> {
    let is_ssgen = dcroxide_stake::is_ssgen(tx);
    let is_coinbase_tx = index == 0 && !stake_tree;
    let num_sig_ops = count_sig_ops(tx, is_coinbase_tx, is_ssgen, is_treasury_enabled);
    let num_p2sh_sig_ops = count_p2sh_sig_ops(
        tx,
        is_coinbase_tx,
        is_ssgen,
        lookup_entry,
        is_treasury_enabled,
    )?;

    // Check for overflow or going over the limits on every iteration.
    let start_cum_sig_ops = cumulative_sig_ops;
    let cumulative_sig_ops = cumulative_sig_ops
        .wrapping_add(num_sig_ops)
        .wrapping_add(num_p2sh_sig_ops);
    if cumulative_sig_ops < start_cum_sig_ops || cumulative_sig_ops > MAX_SIG_OPS_PER_BLOCK {
        return Err(rule_error(
            RuleErrorKind::TooManySigOps,
            format!(
                "block contains too many signature operations - got \
                 {cumulative_sig_ops}, max {MAX_SIG_OPS_PER_BLOCK}"
            ),
        ));
    }

    Ok(cumulative_sig_ops)
}

/// Ensure no vote in the given transactions spends more subsidy than
/// allowed for the height being voted on (dcrd
/// `checkStakeBaseAmounts`).
pub fn check_stake_base_amounts<SP: dcroxide_standalone::SubsidyParams>(
    subsidy_cache: &mut dcroxide_standalone::SubsidyCache<SP>,
    height: i64,
    txs: &[MsgTx],
    lookup_entry: impl Fn(&OutPoint) -> Option<crate::UtxoEntry>,
    subsidy_split_variant: dcroxide_standalone::SubsidySplitVariant,
) -> Result<(), RuleError> {
    for tx in txs {
        if !dcroxide_stake::is_ssgen(tx) {
            continue;
        }

        // Ensure the ticket input is available.
        let tx_in_outpoint = &tx.tx_in[1].previous_out_point;
        let Some(utxo_entry) = lookup_entry(tx_in_outpoint) else {
            return Err(rule_error(
                RuleErrorKind::TicketUnavailable,
                format!(
                    "couldn't find input tx {} for stakebase amounts check",
                    tx_in_outpoint.hash
                ),
            ));
        };
        let origin_tx_atom = utxo_entry.amount();

        // Sum up the outputs.
        let mut total_outputs: i64 = 0;
        for out in &tx.tx_out {
            total_outputs = total_outputs.wrapping_add(out.value);
        }
        let difference = total_outputs.wrapping_sub(origin_tx_atom);

        // Subsidy aligns with the height being voted on, not with the
        // height of the current block.
        let calc_subsidy =
            subsidy_cache.calc_stake_vote_subsidy_v3(height - 1, subsidy_split_variant);
        if difference > calc_subsidy {
            return Err(rule_error(
                RuleErrorKind::SSGenSubsidy,
                format!(
                    "ssgen tx {} spent more than allowed (spent {difference}, allowed \
                     {calc_subsidy})",
                    tx.tx_hash()
                ),
            ));
        }
    }

    Ok(())
}

/// The total amount given as subsidy from the collective stakebase
/// transactions (votes) within a block (dcrd `getStakeBaseAmounts`).
pub fn get_stake_base_amounts(
    txs: &[MsgTx],
    lookup_entry: impl Fn(&OutPoint) -> Option<crate::UtxoEntry>,
) -> Result<i64, RuleError> {
    let mut total_inputs: i64 = 0;
    let mut total_outputs: i64 = 0;
    for tx in txs {
        if !dcroxide_stake::is_ssgen(tx) {
            continue;
        }

        // Ensure the ticket input is available.
        let tx_in_outpoint = &tx.tx_in[1].previous_out_point;
        let Some(utxo_entry) = lookup_entry(tx_in_outpoint) else {
            return Err(rule_error(
                RuleErrorKind::TicketUnavailable,
                format!(
                    "couldn't find input tx {} for stakebase amounts get",
                    tx_in_outpoint.hash
                ),
            ));
        };
        total_inputs = total_inputs.wrapping_add(utxo_entry.amount());
        for out in &tx.tx_out {
            total_outputs = total_outputs.wrapping_add(out.value);
        }
    }

    Ok(total_outputs.wrapping_sub(total_inputs))
}

/// The amount of fees in the stake tx tree of a block given the
/// transactions and a utxo lookup (dcrd `getStakeTreeFees`).
pub fn get_stake_tree_fees<SP: dcroxide_standalone::SubsidyParams>(
    subsidy_cache: &mut dcroxide_standalone::SubsidyCache<SP>,
    height: i64,
    txs: &[MsgTx],
    lookup_entry: impl Fn(&OutPoint) -> Option<crate::UtxoEntry>,
    is_treasury_enabled: bool,
    subsidy_split_variant: dcroxide_standalone::SubsidySplitVariant,
) -> Result<i64, RuleError> {
    let mut total_inputs: i64 = 0;
    let mut total_outputs: i64 = 0;
    for tx in txs {
        let is_ssgen = dcroxide_stake::is_ssgen(tx);
        let is_treasury_base = is_treasury_enabled && dcroxide_standalone::is_treasury_base(tx);
        let is_treasury_spend = is_treasury_enabled && dcroxide_stake::is_tspend(tx);

        for (i, tx_in) in tx.tx_in.iter().enumerate() {
            // Ignore stakebases, treasury spends, and treasurybases
            // since they have no inputs.
            if is_ssgen && i == 0 {
                continue;
            }
            if is_treasury_base || is_treasury_spend {
                continue;
            }

            let tx_in_outpoint = &tx_in.previous_out_point;
            let Some(utxo_entry) = lookup_entry(tx_in_outpoint) else {
                return Err(rule_error(
                    RuleErrorKind::TicketUnavailable,
                    format!(
                        "couldn't find input tx {} for stake tree fee calculation",
                        tx_in_outpoint.hash
                    ),
                ));
            };
            total_inputs = total_inputs.wrapping_add(utxo_entry.amount());
        }

        for out in &tx.tx_out {
            total_outputs = total_outputs.wrapping_add(out.value);
        }

        // For votes, subtract the subsidy (aligned with the height
        // being voted on) to determine actual fees.
        if is_ssgen {
            total_outputs = total_outputs.wrapping_sub(
                subsidy_cache.calc_stake_vote_subsidy_v3(height - 1, subsidy_split_variant),
            );
        }
        if is_treasury_spend {
            total_outputs = total_outputs.wrapping_sub(tx.tx_in[0].value_in);
        }
        if is_treasury_base {
            total_outputs = total_outputs.wrapping_sub(tx.tx_in[0].value_in);
        }
    }

    if total_inputs < total_outputs {
        return Err(rule_error(
            RuleErrorKind::StakeFees,
            "negative cumulative fees found in stake tx tree",
        ));
    }

    Ok(total_inputs - total_outputs)
}

/// Whether duplicate transaction hash checking is performed; disabled
/// in dcrd since the unique coinbase heights already prevent
/// collisions in practice (dcrd `checkForDuplicateHashes`).
const CHECK_FOR_DUPLICATE_HASHES: bool = false;

/// Prevent duplicate transaction hashes from overwriting unspent
/// outputs (dcrd `checkDupTxs`); a no-op at this dcrd version per
/// [`CHECK_FOR_DUPLICATE_HASHES`].
pub fn check_dup_txs(
    txs: &[MsgTx],
    lookup_entry: impl Fn(&OutPoint) -> Option<crate::UtxoEntry>,
    tree: i8,
) -> Result<(), RuleError> {
    if !CHECK_FOR_DUPLICATE_HASHES {
        return Ok(());
    }

    // Duplicate transaction outputs are only allowed if the previous
    // transaction output is spent.
    for tx in txs {
        let mut outpoint = OutPoint {
            hash: tx.tx_hash(),
            index: 0,
            tree,
        };
        for tx_out_idx in 0..tx.tx_out.len() {
            outpoint.index = tx_out_idx as u32;
            if let Some(entry) = lookup_entry(&outpoint) {
                if !entry.is_spent() {
                    return Err(rule_error(
                        RuleErrorKind::OverwriteTx,
                        format!(
                            "tried to overwrite transaction output {outpoint:?} at block \
                             height {} that is not spent",
                            entry.block_height()
                        ),
                    ));
                }
            }
        }
    }

    Ok(())
}

/// The maximum number of revocations per block (dcrd
/// `maxRevocationsPerBlock`).
const MAX_REVOCATIONS_PER_BLOCK: i64 = 255;

/// The maximum number of treasury add transactions per block (dcrd
/// `MaxTAddsPerBlock`).
pub const MAX_TADDS_PER_BLOCK: i64 = 20;

/// Determine the agenda flags to use when checking transactions for
/// the block AFTER the given node (dcrd `determineCheckTxFlags`).
pub fn determine_check_tx_flags(
    view: &impl FullChainView,
    prev_height: Option<i64>,
    params: &Params,
) -> Result<AgendaFlags, RuleError> {
    let unknown = |_| {
        rule_error(
            RuleErrorKind::UnknownDeploymentID,
            "deployment not defined on this network",
        )
    };
    let treasury =
        crate::agendas::is_treasury_agenda_active(view, prev_height, params).map_err(unknown)?;
    let explicit = crate::agendas::is_agenda_active(
        view,
        prev_height,
        crate::agendas::VOTE_ID_EXPLICIT_VERSION_UPGRADES,
        params,
    )
    .map_err(unknown)?;
    let auto_rev = crate::agendas::is_agenda_active(
        view,
        prev_height,
        crate::agendas::VOTE_ID_AUTO_REVOCATIONS,
        params,
    )
    .map_err(unknown)?;
    let split = crate::agendas::is_agenda_active(
        view,
        prev_height,
        crate::agendas::VOTE_ID_CHANGE_SUBSIDY_SPLIT,
        params,
    )
    .map_err(unknown)?;
    let split_r2 = crate::agendas::is_agenda_active(
        view,
        prev_height,
        crate::agendas::VOTE_ID_CHANGE_SUBSIDY_SPLIT_R2,
        params,
    )
    .map_err(unknown)?;

    let mut flags = AgendaFlags::default();
    if treasury {
        flags = flags.with(AgendaFlags::TREASURY_ENABLED);
    }
    if explicit {
        flags = flags.with(AgendaFlags::EXPLICIT_VER_UPGRADES);
    }
    if auto_rev {
        flags = flags.with(AgendaFlags::AUTO_REVOCATIONS_ENABLED);
    }
    if split {
        flags = flags.with(AgendaFlags::SUBSIDY_SPLIT_ENABLED);
    }
    if split_r2 {
        flags = flags.with(AgendaFlags::SUBSIDY_SPLIT_R2_ENABLED);
    }
    Ok(flags)
}

/// Perform the validation checks on the block which depend on having
/// the full block data for all of its ancestors available (dcrd
/// `checkBlockContext`).  The parent stake node is required once the
/// stake validation height is reached unless `fast_add` is set; dcrd's
/// recent-context-checks cache is a pure optimization and is not
/// reproduced.
#[allow(clippy::too_many_arguments)]
pub fn check_block_context(
    view: &impl FullChainView,
    block: &MsgBlock,
    prev_height: Option<i64>,
    fast_add: bool,
    no_pow_check: bool,
    parent_pool_size: u32,
    parent_final_state: [u8; 6],
    parent_stake_node: Option<&dcroxide_stake::ticketnode::Node>,
    params: &Params,
) -> Result<(), RuleError> {
    // The genesis block is valid by definition.
    let Some(prev_height) = prev_height else {
        return Ok(());
    };

    let header = &block.header;

    // Perform all block header related validation checks that depend
    // on having the full block data for all of its ancestors.
    check_block_header_context(
        view,
        header,
        Some(prev_height),
        fast_add,
        no_pow_check,
        parent_pool_size,
        parent_final_state,
        params,
    )?;

    let check_tx_flags = determine_check_tx_flags(view, Some(prev_height), params)?;
    let is_treasury_enabled = check_tx_flags.is_treasury_enabled();
    let is_auto_revocations_enabled = check_tx_flags.is_auto_revocations_enabled();

    // The first transaction in a block must be a coinbase.
    if !dcroxide_standalone::is_coin_base_tx(&block.transactions[0], is_treasury_enabled) {
        return Err(rule_error(
            RuleErrorKind::FirstTxNotCoinbase,
            "first transaction in block is not a coinbase",
        ));
    }

    // The coinbase (and the treasurybase under the treasury agenda)
    // must commit to the block height.
    let block_height = prev_height + 1;
    check_coinbase_unique_height(block_height, block, is_treasury_enabled)?;
    if is_treasury_enabled {
        if block.stransactions.is_empty()
            || !dcroxide_standalone::is_treasury_base(&block.stransactions[0])
        {
            return Err(rule_error(
                RuleErrorKind::FirstTxNotTreasurybase,
                "first transaction in stake tree is not a treasurybase",
            ));
        }
        check_treasurybase_unique_height(block_height, block)?;
    }

    // Contextual per-transaction checks over the regular tree, plus
    // the second-coinbase and misplaced-stake-transaction rules.
    for (tx_idx, tx) in block.transactions.iter().enumerate() {
        check_transaction_context(tx, params, check_tx_flags)?;
        if tx_idx > 0 && dcroxide_standalone::is_coin_base_tx(tx, is_treasury_enabled) {
            return Err(rule_error(
                RuleErrorKind::MultipleCoinbases,
                format!("block contains second coinbase at index {tx_idx}"),
            ));
        }
        if dcroxide_stake::determine_tx_type(tx) != dcroxide_stake::TxType::Regular {
            return Err(rule_error(
                RuleErrorKind::StakeTxInRegularTree,
                format!(
                    "block contains a stake transaction in the regular transaction \
                     tree at index {tx_idx}"
                ),
            ));
        }
    }

    // Contextual per-transaction checks over the stake tree plus the
    // second-treasurybase rule.
    for (tx_idx, stx) in block.stransactions.iter().enumerate() {
        check_transaction_context(stx, params, check_tx_flags)?;
        if tx_idx > 0 && is_treasury_enabled && dcroxide_standalone::is_treasury_base(stx) {
            return Err(rule_error(
                RuleErrorKind::MultipleTreasurybases,
                format!("block contains second treasurybase at index {tx_idx}"),
            ));
        }
    }

    // Tally the stake transactions by type, enforcing the vote target
    // block and collecting yes votes and treasury spends.
    let stake_validation_height = params.stake_validation_height as u32;
    let mut total_tickets: i64 = 0;
    let mut total_votes: i64 = 0;
    let mut total_revocations: i64 = 0;
    let mut total_treasury_add: i64 = 0;
    let mut total_treasury_spend: i64 = 0;
    let mut total_treasurybase: i64 = 0;
    let mut total_yes_votes: i64 = 0;
    let mut treasury_spend_txns: Vec<&MsgTx> = Vec::new();
    for (tx_idx, stx) in block.stransactions.iter().enumerate() {
        let tx_type = dcroxide_stake::determine_tx_type(stx);
        if tx_type == dcroxide_stake::TxType::Regular {
            return Err(rule_error(
                RuleErrorKind::RegTxInStakeTree,
                format!(
                    "block contains regular transaction in stake transaction tree at \
                     index {tx_idx}"
                ),
            ));
        }
        match tx_type {
            dcroxide_stake::TxType::SStx => total_tickets += 1,
            dcroxide_stake::TxType::SSGen => {
                total_votes += 1;
                if header.height >= stake_validation_height {
                    let (voted_hash, voted_height) = dcroxide_stake::ssgen_block_voted_on(stx);
                    if voted_hash != header.prev_block || voted_height != header.height - 1 {
                        return Err(rule_error(
                            RuleErrorKind::VotesOnWrongBlock,
                            format!(
                                "vote {} at index {tx_idx} is for parent block \
                                 {voted_hash} (height {voted_height}) versus expected \
                                 parent block {} (height {})",
                                stx.tx_hash(),
                                header.prev_block,
                                header.height - 1
                            ),
                        ));
                    }
                    if vote_bits_approve_parent(dcroxide_stake::ssgen_vote_bits(stx)) {
                        total_yes_votes += 1;
                    }
                }
            }
            dcroxide_stake::TxType::SSRtx => total_revocations += 1,
            _ => {}
        }
        if is_treasury_enabled {
            match tx_type {
                dcroxide_stake::TxType::TAdd => total_treasury_add += 1,
                dcroxide_stake::TxType::TSpend => {
                    total_treasury_spend += 1;
                    treasury_spend_txns.push(stx);
                }
                dcroxide_stake::TxType::TreasuryBase => total_treasurybase += 1,
                _ => {}
            }
        }
    }

    // The number of treasury adds is bounded.
    if total_treasury_add > MAX_TADDS_PER_BLOCK {
        return Err(rule_error(
            RuleErrorKind::TooManyTAdds,
            format!(
                "block contains {total_treasury_add} treasury adds which exceeds the \
                 maximum allowed amount of {MAX_TADDS_PER_BLOCK}"
            ),
        ));
    }

    // Every stake transaction must be accounted for by the tallies.
    let num_stake_tx = block.stransactions.len() as i64;
    let expected_num_stake_tx = total_tickets
        + total_votes
        + total_revocations
        + total_treasury_add
        + total_treasury_spend
        + total_treasurybase;
    if num_stake_tx != expected_num_stake_tx {
        return Err(rule_error(
            RuleErrorKind::NonstandardStakeTx,
            format!(
                "block contains an unexpected number of stake transactions (contains \
                 {num_stake_tx}, expected {expected_num_stake_tx})"
            ),
        ));
    }

    // The header vote commitment must match, and once stake validation
    // begins the header approval bit must agree with the vote tally.
    if i64::from(header.voters) != total_votes {
        return Err(rule_error(
            RuleErrorKind::VotesMismatch,
            format!(
                "block header commitment to {} votes does not match {total_votes} \
                 contained in the block",
                header.voters
            ),
        ));
    }
    if header.height >= stake_validation_height {
        let total_no_votes = total_votes - total_yes_votes;
        let header_approves = header_approves_parent(header);
        let votes_approve = total_yes_votes > total_no_votes;
        if header_approves != votes_approve {
            return Err(rule_error(
                RuleErrorKind::IncongruentVotebit,
                format!(
                    "block header commitment to previous block approval does not match \
                     votes (header claims: {header_approves}, votes: {votes_approve})"
                ),
            ));
        }
    }

    // Only tickets, treasury adds, and treasurybases are allowed
    // before stake validation begins.
    if header.height < stake_validation_height {
        let num_expected = total_tickets + total_treasury_add + total_treasurybase;
        if num_stake_tx != num_expected {
            return Err(rule_error(
                RuleErrorKind::InvalidEarlyStakeTx,
                format!(
                    "block contains disallowed stake transactions before stake \
                     validation height {stake_validation_height} (total: \
                     {num_stake_tx}, expected {num_expected})"
                ),
            ));
        }
    }

    // The number of revocations is bounded and must match the header
    // commitment.
    if total_revocations > MAX_REVOCATIONS_PER_BLOCK {
        return Err(rule_error(
            RuleErrorKind::TooManyRevocations,
            format!(
                "block contains {total_revocations} revocations which exceeds the \
                 maximum allowed amount of {MAX_REVOCATIONS_PER_BLOCK}"
            ),
        ));
    }
    if i64::from(header.revocations) != total_revocations {
        return Err(rule_error(
            RuleErrorKind::RevocationsMismatch,
            format!(
                "block header commitment to {} revocations does not match \
                 {total_revocations} contained in the block",
                header.revocations
            ),
        ));
    }

    // The block must not contain too many signature operations by the
    // quick counting method, checked cumulatively to avoid overflow.
    let mut total_sig_ops: i64 = 0;
    for tx in block.transactions.iter().chain(&block.stransactions) {
        let last_sig_ops = total_sig_ops;
        let is_coin_base = dcroxide_standalone::is_coin_base_tx(tx, is_treasury_enabled);
        let is_ssgen = dcroxide_stake::is_ssgen(tx);
        total_sig_ops = total_sig_ops.wrapping_add(count_sig_ops(
            tx,
            is_coin_base,
            is_ssgen,
            is_treasury_enabled,
        ));
        if total_sig_ops < last_sig_ops || total_sig_ops > MAX_SIG_OPS_PER_BLOCK {
            return Err(rule_error(
                RuleErrorKind::TooManySigOps,
                format!(
                    "block contains too many signature operations - got \
                     {total_sig_ops}, max {MAX_SIG_OPS_PER_BLOCK}"
                ),
            ));
        }
    }

    if !fast_add {
        // The header's claimed size must not exceed the agenda-driven
        // maximum block size.
        let max_block_size = crate::agendas::max_block_size(view, Some(prev_height), params);
        let serialized_size = i64::from(header.size);
        if serialized_size > max_block_size {
            return Err(rule_error(
                RuleErrorKind::BlockTooBig,
                format!(
                    "serialized block is too big - got {serialized_size}, max \
                     {max_block_size}"
                ),
            ));
        }

        // The merkle root commitments must be valid.
        check_merkle_roots(view, block, prev_height, params)?;

        // All transactions must be finalized, relative to the past
        // median time once the LN features agenda is active.
        let mut block_time = i64::from(header.timestamp);
        let ln_features_active =
            crate::agendas::is_ln_features_agenda_active(view, Some(prev_height), params).map_err(
                |_| {
                    rule_error(
                        RuleErrorKind::UnknownDeploymentID,
                        "ln features deployment not defined on this network",
                    )
                },
            )?;
        if ln_features_active {
            block_time = crate::stakever::calc_past_median_time(
                &crate::sequencelock::AsVersionView(view),
                prev_height,
            );
        }
        for tx in &block.transactions {
            if !is_finalized_transaction(tx, block_height, block_time) {
                return Err(rule_error(
                    RuleErrorKind::UnfinalizedTx,
                    format!(
                        "block contains unfinalized regular transaction {}",
                        tx.tx_hash()
                    ),
                ));
            }
        }
        for stx in &block.stransactions {
            if !is_finalized_transaction(stx, block_height, block_time) {
                return Err(rule_error(
                    RuleErrorKind::UnfinalizedTx,
                    format!(
                        "block contains unfinalized stake transaction {}",
                        stx.tx_hash()
                    ),
                ));
            }
        }

        // Once stake validation begins, votes and revocations must
        // redeem tickets per the parent's lottery.
        if header.height >= stake_validation_height {
            let parent_stake_node = parent_stake_node
                .expect("parent stake node required at or above stake validation height");
            let mut vote_ticket_hashes: Vec<Hash> = Vec::new();
            let mut revocation_ticket_hashes: Vec<Hash> = Vec::new();
            for stx in &block.stransactions {
                if dcroxide_stake::is_ssgen(stx) {
                    vote_ticket_hashes.push(stx.tx_in[1].previous_out_point.hash);
                    continue;
                }
                if dcroxide_stake::is_ssrtx(stx) {
                    revocation_ticket_hashes.push(stx.tx_in[0].previous_out_point.hash);
                }
            }
            check_ticket_redeemers(
                &vote_ticket_hashes,
                &revocation_ticket_hashes,
                parent_stake_node.winners(),
                &parent_stake_node.expiring_next_block(),
                |h| parent_stake_node.exists_missed_ticket(h),
                is_auto_revocations_enabled,
            )?;
        }

        // Treasury spends may only appear on treasury vote intervals
        // and must allow a full voting window.
        if is_treasury_enabled && block_height > 1 {
            let tvi = params.treasury_vote_interval;
            let is_tvi = dcroxide_standalone::is_treasury_vote_interval(block_height as u64, tvi);
            if !is_tvi && !treasury_spend_txns.is_empty() {
                let tx = treasury_spend_txns[0];
                let cur_height = block_height as u64;
                let next_tvi = cur_height + (tvi - (cur_height % tvi));
                return Err(rule_error(
                    RuleErrorKind::NotTVI,
                    format!(
                        "block contains treasury spend {} while not on a treasury vote \
                         interval (block height: {block_height}, next TVI: {next_tvi})",
                        tx.tx_hash()
                    ),
                ));
            }
            if is_tvi {
                let min_required_expiry = 2
                    + u64::from(stake_validation_height)
                    + tvi * params.treasury_vote_interval_multiplier;
                for tx in &treasury_spend_txns {
                    if u64::from(tx.expiry) < min_required_expiry {
                        return Err(rule_error(
                            RuleErrorKind::InvalidTVoteWindow,
                            format!(
                                "block contains treasury spend transaction {} before a \
                                 full voting window is possible (height: \
                                 {block_height}, expiry: {}, min required expiry: \
                                 {min_required_expiry})",
                                tx.tx_hash(),
                                tx.expiry
                            ),
                        ));
                    }
                }
            }
        }
    }

    Ok(())
}

/// The script flags to use when executing transaction scripts to
/// enforce consensus rules for the block AFTER the given node (dcrd
/// `consensusScriptVerifyFlags`).
pub fn consensus_script_verify_flags(
    view: &impl FullChainView,
    prev_height: Option<i64>,
    params: &Params,
) -> Result<dcroxide_txscript::ScriptFlags, RuleError> {
    let unknown = |_| {
        rule_error(
            RuleErrorKind::UnknownDeploymentID,
            "deployment not defined on this network",
        )
    };
    let mut script_flags = dcroxide_txscript::ScriptFlags(
        dcroxide_txscript::ScriptFlags::VERIFY_CLEAN_STACK.0
            | dcroxide_txscript::ScriptFlags::VERIFY_CHECK_LOCK_TIME_VERIFY.0,
    );

    // Enable enforcement of OP_CSV and OP_SHA256 when the LN features
    // agenda is active.
    if crate::agendas::is_ln_features_agenda_active(view, prev_height, params).map_err(unknown)? {
        script_flags.0 |= dcroxide_txscript::ScriptFlags::VERIFY_CHECK_SEQUENCE_VERIFY.0;
        script_flags.0 |= dcroxide_txscript::ScriptFlags::VERIFY_SHA256.0;
    }

    // Enable the treasury opcodes when the treasury agenda is active.
    if crate::agendas::is_treasury_agenda_active(view, prev_height, params).map_err(unknown)? {
        script_flags.0 |= dcroxide_txscript::ScriptFlags::VERIFY_TREASURY.0;
    }
    Ok(script_flags)
}

/// Check the transaction inputs for a transaction list against a
/// predetermined utxo view and connect each one to the view,
/// accumulating and validating the fees and subsidies (dcrd
/// `checkTransactionsAndConnect`).  The treasury and automatic
/// revocation agenda states are supplied by the caller, which dcrd
/// derives from the parent node.
#[allow(clippy::too_many_arguments)]
pub fn check_transactions_and_connect<SP: dcroxide_standalone::SubsidyParams>(
    subsidy_cache: &mut dcroxide_standalone::SubsidyCache<SP>,
    input_fees: i64,
    node_height: i64,
    node_voters: u16,
    prev_header: &dcroxide_wire::BlockHeader,
    txs: &[MsgTx],
    view: &mut crate::utxoview::UtxoView,
    mut stxos: Option<&mut Vec<crate::chainio::SpentTxOut>>,
    stake_tree: bool,
    is_treasury_enabled: bool,
    is_auto_revocations_enabled: bool,
    subsidy_split_variant: dcroxide_standalone::SubsidySplitVariant,
    params: &Params,
) -> Result<(), RuleError> {
    // Perform several checks on the inputs for each transaction,
    // accumulating the total fees, and connect each transaction to
    // the view as it validates.
    let mut in_flight_regular_tx: alloc::collections::BTreeMap<[u8; 32], u32> =
        alloc::collections::BTreeMap::new();
    let mut total_fees: i64 = input_fees; // Stake tx tree carry forward
    let mut cumulative_sig_ops: i64 = 0;
    for (idx, tx) in txs.iter().enumerate() {
        cumulative_sig_ops = check_num_sig_ops(
            tx,
            |op| view.lookup_entry(op).cloned(),
            idx,
            stake_tree,
            cumulative_sig_ops,
            is_treasury_enabled,
        )?;

        const CHECK_FRAUD_PROOF: bool = true;
        let tx_fee = check_transaction_inputs(
            subsidy_cache,
            tx,
            node_height,
            |op| view.lookup_entry(op).cloned(),
            CHECK_FRAUD_PROOF,
            params,
            prev_header,
            is_treasury_enabled,
            is_auto_revocations_enabled,
            subsidy_split_variant,
        )?;

        // Sum the total fees and ensure no overflow.
        let last_total_fees = total_fees;
        total_fees = total_fees.wrapping_add(tx_fee);
        if total_fees < last_total_fees {
            return Err(rule_error(
                RuleErrorKind::BadFees,
                "total fees for block overflows accumulator",
            ));
        }

        // Connect the transaction to the view so the remaining
        // transactions can spend its outputs.
        if !stake_tree {
            view.connect_regular_transaction(
                tx,
                node_height,
                idx as u32,
                &mut in_flight_regular_tx,
                stxos.as_deref_mut(),
                is_treasury_enabled,
            )?;
        } else {
            view.connect_stake_transaction(
                tx,
                node_height,
                idx as u32,
                stxos.as_deref_mut(),
                is_treasury_enabled,
            )?;
        }
    }

    if !stake_tree {
        // Apply the penalty for the regular tree fees based on the
        // number of votes once stake validation begins.
        if node_height >= params.stake_validation_height {
            total_fees *= i64::from(node_voters);
            total_fees /= i64::from(params.tickets_per_block);
        }

        // The coinbase must not pay more than the expected subsidy
        // plus the fees, and its input must commit to the subsidy.
        let mut total_atom_out_regular: i64 = 0;
        for tx_out in &txs[0].tx_out {
            total_atom_out_regular = total_atom_out_regular.wrapping_add(tx_out.value);
        }
        let exp_atom_out = if node_height == 1 {
            subsidy_cache.calc_block_subsidy(node_height)
        } else {
            let subsidy_work =
                subsidy_cache.calc_work_subsidy_v3(node_height, node_voters, subsidy_split_variant);
            let subsidy_treasury =
                subsidy_cache.calc_treasury_subsidy(node_height, node_voters, is_treasury_enabled);
            if is_treasury_enabled {
                subsidy_work + total_fees
            } else {
                subsidy_work + subsidy_treasury + total_fees
            }
        };
        let coinbase_in = &txs[0].tx_in[0];
        let subsidy_without_fees = exp_atom_out - total_fees;
        if coinbase_in.value_in != subsidy_without_fees && node_height > 0 {
            return Err(rule_error(
                RuleErrorKind::BadCoinbaseAmountIn,
                format!(
                    "bad coinbase subsidy in input; got {}, expected \
                     {subsidy_without_fees}",
                    coinbase_in.value_in
                ),
            ));
        }
        if total_atom_out_regular > exp_atom_out {
            return Err(rule_error(
                RuleErrorKind::BadCoinbaseValue,
                format!(
                    "coinbase transaction pays {total_atom_out_regular} which is more \
                     than expected value of {exp_atom_out}"
                ),
            ));
        }
    } else {
        // The treasurybase input must commit to the treasury subsidy.
        if node_height > 1 && is_treasury_enabled {
            if txs.is_empty() {
                return Err(rule_error(
                    RuleErrorKind::NoStakeTx,
                    format!("empty tx tree stake, expected treasurybase at height {node_height}"),
                ));
            }
            let subsidy_tax =
                subsidy_cache.calc_treasury_subsidy(node_height, node_voters, is_treasury_enabled);
            let treasurybase_in = &txs[0].tx_in[0];
            if treasurybase_in.value_in != subsidy_tax {
                return Err(rule_error(
                    RuleErrorKind::BadTreasurybaseAmountIn,
                    format!(
                        "bad treasurybase subsidy in input; got {}, expected {subsidy_tax}",
                        treasurybase_in.value_in
                    ),
                ));
            }
        }

        // An empty stake tree is only allowed before stake validation
        // begins.
        if txs.is_empty() && node_height < params.stake_validation_height {
            return Ok(());
        }
        if txs.is_empty() && node_height >= params.stake_validation_height {
            return Err(rule_error(
                RuleErrorKind::NoStakeTx,
                "empty tx tree stake in block after stake validation height",
            ));
        }

        // The votes must not pay out more than the vote subsidies
        // allow.
        check_stake_base_amounts(
            subsidy_cache,
            node_height,
            txs,
            |op| view.lookup_entry(op).cloned(),
            subsidy_split_variant,
        )?;
        let total_atom_out_stake =
            get_stake_base_amounts(txs, |op| view.lookup_entry(op).cloned())?;
        let exp_atom_out = if node_height >= params.stake_validation_height {
            let vote_subsidy =
                subsidy_cache.calc_stake_vote_subsidy_v3(node_height - 1, subsidy_split_variant);
            vote_subsidy * i64::from(node_voters)
        } else {
            total_fees
        };
        if total_atom_out_stake > exp_atom_out {
            return Err(rule_error(
                RuleErrorKind::BadStakebaseValue,
                format!(
                    "stakebase transactions for block pays {total_atom_out_stake} which \
                     is more than expected value of {exp_atom_out}"
                ),
            ));
        }
    }

    Ok(())
}

/// Ensure the coinbase pays the pre-treasury-agenda organization
/// address the correct tax (dcrd `coinbasePaysTreasuryAddress`).
pub fn coinbase_pays_treasury_address<SP: dcroxide_standalone::SubsidyParams>(
    subsidy_cache: &mut dcroxide_standalone::SubsidyCache<SP>,
    tx: &MsgTx,
    height: i64,
    voters: u16,
    params: &Params,
) -> Result<(), RuleError> {
    // Treasury subsidies only apply from block 2 onwards.
    if height <= 1 {
        return Ok(());
    }
    if tx.tx_out.is_empty() {
        return Err(rule_error(
            RuleErrorKind::NoTxOutputs,
            "invalid coinbase (no outputs)",
        ));
    }
    let treasury_output = &tx.tx_out[0];
    if treasury_output.version != params.organization_pk_script_version {
        return Err(rule_error(
            RuleErrorKind::NoTreasury,
            format!(
                "treasury output version {} is instead of {}",
                treasury_output.version, params.organization_pk_script_version
            ),
        ));
    }
    if treasury_output.pk_script != params.organization_pk_script {
        return Err(rule_error(
            RuleErrorKind::NoTreasury,
            "treasury output script does not pay the organization address",
        ));
    }
    let org_subsidy = subsidy_cache.calc_treasury_subsidy(height, voters, false);
    if org_subsidy != treasury_output.value {
        return Err(rule_error(
            RuleErrorKind::NoTreasury,
            format!(
                "treasury output amount is {} instead of {org_subsidy}",
                treasury_output.value
            ),
        ));
    }
    Ok(())
}

/// Ensure the treasurybase pays the correct subsidy into the treasury
/// account (dcrd `checkTreasuryBase`).
pub fn check_treasury_base<SP: dcroxide_standalone::SubsidyParams>(
    subsidy_cache: &mut dcroxide_standalone::SubsidyCache<SP>,
    tx: &MsgTx,
    height: i64,
    voters: u16,
    _params: &Params,
) -> Result<(), RuleError> {
    if height <= 1 {
        return Ok(());
    }
    const REQUIRED_OUTPUTS: usize = 2;
    if tx.tx_out.len() != REQUIRED_OUTPUTS {
        return Err(rule_error(
            RuleErrorKind::InvalidTreasurybaseTxOutputs,
            format!(
                "treasurybase has {} outputs instead of {REQUIRED_OUTPUTS}",
                tx.tx_out.len()
            ),
        ));
    }
    let treasury_output = &tx.tx_out[0];
    if treasury_output.version != 0 {
        return Err(rule_error(
            RuleErrorKind::InvalidTreasurybaseVersion,
            format!(
                "treasury output script version is {} instead of 0",
                treasury_output.version
            ),
        ));
    }
    if treasury_output.pk_script.len() != 1
        || treasury_output.pk_script[0] != dcroxide_txscript::OP_TADD
    {
        return Err(rule_error(
            RuleErrorKind::InvalidTreasurybaseScript,
            "treasury output script is not a lone OP_TADD",
        ));
    }
    let org_subsidy = subsidy_cache.calc_treasury_subsidy(height, voters, true);
    if org_subsidy != treasury_output.value {
        return Err(rule_error(
            RuleErrorKind::TreasurybaseOutValue,
            format!(
                "treasury output amount is {} instead of {org_subsidy}",
                treasury_output.value
            ),
        ));
    }
    Ok(())
}

/// Ensure the block 1 coinbase pays the initial token distribution
/// per the block one ledger (dcrd `blockOneCoinbasePaysTokens`).
pub fn block_one_coinbase_pays_tokens(tx: &MsgTx, params: &Params) -> Result<(), RuleError> {
    if params.block_one_ledger.is_empty() {
        return Ok(());
    }
    if tx.lock_time != 0 {
        return Err(rule_error(
            RuleErrorKind::BlockOneTx,
            "block 1 coinbase has invalid locktime",
        ));
    }
    if tx.expiry != dcroxide_wire::NO_EXPIRY_VALUE {
        return Err(rule_error(
            RuleErrorKind::BlockOneTx,
            "block 1 coinbase has invalid expiry",
        ));
    }
    if tx.tx_in[0].sequence != u32::MAX {
        return Err(rule_error(
            RuleErrorKind::BlockOneInputs,
            "block 1 coinbase not finalized",
        ));
    }
    if tx.tx_out.is_empty() {
        return Err(rule_error(
            RuleErrorKind::BlockOneOutputs,
            "coinbase outputs empty in block 1",
        ));
    }
    let ledger = &params.block_one_ledger;
    if ledger.len() != tx.tx_out.len() {
        return Err(rule_error(
            RuleErrorKind::BlockOneOutputs,
            format!(
                "wrong number of outputs in block 1 coinbase; got {}, expected {}",
                tx.tx_out.len(),
                ledger.len()
            ),
        ));
    }
    for (i, tx_out) in tx.tx_out.iter().enumerate() {
        let ledger_entry = &ledger[i];
        if tx_out.version != ledger_entry.script_version {
            return Err(rule_error(
                RuleErrorKind::BlockOneOutputs,
                format!("block one output {i} script version is wrong"),
            ));
        }
        if tx_out.pk_script != ledger_entry.script {
            return Err(rule_error(
                RuleErrorKind::BlockOneOutputs,
                format!("block one output {i} script is wrong"),
            ));
        }
        if tx_out.value != ledger_entry.amount {
            return Err(rule_error(
                RuleErrorKind::BlockOneOutputs,
                format!("block one output {i} amount is wrong"),
            ));
        }
    }
    Ok(())
}

/// The total subsidy added by the block: the parent's coinbase input
/// when approved, plus the treasurybase and stakebase inputs (dcrd
/// `calculateAddedSubsidy`).
pub fn calculate_added_subsidy(block: &MsgBlock, parent: &MsgBlock) -> i64 {
    let mut subsidy: i64 = 0;
    if header_approves_parent(&block.header) {
        subsidy += parent.transactions[0].tx_in[0].value_in;
    }
    for (tx_idx, stx) in block.stransactions.iter().enumerate() {
        if (tx_idx == 0 && dcroxide_standalone::is_treasury_base(stx))
            || dcroxide_stake::is_ssgen(stx)
        {
            subsidy += stx.tx_in[0].value_in;
        }
    }
    subsidy
}

/// The version 1 block commitment root: the hash of the sole filter
/// commitment (dcrd `CalcCommitmentRootV1`).
pub fn calc_commitment_root_v1(filter_hash: Hash) -> Hash {
    filter_hash
}

/// The stateless treasury spend checks for blocks on a treasury vote
/// interval: the expiry window and the OP_RETURN value-in encoding
/// (the portable half of dcrd `tspendChecks`; the duplicate-spend
/// lookup and the vote tallies over the voting window require prior
/// block data and arrive with the chain engine).
pub fn tspend_checks_stateless(
    prev_height: i64,
    block: &MsgBlock,
    params: &Params,
) -> Result<(), RuleError> {
    let block_height = prev_height + 1;
    let tvi = params.treasury_vote_interval;
    if !dcroxide_standalone::is_treasury_vote_interval(block_height as u64, tvi) {
        return Ok(());
    }
    for stx in &block.stransactions {
        if !dcroxide_stake::is_tspend(stx) {
            continue;
        }
        let exp = stx.expiry;
        if !dcroxide_standalone::inside_tspend_window(
            block_height,
            exp,
            tvi,
            params.treasury_vote_interval_multiplier,
        ) {
            return Err(rule_error(
                RuleErrorKind::InvalidTSpendWindow,
                format!(
                    "block at height {block_height} contains treasury spend transaction \
                     {} with expiry {exp} that is outside of the valid window",
                    stx.tx_hash()
                ),
            ));
        }

        // A valid treasury spend stores the entire spent amount in the
        // first input, which must match the little-endian amount in
        // the OP_RETURN.
        let value_in = stx.tx_in[0].value_in;
        let mut le = [0u8; 8];
        le.copy_from_slice(&stx.tx_out[0].pk_script[2..10]);
        let value_in_op_ret = i64::from_le_bytes(le);
        if value_in != value_in_op_ret {
            return Err(rule_error(
                RuleErrorKind::InvalidTSpendValueIn,
                format!(
                    "block contains TSpend transaction ({}) that did not encode ValueIn \
                     correctly got {value_in_op_ret} wanted {value_in}",
                    stx.tx_hash()
                ),
            ));
        }
    }
    Ok(())
}

/// Validate every script in one of the block's transaction trees
/// against the utxo view (dcrd `checkBlockScripts`, executed
/// sequentially; dcrd's signature cache is a result-invariant
/// memoization and is not reproduced).
pub fn check_block_scripts(
    block: &MsgBlock,
    view: &crate::utxoview::UtxoView,
    tx_tree_regular: bool,
    script_flags: dcroxide_txscript::ScriptFlags,
    is_auto_revocations_enabled: bool,
) -> Result<(), RuleError> {
    let txs = if tx_tree_regular {
        &block.transactions
    } else {
        &block.stransactions
    };
    for tx in txs {
        // Skip version 2+ revocations under the automatic revocations
        // agenda since consensus already enforces their outputs.
        if is_auto_revocations_enabled
            && !tx_tree_regular
            && tx.version >= dcroxide_stake::TX_VERSION_AUTO_REVOCATIONS
            && dcroxide_stake::is_ssrtx(tx)
        {
            continue;
        }
        for (tx_in_idx, tx_in) in tx.tx_in.iter().enumerate() {
            // Skip coinbase-style inputs.
            if tx_in.previous_out_point.index == u32::MAX {
                continue;
            }
            let Some(entry) = view.lookup_entry(&tx_in.previous_out_point) else {
                return Err(rule_error(
                    RuleErrorKind::MissingTxOut,
                    format!(
                        "unable to find unspent output {:?} referenced from transaction \
                         {}:{tx_in_idx}",
                        tx_in.previous_out_point,
                        tx.tx_hash()
                    ),
                ));
            };
            let pk_script = entry.pk_script().to_vec();
            let version = entry.script_version();
            let mut engine =
                dcroxide_txscript::Engine::new(&pk_script, tx, tx_in_idx, script_flags, version)
                    .map_err(|e| {
                        rule_error(
                            RuleErrorKind::ScriptValidation,
                            format!("failed to create script engine: {e:?}"),
                        )
                    })?;
            engine.execute().map_err(|e| {
                rule_error(
                    RuleErrorKind::ScriptValidation,
                    format!(
                        "failed to validate input {}:{tx_in_idx}: {e:?}",
                        tx.tx_hash()
                    ),
                )
            })?;
        }
    }
    Ok(())
}

/// Perform the final battery of checks needed to connect the block to
/// the main chain, connecting the view and producing the spend
/// journal and header commitment filter (dcrd `checkConnectBlock`).
///
/// The caller supplies the disapproved-parent spend journal (dcrd
/// fetches it from the database), whether scripts should run (dcrd
/// derives this from bulk import mode and the assumed-valid ancestor),
/// and the parent's past median time when the LN features agenda is
/// active.  The treasury spend duplicate and vote tally checks from
/// dcrd's `tspendChecks` require prior block data and arrive with the
/// chain engine.
#[allow(clippy::too_many_arguments)]
pub fn check_connect_block<SP: dcroxide_standalone::SubsidyParams>(
    view_chain: &impl FullChainView,
    subsidy_cache: &mut dcroxide_standalone::SubsidyCache<SP>,
    node_height: i64,
    node_hash: Hash,
    node_voters: u16,
    node_vote_bits: u16,
    block: &MsgBlock,
    parent: &MsgBlock,
    parent_stxos: &[crate::chainio::SpentTxOut],
    view: &mut crate::utxoview::UtxoView,
    resolver: &impl crate::utxoview::UtxoResolver,
    mut stxos: Option<&mut Vec<crate::chainio::SpentTxOut>>,
    run_scripts: bool,
    params: &Params,
) -> Result<Hash, RuleError> {
    let prev_height = node_height - 1;
    // The view must be from the point of view of the parent.
    assert_eq!(
        view.best_hash(),
        block.header.prev_block,
        "inconsistent view when checking block connection"
    );

    let unknown = |_| {
        rule_error(
            RuleErrorKind::UnknownDeploymentID,
            "deployment not defined on this network",
        )
    };
    let is_treasury_enabled =
        crate::agendas::is_treasury_agenda_active(view_chain, Some(prev_height), params)
            .map_err(unknown)?;

    // The treasury subsidy goes to the treasurybase under the agenda
    // and to the organization address before it.
    if is_treasury_enabled {
        check_treasury_base(
            subsidy_cache,
            &block.stransactions[0],
            node_height,
            node_voters,
            params,
        )?;
        tspend_checks_stateless(prev_height, block, params)?;
    } else {
        coinbase_pays_treasury_address(
            subsidy_cache,
            &block.transactions[0],
            node_height,
            node_voters,
            params,
        )?;
    }

    let script_flags = if run_scripts {
        consensus_script_verify_flags(view_chain, Some(prev_height), params)?
    } else {
        dcroxide_txscript::ScriptFlags(0)
    };

    let is_auto_revocations_enabled = crate::agendas::is_agenda_active(
        view_chain,
        Some(prev_height),
        crate::agendas::VOTE_ID_AUTO_REVOCATIONS,
        params,
    )
    .map_err(unknown)?;

    // Undo the parent's regular transactions when this block
    // disapproves them.
    if node_height > 1 && !vote_bits_approve_parent(node_vote_bits) {
        view.disconnect_disapproved_block(parent, parent_stxos, resolver, is_treasury_enabled)?;
    }

    // Duplicate transaction checking is a no-op at this version.
    check_dup_txs(&block.stransactions, |op| view.lookup_entry(op).cloned(), 1)?;

    // Load all of the utxos referenced by the block that are not
    // already in the view.
    view.fetch_input_utxos(block, resolver, is_treasury_enabled);

    // Determine the subsidy split.
    let split = crate::agendas::is_agenda_active(
        view_chain,
        Some(prev_height),
        crate::agendas::VOTE_ID_CHANGE_SUBSIDY_SPLIT,
        params,
    )
    .map_err(unknown)?;
    let split_r2 = crate::agendas::is_agenda_active(
        view_chain,
        Some(prev_height),
        crate::agendas::VOTE_ID_CHANGE_SUBSIDY_SPLIT_R2,
        params,
    )
    .map_err(unknown)?;
    let subsidy_split_variant = if split_r2 {
        dcroxide_standalone::SubsidySplitVariant::Dcp0012
    } else if split {
        dcroxide_standalone::SubsidySplitVariant::Dcp0010
    } else {
        dcroxide_standalone::SubsidySplitVariant::Original
    };

    // Connect the stake tree with full checks.
    let prev_header = &parent.header;
    check_transactions_and_connect(
        subsidy_cache,
        0,
        node_height,
        node_voters,
        prev_header,
        &block.stransactions,
        view,
        stxos.as_deref_mut(),
        true,
        is_treasury_enabled,
        is_auto_revocations_enabled,
        subsidy_split_variant,
        params,
    )?;
    let stake_tree_fees = get_stake_tree_fees(
        subsidy_cache,
        node_height,
        &block.stransactions,
        |op| view.lookup_entry(op).cloned(),
        is_treasury_enabled,
        subsidy_split_variant,
    )?;

    // Enforce sequence locks once the LN features agenda is active.
    let ln_features_active =
        crate::agendas::is_ln_features_agenda_active(view_chain, Some(prev_height), params)
            .map_err(unknown)?;
    let mut prev_median_time = 0i64;
    if ln_features_active {
        prev_median_time = crate::stakever::calc_past_median_time(
            &crate::sequencelock::AsVersionView(view_chain),
            prev_height,
        );
        for stx in &block.stransactions {
            let lock = crate::sequencelock::calc_sequence_lock(
                view_chain,
                node_height,
                stx,
                |op| Some(view.lookup_entry(op)?.block_height()),
                true,
                params,
            )?;
            if !sequence_lock_active(&lock, node_height, prev_median_time) {
                return Err(rule_error(
                    RuleErrorKind::UnfinalizedTx,
                    "block contains stake transaction whose input sequence locks are \
                     not met",
                ));
            }
        }
    }

    if run_scripts {
        check_block_scripts(
            block,
            view,
            false,
            script_flags,
            is_auto_revocations_enabled,
        )?;
    }

    check_dup_txs(&block.transactions, |op| view.lookup_entry(op).cloned(), 0)?;

    // Connect the regular tree with full checks, carrying the stake
    // tree fees forward.
    check_transactions_and_connect(
        subsidy_cache,
        stake_tree_fees,
        node_height,
        node_voters,
        prev_header,
        &block.transactions,
        view,
        stxos,
        false,
        is_treasury_enabled,
        is_auto_revocations_enabled,
        subsidy_split_variant,
        params,
    )?;

    if ln_features_active {
        for tx in &block.transactions[1..] {
            let lock = crate::sequencelock::calc_sequence_lock(
                view_chain,
                node_height,
                tx,
                |op| Some(view.lookup_entry(op)?.block_height()),
                true,
                params,
            )?;
            if !sequence_lock_active(&lock, node_height, prev_median_time) {
                return Err(rule_error(
                    RuleErrorKind::UnfinalizedTx,
                    "block contains transaction whose input sequence locks are not met",
                ));
            }
        }
    }

    // Build the version 2 committed filter and validate the header
    // commitment to it once the agenda is active.
    struct ViewScripts<'a>(&'a crate::utxoview::UtxoView);
    impl dcroxide_gcs::blockcf2::PrevScripter for ViewScripts<'_> {
        fn prev_script(&self, out: &dcroxide_wire::OutPoint) -> Option<(u16, &[u8])> {
            let entry = self.0.lookup_entry(out)?;
            Some((entry.script_version(), entry.pk_script()))
        }
    }
    let filter = dcroxide_gcs::blockcf2::regular(block, &ViewScripts(view))
        .map_err(|e| rule_error(RuleErrorKind::MissingTxOut, format!("{e:?}")))?;
    let filter_hash = filter.hash();

    let hdr_commitments_active =
        crate::agendas::is_header_commitments_agenda_active(view_chain, Some(prev_height), params)
            .map_err(unknown)?;
    if hdr_commitments_active {
        let want_commitment_root = calc_commitment_root_v1(filter_hash);
        if block.header.stake_root != want_commitment_root {
            return Err(rule_error(
                RuleErrorKind::BadCommitmentRoot,
                format!(
                    "block commitment root is invalid - block header indicates {}, but \
                     calculated value is {want_commitment_root}",
                    block.header.stake_root
                ),
            ));
        }
    }

    if run_scripts {
        check_block_scripts(block, view, true, script_flags, is_auto_revocations_enabled)?;
    }

    // The block one coinbase pays the initial token distribution.
    if node_height == 1 {
        block_one_coinbase_pays_tokens(&block.transactions[0], params)?;
    }

    view.set_best_hash(node_hash);
    Ok(filter_hash)
}
