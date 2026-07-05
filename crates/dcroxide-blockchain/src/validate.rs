// SPDX-License-Identifier: ISC
//! Context-free transaction and proof validation (the corresponding
//! portions of dcrd internal/blockchain `validate.go`): agenda flags,
//! the transaction context checks layered over the standalone sanity
//! checks, proof-of-stake commitment checks, and the proof-of-work
//! sanity check spanning both hash versions.

use alloc::format;

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
