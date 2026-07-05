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
