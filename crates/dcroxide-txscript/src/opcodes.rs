// SPDX-License-Identifier: ISC
//! Opcode metadata and execution handlers (dcrd `opcode.go`).
//!
//! The 256-entry dispatch table itself is generated in `opcode_table.rs`;
//! every handler here is a line-by-line port of the corresponding dcrd
//! `opcode*` function, preserving evaluation order, error kinds, and the
//! consensus-frozen quirks called out in dcrd's comments (e.g. the
//! pre-bounds-check empty-string returns in OP_SUBSTR/LEFT/RIGHT and the
//! 4-byte ScriptNum limits on rotation/shift counts).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use sha1::Digest as _;

use crate::consensus::{
    LOCK_TIME_THRESHOLD, check_hash_type_encoding, check_pub_key_encoding, check_signature_encoding,
};
use crate::engine::{Engine, NO_COND_DISABLE_DEPTH, ScriptFlags};
use crate::error::{ErrorKind, ScriptError, script_error};
use crate::opcode_table::*;
use crate::script::remove_opcode_by_data;
use crate::scriptnum::{
    ALT_SIG_SUITES_MAX_SCRIPT_NUM_LEN, CLTV_MAX_SCRIPT_NUM_LEN, CSV_MAX_SCRIPT_NUM_LEN,
    MATH_OP_CODE_MAX_SCRIPT_NUM_LEN, ScriptNum,
};
use crate::sighash::{SigHashType, calc_signature_hash};
use crate::{MAX_OPS_PER_SCRIPT, MAX_PUB_KEYS_PER_MULTI_SIG, MAX_SCRIPT_ELEMENT_SIZE};

/// The signature type identifiers redeemable by OP_CHECKSIGALT (dcrd
/// `dcrec.SignatureType` values).
const ST_ED25519: i64 = 1;
const ST_SCHNORR_SECP256K1: i64 = 2;

/// The handler signature for opcode execution (dcrd `opcode.opfunc`).
pub(crate) type OpcodeFn = fn(&OpcodeInfo, &[u8], &mut Engine) -> Result<(), ScriptError>;

/// Information about a txscript opcode (dcrd `opcode`): its value, name,
/// length semantics (positive: opcode plus that many total bytes; negative:
/// push with -length length-prefix bytes), and execution handler.
pub(crate) struct OpcodeInfo {
    pub value: u8,
    pub name: &'static str,
    pub length: i32,
    pub func: OpcodeFn,
}

/// The length semantics for an opcode from the dispatch table.
pub(crate) fn opcode_length(op: u8) -> i32 {
    OPCODE_ARRAY[op as usize].length
}

/// The human-readable name for an opcode (dcrd `opcodeArray[op].name`,
/// the same names `OpcodeByName` inverts).
pub fn opcode_name(op: u8) -> &'static str {
    OPCODE_ARRAY[op as usize].name
}

/// The compact-disassembly replacement names (dcrd `opcodeOnelineRepls`).
fn oneline_repl(name: &str) -> Option<&'static str> {
    Some(match name {
        "OP_1NEGATE" => "-1",
        "OP_0" => "0",
        "OP_1" => "1",
        "OP_2" => "2",
        "OP_3" => "3",
        "OP_4" => "4",
        "OP_5" => "5",
        "OP_6" => "6",
        "OP_7" => "7",
        "OP_8" => "8",
        "OP_9" => "9",
        "OP_10" => "10",
        "OP_11" => "11",
        "OP_12" => "12",
        "OP_13" => "13",
        "OP_14" => "14",
        "OP_15" => "15",
        "OP_16" => "16",
        _ => return None,
    })
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        use core::fmt::Write as _;
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// Write a human-readable disassembly of the opcode and data (dcrd
/// `disasmOpcode`); `compact` produces the reference one-line form.
pub(crate) fn disasm_opcode(buf: &mut String, op: u8, data: &[u8], compact: bool) {
    let info = &OPCODE_ARRAY[op as usize];
    let mut opcode_name = info.name;
    if compact {
        if let Some(repl) = oneline_repl(opcode_name) {
            opcode_name = repl;
        }

        // Either write the human-readable opcode or the parsed data in hex
        // for data-carrying opcodes.
        if info.length == 1 {
            buf.push_str(opcode_name);
        } else {
            buf.push_str(&hex(data));
        }
        return;
    }

    buf.push_str(opcode_name);

    match info.length {
        // Only write the opcode name for non-data push opcodes.
        1 => return,
        // Add length for the OP_PUSHDATA# opcodes.
        -1 => buf.push_str(&format!(" 0x{:02x}", data.len())),
        -2 => buf.push_str(&format!(" 0x{:04x}", data.len())),
        -4 => buf.push_str(&format!(" 0x{:08x}", data.len())),
        _ => {}
    }

    buf.push_str(&format!(" 0x{}", hex(data)));
}

// *******************************************
// Opcode implementation functions start here.
// *******************************************

/// Common handler for disabled opcodes (dcrd `opcodeDisabled`); per
/// consensus the failure occurs when the program counter passes over one,
/// even in a non-executed branch.
pub(crate) fn opcode_disabled(
    op: &OpcodeInfo,
    _data: &[u8],
    _vm: &mut Engine,
) -> Result<(), ScriptError> {
    Err(script_error(
        ErrorKind::DisabledOpcode,
        format!("attempt to execute disabled opcode {}", op.name),
    ))
}

/// Common handler for reserved opcodes (dcrd `opcodeReserved`).
pub(crate) fn opcode_reserved(
    op: &OpcodeInfo,
    _data: &[u8],
    _vm: &mut Engine,
) -> Result<(), ScriptError> {
    Err(script_error(
        ErrorKind::ReservedOpcode,
        format!("attempt to execute reserved opcode {}", op.name),
    ))
}

/// Common handler for invalid opcodes (dcrd `opcodeInvalid`; note it uses
/// the reserved-opcode error kind, matching dcrd).
pub(crate) fn opcode_invalid(
    op: &OpcodeInfo,
    _data: &[u8],
    _vm: &mut Engine,
) -> Result<(), ScriptError> {
    Err(script_error(
        ErrorKind::ReservedOpcode,
        format!("attempt to execute invalid opcode {}", op.name),
    ))
}

/// Push an empty array to the data stack (dcrd `opcodeFalse`).
pub(crate) fn opcode_false(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    vm.dstack.push_byte_array(Vec::new());
    Ok(())
}

/// Push raw data to the data stack (dcrd `opcodePushData`).
pub(crate) fn opcode_push_data(
    _op: &OpcodeInfo,
    data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    vm.dstack.push_byte_array(data.to_vec());
    Ok(())
}

/// Push -1 encoded as a number (dcrd `opcode1Negate`).
pub(crate) fn opcode_1negate(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    vm.dstack.push_int(ScriptNum(-1));
    Ok(())
}

/// Push the small integer 1-16 the opcode represents (dcrd `opcodeN`).
pub(crate) fn opcode_n(op: &OpcodeInfo, _data: &[u8], vm: &mut Engine) -> Result<(), ScriptError> {
    // The opcodes are all defined consecutively, so the numeric value is
    // the difference.
    vm.dstack
        .push_int(ScriptNum(i64::from(op.value - (OP_1 - 1))));
    Ok(())
}

/// The NOP family (dcrd `opcodeNop`); select opcodes error when the flag to
/// discourage upgradable NOPs is set.
pub(crate) fn opcode_nop(
    op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    if matches!(
        op.value,
        OP_NOP1 | OP_NOP4..=OP_NOP10 | OP_UNKNOWN196..=OP_UNKNOWN248
    ) && vm.has_flag(ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS)
    {
        return Err(script_error(
            ErrorKind::DiscourageUpgradableNOPs,
            format!("{} reserved for upgrades", op.name),
        ));
    }
    Ok(())
}

/// OP_IF (dcrd `opcodeIf`); executed even on non-executing branches so
/// nesting is maintained.
pub(crate) fn opcode_if(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    if vm.is_branch_executing() {
        let ok = vm.dstack.pop_bool()?;
        if !ok {
            // Branch execution is being disabled when it was not
            // previously, so mark the current conditional nesting depth as
            // the depth at which it was disabled.
            vm.cond_disable_depth = vm.cond_nest_depth;
        }
    }
    vm.cond_nest_depth += 1;
    Ok(())
}

/// OP_NOTIF (dcrd `opcodeNotIf`).
pub(crate) fn opcode_notif(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    if vm.is_branch_executing() {
        let ok = vm.dstack.pop_bool()?;
        if ok {
            vm.cond_disable_depth = vm.cond_nest_depth;
        }
    }
    vm.cond_nest_depth += 1;
    Ok(())
}

/// OP_ELSE (dcrd `opcodeElse`).
pub(crate) fn opcode_else(
    op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    if vm.cond_nest_depth == 0 {
        return Err(script_error(
            ErrorKind::UnbalancedConditional,
            format!(
                "encountered opcode {} with no matching opcode to begin conditional execution",
                op.name
            ),
        ));
    }

    let conditional_depth = vm.cond_nest_depth - 1;
    if vm.is_branch_executing() {
        // Branch execution is being disabled when it was not previously,
        // so mark the most recent conditional nesting depth as the depth
        // at which it was disabled.
        vm.cond_disable_depth = conditional_depth;
    } else if vm.cond_disable_depth == conditional_depth {
        // Enable branch execution when it was previously disabled as a
        // result of the opcode at the depth that is being toggled.
        vm.cond_disable_depth = NO_COND_DISABLE_DEPTH;
    }
    Ok(())
}

/// OP_ENDIF (dcrd `opcodeEndif`).
pub(crate) fn opcode_endif(
    op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    if vm.cond_nest_depth == 0 {
        return Err(script_error(
            ErrorKind::UnbalancedConditional,
            format!(
                "encountered opcode {} with no matching opcode to begin conditional execution",
                op.name
            ),
        ));
    }

    vm.cond_nest_depth -= 1;
    if vm.cond_disable_depth == vm.cond_nest_depth {
        vm.cond_disable_depth = NO_COND_DISABLE_DEPTH;
    }
    Ok(())
}

/// Pop the top stack item as a bool and require it to be true, failing with
/// the given kind otherwise (dcrd `abstractVerify`).
fn abstract_verify(op: &OpcodeInfo, vm: &mut Engine, kind: ErrorKind) -> Result<(), ScriptError> {
    let verified = vm.dstack.pop_bool()?;
    if !verified {
        return Err(script_error(kind, format!("{} failed", op.name)));
    }
    Ok(())
}

/// OP_VERIFY (dcrd `opcodeVerify`).
pub(crate) fn opcode_verify(
    op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    abstract_verify(op, vm, ErrorKind::Verify)
}

/// OP_RETURN (dcrd `opcodeReturn`).
pub(crate) fn opcode_return(
    _op: &OpcodeInfo,
    _data: &[u8],
    _vm: &mut Engine,
) -> Result<(), ScriptError> {
    Err(script_error(
        ErrorKind::EarlyReturn,
        "script returned early",
    ))
}

/// Validate locktimes (dcrd `verifyLockTime`).
#[allow(clippy::nonminimal_bool)] // Keep dcrd's exact boolean structure.
fn verify_lock_time(tx_lock_time: i64, threshold: i64, lock_time: i64) -> Result<(), ScriptError> {
    // The lockTimes in both the script and transaction must be of the same
    // type.
    if !((tx_lock_time < threshold && lock_time < threshold)
        || (tx_lock_time >= threshold && lock_time >= threshold))
    {
        return Err(script_error(
            ErrorKind::UnsatisfiedLockTime,
            format!(
                "mismatched locktime types -- tx locktime {tx_lock_time}, stack locktime {lock_time}"
            ),
        ));
    }

    if lock_time > tx_lock_time {
        return Err(script_error(
            ErrorKind::UnsatisfiedLockTime,
            format!(
                "locktime requirement not satisfied -- locktime is greater than the \
                 transaction locktime: {lock_time} > {tx_lock_time}"
            ),
        ));
    }

    Ok(())
}

/// OP_CHECKLOCKTIMEVERIFY (dcrd `opcodeCheckLockTimeVerify`).
pub(crate) fn opcode_check_lock_time_verify(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    // Treat as OP_NOP2 when the flag is not set.
    if !vm.has_flag(ScriptFlags::VERIFY_CHECK_LOCK_TIME_VERIFY) {
        if vm.has_flag(ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS) {
            return Err(script_error(
                ErrorKind::DiscourageUpgradableNOPs,
                "OP_NOP2 reserved for soft-fork upgrades",
            ));
        }
        return Ok(());
    }

    // A 5-byte ScriptNum is used since the locktime field is a u32.
    let lock_time = vm.dstack.peek_int(0, CLTV_MAX_SCRIPT_NUM_LEN)?;

    // In the rare event that the argument needs to be < 0 due to some
    // arithmetic being done first, you can always use
    // 0 OP_MAX OP_CHECKLOCKTIMEVERIFY.
    if lock_time.0 < 0 {
        return Err(script_error(
            ErrorKind::NegativeLockTime,
            format!("negative lock time: {}", lock_time.0),
        ));
    }

    verify_lock_time(i64::from(vm.tx.lock_time), LOCK_TIME_THRESHOLD, lock_time.0)?;

    // The opcode is also ineffective (and thus must fail) when the input
    // being used by it is finalized (max sequence).
    if vm.tx.tx_in[vm.tx_idx].sequence == dcroxide_wire::MAX_TX_IN_SEQUENCE_NUM {
        return Err(script_error(
            ErrorKind::UnsatisfiedLockTime,
            "transaction input is finalized",
        ));
    }

    Ok(())
}

/// OP_CHECKSEQUENCEVERIFY (dcrd `opcodeCheckSequenceVerify`).
pub(crate) fn opcode_check_sequence_verify(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    // Treat as OP_NOP3 when the flag is not set.
    if !vm.has_flag(ScriptFlags::VERIFY_CHECK_SEQUENCE_VERIFY) {
        if vm.has_flag(ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS) {
            return Err(script_error(
                ErrorKind::DiscourageUpgradableNOPs,
                "OP_NOP3 reserved for soft-fork upgrades",
            ));
        }
        return Ok(());
    }

    // A 5-byte ScriptNum is used since the sequence field is a u32.
    let stack_sequence = vm.dstack.peek_int(0, CSV_MAX_SCRIPT_NUM_LEN)?;

    // In the rare event that the argument needs to be < 0 due to some
    // arithmetic being done first, you can always use
    // 0 OP_MAX OP_CHECKSEQUENCEVERIFY.
    if stack_sequence.0 < 0 {
        return Err(script_error(
            ErrorKind::NegativeLockTime,
            format!("negative sequence: {}", stack_sequence.0),
        ));
    }

    let sequence = stack_sequence.0;

    // To provide for future soft-fork extensibility, if the operand has the
    // disabled lock-time flag set, CHECKSEQUENCEVERIFY behaves as a NOP.
    if sequence & i64::from(dcroxide_wire::SEQUENCE_LOCK_TIME_DISABLED) != 0 {
        return Ok(());
    }

    // Transaction version numbers not high enough to trigger CSV rules must
    // fail.
    if vm.tx.version < 2 {
        return Err(script_error(
            ErrorKind::UnsatisfiedLockTime,
            format!("invalid transaction version: {}", vm.tx.version),
        ));
    }

    // Sequence numbers with their most significant bit set are not
    // consensus constrained.
    let tx_sequence = i64::from(vm.tx.tx_in[vm.tx_idx].sequence);
    if tx_sequence & i64::from(dcroxide_wire::SEQUENCE_LOCK_TIME_DISABLED) != 0 {
        return Err(script_error(
            ErrorKind::UnsatisfiedLockTime,
            format!(
                "transaction sequence has sequence locktime disabled bit set: 0x{tx_sequence:x}"
            ),
        ));
    }

    // Mask off non-consensus bits before doing comparisons.
    let lock_time_mask = i64::from(
        dcroxide_wire::SEQUENCE_LOCK_TIME_IS_SECONDS | dcroxide_wire::SEQUENCE_LOCK_TIME_MASK,
    );
    verify_lock_time(
        tx_sequence & lock_time_mask,
        i64::from(dcroxide_wire::SEQUENCE_LOCK_TIME_IS_SECONDS),
        sequence & lock_time_mask,
    )
}

/// OP_TOALTSTACK (dcrd `opcodeToAltStack`).
pub(crate) fn opcode_to_alt_stack(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let so = vm.dstack.pop_byte_array()?;
    vm.astack.push_byte_array(so);
    Ok(())
}

/// OP_FROMALTSTACK (dcrd `opcodeFromAltStack`).
pub(crate) fn opcode_from_alt_stack(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let so = vm.astack.pop_byte_array()?;
    vm.dstack.push_byte_array(so);
    Ok(())
}

/// OP_2DROP (dcrd `opcode2Drop`).
pub(crate) fn opcode_2drop(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    vm.dstack.drop_n(2)
}

/// OP_2DUP (dcrd `opcode2Dup`).
pub(crate) fn opcode_2dup(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    vm.dstack.dup_n(2)
}

/// OP_3DUP (dcrd `opcode3Dup`).
pub(crate) fn opcode_3dup(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    vm.dstack.dup_n(3)
}

/// OP_2OVER (dcrd `opcode2Over`).
pub(crate) fn opcode_2over(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    vm.dstack.over_n(2)
}

/// OP_2ROT (dcrd `opcode2Rot`).
pub(crate) fn opcode_2rot(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    vm.dstack.rot_n(2)
}

/// OP_2SWAP (dcrd `opcode2Swap`).
pub(crate) fn opcode_2swap(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    vm.dstack.swap_n(2)
}

/// OP_IFDUP (dcrd `opcodeIfDup`).
pub(crate) fn opcode_if_dup(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let so = vm.dstack.peek_byte_array(0)?.to_vec();

    // Push copy of data iff it isn't zero.
    if crate::stack::as_bool(&so) {
        vm.dstack.push_byte_array(so);
    }
    Ok(())
}

/// OP_DEPTH (dcrd `opcodeDepth`).
pub(crate) fn opcode_depth(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let depth = vm.dstack.depth();
    vm.dstack.push_int(ScriptNum(i64::from(depth)));
    Ok(())
}

/// OP_DROP (dcrd `opcodeDrop`).
pub(crate) fn opcode_drop(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    vm.dstack.drop_n(1)
}

/// OP_DUP (dcrd `opcodeDup`).
pub(crate) fn opcode_dup(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    vm.dstack.dup_n(1)
}

/// OP_NIP (dcrd `opcodeNip`).
pub(crate) fn opcode_nip(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    vm.dstack.nip_n(1)
}

/// OP_OVER (dcrd `opcodeOver`).
pub(crate) fn opcode_over(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    vm.dstack.over_n(1)
}

/// OP_PICK (dcrd `opcodePick`).
pub(crate) fn opcode_pick(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let val = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack.pick_n(val.int32())
}

/// OP_ROLL (dcrd `opcodeRoll`).
pub(crate) fn opcode_roll(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let val = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack.roll_n(val.int32())
}

/// OP_ROT (dcrd `opcodeRot`).
pub(crate) fn opcode_rot(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    vm.dstack.rot_n(1)
}

/// OP_SWAP (dcrd `opcodeSwap`).
pub(crate) fn opcode_swap(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    vm.dstack.swap_n(1)
}

/// OP_TUCK (dcrd `opcodeTuck`).
pub(crate) fn opcode_tuck(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    vm.dstack.tuck()
}

/// OP_CAT (dcrd `opcodeCat`).
pub(crate) fn opcode_cat(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let a = vm.dstack.pop_byte_array()?; // x2
    let b = vm.dstack.pop_byte_array()?; // x1

    // Handle zero length byte slice cases exactly like dcrd.
    match (a.is_empty(), b.is_empty()) {
        (true, false) => {
            vm.dstack.push_byte_array(b);
            return Ok(());
        }
        (false, true) => {
            vm.dstack.push_byte_array(a);
            return Ok(());
        }
        (true, true) => {
            vm.dstack.push_byte_array(Vec::new());
            return Ok(());
        }
        (false, false) => {}
    }

    // Ensure the result does not overflow the maximum stack item size.
    let combined_len = a.len() + b.len();
    if combined_len > MAX_SCRIPT_ELEMENT_SIZE {
        return Err(script_error(
            ErrorKind::ElementTooBig,
            format!(
                "element size {combined_len} exceeds max allowed size {MAX_SCRIPT_ELEMENT_SIZE}"
            ),
        ));
    }

    let mut c = Vec::with_capacity(combined_len);
    c.extend_from_slice(&b);
    c.extend_from_slice(&a);
    vm.dstack.push_byte_array(c);
    Ok(())
}

/// OP_SUBSTR (dcrd `opcodeSubstr`), including the consensus-frozen quirk of
/// returning an empty push for an empty string before bounds checking.
pub(crate) fn opcode_substr(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?; // x3
    let v1 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?; // x2
    let a = vm.dstack.pop_byte_array()?; // x1

    let a_len = a.len() as i32;
    let start_idx = v0.int32();
    let end_idx = v1.int32();

    // WARNING (from dcrd): this check really should be after the bounds
    // checking, but it is now part of consensus.
    if a_len == 0 {
        vm.dstack.push_byte_array(Vec::new());
        return Ok(());
    }

    if start_idx < 0 {
        return Err(script_error(
            ErrorKind::NegativeSubstrIdx,
            format!("start index {start_idx} is negative"),
        ));
    }
    if end_idx < 0 {
        return Err(script_error(
            ErrorKind::NegativeSubstrIdx,
            format!("end index {end_idx} is negative"),
        ));
    }
    if start_idx > a_len {
        return Err(script_error(
            ErrorKind::OverflowSubstrIdx,
            format!("start index {start_idx} exceeds length {a_len}"),
        ));
    }
    if end_idx > a_len {
        return Err(script_error(
            ErrorKind::OverflowSubstrIdx,
            format!("end index {end_idx} exceeds length {a_len}"),
        ));
    }
    if start_idx > end_idx {
        return Err(script_error(
            ErrorKind::OverflowSubstrIdx,
            format!("start index {start_idx} is after end index {end_idx}"),
        ));
    }

    // Identical start and end indices produce an empty byte push.
    vm.dstack
        .push_byte_array(a[start_idx as usize..end_idx as usize].to_vec());
    Ok(())
}

/// OP_LEFT (dcrd `opcodeLeft`).
pub(crate) fn opcode_left(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?; // x2
    let a = vm.dstack.pop_byte_array()?; // x1

    let a_len = a.len() as i32;
    let end_idx = v0.int32();

    // Consensus-frozen early empty return; see dcrd's WARNING comment.
    if a_len == 0 {
        vm.dstack.push_byte_array(Vec::new());
        return Ok(());
    }

    if end_idx < 0 {
        return Err(script_error(
            ErrorKind::NegativeSubstrIdx,
            format!("index {end_idx} is negative"),
        ));
    }
    if end_idx > a_len {
        return Err(script_error(
            ErrorKind::OverflowSubstrIdx,
            format!("index {end_idx} exceeds length {a_len}"),
        ));
    }

    vm.dstack.push_byte_array(a[..end_idx as usize].to_vec());
    Ok(())
}

/// OP_RIGHT (dcrd `opcodeRight`).
pub(crate) fn opcode_right(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?; // x2
    let a = vm.dstack.pop_byte_array()?; // x1

    let a_len = a.len() as i32;
    let start_idx = v0.int32();

    // Consensus-frozen early empty return; see dcrd's WARNING comment.
    if a_len == 0 {
        vm.dstack.push_byte_array(Vec::new());
        return Ok(());
    }

    if start_idx < 0 {
        return Err(script_error(
            ErrorKind::NegativeSubstrIdx,
            format!("index {start_idx} is negative"),
        ));
    }
    if start_idx > a_len {
        return Err(script_error(
            ErrorKind::OverflowSubstrIdx,
            format!("index {start_idx} exceeds length {a_len}"),
        ));
    }

    vm.dstack.push_byte_array(a[start_idx as usize..].to_vec());
    Ok(())
}

/// OP_SIZE (dcrd `opcodeSize`).
pub(crate) fn opcode_size(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let len = vm.dstack.peek_byte_array(0)?.len();
    vm.dstack.push_int(ScriptNum(len as i64));
    Ok(())
}

/// OP_INVERT (dcrd `opcodeInvert`).
pub(crate) fn opcode_invert(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack.push_int(ScriptNum(i64::from(!v0.int32())));
    Ok(())
}

/// OP_AND (dcrd `opcodeAnd`).
pub(crate) fn opcode_and(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    let v1 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack
        .push_int(ScriptNum(i64::from(v0.int32() & v1.int32())));
    Ok(())
}

/// OP_OR (dcrd `opcodeOr`).
pub(crate) fn opcode_or(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    let v1 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack
        .push_int(ScriptNum(i64::from(v0.int32() | v1.int32())));
    Ok(())
}

/// OP_XOR (dcrd `opcodeXor`).
pub(crate) fn opcode_xor(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    let v1 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack
        .push_int(ScriptNum(i64::from(v0.int32() ^ v1.int32())));
    Ok(())
}

/// OP_EQUAL (dcrd `opcodeEqual`).
pub(crate) fn opcode_equal(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let a = vm.dstack.pop_byte_array()?;
    let b = vm.dstack.pop_byte_array()?;
    vm.dstack.push_bool(a == b);
    Ok(())
}

/// OP_EQUALVERIFY (dcrd `opcodeEqualVerify`).
pub(crate) fn opcode_equal_verify(
    op: &OpcodeInfo,
    data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    opcode_equal(op, data, vm)?;
    abstract_verify(op, vm, ErrorKind::EqualVerify)
}

/// OP_ROTR (dcrd `opcodeRotr`), including the consensus-frozen 4-byte
/// ScriptNum limitation dcrd's WARNING comment describes.
pub(crate) fn opcode_rotr(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?; // x2
    let v1 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?; // x1

    let count = v0.int32();
    let value = v1.int32();

    if count < 0 {
        return Err(script_error(
            ErrorKind::NegativeRotation,
            format!("rotation count {count} is negative"),
        ));
    }
    if count > 31 {
        return Err(script_error(
            ErrorKind::OverflowRotation,
            format!("rotation count {count} > 31"),
        ));
    }

    let rotated = (value as u32).rotate_right(count as u32) as i32;
    vm.dstack.push_int(ScriptNum(i64::from(rotated)));
    Ok(())
}

/// OP_ROTL (dcrd `opcodeRotl`).
pub(crate) fn opcode_rotl(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?; // x2
    let v1 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?; // x1

    let count = v0.int32();
    let value = v1.int32();

    if count < 0 {
        return Err(script_error(
            ErrorKind::NegativeRotation,
            format!("rotation count {count} is negative"),
        ));
    }
    if count > 31 {
        return Err(script_error(
            ErrorKind::OverflowRotation,
            format!("rotation count {count} > 31"),
        ));
    }

    let rotated = (value as u32).rotate_left(count as u32) as i32;
    vm.dstack.push_int(ScriptNum(i64::from(rotated)));
    Ok(())
}

/// OP_1ADD (dcrd `opcode1Add`).
pub(crate) fn opcode_1add(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let m = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack.push_int(ScriptNum(m.0 + 1));
    Ok(())
}

/// OP_1SUB (dcrd `opcode1Sub`).
pub(crate) fn opcode_1sub(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let m = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack.push_int(ScriptNum(m.0 - 1));
    Ok(())
}

/// OP_NEGATE (dcrd `opcodeNegate`).
pub(crate) fn opcode_negate(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let m = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack.push_int(ScriptNum(-m.0));
    Ok(())
}

/// OP_ABS (dcrd `opcodeAbs`).
pub(crate) fn opcode_abs(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let m = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack.push_int(ScriptNum(m.0.abs()));
    Ok(())
}

/// OP_NOT (dcrd `opcodeNot`); the item is interpreted as an integer per
/// consensus, not as a boolean.
pub(crate) fn opcode_not(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let m = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack.push_int(ScriptNum(if m.0 == 0 { 1 } else { 0 }));
    Ok(())
}

/// OP_0NOTEQUAL (dcrd `opcode0NotEqual`).
pub(crate) fn opcode_0notequal(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let m = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack.push_int(ScriptNum(if m.0 != 0 { 1 } else { 0 }));
    Ok(())
}

/// OP_ADD (dcrd `opcodeAdd`).
pub(crate) fn opcode_add(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    let v1 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack.push_int(ScriptNum(v0.0 + v1.0));
    Ok(())
}

/// OP_SUB (dcrd `opcodeSub`).
pub(crate) fn opcode_sub(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    let v1 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack.push_int(ScriptNum(v1.0 - v0.0));
    Ok(())
}

/// OP_MUL (dcrd `opcodeMul`); the multiplication is over wrapping 32-bit
/// integers per consensus.
pub(crate) fn opcode_mul(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    let v1 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    let v2 = v0.int32().wrapping_mul(v1.int32());
    vm.dstack.push_int(ScriptNum(i64::from(v2)));
    Ok(())
}

/// OP_DIV (dcrd `opcodeDiv`); Go's i32::MIN / -1 == i32::MIN wrap-around is
/// preserved via wrapping division.
pub(crate) fn opcode_div(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    let v1 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;

    let divisor = v0.int32();
    let dividend = v1.int32();

    if divisor == 0 {
        return Err(script_error(ErrorKind::DivideByZero, "division by zero"));
    }

    vm.dstack
        .push_int(ScriptNum(i64::from(dividend.wrapping_div(divisor))));
    Ok(())
}

/// OP_MOD (dcrd `opcodeMod`); truncated division semantics.
pub(crate) fn opcode_mod(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    let v1 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;

    let divisor = v0.int32();
    let dividend = v1.int32();

    if divisor == 0 {
        return Err(script_error(ErrorKind::DivideByZero, "division by zero"));
    }

    vm.dstack
        .push_int(ScriptNum(i64::from(dividend.wrapping_rem(divisor))));
    Ok(())
}

/// OP_LSHIFT (dcrd `opcodeLShift`); a count of exactly 32 is allowed and
/// produces 0, matching Go's shift semantics.
pub(crate) fn opcode_lshift(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?; // x2
    let v1 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?; // x1

    let count = v0.int32();
    let value = v1.int32();

    if count < 0 {
        return Err(script_error(
            ErrorKind::NegativeShift,
            format!("shift count {count} is negative"),
        ));
    }
    if count > 32 {
        return Err(script_error(
            ErrorKind::OverflowShift,
            format!("shift count {count} > 32"),
        ));
    }

    // Go defines shifts by >= the width as 0 for left shifts; shifts below
    // the width discard high bits (wrap).
    let shifted = if count >= 32 {
        0
    } else {
        value.wrapping_shl(count as u32)
    };
    vm.dstack.push_int(ScriptNum(i64::from(shifted)));
    Ok(())
}

/// OP_RSHIFT (dcrd `opcodeRShift`); arithmetic (sign-extending) shift, with
/// a count of exactly 32 yielding all sign bits, matching Go.
pub(crate) fn opcode_rshift(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?; // x2
    let v1 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?; // x1

    let count = v0.int32();
    let value = v1.int32();

    if count < 0 {
        return Err(script_error(
            ErrorKind::NegativeShift,
            format!("shift count {count} is negative"),
        ));
    }
    if count > 32 {
        return Err(script_error(
            ErrorKind::OverflowShift,
            format!("shift count {count} > 32"),
        ));
    }

    let shifted = if count >= 32 {
        value >> 31
    } else {
        value >> count
    };
    vm.dstack.push_int(ScriptNum(i64::from(shifted)));
    Ok(())
}

/// OP_BOOLAND (dcrd `opcodeBoolAnd`).
pub(crate) fn opcode_bool_and(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    let v1 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack
        .push_int(ScriptNum(if v0.0 != 0 && v1.0 != 0 { 1 } else { 0 }));
    Ok(())
}

/// OP_BOOLOR (dcrd `opcodeBoolOr`).
pub(crate) fn opcode_bool_or(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    let v1 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack
        .push_int(ScriptNum(if v0.0 != 0 || v1.0 != 0 { 1 } else { 0 }));
    Ok(())
}

/// OP_NUMEQUAL (dcrd `opcodeNumEqual`).
pub(crate) fn opcode_num_equal(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    let v1 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack
        .push_int(ScriptNum(if v0.0 == v1.0 { 1 } else { 0 }));
    Ok(())
}

/// OP_NUMEQUALVERIFY (dcrd `opcodeNumEqualVerify`).
pub(crate) fn opcode_num_equal_verify(
    op: &OpcodeInfo,
    data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    opcode_num_equal(op, data, vm)?;
    abstract_verify(op, vm, ErrorKind::NumEqualVerify)
}

/// OP_NUMNOTEQUAL (dcrd `opcodeNumNotEqual`).
pub(crate) fn opcode_num_not_equal(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    let v1 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack
        .push_int(ScriptNum(if v0.0 != v1.0 { 1 } else { 0 }));
    Ok(())
}

/// OP_LESSTHAN (dcrd `opcodeLessThan`).
pub(crate) fn opcode_less_than(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    let v1 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack
        .push_int(ScriptNum(if v1.0 < v0.0 { 1 } else { 0 }));
    Ok(())
}

/// OP_GREATERTHAN (dcrd `opcodeGreaterThan`).
pub(crate) fn opcode_greater_than(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    let v1 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack
        .push_int(ScriptNum(if v1.0 > v0.0 { 1 } else { 0 }));
    Ok(())
}

/// OP_LESSTHANOREQUAL (dcrd `opcodeLessThanOrEqual`).
pub(crate) fn opcode_less_than_or_equal(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    let v1 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack
        .push_int(ScriptNum(if v1.0 <= v0.0 { 1 } else { 0 }));
    Ok(())
}

/// OP_GREATERTHANOREQUAL (dcrd `opcodeGreaterThanOrEqual`).
pub(crate) fn opcode_greater_than_or_equal(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    let v1 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack
        .push_int(ScriptNum(if v1.0 >= v0.0 { 1 } else { 0 }));
    Ok(())
}

/// OP_MIN (dcrd `opcodeMin`).
pub(crate) fn opcode_min(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    let v1 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack.push_int(if v1.0 < v0.0 { v1 } else { v0 });
    Ok(())
}

/// OP_MAX (dcrd `opcodeMax`).
pub(crate) fn opcode_max(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let v0 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    let v1 = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack.push_int(if v1.0 > v0.0 { v1 } else { v0 });
    Ok(())
}

/// OP_WITHIN (dcrd `opcodeWithin`).
pub(crate) fn opcode_within(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let max_val = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    let min_val = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    let x = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    vm.dstack
        .push_int(ScriptNum(if x.0 >= min_val.0 && x.0 < max_val.0 {
            1
        } else {
            0
        }));
    Ok(())
}

/// OP_RIPEMD160 (dcrd `opcodeRipemd160`).
pub(crate) fn opcode_ripemd160(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let buf = vm.dstack.pop_byte_array()?;
    vm.dstack
        .push_byte_array(dcroxide_crypto::ripemd160::sum160(&buf).to_vec());
    Ok(())
}

/// OP_SHA1 (dcrd `opcodeSha1`).
pub(crate) fn opcode_sha1(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let buf = vm.dstack.pop_byte_array()?;
    let hash = sha1::Sha1::digest(&buf);
    vm.dstack.push_byte_array(hash.to_vec());
    Ok(())
}

/// OP_SHA256 (dcrd `opcodeSha256`); treated as OP_UNKNOWN192 without the
/// ScriptVerifySHA256 flag.
pub(crate) fn opcode_sha256(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    if !vm.has_flag(ScriptFlags::VERIFY_SHA256) {
        if vm.has_flag(ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS) {
            return Err(script_error(
                ErrorKind::DiscourageUpgradableNOPs,
                "OP_UNKNOWN192 reserved for upgrades",
            ));
        }
        return Ok(());
    }

    let buf = vm.dstack.pop_byte_array()?;
    let hash = sha2::Sha256::digest(&buf);
    vm.dstack.push_byte_array(hash.to_vec());
    Ok(())
}

/// OP_BLAKE256 (dcrd `opcodeBlake256`).
pub(crate) fn opcode_blake256(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let buf = vm.dstack.pop_byte_array()?;
    vm.dstack
        .push_byte_array(dcroxide_crypto::blake256::sum256(&buf).to_vec());
    Ok(())
}

/// OP_HASH160 (dcrd `opcodeHash160`): ripemd160(blake256(data)).
pub(crate) fn opcode_hash160(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let buf = vm.dstack.pop_byte_array()?;
    let hash = dcroxide_crypto::blake256::sum256(&buf);
    vm.dstack
        .push_byte_array(dcroxide_crypto::ripemd160::sum160(&hash).to_vec());
    Ok(())
}

/// OP_HASH256 (dcrd `opcodeHash256`): blake256(blake256(data)).
pub(crate) fn opcode_hash256(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let buf = vm.dstack.pop_byte_array()?;
    vm.dstack
        .push_byte_array(dcroxide_crypto::blake256::sum256d(&buf).to_vec());
    Ok(())
}

/// OP_CHECKSIG (dcrd `opcodeCheckSig`).
pub(crate) fn opcode_check_sig(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let pk_bytes = vm.dstack.pop_byte_array()?;
    let full_sig_bytes = vm.dstack.pop_byte_array()?;

    // The signature actually needs to be longer than this, but at least 1
    // byte is needed for the hash type below.
    if full_sig_bytes.is_empty() {
        vm.dstack.push_bool(false);
        return Ok(());
    }

    // Trim off hashtype from the signature string and check that the
    // signature and pubkey conform to the strict encoding requirements.
    //
    // NOTE: The strict encoding requirements cause any errors in the
    // signature or public encoding to result in an immediate script error
    // (no result bool is pushed to the data stack), unlike the parse
    // failures below which push false.
    let hash_type = SigHashType(full_sig_bytes[full_sig_bytes.len() - 1]);
    let sig_bytes = &full_sig_bytes[..full_sig_bytes.len() - 1];
    check_hash_type_encoding(hash_type)?;
    check_signature_encoding(sig_bytes)?;
    check_pub_key_encoding(&pk_bytes)?;

    // Get script starting from the most recent OP_CODESEPARATOR.
    let sub_script = vm.sub_script().to_vec();

    // Remove the signature since there is no way for a signature to sign
    // itself.
    let sub_script = remove_opcode_by_data(&sub_script, &full_sig_bytes);

    // Generate the signature hash based on the signature hash type.
    let hash = match calc_signature_hash(&sub_script, hash_type, vm.tx, vm.tx_idx) {
        Ok(hash) => hash,
        Err(_) => {
            vm.dstack.push_bool(false);
            return Ok(());
        }
    };

    let pub_key = match dcroxide_dcrec::secp256k1::PublicKey::parse(&pk_bytes) {
        Ok(key) => key,
        Err(_) => {
            vm.dstack.push_bool(false);
            return Ok(());
        }
    };

    let signature = match dcroxide_dcrec::secp256k1::ecdsa::parse_der_signature(sig_bytes) {
        Ok(sig) => sig,
        Err(_) => {
            vm.dstack.push_bool(false);
            return Ok(());
        }
    };

    let valid = signature.verify(&hash, &pub_key);
    vm.dstack.push_bool(valid);
    Ok(())
}

/// OP_CHECKSIGVERIFY (dcrd `opcodeCheckSigVerify`).
pub(crate) fn opcode_check_sig_verify(
    op: &OpcodeInfo,
    data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    opcode_check_sig(op, data, vm)?;
    abstract_verify(op, vm, ErrorKind::CheckSigVerify)
}

/// A raw signature along with its parsed form (dcrd `parsedSigInfo`).
struct ParsedSigInfo {
    signature: Vec<u8>,
    parsed_signature: Option<dcroxide_dcrec::secp256k1::ecdsa::Signature>,
    parsed: bool,
}

/// OP_CHECKMULTISIG (dcrd `opcodeCheckMultiSig`).
pub(crate) fn opcode_check_multi_sig(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let num_keys = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    let num_pub_keys_signed = num_keys.int32();
    if num_pub_keys_signed < 0 {
        return Err(script_error(
            ErrorKind::InvalidPubKeyCount,
            format!("number of pubkeys {num_pub_keys_signed} is negative"),
        ));
    }
    let mut num_pub_keys = num_pub_keys_signed as usize;
    if num_pub_keys > MAX_PUB_KEYS_PER_MULTI_SIG {
        return Err(script_error(
            ErrorKind::InvalidPubKeyCount,
            format!("too many pubkeys: {num_pub_keys} > {MAX_PUB_KEYS_PER_MULTI_SIG}"),
        ));
    }
    vm.num_ops += num_pub_keys as i32;
    if vm.num_ops > MAX_OPS_PER_SCRIPT {
        return Err(script_error(
            ErrorKind::TooManyOperations,
            format!("exceeded max operation limit of {MAX_OPS_PER_SCRIPT}"),
        ));
    }

    let mut pub_keys: Vec<Vec<u8>> = Vec::with_capacity(num_pub_keys);
    for _ in 0..num_pub_keys {
        pub_keys.push(vm.dstack.pop_byte_array()?);
    }

    let num_sigs = vm.dstack.pop_int(MATH_OP_CODE_MAX_SCRIPT_NUM_LEN)?;
    let num_signatures_signed = num_sigs.int32();
    if num_signatures_signed < 0 {
        return Err(script_error(
            ErrorKind::InvalidSignatureCount,
            format!("number of signatures {num_signatures_signed} is negative"),
        ));
    }
    let mut num_signatures = num_signatures_signed as usize;
    if num_signatures > num_pub_keys {
        return Err(script_error(
            ErrorKind::InvalidSignatureCount,
            format!("more signatures than pubkeys: {num_signatures} > {num_pub_keys}"),
        ));
    }

    let mut signatures: Vec<ParsedSigInfo> = Vec::with_capacity(num_signatures);
    for _ in 0..num_signatures {
        let signature = vm.dstack.pop_byte_array()?;
        signatures.push(ParsedSigInfo {
            signature,
            parsed_signature: None,
            parsed: false,
        });
    }

    // Get script starting from the most recent OP_CODESEPARATOR and remove
    // any of the signatures since there is no way for a signature to sign
    // itself.
    let mut script = vm.sub_script().to_vec();
    for sig_info in &signatures {
        script = remove_opcode_by_data(&script, &sig_info.signature);
    }

    let mut success = true;
    num_pub_keys += 1;
    let mut pub_key_idx: isize = -1;
    let mut signature_idx = 0usize;
    while num_signatures > 0 {
        // When there are more signatures than public keys remaining, there
        // is no way to succeed since too many signatures are invalid, so
        // exit early.
        pub_key_idx += 1;
        num_pub_keys -= 1;
        if num_signatures > num_pub_keys {
            success = false;
            break;
        }

        let pub_key = pub_keys[pub_key_idx as usize].clone();

        // The order of the signature and public key evaluation is important
        // here since it can be distinguished by an OP_CHECKMULTISIG NOT.
        let raw_sig = signatures[signature_idx].signature.clone();
        if raw_sig.is_empty() {
            // Skip to the next pubkey if signature is empty.
            continue;
        }

        // Split the signature into hash type and signature components.
        let hash_type = SigHashType(raw_sig[raw_sig.len() - 1]);
        let signature = &raw_sig[..raw_sig.len() - 1];

        // Only parse and check the signature encoding once.
        let parsed_sig;
        if !signatures[signature_idx].parsed {
            check_hash_type_encoding(hash_type)?;
            check_signature_encoding(signature)?;

            // Parse the signature.
            let parse_result = dcroxide_dcrec::secp256k1::ecdsa::parse_der_signature(signature);
            signatures[signature_idx].parsed = true;
            match parse_result {
                Ok(sig) => {
                    signatures[signature_idx].parsed_signature = Some(sig);
                    parsed_sig = sig;
                }
                Err(_) => continue,
            }
        } else {
            // Skip to the next pubkey if the signature is invalid.
            match &signatures[signature_idx].parsed_signature {
                Some(sig) => parsed_sig = *sig,
                None => continue,
            }
        }

        check_pub_key_encoding(&pub_key)?;

        // Parse the pubkey.
        let parsed_pub_key = match dcroxide_dcrec::secp256k1::PublicKey::parse(&pub_key) {
            Ok(key) => key,
            Err(_) => continue,
        };

        // Generate the signature hash based on the signature hash type.
        let hash = calc_signature_hash(&script, hash_type, vm.tx, vm.tx_idx)?;

        if parsed_sig.verify(&hash, &parsed_pub_key) {
            // PubKey verified, move on to the next signature.
            signature_idx += 1;
            num_signatures -= 1;
        }
    }

    vm.dstack.push_bool(success);
    Ok(())
}

/// OP_CHECKMULTISIGVERIFY (dcrd `opcodeCheckMultiSigVerify`).
pub(crate) fn opcode_check_multi_sig_verify(
    op: &OpcodeInfo,
    data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    opcode_check_multi_sig(op, data, vm)?;
    abstract_verify(op, vm, ErrorKind::CheckMultiSigVerify)
}

/// OP_CHECKSIGALT (dcrd `opcodeCheckSigAlt`): signature-type-dispatched
/// verification for Ed25519 and EC-Schnorr-DCRv0; unknown non-zero types
/// push true for soft-fork extensibility, type 0 pushes false.
pub(crate) fn opcode_check_sig_alt(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    let sig_type = vm.dstack.pop_int(ALT_SIG_SUITES_MAX_SCRIPT_NUM_LEN)?;

    match sig_type.0 {
        0 => {
            // Zero case; pre-softfork clients will return 0 in this case
            // as well.
            vm.dstack.push_bool(false);
            return Ok(());
        }
        ST_ED25519 | ST_SCHNORR_SECP256K1 => {}
        _ => {
            // Caveat: All unknown signature types return true, allowing for
            // future softforks with other new signature types.
            vm.dstack.push_bool(true);
            return Ok(());
        }
    }

    let pk_bytes = vm.dstack.pop_byte_array()?;

    // Check the public key lengths: 32 bytes for Ed25519, 33-byte
    // compressed keys for secp256k1 Schnorr.
    match sig_type.0 {
        ST_ED25519 => {
            if pk_bytes.len() != 32 {
                vm.dstack.push_bool(false);
                return Ok(());
            }
        }
        ST_SCHNORR_SECP256K1 => {
            if pk_bytes.len() != 33 {
                vm.dstack.push_bool(false);
                return Ok(());
            }
        }
        _ => unreachable!("sig type restricted above"),
    }

    let full_sig_bytes = vm.dstack.pop_byte_array()?;

    // Signatures are 65 bytes in length (64 bytes for [r,s] plus 1 byte
    // appended for the hash type).
    if full_sig_bytes.len() != 65 {
        vm.dstack.push_bool(false);
        return Ok(());
    }

    // Trim off hashtype from the signature string; the hash type check
    // results in an immediate script error, unlike the parse failures
    // below which push false.
    let hash_type = SigHashType(full_sig_bytes[full_sig_bytes.len() - 1]);
    let sig_bytes = &full_sig_bytes[..full_sig_bytes.len() - 1];
    check_hash_type_encoding(hash_type)?;

    // Get the subscript and remove the signature since there is no way for
    // a signature to sign itself.
    let sub_script = vm.sub_script().to_vec();
    let sub_script = remove_opcode_by_data(&sub_script, &full_sig_bytes);

    // Generate the signature hash based on the signature hash type.
    let hash = match calc_signature_hash(&sub_script, hash_type, vm.tx, vm.tx_idx) {
        Ok(hash) => hash,
        Err(_) => {
            vm.dstack.push_bool(false);
            return Ok(());
        }
    };

    match sig_type.0 {
        ST_ED25519 => {
            let pub_key = match dcroxide_dcrec::edwards::parse_pub_key(&pk_bytes) {
                Ok(key) => key,
                Err(_) => {
                    vm.dstack.push_bool(false);
                    return Ok(());
                }
            };
            let sig = match dcroxide_dcrec::edwards::parse_signature(sig_bytes) {
                Ok(sig) => sig,
                Err(_) => {
                    vm.dstack.push_bool(false);
                    return Ok(());
                }
            };
            let ok = sig.verify(&hash, &pub_key);
            vm.dstack.push_bool(ok);
            Ok(())
        }
        ST_SCHNORR_SECP256K1 => {
            let pub_key = match dcroxide_dcrec::secp256k1::schnorr::parse_pub_key(&pk_bytes) {
                Ok(key) => key,
                Err(_) => {
                    vm.dstack.push_bool(false);
                    return Ok(());
                }
            };
            let sig = match dcroxide_dcrec::secp256k1::schnorr::parse_signature(sig_bytes) {
                Ok(sig) => sig,
                Err(_) => {
                    vm.dstack.push_bool(false);
                    return Ok(());
                }
            };
            let ok = sig.verify(&hash, &pub_key);
            vm.dstack.push_bool(ok);
            Ok(())
        }
        _ => unreachable!("sig type restricted above"),
    }
}

/// OP_CHECKSIGALTVERIFY (dcrd `opcodeCheckSigAltVerify`).
pub(crate) fn opcode_check_sig_alt_verify(
    op: &OpcodeInfo,
    data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    opcode_check_sig_alt(op, data, vm)?;
    abstract_verify(op, vm, ErrorKind::CheckSigAltVerify)
}

/// OP_TADD (dcrd `opcodeTAdd`): a treasury tag opcode; OP_UNKNOWN193
/// without the treasury flag.
pub(crate) fn opcode_tadd(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    if !vm.has_flag(ScriptFlags::VERIFY_TREASURY)
        && vm.has_flag(ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS)
    {
        return Err(script_error(
            ErrorKind::DiscourageUpgradableNOPs,
            "OP_UNKNOWN193 reserved for upgrades",
        ));
    }
    Ok(())
}

/// OP_TSPEND (dcrd `opcodeTSpend`): OP_UNKNOWN194 without the treasury
/// flag.
pub(crate) fn opcode_tspend(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    if !vm.has_flag(ScriptFlags::VERIFY_TREASURY)
        && vm.has_flag(ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS)
    {
        return Err(script_error(
            ErrorKind::DiscourageUpgradableNOPs,
            "OP_UNKNOWN194 reserved for upgrades",
        ));
    }
    Ok(())
}

/// OP_TGEN (dcrd `opcodeTGen`): OP_UNKNOWN195 without the treasury flag.
pub(crate) fn opcode_tgen(
    _op: &OpcodeInfo,
    _data: &[u8],
    vm: &mut Engine,
) -> Result<(), ScriptError> {
    if !vm.has_flag(ScriptFlags::VERIFY_TREASURY)
        && vm.has_flag(ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS)
    {
        return Err(script_error(
            ErrorKind::DiscourageUpgradableNOPs,
            "OP_UNKNOWN195 reserved for upgrades",
        ));
    }
    Ok(())
}

/// Look up an opcode value by its human-readable name (dcrd
/// `OpcodeByName`), including the `OP_FALSE`/`OP_TRUE`/`OP_NOP2`/`OP_NOP3`
/// aliases.
pub fn opcode_by_name(name: &str) -> Option<u8> {
    match name {
        "OP_FALSE" => return Some(OP_FALSE),
        "OP_TRUE" => return Some(OP_TRUE),
        "OP_NOP2" => return Some(OP_NOP2),
        "OP_NOP3" => return Some(OP_NOP3),
        _ => {}
    }
    OPCODE_ARRAY
        .iter()
        .find(|info| info.name == name)
        .map(|info| info.value)
}
