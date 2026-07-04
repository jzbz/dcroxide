// SPDX-License-Identifier: ISC
//! The script engine (dcrd `engine.go`): execution flags, per-step
//! semantics including P2SH handling, conditional-execution tracking, and
//! dcrd's exact validation order and error identities.
//!
//! dcrd's optional `SigCache` is not reproduced: it is a concurrency
//! optimization that memoizes successful verifications and has no effect
//! on results (see PARITY.md); this engine always verifies directly.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use dcroxide_wire::MsgTx;

use crate::error::{ErrorKind, ScriptError, script_error};
use crate::opcode_table::*;
use crate::opcodes::{OpcodeInfo, disasm_opcode};
use crate::script::{
    check_script_parses, contains_stake_op_codes, final_opcode_data, is_any_kind_of_script_hash,
    is_push_only_script,
};
use crate::stack::Stack;
use crate::tokenizer::parse_opcode;
use crate::{MAX_OPS_PER_SCRIPT, MAX_SCRIPT_ELEMENT_SIZE, MAX_SCRIPT_SIZE, MAX_STACK_SIZE};

/// A bitmask defining additional operations or tests done when executing a
/// script pair (dcrd `ScriptFlags`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScriptFlags(pub u32);

impl ScriptFlags {
    /// Verify that currently unused opcodes in the NOP and UNKNOWN families
    /// are reserved for future upgrades; standardness only, never
    /// consensus (dcrd `ScriptDiscourageUpgradableNops`).
    pub const DISCOURAGE_UPGRADABLE_NOPS: ScriptFlags = ScriptFlags(1 << 0);
    /// Verify spendability based on the locktime, BIP0065 (dcrd
    /// `ScriptVerifyCheckLockTimeVerify`).
    pub const VERIFY_CHECK_LOCK_TIME_VERIFY: ScriptFlags = ScriptFlags(1 << 1);
    /// Allow execution pathways to be restricted based on output age,
    /// BIP0112 (dcrd `ScriptVerifyCheckSequenceVerify`).
    pub const VERIFY_CHECK_SEQUENCE_VERIFY: ScriptFlags = ScriptFlags(1 << 2);
    /// Require exactly one true stack element after evaluation, rule 6 of
    /// BIP0062 (dcrd `ScriptVerifyCleanStack`).
    pub const VERIFY_CLEAN_STACK: ScriptFlags = ScriptFlags(1 << 3);
    /// Require signature scripts to contain only pushed data, rule 2 of
    /// BIP0062 (dcrd `ScriptVerifySigPushOnly`).
    pub const VERIFY_SIG_PUSH_ONLY: ScriptFlags = ScriptFlags(1 << 4);
    /// Treat opcode 192 as OP_SHA256 (dcrd `ScriptVerifySHA256`).
    pub const VERIFY_SHA256: ScriptFlags = ScriptFlags(1 << 5);
    /// Treat opcodes 193-195 as OP_TADD/OP_TSPEND/OP_TGEN (dcrd
    /// `ScriptVerifyTreasury`).
    pub const VERIFY_TREASURY: ScriptFlags = ScriptFlags(1 << 6);

    /// The union of two flag sets.
    pub const fn union(self, other: ScriptFlags) -> ScriptFlags {
        ScriptFlags(self.0 | other.0)
    }
}

impl core::ops::BitOr for ScriptFlags {
    type Output = ScriptFlags;
    fn bitor(self, rhs: ScriptFlags) -> ScriptFlags {
        self.union(rhs)
    }
}

/// The nesting depth indicating no conditional opcode has disabled the
/// current execution state (dcrd `noCondDisableDepth`).
pub(crate) const NO_COND_DISABLE_DEPTH: i32 = -1;

/// The virtual machine that executes scripts (dcrd `Engine`).
pub struct Engine {
    // Set at creation and unchanged afterwards.
    pub(crate) flags: ScriptFlags,
    pub(crate) tx: MsgTx,
    pub(crate) tx_idx: usize,
    pub(crate) version: u16,
    pub(crate) is_p2sh: bool,

    // Current execution state.
    pub(crate) scripts: Vec<Vec<u8>>,
    pub(crate) script_idx: usize,
    pub(crate) opcode_idx: usize,
    pub(crate) last_code_sep: usize,
    pub(crate) tokenizer_offset: usize,
    pub(crate) saved_first_stack: Vec<Vec<u8>>,
    pub(crate) dstack: Stack,
    pub(crate) astack: Stack,
    pub(crate) num_ops: i32,

    // Conditional execution state: the current nesting depth and the depth
    // at which branch execution was disabled (or NO_COND_DISABLE_DEPTH).
    pub(crate) cond_nest_depth: i32,
    pub(crate) cond_disable_depth: i32,
}

impl Engine {
    /// Whether the engine has the passed flag set (dcrd `hasFlag`).
    pub(crate) fn has_flag(&self, flag: ScriptFlags) -> bool {
        self.flags.0 & flag.0 == flag.0
    }

    /// Whether the current conditional branch is actively executing (dcrd
    /// `isBranchExecuting`).
    pub(crate) fn is_branch_executing(&self) -> bool {
        self.cond_disable_depth == NO_COND_DISABLE_DEPTH
    }

    /// The script since the last OP_CODESEPARATOR (dcrd `subScript`).
    /// OP_CODESEPARATOR is disabled in Decred, so this is always the whole
    /// current script, but the field is kept for structural fidelity.
    pub(crate) fn sub_script(&self) -> &[u8] {
        &self.scripts[self.script_idx][self.last_code_sep..]
    }

    /// Execute an opcode taking into account disabled/illegal opcodes,
    /// operation and element limits, conditionals, and minimal data pushes
    /// (dcrd `executeOpcode`).
    fn execute_opcode(&mut self, op: &OpcodeInfo, data: &[u8]) -> Result<(), ScriptError> {
        // Disabled opcodes are fail on program counter.
        if is_opcode_disabled(op.value) {
            return Err(script_error(
                ErrorKind::DisabledOpcode,
                format!("attempt to execute disabled opcode {}", op.name),
            ));
        }

        // Always-illegal opcodes are fail on program counter.
        if is_opcode_always_illegal(op.value) {
            return Err(script_error(
                ErrorKind::ReservedOpcode,
                format!("attempt to execute reserved opcode {}", op.name),
            ));
        }

        // Note that this includes OP_RESERVED which counts as a push
        // operation.
        if op.value > OP_16 {
            self.num_ops += 1;
            if self.num_ops > MAX_OPS_PER_SCRIPT {
                return Err(script_error(
                    ErrorKind::TooManyOperations,
                    format!("exceeded max operation limit of {MAX_OPS_PER_SCRIPT}"),
                ));
            }
        } else if data.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(script_error(
                ErrorKind::ElementTooBig,
                format!(
                    "element size {} exceeds max allowed size {MAX_SCRIPT_ELEMENT_SIZE}",
                    data.len()
                ),
            ));
        }

        // Nothing left to do when this is not a conditional opcode and it
        // is not in an executing branch.
        if !self.is_branch_executing() && !is_opcode_conditional(op.value) {
            return Ok(());
        }

        // Ensure all executed data push opcodes use the minimal encoding.
        if self.is_branch_executing() && op.value <= OP_PUSHDATA4 {
            check_minimal_data_push(op, data)?;
        }

        (op.func)(op, data, self)
    }

    /// Returns an error if the current script position is not valid for
    /// execution (dcrd `checkValidPC`).
    fn check_valid_pc(&self) -> Result<(), ScriptError> {
        if self.script_idx >= self.scripts.len() {
            return Err(script_error(
                ErrorKind::InvalidProgramCounter,
                format!(
                    "program counter beyond input scripts (script idx {}, total scripts {})",
                    self.script_idx,
                    self.scripts.len()
                ),
            ));
        }
        Ok(())
    }

    /// The disassembly of the opcode that will execute next (dcrd
    /// `DisasmPC`).
    pub fn disasm_pc(&self) -> Result<String, ScriptError> {
        self.check_valid_pc()?;

        let script = &self.scripts[self.script_idx];
        match parse_opcode(script, self.tokenizer_offset) {
            Ok(Some(parsed)) => {
                let mut buf = String::new();
                disasm_opcode(&mut buf, parsed.op, &script[parsed.data.clone()], false);
                Ok(format!(
                    "{:02x}:{:04x}: {}",
                    self.script_idx, self.opcode_idx, buf
                ))
            }
            Ok(None) => Err(script_error(
                ErrorKind::InvalidProgramCounter,
                format!(
                    "program counter beyond script index {} (bytes {})",
                    self.script_idx,
                    hex(script)
                ),
            )),
            Err(err) => Err(err),
        }
    }

    /// The disassembly for the script at the requested offset index: 0 is
    /// the signature script, 1 the public key script, and 2 the redeem
    /// script once P2SH execution has reached it (dcrd `DisasmScript`).
    pub fn disasm_script(&self, idx: usize) -> Result<String, ScriptError> {
        if idx >= self.scripts.len() {
            return Err(script_error(
                ErrorKind::InvalidIndex,
                format!(
                    "script index {} >= total scripts {}",
                    idx,
                    self.scripts.len()
                ),
            ));
        }

        let mut disbuf = String::new();
        let script = &self.scripts[idx];
        let mut tokenizer = crate::tokenizer::ScriptTokenizer::new(self.version, script);
        let mut opcode_idx = 0;
        while tokenizer.next() {
            disbuf.push_str(&format!("{idx:02x}:{opcode_idx:04x}: "));
            disasm_opcode(&mut disbuf, tokenizer.opcode(), tokenizer.data(), false);
            disbuf.push('\n');
            opcode_idx += 1;
        }
        match tokenizer.into_err() {
            Some(err) => Err(err),
            None => Ok(disbuf),
        }
    }

    /// Returns Ok if the running script has ended and was successful (dcrd
    /// `CheckErrorCondition`).
    pub fn check_error_condition(&mut self, final_script: bool) -> Result<(), ScriptError> {
        // Check execution is actually done.
        if self.script_idx < self.scripts.len() {
            return Err(script_error(
                ErrorKind::ScriptUnfinished,
                "error check when script unfinished",
            ));
        }

        // The final script must end with exactly one data stack item when
        // the clean stack flag is set; otherwise at least one item is
        // needed to interpret as a boolean.
        if final_script
            && self.has_flag(ScriptFlags::VERIFY_CLEAN_STACK)
            && self.dstack.depth() != 1
        {
            return Err(script_error(
                ErrorKind::CleanStack,
                format!(
                    "stack must contain exactly one item (contains {})",
                    self.dstack.depth()
                ),
            ));
        } else if self.dstack.depth() < 1 {
            return Err(script_error(
                ErrorKind::EmptyStack,
                "stack empty at end of script execution",
            ));
        }

        let v = self.dstack.pop_bool()?;
        if !v {
            return Err(script_error(
                ErrorKind::EvalFalse,
                "false stack entry at end of script execution",
            ));
        }
        Ok(())
    }

    /// Execute the next instruction and move the program counter (dcrd
    /// `Step`); returns true when the last opcode was executed.
    pub fn step(&mut self) -> Result<bool, ScriptError> {
        // Verify the engine is pointing to a valid program counter.
        self.check_valid_pc()?;

        // dcrd's tokenizer is created with the script version and carries
        // an unsupported-version error that surfaces on the first Next
        // call; reproduce that for direct Step use (Execute never gets
        // here for non-zero versions).
        if self.version != 0 {
            return Err(script_error(
                ErrorKind::UnsupportedScriptVersion,
                format!("script version {} is not supported", self.version),
            ));
        }

        // Attempt to parse the next opcode from the current script.
        let script = &self.scripts[self.script_idx];
        let (op_value, data, next_offset) = match parse_opcode(script, self.tokenizer_offset) {
            Ok(Some(parsed)) => (
                parsed.op,
                script[parsed.data.clone()].to_vec(),
                parsed.next_offset,
            ),
            Ok(None) => {
                return Err(script_error(
                    ErrorKind::InvalidProgramCounter,
                    format!(
                        "attempt to step beyond script index {} (bytes {})",
                        self.script_idx,
                        hex(script)
                    ),
                ));
            }
            Err(err) => {
                // All scripts are checked for parse failures before
                // execution, so this should be unreachable, but mirror
                // dcrd's defensive handling.
                return Err(err);
            }
        };
        self.tokenizer_offset = next_offset;

        // Execute the opcode.
        let op = &OPCODE_ARRAY[op_value as usize];
        self.execute_opcode(op, &data)?;

        // The combined data and alt stacks must not exceed the maximum.
        let combined_stack_size = self.dstack.depth() + self.astack.depth();
        if combined_stack_size > MAX_STACK_SIZE {
            return Err(script_error(
                ErrorKind::StackOverflow,
                format!("combined stack size {combined_stack_size} > max allowed {MAX_STACK_SIZE}"),
            ));
        }

        // Prepare for next instruction.
        self.opcode_idx += 1;
        if self.tokenizer_offset >= self.scripts[self.script_idx].len() {
            // Illegal to have a conditional that straddles two scripts.
            if self.cond_nest_depth != 0 {
                return Err(script_error(
                    ErrorKind::UnbalancedConditional,
                    "end of script reached in conditional execution",
                ));
            }

            // Alt stack doesn't persist between scripts.
            let astack_depth = self.astack.depth();
            let _ = self.astack.drop_n(astack_depth);

            // The number of operations is per script.
            self.num_ops = 0;

            // Reset the opcode index for the next script.
            self.opcode_idx = 0;

            // Advance to the next script as needed.
            if self.script_idx == 0 && self.is_p2sh {
                self.script_idx += 1;
                self.saved_first_stack = self.get_stack();
            } else if self.script_idx == 1 && self.is_p2sh {
                // Put us past the end for check_error_condition().
                self.script_idx += 1;

                // Check script ran successfully.
                self.check_error_condition(false)?;

                // Obtain the redeem script from the first stack and ensure
                // it parses.
                let script = self.saved_first_stack[self.saved_first_stack.len() - 1].clone();
                check_script_parses(self.version, &script)?;
                self.scripts.push(script);

                // Set the stack to the first script's stack minus the
                // redeem script itself.
                let stack = self.saved_first_stack[..self.saved_first_stack.len() - 1].to_vec();
                self.set_stack(stack);
            } else {
                self.script_idx += 1;
            }

            // Skip empty scripts.
            if self.script_idx < self.scripts.len() && self.scripts[self.script_idx].is_empty() {
                self.script_idx += 1;
            }

            self.last_code_sep = 0;
            if self.script_idx >= self.scripts.len() {
                return Ok(true);
            }

            // Restart parsing at the beginning of the new script.
            self.tokenizer_offset = 0;
        }

        Ok(false)
    }

    /// Execute all scripts in the engine (dcrd `Execute`), returning Ok for
    /// successful validation.
    pub fn execute(&mut self) -> Result<(), ScriptError> {
        // All script versions other than 0 currently execute without
        // issue, making all outputs to them anyone can pay. In the future
        // this will allow for the addition of new scripting languages.
        if self.version != 0 {
            return Ok(());
        }

        let mut done = false;
        while !done {
            done = self.step()?;
        }

        self.check_error_condition(true)
    }

    /// The contents of the primary stack, bottom-up (dcrd `GetStack`).
    pub fn get_stack(&self) -> Vec<Vec<u8>> {
        get_stack(&self.dstack)
    }

    /// Set the contents of the primary stack (dcrd `SetStack`); the last
    /// item in the array is the top of the stack.
    pub fn set_stack(&mut self, data: Vec<Vec<u8>>) {
        set_stack(&mut self.dstack, data);
    }

    /// The contents of the alternate stack, bottom-up (dcrd
    /// `GetAltStack`).
    pub fn get_alt_stack(&self) -> Vec<Vec<u8>> {
        get_stack(&self.astack)
    }

    /// Set the contents of the alternate stack (dcrd `SetAltStack`).
    pub fn set_alt_stack(&mut self, data: Vec<Vec<u8>>) {
        set_stack(&mut self.astack, data);
    }

    /// A new script engine for the provided public key script, transaction,
    /// and input index (dcrd `NewEngine`), reproducing its exact validation
    /// order: input index, empty-scripts short-circuit, push-only checks,
    /// P2SH detection, stake-opcode redeem script checks, script size, and
    /// version-0 parse checks.
    pub fn new(
        script_pub_key: &[u8],
        tx: &MsgTx,
        tx_idx: usize,
        flags: ScriptFlags,
        script_version: u16,
    ) -> Result<Engine, ScriptError> {
        // The provided transaction input index must refer to a valid input.
        if tx_idx >= tx.tx_in.len() {
            return Err(script_error(
                ErrorKind::InvalidIndex,
                format!(
                    "transaction input index {} is negative or >= {}",
                    tx_idx,
                    tx.tx_in.len()
                ),
            ));
        }
        let script_sig: &[u8] = &tx.tx_in[tx_idx].signature_script;

        // When both the signature script and public key script are empty
        // the result is necessarily an error since the stack would end up
        // being empty, which is equivalent to a false top element.
        if script_sig.is_empty() && script_pub_key.is_empty() {
            return Err(script_error(
                ErrorKind::EvalFalse,
                "false stack entry at end of script execution",
            ));
        }

        let mut vm = Engine {
            flags,
            tx: tx.clone(),
            tx_idx,
            version: script_version,
            is_p2sh: false,
            scripts: Vec::new(),
            script_idx: 0,
            opcode_idx: 0,
            last_code_sep: 0,
            tokenizer_offset: 0,
            saved_first_stack: Vec::new(),
            dstack: Stack::default(),
            astack: Stack::default(),
            num_ops: 0,
            cond_nest_depth: 0,
            cond_disable_depth: NO_COND_DISABLE_DEPTH,
        };

        // The signature script must only contain data pushes when the
        // associated flag is set.
        if vm.has_flag(ScriptFlags::VERIFY_SIG_PUSH_ONLY) && !is_push_only_script(script_sig) {
            return Err(script_error(
                ErrorKind::NotPushOnly,
                "signature script is not push only",
            ));
        }

        // The signature script must only contain data pushes for P2SH.
        let treasury = vm.has_flag(ScriptFlags::VERIFY_TREASURY);
        if is_any_kind_of_script_hash(script_pub_key, treasury) {
            // The push-only check was already done above when the sig-push-
            // only flag is set, so avoid checking again.
            let already_checked = vm.has_flag(ScriptFlags::VERIFY_SIG_PUSH_ONLY);
            if !already_checked && !is_push_only_script(script_sig) {
                return Err(script_error(
                    ErrorKind::NotPushOnly,
                    "pay to script hash is not push only",
                ));
            }
            vm.is_p2sh = true;
        }

        if script_version == 0 {
            has_p2sh_redeem_script_stake_op_codes(
                script_version,
                script_sig,
                script_pub_key,
                treasury,
            )?;
        }

        // The engine stores the scripts in a vector so multiple scripts can
        // execute in sequence (a third for the P2SH redeem script).
        let scripts = alloc::vec![script_sig.to_vec(), script_pub_key.to_vec()];
        for scr in &scripts {
            if scr.len() > MAX_SCRIPT_SIZE {
                return Err(script_error(
                    ErrorKind::ScriptTooBig,
                    format!(
                        "script size {} is larger than max allowed size {MAX_SCRIPT_SIZE}",
                        scr.len()
                    ),
                ));
            }

            // Consensus currently dictates scripts must fully parse
            // according to version 0 semantics regardless of the actual
            // script version; see dcrd's extended comment.
            const CONSENSUS_VERSION: u16 = 0;
            check_script_parses(CONSENSUS_VERSION, scr)?;
        }
        vm.scripts = scripts;

        // Advance the program counter to the public key script when the
        // signature script is empty.
        if script_sig.is_empty() {
            vm.script_idx += 1;
        }

        Ok(vm)
    }
}

/// Whether the opcode is disabled: fail on program counter even in a
/// non-executed branch (dcrd `isOpcodeDisabled`).
fn is_opcode_disabled(opcode: u8) -> bool {
    opcode == OP_CODESEPARATOR
}

/// Whether the opcode is always illegal when passed over by the program
/// counter, even in a non-executed branch (dcrd `isOpcodeAlwaysIllegal`).
fn is_opcode_always_illegal(opcode: u8) -> bool {
    opcode == OP_VERIF || opcode == OP_VERNOTIF
}

/// Whether the opcode is a conditional (dcrd `isOpcodeConditional`).
fn is_opcode_conditional(opcode: u8) -> bool {
    matches!(opcode, OP_IF | OP_NOTIF | OP_ELSE | OP_ENDIF)
}

/// Whether the provided opcode is the smallest possible way to represent
/// the given data (dcrd `checkMinimalDataPush`).
fn check_minimal_data_push(op: &OpcodeInfo, data: &[u8]) -> Result<(), ScriptError> {
    let opcode = op.value;
    let data_len = data.len();

    if data_len == 0 && opcode != OP_0 {
        return Err(script_error(
            ErrorKind::MinimalData,
            format!(
                "zero length data push is encoded with opcode {} instead of OP_0",
                op.name
            ),
        ));
    } else if data_len == 1 && data[0] >= 1 && data[0] <= 16 {
        if opcode != OP_1 + data[0] - 1 {
            // Should have used OP_1 .. OP_16.
            return Err(script_error(
                ErrorKind::MinimalData,
                format!(
                    "data push of the value {} encoded with opcode {} instead of OP_{}",
                    data[0], op.name, data[0]
                ),
            ));
        }
    } else if data_len == 1 && data[0] == 0x81 {
        if opcode != OP_1NEGATE {
            return Err(script_error(
                ErrorKind::MinimalData,
                format!(
                    "data push of the value -1 encoded with opcode {} instead of OP_1NEGATE",
                    op.name
                ),
            ));
        }
    } else if data_len <= 75 {
        if usize::from(opcode) != data_len {
            // Should have used a direct push.
            return Err(script_error(
                ErrorKind::MinimalData,
                format!(
                    "data push of {data_len} bytes encoded with opcode {} instead of OP_DATA_{data_len}",
                    op.name
                ),
            ));
        }
    } else if data_len <= 255 {
        if opcode != OP_PUSHDATA1 {
            return Err(script_error(
                ErrorKind::MinimalData,
                format!(
                    "data push of {data_len} bytes encoded with opcode {} instead of OP_PUSHDATA1",
                    op.name
                ),
            ));
        }
    } else if data_len <= 65535 && opcode != OP_PUSHDATA2 {
        return Err(script_error(
            ErrorKind::MinimalData,
            format!(
                "data push of {data_len} bytes encoded with opcode {} instead of OP_PUSHDATA2",
                op.name
            ),
        ));
    }
    Ok(())
}

/// Returns an error when the public key script is a (possibly stake-tagged)
/// pay-to-script-hash and the redeem script within the signature script
/// contains stake opcodes (dcrd `hasP2SHRedeemScriptStakeOpCodes`).
fn has_p2sh_redeem_script_stake_op_codes(
    version: u16,
    sig_script: &[u8],
    pk_script: &[u8],
    is_treasury_enabled: bool,
) -> Result<(), ScriptError> {
    // The only stake scripts currently supported are version 0.
    if version != 0 {
        return Ok(());
    }

    // Nothing further to check unless the public key script is a normal or
    // stake-tagged pay-to-script-hash script.
    if !is_any_kind_of_script_hash(pk_script, is_treasury_enabled) {
        return Ok(());
    }

    // Extract the redeem script from the signature script.
    let redeem_script = final_opcode_data(version, sig_script);
    let redeem_script = match redeem_script {
        Some(data) if !data.is_empty() => data,
        _ => {
            return Err(script_error(
                ErrorKind::NotPushOnly,
                "p2sh signature script has no pushed data",
            ));
        }
    };

    // Ensure the redeem script does not contain any stake opcodes.
    let has_stake_op_codes = contains_stake_op_codes(redeem_script, is_treasury_enabled)?;
    if has_stake_op_codes {
        return Err(script_error(
            ErrorKind::P2SHStakeOpCodes,
            "stake opcodes were found in a p2sh script",
        ));
    }

    Ok(())
}

/// The contents of a stack as an array, bottom-up (dcrd `getStack`).
fn get_stack(stack: &Stack) -> Vec<Vec<u8>> {
    let mut array = Vec::with_capacity(stack.stk.len());
    array.extend(stack.stk.iter().cloned());
    array
}

/// Set the stack to the contents of the array where the last item is the
/// top of the stack (dcrd `setStack`).
fn set_stack(stack: &mut Stack, data: Vec<Vec<u8>>) {
    stack.stk = data;
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        use core::fmt::Write as _;
        let _ = write!(s, "{x:02x}");
        s
    })
}
