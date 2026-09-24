// SPDX-License-Identifier: ISC
//! `Engine::disasm_pc` and `Engine::disasm_script` against dcrd's
//! `DisasmPC` and `DisasmScript` (txscript/engine.go), with the expected
//! text taken from running dcrd at the parity pin.
//!
//! Two divergences: `disasm_pc` parsed the next opcode with no version
//! check, where dcrd peeks with a copy of the engine's tokenizer and so
//! fails with `ErrUnsupportedScriptVersion` for a non-zero version; and
//! the full disassembly printed ` 0x` for a zero-length OP_PUSHDATA#,
//! where dcrd's `fmt.Sprintf(" 0x%02x", data)` pads it to ` 0x00`.

mod common;

use common::create_spending_tx;
use dcroxide_txscript::{Engine, ErrorKind, ScriptFlags};

/// OP_PUSHDATA1 and OP_PUSHDATA2 of nothing, then OP_1.
const SIG_SCRIPT: [u8; 6] = [0x4c, 0x00, 0x4d, 0x00, 0x00, 0x51];
/// OP_DROP OP_DROP OP_1.
const PK_SCRIPT: [u8; 3] = [0x75, 0x75, 0x51];

#[test]
fn empty_pushdata_disassembles_as_dcrd_does() {
    let tx = create_spending_tx(&SIG_SCRIPT, &PK_SCRIPT);
    let vm = Engine::new(&PK_SCRIPT, &tx, 0, ScriptFlags::default(), 0).expect("engine");
    assert_eq!(
        vm.disasm_pc().expect("valid pc"),
        "00:0000: OP_PUSHDATA1 0x00 0x00"
    );
    assert_eq!(
        vm.disasm_script(0).expect("parses"),
        "00:0000: OP_PUSHDATA1 0x00 0x00\n00:0001: OP_PUSHDATA2 0x0000 0x00\n00:0002: OP_1\n"
    );
}

#[test]
fn disasm_pc_rejects_an_unsupported_script_version() {
    let tx = create_spending_tx(&SIG_SCRIPT, &PK_SCRIPT);
    let vm = Engine::new(&PK_SCRIPT, &tx, 0, ScriptFlags::default(), 1).expect("engine");
    for err in [
        vm.disasm_pc().expect_err("version 1"),
        vm.disasm_script(0).expect_err("version 1"),
    ] {
        assert_eq!(err.kind, ErrorKind::UnsupportedScriptVersion);
        assert_eq!(err.to_string(), "script version 1 is not supported");
    }
}
