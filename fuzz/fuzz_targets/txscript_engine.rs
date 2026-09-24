// SPDX-License-Identifier: ISC
//! Script engine fuzz target: engine construction and execution over
//! arbitrary signature/public-key script pairs, flags, script versions,
//! and the transaction fields the lock-time opcodes read must never panic
//! and must terminate.
//!
//! Input layout, little endian: flags (4), a script-version selector (1),
//! the transaction version (2), the input's sequence (4), the lock time
//! (4), a split point (2), then the script bytes.  Every field has bytes
//! of its own so the fuzzer varies each independently.  An earlier layout
//! reused the flag bytes as the sequence and the version bytes as the lock
//! time, and fixed the transaction version at 1, so
//! OP_CHECKSEQUENCEVERIFY always failed its version check before reaching
//! the sequence comparison.  It also drew the script version modulo 3,
//! and the engine executes only version 0 (any other version succeeds
//! without running, dcrd `Execute`), so two inputs in three tested
//! nothing past construction.  The selector now names a non-zero version
//! for one value in sixteen, enough to keep that early return covered.

#![no_main]

use libfuzzer_sys::fuzz_target;

use dcroxide_chainhash::Hash;
use dcroxide_txscript::{Engine, ScriptFlags};
use dcroxide_wire::{MsgTx, OutPoint, TxIn, TxOut, TxSerializeType};

/// The bytes ahead of the scripts.
const HEADER: usize = 17;

fn le16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER {
        return;
    }
    // Only the defined flag bits: undefined ones change nothing.
    let flags = ScriptFlags(le32(&data[0..4]) & 0x7f);
    let selector = data[4];
    let version = if selector & 0xf0 == 0xf0 {
        u16::from(selector & 0x0f) + 1
    } else {
        0
    };
    let tx_version = le16(&data[5..7]);
    let sequence = le32(&data[7..11]);
    let lock_time = le32(&data[11..15]);
    let split = usize::from(le16(&data[15..17]));
    let scripts = &data[HEADER..];
    let split = split.min(scripts.len());
    let (sig_script, pk_script) = scripts.split_at(split);

    let tx = MsgTx {
        ser_type: TxSerializeType::Full,
        version: tx_version,
        tx_in: vec![TxIn {
            previous_out_point: OutPoint {
                hash: Hash::ZERO,
                index: 0,
                tree: 0,
            },
            sequence,
            value_in: 0,
            block_height: 0,
            block_index: 0,
            signature_script: sig_script.to_vec(),
        }],
        tx_out: vec![TxOut {
            value: 0,
            version: 0,
            pk_script: Vec::new(),
        }],
        lock_time,
        expiry: 0,
    };

    if let Ok(mut vm) = Engine::new(pk_script, &tx, 0, flags, version) {
        let result = vm.execute();
        // dcrd `Execute` runs nothing for a non-zero script version.
        if version != 0 {
            assert!(result.is_ok(), "script version {version} executed");
        }
    }
});
