// SPDX-License-Identifier: ISC
//! Script engine fuzz target: engine construction and execution over
//! arbitrary signature/public-key script pairs, flags, and script versions
//! must never panic and must terminate. The input encodes flags (4 LE),
//! script version (2 LE), a split point, and the raw script bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;

use dcroxide_chainhash::Hash;
use dcroxide_txscript::{Engine, ScriptFlags};
use dcroxide_wire::{MsgTx, OutPoint, TxIn, TxOut, TxSerializeType};

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let flags = ScriptFlags(u32::from_le_bytes([data[0], data[1], data[2], data[3]]) & 0x7f);
    let version = u16::from_le_bytes([data[4], data[5]]) % 3;
    let split = usize::from(u16::from_le_bytes([data[6], data[7]]));
    let scripts = &data[8..];
    let split = split.min(scripts.len());
    let (sig_script, pk_script) = scripts.split_at(split);

    let tx = MsgTx {
        ser_type: TxSerializeType::Full,
        version: 1,
        tx_in: vec![TxIn {
            previous_out_point: OutPoint {
                hash: Hash::ZERO,
                index: 0,
                tree: 0,
            },
            sequence: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
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
        lock_time: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
        expiry: 0,
    };

    if let Ok(mut vm) = Engine::new(pk_script, &tx, 0, flags, version) {
        let _ = vm.execute();
    }
});
