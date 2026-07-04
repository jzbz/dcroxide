// SPDX-License-Identifier: ISC
//! Differential tests: our script engine vs. dcrd's txscript, live through
//! the oracle, comparing verdict *and* error kind over structured random
//! scripts × random flag combinations, plus signature hash byte-equality
//! over random transactions. This is the in-tree slice of the brief's
//! always-on differential script fuzzer.

// Test-harness arithmetic over bounded indices and lengths.
#![allow(clippy::arithmetic_side_effects)]
mod common;

use common::create_spending_tx;
use dcroxide_chainhash::Hash;
use dcroxide_testutil::{Oracle, SplitMix64, oracle_or_skip};
use dcroxide_txscript::{
    Engine, OP_16, OP_CHECKMULTISIG, OP_CHECKSIG, OP_CHECKSIGALT, OP_DATA_1, OP_DUP, OP_ELSE,
    OP_ENDIF, OP_EQUAL, OP_HASH160, OP_IF, OP_NOTIF, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4,
    OP_RETURN, OP_SSTX, ScriptFlags, SigHashType, calc_signature_hash_checked,
};
use dcroxide_wire::{MsgTx, OutPoint, TxIn, TxOut, TxSerializeType};

/// A structured random script: biased toward interesting shapes rather
/// than pure noise so deep engine paths (conditionals, sig checks, pushes,
/// stake tagging, limits) are exercised.
fn random_script(rng: &mut SplitMix64, max_len: usize) -> Vec<u8> {
    let mut script = Vec::new();
    let target = rng.below(max_len as u64 + 1) as usize;
    while script.len() < target {
        match rng.below(12) {
            // Small data push with random minimality.
            0 => {
                let n = rng.below(6) as usize;
                script.push(OP_DATA_1 + n as u8);
                script.extend(rng.bytes(n + 1));
            }
            // Small int / random single opcode below OP_16.
            1 => script.push(rng.below(u64::from(OP_16) + 1) as u8),
            // Completely random opcode.
            2 | 3 => script.push(rng.next_u64() as u8),
            // Conditional scaffolding.
            4 => script.push(if rng.below(2) == 0 { OP_IF } else { OP_NOTIF }),
            5 => script.push(OP_ELSE),
            6 => script.push(OP_ENDIF),
            // Signature-check ops over whatever garbage is on the stack.
            7 => script.push(match rng.below(3) {
                0 => OP_CHECKSIG,
                1 => OP_CHECKMULTISIG,
                _ => OP_CHECKSIGALT,
            }),
            // PUSHDATA with possibly-truncated payloads.
            8 => {
                let op = match rng.below(3) {
                    0 => OP_PUSHDATA1,
                    1 => OP_PUSHDATA2,
                    _ => OP_PUSHDATA4,
                };
                script.push(op);
                let len_bytes = match op {
                    x if x == OP_PUSHDATA1 => 1,
                    x if x == OP_PUSHDATA2 => 2,
                    _ => 4,
                };
                let claimed = rng.below(8) as usize;
                let mut len_le = [0u8; 4];
                len_le[..].copy_from_slice(&(claimed as u32).to_le_bytes());
                script.extend_from_slice(&len_le[..len_bytes]);
                // Sometimes deliver fewer bytes than claimed.
                let deliver = if rng.below(4) == 0 {
                    rng.below(claimed as u64 + 1) as usize
                } else {
                    claimed
                };
                script.extend(rng.bytes(deliver + 1));
            }
            // Common template fragments.
            9 => script.extend_from_slice(&[OP_DUP, OP_HASH160]),
            10 => script.extend_from_slice(&[OP_EQUAL]),
            // Stake / unspendable markers.
            _ => script.push(if rng.below(2) == 0 {
                OP_SSTX
            } else {
                OP_RETURN
            }),
        }
    }
    script.truncate(target.max(script.len().min(max_len)));
    script
}

/// A push-heavy random signature script.
fn random_sig_script(rng: &mut SplitMix64, max_len: usize) -> Vec<u8> {
    let mut script = Vec::new();
    let target = rng.below(max_len as u64 + 1) as usize;
    while script.len() < target {
        match rng.below(4) {
            0 => script.push(rng.below(u64::from(OP_16) + 1) as u8),
            1 => {
                let n = rng.below(8) as usize;
                script.push(OP_DATA_1 + n as u8);
                script.extend(rng.bytes(n + 1));
            }
            2 => script.push(rng.next_u64() as u8),
            _ => {
                // A 20-byte push, plausible hash input for P2SH shapes.
                script.push(20);
                let mut b = vec![0u8; 20];
                rng.fill(&mut b);
                script.extend_from_slice(&b);
            }
        }
    }
    script.truncate(target.max(script.len().min(max_len)));
    script
}

/// A random flag combination over all the flags dcrd defines.
fn random_flags(rng: &mut SplitMix64) -> ScriptFlags {
    ScriptFlags(rng.below(1 << 7) as u32)
}

/// Run one script pair through our engine, returning "ok" or the kind
/// name.
fn ours_exec(pk_script: &[u8], tx: &MsgTx, flags: ScriptFlags, version: u16) -> String {
    let result = Engine::new(pk_script, tx, 0, flags, version).and_then(|mut vm| vm.execute());
    match result {
        Ok(()) => "ok".to_string(),
        Err(err) => err.kind.kind_name().to_string(),
    }
}

/// Run the same pair through dcrd, returning "ok" or the kind name.
fn theirs_exec(
    oracle: &mut Oracle,
    pk_script: &[u8],
    tx: &MsgTx,
    flags: ScriptFlags,
    version: u16,
) -> String {
    let mut req = Vec::new();
    req.extend_from_slice(&flags.0.to_be_bytes());
    req.extend_from_slice(&version.to_be_bytes());
    req.extend_from_slice(&0u32.to_be_bytes());
    req.extend_from_slice(&(pk_script.len() as u32).to_be_bytes());
    req.extend_from_slice(pk_script);
    req.extend_from_slice(&tx.serialize());
    let resp = oracle.call("script_exec", &req);
    if resp["result"] == "ok" {
        "ok".to_string()
    } else if let Some(kind) = resp["kind"].as_str() {
        kind.to_string()
    } else {
        panic!("oracle script_exec unexpected response: {resp}");
    }
}

#[test]
fn engine_differential_structured() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("txscript-engine-differential");

    const ROUNDS: usize = 4000;
    for round in 0..ROUNDS {
        let sig_script = random_sig_script(&mut rng, 64);
        let pk_script = random_script(&mut rng, 96);
        let flags = random_flags(&mut rng);
        // Occasionally exercise non-zero script versions.
        let version = if rng.below(16) == 0 {
            rng.below(3) as u16 + 1
        } else {
            0
        };

        let mut tx = create_spending_tx(&sig_script, &pk_script);
        // Sometimes randomize the fields the lock-time opcodes read.
        if rng.below(4) == 0 {
            tx.lock_time = rng.next_u64() as u32;
            tx.expiry = rng.next_u64() as u32;
            tx.version = (rng.below(4)) as u16;
            tx.tx_in[0].sequence = rng.next_u64() as u32;
        }

        let ours = ours_exec(&pk_script, &tx, flags, version);
        let theirs = theirs_exec(&mut oracle, &pk_script, &tx, flags, version);
        assert_eq!(
            ours,
            theirs,
            "engine divergence at round {round}: sig={} pk={} flags={:#x} version={version} \
             locktime={} sequence={} txversion={}",
            hex(&sig_script),
            hex(&pk_script),
            flags.0,
            tx.lock_time,
            tx.tx_in[0].sequence,
            tx.version,
        );
    }
}

/// Targeted differential for the paths random scripts essentially never
/// assemble: valid, corrupted, stake-tagged, and unparseable-redeem P2SH
/// spends (the engine's multi-script transition machinery), and the
/// CLTV/CSV locktime failure modes.
#[test]
fn engine_differential_p2sh_and_locktime() {
    use dcroxide_txscript::{
        OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY, OP_SSTXCHANGE, OP_TADD, ScriptBuilder,
    };

    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("txscript-p2sh-locktime-differential");

    const ROUNDS: usize = 2000;
    for round in 0..ROUNDS {
        let (sig_script, pk_script) = if rng.below(2) == 0 {
            // --- P2SH shapes ---
            // A small redeem script; sometimes containing stake/treasury
            // opcodes (must be rejected at engine creation), sometimes
            // deliberately unparseable (rejected at the redeem-script
            // transition), usually a simple satisfiable script.
            let mut redeem = match rng.below(6) {
                0 => vec![dcroxide_txscript::OP_1],
                1 => vec![dcroxide_txscript::OP_1, dcroxide_txscript::OP_1, OP_EQUAL],
                2 => random_script(&mut rng, 24),
                3 => {
                    // Unparseable: a push claiming more data than present.
                    vec![0x4b, 0x01]
                }
                _ => {
                    let n = rng.below(4) as usize;
                    let mut r = rng.bytes(n);
                    r.push(dcroxide_txscript::OP_1);
                    r
                }
            };
            if rng.below(4) == 0 {
                let stake_op = match rng.below(3) {
                    0 => OP_SSTX,
                    1 => OP_SSTXCHANGE,
                    _ => OP_TADD,
                };
                redeem.insert(rng.below(redeem.len() as u64 + 1) as usize, stake_op);
            }

            // The signature script pushes optional args then the redeem
            // script; occasionally violate push-only.
            let mut builder = ScriptBuilder::new();
            if rng.below(2) == 0 {
                builder = builder.add_int64(rng.below(17) as i64);
            }
            if rng.below(8) == 0 {
                builder = builder.add_op(OP_DUP); // not push-only
            }
            let sig_script = builder
                .add_data_unchecked(&redeem)
                .script()
                .expect("builds");

            // The P2SH script hash; sometimes corrupted, sometimes
            // stake-tagged (whose recognition depends on the treasury flag
            // for OP_TADD..OP_TGEN prefixes).
            let mut hash160 =
                dcroxide_crypto::ripemd160::sum160(&dcroxide_crypto::blake256::sum256(&redeem));
            if rng.below(8) == 0 {
                hash160[0] ^= 0x01;
            }
            let mut pk_script = Vec::new();
            if rng.below(3) == 0 {
                pk_script.push(match rng.below(3) {
                    0 => OP_SSTX,
                    1 => OP_SSTXCHANGE,
                    _ => OP_TADD,
                });
            }
            pk_script.push(OP_HASH160);
            pk_script.push(20); // OP_DATA_20
            pk_script.extend_from_slice(&hash160);
            pk_script.push(OP_EQUAL);
            (sig_script, pk_script)
        } else {
            // --- CLTV/CSV shapes ---
            // Push a boundary-biased locktime operand and run the
            // (flag-gated) opcode, leaving the operand as the result.
            let operand: i64 = match rng.below(6) {
                0 => 0,
                1 => rng.below(1000) as i64,
                2 => 499_999_999 + rng.below(3) as i64, // around the threshold
                3 => (1 << 22) | rng.below(0xffff) as i64, // seconds flag
                4 => 1 << 31,                           // disable flag
                _ => -(rng.below(1000) as i64) - 1,     // negative
            };
            let opcode = if rng.below(2) == 0 {
                OP_CHECKLOCKTIMEVERIFY
            } else {
                OP_CHECKSEQUENCEVERIFY
            };
            let pk_script = ScriptBuilder::new()
                .add_int64(operand)
                .add_op(opcode)
                .add_op(dcroxide_txscript::OP_DROP)
                .add_op(dcroxide_txscript::OP_1)
                .script()
                .expect("builds");
            (Vec::new(), pk_script)
        };

        let flags = random_flags(&mut rng);
        let mut tx = create_spending_tx(&sig_script, &pk_script);
        // Boundary-biased tx fields for the locktime opcodes.
        tx.lock_time = match rng.below(4) {
            0 => 0,
            1 => rng.below(1000) as u32,
            2 => 500_000_000 + rng.below(1000) as u32,
            _ => rng.next_u64() as u32,
        };
        tx.version = rng.below(4) as u16;
        tx.tx_in[0].sequence = match rng.below(4) {
            0 => dcroxide_wire::MAX_TX_IN_SEQUENCE_NUM,
            1 => rng.below(0xffff) as u32,
            2 => dcroxide_wire::SEQUENCE_LOCK_TIME_IS_SECONDS | rng.below(0xffff) as u32,
            _ => rng.next_u64() as u32,
        };

        let ours = ours_exec(&pk_script, &tx, flags, 0);
        let theirs = theirs_exec(&mut oracle, &pk_script, &tx, flags, 0);
        assert_eq!(
            ours,
            theirs,
            "p2sh/locktime divergence at round {round}: sig={} pk={} flags={:#x} locktime={} \
             sequence={} txversion={}",
            hex(&sig_script),
            hex(&pk_script),
            flags.0,
            tx.lock_time,
            tx.tx_in[0].sequence,
            tx.version,
        );
    }
}

/// A random transaction for sighash coverage.
fn random_tx(rng: &mut SplitMix64) -> MsgTx {
    let num_in = rng.below(3) as usize + 1;
    let num_out = rng.below(3) as usize + 1;
    let mut tx = MsgTx {
        ser_type: TxSerializeType::Full,
        version: rng.next_u64() as u16,
        tx_in: Vec::new(),
        tx_out: Vec::new(),
        lock_time: rng.next_u64() as u32,
        expiry: rng.next_u64() as u32,
    };
    for _ in 0..num_in {
        let mut hash = [0u8; 32];
        rng.fill(&mut hash);
        tx.tx_in.push(TxIn {
            previous_out_point: OutPoint {
                hash: Hash(hash),
                index: rng.next_u64() as u32,
                tree: (rng.below(3) as i8) - 1,
            },
            sequence: rng.next_u64() as u32,
            value_in: rng.next_u64() as i64,
            block_height: rng.next_u64() as u32,
            block_index: rng.next_u64() as u32,
            signature_script: rng.bytes(32),
        });
    }
    for _ in 0..num_out {
        tx.tx_out.push(TxOut {
            value: (rng.next_u64() & 0x7fff_ffff_ffff) as i64,
            version: rng.next_u64() as u16,
            pk_script: rng.bytes(48),
        });
    }
    tx
}

#[test]
fn sighash_differential() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("txscript-sighash-differential");

    const ROUNDS: usize = 2000;
    for round in 0..ROUNDS {
        let tx = random_tx(&mut rng);
        let idx = rng.below(tx.tx_in.len() as u64) as usize;
        // Bias toward defined hash types with random AnyOneCanPay, but
        // also cover undefined types.
        let hash_type = if rng.below(4) == 0 {
            SigHashType(rng.next_u64() as u8)
        } else {
            SigHashType((rng.below(3) as u8 + 1) | if rng.below(2) == 0 { 0x80 } else { 0 })
        };
        // Random script; occasionally malformed so the parse check path is
        // compared as well.
        let script = random_script(&mut rng, 48);

        let ours = match calc_signature_hash_checked(&script, hash_type, &tx, idx) {
            Ok(hash) => hex(&hash),
            Err(err) => err.kind.kind_name().to_string(),
        };

        let mut req = Vec::new();
        req.push(hash_type.0);
        req.extend_from_slice(&(idx as u32).to_be_bytes());
        req.extend_from_slice(&(script.len() as u32).to_be_bytes());
        req.extend_from_slice(&script);
        req.extend_from_slice(&tx.serialize());
        let resp = oracle.call("calc_sighash", &req);
        let theirs = if let Some(kind) = resp["kind"].as_str() {
            kind.to_string()
        } else if let Some(result) = resp["result"].as_str() {
            result.to_string()
        } else {
            panic!("oracle calc_sighash unexpected response: {resp}");
        };

        assert_eq!(
            ours,
            theirs,
            "sighash divergence at round {round}: script={} hash_type={:#x} idx={idx} tx={}",
            hex(&script),
            hash_type.0,
            hex(&tx.serialize()),
        );
    }
}

fn hex(b: &[u8]) -> String {
    dcroxide_testutil::hex(b)
}
