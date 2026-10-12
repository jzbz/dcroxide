// SPDX-License-Identifier: ISC
//! Signature hash calculation (dcrd `sighash.go`): Decred's split
//! prefix/witness commitment digests combined under BLAKE-256.

use alloc::format;
use alloc::vec::Vec;

use dcroxide_chainhash::{Hash, hash_b, hash_h};
use dcroxide_wire::MsgTx;

use crate::error::{ErrorKind, ScriptError, script_error};
use crate::script::check_script_parses;

/// Hash type bits at the end of a signature (dcrd `SigHashType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigHashType(pub u8);

/// Signs all outputs (dcrd `SigHashAll`).
pub const SIG_HASH_ALL: SigHashType = SigHashType(0x1);
/// Signs no outputs (dcrd `SigHashNone`).
pub const SIG_HASH_NONE: SigHashType = SigHashType(0x2);
/// Signs the single corresponding output (dcrd `SigHashSingle`).
pub const SIG_HASH_SINGLE: SigHashType = SigHashType(0x3);
/// Commits only to the input being signed (dcrd `SigHashAnyOneCanPay`).
pub const SIG_HASH_ANY_ONE_CAN_PAY: SigHashType = SigHashType(0x80);

/// The bits of the hash type which identify which outputs are signed (dcrd
/// `sigHashMask`).
pub(crate) const SIG_HASH_MASK: u8 = 0x1f;

/// The serialization type committed to in place of witness data (dcrd
/// `SigHashSerializePrefix`).
pub const SIG_HASH_SERIALIZE_PREFIX: u32 = 1;

/// The serialization type committing only to witness data (dcrd
/// `SigHashSerializeWitness`).
pub const SIG_HASH_SERIALIZE_WITNESS: u32 = 3;

/// Append a varint in the signature hash encoding (same format as the wire
/// varint; dcrd `putVarInt`).
fn put_var_int(buf: &mut Vec<u8>, val: u64) {
    if val < 0xfd {
        buf.push(val as u8);
    } else if val <= u64::from(u16::MAX) {
        buf.push(0xfd);
        buf.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= u64::from(u32::MAX) {
        buf.push(0xfe);
        buf.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

/// The number of bytes the varint encoding of `val` occupies (dcrd
/// `varIntSerializeSize`).
fn var_int_serialize_size(val: u64) -> usize {
    if val < 0xfd {
        1
    } else if val <= u64::from(u16::MAX) {
        3
    } else if val <= u64::from(u32::MAX) {
        5
    } else {
        9
    }
}

/// The number of bytes the prefix hash portion of the signature hash
/// occupies when serialized (dcrd `sigHashPrefixSerializeSize`).
#[allow(
    clippy::arithmetic_side_effects,
    reason = "every term is bounded by tx's in-memory size: a TxIn occupies more than the 41 \
              bytes counted for it, a TxOut more than the 10 + 9 counted for it besides its \
              script, and each pk_script's bytes are held in memory, so the sum fits in usize"
)]
fn sig_hash_prefix_serialize_size(
    hash_type: SigHashType,
    tx_ins: &[dcroxide_wire::TxIn],
    tx_outs: &[dcroxide_wire::TxOut],
    sign_idx: usize,
) -> usize {
    // 1) 4 bytes version/serialization type
    // 2) number of inputs varint
    // 3) per input: 32-byte prevout hash, 4-byte index, 1-byte tree,
    //    4-byte sequence
    // 4) number of outputs varint
    // 5) per output: 8-byte amount, 2-byte script version, pkscript
    //    varint + bytes (nil script for non-signed SigHashSingle outputs)
    // 6) 4 bytes lock time
    // 7) 4 bytes expiry
    let num_tx_ins = tx_ins.len();
    let num_tx_outs = tx_outs.len();
    let mut size = 4
        + var_int_serialize_size(num_tx_ins as u64)
        + num_tx_ins * (32 + 4 + 1 + 4)
        + var_int_serialize_size(num_tx_outs as u64)
        + num_tx_outs * (8 + 2)
        + 4
        + 4;
    for (tx_out_idx, tx_out) in tx_outs.iter().enumerate() {
        let mut pk_script: &[u8] = &tx_out.pk_script;
        if hash_type.0 & SIG_HASH_MASK == SIG_HASH_SINGLE.0 && tx_out_idx != sign_idx {
            pk_script = &[];
        }
        size += var_int_serialize_size(pk_script.len() as u64);
        size += pk_script.len();
    }
    size
}

/// The number of bytes the witness hash portion of the signature hash
/// occupies when serialized (dcrd `sigHashWitnessSerializeSize`).
#[allow(
    clippy::arithmetic_side_effects,
    reason = "num_tx_ins counts TxIns held in memory and sign_script is a slice, so their sum \
              plus at most 22 varint and version bytes fits in usize; the sum is at least \
              4 + 1 + 1 = 6, so subtracting 1 cannot underflow"
)]
fn sig_hash_witness_serialize_size(num_tx_ins: usize, sign_script: &[u8]) -> usize {
    // 1) 4 bytes version/serialization type
    // 2) number of inputs varint
    // 3) per input: the signing script for the input being signed and a
    //    nil script (a single 0x00 varint byte) for the numTxIns-1 others.
    // dcrd adds `numTxIns - 1` in `int` arithmetic, which is -1 for a
    // transaction with no inputs, and the size is load-bearing there:
    // `calc_signature_hash` hashes the whole zero-padded buffer, as dcrd
    // does.  Subtracting the one last gives dcrd's exact sum without
    // underflowing, since the other terms total at least five.
    (4 + var_int_serialize_size(num_tx_ins as u64)
        + num_tx_ins
        + var_int_serialize_size(sign_script.len() as u64)
        + sign_script.len())
        - 1
}

/// Compute the signature hash for the specified input, serializing and
/// hashing every part of it (dcrd `calcSignatureHash` called with a nil
/// `cachedPrefix`, which is every call dcrd makes at the parity commit).
pub(crate) fn calc_signature_hash(
    sign_script: &[u8],
    hash_type: SigHashType,
    tx: &MsgTx,
    idx: usize,
) -> Result<[u8; 32], ScriptError> {
    calc_signature_hash_with_prefix(sign_script, hash_type, tx, idx, None)
}

/// Compute the signature hash for the specified input (dcrd
/// `calcSignatureHash`, `sighash.go:229-440`).
///
/// `cached_prefix` is dcrd's `cachedPrefix` argument: the hash of the
/// transaction ([`MsgTx::tx_hash`]) when the caller already has it.  It
/// must be the hash of `tx` itself; nothing here checks that.  It stands
/// in for the prefix hash when the masked hash type is `SigHashAll` and
/// `SigHashAnyOneCanPay` is clear, dcrd's own condition
/// (`sighash.go:301-305`), and is ignored for every other hash type.
///
/// Under that condition the prefix commits to every input with its own
/// sequence and to every output unaltered, so the bytes hashed for it
/// are the version with serialization type 1, the inputs, the outputs,
/// the lock time and the expiry: the no-witness serialization
/// `MsgTx::tx_hash` hashes ([`SIG_HASH_SERIALIZE_PREFIX`] has the value
/// of `TxSerializeNoWitness`), whatever the input index, the script and
/// the serialization type the transaction itself carries.  The witness
/// hash and the error for a `SigHashSingle` index are not affected.
///
/// dcrd ships this path switched off (`optimizeSigVerification`,
/// `opcode.go:27-32`) and hashes the prefix again for every signature.
/// The port takes it when a caller supplies the hash, a recorded step
/// past dcrd (PARITY.md).  dcrd's version reads the hash from a cache
/// kept on the transaction (`CachedTxHash`, `wire/msgtx.go:442-449`),
/// which is stale once the transaction is modified; here the hash is an
/// argument and nothing is stored on a transaction, and handing in the
/// hash of the transaction as it stands is the caller's part
/// ([`crate::Engine::set_tx_hash`]).  With `None` every part is
/// serialized and hashed, as dcrd does.
pub(crate) fn calc_signature_hash_with_prefix(
    sign_script: &[u8],
    hash_type: SigHashType,
    tx: &MsgTx,
    idx: usize,
    cached_prefix: Option<&Hash>,
) -> Result<[u8; 32], ScriptError> {
    // The SigHashSingle signature type signs only the corresponding input
    // and output, so it is improper to use it on input indices that don't
    // have a corresponding output.
    if hash_type.0 & SIG_HASH_MASK == SIG_HASH_SINGLE.0 && idx >= tx.tx_out.len() {
        return Err(script_error(
            ErrorKind::InvalidSigHashSingleIndex,
            format!(
                "attempt to sign single input at index {idx} >= {} outputs",
                tx.tx_out.len()
            ),
        ));
    }

    // Choose the inputs that will be committed to based on the signature
    // hash type. SigHashAnyOneCanPay commits only to the input being
    // signed; otherwise all inputs are committed to.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "idx < tx.tx_in.len() is the documented precondition under \
                  SigHashAnyOneCanPay (the engine passes its own input index), so \
                  idx + 1 <= tx.tx_in.len(); an out-of-range idx panics on the slice as dcrd's \
                  tx.TxIn[idx : idx+1] does"
    )]
    let (tx_ins, sign_tx_in_idx) = if hash_type.0 & SIG_HASH_ANY_ONE_CAN_PAY.0 != 0 {
        (&tx.tx_in[idx..idx + 1], 0usize)
    } else {
        (&tx.tx_in[..], idx)
    };

    // The prefix hash is the transaction hash when the caller supplied it
    // and the signature commits to the whole prefix (dcrd
    // `sighash.go:296-305`).  Otherwise it is computed below.
    let prefix_hash = match cached_prefix {
        Some(cached)
            if hash_type.0 & SIG_HASH_MASK == SIG_HASH_ALL.0
                && hash_type.0 & SIG_HASH_ANY_ONE_CAN_PAY.0 == 0 =>
        {
            *cached
        }
        _ => {
            // Choose the outputs to commit to based on the signature hash
            // type: SigHashNone commits to none, SigHashSingle to the
            // outputs up to and including the corresponding one (with
            // prior outputs cleared), and everything else (including
            // undefined hash types) to all outputs.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "idx < tx.tx_out.len() is checked above for SigHashSingle, so \
                          idx + 1 <= tx.tx_out.len()"
            )]
            let tx_outs: &[dcroxide_wire::TxOut] = match hash_type.0 & SIG_HASH_MASK {
                x if x == SIG_HASH_NONE.0 => &[],
                x if x == SIG_HASH_SINGLE.0 => &tx.tx_out[..idx + 1],
                _ => &tx.tx_out[..],
            };

            // The prefix hash commits to the non-witness data:
            // 1) txversion|(SigHashSerializePrefix<<16) (LE u32)
            // 2) number of inputs (varint), then per input: prevout hash,
            //    index (LE u32), tree (byte), sequence (LE u32, zeroed for
            //    non-signed inputs under SigHashNone/SigHashSingle)
            // 3) number of outputs (varint), then per output: amount (LE
            //    u64), script version (LE u16), pkscript (varint length +
            //    bytes); under SigHashSingle non-corresponding outputs
            //    commit to value -1 and a nil script
            // 4) lock time and expiry (LE u32 each).
            let prefix_size = sig_hash_prefix_serialize_size(hash_type, tx_ins, tx_outs, idx);
            let mut prefix_buf = Vec::with_capacity(prefix_size);
            let version = u32::from(tx.version) | (SIG_HASH_SERIALIZE_PREFIX << 16);
            prefix_buf.extend_from_slice(&version.to_le_bytes());

            put_var_int(&mut prefix_buf, tx_ins.len() as u64);
            for (tx_in_idx, tx_in) in tx_ins.iter().enumerate() {
                let prev_out = &tx_in.previous_out_point;
                prefix_buf.extend_from_slice(&prev_out.hash.0);
                prefix_buf.extend_from_slice(&prev_out.index.to_le_bytes());
                prefix_buf.push(prev_out.tree as u8);

                let mut sequence = tx_in.sequence;
                if (hash_type.0 & SIG_HASH_MASK == SIG_HASH_NONE.0
                    || hash_type.0 & SIG_HASH_MASK == SIG_HASH_SINGLE.0)
                    && tx_in_idx != sign_tx_in_idx
                {
                    sequence = 0;
                }
                prefix_buf.extend_from_slice(&sequence.to_le_bytes());
            }

            put_var_int(&mut prefix_buf, tx_outs.len() as u64);
            for (tx_out_idx, tx_out) in tx_outs.iter().enumerate() {
                let mut value = tx_out.value;
                let mut pk_script: &[u8] = &tx_out.pk_script;
                if hash_type.0 & SIG_HASH_MASK == SIG_HASH_SINGLE.0 && tx_out_idx != idx {
                    value = -1;
                    pk_script = &[];
                }
                prefix_buf.extend_from_slice(&(value as u64).to_le_bytes());
                prefix_buf.extend_from_slice(&tx_out.version.to_le_bytes());
                put_var_int(&mut prefix_buf, pk_script.len() as u64);
                prefix_buf.extend_from_slice(pk_script);
            }

            prefix_buf.extend_from_slice(&tx.lock_time.to_le_bytes());
            prefix_buf.extend_from_slice(&tx.expiry.to_le_bytes());
            hash_h(&prefix_buf)
        }
    };

    // The witness hash commits to the input witness data:
    // 1) txversion|(SigHashSerializeWitness<<16) (LE u32)
    // 2) number of inputs (varint), then per input the signing script for
    //    the input being signed and a nil script for all others.
    //
    // dcrd allocates the buffer at its computed size and hashes all of
    // it.  The size assumes the signing script is written, so when no
    // input sits at the signed index -- a transaction with no inputs, or
    // an index past the last one -- the unwritten tail stays zero and is
    // hashed too.  Consensus never gets there (the engine requires a
    // valid input index), but the public wrappers do.
    let witness_size = sig_hash_witness_serialize_size(tx_ins.len(), sign_script);
    let mut witness_buf = Vec::with_capacity(witness_size);
    let version = u32::from(tx.version) | (SIG_HASH_SERIALIZE_WITNESS << 16);
    witness_buf.extend_from_slice(&version.to_le_bytes());

    put_var_int(&mut witness_buf, tx_ins.len() as u64);
    for tx_in_idx in 0..tx_ins.len() {
        let commit_script: &[u8] = if tx_in_idx == sign_tx_in_idx {
            sign_script
        } else {
            &[]
        };
        put_var_int(&mut witness_buf, commit_script.len() as u64);
        witness_buf.extend_from_slice(commit_script);
    }
    debug_assert!(witness_buf.len() <= witness_size);
    witness_buf.resize(witness_size, 0);
    let witness_hash = hash_h(&witness_buf);

    // The final signature hash is blake256 over the hash type (LE u32),
    // the prefix hash, and the witness hash.
    let mut sig_hash_buf = Vec::with_capacity(32 * 2 + 4);
    sig_hash_buf.extend_from_slice(&u32::from(hash_type.0).to_le_bytes());
    sig_hash_buf.extend_from_slice(&prefix_hash.0);
    sig_hash_buf.extend_from_slice(&witness_hash.0);
    Ok(hash_b(&sig_hash_buf))
}

/// Compute the signature hash for the specified input of the target
/// transaction (dcrd `CalcSignatureHash`).
///
/// Like dcrd, `idx` must be a valid input index for the transaction under
/// `SigHashAnyOneCanPay` (dcrd panics otherwise; this port panics on the
/// same out-of-range slicing).  Without that flag an index past the last
/// input commits the script nowhere, and the hash covers the zero-padded
/// witness buffer exactly as dcrd's does.
///
/// NOTE: This function is only valid for version 0 scripts.
pub fn calc_signature_hash_checked(
    script: &[u8],
    hash_type: SigHashType,
    tx: &MsgTx,
    idx: usize,
) -> Result<[u8; 32], ScriptError> {
    const SCRIPT_VERSION: u16 = 0;
    check_script_parses(SCRIPT_VERSION, script)?;
    calc_signature_hash(script, hash_type, tx, idx)
}

/// Convenience wrapper returning the sighash as a [`Hash`](struct@Hash).
pub fn calc_signature_hash_as_hash(
    script: &[u8],
    hash_type: SigHashType,
    tx: &MsgTx,
    idx: usize,
) -> Result<Hash, ScriptError> {
    calc_signature_hash_checked(script, hash_type, tx, idx).map(Hash)
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test arithmetic over small fixed values"
)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use dcroxide_testutil::SplitMix64;
    use dcroxide_wire::{OutPoint, TxIn, TxOut, TxSerializeType};

    use super::*;

    /// The hash type bytes dcrd's condition selects (`sighash.go:301-305`):
    /// masked type `SigHashAll` with `SigHashAnyOneCanPay` clear, the two
    /// bits the mask leaves out taking every value.
    const TAKES_TX_HASH: [u8; 4] = [0x01, 0x21, 0x41, 0x61];

    /// A transaction with the given numbers of inputs and outputs and
    /// every field drawn at random, the witness fields and the
    /// transaction's own serialization type included.  The inputs spend
    /// from both trees, and from trees no decoder accepts.
    fn random_tx(rng: &mut SplitMix64, num_in: usize, num_out: usize) -> MsgTx {
        let mut tx = MsgTx {
            ser_type: match rng.below(3) {
                0 => TxSerializeType::Full,
                1 => TxSerializeType::NoWitness,
                _ => TxSerializeType::OnlyWitness,
            },
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
                    tree: match rng.below(4) {
                        0 => dcroxide_wire::TX_TREE_REGULAR,
                        1 => dcroxide_wire::TX_TREE_STAKE,
                        2 => -1,
                        _ => rng.next_u64() as i8,
                    },
                },
                sequence: rng.next_u64() as u32,
                value_in: rng.next_u64() as i64,
                block_height: rng.next_u64() as u32,
                block_index: rng.next_u64() as u32,
                signature_script: rng.bytes(40),
            });
        }
        for _ in 0..num_out {
            // One script in eight may be long enough for a three-byte
            // length.
            let max_len = if rng.below(8) == 0 { 600 } else { 40 };
            tx.tx_out.push(TxOut {
                value: rng.next_u64() as i64,
                version: rng.next_u64() as u16,
                pk_script: rng.bytes(max_len),
            });
        }
        tx
    }

    /// Whether the call slices the inputs out of range, as dcrd's
    /// `tx.TxIn[idx : idx+1]` does: `SigHashAnyOneCanPay` at an index
    /// with no input, once the `SigHashSingle` check has let it through.
    fn slices_out_of_range(tx: &MsgTx, hash_type: u8, idx: usize) -> bool {
        let single_error = hash_type & SIG_HASH_MASK == SIG_HASH_SINGLE.0 && idx >= tx.tx_out.len();
        !single_error && hash_type & SIG_HASH_ANY_ONE_CAN_PAY.0 != 0 && idx >= tx.tx_in.len()
    }

    /// Given the transaction's hash, the signature hash is the one
    /// computed without it: for every one of the 256 hash type bytes, at
    /// every input index and at two past the last, the same hash or the
    /// same error.  The transactions have none to five inputs and
    /// outputs, and enough of either for a three-byte count.
    #[test]
    fn the_transaction_hash_leaves_every_signature_hash_unchanged() {
        let mut rng = SplitMix64::from_entropy("txscript-sighash-tx-hash");
        let mut shapes = vec![(0, 0), (0, 3), (3, 0), (1, 1), (0xfd, 2), (2, 0xfd)];
        for _ in 0..48 {
            shapes.push((rng.below(6) as usize, rng.below(6) as usize));
        }

        let (mut hashes, mut errors, mut took_tx_hash) = (0usize, 0usize, 0usize);
        for (num_in, num_out) in shapes {
            let tx = random_tx(&mut rng, num_in, num_out);
            let tx_hash = tx.tx_hash();
            let script = rng.bytes(60);
            // Every index of a small transaction; the first, the last and
            // the two past it of a large one.
            let mut indexes: Vec<usize> = (0..num_in.min(6)).collect();
            indexes.extend([num_in.saturating_sub(1), num_in, num_in + 1]);
            indexes.dedup();
            for idx in indexes {
                for hash_type in 0u8..=255 {
                    if slices_out_of_range(&tx, hash_type, idx) {
                        continue;
                    }
                    let plain = calc_signature_hash(&script, SigHashType(hash_type), &tx, idx);
                    let given = calc_signature_hash_with_prefix(
                        &script,
                        SigHashType(hash_type),
                        &tx,
                        idx,
                        Some(&tx_hash),
                    );
                    assert_eq!(
                        given, plain,
                        "{num_in} inputs, {num_out} outputs, index {idx}, hash type {hash_type:#04x}"
                    );
                    match plain {
                        Ok(_) => hashes += 1,
                        Err(err) => {
                            assert_eq!(err.kind, ErrorKind::InvalidSigHashSingleIndex);
                            errors += 1;
                        }
                    }
                    if TAKES_TX_HASH.contains(&hash_type) {
                        took_tx_hash += 1;
                    }
                }
            }
        }
        // Not vacuous: hashes, `SigHashSingle` index errors, and calls
        // that took the prefix hash from the transaction hash.
        assert!(hashes > 10_000 && errors > 100 && took_tx_hash > 500);
    }

    /// The out-of-range slice under `SigHashAnyOneCanPay` panics with
    /// the transaction hash as it does without: the input selection
    /// comes before the prefix hash either way.
    #[test]
    fn an_index_without_an_input_under_anyonecanpay_panics_either_way() {
        let mut rng = SplitMix64(0x5eed);
        let tx = random_tx(&mut rng, 2, 3);
        let tx_hash = tx.tx_hash();
        for hash_type in [0x80u8, 0x81, 0x82, 0x83, 0xa1, 0xff] {
            for idx in [2usize, 3] {
                assert!(slices_out_of_range(&tx, hash_type, idx) || hash_type & 0x1f == 3);
                let plain = catch_unwind(AssertUnwindSafe(|| {
                    calc_signature_hash(&[], SigHashType(hash_type), &tx, idx)
                }));
                let given = catch_unwind(AssertUnwindSafe(|| {
                    calc_signature_hash_with_prefix(
                        &[],
                        SigHashType(hash_type),
                        &tx,
                        idx,
                        Some(&tx_hash),
                    )
                }));
                match (plain, given) {
                    // `SigHashSingle` at an index with no output is the
                    // error, returned before the slice.
                    (Ok(plain), Ok(given)) => {
                        assert!(idx >= tx.tx_out.len() && hash_type & 0x1f == 3);
                        assert_eq!(given, plain);
                        assert!(plain.is_err());
                    }
                    (Err(_), Err(_)) => assert!(slices_out_of_range(&tx, hash_type, idx)),
                    _ => panic!("hash type {hash_type:#04x}, index {idx}: one call panicked"),
                }
            }
        }
    }

    /// A hash that is not the transaction's changes the signature hash
    /// for the four bytes of dcrd's condition, at every index, and for no
    /// other byte: the argument is read exactly when the masked type is
    /// `SigHashAll` and `SigHashAnyOneCanPay` is clear.  An undefined
    /// masked type commits to the same prefix bytes and still computes
    /// them, as dcrd's does.
    #[test]
    fn only_sighashall_without_anyonecanpay_reads_the_given_hash() {
        let mut rng = SplitMix64(0xa11);
        let tx = random_tx(&mut rng, 3, 4);
        let wrong = Hash([0x5a; 32]);
        assert_ne!(wrong, tx.tx_hash());
        let script = [0x51u8, 0x76, 0xac];

        let mut read = Vec::new();
        for hash_type in 0u8..=255 {
            let changed: Vec<bool> = (0..=tx.tx_in.len())
                .filter(|idx| !slices_out_of_range(&tx, hash_type, *idx))
                .map(|idx| {
                    let plain = calc_signature_hash(&script, SigHashType(hash_type), &tx, idx);
                    let given = calc_signature_hash_with_prefix(
                        &script,
                        SigHashType(hash_type),
                        &tx,
                        idx,
                        Some(&wrong),
                    );
                    given != plain
                })
                .collect();
            assert!(!changed.is_empty(), "hash type {hash_type:#04x}");
            // All indexes or none.
            assert!(
                changed.iter().all(|c| *c == changed[0]),
                "hash type {hash_type:#04x}: {changed:?}"
            );
            if changed[0] {
                read.push(hash_type);
            }
        }
        assert_eq!(read, TAKES_TX_HASH);
    }

    /// The given hash goes where the prefix hash goes and nowhere else:
    /// the signature hash is BLAKE-256 over the hash type, that hash and
    /// the witness hash, here for a one-input transaction whose witness
    /// buffer is written out by hand.
    #[test]
    fn the_given_hash_stands_in_for_the_prefix_hash() {
        let mut rng = SplitMix64(0xbee);
        let tx = random_tx(&mut rng, 1, 2);
        let script = [0x51u8, 0x52];
        let given = Hash([0x77; 32]);

        let mut witness = Vec::new();
        witness.extend_from_slice(
            &(u32::from(tx.version) | (SIG_HASH_SERIALIZE_WITNESS << 16)).to_le_bytes(),
        );
        witness.extend_from_slice(&[1, 2, 0x51, 0x52]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&given.0);
        buf.extend_from_slice(&hash_h(&witness).0);

        assert_eq!(
            calc_signature_hash_with_prefix(&script, SIG_HASH_ALL, &tx, 0, Some(&given)),
            Ok(hash_b(&buf))
        );
        // With the transaction's own hash there, it is the signature
        // hash.
        buf[4..36].copy_from_slice(&tx.tx_hash().0);
        assert_eq!(
            calc_signature_hash(&script, SIG_HASH_ALL, &tx, 0),
            Ok(hash_b(&buf))
        );
    }

    /// What dcrd's `CalcSignatureHash` returns for the call: the hash in
    /// hex, or the error's kind and text.  The script is parsed first,
    /// as [`calc_signature_hash_checked`] parses it, and the signature
    /// hash then takes the transaction's hash.
    fn checked_with_tx_hash(
        script: &[u8],
        hash_type: SigHashType,
        tx: &MsgTx,
        idx: usize,
    ) -> Result<[u8; 32], ScriptError> {
        check_script_parses(0, script)?;
        calc_signature_hash_with_prefix(script, hash_type, tx, idx, Some(&tx.tx_hash()))
    }

    /// dcrd's `sighash.json` vectors (`reference_test.go`, the corpus the
    /// `reference_corpus` test runs through the public function) hold
    /// with the transaction's hash in hand: dcrd's expected hash for
    /// every vector, those of type `SigHashAll` built on the transaction
    /// hash, and the `SigHashSingle` index error where dcrd expects it.
    #[test]
    fn sighash_json_vectors_hold_with_the_transaction_hash() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/sighash.json");
        let tests: Vec<Vec<serde_json::Value>> =
            serde_json::from_str(&std::fs::read_to_string(path).expect("testdata file readable"))
                .expect("valid JSON");

        let (mut executed, mut took_tx_hash) = (0usize, 0usize);
        for (i, test) in tests.iter().enumerate() {
            // Skip comment lines.
            if test.len() == 1 {
                continue;
            }
            let unhex = |field: usize| dcroxide_testutil::unhex(test[field].as_str().expect("hex"));
            let (tx, _) = MsgTx::from_bytes(&unhex(0)).expect("tx deserializes");
            let sub_script = unhex(1);
            let idx = test[2].as_f64().expect("input idx") as usize;
            // The JSON number is a signed 32-bit value whose low byte is
            // the hash type (dcrd `testVecF64ToUint32`).
            let hash_type = SigHashType(test[3].as_f64().expect("hash type") as i64 as u8);

            let result = checked_with_tx_hash(&sub_script, hash_type, &tx, idx);
            match test[5].as_str().expect("expected result") {
                "OK" => assert_eq!(result, Ok(unhex(4).try_into().expect("32 bytes")), "#{i}"),
                "SIGHASH_SINGLE_IDX" => assert_eq!(
                    result.expect_err("an error").kind,
                    ErrorKind::InvalidSigHashSingleIndex,
                    "#{i}"
                ),
                other => panic!("test #{i}: unrecognized expected result {other}"),
            }
            executed += 1;
            if TAKES_TX_HASH.contains(&hash_type.0) {
                took_tx_hash += 1;
            }
        }
        assert!(executed > 100, "only {executed} sighash vectors executed");
        assert!(took_tx_hash > 0, "no vector takes the transaction hash");
    }

    /// The signature hash built on the transaction's hash is the one
    /// dcrd computes: its `CalcSignatureHash` through the oracle, which
    /// serializes and hashes the prefix for every call
    /// (`optimizeSigVerification` is `false`).  Random transactions with
    /// none to four inputs and outputs; half the rounds `SigHashAll`, the
    /// rest any byte; every index, and without `SigHashAnyOneCanPay` the
    /// two past the last input as well, where dcrd hashes its padded
    /// witness buffer; scripts that parse and scripts that do not.
    #[test]
    fn the_transaction_hash_gives_the_signature_hash_dcrd_computes() {
        let Some(mut oracle) = dcroxide_testutil::oracle_or_skip() else {
            return;
        };
        let mut rng = SplitMix64::from_entropy("txscript-sighash-tx-hash-oracle");

        const ROUNDS: usize = 3000;
        let (mut took_tx_hash, mut past_the_inputs, mut errors) = (0usize, 0usize, 0usize);
        for round in 0..ROUNDS {
            let (num_in, num_out) = (rng.below(5) as usize, rng.below(5) as usize);
            let mut tx = random_tx(&mut rng, num_in, num_out);
            // The oracle deserializes the transaction: the full
            // serialization, and no negative tree, which dcrd's
            // `ReadOutPoint` refuses.
            tx.ser_type = TxSerializeType::Full;
            for tx_in in &mut tx.tx_in {
                tx_in.previous_out_point.tree &= 0x7f;
            }
            let hash_type = match rng.below(4) {
                0 | 1 => 0x01,
                _ => rng.next_u64() as u8,
            };
            let idx = rng.below(num_in as u64 + 2) as usize;
            if slices_out_of_range(&tx, hash_type, idx) {
                continue;
            }
            // One script in four is any bytes at all and may not parse;
            // the others hold no data push and always do.
            let mut script = rng.bytes(40);
            if rng.below(4) != 0 {
                for byte in &mut script {
                    *byte |= 0x80;
                }
            }

            let ours = match checked_with_tx_hash(&script, SigHashType(hash_type), &tx, idx) {
                Ok(hash) => {
                    if TAKES_TX_HASH.contains(&hash_type) {
                        took_tx_hash += 1;
                        if idx >= num_in {
                            past_the_inputs += 1;
                        }
                    }
                    dcroxide_testutil::hex(&hash)
                }
                Err(err) => {
                    errors += 1;
                    format!("{}: {err}", err.kind.kind_name())
                }
            };

            let mut req = Vec::new();
            req.push(hash_type);
            req.extend_from_slice(&(idx as u32).to_be_bytes());
            req.extend_from_slice(&(script.len() as u32).to_be_bytes());
            req.extend_from_slice(&script);
            req.extend_from_slice(&tx.serialize());
            let resp = oracle.call("calc_sighash", &req);
            let theirs = match (resp["kind"].as_str(), resp["error"].as_str()) {
                (Some(kind), Some(text)) => format!("{kind}: {text}"),
                _ => resp["result"]
                    .as_str()
                    .unwrap_or_else(|| panic!("oracle calc_sighash unexpected response: {resp}"))
                    .to_string(),
            };
            assert_eq!(
                ours,
                theirs,
                "round {round}: script={} hash_type={hash_type:#04x} idx={idx} tx={}",
                dcroxide_testutil::hex(&script),
                dcroxide_testutil::hex(&tx.serialize()),
            );
        }
        // Not vacuous: hashes built on the transaction hash, some of
        // them at an index with no input, and rounds that end in an
        // error.
        assert!(
            took_tx_hash > ROUNDS / 4 && past_the_inputs > ROUNDS / 20 && errors > ROUNDS / 20,
            "{took_tx_hash} on the transaction hash, {past_the_inputs} past the inputs, \
             {errors} errors"
        );
    }
}
