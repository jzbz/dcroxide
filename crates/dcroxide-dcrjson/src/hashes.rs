// SPDX-License-Identifier: ISC
//! Concatenated hash encoding helpers (dcrd dcrjson `parse.go`).

use dcroxide_chainhash::{HASH_SIZE, Hash};

use crate::jsonrpc::{RPCError, codes};

/// Serialize a slice of hashes into a string of hex-encoded bytes
/// (dcrd `EncodeConcatenatedHashes`).
pub fn encode_concatenated_hashes(hashes: &[Hash]) -> String {
    let mut out = String::with_capacity(hashes.len().saturating_mul(HASH_SIZE).saturating_mul(2));
    for hash in hashes {
        for b in hash.as_bytes() {
            out.push_str(&format!("{b:02x}"));
        }
    }
    out
}

/// Decode a slice of contiguous hashes from a single string of
/// concatenated hex-encoded hashes (dcrd `DecodeConcatenatedHashes`).
///
/// These hashes must NOT be the byte-reversed string encoding that is
/// typically used for block and transaction hashes, or each resulting
/// hash will also be reversed.  Errors are [`RPCError`] values exactly
/// as dcrd produces for a JSON-RPC request.
pub fn decode_concatenated_hashes(hashes: &str) -> Result<Vec<Hash>, RPCError> {
    let chunk = HASH_SIZE.saturating_mul(2);
    let num_hashes = hashes.len().checked_div(chunk).unwrap_or(0);
    if num_hashes.saturating_mul(chunk) != hashes.len() {
        return Err(RPCError::new(
            codes::INVALID_PARAMETER,
            "Hashes is not evenly divisible by the hash size",
        ));
    }
    let mut decoded = Vec::with_capacity(num_hashes);
    let bytes = hashes.as_bytes();
    for i in 0..num_hashes {
        let src = &bytes[i.saturating_mul(chunk)..i.saturating_mul(chunk).saturating_add(chunk)];
        let mut hash = [0u8; HASH_SIZE];
        let mut ok = true;
        for (j, pair) in src.chunks(2).enumerate() {
            let hi = (pair[0] as char).to_digit(16);
            let lo = (pair[1] as char).to_digit(16);
            match (hi, lo) {
                (Some(hi), Some(lo)) => hash[j] = ((hi << 4) | lo) as u8,
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            let src_str = String::from_utf8_lossy(src);
            return Err(RPCError::new(
                codes::DECODE_HEX_STRING,
                &format!("Parameter contains invalid hexadecimal encoding: {src_str}"),
            ));
        }
        decoded.push(Hash(hash));
    }
    Ok(decoded)
}
