// SPDX-License-Identifier: ISC
//! Deterministic nonce generation per RFC 6979 with dcrd's exact input
//! handling (mirrors dcrd `secp256k1.NonceRFC6979`).
//!
//! dcrd deviates from a strict RFC 6979 reading in ways that are fixed
//! behavior for Decred: the HMAC key material is the raw
//! `privkey || hash [|| extra [|| version]]` bytes (the hash is *not*
//! reduced mod N first), and the `extra_iterations` parameter skips that
//! many valid candidates from the DRBG stream rather than re-seeding.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::{GROUP_ORDER_BYTES, is_zero};

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 of the concatenated message parts under `key`.
fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// Generate a deterministic nonce in `[1, N-1]` per RFC 6979 (HMAC-SHA256),
/// byte-compatible with dcrd's `NonceRFC6979`.
///
/// `priv_key` and `hash` are truncated to 32 bytes / left-padded with zeros
/// exactly as dcrd does. When `version` is provided without `extra`, the
/// 32-byte extra-data slot is filled with zeros (dcrd behavior). The
/// `extra_iterations` parameter returns the (n+1)-th valid candidate from
/// the DRBG stream, supporting signing-retry loops.
// Offset arithmetic is bounded by the fixed 112-byte key buffer and the
// 32-byte-capped input slices.
#[allow(clippy::arithmetic_side_effects)]
pub fn nonce_rfc6979(
    priv_key: &[u8],
    hash: &[u8],
    extra: Option<&[u8; 32]>,
    version: Option<&[u8; 16]>,
    extra_iterations: u32,
) -> [u8; 32] {
    // Assemble the HMAC key material: privkey(32) || hash(32) with dcrd's
    // truncate/left-pad handling, then the optional extra and version.
    let mut key_buf = [0u8; 32 + 32 + 32 + 16];
    let priv_key = &priv_key[..priv_key.len().min(32)];
    let hash = &hash[..hash.len().min(32)];

    let mut offset = 32 - priv_key.len();
    key_buf[offset..offset + priv_key.len()].copy_from_slice(priv_key);
    offset += priv_key.len();
    offset += 32 - hash.len();
    key_buf[offset..offset + hash.len()].copy_from_slice(hash);
    offset += hash.len();
    match (extra, version) {
        (Some(extra), None) => {
            key_buf[offset..offset + 32].copy_from_slice(extra);
            offset += 32;
        }
        (Some(extra), Some(version)) => {
            key_buf[offset..offset + 32].copy_from_slice(extra);
            offset += 32;
            key_buf[offset..offset + 16].copy_from_slice(version);
            offset += 16;
        }
        (None, Some(version)) => {
            // Version without extra data: leave the extra slot all zero,
            // exactly like dcrd.
            offset += 32;
            key_buf[offset..offset + 16].copy_from_slice(version);
            offset += 16;
        }
        (None, None) => {}
    }
    let key = &key_buf[..offset];

    // RFC 6979 HMAC-DRBG.
    //
    // Step B: V = 0x01 x 32.  Step C: K = 0x00 x 32.
    let mut v = [0x01u8; 32];
    let mut k = [0x00u8; 32];

    // Step D: K = HMAC_K(V || 0x00 || key).
    k = hmac_sha256(&k, &[&v, &[0x00], key]);
    // Step E: V = HMAC_K(V).
    v = hmac_sha256(&k, &[&v]);
    // Step F: K = HMAC_K(V || 0x01 || key).
    k = hmac_sha256(&k, &[&v, &[0x01], key]);
    // Step G: V = HMAC_K(V).
    v = hmac_sha256(&k, &[&v]);

    // Step H: draw candidates until one is in [1, N-1]; skip
    // `extra_iterations` valid candidates first.
    let mut generated: u32 = 0;
    loop {
        v = hmac_sha256(&k, &[&v]);

        if v < GROUP_ORDER_BYTES && !is_zero(&v) {
            generated = generated.wrapping_add(1);
            if generated > extra_iterations {
                return v;
            }
        }

        k = hmac_sha256(&k, &[&v, &[0x00]]);
        v = hmac_sha256(&k, &[&v]);
    }
}
