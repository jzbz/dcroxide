// SPDX-License-Identifier: ISC
//! Deterministic nonce generation per RFC 6979 with dcrd's exact input
//! handling (mirrors dcrd `secp256k1.NonceRFC6979`).
//!
//! dcrd deviates from a strict RFC 6979 reading in ways that are fixed
//! behavior for Decred: the HMAC key material is the raw
//! `privkey || hash [|| extra [|| version]]` bytes (the hash is *not*
//! reduced mod N first), and the `extra_iterations` parameter skips that
//! many valid candidates from the DRBG stream rather than re-seeding.
//!
//! A candidate is tested in constant time, and the key buffer and the
//! DRBG state, which hold the private key and derive the nonce, are wiped
//! on return, as is each HMAC's state when it is dropped (the `zeroize`
//! features of `hmac` and `sha2`, pinned below); dcrd wipes none of them.

use hmac::{EagerHash, Hmac, KeyInit, Mac};
use k256::Scalar;
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::subtle::Choice;
use sha2::Sha256;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

// What wipes each HMAC when it is dropped.  `hmac`'s core holds the two
// SHA-2 states, keyed by K, and has no `Drop` of its own
// (`hmac-0.13.0/src/block_api.rs:13-17`); each state wipes itself under
// `sha2`'s `zeroize` feature (`sha2-0.11.1/src/block_api.rs:92-104`), and
// the block buffer beside them, which the private key's bytes pass
// through in steps D and F, under `digest`'s
// (`block-buffer-0.12.1/src/lib.rs:433-442`), which `sha2`'s feature
// turns on, and `hmac`'s as well.  So this does not compile without
// `sha2`'s feature; the manifest enables `hmac`'s too, so that the
// buffer's wipe does not rest on what `sha2`'s feature happens to
// include.  Cargo unifies features, so only a build without
// dcroxide-tlscrypto, which enables both as well, depends on this
// crate's own.
const _: () = {
    fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    let _ = wiped_on_drop::<<Sha256 as EagerHash>::Core>;
    let _ = wiped_on_drop::<hmac::digest::block_api::Buffer<hmac::block_api::HmacCore<Sha256>>>;
};

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
    let mut key_buf = Zeroizing::new([0u8; 32 + 32 + 32 + 16]);
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
    let mut v = Zeroizing::new([0x01u8; 32]);
    let mut k = Zeroizing::new([0x00u8; 32]);

    // Step D: K = HMAC_K(V || 0x00 || key).
    *k = hmac_sha256(&*k, &[&*v, &[0x00], key]);
    // Step E: V = HMAC_K(V).
    *v = hmac_sha256(&*k, &[&*v]);
    // Step F: K = HMAC_K(V || 0x01 || key).
    *k = hmac_sha256(&*k, &[&*v, &[0x01], key]);
    // Step G: V = HMAC_K(V).
    *v = hmac_sha256(&*k, &[&*v]);

    // Step H: draw candidates until one is in [1, N-1]; skip
    // `extra_iterations` valid candidates first.
    let mut generated: u32 = 0;
    loop {
        *v = hmac_sha256(&*k, &[&*v]);

        // dcrd's `!overflow && !secret.IsZero()` (nonce.go), in constant
        // time: `from_repr` compares with N in constant time, and the zero
        // test runs on the value it selects.  The one branch is dcrd's, on
        // a rejected candidate, at odds of about 2^-128.
        let valid = bool::from(
            Scalar::from_repr((*v).into())
                .map(|candidate| !candidate.is_zero())
                .unwrap_or(Choice::from(0)),
        );
        if valid {
            generated = generated.wrapping_add(1);
            if generated > extra_iterations {
                // Copied out before `k`, `v` and `key_buf` are wiped.
                return *v;
            }
        }

        *k = hmac_sha256(&*k, &[&*v, &[0x00]]);
        *v = hmac_sha256(&*k, &[&*v]);
    }
}
