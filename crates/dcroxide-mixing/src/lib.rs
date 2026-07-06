// SPDX-License-Identifier: ISC
//! StakeShuffle mixing primitives mirroring dcrd's `mixing` package
//! at `release-v2.1.5`: message identities and signatures over the
//! wire mix messages, session ID derivation and validation, the
//! DC-net finite field and vector math, the per-run ChaCha20 PRNG,
//! UTXO ownership proofs, and the mixing limits.
//!
//! The hybrid key agreement (`keyagreement.go`, X25519-style ECDH
//! plus the sntrup4591761 post-quantum KEM) is only used by the
//! wallet-side mix client and is deferred with it; the mixpool relay
//! validation paths do not require it.

use core::fmt;

mod dcnet;
mod field;
mod prng;
mod sid;
mod signatures;
mod utxoproof;

pub use dcnet::{
    MSIZE, Vect, add_vectors, coefficients, dc_mix, dc_mix_pads, int_vectors_from_bytes,
    int_vectors_to_bytes, is_root, rand_vec, sr_mix, sr_mix_pads, vec_equals, vec_string, vec_xor,
    xor_vectors,
};
pub use field::{F, FieldInt, in_field_be_bytes};
pub use prng::{ChaCha20Prng, SEED_SIZE};
pub use sid::{sort_prs_for_session, validate_session};
pub use signatures::{MixMessage, sign_message, verify_signature, verify_signed_message};
pub use utxoproof::{Secp256k1KeyPair, validate_secp256k1_p2pkh};

/// A bit in the pair request flags field indicating support for
/// solving and publishing factored slot reservation polynomials (dcrd
/// `PRFlagCanSolveRoots`).
pub const PR_FLAG_CAN_SOLVE_ROOTS: u8 = 1;

/// The script class descriptor for the mixed outputs; only secp256k1
/// P2PKH is allowed at this time (dcrd `ScriptClassP2PKHv0`).
pub const SCRIPT_CLASS_P2PKH_V0: &str = "P2PKH-secp256k1-v0";

/// The minimum number of peers required for a mix run to proceed
/// (dcrd `MinPeers`).
pub const MIN_PEERS: u32 = 4;

/// The maximum number of peers allowed together in a single mix
/// session (dcrd mixing `MaxPeers`; a practical limit below the wire
/// protocol's).
pub const MAX_PEERS: u32 = 64;

/// The maximum number of mixed messages that any single peer can
/// contribute to the mix (dcrd mixing `MaxMcount`).
pub const MAX_MCOUNT: u32 = 16;

/// The maximum number of mixed messages in total that can be created
/// during a session (dcrd mixing `MaxMtot`).
pub const MAX_MTOT: u32 = 1024;

/// The maximum size of a mix transaction (dcrd
/// `MaxMixTxSerializeSize`).
pub const MAX_MIX_TX_SERIALIZE_SIZE: u32 = 100_000;

/// The maximum value of a mixed output (dcrd `MaxMixAmount`: the
/// 21,000,000 DCR supply in atoms over the minimum peer count).
pub const MAX_MIX_AMOUNT: i64 = 2_100_000_000_000_000 / MIN_PEERS as i64;

/// The maximum allowed expiry for a new pair request message created
/// with a blockchain tip at `tip_height` (dcrd `MaxExpiry`).
pub fn max_expiry(tip_height: u32, params: &dcroxide_chaincfg::Params) -> u32 {
    // dcrd divides an hour by the per-block target duration; every
    // network's target is positive.
    let per_hour = 3600i64.checked_div(params.target_time_per_block_secs);
    tip_height
        .wrapping_add(per_hour.unwrap_or_default() as u32)
        .wrapping_add(1)
}

/// Errors surfaced by the mixing primitives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MixError {
    /// The pair request order of a key exchange is not validly sorted
    /// (dcrd `errInvalidPROrder`).
    InvalidPROrder,
    /// A run-0 key exchange session ID is not derived from its pair
    /// requests and epoch (dcrd `errInvalidSessionID`).
    InvalidSessionID,
    /// A message could not be signed.
    Signing,
}

impl fmt::Display for MixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MixError::InvalidPROrder => f.write_str("invalid pair request order"),
            MixError::InvalidSessionID => f.write_str("invalid session ID"),
            MixError::Signing => f.write_str("unable to sign message"),
        }
    }
}

impl std::error::Error for MixError {}
