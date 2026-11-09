// SPDX-License-Identifier: ISC
//! Variable-time secp256k1 arithmetic for **public data only**: every
//! function here may take time that depends on its inputs, and nothing in
//! this crate takes a private key, a nonce or a zeroizing type.  Keys made
//! from secrets, signing and the nonce stay on `k256`, in constant time.
//!
//! The arithmetic is a port of libsecp256k1's portable C (see `NOTICE`),
//! owned in tree as ADR-0016 records, for `dcroxide-dcrec`'s ECDSA
//! verification, compact recovery, EC-Schnorr-DCRv0 verification and key
//! decompression.  It lands in increments.  Today it holds:
//!
//! - the integers mod the group order N ([`Scalar`], libsecp256k1's 4x64
//!   form) and their inverse by safegcd (`modinv64`), which dcrec's
//!   verification and recovery take for s^-1 and r^-1;
//! - the base field in libsecp256k1's 5x52 form (`field`), with its
//!   debug-build magnitude tracking, and its square root;
//! - affine points ([`Affine`]) with key decompression and the curve
//!   check, which dcrec's key parsing and recovery take for decompression.
//!
//! Every fallible step returns `Option` rather than panicking, so a caller
//! on the consensus path can fall back: [`Scalar::try_inverse_var`] gives
//! `None` past the safegcd loop's iteration cap, which the proof rules
//! out, and [`Affine::decompress_var`] gives `None` when x is not below p
//! or no point has it.  The crate needs `core` alone, with no `alloc`.
//!
//! The `internals` feature, for the fuzz target only, re-exports the field
//! types and adds nothing else; no workspace crate turns it on.

#![cfg_attr(not(test), no_std)]

mod field;
mod group;
mod modinv64;
mod point;
mod scalar;

pub use point::Affine;
pub use scalar::Scalar;

#[cfg(feature = "internals")]
#[doc(hidden)]
pub use field::{Fe, FeRaw};

#[cfg(test)]
mod tests;
