// SPDX-License-Identifier: ISC
//! Variable-time secp256k1 arithmetic for **public data only**: every
//! function here may take time that depends on its inputs, and nothing in
//! this crate takes a private key, a nonce or a zeroizing type.  Keys made
//! from secrets, signing and the nonce stay on `k256`, in constant time.
//!
//! The arithmetic is a port of libsecp256k1's portable C (see `NOTICE`),
//! owned in tree as ADR-0016 records, for `dcroxide-dcrec`'s ECDSA
//! verification, compact recovery, EC-Schnorr-DCRv0 verification and key
//! decompression.  It lands in increments.  Today it holds the integers
//! mod the group order N ([`Scalar`], libsecp256k1's 4x64 form) and their
//! inverse by safegcd (`modinv64`), which dcrec's verification and
//! recovery take for s^-1 and r^-1.
//!
//! Every fallible step returns `Option` rather than panicking, so a caller
//! on the consensus path can fall back: [`Scalar::try_inverse_var`] gives
//! `None` past the safegcd loop's iteration cap, which the proof rules
//! out.  The crate needs `core` alone, with no `alloc`.

#![cfg_attr(not(test), no_std)]

mod modinv64;
mod scalar;

pub use scalar::Scalar;

#[cfg(test)]
mod tests;
