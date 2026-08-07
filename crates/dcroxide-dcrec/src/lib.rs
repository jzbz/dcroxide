// SPDX-License-Identifier: ISC
//! Decred signature types, mirroring dcrd's `dcrec` packages at the pinned
//! parity tag (`release-v2.1.5`; module `dcrec/secp256k1/v4` v4.4.0).
//!
//! Decred scripts use three signature types; this crate implements all
//! three: **type 0 (ECDSA-secp256k1)**, **type 1 (Ed25519)**, and **type 2
//! (EC-Schnorr-DCRv0)**.
//!
//! Per ADR-0006, elliptic-curve arithmetic comes from the audited
//! libsecp256k1 C library (via the `secp256k1` bindings crate); everything
//! dcrd-behavior-specific — DER signature acceptance, public key format
//! acceptance, low-S serialization, error identities — is implemented here
//! and differential-tested against dcrd's own code via `tools/oracle`.
//!
//! Like the codec crates this one is `no_std` without its default `std`
//! feature, and needs `alloc` (libsecp256k1 context creation and the DER
//! `Vec`).  `std` selects two pure-performance options — libsecp256k1's
//! process-wide context and k256's precomputed generator tables — and
//! changes no acceptance rule, error identity, or encoded byte; the vectors
//! run in both configurations.  Note that this makes the *Rust* side
//! std-free: `secp256k1-sys` still compiles the C library, so a genuinely
//! freestanding build additionally needs a cross C toolchain and a global
//! allocator.

#![cfg_attr(not(any(test, feature = "std")), no_std)]
// This crate holds no hashed containers: every map and set in it is
// ordered.  That is a property worth keeping rather than rediscovering
// -- iteration order over a consensus structure must not depend on a
// per-process hash seed.  Denied here rather than workspace-wide
// because the P2P, RPC and mixing crates legitimately hash (see
// ADR-0008); note the lint fires only on `for` loops.
#![deny(clippy::iter_over_hash_type)]

extern crate alloc;

pub mod edwards;
pub mod secp256k1;
