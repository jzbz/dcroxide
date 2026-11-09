// SPDX-License-Identifier: ISC
//! Decred signature types, mirroring dcrd's `dcrec` packages as the parity
//! pin, dcrd master 3360ae4d, links them: `dcrec/secp256k1/v4` is dcrd's
//! in-tree source, which its `go.mod` substitutes for the published module
//! (the oracle pins it as v4.4.2-0.20261019113547-3360ae4dbef8), and
//! `dcrec/edwards/v2` is the v2.0.4 release dcrd requires.
//!
//! Decred scripts use three signature types; this crate implements all
//! three: **type 0 (ECDSA-secp256k1)**, **type 1 (Ed25519)**, and **type 2
//! (EC-Schnorr-DCRv0)**.
//!
//! Per ADR-0006's 2026-10-26 addendum and ADR-0012, ECDSA,
//! EC-Schnorr-DCRv0 and every secp256k1 key run on `k256`'s field, scalar
//! and point arithmetic, and Ed25519 on `curve25519-dalek`'s.  ECDSA
//! verification's scalars, its a*G + b*P and its x check, recovery's
//! scalar inverse, and the decompression of compressed keys and of
//! recovery's R run on `dcroxide-secp256k1-vartime`, variable-time
//! arithmetic on public values owned in tree and ported from
//! libsecp256k1, behind one seam module with k256 as its fallback
//! (ADR-0016).  The variable-time a*G + b*P of recovery and Schnorr
//! verification is still this crate's own loop over k256's public point
//! operations, with static tables of the generator built on first use
//! (ADR-0006's 2026-11-08 addendum).
//! Everything dcrd-behavior-specific — DER signature acceptance, public
//! key format acceptance, low-S serialization, the order of compact
//! recovery's checks, error identities — is implemented here and
//! differential-tested against dcrd's own code via `tools/oracle`.
//!
//! Like the codec crates this one is `no_std` outside its own tests, and
//! needs `alloc` (the DER `Vec` and the static generator tables).  It has
//! no features, and it compiles no C: every dependency it builds is Rust.

#![cfg_attr(not(test), no_std)]
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
