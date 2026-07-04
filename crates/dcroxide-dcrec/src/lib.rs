// SPDX-License-Identifier: ISC
//! Decred signature types, mirroring dcrd's `dcrec` packages at the pinned
//! parity tag (`release-v2.1.5`; module `dcrec/secp256k1/v4` v4.4.0).
//!
//! Decred scripts use three signature types; this crate currently implements
//! **type 0 (ECDSA-secp256k1)** and **type 2 (EC-Schnorr-DCRv0)**. Ed25519
//! (type 1) lands later in Phase 1.
//!
//! Per ADR-0006, elliptic-curve arithmetic comes from the audited
//! libsecp256k1 C library (via the `secp256k1` bindings crate); everything
//! dcrd-behavior-specific — DER signature acceptance, public key format
//! acceptance, low-S serialization, error identities — is implemented here
//! and differential-tested against dcrd's own code via `tools/oracle`.
//!
//! Unlike the codec crates this one is not `no_std`: the C bindings require
//! std (embedded consumers should use dcr-rs, where this crate's vendored
//! primitives originate).

pub mod secp256k1;
