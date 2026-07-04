// SPDX-License-Identifier: ISC
//! Decred cryptographic primitives for dcroxide.
//!
//! Mirrors dcrd's `crypto/*` packages at the pinned parity tag
//! (`release-v2.1.5`). Provides BLAKE-256 (vendored) and RIPEMD-160
//! (RustCrypto-backed, mirroring dcrd's `crypto/ripemd160`); the CSPRNG
//! wrapper lands later in Phase 1.
//!
//! Everything here is `no_std`-compatible: these primitives are also useful
//! to embedded/hardware-wallet consumers (the vendored BLAKE-256 originates
//! from one).

#![cfg_attr(not(test), no_std)]

pub mod blake256;
pub mod ripemd160;
