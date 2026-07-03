// SPDX-License-Identifier: ISC
//! Decred cryptographic primitives for dcroxide.
//!
//! Mirrors dcrd's `crypto/*` packages at the pinned parity tag
//! (`release-v2.1.5`). Currently provides BLAKE-256; RIPEMD-160/SHA-256
//! re-exports and the CSPRNG wrapper land with Phase 1.
//!
//! Everything here is `no_std`-compatible: these primitives are also useful
//! to embedded/hardware-wallet consumers (the vendored BLAKE-256 originates
//! from one).

#![cfg_attr(not(test), no_std)]

pub mod blake256;
