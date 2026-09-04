// SPDX-License-Identifier: ISC
//! Decred cryptographic primitives for dcroxide.
//!
//! Mirrors dcrd's `crypto/*` packages at the pinned parity tag
//! Provides BLAKE-256 (vendored), RIPEMD-160 (RustCrypto-backed,
//! mirroring dcrd's `crypto/ripemd160`), and -- behind the `rand`
//! feature -- dcrd's `crypto/rand` userspace CSPRNG.
//!
//! Everything outside the `rand` feature is `no_std`-compatible: these
//! primitives are also useful to embedded/hardware-wallet consumers (the
//! vendored BLAKE-256 originates from one).  `rand` is the one part that
//! needs an operating system to seed from, which is why it is not a
//! default feature.

#![cfg_attr(not(test), no_std)]
// This crate holds no hashed containers: every map and set in it is
// ordered.  That is a property worth keeping rather than rediscovering
// -- iteration order over a consensus structure must not depend on a
// per-process hash seed.  Denied here rather than workspace-wide
// because the P2P, RPC and mixing crates legitimately hash (see
// ADR-0008); note the lint fires only on `for` loops.
#![deny(clippy::iter_over_hash_type)]

pub mod blake256;
#[cfg(feature = "rand")]
pub mod rand;
pub mod ripemd160;
