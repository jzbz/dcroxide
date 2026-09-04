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
//! needs an operating system to seed from and the one part that links
//! `std`, which is why it is not a default feature.

#![cfg_attr(not(test), no_std)]
// This crate holds no hashed containers: every map and set in it is
// ordered.  That is a property worth keeping rather than rediscovering
// -- iteration order over a consensus structure must not depend on a
// per-process hash seed.  Denied here rather than workspace-wide
// because the P2P, RPC and mixing crates legitimately hash (see
// ADR-0008); note the lint fires only on `for` loops.
#![deny(clippy::iter_over_hash_type)]

// The `rand` feature links `std`.  dcrd's package global is a PRNG plus
// a mutex initialised once per process (`crypto/rand/prng.go:111-122`);
// the port of it is a `OnceLock<Mutex<Prng>>`, and `core` has neither
// type.  The no_std CI job builds this crate with
// `--no-default-features`, where the feature and this `extern crate`
// are both off, so the freestanding claim that job checks is unchanged.
#[cfg(feature = "rand")]
extern crate std;

pub mod blake256;
#[cfg(feature = "rand")]
pub mod rand;
pub mod ripemd160;
