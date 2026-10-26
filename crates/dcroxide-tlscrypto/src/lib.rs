// SPDX-License-Identifier: ISC
//! The rustls crypto provider ADR-0015 moves the node's TLS to, written in
//! this tree over RustCrypto's primitives, so that no C serves or dials TLS
//! (ADR-0012).
//!
//! rustls does the protocol and leaves the cryptography to a provider:
//! the record ciphers, the key exchanges, the signing keys, the signature
//! checks and the random numbers.  The node's provider is still `ring`'s;
//! this crate is built up beside it, step by step, until it does all ring
//! does for the node, and the switch then replaces ring in one change
//! (ADR-0015, "T1").  Each part keeps ring's choices: the same suites in
//! the same order, the same limits, the same verdicts.
//!
//! So far it holds record protection: the nine cipher suites the node
//! serves and the seeders dial with, TLS 1.3's AES-128-GCM, AES-256-GCM and
//! ChaCha20-Poly1305 and TLS 1.2's ECDHE-ECDSA and ECDHE-RSA with each of
//! the three, on `aes-gcm` and `chacha20poly1305`, with their transcript
//! hashes, HKDF and PRF on `sha2` and `hmac`.  The suites are items of
//! their own under the names of rustls's ring provider
//! (`rustls-0.23.46/src/crypto/ring/mod.rs:65-103`), so the node can build
//! both of Go's suite orders from them as it does from ring's.  Key
//! exchange, signing, verification and randomness are still ring's, and a
//! suite from here runs beside them in any `CryptoProvider` that lists it.
//!
//! Every function a peer's record reaches computes on lengths with
//! `checked_*` and fails the record, not the process, when a length is
//! wrong, since the release build aborts on a panic and wraps on overflow.

mod aead;
mod hash;
mod hmac;
mod tls12;
mod tls13;
#[cfg(test)]
mod wycheproof_tests;

use rustls::SupportedCipherSuite;

/// The cipher suites to offer by default: every suite, as ring's provider
/// does (`rustls-0.23.46/src/crypto/ring/mod.rs:65-69`).
pub static DEFAULT_CIPHER_SUITES: &[SupportedCipherSuite] = ALL_CIPHER_SUITES;

/// Every cipher suite this crate implements, in ring's order
/// (`rustls-0.23.46/src/crypto/ring/mod.rs:71-90`): TLS 1.3's first, each
/// version's with AES-256-GCM ahead of AES-128-GCM and ChaCha20-Poly1305
/// last, and TLS 1.2's ECDSA suites ahead of its RSA ones.
pub static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    cipher_suite::TLS13_AES_256_GCM_SHA384,
    cipher_suite::TLS13_AES_128_GCM_SHA256,
    cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

/// The nine cipher suites, each on its own, under the names of rustls's
/// ring provider (`rustls-0.23.46/src/crypto/ring/mod.rs:92-103`).
pub mod cipher_suite {
    pub use crate::tls12::{
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };
    pub use crate::tls13::{
        TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
    };
}
