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
//! It holds all of that now.  Record protection is the nine cipher suites
//! the node serves and the seeders dial with, TLS 1.3's AES-128-GCM,
//! AES-256-GCM and ChaCha20-Poly1305 and TLS 1.2's ECDHE-ECDSA and
//! ECDHE-RSA with each of the three, on `aes-gcm` and `chacha20poly1305`,
//! with their transcript hashes, HKDF and PRF on `sha2` and `hmac`.  Key
//! exchange is ring's three groups, X25519, P-256 and P-384, and P-521,
//! which ring lacks and Go's server offers, on `curve25519-dalek` and the
//! `p256`, `p384` and `p521` crates, each with Go's rules for the peer's
//! share and its ephemeral key drawn from the kernel (`kx`, `rand`).  The
//! suites and groups are items of their own under the names of rustls's
//! ring provider (`rustls-0.23.46/src/crypto/ring/mod.rs:65-103`,
//! `:172-181`), so the node can build both of Go's suite orders from them,
//! and its per-group configurations, as it does from ring's.  The signing
//! keys are ECDSA on the three NIST curves, hedged RFC 6979 on the curve
//! crates, and Ed25519 on `curve25519-dalek`, read from an `rpc.key` by
//! Go's `tls.X509KeyPair` rules and refusing RSA keys ([`sign`]).  The
//! verification algorithms are ring's fourteen under `webpki::ring`'s
//! names ([`verify`]): ECDSA and Ed25519 on the same crates, and RSA
//! PKCS#1 v1.5 and PSS written here on `num-bigint` (ADR-0015 T5), each
//! within ring's limits and returning ring's verdicts, listed with ring's
//! mapping to TLS signature schemes in [`SUPPORTED_SIG_ALGS`].
//! [`default_provider`] puts them together with the kernel's random
//! numbers.
//!
//! The node takes P-521 from here already, its key exchange and its
//! signing key, both of which ring lacks; the rest is still ring's until
//! the switch replaces ring's provider with [`default_provider`], and an
//! item from here runs beside ring's in any `CryptoProvider` that lists
//! it.
//!
//! Every function a peer's record, key share, key or signature reaches
//! computes on lengths with `checked_*` or compares them first, and fails
//! the record or the handshake, not the process, when a length is wrong,
//! since the release build aborts on a panic and wraps on overflow.

mod aead;
mod der;
mod hash;
mod hmac;
mod keys;
mod kx;
mod rand;
mod rsa;
pub mod sign;
mod tls12;
mod tls13;
pub mod verify;
#[cfg(test)]
mod wycheproof_tests;

use rustls::crypto::{CryptoProvider, SupportedKxGroup, WebPkiSupportedAlgorithms};
use rustls::{SignatureScheme, SupportedCipherSuite};

/// The provider: ring's default suite and group lists and ring's
/// verification set, this crate's own throughout, with the kernel's
/// random numbers and Go's key loading.  A client built on it offers what
/// one built on ring's offers: the same suites in the same order, X25519,
/// P-256 and P-384, and the same signature schemes
/// (`rustls-0.23.46/src/crypto/ring/mod.rs:32-40`).
pub fn default_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: DEFAULT_CIPHER_SUITES.to_vec(),
        kx_groups: DEFAULT_KX_GROUPS.to_vec(),
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: &rand::KernelRandom,
        key_provider: sign::KEY_PROVIDER,
    }
}

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

/// The key exchange groups to offer by default: ring's, X25519, P-256 and
/// P-384, in ring's order (`rustls-0.23.46/src/crypto/ring/mod.rs:176-181`),
/// so a client built on this provider offers the groups a client built on
/// ring's does.
pub static DEFAULT_KX_GROUPS: &[&dyn SupportedKxGroup] =
    &[kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1];

/// Every key exchange group this crate implements, in the order of Go's
/// default preferences (`crypto/tls/defaults.go:29-32`) less the
/// post-quantum hybrids ahead of them: X25519, P-256, P-384, P-521.
pub static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    kx_group::X25519,
    kx_group::SECP256R1,
    kx_group::SECP384R1,
    kx_group::SECP521R1,
];

/// The four key exchange groups, each on its own, under the names of
/// rustls's ring provider (`rustls-0.23.46/src/crypto/ring/mod.rs:172-174`)
/// and, for P-521, which ring lacks, the name it would take there.
pub mod kx_group {
    pub use crate::kx::{SECP256R1, SECP384R1, SECP521R1, X25519};
}

/// The signature verification algorithms and their mapping to TLS
/// signature schemes: ring's, entry for entry and in ring's order
/// (`rustls-0.23.46/src/crypto/ring/mod.rs:105-166`).  rustls offers the
/// mapping's schemes in its order, in a ClientHello and a
/// CertificateRequest, and TLS 1.3 tries only the first algorithm of a
/// scheme (`rustls-0.23.46/src/webpki/verify.rs:68-92`, `:202`).  Neither
/// list has P-521 or SHA-512 ECDSA, which ring lacks; Go verifies both, as
/// PARITY.md records, and they come with Go's client-certificate set
/// (ADR-0015, T4).
pub static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        verify::ECDSA_P256_SHA256,
        verify::ECDSA_P256_SHA384,
        verify::ECDSA_P384_SHA256,
        verify::ECDSA_P384_SHA384,
        verify::ED25519,
        verify::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        verify::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        verify::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        verify::RSA_PKCS1_2048_8192_SHA256,
        verify::RSA_PKCS1_2048_8192_SHA384,
        verify::RSA_PKCS1_2048_8192_SHA512,
        verify::RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
        verify::RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
        verify::RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
    ],
    mapping: &[
        // In TLS 1.2 an ECDSA scheme names a hash and not a curve, so each
        // takes either curve's key; in TLS 1.3 it names both, and the
        // first algorithm is the one tried.
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[verify::ECDSA_P384_SHA384, verify::ECDSA_P256_SHA384],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[verify::ECDSA_P256_SHA256, verify::ECDSA_P384_SHA256],
        ),
        (SignatureScheme::ED25519, &[verify::ED25519]),
        (
            SignatureScheme::RSA_PSS_SHA512,
            &[verify::RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA384,
            &[verify::RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA256,
            &[verify::RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            &[verify::RSA_PKCS1_2048_8192_SHA512],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            &[verify::RSA_PKCS1_2048_8192_SHA384],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[verify::RSA_PKCS1_2048_8192_SHA256],
        ),
    ],
};
