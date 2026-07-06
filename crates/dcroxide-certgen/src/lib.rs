// SPDX-License-Identifier: ISC
//! An implementation of dcrd's `certgen` package: self-signed TLS
//! certificate pair generation for the RPC server, reproducing Go's
//! `x509.CreateCertificate` output byte for byte for the certificate
//! shapes dcrd builds.
//!
//! dcrd draws on the wall clock, `crypto/rand`, the OS hostname, and
//! the interface addresses; those inputs come through the injectable
//! [`CertEnv`] so the daemon supplies the real sources and tests
//! script them.  Ed25519 signatures are deterministic, so those
//! certificates pin byte for byte; ECDSA signatures are randomized in
//! Go, so the to-be-signed bytes pin exactly and the signature is
//! verified instead (QK-0007 documents that the Ed25519 variant lacks
//! the ECDSA variant's IDNA handling and fails on non-ASCII
//! hostnames).

mod certgen;
mod der;
mod pem;
mod x509;

pub use certgen::{CertEnv, CertPair, Curve, new_ed25519_tls_cert_pair, new_tls_cert_pair};

#[doc(hidden)]
pub use certgen::{CertParts, new_ed25519_tls_cert_pair_parts, new_tls_cert_pair_parts};
