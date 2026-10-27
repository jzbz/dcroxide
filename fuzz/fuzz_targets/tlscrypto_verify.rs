// SPDX-License-Identifier: ISC
//! TLS signature verification fuzz target: each of `dcroxide-tlscrypto`'s
//! fourteen verification algorithms, ECDSA, Ed25519 and the in-tree RSA,
//! on an arbitrary key, message and signature, never panics.
//!
//! A peer's certificate chain and handshake signature reach these before
//! anything else of theirs is trusted, so under `panic = "abort"` a panic
//! in a key parser, a DER reader or the RSA arithmetic would be a
//! pre-authentication abort.  The input is cut into the three by
//! `verify::fuzz_verify`, which can also put the P-256 and P-384
//! generators or Ed25519's base point in as the key, or an RSA key of
//! e = 65537 and a 2048-bit modulus taken from the input, so that
//! arbitrary signatures reach the curve and RSA arithmetic and the RSA
//! padding checks as well as the parsers.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    dcroxide_tlscrypto::verify::fuzz_verify(data);
});
