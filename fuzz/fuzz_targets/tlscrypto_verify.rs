// SPDX-License-Identifier: ISC
//! TLS signature verification fuzz target: each of `dcroxide-tlscrypto`'s
//! seventeen verification algorithms, ECDSA, Ed25519, the in-tree RSA and
//! ML-DSA-44, -65 and -87 on the `ml-dsa` crate, on an arbitrary key,
//! message and signature, never panics.
//!
//! A peer's certificate chain and handshake signature reach ring's
//! fourteen of these before anything else of theirs is trusted, and the
//! ML-DSA three once the RPC listener verifies ML-DSA client
//! certificates, so under `panic = "abort"` a panic in a key parser, a
//! DER reader, a signature decoder or the arithmetic would be a
//! pre-authentication abort.  The input is cut into the three by
//! `verify::fuzz_verify`, which can also put the P-256 and P-384
//! generators or Ed25519's base point in as the key, or an RSA key of
//! e = 65537 and a 2048-bit modulus taken from the input, so that
//! arbitrary signatures reach the curve and RSA arithmetic and the RSA
//! padding checks as well as the parsers; or an ML-DSA key of each set,
//! with the input laid over a signature of the set's length that decodes,
//! so that every input is decoded whole, its hints and z checked, and one
//! that passes them reaches the lattice arithmetic.  Under libFuzzer's
//! default input limit of 4096 bytes an ML-DSA-87 signature's hints are
//! always the template's empty ones; the other two sets' are fuzzed.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    dcroxide_tlscrypto::verify::fuzz_verify(data);
});
