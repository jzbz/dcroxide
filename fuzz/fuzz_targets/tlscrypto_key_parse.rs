// SPDX-License-Identifier: ISC
//! RPC key parsing fuzz target: `dcroxide-tlscrypto`'s port of Go's
//! `parsePrivateKey`, PKCS#1, PKCS#8 and SEC 1 under Go's `encoding/asn1`
//! rules, on arbitrary DER, never panics, and agrees with itself.
//!
//! `sign::fuzz_key_parse` runs `load_der`, which reads `rpc.key`, and
//! holds it to `key_algorithm`: a key it loads is of the type that names,
//! signs with that type's scheme, and, for the types the provider
//! verifies, ML-DSA's three among them, gives a signature the provider's
//! own verifier takes; a key it refuses as RSA is RSA, and any other it
//! refuses has no type and is refused with Go's "tls: failed to parse
//! private key: " and a cause of one line, or with one of the fixed texts
//! for the keys Go reads and the provider does not sign with.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    dcroxide_tlscrypto::sign::fuzz_key_parse(data);
});
