// SPDX-License-Identifier: ISC
//! RPC key parsing fuzz target: `dcroxide-tlscrypto`'s port of Go's
//! `parsePrivateKey`, PKCS#1, PKCS#8 and SEC 1 under Go's `encoding/asn1`
//! rules, on arbitrary DER, never panics, and agrees with itself.
//!
//! `sign::fuzz_key_parse` runs `load_der`, which reads `rpc.key`, and
//! holds it to `key_algorithm`: a key it loads is of the type that names,
//! signs with that type's scheme, and, on the curves the provider
//! verifies, gives a signature the provider's own verifier takes; a key it
//! refuses as RSA is RSA, and any other it refuses has no type.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    dcroxide_tlscrypto::sign::fuzz_key_parse(data);
});
