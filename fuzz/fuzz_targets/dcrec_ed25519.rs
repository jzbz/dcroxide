// SPDX-License-Identifier: ISC
//! Ed25519 fuzz target: parsers never panic; accepted signatures/keys
//! round-trip; signing over arbitrary seed/message material always produces
//! a verifying, reparseable signature.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = dcroxide_dcrec::edwards::parse_signature(data);
    if let Ok(pk) = dcroxide_dcrec::edwards::parse_pub_key(data.get(..32).unwrap_or(data)) {
        // Canonical re-encoding is a parse fixed point.
        let reparsed = dcroxide_dcrec::edwards::parse_pub_key(&pk.serialize())
            .expect("canonical form parses");
        assert_eq!(reparsed.serialize(), pk.serialize());
    }

    if data.len() >= 32 {
        let seed: [u8; 32] = data[..32].try_into().expect("32 bytes");
        let msg = &data[32..];
        let secret = dcroxide_dcrec::edwards::SecretKey::from_seed(seed);
        let sig = dcroxide_dcrec::edwards::sign(&secret, msg);
        assert!(sig.verify(msg, &secret.public_key()), "own signature verifies");
        let reparsed = dcroxide_dcrec::edwards::parse_signature(&sig.serialize())
            .expect("own serialization parses");
        assert_eq!(reparsed, sig);
    }
});
