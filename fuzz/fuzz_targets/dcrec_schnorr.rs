// SPDX-License-Identifier: ISC
//! EC-Schnorr-DCRv0 fuzz target: for arbitrary key/hash material, signing
//! must never panic, every produced signature must verify and round-trip
//! through parse/serialize, and the parser itself must never panic on
//! arbitrary bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Arbitrary bytes exercise the parser directly.
    let _ = dcroxide_dcrec::secp256k1::schnorr::parse_signature(data);

    // With 64+ bytes, treat the input as key || hash and exercise the full
    // sign/verify/round-trip cycle.
    if data.len() >= 64 {
        let key_bytes: [u8; 32] = data[..32].try_into().expect("32 bytes");
        let hash: [u8; 32] = data[32..64].try_into().expect("32 bytes");
        let Some(key) = dcroxide_dcrec::secp256k1::PrivateKey::from_bytes(&key_bytes) else {
            return;
        };
        let sig = dcroxide_dcrec::secp256k1::schnorr::sign(&key, &hash).expect("32-byte hash");
        assert!(sig.verify(&hash, &key.public_key()), "own signature verifies");
        let reparsed = dcroxide_dcrec::secp256k1::schnorr::parse_signature(&sig.serialize())
            .expect("own serialization parses");
        assert_eq!(reparsed, sig, "round trip");
    }
});
