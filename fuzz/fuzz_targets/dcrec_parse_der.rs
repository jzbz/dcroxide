// SPDX-License-Identifier: ISC
//! DER signature parser fuzz target: never panics, and any accepted
//! signature survives a serialize/reparse cycle with serialization
//! idempotent (low-S normalization applies exactly once).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(sig) = dcroxide_dcrec::secp256k1::ecdsa::parse_der_signature(data) {
        let der = sig.serialize();
        let reparsed = dcroxide_dcrec::secp256k1::ecdsa::parse_der_signature(&der)
            .expect("own serialization must parse");
        assert_eq!(reparsed.serialize(), der, "serialization is idempotent");
        assert_eq!(reparsed.r_bytes(), sig.r_bytes(), "R survives round trip");
    }
});
