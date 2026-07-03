// SPDX-License-Identifier: ISC
//! Public key parser fuzz target: never panics, and any accepted key
//! round-trips through both serializations.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(pk) = dcroxide_dcrec::secp256k1::PublicKey::parse(data) {
        let compressed = pk.serialize_compressed();
        let uncompressed = pk.serialize_uncompressed();
        let from_compressed = dcroxide_dcrec::secp256k1::PublicKey::parse(&compressed)
            .expect("compressed serialization parses");
        let from_uncompressed = dcroxide_dcrec::secp256k1::PublicKey::parse(&uncompressed)
            .expect("uncompressed serialization parses");
        assert_eq!(from_compressed, pk);
        assert_eq!(from_uncompressed, pk);
    }
});
