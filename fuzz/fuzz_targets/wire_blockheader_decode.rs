// SPDX-License-Identifier: ISC
//! Block header decoder fuzz target: never panics; accepted input re-encodes
//! byte-identically.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((header, consumed)) = dcroxide_wire::BlockHeader::from_bytes(data) {
        assert_eq!(consumed, 180);
        assert_eq!(&header.serialize()[..], &data[..consumed]);
        let _ = header.block_hash();
    }
});
