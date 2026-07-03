// SPDX-License-Identifier: ISC
//! Incremental hashing must equal one-shot hashing for every chunking of the
//! same message — this exercises the buffered/full-block/remainder paths in
//! `Blake256::update` and the single-vs-double padding-block finalization.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|chunks: Vec<Vec<u8>>| {
    let mut incremental = dcroxide_crypto::blake256::Blake256::new();
    let mut whole = Vec::new();
    for chunk in &chunks {
        incremental.update(chunk);
        whole.extend_from_slice(chunk);
    }
    assert_eq!(
        incremental.finalize(),
        dcroxide_crypto::blake256::sum256(&whole)
    );
});
