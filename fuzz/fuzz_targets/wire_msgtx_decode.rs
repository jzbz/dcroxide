// SPDX-License-Identifier: ISC
//! Transaction decoder fuzz target: must never panic, and any accepted input
//! must re-encode byte-identically to its consumed prefix (canonical-encoding
//! law). Hash computation is exercised on every accepted transaction.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((tx, consumed)) = dcroxide_wire::MsgTx::from_bytes(data) {
        assert_eq!(tx.serialize().as_slice(), &data[..consumed]);
        assert_eq!(tx.serialize_size(), consumed);
        let _ = tx.tx_hash_full();
    }
});
