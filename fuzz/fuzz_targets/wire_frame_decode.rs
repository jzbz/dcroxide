// SPDX-License-Identifier: ISC
//! Message frame decoder fuzz target: never panics, and any accepted frame
//! re-encodes byte-identically to the consumed prefix.

#![no_main]

use libfuzzer_sys::fuzz_target;

use dcroxide_wire::{CurrencyNet, PROTOCOL_VERSION, read_message, write_message};

fuzz_target!(|data: &[u8]| {
    if let Ok((msg, consumed)) =
        read_message(data, PROTOCOL_VERSION, CurrencyNet::MAIN_NET)
    {
        let reencoded = write_message(&msg, PROTOCOL_VERSION, CurrencyNet::MAIN_NET)
            .expect("decoded message re-encodes");
        assert_eq!(reencoded.as_slice(), &data[..consumed]);
    }
});
