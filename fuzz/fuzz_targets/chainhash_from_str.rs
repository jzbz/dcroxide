// SPDX-License-Identifier: ISC
//! Hash-string parser fuzz target: never panics, and every accepted string
//! survives a display/parse round trip (short inputs decode to the same hash
//! as their zero-padded display form — the dcrd quirk).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = core::str::from_utf8(data) else {
        return;
    };
    if let Ok(hash) = s.parse::<dcroxide_chainhash::Hash>() {
        let round_tripped: dcroxide_chainhash::Hash =
            hash.to_string().parse().expect("display always parses");
        assert_eq!(round_tripped, hash);
    }
});
