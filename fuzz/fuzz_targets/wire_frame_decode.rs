// SPDX-License-Identifier: ISC
//! Message frame decoder fuzz target: never panics, and any accepted frame
//! re-encodes to a form that decodes back to the same message.
//!
//! Note what is *not* asserted: that the re-encoding equals the consumed
//! prefix.  That is false for dcrd, and therefore for this port.
//! `MsgVersion::decode` treats its trailing fields as optional and stops
//! when the payload runs out, while `encode` always writes all of them, so
//! a short but perfectly valid `version` frame re-encodes longer than it
//! arrived.  An earlier revision asserted the strict form and passed only
//! because libFuzzer cannot forge the BLAKE-256 checksum that would let a
//! `version` frame through — it would have fired on the first real seed or
//! structured input, on a non-bug.
//!
//! The invariant that does hold is canonical-form stability: whatever the
//! encoder produces must decode back to an equal message, consuming
//! exactly what it wrote.  That still catches encoder/decoder
//! disagreement, which is the bug class worth guarding here.

#![no_main]

use libfuzzer_sys::fuzz_target;

use dcroxide_wire::{CurrencyNet, PROTOCOL_VERSION, read_message, write_message};

fuzz_target!(|data: &[u8]| {
    if let Ok((msg, _consumed)) = read_message(data, PROTOCOL_VERSION, CurrencyNet::MAIN_NET) {
        // A decoded message need not be encodable -- see QK-0010.  When it
        // is not, dcrd refuses the same message, so there is nothing to
        // compare and nothing wrong.
        let Ok(reencoded) = write_message(&msg, PROTOCOL_VERSION, CurrencyNet::MAIN_NET) else {
            return;
        };
        let (roundtripped, consumed_again) =
            read_message(&reencoded, PROTOCOL_VERSION, CurrencyNet::MAIN_NET)
                .expect("re-encoded message decodes");
        assert_eq!(roundtripped, msg, "re-encoding changed the message");
        assert_eq!(
            consumed_again,
            reencoded.len(),
            "re-encoded frame has trailing bytes"
        );
    }
});
