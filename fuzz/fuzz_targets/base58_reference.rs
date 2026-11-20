// SPDX-License-Identifier: ISC
//! Base58 fuzz target: dcroxide-base58's limb-based conversion against the
//! per-digit algorithm it replaced, a port of decred/base58 v1.0.6 kept as
//! a test-only reference in the crate's tests and included here from
//! there, so both read one copy.  No oracle: the batch differential in
//! `crates/dcroxide-base58/tests/oracle_differential.rs` holds the
//! reference's answers to Go's.
//!
//! The input, read as text when it is UTF-8, goes to `decode` and
//! `check_decode`; read as bytes, to `encode` and, under the first two
//! bytes as the version, `check_encode`.  Every output must equal the
//! reference's, and whatever decodes must encode back to the text.

#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../crates/dcroxide-base58/tests/per_digit/mod.rs"]
mod per_digit;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let decoded = dcroxide_base58::decode(text);
        assert_eq!(decoded, per_digit::decode(text), "decode");
        if !decoded.is_empty() {
            assert_eq!(dcroxide_base58::encode(&decoded), text, "round trip");
        }
        assert_eq!(
            dcroxide_base58::check_decode(text),
            per_digit::check_decode(text),
            "check_decode"
        );
    }

    assert_eq!(
        dcroxide_base58::encode(data),
        per_digit::encode(data),
        "encode"
    );
    if let [v0, v1, payload @ ..] = data {
        assert_eq!(
            dcroxide_base58::check_encode(payload, [*v0, *v1]),
            per_digit::check_encode(payload, [*v0, *v1]),
            "check_encode"
        );
    }
});
