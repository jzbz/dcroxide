// SPDX-License-Identifier: ISC
//! RIPEMD-160, mirroring dcrd's `crypto/ripemd160` package surface.
//!
//! Backed by the RustCrypto `ripemd` crate per the no-hand-rolled-crypto
//! rule (ADR-0006 rationale); dcrd's package is itself the old Go x/crypto
//! implementation. Only the one-shot digest the script engine and address
//! hashing need is exposed.

use ripemd::{Digest, Ripemd160};

/// The RIPEMD-160 digest size in bytes (dcrd `ripemd160.Size`).
pub const SIZE: usize = 20;

/// One-shot RIPEMD-160 digest of `data`.
pub fn sum160(data: &[u8]) -> [u8; SIZE] {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::sum160;

    /// Standard RIPEMD-160 test vectors from the original Bosselaers
    /// reference (same vectors dcrd's package inherited from x/crypto).
    #[test]
    fn reference_vectors() {
        let vectors: &[(&str, &str)] = &[
            ("", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
            ("a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
            ("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
            ("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
            ),
        ];
        for (input, want) in vectors {
            let got = sum160(input.as_bytes());
            let got_hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(&got_hex, want, "input {input:?}");
        }
    }
}
