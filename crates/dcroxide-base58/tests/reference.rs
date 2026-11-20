// SPDX-License-Identifier: ISC
//! Property tests: the limb-based conversion against the per-digit
//! algorithm it replaced (`tests/per_digit/mod.rs`, a port of decred/base58
//! v1.0.6), over valid and invalid strings and arbitrary bytes, every
//! output compared whole.  The batch differential in
//! `tests/oracle_differential.rs` holds the same functions to Go itself.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

mod inputs;
mod per_digit;

use dcroxide_base58::{check_decode, check_encode, decode, encode};
use dcroxide_testutil::{SplitMix64, hex};

/// `decode` and `check_decode` equal the reference on every structured
/// string and 100,000 random ones, and `encode` of each decoding equals
/// the reference's (and gives the string back when it decoded).
#[test]
fn decode_matches_the_reference() {
    let mut rng = SplitMix64::from_entropy("base58 decode against the reference");
    let mut strings = inputs::structured(&mut rng, 8);
    for _ in 0..100_000 {
        strings.push(inputs::random(&mut rng));
    }
    let mut decoded_nonempty = 0usize;
    for s in &strings {
        let ours = decode(s);
        assert_eq!(ours, per_digit::decode(s), "decode {s:?}");
        assert_eq!(
            check_decode(s),
            per_digit::check_decode(s),
            "check_decode {s:?}"
        );
        let encoded = encode(&ours);
        assert_eq!(encoded, per_digit::encode(&ours), "encode {}", hex(&ours));
        if !ours.is_empty() {
            decoded_nonempty += 1;
            assert_eq!(&encoded, s, "round trip");
        }
    }
    // About two strings in five above are valid; a generator that stopped
    // producing them would pass vacuously.
    assert!(
        decoded_nonempty > strings.len() / 4,
        "{decoded_nonempty} of {} decoded",
        strings.len()
    );
}

/// `encode` and `check_encode` equal the reference on arbitrary bytes:
/// every length from 0 to 300 with leading zeros and without, lengths
/// around the encoder's stack array (233 bytes after the leading zeros),
/// all-zero and all-0xff inputs, and long inputs; and `decode` and
/// `check_decode` give the input back.
#[test]
fn encode_matches_the_reference() {
    let mut rng = SplitMix64::from_entropy("base58 encode against the reference");
    let mut cases: Vec<Vec<u8>> = Vec::new();
    for len in 0..=300 {
        for _ in 0..16 {
            let mut b = vec![0u8; len];
            rng.fill(&mut b);
            cases.push(b);
        }
        let mut b = vec![0u8; len];
        rng.fill(&mut b);
        let zeros = (rng.below(8) as usize).min(len);
        b[..zeros].fill(0);
        cases.push(b);
        cases.push(vec![0u8; len]);
        cases.push(vec![0xff; len]);
    }
    for len in 228..=240 {
        for zeros in [0, 1, 5] {
            let mut b = vec![0xffu8; zeros + len];
            b[..zeros].fill(0);
            cases.push(b);
            let mut b = vec![0u8; zeros + len];
            rng.fill(&mut b[zeros..]);
            b[zeros] |= 1;
            cases.push(b);
        }
    }
    for len in [301, 512, 733, 1000, 1500] {
        let mut b = vec![0u8; len];
        rng.fill(&mut b);
        cases.push(b);
        cases.push(vec![0xff; len]);
    }
    for b in &cases {
        let ours = encode(b);
        assert_eq!(ours, per_digit::encode(b), "encode {}", hex(b));
        assert_eq!(decode(&ours), *b, "decode back {ours}");

        let version = [rng.next_u64() as u8, rng.next_u64() as u8];
        let checked = check_encode(b, version);
        assert_eq!(
            checked,
            per_digit::check_encode(b, version),
            "check_encode {}",
            hex(b)
        );
        assert_eq!(check_decode(&checked), Ok((b.clone(), version)));
    }
}

/// The largest value of every length, which is where an undersized limb
/// array would show: 'z' repeated, from 0 to 1,200 characters and at six
/// longer lengths (four of them multiples of 512, where the decoder's
/// scratch is a limb larger than Go's `out32` rounded up to eight bytes),
/// decodes without panicking, to the reference's bytes at every length to
/// 400 and the longer ones, and the bytes encode back; 0xff repeated does
/// the same through `encode`.
#[test]
fn the_largest_values_fit() {
    for len in (0..=1200).chain([1536, 2047, 2048, 4096, 4608, 6000]) {
        let s = "z".repeat(len);
        let ours = decode(&s);
        if len <= 400 || len > 1200 {
            assert_eq!(ours, per_digit::decode(&s), "decode {len} z");
        }
        assert_eq!(encode(&ours), s, "{len} z back");

        let b = vec![0xffu8; len];
        let ours = encode(&b);
        if len <= 400 || len > 1200 {
            assert_eq!(ours, per_digit::encode(&b), "encode {len} 0xff");
        }
        assert_eq!(decode(&ours), b, "{len} 0xff back");
    }
}

/// The edge cases decred/base58 documents by behavior: empty input, only
/// '1's, only zero bytes, and an invalid character after valid ones
/// decoding to nothing, each the reference's answer too.
#[test]
fn edges_match_the_reference() {
    for s in [
        "",
        "1",
        "11",
        "1111111111",
        "z",
        "1z",
        "11z1",
        "1O",
        "z0",
        "\u{e9}",
    ] {
        assert_eq!(decode(s), per_digit::decode(s), "decode {s:?}");
        assert_eq!(check_decode(s), per_digit::check_decode(s), "{s:?}");
    }
    assert!(decode("").is_empty());
    assert_eq!(decode("111"), [0, 0, 0]);
    assert!(decode("111O").is_empty());
    assert_eq!(encode(&[]), "");
    assert_eq!(encode(&[0, 0, 0]), "111");
    assert_eq!(encode(&[0, 0, 0, 1]), "1112");
}
