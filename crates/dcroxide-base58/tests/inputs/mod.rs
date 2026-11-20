// SPDX-License-Identifier: ISC
//! Strings for the decoder's tests, valid and invalid: shared by the
//! property tests against the reference (`tests/reference.rs`) and the
//! batch differential against Go (`tests/oracle_differential.rs`).

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects, dead_code)]

use dcroxide_base58::{ALPHABET, check_encode};
use dcroxide_testutil::SplitMix64;

/// Characters outside the alphabet, each inserted at every position of
/// strings of every length up to 120: the four lookalikes the alphabet
/// leaves out, ASCII punctuation, space, NUL and DEL, the byte after
/// 'z', and multi-byte UTF-8 (a two-byte letter and a three-byte
/// full-width zero), whose every byte is above 0x7f.
pub const INVALID: &[&str] = &[
    "0", "O", "I", "l", "+", "/", " ", "\0", "\u{7f}", "{", "\u{e9}", "\u{ff10}",
];

/// The longest string of the families that cover every length.
pub const MAX_LEN: usize = 120;

/// A random string of `len` base58 characters.
pub fn digits(rng: &mut SplitMix64, len: usize) -> String {
    (0..len)
        .map(|_| char::from(ALPHABET[rng.below(58) as usize]))
        .collect()
}

/// A random string of `len` base58 characters whose first is not '1', so
/// it has no leading zero bytes.
pub fn digits_no_lead(rng: &mut SplitMix64, len: usize) -> String {
    (0..len)
        .map(|i| {
            let d = if i == 0 {
                1 + rng.below(57)
            } else {
                rng.below(58)
            };
            char::from(ALPHABET[d as usize])
        })
        .collect()
}

/// A random payload of up to `max` bytes, its first bytes zero a quarter
/// of the time.
pub fn payload(rng: &mut SplitMix64, max: usize) -> Vec<u8> {
    let mut p = rng.bytes(max);
    if rng.below(4) == 0 {
        let zeros = rng.below(6) as usize;
        for b in p.iter_mut().take(zeros) {
            *b = 0;
        }
    }
    p
}

/// `s` with the character at `pos` replaced by a different base58
/// character.
pub fn change_one(rng: &mut SplitMix64, s: &str, pos: usize) -> String {
    let mut b = s.as_bytes().to_vec();
    let mut c = ALPHABET[rng.below(58) as usize];
    while c == b[pos] {
        c = ALPHABET[rng.below(58) as usize];
    }
    b[pos] = c;
    String::from_utf8(b).expect("ascii")
}

/// The structured families, in order:
///
/// - every length from 0 to 120, `per_len` random strings each;
/// - strings of only '1', every length from 0 to 300;
/// - one to 20 '1's before random digits;
/// - the largest value of every length from 0 to 300 ('z' repeated), and
///   one to eight '1's before it;
/// - for every length from 1 to 120, one invalid character at each
///   position, every character of [`INVALID`] in turn;
/// - random bytes of every length from 0 to 120 read as UTF-8 (invalid
///   sequences become U+FFFD), and random printable ASCII;
/// - check-encoded payloads of up to 100 bytes under random versions,
///   with each one also with one character changed and with its last
///   character dropped;
/// - lengths around the decoder's stack array (255 to 266 digits after
///   the leading '1's), and longer strings up to 1,200 characters.
pub fn structured(rng: &mut SplitMix64, per_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    for len in 0..=MAX_LEN {
        for _ in 0..per_len {
            out.push(digits(rng, len));
        }
    }
    for len in 0..=300 {
        out.push("1".repeat(len));
    }
    for ones in 1..=20 {
        for _ in 0..per_len.div_ceil(2).max(1) {
            let len = rng.below(100) as usize;
            out.push("1".repeat(ones) + &digits(rng, len));
        }
    }
    for len in 0..=300 {
        out.push("z".repeat(len));
    }
    for ones in 1..=8 {
        for len in 0..=150 {
            out.push("1".repeat(ones) + &"z".repeat(len));
        }
    }
    let mut which = 0usize;
    for len in 1..=MAX_LEN {
        for pos in 0..len {
            for _ in 0..INVALID.len() {
                let s = digits(rng, len);
                let bad = INVALID[which % INVALID.len()];
                which += 1;
                out.push(format!("{}{bad}{}", &s[..pos], &s[pos + 1..]));
            }
        }
    }
    for len in 0..=MAX_LEN {
        for _ in 0..per_len.div_ceil(2).max(1) {
            let mut b = vec![0u8; len];
            rng.fill(&mut b);
            out.push(String::from_utf8_lossy(&b).into_owned());
            let ascii: String = (0..len)
                .map(|_| char::from(0x20 + rng.below(0x5f) as u8))
                .collect();
            out.push(ascii);
        }
    }
    for _ in 0..per_len * 30 {
        let p = payload(rng, 100);
        let version = [rng.next_u64() as u8, rng.next_u64() as u8];
        let s = check_encode(&p, version);
        let pos = rng.below(s.len() as u64) as usize;
        out.push(change_one(rng, &s, pos));
        out.push(s[..s.len() - 1].to_string());
        out.push(s);
    }
    for digits_len in 255..=266 {
        for ones in [0, 1, 3] {
            out.push("1".repeat(ones) + &"z".repeat(digits_len));
            out.push("1".repeat(ones) + &digits_no_lead(rng, digits_len));
        }
    }
    for _ in 0..per_len * 3 {
        let len = MAX_LEN + 1 + rng.below(1080) as usize;
        out.push(digits(rng, len));
    }
    out
}

/// The largest value of the lengths [`structured`] leaves out, for the
/// differential against Go only (the per-digit reference is too slow for
/// them in an unoptimized build): 'z' repeated at every length from 301
/// to 1,200, and at every multiple of 512 digits up to 4,608 and one
/// either side of it, alone and behind one '1'.  At a multiple of 512 the
/// decoder's scratch is a limb larger than Go's `out32` rounded up to
/// eight bytes; either side of it, the two are the same size.
pub fn largest() -> Vec<String> {
    let mut out: Vec<String> = (301..=1200).map(|len| "z".repeat(len)).collect();
    for k in 1..=9 {
        for len in [512 * k - 1, 512 * k, 512 * k + 1] {
            for ones in [0, 1] {
                out.push("1".repeat(ones) + &"z".repeat(len));
            }
        }
    }
    out
}

/// One random string: mostly base58 of up to 120 characters, some with
/// leading '1's, an invalid character, a check-encoded payload or one
/// character of one changed.
pub fn random(rng: &mut SplitMix64) -> String {
    let len = rng.below(MAX_LEN as u64 + 1) as usize;
    match rng.below(20) {
        0 | 1 => {
            let s = digits(rng, len);
            if s.is_empty() {
                return s;
            }
            let pos = rng.below(s.len() as u64) as usize;
            let bad = INVALID[rng.below(INVALID.len() as u64) as usize];
            format!("{}{bad}{}", &s[..pos], &s[pos + 1..])
        }
        2 => "1".repeat(rng.below(8) as usize + 1) + &digits(rng, len),
        3 | 4 => {
            let p = payload(rng, 80);
            let s = check_encode(&p, [rng.next_u64() as u8, rng.next_u64() as u8]);
            if rng.below(2) == 0 {
                s
            } else {
                let pos = rng.below(s.len() as u64) as usize;
                change_one(rng, &s, pos)
            }
        }
        _ => digits(rng, len),
    }
}
