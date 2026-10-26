// SPDX-License-Identifier: ISC
//! The key shares `tests/ring_parity.rs` and `tests/go_differential.rs` put
//! to each key exchange group, valid and not, so that the groups' verdicts
//! can be held to ring's and Go's share by share (ADR-0015, step 1).
//!
//! For each group: nothing at all, and every length from one byte to 140
//! under each leading byte SEC 1 gives a meaning or reserves (`0x00`,
//! `0x02` to `0x07`), the rest taken from a valid share, so that at the
//! right lengths these are the valid share itself, its compressed and its
//! hybrid forms and the identity's encoding.  Then, for a NIST curve, the
//! valid share with a bit flipped in either coordinate, and the point
//! whose x is 0, which each of the three curves has, written with x as 0,
//! as p and as p + 1, the last two at or above p and so refused, the
//! first on the curve; and for X25519 the u-coordinates of small order,
//! their forms at or above p, points of the curve and of its twist, each
//! with the top bit RFC 7748 ignores clear and set.  The valid share is
//! the generator's, or X25519's base point 9, so every run puts the same
//! shares.

use curve25519_dalek::montgomery::MontgomeryPoint;
use dcroxide_testutil::unhex;
use p256::elliptic_curve::sec1::ToSec1Point;
use rustls::NamedGroup;

/// The shares to put to `group`, each with a label for messages.
pub fn shares(group: NamedGroup) -> Vec<(String, Vec<u8>)> {
    let (valid, mut extra) = match group {
        NamedGroup::X25519 => (x25519_base(), x25519_extra()),
        NamedGroup::secp256r1 => nist(
            P256_P,
            p256::PublicKey::from_affine(p256::AffinePoint::GENERATOR)
                .expect("the generator")
                .to_sec1_point(false)
                .as_bytes(),
            |compressed| {
                p256::PublicKey::from_sec1_bytes(compressed)
                    .ok()
                    .map(|key| key.to_sec1_point(false).as_bytes().to_vec())
            },
        ),
        NamedGroup::secp384r1 => nist(
            P384_P,
            p384::PublicKey::from_affine(p384::AffinePoint::GENERATOR)
                .expect("the generator")
                .to_sec1_point(false)
                .as_bytes(),
            |compressed| {
                p384::PublicKey::from_sec1_bytes(compressed)
                    .ok()
                    .map(|key| key.to_sec1_point(false).as_bytes().to_vec())
            },
        ),
        NamedGroup::secp521r1 => nist(
            P521_P,
            p521::PublicKey::from_affine(p521::AffinePoint::GENERATOR)
                .expect("the generator")
                .to_sec1_point(false)
                .as_bytes(),
            |compressed| {
                p521::PublicKey::from_sec1_bytes(compressed)
                    .ok()
                    .map(|key| key.to_sec1_point(false).as_bytes().to_vec())
            },
        ),
        other => panic!("no shares for {other:?}"),
    };
    let mut shares = vec![("nothing".to_owned(), Vec::new())];
    for len in 1..=140usize {
        for lead in [0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07] {
            let share = std::iter::once(lead)
                .chain(valid.iter().skip(1).cycle().copied())
                .take(len)
                .collect();
            shares.push((format!("{len} bytes under {lead:#04x}"), share));
        }
    }
    shares.append(&mut extra);
    shares
}

/// Each NIST curve's field prime, big-endian at the field's length.
const P256_P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
const P384_P: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
const P521_P: &str = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// The valid share of a NIST curve, `generator`, and the curve's own
/// cases: its corruptions and the point at x = 0 in its three spellings.
/// `uncompress` gives the uncompressed encoding of a compressed point.
fn nist(
    p: &str,
    generator: &[u8],
    uncompress: impl Fn(&[u8]) -> Option<Vec<u8>>,
) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
    let p = unhex(p);
    let len = p.len();
    let mut extra = Vec::new();
    for (label, at) in [("x", 1), ("y", 1 + len)] {
        let mut share = generator.to_vec();
        share[at + len - 1] ^= 1;
        extra.push((
            format!("the generator with a bit of {label} flipped"),
            share,
        ));
    }
    // (0, y) is on each curve: b is a square modulo each prime.
    let compressed = [&[0x02][..], &vec![0; len]].concat();
    let at_zero = uncompress(&compressed).expect("a point at x = 0");
    let y = at_zero[1 + len..].to_vec();
    let mut p_plus_one = p.clone();
    for byte in p_plus_one.iter_mut().rev() {
        let (sum, carry) = byte.overflowing_add(1);
        *byte = sum;
        if !carry {
            break;
        }
    }
    for (label, x) in [("0", vec![0; len]), ("p", p.clone()), ("p + 1", p_plus_one)] {
        extra.push((
            format!("the point at x = 0, x written as {label}"),
            [&[0x04][..], &x, &y].concat(),
        ));
    }
    extra.push((
        "the generator's x with y written as p".to_owned(),
        [&generator[..=len], &p].concat(),
    ));
    (generator.to_vec(), extra)
}

/// X25519's base point, u = 9.
fn x25519_base() -> Vec<u8> {
    let mut base = vec![0; 32];
    base[0] = 9;
    base
}

/// X25519's own cases, little-endian u-coordinates: those of small order
/// on the curve and its twist (0, 1, p - 1 and the curve's two of order
/// eight), 0 and 1 written as p and p + 1, points of the curve (4, 9,
/// 9 + p) and of its twist (2, 3, 5, 2 + p), and the share of the private
/// key `0x01` repeated, each with the top bit clear and set.
fn x25519_extra() -> Vec<(String, Vec<u8>)> {
    let small = |n: u8| {
        let mut u = vec![0; 32];
        u[0] = n;
        u
    };
    let above_p = |n: u8| {
        // p + n for n < 19: p is 2^255 - 19, so its low byte is 0xed.
        let mut u = unhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        u[0] = 0xed + n;
        u
    };
    let mut cases = vec![
        ("0, of order 2".to_owned(), small(0)),
        ("1, of order 4".to_owned(), small(1)),
        (
            "of order 8".to_owned(),
            unhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        ),
        (
            "of order 8, the other".to_owned(),
            unhex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        ),
        (
            "p - 1, of order 4 on the twist".to_owned(),
            unhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ),
        ("p, which is 0".to_owned(), above_p(0)),
        ("p + 1, which is 1".to_owned(), above_p(1)),
        ("4, on the curve".to_owned(), small(4)),
        ("9, the base point".to_owned(), small(9)),
        ("p + 9, the base point".to_owned(), above_p(9)),
        ("2, on the twist".to_owned(), small(2)),
        ("3, on the twist".to_owned(), small(3)),
        ("5, on the twist".to_owned(), small(5)),
        ("p + 2, on the twist".to_owned(), above_p(2)),
        (
            "the share of the private key 0x01 repeated".to_owned(),
            MontgomeryPoint::mul_base_clamped([1; 32])
                .to_bytes()
                .to_vec(),
        ),
    ];
    let with_top_bit: Vec<_> = cases
        .iter()
        .map(|(label, u)| {
            let mut u = u.clone();
            u[31] |= 0x80;
            (format!("{label}, top bit set"), u)
        })
        .collect();
    cases.extend(with_top_bit);
    cases
}
