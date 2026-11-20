// SPDX-License-Identifier: ISC
//! Go 1.27.3's `ecdsa.ParseUncompressedPublicKey` (`crypto/ecdsa/ecdsa.go:107-131`),
//! which `crypto/x509`'s `parsePublicKey` ends its ECDSA case with
//! (`crypto/x509/parser.go:345-355`), so that a certificate whose ECDSA
//! key Go refuses is refused where it is read, with Go's words for it
//! ([`go_parse_uncompressed_public_key`]).
//!
//! Go takes a key on P-224, P-256, P-384 or P-521 only as an uncompressed
//! point: `0x04` ("ecdsa: invalid uncompressed public key" otherwise,
//! which covers the compressed and the hybrid forms and an empty key),
//! then the two coordinates at the field's length ("invalid P256 point
//! encoding"), each below p ("invalid P256 element encoding" on P-256,
//! "invalid P384Element encoding" on the others), on the curve ("P256
//! point not on curve") (`crypto/internal/fips140/ecdsa/ecdsa.go:185-197`,
//! `crypto/internal/fips140/nistec`).  The P-256 text for a coordinate at
//! or above p is that of Go's assembly P-256, which amd64, arm64, ppc64le
//! and s390x build (`nistec/p256_asm.go:78-135`); Go's generic P-256,
//! built on other architectures or with `purego`, says "invalid
//! P256Element encoding" there (`nistec/fiat/p256.go:74-82`).
//!
//! The check is the curve equation y² = x³ - 3x + b mod p on `num-bigint`,
//! the same for all four curves, P-224 among them, for which the tree has
//! no curve crate.  A key is public data: this runs in variable time.

use num_bigint::BigUint;

/// A curve Go's `crypto/x509` gives an ECDSA key on (`namedCurveFromOID`,
/// `crypto/x509/x509.go:583-595`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NistCurve {
    /// P-224, `secp224r1`.
    P224,
    /// P-256, `prime256v1`.
    P256,
    /// P-384, `secp384r1`.
    P384,
    /// P-521, `secp521r1`.
    P521,
}

/// One curve's field prime and b, big-endian at the field's length, and
/// Go's three texts for a point on it that does not read.
struct CurveRules {
    p: &'static [u8],
    b: &'static [u8],
    point_encoding: &'static str,
    element_encoding: &'static str,
    not_on_curve: &'static str,
}

/// P-224's field prime, 2^224 - 2^96 + 1.
const P224_P: [u8; 28] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];
/// P-224's b.
const P224_B: [u8; 28] = [
    0xb4, 0x05, 0x0a, 0x85, 0x0c, 0x04, 0xb3, 0xab, 0xf5, 0x41, 0x32, 0x56, 0x50, 0x44, 0xb0, 0xb7,
    0xd7, 0xbf, 0xd8, 0xba, 0x27, 0x0b, 0x39, 0x43, 0x23, 0x55, 0xff, 0xb4,
];
/// P-256's field prime, 2^256 - 2^224 + 2^192 + 2^96 - 1.
const P256_P: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];
/// P-256's b.
const P256_B: [u8; 32] = [
    0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
    0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b,
];
/// P-384's field prime, 2^384 - 2^128 - 2^96 + 2^32 - 1.
const P384_P: [u8; 48] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
];
/// P-384's b.
const P384_B: [u8; 48] = [
    0xb3, 0x31, 0x2f, 0xa7, 0xe2, 0x3e, 0xe7, 0xe4, 0x98, 0x8e, 0x05, 0x6b, 0xe3, 0xf8, 0x2d, 0x19,
    0x18, 0x1d, 0x9c, 0x6e, 0xfe, 0x81, 0x41, 0x12, 0x03, 0x14, 0x08, 0x8f, 0x50, 0x13, 0x87, 0x5a,
    0xc6, 0x56, 0x39, 0x8d, 0x8a, 0x2e, 0xd1, 0x9d, 0x2a, 0x85, 0xc8, 0xed, 0xd3, 0xec, 0x2a, 0xef,
];
/// P-521's field prime, 2^521 - 1, at 66 bytes.
const P521_P: [u8; 66] = {
    let mut p = [0xff; 66];
    p[0] = 0x01;
    p
};
/// P-521's b, at 66 bytes.
const P521_B: [u8; 66] = [
    0x00, 0x51, 0x95, 0x3e, 0xb9, 0x61, 0x8e, 0x1c, 0x9a, 0x1f, 0x92, 0x9a, 0x21, 0xa0, 0xb6, 0x85,
    0x40, 0xee, 0xa2, 0xda, 0x72, 0x5b, 0x99, 0xb3, 0x15, 0xf3, 0xb8, 0xb4, 0x89, 0x91, 0x8e, 0xf1,
    0x09, 0xe1, 0x56, 0x19, 0x39, 0x51, 0xec, 0x7e, 0x93, 0x7b, 0x16, 0x52, 0xc0, 0xbd, 0x3b, 0xb1,
    0xbf, 0x07, 0x35, 0x73, 0xdf, 0x88, 0x3d, 0x2c, 0x34, 0xf1, 0xef, 0x45, 0x1f, 0xd4, 0x6b, 0x50,
    0x3f, 0x00,
];

impl NistCurve {
    /// The curve a named-curve object identifier names, as DER contents:
    /// 1.3.132.0.33, 1.2.840.10045.3.1.7, 1.3.132.0.34 or 1.3.132.0.35.
    pub fn from_oid(oid: &[u8]) -> Option<NistCurve> {
        match oid {
            [0x2b, 0x81, 0x04, 0x00, 0x21] => Some(NistCurve::P224),
            [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => Some(NistCurve::P256),
            [0x2b, 0x81, 0x04, 0x00, 0x22] => Some(NistCurve::P384),
            [0x2b, 0x81, 0x04, 0x00, 0x23] => Some(NistCurve::P521),
            _ => None,
        }
    }

    /// The length of a field element: 28, 32, 48 or 66 bytes.
    pub fn field_len(self) -> usize {
        self.rules().p.len()
    }

    fn rules(self) -> CurveRules {
        match self {
            NistCurve::P224 => CurveRules {
                p: &P224_P,
                b: &P224_B,
                point_encoding: "invalid P224 point encoding",
                element_encoding: "invalid P224Element encoding",
                not_on_curve: "P224 point not on curve",
            },
            NistCurve::P256 => CurveRules {
                p: &P256_P,
                b: &P256_B,
                point_encoding: "invalid P256 point encoding",
                element_encoding: "invalid P256 element encoding",
                not_on_curve: "P256 point not on curve",
            },
            NistCurve::P384 => CurveRules {
                p: &P384_P,
                b: &P384_B,
                point_encoding: "invalid P384 point encoding",
                element_encoding: "invalid P384Element encoding",
                not_on_curve: "P384 point not on curve",
            },
            NistCurve::P521 => CurveRules {
                p: &P521_P,
                b: &P521_B,
                point_encoding: "invalid P521 point encoding",
                element_encoding: "invalid P521Element encoding",
                not_on_curve: "P521 point not on curve",
            },
        }
    }
}

/// Go's refusal of `data` as a public key on `curve` by
/// `ecdsa.ParseUncompressedPublicKey`, in Go's words, or `Ok` where Go
/// takes it (the module's documentation has the rules).
#[allow(
    clippy::arithmetic_side_effects,
    reason = "big-integer arithmetic, and lengths compared before they are used"
)]
pub fn go_parse_uncompressed_public_key(curve: NistCurve, data: &[u8]) -> Result<(), &'static str> {
    let rules = curve.rules();
    let Some((&4, coordinates)) = data.split_first() else {
        return Err("ecdsa: invalid uncompressed public key");
    };
    let len = rules.p.len();
    if coordinates.len() != 2 * len {
        return Err(rules.point_encoding);
    }
    let (x, y) = coordinates.split_at(len);
    // Big-endian at the same length, so the bytes compare as the values.
    if x >= rules.p || y >= rules.p {
        return Err(rules.element_encoding);
    }
    let p = BigUint::from_bytes_be(rules.p);
    let x = BigUint::from_bytes_be(x);
    let y = BigUint::from_bytes_be(y);
    let b = BigUint::from_bytes_be(rules.b);
    // x < p, so p - x is the negation of x, zero's being p itself.
    let rhs = ((&x * &x % &p) * &x + (&p - &x) * 3u8 + b) % &p;
    let lhs = &y * &y % &p;
    if lhs != rhs {
        return Err(rules.not_on_curve);
    }
    Ok(())
}

#[cfg(test)]
// Test-harness arithmetic over bounded lengths.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use dcroxide_testutil::unhex;
    use ecdsa::elliptic_curve::sec1::ToSec1Point;

    /// Uncompressed points of small multiples of each curve's generator:
    /// for P-256, P-384 and P-521 made by the curve crates, for P-224, 1,
    /// 2, 3 and 12345 times its generator as Go 1.27.3's
    /// `elliptic.P224().ScalarBaseMult` gives them.
    fn points(curve: NistCurve) -> Vec<Vec<u8>> {
        fn scalar(k: u8, len: usize) -> Vec<u8> {
            let mut bytes = vec![0u8; len];
            if let Some(last) = bytes.last_mut() {
                *last = k;
            }
            bytes
        }
        macro_rules! public {
            ($krate:ident, $k:expr) => {{
                let repr = $krate::FieldBytes::try_from(scalar($k, curve.field_len()).as_slice())
                    .expect("a scalar's length");
                let secret = $krate::NonZeroScalar::from_repr(repr)
                    .into_option()
                    .expect("a scalar");
                $krate::PublicKey::from_secret_scalar(&secret)
                    .to_sec1_point(false)
                    .as_bytes()
                    .to_vec()
            }};
        }
        let ks = 1u8..=20;
        match curve {
            NistCurve::P224 => [
                "04b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
                "04706a46dc76dcb76798e60e6d89474788d16dc18032d268fd1a704fa61c2b76a7bc25e7702a704fa986892849fca629487acf3709d2e4e8bb",
                "04df1b1d66a551d0d31eff822558b9d2cc75c2180279fe0d08fd896d04a3f7f03cadd0be444c0aa56830130ddf77d317344e1af3591981a925",
                "041d1311a96120cf37508f71601c30cd549e346aca41b43a2a60a44da2af0f98f515d6dbf2e3d0e444bd8a9d77ebb82da3bda478a426436179",
            ]
            .iter()
            .map(|h| unhex(h))
            .collect(),
            NistCurve::P256 => ks.map(|k| public!(p256, k)).collect(),
            NistCurve::P384 => ks.map(|k| public!(p384, k)).collect(),
            NistCurve::P521 => ks.map(|k| public!(p521, k)).collect(),
        }
    }

    /// Whether the curve crate takes `data` as a key, the uncompressed
    /// form alone given to it; `None` for P-224, which has no crate here.
    fn crate_takes(curve: NistCurve, data: &[u8]) -> Option<bool> {
        if data.first() != Some(&4) {
            return Some(false);
        }
        match curve {
            NistCurve::P224 => None,
            NistCurve::P256 => Some(p256::PublicKey::from_sec1_bytes(data).is_ok()),
            NistCurve::P384 => Some(p384::PublicKey::from_sec1_bytes(data).is_ok()),
            NistCurve::P521 => Some(p521::PublicKey::from_sec1_bytes(data).is_ok()),
        }
    }

    /// Each curve's points are taken, and each way of breaking one is
    /// refused with Go's words for it, in the order Go checks: the
    /// prefix, the length, a coordinate at or above p, then the
    /// equation.  Where a curve crate is in the tree, it agrees on every
    /// verdict.
    #[test]
    fn uncompressed_points_are_read_as_go_reads_them() {
        let curves = [
            (NistCurve::P224, "P224", "P224Element"),
            (NistCurve::P256, "P256", "P256 element"),
            (NistCurve::P384, "P384", "P384Element"),
            (NistCurve::P521, "P521", "P521Element"),
        ];
        for (curve, name, element) in curves {
            let len = curve.field_len();
            let rules = curve.rules();
            for point in points(curve) {
                assert_eq!(point.len(), 1 + 2 * len, "{name}");
                assert_eq!(
                    go_parse_uncompressed_public_key(curve, &point),
                    Ok(()),
                    "{name}"
                );
                assert_ne!(crate_takes(curve, &point), Some(false), "{name}");

                let mut cases: Vec<(&str, Vec<u8>, String)> = Vec::new();
                let bad_prefix = "ecdsa: invalid uncompressed public key".to_string();
                cases.push(("empty", Vec::new(), bad_prefix.clone()));
                for prefix in [0u8, 2, 3, 5, 6, 7] {
                    let mut p = point.clone();
                    p[0] = prefix;
                    cases.push(("prefix", p, bad_prefix.clone()));
                }
                // The compressed form of the point.
                let mut compressed = point[..=len].to_vec();
                compressed[0] = 2 | (point[2 * len] & 1);
                cases.push(("compressed", compressed, bad_prefix.clone()));
                let point_encoding = format!("invalid {name} point encoding");
                cases.push(("prefix alone", vec![4], point_encoding.clone()));
                cases.push(("short", point[..2 * len].to_vec(), point_encoding.clone()));
                let mut long = point.clone();
                long.push(0);
                cases.push(("long", long, point_encoding.clone()));
                let element_encoding = format!("invalid {element} encoding");
                let mut x_is_p = point.clone();
                x_is_p[1..=len].copy_from_slice(rules.p);
                cases.push(("x = p", x_is_p, element_encoding.clone()));
                let mut y_is_p = point.clone();
                y_is_p[1 + len..].copy_from_slice(rules.p);
                cases.push(("y = p", y_is_p, element_encoding.clone()));
                let mut y_max = point.clone();
                y_max[1 + len..].fill(0xff);
                cases.push(("y all ones", y_max, element_encoding.clone()));
                let not_on_curve = format!("{name} point not on curve");
                let mut y_plus_one = point.clone();
                let last = y_plus_one.len() - 1;
                y_plus_one[last] ^= 1;
                cases.push(("y off by one", y_plus_one, not_on_curve.clone()));
                let mut zero = vec![4u8];
                zero.resize(1 + 2 * len, 0);
                cases.push(("the origin", zero, not_on_curve.clone()));
                for (what, data, words) in cases {
                    assert_eq!(
                        go_parse_uncompressed_public_key(curve, &data),
                        Err(words.as_str()),
                        "{name}, {what}"
                    );
                    assert_ne!(crate_takes(curve, &data), Some(true), "{name}, {what}");
                }
            }
        }
    }

    /// The curves by their identifiers, as `namedCurveFromOID` knows them,
    /// and no other, secp256k1 among those it does not.
    #[test]
    fn curves_are_named_by_their_identifiers() {
        assert_eq!(
            NistCurve::from_oid(&[0x2b, 0x81, 0x04, 0x00, 0x21]),
            Some(NistCurve::P224)
        );
        assert_eq!(
            NistCurve::from_oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
            Some(NistCurve::P256)
        );
        assert_eq!(
            NistCurve::from_oid(&[0x2b, 0x81, 0x04, 0x00, 0x22]),
            Some(NistCurve::P384)
        );
        assert_eq!(
            NistCurve::from_oid(&[0x2b, 0x81, 0x04, 0x00, 0x23]),
            Some(NistCurve::P521)
        );
        assert_eq!(NistCurve::from_oid(&[0x2b, 0x81, 0x04, 0x00, 0x0a]), None);
        assert_eq!(NistCurve::from_oid(&[]), None);
        for (curve, len) in [
            (NistCurve::P224, 28),
            (NistCurve::P256, 32),
            (NistCurve::P384, 48),
            (NistCurve::P521, 66),
        ] {
            assert_eq!(curve.field_len(), len);
            assert_eq!(curve.rules().b.len(), len);
        }
    }
}
