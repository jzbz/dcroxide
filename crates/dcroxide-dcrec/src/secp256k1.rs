// SPDX-License-Identifier: ISC
//! secp256k1 public/private keys with dcrd's exact parsing and acceptance
//! rules (mirrors dcrd `dcrec/secp256k1/v4`).

use core::fmt;

use k256::elliptic_curve::group::CurveAffine;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};
use zeroize::{Zeroize, Zeroizing};

mod backend;
pub mod ecdsa;
pub mod nonce;
pub mod schnorr;

/// The secp256k1 field prime P as 32 big-endian bytes.
pub const FIELD_PRIME_BYTES: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];

/// The secp256k1 group order N as 32 big-endian bytes.
pub const GROUP_ORDER_BYTES: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// P - N, the field prime less the group order, as 32 big-endian bytes
/// (0x14551231950b75fc4402da1722fc9baee): the bound of dcrd's
/// `FieldVal.IsGtOrEqPrimeMinusOrder` (field.go).  ECDSA verification's
/// step 9 rejects an r at or above it, since r + N would reach P.
pub(crate) const PRIME_MINUS_ORDER_BYTES: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x45, 0x51, 0x23, 0x19, 0x50, 0xb7, 0x5f, 0xc4, 0x40, 0x2d, 0xa1, 0x72, 0x2f, 0xc9, 0xba, 0xee,
];

/// Half the group order (floor(N/2)) as 32 big-endian bytes; S components
/// above this are normalized on serialization, matching dcrd.
pub(crate) const HALF_GROUP_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// Whether a 32-byte big-endian value is zero.
pub(crate) fn is_zero(v: &[u8; 32]) -> bool {
    v.iter().all(|&b| b == 0)
}

/// N - s for 0 < s < N (big-endian byte arithmetic).
// Schoolbook borrow subtraction over fixed 32-byte arrays; every intermediate
// fits i32 and the input domain (0 < s < N) makes underflow of the total
// impossible.
#[allow(clippy::arithmetic_side_effects)]
pub(crate) fn negate_mod_n(s: &[u8; 32]) -> [u8; 32] {
    debug_assert!(!is_zero(s) && *s < GROUP_ORDER_BYTES);
    let mut out = [0u8; 32];
    let mut borrow: i32 = 0;
    for i in (0..32).rev() {
        let mut diff = i32::from(GROUP_ORDER_BYTES[i]) - i32::from(s[i]) - borrow;
        borrow = if diff < 0 {
            diff += 256;
            1
        } else {
            0
        };
        out[i] = diff as u8;
    }
    debug_assert_eq!(borrow, 0);
    out
}

/// r + N for r below P - N (big-endian byte arithmetic): the x coordinate
/// compact recovery takes when the recovery code's overflow bit is set
/// (dcrd's `fieldR.Add(&orderAsFieldVal)`, ecdsa/signature.go:928).  The
/// sum is below P, so it never carries out of 32 bytes.
// Schoolbook carry addition over fixed 32-byte arrays; every intermediate
// fits u16, and the input domain (r < P - N) makes a carry out of the top
// byte impossible.
#[allow(clippy::arithmetic_side_effects)]
pub(crate) fn add_group_order(r: &[u8; 32]) -> [u8; 32] {
    debug_assert!(*r < PRIME_MINUS_ORDER_BYTES);
    let mut out = [0u8; 32];
    let mut carry: u16 = 0;
    for i in (0..32).rev() {
        let sum = u16::from(r[i]) + u16::from(GROUP_ORDER_BYTES[i]) + carry;
        out[i] = sum as u8;
        carry = sum >> 8;
    }
    debug_assert_eq!(carry, 0);
    out
}

/// Number of bytes of a serialized compressed public key.
pub const PUB_KEY_BYTES_LEN_COMPRESSED: usize = 33;

/// Number of bytes of a serialized uncompressed public key.
pub const PUB_KEY_BYTES_LEN_UNCOMPRESSED: usize = 65;

/// Prefix byte for an even-Y compressed public key.
pub const PUB_KEY_FORMAT_COMPRESSED_EVEN: u8 = 0x02;

/// Prefix byte for an odd-Y compressed public key.
pub const PUB_KEY_FORMAT_COMPRESSED_ODD: u8 = 0x03;

/// Prefix byte for an uncompressed public key.
pub const PUB_KEY_FORMAT_UNCOMPRESSED: u8 = 0x04;

/// Prefix byte for an even-Y hybrid public key (parsed, never produced —
/// same stance as dcrd).
pub const PUB_KEY_FORMAT_HYBRID_EVEN: u8 = 0x06;

/// Prefix byte for an odd-Y hybrid public key (parsed, never produced).
pub const PUB_KEY_FORMAT_HYBRID_ODD: u8 = 0x07;

/// Public key parsing errors, 1:1 with dcrd `secp256k1.ErrorKind`.  Each
/// variant carries the values dcrd formats into its description, so the
/// `Display` text is dcrd's `Error()` string exactly (dcrd's callers wrap
/// it with `%v`, e.g. stdaddr's `failed to parse public key: %v`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Wrong overall length (`ErrPubKeyInvalidLen`), with the length.
    PubKeyInvalidLen(usize),
    /// Unsupported format byte for the given length
    /// (`ErrPubKeyInvalidFormat`), with the format byte.
    PubKeyInvalidFormat(u8),
    /// X coordinate >= field prime (`ErrPubKeyXTooBig`).
    PubKeyXTooBig,
    /// Y coordinate >= field prime (`ErrPubKeyYTooBig`).
    PubKeyYTooBig,
    /// Point is not on the secp256k1 curve (`ErrPubKeyNotOnCurve`), with
    /// the x coordinate and, for the uncompressed and hybrid formats,
    /// the y coordinate: dcrd words the two cases differently.
    PubKeyNotOnCurve {
        /// The x coordinate, big-endian (below the field prime).
        x: [u8; 32],
        /// The y coordinate for a 65-byte key; `None` for a compressed
        /// key, whose y could not be computed.
        y: Option<[u8; 32]>,
    },
    /// Hybrid key Y oddness does not match its format byte
    /// (`ErrPubKeyMismatchedOddness`), with the oddness the format byte
    /// asked for.
    PubKeyMismatchedOddness(bool),
}

impl Error {
    /// The dcrd error kind name, used for differential comparison.
    pub fn kind_name(self) -> &'static str {
        match self {
            Error::PubKeyInvalidLen(_) => "ErrPubKeyInvalidLen",
            Error::PubKeyInvalidFormat(_) => "ErrPubKeyInvalidFormat",
            Error::PubKeyXTooBig => "ErrPubKeyXTooBig",
            Error::PubKeyYTooBig => "ErrPubKeyYTooBig",
            Error::PubKeyNotOnCurve { .. } => "ErrPubKeyNotOnCurve",
            Error::PubKeyMismatchedOddness(_) => "ErrPubKeyMismatchedOddness",
        }
    }
}

/// Lower-case hex of a field element, as dcrd's `FieldVal.String` renders
/// a normalized value (every coordinate here is below the field prime).
fn write_field_hex(f: &mut fmt::Formatter<'_>, v: &[u8; 32]) -> fmt::Result {
    for b in v {
        write!(f, "{b:02x}")?;
    }
    Ok(())
}

impl fmt::Display for Error {
    /// dcrd's descriptions (dcrec/secp256k1 `pubkey.go` `parse`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::PubKeyInvalidLen(len) => {
                write!(f, "malformed public key: invalid length: {len}")
            }
            // Go's `%x` of a byte: lower-case, unpadded.
            Error::PubKeyInvalidFormat(format) => {
                write!(f, "invalid public key: unsupported format: {format:x}")
            }
            Error::PubKeyXTooBig => f.write_str("invalid public key: x >= field prime"),
            Error::PubKeyYTooBig => f.write_str("invalid public key: y >= field prime"),
            Error::PubKeyNotOnCurve { x, y: Some(y) } => {
                f.write_str("invalid public key: [")?;
                write_field_hex(f, x)?;
                f.write_str(",")?;
                write_field_hex(f, y)?;
                f.write_str("] not on secp256k1 curve")
            }
            Error::PubKeyNotOnCurve { x, y: None } => {
                f.write_str("invalid public key: x coordinate ")?;
                write_field_hex(f, x)?;
                f.write_str(" is not on the secp256k1 curve")
            }
            Error::PubKeyMismatchedOddness(want_odd_y) => write!(
                f,
                "invalid public key: y oddness does not match specified value of {want_odd_y}"
            ),
        }
    }
}

impl core::error::Error for Error {}

/// A validated secp256k1 public key: a k256 affine point on the curve,
/// never the identity, built only once dcrd's format, range and oddness
/// checks have passed.
///
/// `PartialEq` compares the coordinates in constant time.  `Debug` prints
/// the compressed serialization in hex, not the point's internal limbs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    point: AffinePoint,
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicKey(")?;
        for b in self.serialize_compressed() {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

impl PublicKey {
    /// Parse a public key with dcrd's exact acceptance rules
    /// (`secp256k1.ParsePubKey`): compressed (0x02/0x03), uncompressed
    /// (0x04), and hybrid (0x06/0x07) formats; coordinates must be below the
    /// field prime (no wraparound); hybrid Y oddness must match the format
    /// byte; the point must be on the curve.
    pub fn parse(serialized: &[u8]) -> Result<PublicKey, Error> {
        match serialized.len() {
            PUB_KEY_BYTES_LEN_UNCOMPRESSED => {
                let format = serialized[0];
                match format {
                    PUB_KEY_FORMAT_UNCOMPRESSED
                    | PUB_KEY_FORMAT_HYBRID_EVEN
                    | PUB_KEY_FORMAT_HYBRID_ODD => {}
                    _ => return Err(Error::PubKeyInvalidFormat(format)),
                }

                // Coordinates must be in range (dcrd rejects values that
                // would wrap around the field prime).
                let x: &[u8; 32] = serialized[1..33].try_into().expect("32 bytes");
                let y: &[u8; 32] = serialized[33..65].try_into().expect("32 bytes");
                if *x >= FIELD_PRIME_BYTES {
                    return Err(Error::PubKeyXTooBig);
                }
                if *y >= FIELD_PRIME_BYTES {
                    return Err(Error::PubKeyYTooBig);
                }

                // Hybrid keys encode the Y oddness in the format byte and it
                // must match the actual coordinate.
                if format == PUB_KEY_FORMAT_HYBRID_EVEN || format == PUB_KEY_FORMAT_HYBRID_ODD {
                    let want_odd_y = format == PUB_KEY_FORMAT_HYBRID_ODD;
                    if (y[31] & 1 == 1) != want_odd_y {
                        return Err(Error::PubKeyMismatchedOddness(want_odd_y));
                    }
                }

                // The remaining failure is an off-curve point (dcrd's
                // `IsOnCurve`): k256's `from_coordinates` tests
                // y^2 = x^3 + 7 on coordinates already below the prime, so
                // the range errors above keep their own kinds.  Its result
                // is never the identity.
                let point = Option::<AffinePoint>::from(AffinePoint::from_coordinates(
                    &(*x).into(),
                    &(*y).into(),
                ))
                .ok_or(Error::PubKeyNotOnCurve { x: *x, y: Some(*y) })?;
                Ok(PublicKey { point })
            }
            PUB_KEY_BYTES_LEN_COMPRESSED => {
                let format = serialized[0];
                if format != PUB_KEY_FORMAT_COMPRESSED_EVEN
                    && format != PUB_KEY_FORMAT_COMPRESSED_ODD
                {
                    return Err(Error::PubKeyInvalidFormat(format));
                }
                let x: &[u8; 32] = serialized[1..33].try_into().expect("32 bytes");
                if *x >= FIELD_PRIME_BYTES {
                    return Err(Error::PubKeyXTooBig);
                }

                // Decompression fails iff x^3 + 7 has no square root, so no
                // curve point has this x (dcrd's `DecompressY`).  The seam
                // takes the root on dcroxide-secp256k1-vartime (ADR-0016),
                // which normalizes it before choosing the one whose oddness
                // the format byte asks for, 0x03 the odd one, and again
                // after negating it, as dcrd does.
                let point = backend::decompress(x, format & 1 == 1)
                    .ok_or(Error::PubKeyNotOnCurve { x: *x, y: None })?;
                Ok(PublicKey { point })
            }
            _ => Err(Error::PubKeyInvalidLen(serialized.len())),
        }
    }

    /// The 33-byte compressed serialization (dcrd `SerializeCompressed`).
    pub fn serialize_compressed(&self) -> [u8; PUB_KEY_BYTES_LEN_COMPRESSED] {
        let mut out = [0u8; PUB_KEY_BYTES_LEN_COMPRESSED];
        // 0x02, or 0x03 for an odd y.
        out[0] = PUB_KEY_FORMAT_COMPRESSED_EVEN | self.point.y_is_odd().unwrap_u8();
        out[1..].copy_from_slice(&self.point.x());
        out
    }

    /// The 65-byte uncompressed serialization (dcrd `SerializeUncompressed`).
    /// Hybrid-parsed keys serialize with the 0x04 prefix; dcrd never emits
    /// the hybrid format either.
    pub fn serialize_uncompressed(&self) -> [u8; PUB_KEY_BYTES_LEN_UNCOMPRESSED] {
        let mut out = [0u8; PUB_KEY_BYTES_LEN_UNCOMPRESSED];
        out[0] = PUB_KEY_FORMAT_UNCOMPRESSED;
        out[1..33].copy_from_slice(&self.point.x());
        out[33..].copy_from_slice(&self.point.y());
        out
    }

    /// The key from a k256 point, which must not be the identity: a point
    /// on the curve that recovery computed (the seam converts it from the
    /// vartime crate's).
    pub(crate) fn from_affine(point: AffinePoint) -> PublicKey {
        debug_assert!(!bool::from(point.is_identity()));
        PublicKey { point }
    }

    /// The key as a k256 projective point, for the seam's k256 arms.  The
    /// key already holds the point, so this only sets z = 1.
    pub(crate) fn as_k256_point(&self) -> ProjectivePoint {
        ProjectivePoint::from(self.point)
    }
}

/// A secp256k1 private key in the range `[1, N-1]`, held as a
/// `k256::SecretKey`, which wipes the key when dropped.
///
/// `Debug` prints `PrivateKey(..)` and no key material.
///
/// Note: dcrd's `PrivKeyFromBytes` silently reduces out-of-range values mod
/// N; this constructor rejects them instead. The daemon's consensus paths
/// never construct private keys from untrusted bytes, so the difference is
/// not an observable-compatibility surface (tracked in `PARITY.md`).
#[derive(Clone)]
pub struct PrivateKey {
    inner: k256::SecretKey,
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(..)")
    }
}

impl PrivateKey {
    /// Construct from 32 big-endian bytes; `None` if zero or >= N.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<PrivateKey> {
        let repr = Zeroizing::new(FieldBytes::from(*bytes));
        k256::SecretKey::from_bytes(&repr)
            .ok()
            .map(|inner| PrivateKey { inner })
    }

    /// The corresponding public key, dG.  The scalar copy is wiped; the
    /// multiplication is k256's constant-time `GENERATOR * d`.
    // The flagged operator is k256 point multiplication, a group operation.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn public_key(&self) -> PublicKey {
        let mut d = Scalar::from(self.inner.as_scalar_value());
        let point = (ProjectivePoint::GENERATOR * d).to_affine();
        d.zeroize();
        PublicKey { point }
    }

    /// The key's 32 big-endian bytes, wiped when dropped (dcrd's signers
    /// copy the key out with `PutBytes` and zero the copy when done).
    pub(crate) fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.inner.to_bytes().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcroxide_testutil::unhex;

    /// Ported from dcrd's TestParsePubKey (pubkey_test.go).
    #[test]
    fn parse_pub_key_vectors() {
        struct Case {
            name: &'static str,
            key: &'static str,
            want: Result<(), &'static str>,
        }
        let cases = [
            Case {
                name: "uncompressed ok",
                key: "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
                want: Ok(()),
            },
            Case {
                name: "uncompressed x changed (not on curve)",
                key: "0415db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
                want: Err("ErrPubKeyNotOnCurve"),
            },
            Case {
                name: "uncompressed y changed (not on curve)",
                key: "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a4",
                want: Err("ErrPubKeyNotOnCurve"),
            },
            Case {
                name: "uncompressed claims compressed",
                key: "0311db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
                want: Err("ErrPubKeyInvalidFormat"),
            },
            Case {
                name: "uncompressed as hybrid ok (ybit = 0)",
                key: "0611db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c4d1f1522047b33068bbb9b07d1e9f40564749b062b3fc0666479bc08a94be98c",
                want: Ok(()),
            },
            Case {
                name: "uncompressed as hybrid ok (ybit = 1)",
                key: "0711db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
                want: Ok(()),
            },
            Case {
                name: "uncompressed as hybrid wrong oddness",
                key: "0611db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
                want: Err("ErrPubKeyMismatchedOddness"),
            },
            Case {
                name: "compressed ok (ybit = 0)",
                key: "02ce0b14fb842b1ba549fdd675c98075f12e9c510f8ef52bd021a9a1f4809d3b4d",
                want: Ok(()),
            },
            Case {
                name: "compressed ok (ybit = 1)",
                key: "032689c7c2dab13309fb143e0e8fe396342521887e976690b6b47f5b2a4b7d448e",
                want: Ok(()),
            },
            Case {
                name: "compressed claims uncompressed (ybit = 0)",
                key: "04ce0b14fb842b1ba549fdd675c98075f12e9c510f8ef52bd021a9a1f4809d3b4d",
                want: Err("ErrPubKeyInvalidFormat"),
            },
            Case {
                name: "compressed claims uncompressed (ybit = 1)",
                key: "042689c7c2dab13309fb143e0e8fe396342521887e976690b6b47f5b2a4b7d448e",
                want: Err("ErrPubKeyInvalidFormat"),
            },
            Case {
                name: "compressed claims hybrid (ybit = 0)",
                key: "06ce0b14fb842b1ba549fdd675c98075f12e9c510f8ef52bd021a9a1f4809d3b4d",
                want: Err("ErrPubKeyInvalidFormat"),
            },
            Case {
                name: "compressed claims hybrid (ybit = 1)",
                key: "072689c7c2dab13309fb143e0e8fe396342521887e976690b6b47f5b2a4b7d448e",
                want: Err("ErrPubKeyInvalidFormat"),
            },
            Case {
                name: "compressed with invalid x coord (ybit = 0)",
                key: "03ce0b14fb842b1ba549fdd675c98075f12e9c510f8ef52bd021a9a1f4809d3b4c",
                want: Err("ErrPubKeyNotOnCurve"),
            },
            Case {
                name: "compressed with invalid x coord (ybit = 1)",
                key: "032689c7c2dab13309fb143e0e8fe396342521887e976690b6b47f5b2a4b7d448d",
                want: Err("ErrPubKeyNotOnCurve"),
            },
            Case {
                name: "empty",
                key: "",
                want: Err("ErrPubKeyInvalidLen"),
            },
            Case {
                name: "wrong length",
                key: "05",
                want: Err("ErrPubKeyInvalidLen"),
            },
            Case {
                name: "uncompressed x == p",
                key: "04fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
                want: Err("ErrPubKeyXTooBig"),
            },
            Case {
                name: "uncompressed x > p (p + 1 -- aka 1)",
                key: "04fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30bde70df51939b94c9c24979fa7dd04ebd9b3572da7802290438af2a681895441",
                want: Err("ErrPubKeyXTooBig"),
            },
            Case {
                name: "uncompressed y == p",
                key: "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
                want: Err("ErrPubKeyYTooBig"),
            },
            Case {
                name: "uncompressed y > p (p + 1 -- aka 1)",
                key: "041fe1e5ef3fceb5c135ab7741333ce5a6e80d68167653f6b2b24bcbcfaaaff507fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30",
                want: Err("ErrPubKeyYTooBig"),
            },
            Case {
                name: "compressed x == p (ybit = 0)",
                key: "02fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
                want: Err("ErrPubKeyXTooBig"),
            },
            Case {
                name: "compressed x == p (ybit = 1)",
                key: "03fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
                want: Err("ErrPubKeyXTooBig"),
            },
            Case {
                name: "compressed x > p (p + 2 -- aka 2) (ybit = 0)",
                key: "02fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc31",
                want: Err("ErrPubKeyXTooBig"),
            },
            Case {
                name: "compressed x > p (p + 1 -- aka 1) (ybit = 1)",
                key: "03fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30",
                want: Err("ErrPubKeyXTooBig"),
            },
            Case {
                name: "hybrid x == p (ybit = 1)",
                key: "07fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
                want: Err("ErrPubKeyXTooBig"),
            },
            Case {
                name: "hybrid x > p (p + 1 -- aka 1) (ybit = 0)",
                key: "06fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30bde70df51939b94c9c24979fa7dd04ebd9b3572da7802290438af2a681895441",
                want: Err("ErrPubKeyXTooBig"),
            },
            Case {
                name: "hybrid y == p (ybit = 0 when mod p)",
                key: "0611db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
                want: Err("ErrPubKeyYTooBig"),
            },
            Case {
                name: "hybrid y > p (p + 1 -- aka 1) (ybit = 1 when mod p)",
                key: "071fe1e5ef3fceb5c135ab7741333ce5a6e80d68167653f6b2b24bcbcfaaaff507fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30",
                want: Err("ErrPubKeyYTooBig"),
            },
        ];

        for case in &cases {
            let got = PublicKey::parse(&unhex(case.key)).map(|_| ());
            assert_eq!(got.map_err(Error::kind_name), case.want, "{}", case.name);
        }
    }

    /// The error text is dcrd's `Error()` string, dynamic parts and all
    /// (dcrec/secp256k1 `pubkey.go`): stdaddr's P2PK constructors wrap it
    /// with `failed to parse public key: %v`, which RPC address decoding
    /// hands to clients.
    #[test]
    fn parse_error_text_matches_dcrd() {
        let cases = [
            ("", "malformed public key: invalid length: 0"),
            ("05", "malformed public key: invalid length: 1"),
            (
                "0311db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
                "invalid public key: unsupported format: 3",
            ),
            (
                "1d2689c7c2dab13309fb143e0e8fe396342521887e976690b6b47f5b2a4b7d448e",
                "invalid public key: unsupported format: 1d",
            ),
            (
                "02fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
                "invalid public key: x >= field prime",
            ),
            (
                "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
                "invalid public key: y >= field prime",
            ),
            (
                "0611db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
                "invalid public key: y oddness does not match specified value of false",
            ),
            (
                "0415db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
                "invalid public key: [15db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c,\
                 b2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3] not on \
                 secp256k1 curve",
            ),
            (
                "03ce0b14fb842b1ba549fdd675c98075f12e9c510f8ef52bd021a9a1f4809d3b4c",
                "invalid public key: x coordinate \
                 ce0b14fb842b1ba549fdd675c98075f12e9c510f8ef52bd021a9a1f4809d3b4c is not on the \
                 secp256k1 curve",
            ),
        ];
        for (key, want) in cases {
            let err = PublicKey::parse(&unhex(key)).expect_err(key);
            assert_eq!(err.to_string(), want, "{key}");
        }
    }

    #[test]
    fn hybrid_parses_to_same_key_as_uncompressed() {
        // The (ybit = 1) hybrid vector above is the same point as the
        // "uncompressed ok" vector; both serializations must agree.
        let uncompressed = PublicKey::parse(&unhex(
            "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
        ))
        .expect("parse uncompressed");
        let hybrid = PublicKey::parse(&unhex(
            "0711db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
        ))
        .expect("parse hybrid");
        assert_eq!(uncompressed, hybrid);
        // Hybrid keys serialize with the standard prefixes, never 0x06/0x07.
        assert_eq!(hybrid.serialize_uncompressed()[0], 0x04);
    }

    /// The decimal digits of a 32-byte big-endian value, by long division.
    // Test-only byte arithmetic: each remainder is below 10, so every
    // intermediate fits in a u32.
    #[allow(clippy::arithmetic_side_effects)]
    fn decimal(v: &[u8; 32]) -> alloc::string::String {
        let mut n = *v;
        let mut digits = alloc::vec::Vec::new();
        while !is_zero(&n) {
            let mut rem = 0u32;
            for b in n.iter_mut() {
                let cur = (rem << 8) | u32::from(*b);
                *b = (cur / 10) as u8;
                rem = cur % 10;
            }
            digits.push(char::from(b'0' + rem as u8));
        }
        if digits.is_empty() {
            digits.push('0');
        }
        digits.iter().rev().collect()
    }

    /// A private key's Debug output names the type and nothing else: no
    /// hex and no decimal rendering of the key, plain or alternate.
    #[test]
    fn debug_prints_no_secret() {
        let mut one = [0u8; 32];
        one[31] = 1;
        let mut random = [0u8; 32];
        let mut rng = dcroxide_testutil::SplitMix64(0x6b32_3536_6b65_7973);
        let random_key = loop {
            rng.fill(&mut random);
            if let Some(key) = PrivateKey::from_bytes(&random) {
                break key;
            }
        };
        let keys = [
            (one, PrivateKey::from_bytes(&one).expect("key 1")),
            (random, random_key),
        ];
        for (bytes, key) in &keys {
            let hex = dcroxide_testutil::hex(bytes);
            let hex_trimmed = hex.trim_start_matches('0');
            let dec = decimal(bytes);
            for shown in [alloc::format!("{key:?}"), alloc::format!("{key:#?}")] {
                assert_eq!(shown, "PrivateKey(..)");
                assert!(!shown.contains(&hex), "{shown}");
                assert!(!shown.contains(hex_trimmed), "{shown}");
                assert!(!shown.contains(&dec), "{shown}");
            }
        }
        assert_eq!(decimal(&one), "1");
    }

    /// A public key's Debug output is its compressed serialization in hex,
    /// however it was parsed.
    #[test]
    fn public_key_debug_is_compressed_hex() {
        let compressed = "0311db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c";
        for key in [
            "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
            "0711db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
            compressed,
        ] {
            let parsed = PublicKey::parse(&unhex(key)).expect(key);
            assert_eq!(
                alloc::format!("{parsed:?}"),
                alloc::format!("PublicKey({compressed})")
            );
            assert_eq!(
                dcroxide_testutil::hex(&parsed.serialize_compressed()),
                compressed
            );
        }
        let even = "02ce0b14fb842b1ba549fdd675c98075f12e9c510f8ef52bd021a9a1f4809d3b4d";
        let parsed = PublicKey::parse(&unhex(even)).expect(even);
        assert_eq!(
            alloc::format!("{parsed:?}"),
            alloc::format!("PublicKey({even})")
        );
    }

    #[test]
    fn prime_minus_order_is_p_minus_n() {
        use k256::U256;
        assert_eq!(
            U256::from_be_slice(&FIELD_PRIME_BYTES)
                .wrapping_sub(&U256::from_be_slice(&GROUP_ORDER_BYTES)),
            U256::from_be_slice(&PRIME_MINUS_ORDER_BYTES)
        );
    }

    /// r + N against crypto-bigint's wrapping addition, at the top of the
    /// domain (P - N - 1, whose sum is P - 1), at 1 and at seeded random
    /// values below P - N.
    #[test]
    fn add_group_order_adds_n() {
        use k256::U256;
        let n = U256::from_be_slice(&GROUP_ORDER_BYTES);
        let adds_n = |r: &[u8; 32]| {
            U256::from_be_slice(&add_group_order(r)) == U256::from_be_slice(r).wrapping_add(&n)
        };

        let mut top = PRIME_MINUS_ORDER_BYTES;
        top[31] -= 1;
        let mut p_minus_1 = FIELD_PRIME_BYTES;
        p_minus_1[31] -= 1;
        assert_eq!(add_group_order(&top), p_minus_1);
        assert!(adds_n(&top));

        let mut one = [0u8; 32];
        one[31] = 1;
        assert!(adds_n(&one));

        let mut rng = dcroxide_testutil::SplitMix64(0x7270_6e5f_6164_6430);
        let mut r = [0u8; 32];
        let mut checked = 0;
        while checked < 256 {
            rng.fill(&mut r);
            // Keep 129 random bits so that most draws fall below P - N.
            r[..15].fill(0);
            r[15] &= 1;
            if r >= PRIME_MINUS_ORDER_BYTES {
                continue;
            }
            assert!(adds_n(&r), "{r:02x?}");
            checked += 1;
        }
    }

    #[test]
    fn negate_mod_n_round_trip() {
        let mut s = [0u8; 32];
        s[31] = 1;
        let neg = negate_mod_n(&s);
        // N - 1, negated again, is 1.
        assert_eq!(negate_mod_n(&neg), s);
        // And N - 1 is one less than the group order.
        let mut want = GROUP_ORDER_BYTES;
        want[31] -= 1;
        assert_eq!(neg, want);
    }
}
