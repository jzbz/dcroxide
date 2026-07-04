// SPDX-License-Identifier: ISC
//! secp256k1 public/private keys with dcrd's exact parsing and acceptance
//! rules (mirrors dcrd `dcrec/secp256k1/v4`).

use core::fmt;

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

/// Public key parsing errors, 1:1 with dcrd `secp256k1.ErrorKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Wrong overall length (`ErrPubKeyInvalidLen`).
    PubKeyInvalidLen,
    /// Unsupported format byte for the given length (`ErrPubKeyInvalidFormat`).
    PubKeyInvalidFormat,
    /// X coordinate >= field prime (`ErrPubKeyXTooBig`).
    PubKeyXTooBig,
    /// Y coordinate >= field prime (`ErrPubKeyYTooBig`).
    PubKeyYTooBig,
    /// Point is not on the secp256k1 curve (`ErrPubKeyNotOnCurve`).
    PubKeyNotOnCurve,
    /// Hybrid key Y oddness does not match its format byte
    /// (`ErrPubKeyMismatchedOddness`).
    PubKeyMismatchedOddness,
}

impl Error {
    /// The dcrd error kind name, used for differential comparison.
    pub fn kind_name(self) -> &'static str {
        match self {
            Error::PubKeyInvalidLen => "ErrPubKeyInvalidLen",
            Error::PubKeyInvalidFormat => "ErrPubKeyInvalidFormat",
            Error::PubKeyXTooBig => "ErrPubKeyXTooBig",
            Error::PubKeyYTooBig => "ErrPubKeyYTooBig",
            Error::PubKeyNotOnCurve => "ErrPubKeyNotOnCurve",
            Error::PubKeyMismatchedOddness => "ErrPubKeyMismatchedOddness",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Error::PubKeyInvalidLen => "malformed public key: invalid length",
            Error::PubKeyInvalidFormat => "invalid public key: unsupported format",
            Error::PubKeyXTooBig => "invalid public key: x >= field prime",
            Error::PubKeyYTooBig => "invalid public key: y >= field prime",
            Error::PubKeyNotOnCurve => "invalid public key: not on secp256k1 curve",
            Error::PubKeyMismatchedOddness => {
                "invalid public key: y oddness does not match specified value"
            }
        };
        f.write_str(s)
    }
}

impl core::error::Error for Error {}

/// A validated secp256k1 public key (always a point on the curve).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    inner: libsecp256k1::PublicKey,
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
                    _ => return Err(Error::PubKeyInvalidFormat),
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
                        return Err(Error::PubKeyMismatchedOddness);
                    }
                }

                // Remaining failure mode is an off-curve point; libsecp256k1
                // validates that (it accepts all three formats).
                let inner = libsecp256k1::PublicKey::from_slice(serialized)
                    .map_err(|_| Error::PubKeyNotOnCurve)?;
                Ok(PublicKey { inner })
            }
            PUB_KEY_BYTES_LEN_COMPRESSED => {
                let format = serialized[0];
                if format != PUB_KEY_FORMAT_COMPRESSED_EVEN
                    && format != PUB_KEY_FORMAT_COMPRESSED_ODD
                {
                    return Err(Error::PubKeyInvalidFormat);
                }
                let x: &[u8; 32] = serialized[1..33].try_into().expect("32 bytes");
                if *x >= FIELD_PRIME_BYTES {
                    return Err(Error::PubKeyXTooBig);
                }

                // Decompression fails iff there is no curve point with this
                // X coordinate.
                let inner = libsecp256k1::PublicKey::from_slice(serialized)
                    .map_err(|_| Error::PubKeyNotOnCurve)?;
                Ok(PublicKey { inner })
            }
            _ => Err(Error::PubKeyInvalidLen),
        }
    }

    /// The 33-byte compressed serialization (dcrd `SerializeCompressed`).
    pub fn serialize_compressed(&self) -> [u8; PUB_KEY_BYTES_LEN_COMPRESSED] {
        self.inner.serialize()
    }

    /// The 65-byte uncompressed serialization (dcrd `SerializeUncompressed`).
    /// Hybrid-parsed keys serialize with the 0x04 prefix; dcrd never emits
    /// the hybrid format either.
    pub fn serialize_uncompressed(&self) -> [u8; PUB_KEY_BYTES_LEN_UNCOMPRESSED] {
        self.inner.serialize_uncompressed()
    }

    pub(crate) fn inner(&self) -> &libsecp256k1::PublicKey {
        &self.inner
    }

    /// The key as a k256 projective point (for the Schnorr-DCRv0 math,
    /// which needs raw group operations per ADR-0006).
    pub(crate) fn as_k256_point(&self) -> k256::ProjectivePoint {
        let compressed = self.inner.serialize();
        k256::PublicKey::from_sec1_bytes(&compressed)
            .expect("PublicKey is always a valid curve point")
            .to_projective()
    }
}

/// A secp256k1 private key in the range `[1, N-1]`.
///
/// Note: dcrd's `PrivKeyFromBytes` silently reduces out-of-range values mod
/// N; this constructor rejects them instead. The daemon's consensus paths
/// never construct private keys from untrusted bytes, so the difference is
/// not an observable-compatibility surface (tracked in `PARITY.md`).
#[derive(Debug, Clone)]
pub struct PrivateKey {
    inner: libsecp256k1::SecretKey,
}

impl PrivateKey {
    /// Construct from 32 big-endian bytes; `None` if zero or >= N.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<PrivateKey> {
        let inner = libsecp256k1::SecretKey::from_slice(bytes).ok()?;
        Some(PrivateKey { inner })
    }

    /// The corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.public_key(libsecp256k1::SECP256K1),
        }
    }

    pub(crate) fn inner(&self) -> &libsecp256k1::SecretKey {
        &self.inner
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
            want: Result<(), Error>,
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
                want: Err(Error::PubKeyNotOnCurve),
            },
            Case {
                name: "uncompressed y changed (not on curve)",
                key: "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a4",
                want: Err(Error::PubKeyNotOnCurve),
            },
            Case {
                name: "uncompressed claims compressed",
                key: "0311db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
                want: Err(Error::PubKeyInvalidFormat),
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
                want: Err(Error::PubKeyMismatchedOddness),
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
                want: Err(Error::PubKeyInvalidFormat),
            },
            Case {
                name: "compressed claims uncompressed (ybit = 1)",
                key: "042689c7c2dab13309fb143e0e8fe396342521887e976690b6b47f5b2a4b7d448e",
                want: Err(Error::PubKeyInvalidFormat),
            },
            Case {
                name: "compressed claims hybrid (ybit = 0)",
                key: "06ce0b14fb842b1ba549fdd675c98075f12e9c510f8ef52bd021a9a1f4809d3b4d",
                want: Err(Error::PubKeyInvalidFormat),
            },
            Case {
                name: "compressed claims hybrid (ybit = 1)",
                key: "072689c7c2dab13309fb143e0e8fe396342521887e976690b6b47f5b2a4b7d448e",
                want: Err(Error::PubKeyInvalidFormat),
            },
            Case {
                name: "compressed with invalid x coord (ybit = 0)",
                key: "03ce0b14fb842b1ba549fdd675c98075f12e9c510f8ef52bd021a9a1f4809d3b4c",
                want: Err(Error::PubKeyNotOnCurve),
            },
            Case {
                name: "compressed with invalid x coord (ybit = 1)",
                key: "032689c7c2dab13309fb143e0e8fe396342521887e976690b6b47f5b2a4b7d448d",
                want: Err(Error::PubKeyNotOnCurve),
            },
            Case {
                name: "empty",
                key: "",
                want: Err(Error::PubKeyInvalidLen),
            },
            Case {
                name: "wrong length",
                key: "05",
                want: Err(Error::PubKeyInvalidLen),
            },
            Case {
                name: "uncompressed x == p",
                key: "04fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
                want: Err(Error::PubKeyXTooBig),
            },
            Case {
                name: "uncompressed x > p (p + 1 -- aka 1)",
                key: "04fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30bde70df51939b94c9c24979fa7dd04ebd9b3572da7802290438af2a681895441",
                want: Err(Error::PubKeyXTooBig),
            },
            Case {
                name: "uncompressed y == p",
                key: "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
                want: Err(Error::PubKeyYTooBig),
            },
            Case {
                name: "uncompressed y > p (p + 1 -- aka 1)",
                key: "041fe1e5ef3fceb5c135ab7741333ce5a6e80d68167653f6b2b24bcbcfaaaff507fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30",
                want: Err(Error::PubKeyYTooBig),
            },
            Case {
                name: "compressed x == p (ybit = 0)",
                key: "02fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
                want: Err(Error::PubKeyXTooBig),
            },
            Case {
                name: "compressed x == p (ybit = 1)",
                key: "03fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
                want: Err(Error::PubKeyXTooBig),
            },
            Case {
                name: "compressed x > p (p + 2 -- aka 2) (ybit = 0)",
                key: "02fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc31",
                want: Err(Error::PubKeyXTooBig),
            },
            Case {
                name: "compressed x > p (p + 1 -- aka 1) (ybit = 1)",
                key: "03fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30",
                want: Err(Error::PubKeyXTooBig),
            },
            Case {
                name: "hybrid x == p (ybit = 1)",
                key: "07fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
                want: Err(Error::PubKeyXTooBig),
            },
            Case {
                name: "hybrid x > p (p + 1 -- aka 1) (ybit = 0)",
                key: "06fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30bde70df51939b94c9c24979fa7dd04ebd9b3572da7802290438af2a681895441",
                want: Err(Error::PubKeyXTooBig),
            },
            Case {
                name: "hybrid y == p (ybit = 0 when mod p)",
                key: "0611db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
                want: Err(Error::PubKeyYTooBig),
            },
            Case {
                name: "hybrid y > p (p + 1 -- aka 1) (ybit = 1 when mod p)",
                key: "071fe1e5ef3fceb5c135ab7741333ce5a6e80d68167653f6b2b24bcbcfaaaff507fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30",
                want: Err(Error::PubKeyYTooBig),
            },
        ];

        for case in &cases {
            let got = PublicKey::parse(&unhex(case.key)).map(|_| ());
            assert_eq!(got, case.want, "{}", case.name);
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
