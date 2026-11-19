// SPDX-License-Identifier: ISC
//! secp256k1 public/private keys with dcrd's exact parsing and acceptance
//! rules (mirrors dcrd `dcrec/secp256k1/v4`).

use core::fmt;

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

/// A validated secp256k1 public key: a point on the curve, never the
/// identity, held as dcroxide-secp256k1-vartime's affine point with both
/// coordinates normalized (ADR-0016), built only once dcrd's format, range
/// and oddness checks have passed.
///
/// A public key is public data: `PartialEq` compares x and y, as dcrd's
/// `IsEqual` does, on the normalized limbs and in variable time.
/// `Debug` prints the compressed serialization in hex, not the point's
/// internal limbs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    point: backend::KeyPoint,
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
                // `IsOnCurve`): the seam tests y^2 = x^3 + 7 on
                // dcroxide-secp256k1-vartime (ADR-0016), libsecp256k1's
                // `ge_is_valid_var`, on coordinates already below the
                // prime, so the range errors above keep their own kinds.
                // Its result is never the identity.
                let point = backend::from_coordinates(x, y)
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
        let (x, _) = self.point.to_be_bytes();
        let mut out = [0u8; PUB_KEY_BYTES_LEN_COMPRESSED];
        // 0x02, or 0x03 for an odd y.
        out[0] = PUB_KEY_FORMAT_COMPRESSED_EVEN | u8::from(self.point.y_is_odd());
        out[1..].copy_from_slice(&x);
        out
    }

    /// The 65-byte uncompressed serialization (dcrd `SerializeUncompressed`).
    /// Hybrid-parsed keys serialize with the 0x04 prefix; dcrd never emits
    /// the hybrid format either.
    pub fn serialize_uncompressed(&self) -> [u8; PUB_KEY_BYTES_LEN_UNCOMPRESSED] {
        let (x, y) = self.point.to_be_bytes();
        let mut out = [0u8; PUB_KEY_BYTES_LEN_UNCOMPRESSED];
        out[0] = PUB_KEY_FORMAT_UNCOMPRESSED;
        out[1..33].copy_from_slice(&x);
        out[33..].copy_from_slice(&y);
        out
    }

    /// The key k256 computed for a private key, its finished public point,
    /// entering the key type through the vartime crate's curve check.
    /// `None` only if that check refuses a point k256 computed, a fault in
    /// one of them.
    fn from_k256_point(point: &AffinePoint) -> Option<PublicKey> {
        backend::key_from_k256(point).map(|point| PublicKey { point })
    }
}

/// kG for a secret scalar k, in constant time: every multiplication of the
/// generator by a secret goes through here, the public key from a private
/// key and the nonce point of ECDSA and EC-Schnorr-DCRv0 signing.  dcrd
/// computes these with `ScalarBaseMultNonConst`, in variable time; the
/// point is the same.
///
/// It is k256's `mul_by_generator`.  With the crate's `precomputed-tables`
/// feature, on by default, that walks k256's basepoint table, built once
/// on first use.  A recoding of k that has no branch on k gives 65 signed
/// radix-16 digits; each selects, in constant time, one entry of 33
/// tables of eight precomputed multiples (digit 64 from table 32, digits
/// 2i and 2i+1 from table i).  The 65 entries are summed into two
/// accumulators by 64 additions, the odd-digit one is doubled four
/// times, and one final addition joins them.  Without the feature, as in
/// the no_std build, k256 computes it as `GENERATOR * k`, its
/// constant-time `lincomb`.  Neither
/// branches on k or indexes memory by it; neither wipes the recoding or
/// the intermediate points it leaves on the stack.
///
/// The public paths, verification, recovery and HD derivation's public
/// tweak sum, never come here: they run in variable time on
/// dcroxide-secp256k1-vartime (ADR-0016).
#[must_use]
pub(crate) fn mul_secret_by_generator(k: &Scalar) -> ProjectivePoint {
    ProjectivePoint::mul_by_generator(k)
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
/// [`ReducedPrivateKey::from_bytes`] is dcrd's `PrivKeyFromBytes`, for
/// callers that need its reduction (HD keys).
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

    /// The corresponding public key, dG.  The multiplication is the
    /// crate's `mul_secret_by_generator`, constant time on d (k256's
    /// basepoint table, or its `lincomb` without the `precomputed-tables`
    /// feature), and the scalar copy is wiped; the product is public, and
    /// enters the public key type once, through the vartime crate's curve
    /// check.
    ///
    /// # Panics
    ///
    /// Only if that curve check refuses the point k256 computed, a fault
    /// in one of the two crates: there is no correct key to return then.
    pub fn public_key(&self) -> PublicKey {
        let mut d = Scalar::from(self.inner.as_scalar_value());
        let point = mul_secret_by_generator(&d).to_affine();
        d.zeroize();
        // dG is never the identity for d in [1, N-1], and k256's affine
        // coordinates are below P and on the curve, so only a fault in the
        // vartime crate's curve check, which also guards every uncompressed
        // key parse, could refuse it.  There is no correct key to return
        // without it, so this panics rather than hand back a wrong one, as
        // the signing paths do on their impossible states.
        PublicKey::from_k256_point(&point).expect("k256's dG passes the curve check")
    }

    /// The key's 32 big-endian bytes, wiped when dropped (dcrd's signers
    /// copy the key out with `PutBytes` and zero the copy when done).
    pub(crate) fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.inner.to_bytes().into())
    }

    /// The key's 32 big-endian bytes, leading zeros kept (dcrd's
    /// `PrivateKey.Serialize`), for a caller that stores or encodes the
    /// key, such as an HD key's serialization.  The returned copy is
    /// wiped when dropped; the intermediate encoding k256's `to_bytes`
    /// returns, and stack copies the compiler leaves, are not.  The key's
    /// `Debug` still prints no key material.
    pub fn serialize(&self) -> Zeroizing<[u8; 32]> {
        self.secret_bytes()
    }
}

/// Why 32 bytes are not a usable private scalar: dcrd's
/// `overflow || IsZero` after `ModNScalar.SetByteSlice`, the check
/// hdkeychain makes on a master key (`ErrUnusableSeed`), on the private
/// key of a parsed extended key (`ErrUnusableSeed`) and on a derivation's
/// intermediate key Il (`ErrInvalidChild`).  dcrd reports the two cases
/// alike; they are told apart here only because it costs nothing, the
/// overflow taking precedence, as dcrd's `||` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarError {
    /// The value is at or above the group order N (`SetByteSlice`'s
    /// overflow).
    Overflow,
    /// The value is zero.
    Zero,
}

impl fmt::Display for ScalarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ScalarError::Overflow => "scalar is not below the group order",
            ScalarError::Zero => "scalar is zero",
        })
    }
}

impl core::error::Error for ScalarError {}

/// The scalar of 32 big-endian bytes in [1, N-1], or why it is not one.
/// The range and zero tests are k256's constant-time `from_repr` and
/// `is_zero`; only the verdict is branched on.  The encoding and the
/// scalar this holds are `Zeroizing`, wiped on drop; the copy k256's
/// `from_repr` takes by value, k256's internal copies, and stack copies
/// the compiler leaves when values move are not wiped, so the value can
/// remain in freed stack memory.
fn nonzero_scalar(bytes: &[u8; 32]) -> Result<Zeroizing<Scalar>, ScalarError> {
    use k256::elliptic_curve::PrimeField;
    let repr = Zeroizing::new(FieldBytes::from(*bytes));
    let parsed = Scalar::from_repr(*repr);
    let in_range = parsed.is_some();
    let scalar = Zeroizing::new(parsed.unwrap_or(Scalar::ZERO));
    let zero = scalar.is_zero();
    if !bool::from(in_range) {
        Err(ScalarError::Overflow)
    } else if bool::from(zero) {
        Err(ScalarError::Zero)
    } else {
        Ok(scalar)
    }
}

/// Whether 32 big-endian bytes are a usable private scalar, in [1, N-1]:
/// dcrd's `overflow || IsZero` after `ModNScalar.SetByteSlice`, which
/// hdkeychain's `NewMaster` and `NewKeyFromString` apply to a private key
/// (`ErrUnusableSeed`) and `Child` to Il (`ErrInvalidChild`).  Constant
/// time in the value; only the verdict is branched on.  The `Zeroizing`
/// copies this crate makes are wiped on drop; copies inside k256's
/// `from_repr`, and stack copies the compiler leaves when values move, are
/// not.
///
/// `PrivateKey::from_bytes(b).is_some()` gives the same verdict; this
/// names the case and builds no key.
pub fn check_scalar(bytes: &[u8; 32]) -> Result<(), ScalarError> {
    nonzero_scalar(bytes).map(|_| ())
}

/// Up to 32 big-endian bytes reduced modulo N, as dcrd's
/// `ModNScalar.SetByteSlice` reduces them: a longer slice is truncated to
/// its first 32 bytes, a shorter one left-padded with zeros, and the
/// overflow flag dropped.  Constant time in the bytes' values (the
/// reduction is k256's conditional subtraction).  The padded encoding and
/// the result this holds are `Zeroizing`, wiped on drop; k256's internal
/// copies inside `reduce`, and stack copies the compiler leaves when
/// values move, are not wiped.
fn reduce_slice(bytes: &[u8]) -> Zeroizing<Scalar> {
    use k256::elliptic_curve::ops::Reduce;
    let taken = bytes.get(..32).unwrap_or(bytes);
    let mut repr = Zeroizing::new(FieldBytes::default());
    repr[32usize.saturating_sub(taken.len())..].copy_from_slice(taken);
    Zeroizing::new(<Scalar as Reduce<FieldBytes>>::reduce(&repr))
}

/// A private key as dcrd's `PrivKeyFromBytes` makes one: any value modulo
/// N, zero included.  dcrd's `PrivateKey` holds a `ModNScalar` and takes
/// zero; this crate's [`PrivateKey`] does not, so that every key it signs
/// with is in [1, N-1], and the zero dcrd lets through is a variant of its
/// own here, explicit at every use, rather than a key.
///
/// Why a separate type and not a wider `PrivateKey`: dcrd signs with a
/// zero key (ECDSA then signs for the point at infinity, and never returns
/// over a hash that is zero modulo N, `tools/oracle`'s `ecdsa_sign` notes),
/// behaviour no caller wants reproduced; keeping zero out of `PrivateKey`
/// keeps signing with it impossible, as it has been, and leaves every
/// existing constructor and signer unchanged.  What dcrd does observably
/// with a zero key, outside signing, is serialize it (32 zero bytes,
/// [`serialize`](Self::serialize)) and give its public key, the point at
/// infinity, which `PubKey().SerializeCompressed()` writes as 0x02 and 32
/// zero bytes ([`public_point`](Self::public_point),
/// [`PublicPoint::serialize_compressed`]); both are reproduced here.
///
/// hdkeychain reaches zero two ways: a private child whose sum
/// `Il + parent` is N ([`add_private_tweak`]), and a stored key
/// that is zero, which `pubKeyBytes` passes to `PrivKeyFromBytes`.
///
/// `Debug` prints `Key(PrivateKey(..))` or `Zero`: whether the key is
/// zero, and no other key material.
#[derive(Clone, Debug)]
pub enum ReducedPrivateKey {
    /// A nonzero value, a key in [1, N-1].
    Key(PrivateKey),
    /// Zero: dcrd's zero `ModNScalar`, whose public key is the point at
    /// infinity.
    Zero,
}

impl ReducedPrivateKey {
    /// dcrd's `PrivKeyFromBytes`: at most the first 32 bytes, left-padded
    /// with zeros when shorter, reduced modulo N, zero accepted.  The bytes
    /// are hdkeychain's stored private key, which `Child` strips of its
    /// leading zeros, or an imported key.  Constant time in the bytes'
    /// values; the slice's length is public, and so is whether the
    /// result is zero, the variant.  The encodings and scalar this crate
    /// holds on the way are `Zeroizing`, wiped on drop, and the key wipes
    /// itself when dropped; k256's internal copies inside `reduce` and
    /// `SecretKey::from_bytes`, and stack copies the compiler leaves when
    /// values move, are not wiped, so the bytes can remain in freed stack
    /// memory.
    pub fn from_bytes(bytes: &[u8]) -> ReducedPrivateKey {
        ReducedPrivateKey::from_scalar(&reduce_slice(bytes))
    }

    /// The key of a scalar below N, or `Zero`.  The encoding is
    /// `Zeroizing`, wiped on drop (k256's internal copies are not); k256's
    /// `SecretKey::from_bytes` refuses only zero here, since the scalar is
    /// below N.
    fn from_scalar(scalar: &Scalar) -> ReducedPrivateKey {
        use k256::elliptic_curve::PrimeField;
        let repr = Zeroizing::new(scalar.to_repr());
        match k256::SecretKey::from_bytes(&repr) {
            Ok(inner) => ReducedPrivateKey::Key(PrivateKey { inner }),
            Err(_) => ReducedPrivateKey::Zero,
        }
    }

    /// The value's 32 big-endian bytes, leading zeros kept (dcrd's
    /// `PrivateKey.Serialize`, or `ModNScalar.Bytes`), 32 zero bytes for
    /// `Zero`; wiped when dropped.
    pub fn serialize(&self) -> Zeroizing<[u8; 32]> {
        match self {
            ReducedPrivateKey::Key(key) => key.serialize(),
            ReducedPrivateKey::Zero => Zeroizing::new([0; 32]),
        }
    }

    /// The public point, dG (dcrd's `PubKey`): [`PrivateKey::public_key`],
    /// constant time on d, for a key, and the point at infinity for
    /// `Zero`.  `public_point().serialize_compressed()` is
    /// dcrd's `PrivKeyFromBytes(b).PubKey().SerializeCompressed()`, the
    /// bytes hdkeychain's `pubKeyBytes` gives a private extended key.
    ///
    /// # Panics
    ///
    /// As [`PrivateKey::public_key`] does, only on a fault in k256 or in
    /// dcroxide-secp256k1-vartime's curve check.
    pub fn public_point(&self) -> PublicPoint {
        match self {
            ReducedPrivateKey::Key(key) => PublicPoint::Key(key.public_key()),
            ReducedPrivateKey::Zero => PublicPoint::Infinity,
        }
    }
}

/// A point dcrd's arithmetic can return where a public key is expected: a
/// key, or the point at infinity, which [`PublicKey`] never holds.  dcrd's
/// `ToAffine` turns infinity into (0, 0), which `NewPublicKey` accepts
/// unchecked and `SerializeCompressed` writes as 0x02 and 32 zero bytes;
/// [`serialize_compressed`](Self::serialize_compressed) gives the same
/// bytes.  Those bytes do not parse back: x = 0 is on no point, so
/// [`PublicKey::parse`] refuses them with `ErrPubKeyNotOnCurve`, as dcrd's
/// `ParsePubKey` does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicPoint {
    /// A public key.
    Key(PublicKey),
    /// The point at infinity.
    Infinity,
}

impl PublicPoint {
    /// The 33-byte compressed serialization dcrd gives the point:
    /// [`PublicKey::serialize_compressed`] for a key, and 0x02 followed by
    /// 32 zero bytes for infinity.
    pub fn serialize_compressed(&self) -> [u8; PUB_KEY_BYTES_LEN_COMPRESSED] {
        match self {
            PublicPoint::Key(key) => key.serialize_compressed(),
            PublicPoint::Infinity => {
                let mut out = [0u8; PUB_KEY_BYTES_LEN_COMPRESSED];
                out[0] = PUB_KEY_FORMAT_COMPRESSED_EVEN;
                out
            }
        }
    }
}

/// The private child's key of HD derivation, `(Il + parent) mod N`
/// (hdkeychain's `Child` on a private key, `extendedkey.go:278` and
/// `:298-302`), constant time in both values.
///
/// `tweak` is Il, which must be in [1, N-1]: else `Err`, the `overflow ||
/// IsZero` for which hdkeychain returns `ErrInvalidChild`.  `parent` is
/// reduced exactly as [`ReducedPrivateKey::from_bytes`] reduces a slice
/// (dcrd's `SetByteSlice`, overflow ignored), so hdkeychain's stored key,
/// stripped of leading zeros or not, and zero included, is passed as
/// stored.  The sum is k256's constant-time addition modulo N.
///
/// What is wiped: the `Zeroizing` scalars and encodings this crate holds
/// (Il's, the parent's and the sum's) are wiped on drop, and the returned
/// key wipes itself.  What is not: the copies k256 makes inside
/// `from_repr`, `reduce` and the addition, and stack copies the compiler
/// leaves when values move, so Il and the parent can remain in freed stack
/// memory.
///
/// A sum of zero, `Il = N - parent`, is not an error: it is
/// [`ReducedPrivateKey::Zero`], since dcrd's `Child` returns that key
/// (stripped to an empty key by the Decred variant, 32 zero bytes by
/// `ChildBIP32Std`), and what to do with it is the caller's to decide.
/// Whether the sum is zero is the one fact about it the result's variant
/// shows.
pub fn add_private_tweak(
    tweak: &[u8; 32],
    parent: &[u8],
) -> Result<ReducedPrivateKey, ScalarError> {
    let tweak = nonzero_scalar(tweak)?;
    let parent = reduce_slice(parent);
    // k256's addition modulo N, constant time.
    #[allow(clippy::arithmetic_side_effects)]
    let sum = Zeroizing::new(*tweak + *parent);
    Ok(ReducedPrivateKey::from_scalar(&sum))
}

/// The public child's key of HD derivation, `Il*G + parent` (hdkeychain's
/// `Child` on a public key, `extendedkey.go:278` and `:317-341`), on public
/// values and in variable time, as dcrd computes it with
/// `ScalarBaseMultNonConst` and `AddNonConst`.
///
/// `tweak` is Il, which must be in [1, N-1]: else `Err`, the `overflow ||
/// IsZero` for which hdkeychain returns `ErrInvalidChild`.  The range check
/// is [`check_scalar`]'s, made before any point arithmetic, so hdkeychain's
/// order, Il's check before the parent key's parse, is kept by a caller
/// that calls [`check_scalar`] on Il before [`PublicKey::parse`] on the
/// parent, or this with a parent already parsed.
///
/// hdkeychain's second check, that `Il*G` has no zero coordinate after
/// `ToAffine`, never fires for Il in [1, N-1]: `Il*G` is then a point of
/// the group, never infinity, and no point has x = 0 (7 is not a square
/// modulo P) or y = 0 (the group's order is odd).  So it has no outcome of
/// its own here.  A sum at infinity, `parent = -Il*G`, is not an error:
/// it is [`PublicPoint::Infinity`], since dcrd's `Child` returns the key
/// 0x02 and 32 zero bytes for it, which the caller gets from
/// [`PublicPoint::serialize_compressed`].
///
/// The sum is dcroxide-secp256k1-vartime's Straus loop, `ecmult_var`,
/// computing 1*parent + Il*G with the parent as the crate's affine point,
/// and the result's affine coordinates by one field inversion, normalized
/// as dcrd's `ToAffine` does; k256's combined multiply is the fallback
/// should the vartime crate decline (ADR-0016), and builds with debug
/// assertions compute both and require the same answer.
///
/// # Security
///
/// Both inputs are treated as public and are computed on in variable
/// time: on the vartime crate's path, and with k256's
/// `mul_by_generator_and_mul_add_vartime` on the fallback and in builds
/// with debug assertions.  Timing can leak them.  The only tweak this may
/// be given is the Il of a non-hardened child of an extended public key,
/// HMAC-SHA512 over the chain code, the public key and the index: data the
/// extended public key already gives away.  Never pass a secret: not a
/// hardened child's Il, and not any private key or scalar.  For a child of
/// a private extended key, hardened or not, use [`add_private_tweak`].
///
/// # Panics
///
/// Only if the vartime crate declines and k256's answer then fails the
/// key type's curve check, two independent faults: there is no correct key
/// to return, as for [`PrivateKey::public_key`].
pub fn add_public_tweak(tweak: &[u8; 32], parent: &PublicKey) -> Result<PublicPoint, ScalarError> {
    check_scalar(tweak)?;
    Ok(backend::add_tweak(tweak, parent)
        .expect("the tweak sum passes the curve check: k256 refused, after a decline"))
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

    /// a - b, big-endian, for a >= b.
    // Test-only byte arithmetic: each digit difference fits an i16.
    #[allow(clippy::arithmetic_side_effects)]
    fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = i16::from(a[i]) - i16::from(b[i]) - borrow;
            out[i] = d.rem_euclid(256) as u8;
            borrow = i16::from(d < 0);
        }
        assert_eq!(borrow, 0);
        out
    }

    /// The private key of 32 seeded bytes, retried until they are a key.
    fn seeded_key(rng: &mut dcroxide_testutil::SplitMix64) -> PrivateKey {
        loop {
            let mut d = [0u8; 32];
            rng.fill(&mut d);
            if let Some(key) = PrivateKey::from_bytes(&d) {
                return key;
            }
        }
    }

    /// k256's dG for a private key, by its own constant-time multiply.
    // The flagged operator is k256 point multiplication.
    #[allow(clippy::arithmetic_side_effects)]
    fn k256_point(key: &PrivateKey) -> AffinePoint {
        (ProjectivePoint::GENERATOR * Scalar::from(key.inner.as_scalar_value())).to_affine()
    }

    /// lambda, the endomorphism's scalar, big-endian: lambda*(x, y) is
    /// (beta*x, y), another point with the same y.
    const LAMBDA: [u8; 32] = [
        0x53, 0x63, 0xad, 0x4c, 0xc0, 0x5c, 0x30, 0xe0, 0xa5, 0x26, 0x1c, 0x02, 0x88, 0x12, 0x64,
        0x5a, 0x12, 0x2e, 0x22, 0xea, 0x20, 0x81, 0x66, 0x78, 0xdf, 0x02, 0x96, 0x7c, 0x1b, 0x23,
        0xbd, 0x72,
    ];

    /// Public key equality is point equality, however the key was made:
    /// `public_key`, its compressed, uncompressed and hybrid encodings
    /// parsed, and k256's own SEC1 encodings of dG parsed all give one
    /// key; the negation (same x) and the endomorphism's image (same y)
    /// give others; and over every pair, `==` holds exactly when the
    /// uncompressed serializations are equal.
    #[test]
    fn equality_is_point_equality() {
        use k256::elliptic_curve::PrimeField;
        use k256::elliptic_curve::sec1::ToSec1Point;
        let mut rng = dcroxide_testutil::SplitMix64(0x6571_7561_6c69_7479);
        let lambda = Option::<Scalar>::from(Scalar::from_repr(LAMBDA.into())).expect("below N");
        let mut keys = alloc::vec::Vec::new();
        for _ in 0..64 {
            let key = seeded_key(&mut rng);
            let pk = key.public_key();
            let c = pk.serialize_compressed();
            let u = pk.serialize_uncompressed();
            let mut h = u;
            h[0] = PUB_KEY_FORMAT_HYBRID_EVEN | (u[64] & 1);
            let k = k256_point(&key);
            let (kc, ku) = (k.to_sec1_point(true), k.to_sec1_point(false));
            for enc in [&c[..], &u[..], &h[..], kc.as_bytes(), ku.as_bytes()] {
                assert_eq!(
                    PublicKey::parse(enc),
                    Ok(pk),
                    "{}",
                    dcroxide_testutil::hex(enc)
                );
            }

            let mut neg = u;
            let y: [u8; 32] = u[33..].try_into().expect("32 bytes");
            neg[33..].copy_from_slice(&sub_be(&FIELD_PRIME_BYTES, &y));
            let neg = PublicKey::parse(&neg).expect("the negation is on the curve");
            assert_ne!(neg, pk);
            assert_eq!(neg.serialize_compressed()[1..], c[1..]);

            let d = Scalar::from(key.inner.as_scalar_value());
            #[allow(clippy::arithmetic_side_effects)] // k256 scalar product mod N
            let beta_key = PrivateKey::from_bytes(&(d * lambda).to_repr().into())
                .expect("nonzero")
                .public_key();
            assert_ne!(beta_key, pk);
            assert_eq!(beta_key.serialize_uncompressed()[33..], u[33..]);
            keys.extend([pk, neg, beta_key]);
        }
        for (i, a) in keys.iter().enumerate() {
            for b in &keys[i..] {
                assert_eq!(
                    a == b,
                    a.serialize_uncompressed() == b.serialize_uncompressed(),
                    "{a:?} {b:?}"
                );
            }
        }
    }

    /// Both serializations equal k256's SEC1 encodings of dG for 1,024
    /// seeded keys and for d = 1 and N - 1, and each parses back to the
    /// same key.
    #[test]
    fn serialization_matches_k256_for_random_keys() {
        use k256::elliptic_curve::sec1::ToSec1Point;
        let mut rng = dcroxide_testutil::SplitMix64(0x7365_7269_616c_697a);
        let mut one = [0u8; 32];
        one[31] = 1;
        let n_minus_1 = negate_mod_n(&one);
        let mut keys: alloc::vec::Vec<PrivateKey> = [one, n_minus_1]
            .iter()
            .map(|d| PrivateKey::from_bytes(d).expect("a key"))
            .collect();
        while keys.len() < 1026 {
            keys.push(seeded_key(&mut rng));
        }
        for key in &keys {
            let pk = key.public_key();
            let k = k256_point(key);
            let (c, u) = (pk.serialize_compressed(), pk.serialize_uncompressed());
            assert_eq!(&c[..], k.to_sec1_point(true).as_bytes());
            assert_eq!(&u[..], k.to_sec1_point(false).as_bytes());
            assert_eq!(PublicKey::parse(&c), Ok(pk));
            assert_eq!(PublicKey::parse(&u), Ok(pk));
        }
    }

    /// Hybrid keys are checked in dcrd's order: x's range, y's range, y's
    /// parity against the format byte, then the curve, so the parity
    /// error comes before the curve's and after both range errors, with
    /// dcrd's text for each.
    #[test]
    fn hybrid_checks_run_in_dcrds_order() {
        // dcrd's "uncompressed ok" vector, whose y is odd.
        let x = "11db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c";
        let y = "b2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3";
        // y + 1, even and not on the curve.
        let y1 = "b2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a4";
        let p = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
        let p1 = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30";
        let key = |format: &str, x: &str, y: &str| {
            PublicKey::parse(&unhex(&alloc::format!("{format}{x}{y}")))
        };
        let text = |r: Result<PublicKey, Error>| r.map(|_| ()).map_err(|e| e.to_string());

        let good = key("04", x, y).expect("dcrd's vector");
        assert_eq!(key("07", x, y), Ok(good));
        assert_eq!(key("06", x, y), Err(Error::PubKeyMismatchedOddness(false)));
        assert_eq!(
            text(key("06", x, y)),
            Err("invalid public key: y oddness does not match specified value of false".into())
        );

        // Off the curve: the right parity reaches the curve check, the
        // wrong one stops at the parity.
        let off = alloc::format!("invalid public key: [{x},{y1}] not on secp256k1 curve");
        for format in ["04", "06"] {
            assert!(matches!(
                key(format, x, y1),
                Err(Error::PubKeyNotOnCurve { y: Some(_), .. })
            ));
            assert_eq!(text(key(format, x, y1)), Err(off.clone()));
        }
        assert_eq!(key("07", x, y1), Err(Error::PubKeyMismatchedOddness(true)));

        // y at or above P, either parity: y's range first.
        for (format, yy) in [("06", p), ("07", p), ("06", p1), ("07", p1), ("04", p1)] {
            assert_eq!(
                key(format, x, yy),
                Err(Error::PubKeyYTooBig),
                "{format} {yy}"
            );
        }
        // x at or above P: x's range before everything else.
        for format in ["04", "06", "07"] {
            for (xx, yy) in [(p, p), (p1, p1), (p, y), (p1, y1)] {
                assert_eq!(
                    key(format, xx, yy),
                    Err(Error::PubKeyXTooBig),
                    "{format} {xx} {yy}"
                );
            }
        }
    }

    /// Two keys whose coordinates differ only in y's lowest 52-bit limb
    /// are unequal: (x, y) and its negation for y = (P - 1) / 2 - 2, the
    /// first y below (P - 1) / 2 with a point, so y and P - y differ by 5
    /// and share their top 204 bits.  An equality that skipped a limb,
    /// which random keys never notice, fails here.
    #[test]
    fn keys_differing_in_one_limb_are_unequal() {
        let x = "8a369db2d6ecfaa666514299e447165e31fba21f0b2c3c1d5a0fc77c3e150672";
        let y_odd = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe15";
        let y_even = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe1a";
        let key = |s: alloc::string::String| PublicKey::parse(&unhex(&s)).expect("on the curve");
        let odd = key(alloc::format!("04{x}{y_odd}"));
        let even = key(alloc::format!("04{x}{y_even}"));
        assert_ne!(odd, even);
        assert_eq!(odd, key(alloc::format!("03{x}")));
        assert_eq!(even, key(alloc::format!("02{x}")));
        assert_eq!(odd, key(alloc::format!("07{x}{y_odd}")));
        assert_eq!(even, key(alloc::format!("06{x}{y_even}")));
    }

    /// The secret paths' multiply, k256's basepoint table under the
    /// default `precomputed-tables` feature, gives the point k256's plain
    /// constant-time `GENERATOR * k` (`lincomb`, no table) gives, over
    /// scalars aimed at the table walk and over random ones.  The table
    /// walk recodes k into 65 signed radix-16 digits in [-8, 8), with a
    /// carry out of each nibble of 8 or more; the edge scalars are those
    /// where the recoding or the walk could go wrong: 0 (refused before it
    /// reaches here, but the walk must still give the identity), 1 to 64
    /// and N - 1 to N - 64 (checked also against repeated addition, which
    /// uses no multiply), every power of two and every 2^i - 1 (reduced
    /// mod N past 255 bits), each byte value repeated over all 32 bytes
    /// (0x88... and 0x77... carry through every digit or none), and
    /// (N - 1) / 2 and its neighbours, the low-S boundary.  Then 4,096
    /// random scalars, a quarter of them with the top bit forced on.
    /// Without the feature both sides are `lincomb` and the test is
    /// trivially true; the no_std build's arithmetic is what it was.
    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn mul_secret_by_generator_matches_the_plain_multiply() {
        use k256::elliptic_curve::ops::Reduce;
        let reduce = |b: [u8; 32]| <Scalar as Reduce<FieldBytes>>::reduce(&b.into());
        let check = |k: &Scalar, what: &dyn fmt::Display| {
            let table = mul_secret_by_generator(k).to_affine();
            let plain = (ProjectivePoint::GENERATOR * *k).to_affine();
            assert_eq!(table, plain, "kG differs for {what}");
        };

        // 0, and 1..=64 and N - 1..=N - 64 against repeated addition.
        assert_eq!(
            mul_secret_by_generator(&Scalar::ZERO),
            ProjectivePoint::IDENTITY,
            "0G is the identity"
        );
        check(&Scalar::ZERO, &"0");
        let mut sum = ProjectivePoint::IDENTITY;
        for j in 1u64..=64 {
            sum += ProjectivePoint::GENERATOR;
            let k = Scalar::from(j);
            assert_eq!(mul_secret_by_generator(&k), sum, "{j}G by addition");
            assert_eq!(mul_secret_by_generator(&-k), -sum, "(N - {j})G by addition");
            check(&k, &j);
            check(&-k, &alloc::format!("N - {j}"));
        }

        // Every 2^i and 2^i - 1 (the latter reduced mod N from i = 256).
        for i in 0..256usize {
            let mut b = [0u8; 32];
            b[31 - i / 8] = 1 << (i % 8);
            check(&reduce(b), &alloc::format!("2^{i}"));
            let mut m = [0u8; 32];
            for bit in 0..i {
                m[31 - bit / 8] |= 1 << (bit % 8);
            }
            check(&reduce(m), &alloc::format!("2^{i} - 1"));
        }
        check(&reduce([0xff; 32]), &"2^256 - 1 mod N");

        // Each byte value over all 32 bytes, reduced mod N.
        for v in 0..=255u8 {
            check(&reduce([v; 32]), &alloc::format!("{v:#04x} repeated"));
        }

        // (N - 1) / 2, the largest low S, and its neighbours.
        let half = reduce(HALF_GROUP_ORDER);
        for (k, what) in [
            (half - Scalar::ONE, "(N - 1) / 2 - 1"),
            (half, "(N - 1) / 2"),
            (half + Scalar::ONE, "(N + 1) / 2"),
            (half + Scalar::from(2u64), "(N + 3) / 2"),
        ] {
            check(&k, &what);
        }

        // Random scalars, a quarter with the top bit on.
        let mut rng = dcroxide_testutil::SplitMix64::from_entropy("mul_secret_by_generator");
        for n in 0..4096u32 {
            let mut b = [0u8; 32];
            rng.fill(&mut b);
            if n % 4 == 0 {
                b[0] |= 0x80;
            }
            let k = reduce(b);
            check(&k, &alloc::format!("random case {n}, {k:?}"));
        }
    }

    /// The public key type keeps the traits its users rely on: copying,
    /// equality, `Debug`, and sharing between threads.
    #[test]
    fn public_key_type_keeps_its_traits() {
        fn traits<T: Copy + Eq + Send + Sync + core::fmt::Debug>() {}
        traits::<PublicKey>();
    }

    /// In release the key is no larger than k256's affine point, which it
    /// replaced.  On 64-bit targets both are two coordinates of five
    /// 64-bit limbs and an infinity flag, so the sizes are equal; builds
    /// with debug assertions add the field's bookkeeping.
    #[cfg(not(debug_assertions))]
    #[test]
    fn public_key_is_no_larger_than_k256s_point() {
        assert!(core::mem::size_of::<PublicKey>() <= core::mem::size_of::<AffinePoint>());
    }
}
