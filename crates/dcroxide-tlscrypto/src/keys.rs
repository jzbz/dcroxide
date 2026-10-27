// SPDX-License-Identifier: ISC
//! Go's `parsePrivateKey` (`crypto/tls/tls.go:366-383`), which
//! `tls.X509KeyPair` reads the key of an `rpc.key` with: PKCS#1, then
//! PKCS#8, then SEC 1, on the raw DER, whatever PEM block it came from.
//! A key that none of the three reads is Go's "tls: failed to parse
//! private key".
//!
//! Each of the three is Go's `crypto/x509` parser as `asn1.Unmarshal`
//! reads its structure ([`crate::der`]), with Go's checks after it:
//!
//! * **PKCS#1** (`crypto/x509/pkcs1.go:15-27`, `:54-72`): version, N, E,
//!   D, P and Q, each an INTEGER, the version and E fitting an `int`;
//!   then Dp, Dq and Qinv, each only if the next element is an INTEGER;
//!   then, if the next element is a SEQUENCE, the additional primes, each
//!   a SEQUENCE of three INTEGERs.  Nothing may follow the key, and its
//!   version may not exceed 1, though it may be negative.  The values
//!   are not checked further: a key with that structure is RSA, which
//!   this provider does not sign with (ADR-0015, T6), and is refused
//!   with its own text whether or not Go's `Validate` would pass it.
//! * **PKCS#8** (`crypto/x509/pkcs8.go:21-95`): a version Go does not
//!   look at, an algorithm identifier and the key's OCTET STRING, later
//!   elements ignored.  `rsaEncryption` holds a PKCS#1 key;
//!   `id-ecPublicKey` a SEC 1 key, on the curve the parameters name when
//!   they read as an OBJECT IDENTIFIER, which then wins over any curve
//!   inside; `id-Ed25519` the 32-byte seed in an OCTET STRING, with no
//!   parameters; and `id-X25519`, with no parameters and 32 bytes, a key
//!   Go reads and `crypto/tls` refuses as "tls: found unknown private key
//!   type in PKCS#8 wrapping".  Any other algorithm is a parse failure.
//! * **SEC 1** (`crypto/x509/sec1.go:26-31`, `:87-130`): version 1, the
//!   scalar's OCTET STRING, then an optional `[0]` curve and `[1]` public
//!   key, read as Go reads explicitly tagged fields ([`crate::der`]): a
//!   `[0]` or `[1]` holding an element of another type is absent, so a key
//!   whose `[0]` holds no OBJECT IDENTIFIER names no curve of its own,
//!   while an identifier or a BIT STRING there that does not read fails
//!   the key.  The public key is not compared with the scalar, as Go does
//!   not compare it.  The curve is P-256, P-384 or P-521, or P-224, which
//!   Go loads and this provider refuses with its own text, as ring did,
//!   where Go would load the scalar.  The scalar loses leading zero bytes
//!   while it is longer than the curve's order, any other excess byte
//!   failing, is left-padded when shorter, and must then be in `[1, n)`
//!   (`crypto/ecdsa/ecdsa.go:246-270`).
//!
//! The three shapes differ in their second element, an INTEGER, a
//! SEQUENCE or an OCTET STRING, so at most one of them reads any input;
//! the order is Go's all the same.  `tests/go_differential.rs` holds the
//! verdicts to Go's `tls.X509KeyPair` on a corpus of keys mutated in each
//! of these rules.
//!
//! The scalar and the seed are copied out of the input into buffers that
//! are wiped when dropped; the key types they become wipe themselves.

use zeroize::Zeroizing;

use crate::der::{
    self, BIT_STRING, INTEGER, Malformed, OBJECT_IDENTIFIER, OCTET_STRING, Reader, SEQUENCE,
};

/// `rsaEncryption`, 1.2.840.113549.1.1.1.
const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// `id-ecPublicKey`, 1.2.840.10045.2.1.
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// `id-Ed25519`, 1.3.101.112.
const ED25519: &[u8] = &[0x2b, 0x65, 0x70];
/// `id-X25519`, 1.3.101.110.
const X25519: &[u8] = &[0x2b, 0x65, 0x6e];
/// `secp224r1`, 1.3.132.0.33.
const P224: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x21];
/// `prime256v1`, 1.2.840.10045.3.1.7.
const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// `secp384r1`, 1.3.132.0.34.
const P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
/// `secp521r1`, 1.3.132.0.35.
const P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];

/// P-224's order, big-endian (`crypto/elliptic/nistec.go:23`).
const P224_ORDER: [u8; 28] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x16, 0xa2,
    0xe0, 0xb8, 0xf0, 0x3e, 0x13, 0xdd, 0x29, 0x45, 0x5c, 0x5c, 0x2a, 0x3d,
];

/// A key Go's `parsePrivateKey` reads, of a type this provider knows.
pub(crate) enum ParsedKey {
    /// An ECDSA key on P-256.
    EcdsaP256(p256::ecdsa::SigningKey),
    /// An ECDSA key on P-384.
    EcdsaP384(p384::ecdsa::SigningKey),
    /// An ECDSA key on P-521.
    EcdsaP521(p521::ecdsa::SigningKey),
    /// An Ed25519 key: its seed, wiped when dropped.
    Ed25519(Zeroizing<[u8; 32]>),
    /// An RSA key, read for its structure alone.
    Rsa,
}

/// Why a key is not a [`ParsedKey`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KeyError {
    /// None of Go's three parsers reads it.
    Unparsable,
    /// A PKCS#8 X25519 key, which Go reads and `crypto/tls` refuses.
    UnknownPkcs8Type,
    /// A P-224 key, which Go loads and this provider does not sign with.
    P224,
}

/// What one of Go's parsers made of a key it read.
type Read = Result<ParsedKey, KeyError>;

/// `der` as Go's `parsePrivateKey` reads it.
pub(crate) fn parse(der: &[u8]) -> Read {
    if pkcs1(der).is_ok() {
        return Ok(ParsedKey::Rsa);
    }
    if let Ok(read) = pkcs8(der) {
        return read;
    }
    sec1(None, der).unwrap_or(Err(KeyError::Unparsable))
}

/// Go's `ParsePKCS1PrivateKey`, as far as the key's structure: the key
/// is RSA when this returns `Ok`.
fn pkcs1(der: &[u8]) -> Result<(), Malformed> {
    let mut top = Reader::new(der);
    let key = top.field(SEQUENCE)?;
    if !top.rest().is_empty() {
        // Go's "trailing data" (`crypto/x509/pkcs1.go:56-58`).
        return Err(Malformed);
    }
    let mut fields = Reader::new(key);
    let version = der::int64(fields.field(INTEGER)?)?;
    big(fields.field(INTEGER)?)?;
    der::int64(fields.field(INTEGER)?)?;
    for _ in 0..3 {
        // D, P and Q.
        big(fields.field(INTEGER)?)?;
    }
    for _ in 0..3 {
        // Dp, Dq and Qinv, each tried on the same next element when the
        // one before it is absent.
        if let Some(value) = fields.optional(INTEGER)? {
            big(value)?;
        }
    }
    if let Some(primes) = fields.optional(SEQUENCE)? {
        let mut primes = Reader::new(primes);
        while !primes.rest().is_empty() {
            let mut prime = Reader::new(primes.field(SEQUENCE)?);
            for _ in 0..3 {
                // The prime, its exponent and its coefficient.
                big(prime.field(INTEGER)?)?;
            }
        }
    }
    if version > 1 {
        return Err(Malformed);
    }
    Ok(())
}

/// An INTEGER Go reads into a `*big.Int`: any length, minimally encoded.
fn big(content: &[u8]) -> Result<(), Malformed> {
    if der::integer_ok(content) {
        Ok(())
    } else {
        Err(Malformed)
    }
}

/// Go's `ParsePKCS8PrivateKey` with `parsePrivateKey`'s check of the key
/// type it returns.
fn pkcs8(der: &[u8]) -> Result<Read, Malformed> {
    let mut top = Reader::new(der);
    let mut fields = Reader::new(top.field(SEQUENCE)?);
    der::int64(fields.field(INTEGER)?)?;
    let mut algorithm = Reader::new(fields.field(SEQUENCE)?);
    let private_key = fields.field(OCTET_STRING)?;
    let oid = algorithm.field(OBJECT_IDENTIFIER)?;
    if !der::object_identifier_ok(oid) {
        return Err(Malformed);
    }
    let parameters = algorithm.optional_any()?;
    match oid {
        RSA_ENCRYPTION => pkcs1(private_key).map(|()| Ok(ParsedKey::Rsa)),
        EC_PUBLIC_KEY => sec1(parameters.and_then(named_curve), private_key),
        ED25519 => {
            let bytes = curve_private_key(parameters, private_key)?;
            if bytes.len() != 32 {
                return Err(Malformed);
            }
            let mut seed = Zeroizing::new([0; 32]);
            seed.copy_from_slice(bytes);
            Ok(Ok(ParsedKey::Ed25519(seed)))
        }
        X25519 => match curve_private_key(parameters, private_key)?.len() {
            32 => Ok(Err(KeyError::UnknownPkcs8Type)),
            _ => Err(Malformed),
        },
        _ => Err(Malformed),
    }
}

/// The named curve of PKCS#8's EC parameters, the whole element: its
/// OBJECT IDENTIFIER when it is one that reads, as Go's `asn1.Unmarshal`
/// into an `ObjectIdentifier` takes it (`crypto/x509/pkcs8.go:58-62`).
fn named_curve(parameters: &[u8]) -> Option<&[u8]> {
    Reader::new(parameters)
        .field(OBJECT_IDENTIFIER)
        .ok()
        .filter(|oid| der::object_identifier_ok(oid))
}

/// The key bytes of a PKCS#8 Ed25519 or X25519 key: no parameters, and
/// an OCTET STRING inside the key's own, whatever follows it
/// (`crypto/x509/pkcs8.go:69-90`).
fn curve_private_key<'a>(
    parameters: Option<&[u8]>,
    private_key: &'a [u8],
) -> Result<&'a [u8], Malformed> {
    if parameters.is_some() {
        return Err(Malformed);
    }
    Reader::new(private_key).field(OCTET_STRING)
}

/// Go's `parseECPrivateKey`: SEC 1 on the curve `outer_curve` names when
/// PKCS#8's parameters name one, else on the curve of its own `[0]`.
fn sec1(outer_curve: Option<&[u8]>, der: &[u8]) -> Result<Read, Malformed> {
    let mut top = Reader::new(der);
    let mut fields = Reader::new(top.field(SEQUENCE)?);
    let version = der::int64(fields.field(INTEGER)?)?;
    let scalar = fields.field(OCTET_STRING)?;
    let inner_curve = fields.optional_explicit(0, OBJECT_IDENTIFIER)?;
    if inner_curve.is_some_and(|oid| !der::object_identifier_ok(oid)) {
        return Err(Malformed);
    }
    let public_key = fields.optional_explicit(1, BIT_STRING)?;
    if public_key.is_some_and(|bits| !der::bit_string_ok(bits)) {
        return Err(Malformed);
    }
    if version != 1 {
        return Err(Malformed);
    }
    match outer_curve.or(inner_curve).ok_or(Malformed)? {
        P256 => signing_key(scalar).map(|key| Ok(ParsedKey::EcdsaP256(key))),
        P384 => signing_key(scalar).map(|key| Ok(ParsedKey::EcdsaP384(key))),
        P521 => signing_key(scalar).map(|key| Ok(ParsedKey::EcdsaP521(key))),
        P224 => {
            let scalar = field_length(scalar, P224_ORDER.len())?;
            if scalar.iter().all(|&byte| byte == 0) || scalar[..] >= P224_ORDER[..] {
                return Err(Malformed);
            }
            Ok(Err(KeyError::P224))
        }
        _ => Err(Malformed),
    }
}

/// The signing key for a SEC 1 scalar on the curve `C`: the scalar at
/// the field's length, which must be in `[1, n)`.
fn signing_key<C>(scalar: &[u8]) -> Result<ecdsa::SigningKey<C>, Malformed>
where
    C: ecdsa::EcdsaCurve + ecdsa::elliptic_curve::CurveArithmetic,
{
    use ecdsa::elliptic_curve::array::typenum::Unsigned;
    let scalar = field_length(scalar, C::FieldBytesSize::USIZE)?;
    ecdsa::SigningKey::<C>::from_slice(&scalar).map_err(|_| Malformed)
}

/// A SEC 1 scalar at `len` bytes, as Go reads it
/// (`crypto/x509/sec1.go:112-127`): leading zero bytes dropped while it
/// is longer, any other excess byte refused, and zeros added in front
/// while it is shorter.
fn field_length(scalar: &[u8], len: usize) -> Result<Zeroizing<Vec<u8>>, Malformed> {
    let mut scalar = scalar;
    while scalar.len() > len {
        match scalar.split_first() {
            Some((0, rest)) => scalar = rest,
            _ => return Err(Malformed),
        }
    }
    let mut padded = Zeroizing::new(vec![0; len]);
    let start = len.checked_sub(scalar.len()).ok_or(Malformed)?;
    padded
        .get_mut(start..)
        .ok_or(Malformed)?
        .copy_from_slice(scalar);
    Ok(padded)
}

#[cfg(test)]
// Test-harness arithmetic over bounded lengths.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use dcroxide_testutil::unhex;

    use super::*;

    /// A DER element: `tag`, its length and `content`.
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let len = content.len();
        let mut out = vec![tag];
        match len {
            0..0x80 => out.push(len as u8),
            0x80..0x100 => out.extend([0x81, len as u8]),
            _ => out.extend([0x82, (len >> 8) as u8, len as u8]),
        }
        out.extend_from_slice(content);
        out
    }

    /// A SEQUENCE of `parts`.
    fn seq(parts: &[&[u8]]) -> Vec<u8> {
        tlv(0x30, &parts.concat())
    }

    /// The verdict on `der`, by name.
    fn verdict(der: &[u8]) -> &'static str {
        match parse(der) {
            Ok(ParsedKey::EcdsaP256(_)) => "P-256",
            Ok(ParsedKey::EcdsaP384(_)) => "P-384",
            Ok(ParsedKey::EcdsaP521(_)) => "P-521",
            Ok(ParsedKey::Ed25519(_)) => "Ed25519",
            Ok(ParsedKey::Rsa) => "RSA",
            Err(KeyError::Unparsable) => "unparsable",
            Err(KeyError::UnknownPkcs8Type) => "unknown PKCS#8 type",
            Err(KeyError::P224) => "P-224",
        }
    }

    /// A SEC 1 key: version 1, `scalar`, then `rest` inside.
    fn sec1_key(scalar: &[u8], rest: &[&[u8]]) -> Vec<u8> {
        seq(&[&[&tlv(0x02, &[1])[..], &tlv(0x04, scalar)][..], rest].concat())
    }

    /// A `[0]` naming `curve`.
    fn curve(oid: &[u8]) -> Vec<u8> {
        tlv(0xa0, &tlv(0x06, oid))
    }

    /// A PKCS#8 key: version 0, `algorithm`, and `key` in its OCTET
    /// STRING.
    fn pkcs8_key(algorithm: &[&[u8]], key: &[u8]) -> Vec<u8> {
        seq(&[&tlv(0x02, &[0]), &seq(algorithm), &tlv(0x04, key)])
    }

    /// The verdicts of each rule of the module doc, by name, so that the
    /// parser is pinned where no oracle runs; `tests/go_differential.rs`
    /// holds all of them, and many more, to Go's.
    #[test]
    fn keys_read_as_go_reads_them() {
        let one = [0x01];
        let p256 = sec1_key(&one, &[&curve(P256)]);
        let ec = tlv(0x06, EC_PUBLIC_KEY);
        let p384_params = tlv(0x06, P384);
        let ed = tlv(0x06, ED25519);
        let x = tlv(0x06, X25519);
        let seed = tlv(0x04, &[7; 32]);
        let int = |content: &[u8]| tlv(0x02, content);
        let rsa = |version: &[u8], rest: &[&[u8]]| {
            seq(&[
                &[&int(version)[..], &int(&[0x00, 0xc5]), &int(&[3])][..],
                &[&int(&[5])[..], &int(&[7]), &int(&[11])],
                rest,
            ]
            .concat())
        };
        let cases: [(&str, Vec<u8>, &str); 29] = [
            ("SEC 1", p256.clone(), "P-256"),
            (
                "SEC 1, 33 bytes, the first zero",
                sec1_key(&[&[0; 32][..], &one].concat(), &[&curve(P256)]),
                "P-256",
            ),
            (
                "SEC 1, 33 bytes, the first not zero",
                sec1_key(&[1; 33], &[&curve(P256)]),
                "unparsable",
            ),
            (
                "SEC 1, scalar zero",
                sec1_key(&[], &[&curve(P256)]),
                "unparsable",
            ),
            ("SEC 1, no curve", sec1_key(&one, &[]), "unparsable"),
            (
                "SEC 1, version 0",
                seq(&[&int(&[0]), &tlv(0x04, &one), &curve(P256)]),
                "unparsable",
            ),
            (
                "SEC 1, version 2",
                seq(&[&int(&[2]), &tlv(0x04, &one), &curve(P256)]),
                "unparsable",
            ),
            ("SEC 1, P-384", sec1_key(&one, &[&curve(P384)]), "P-384"),
            ("SEC 1, P-521", sec1_key(&one, &[&curve(P521)]), "P-521"),
            ("SEC 1, P-224", sec1_key(&one, &[&curve(P224)]), "P-224"),
            (
                "SEC 1, P-224, scalar the order",
                sec1_key(&P224_ORDER, &[&curve(P224)]),
                "unparsable",
            ),
            (
                "SEC 1, [0] holding an INTEGER",
                sec1_key(&one, &[&tlv(0xa0, &int(&one))]),
                "unparsable",
            ),
            (
                "SEC 1, [1] with a bad bit string",
                sec1_key(&one, &[&curve(P256), &tlv(0xa1, &tlv(0x03, &[1]))]),
                "unparsable",
            ),
            (
                "SEC 1, trailing data after it",
                [&p256[..], &[0xff, 0xff]].concat(),
                "P-256",
            ),
            (
                "SEC 1, a NULL closing it after [0]",
                sec1_key(&one, &[&curve(P256), &[0x05, 0x00]]),
                "unparsable",
            ),
            (
                "PKCS#8 EC, no inner curve",
                pkcs8_key(&[&ec, &tlv(0x06, P256)], &sec1_key(&one, &[])),
                "P-256",
            ),
            (
                "PKCS#8 EC, outer curve wins",
                pkcs8_key(&[&ec, &p384_params], &sec1_key(&one, &[&curve(P256)])),
                "P-384",
            ),
            (
                "PKCS#8 EC, NULL parameters, inner curve",
                pkcs8_key(&[&ec, &[0x05, 0x00]], &sec1_key(&one, &[&curve(P521)])),
                "P-521",
            ),
            (
                "PKCS#8 EC, [0] holding an INTEGER",
                pkcs8_key(
                    &[&ec, &p384_params],
                    &sec1_key(&one, &[&tlv(0xa0, &int(&one))]),
                ),
                "P-384",
            ),
            ("PKCS#8 Ed25519", pkcs8_key(&[&ed], &seed), "Ed25519"),
            (
                "PKCS#8 Ed25519, NULL parameters",
                pkcs8_key(&[&ed, &[0x05, 0x00]], &seed),
                "unparsable",
            ),
            (
                "PKCS#8 Ed25519, 31 bytes",
                pkcs8_key(&[&ed], &tlv(0x04, &[7; 31])),
                "unparsable",
            ),
            (
                "PKCS#8 Ed25519, 33 bytes",
                pkcs8_key(&[&ed], &tlv(0x04, &[7; 33])),
                "unparsable",
            ),
            (
                "PKCS#8 X25519",
                pkcs8_key(&[&x], &seed),
                "unknown PKCS#8 type",
            ),
            (
                "PKCS#8 X25519, 31 bytes",
                pkcs8_key(&[&x], &tlv(0x04, &[7; 31])),
                "unparsable",
            ),
            ("PKCS#1", rsa(&[0], &[]), "RSA"),
            ("PKCS#1, negative version", rsa(&[0xff], &[]), "RSA"),
            ("PKCS#1, version 2", rsa(&[2], &[]), "unparsable"),
            (
                "PKCS#1, trailing data after it",
                [&rsa(&[0], &[])[..], &[0x00]].concat(),
                "unparsable",
            ),
        ];
        for (label, der, want) in cases {
            assert_eq!(verdict(&der), want, "{label}: {der:02x?}");
        }
    }

    /// PKCS#1's optional values: the CRT values only as INTEGERs, the
    /// additional primes only as a SEQUENCE whose elements are each a
    /// SEQUENCE of three INTEGERs, and anything after them ignored but for
    /// a header that does not read.  And the version and E each held to
    /// the eight bytes of a 64-bit Go's `int`
    /// (`encoding/asn1/asn1.go:950-954`), on a key that is whole but for
    /// that one value.
    #[test]
    fn pkcs1_reads_as_go_reads_it() {
        let int = |content: &[u8]| tlv(0x02, content);
        let base = [
            int(&[0]),
            int(&[0x00, 0xc5]),
            int(&[3]),
            int(&[5]),
            int(&[7]),
            int(&[11]),
        ];
        let key = |rest: &[&[u8]]| {
            let base: Vec<&[u8]> = base.iter().map(Vec::as_slice).collect();
            seq(&[&base[..], rest].concat())
        };
        let with = |index: usize, content: &[u8]| {
            let mut fields = base.clone();
            fields[index] = int(content);
            let fields: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
            seq(&fields)
        };
        let prime = seq(&[&int(&[13]), &int(&[1]), &int(&[1])]);
        for (label, der, rsa) in [
            ("no CRT values", key(&[]), true),
            ("Dp alone", key(&[&int(&[1])]), true),
            (
                "CRT values",
                key(&[&int(&[1]), &int(&[1]), &int(&[1])]),
                true,
            ),
            ("a prime", key(&[&seq(&[&prime])]), true),
            ("no primes", key(&[&seq(&[])]), true),
            ("a NULL after it", key(&[&[0x05, 0x00]]), true),
            (
                "a prime of two values",
                key(&[&seq(&[&seq(&[&int(&[13]), &int(&[1])])])]),
                false,
            ),
            (
                "a prime that is an INTEGER",
                key(&[&seq(&[&int(&[13])])]),
                false,
            ),
            ("a bad header after it", key(&[&[0xff]]), false),
            (
                "an E of eight bytes",
                with(2, &[1, 0, 0, 0, 0, 0, 0, 0]),
                true,
            ),
            (
                "an E of nine bytes",
                with(2, &[1, 0, 0, 0, 0, 0, 0, 0, 1]),
                false,
            ),
            (
                "a negative version of eight bytes",
                with(0, &[0xff, 0, 0, 0, 0, 0, 0, 0]),
                true,
            ),
            (
                "a negative version of nine bytes",
                with(0, &[0xff, 0, 0, 0, 0, 0, 0, 0, 0]),
                false,
            ),
            ("a CRT value not minimal", key(&[&int(&[0, 1])]), false),
        ] {
            assert_eq!(pkcs1(&der).is_ok(), rsa, "{label}: {der:02x?}");
        }
    }

    /// Each curve the provider signs on takes a scalar of n - 1, at the
    /// field's length or stripped to it, and refuses n: the top of
    /// `[1, n)`, which the curve crate checks
    /// (`elliptic-curve-0.14.1/src/scalar/value.rs:69-79`) where Go's
    /// `NewPrivateKey` does
    /// (`crypto/internal/fips140/ecdsa/ecdsa.go:171-174`).
    #[test]
    fn each_signing_curve_takes_scalars_below_its_order() {
        for (oid, order, name) in [
            (
                P256,
                "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "P-256",
            ),
            (
                P384,
                "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
                 581a0db248b0a77aecec196accc52973",
                "P-384",
            ),
            (
                P521,
                "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                 fffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138\
                 6409",
                "P-521",
            ),
        ] {
            let order = unhex(order);
            let mut n_minus_one = order.clone();
            *n_minus_one.last_mut().expect("an order") -= 1;
            let key = |scalar: &[u8]| verdict(&sec1_key(scalar, &[&curve(oid)]));
            assert_eq!(key(&n_minus_one), name);
            assert_eq!(key(&[&[0][..], &n_minus_one].concat()), name);
            assert_eq!(key(&order), "unparsable", "{name}: n");
            assert_eq!(key(&[&[0][..], &order].concat()), "unparsable", "{name}");
        }
    }

    /// A P-224 scalar is refused as P-224 only where Go loads it: in
    /// `[1, n)` once Go has stripped or padded it.
    #[test]
    fn p224_is_refused_only_where_go_loads_it() {
        let n_minus_one = unhex("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3c");
        let key = |scalar: &[u8]| verdict(&sec1_key(scalar, &[&curve(P224)]));
        assert_eq!(key(&n_minus_one), "P-224");
        assert_eq!(key(&[&[0, 0][..], &n_minus_one].concat()), "P-224");
        assert_eq!(key(&[1]), "P-224");
        assert_eq!(key(&[0; 28]), "unparsable");
        assert_eq!(key(&P224_ORDER), "unparsable");
        assert_eq!(key(&[1; 29]), "unparsable");
    }
}
