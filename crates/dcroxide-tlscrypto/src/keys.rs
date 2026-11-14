// SPDX-License-Identifier: ISC
//! Go's `parsePrivateKey` (`crypto/tls/tls.go:361-379`), which
//! `tls.X509KeyPair` reads the key of an `rpc.key` with: PKCS#8, then
//! PKCS#1, then SEC 1, on the raw DER, whatever PEM block it came from.
//! A key that none of the three reads is refused with the PKCS#8
//! parser's error, as Go's "tls: failed to parse private key: " and that
//! error ([`KeyError`]).  Line citations are to Go 1.27.3.
//!
//! Each of the three is Go's `crypto/x509` parser as `asn1.Unmarshal`
//! reads its structure ([`crate::der`]), with Go's checks after it, in
//! Go's order and with Go's texts:
//!
//! * **PKCS#8** (`crypto/x509/pkcs8.go:22-27`, `:39-126`): a version Go
//!   does not look at, an algorithm identifier and the key's OCTET
//!   STRING, later elements ignored.  When that structure does not read,
//!   Go names the format it does read as, SEC 1 or PKCS#1, if either,
//!   and otherwise gives the structure's error.  `rsaEncryption` holds a
//!   PKCS#1 key and `id-ecPublicKey` a SEC 1 key, either refused with
//!   that parser's error after Go's words for it; the EC key is on the
//!   curve the parameters name when they read as an OBJECT IDENTIFIER,
//!   which then wins over any curve inside.  `id-Ed25519` holds the
//!   32-byte seed in an OCTET STRING, with no parameters.  ML-DSA-44, -65
//!   and -87 hold, with no parameters, a 32-byte seed in an implicit
//!   `[0]`, which Go loads and this provider does not sign with; the
//!   semi-expanded and the expanded forms Go refuses, each with its own
//!   text.  `id-X25519`, with no parameters and 32 bytes, is a key Go
//!   reads and `crypto/tls` refuses as "tls: found unknown private key
//!   type in PKCS#8 wrapping".  Any other algorithm is refused, naming it.
//! * **PKCS#1** (`crypto/x509/pkcs1.go:16-36`, `:54-122`): version, N, E,
//!   D, P and Q, each an INTEGER, the version and E fitting an `int`;
//!   then Dp, Dq and Qinv, each only if the next element is an INTEGER;
//!   then, if the next element is a SEQUENCE, the additional primes, each
//!   a SEQUENCE of three INTEGERs, all of whose headers Go checks before
//!   it reads any of them.  Nothing may follow the key, and its version
//!   may not exceed 1, though it may be negative.  The values are not
//!   checked further: a key with that structure is RSA, which this
//!   provider does not sign with (ADR-0015, T6), and is refused with its
//!   own text whether or not Go's `Validate` would pass it.
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
//!   (`crypto/ecdsa/ecdsa.go:246-271`).
//!
//! The three shapes differ in their second element, a SEQUENCE, an
//! INTEGER or an OCTET STRING, so at most one of them reads any input,
//! and the order decides no verdict.  It decides the text: the error
//! given is always the PKCS#8 parser's, even for a key whose shape is
//! plainly SEC 1 or PKCS#1, since `parsePrivateKey` drops the other two
//! (`crypto/tls/tls.go:362-372`).  Those two show only inside PKCS#8.
//! `tests/go_differential.rs` holds the verdicts and the texts to Go's
//! `tls.X509KeyPair` on a corpus of keys mutated in each of these rules,
//! and on mutations of every key of it.
//!
//! The scalar and the seed are copied out of the input into buffers that
//! are wiped when dropped; the key types they become wipe themselves.
//! Only a scalar outside `[1, n)`, which is no key, is copied into an
//! integer that is not wiped, to choose Go's text for it.
//! A text for a key that does not parse carries what Go read where the
//! parse failed: a header's class, tag and length, a version or a length,
//! or, for an ML-DSA key whose first byte is no tag Go knows, that byte
//! (`crypto/x509/pkcs8.go:99`).  In a damaged key these can be bytes of
//! the scalar, as in Go's own text, which dcrd prints.

use core::fmt;

use num_bigint::BigUint;
use zeroize::Zeroizing;

use crate::der::{
    self, Asn1Error, BIG_INT, BIT_STRING, BYTES, Dotted, Field, INT, INTEGER, OBJECT_IDENTIFIER,
    OID, Reader, SEQUENCE,
};

/// `rsaEncryption`, 1.2.840.113549.1.1.1.
const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// `id-ecPublicKey`, 1.2.840.10045.2.1.
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// `id-Ed25519`, 1.3.101.112.
const ED25519: &[u8] = &[0x2b, 0x65, 0x70];
/// `id-X25519`, 1.3.101.110.
const X25519: &[u8] = &[0x2b, 0x65, 0x6e];
/// `id-ml-dsa-44`, 2.16.840.1.101.3.4.3.17.
const ML_DSA_44: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11];
/// `id-ml-dsa-65`, 2.16.840.1.101.3.4.3.18.
const ML_DSA_65: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];
/// `id-ml-dsa-87`, 2.16.840.1.101.3.4.3.19.
const ML_DSA_87: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13];
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
/// P-256's order, big-endian (`crypto/elliptic/nistec.go:40`).
const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
/// P-384's order, big-endian (`crypto/elliptic/nistec.go:58`).
const P384_ORDER: [u8; 48] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf,
    0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73,
];
/// P-521's order, big-endian (`crypto/elliptic/nistec.go:81`).
const P521_ORDER: [u8; 66] = [
    0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f, 0x96, 0x6b, 0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09,
    0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c, 0x47, 0xae, 0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38,
    0x64, 0x09,
];

/// The length of an ML-DSA seed, and of Go's `mldsa.PrivateKeySize`.
const ML_DSA_SEED_LEN: u8 = 32;

/// Go's hint for input that reads as a SEC 1 structure
/// (`crypto/x509/pkcs8.go:43`, `pkcs1.go:62`).
const SEC1_HINT: &str =
    "x509: failed to parse private key (use ParseECPrivateKey instead for this key format)";
/// Go's hint for input that reads as a PKCS#1 structure
/// (`crypto/x509/pkcs8.go:46`, `sec1.go:94`).
const PKCS1_HINT: &str =
    "x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)";
/// Go's hint for input that reads as a PKCS#8 structure
/// (`crypto/x509/pkcs1.go:65`, `sec1.go:91`).
const PKCS8_HINT: &str =
    "x509: failed to parse private key (use ParsePKCS8PrivateKey instead for this key format)";

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

/// An ML-DSA parameter set (FIPS 204), as Go names it
/// (`crypto/x509/x509.go:401-403`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MlDsa {
    /// ML-DSA-44.
    MlDsa44,
    /// ML-DSA-65.
    MlDsa65,
    /// ML-DSA-87.
    MlDsa87,
}

impl fmt::Display for MlDsa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            MlDsa::MlDsa44 => "ML-DSA-44",
            MlDsa::MlDsa65 => "ML-DSA-65",
            MlDsa::MlDsa87 => "ML-DSA-87",
        })
    }
}

/// Why a key is not a [`ParsedKey`], which prints as the text the key is
/// refused with.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KeyError {
    /// None of Go's three parsers reads it: Go's "tls: failed to parse
    /// private key: " and the PKCS#8 parser's error
    /// (`crypto/tls/tls.go:371`).
    Unparsable(Cause),
    /// A PKCS#8 X25519 key, which Go reads and `crypto/tls` refuses
    /// (`crypto/tls/tls.go:377`).
    UnknownPkcs8Type,
    /// A P-224 key, which Go loads and serves over TLS 1.2 only, and ring
    /// refused, as this provider does.
    P224,
    /// An ML-DSA key in the seed form, which Go loads
    /// (`crypto/x509/pkcs8.go:83-111`) and this provider does not sign
    /// with yet.
    MlDsa(MlDsa),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Unparsable(cause) => write!(f, "tls: failed to parse private key: {cause}"),
            KeyError::UnknownPkcs8Type => {
                f.write_str("tls: found unknown private key type in PKCS#8 wrapping")
            }
            KeyError::P224 => f.write_str("unsupported private key: ECDSA P-224"),
            KeyError::MlDsa(set) => write!(f, "unsupported private key: {set}"),
        }
    }
}

/// The error one of Go's `crypto/x509` parsers returns for a key, which
/// prints as Go prints it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Cause {
    /// An `encoding/asn1` error.
    Asn1(Asn1Error),
    /// One of Go's fixed texts.
    Text(&'static str),
    /// A SEC 1 version other than 1, as Go's `%d` prints it
    /// (`crypto/x509/sec1.go:99`).
    EcVersion(i64),
    /// An Ed25519 seed of another length (`crypto/x509/pkcs8.go:79`).
    Ed25519Length(usize),
    /// An ML-DSA key of another length (`crypto/x509/pkcs8.go:90`, `:102`).
    MlDsaLength(usize),
    /// An ML-DSA key whose first byte is no tag Go knows
    /// (`crypto/x509/pkcs8.go:99`).
    MlDsaTag(u8),
    /// A PKCS#8 algorithm Go does not know: the content of its OBJECT
    /// IDENTIFIER (`crypto/x509/pkcs8.go:124`).
    UnknownAlgorithm(Vec<u8>),
    /// Go's words for where an error arose, then the error.
    Within(&'static str, Box<Cause>),
}

impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Cause::Asn1(error) => write!(f, "{error}"),
            Cause::Text(text) => f.write_str(text),
            Cause::EcVersion(version) => {
                write!(f, "x509: unknown EC private key version {version}")
            }
            Cause::Ed25519Length(len) => {
                write!(f, "x509: invalid Ed25519 private key length: {len}")
            }
            Cause::MlDsaLength(len) => write!(f, "x509: invalid ML-DSA private key length: {len}"),
            Cause::MlDsaTag(tag) => {
                write!(
                    f,
                    "x509: invalid ML-DSA private key: invalid ASN.1 tag {tag:02x}"
                )
            }
            Cause::UnknownAlgorithm(oid) => write!(
                f,
                "x509: PKCS#8 wrapping contained private key with unknown algorithm: {}",
                Dotted(oid)
            ),
            Cause::Within(context, cause) => write!(f, "{context}{cause}"),
        }
    }
}

/// `cause`, after Go's words `context`.
fn within(context: &'static str, cause: Cause) -> Cause {
    Cause::Within(context, Box::new(cause))
}

/// What one of Go's parsers made of a key it read.
type Read = Result<ParsedKey, KeyError>;

/// `der` as Go's `parsePrivateKey` reads it (`crypto/tls/tls.go:361-379`).
pub(crate) fn parse(der: &[u8]) -> Read {
    let pkcs8_error = match parse_pkcs8(der) {
        Ok(read) => return read,
        Err(cause) => cause,
    };
    if parse_pkcs1(der).is_ok() {
        return Ok(ParsedKey::Rsa);
    }
    if let Ok(read) = parse_ec(None, der) {
        return read;
    }
    Err(KeyError::Unparsable(pkcs8_error))
}

/// The fields of Go's `pkcs8` structure (`crypto/x509/pkcs8.go:22-27`).
struct Pkcs8<'a> {
    /// The algorithm's OBJECT IDENTIFIER, which reads.
    algorithm: &'a [u8],
    /// The algorithm's parameters, the whole element, when there are any.
    parameters: Option<&'a [u8]>,
    /// The content of the key's OCTET STRING.
    private_key: &'a [u8],
}

/// `asn1.Unmarshal` into Go's `pkcs8`: the version, then the algorithm
/// identifier, its parameters read before the key that follows it.
fn pkcs8_structure(der: &[u8]) -> Result<Pkcs8<'_>, Asn1Error> {
    let mut top = Reader::new(der);
    let mut fields = Reader::new(top.field(Field::structure("pkcs8"))?);
    der::int64(fields.field(INT)?)?;
    let mut algorithm = Reader::new(fields.field(Field::structure("AlgorithmIdentifier"))?);
    let oid = algorithm.field(OID)?;
    der::object_identifier(oid)?;
    let parameters = algorithm.optional_any()?;
    let private_key = fields.field(BYTES)?;
    Ok(Pkcs8 {
        algorithm: oid,
        parameters,
        private_key,
    })
}

/// The fields of Go's `ecPrivateKey` structure Go looks at
/// (`crypto/x509/sec1.go:26-31`).
struct Ec<'a> {
    /// The version.
    version: i64,
    /// The content of the scalar's OCTET STRING.
    scalar: &'a [u8],
    /// The curve's OBJECT IDENTIFIER in `[0]`, which reads, if there.
    curve: Option<&'a [u8]>,
}

/// `asn1.Unmarshal` into Go's `ecPrivateKey`.
fn ec_structure(der: &[u8]) -> Result<Ec<'_>, Asn1Error> {
    let mut top = Reader::new(der);
    let mut fields = Reader::new(top.field(Field::structure("ecPrivateKey"))?);
    let version = der::int64(fields.field(INT)?)?;
    let scalar = fields.field(BYTES)?;
    let curve = fields.optional_explicit(0, OBJECT_IDENTIFIER)?;
    if let Some(oid) = curve {
        der::object_identifier(oid)?;
    }
    if let Some(bits) = fields.optional_explicit(1, BIT_STRING)? {
        der::bit_string(bits)?;
    }
    Ok(Ec {
        version,
        scalar,
        curve,
    })
}

/// `asn1.Unmarshal` into Go's `pkcs1PrivateKey`: the version, and what
/// follows the key.
fn pkcs1_structure(der: &[u8]) -> Result<(i64, &[u8]), Asn1Error> {
    let mut top = Reader::new(der);
    let mut fields = Reader::new(top.field(Field::structure("pkcs1PrivateKey"))?);
    let version = der::int64(fields.field(INT)?)?;
    der::integer(fields.field(BIG_INT)?)?;
    der::int64(fields.field(INT)?)?;
    for _ in 0..3 {
        // D, P and Q.
        der::integer(fields.field(BIG_INT)?)?;
    }
    for _ in 0..3 {
        // Dp, Dq and Qinv, each tried on the same next element when the
        // one before it is absent.
        if let Some(value) = fields.optional(INTEGER)? {
            der::integer(value)?;
        }
    }
    if let Some(primes) = fields.optional(SEQUENCE)? {
        der::sequence_of(primes, SEQUENCE)?;
        let mut primes = Reader::new(primes);
        while !primes.rest().is_empty() {
            let prime = primes.field(Field::structure("pkcs1AdditionalRSAPrime"))?;
            let mut prime = Reader::new(prime);
            for _ in 0..3 {
                // The prime, its exponent and its coefficient.
                der::integer(prime.field(BIG_INT)?)?;
            }
        }
    }
    Ok((version, top.rest()))
}

/// Go's `ParsePKCS8PrivateKey` (`crypto/x509/pkcs8.go:39-126`) with
/// `parsePrivateKey`'s check of the key type it returns.
fn parse_pkcs8(der: &[u8]) -> Result<Read, Cause> {
    let key = match pkcs8_structure(der) {
        Ok(key) => key,
        Err(error) => {
            if ec_structure(der).is_ok() {
                return Err(Cause::Text(SEC1_HINT));
            }
            if pkcs1_structure(der).is_ok() {
                return Err(Cause::Text(PKCS1_HINT));
            }
            return Err(Cause::Asn1(error));
        }
    };
    match key.algorithm {
        RSA_ENCRYPTION => parse_pkcs1(key.private_key)
            .map(|()| Ok(ParsedKey::Rsa))
            .map_err(|cause| {
                within(
                    "x509: failed to parse RSA private key embedded in PKCS#8: ",
                    cause,
                )
            }),
        EC_PUBLIC_KEY => {
            parse_ec(key.parameters.and_then(named_curve), key.private_key).map_err(|cause| {
                within(
                    "x509: failed to parse EC private key embedded in PKCS#8: ",
                    cause,
                )
            })
        }
        ED25519 => {
            if key.parameters.is_some() {
                return Err(Cause::Text("x509: invalid Ed25519 private key parameters"));
            }
            let bytes = Reader::new(key.private_key).field(BYTES).map_err(|error| {
                within("x509: invalid Ed25519 private key: ", Cause::Asn1(error))
            })?;
            if bytes.len() != 32 {
                return Err(Cause::Ed25519Length(bytes.len()));
            }
            let mut seed = Zeroizing::new([0; 32]);
            seed.copy_from_slice(bytes);
            Ok(Ok(ParsedKey::Ed25519(seed)))
        }
        ML_DSA_44 => ml_dsa(MlDsa::MlDsa44, &key),
        ML_DSA_65 => ml_dsa(MlDsa::MlDsa65, &key),
        ML_DSA_87 => ml_dsa(MlDsa::MlDsa87, &key),
        X25519 => {
            if key.parameters.is_some() {
                return Err(Cause::Text("x509: invalid X25519 private key parameters"));
            }
            let bytes = Reader::new(key.private_key).field(BYTES).map_err(|error| {
                within("x509: invalid X25519 private key: ", Cause::Asn1(error))
            })?;
            if bytes.len() != 32 {
                // `ecdh.X25519().NewPrivateKey` (`crypto/ecdh/x25519.go:54`).
                return Err(Cause::Text("crypto/ecdh: invalid private key size"));
            }
            Ok(Err(KeyError::UnknownPkcs8Type))
        }
        other => Err(Cause::UnknownAlgorithm(other.to_vec())),
    }
}

/// The named curve of PKCS#8's EC parameters, the whole element: its
/// OBJECT IDENTIFIER when it is one that reads, as Go's `asn1.Unmarshal`
/// into an `ObjectIdentifier` takes it (`crypto/x509/pkcs8.go:59-63`).
fn named_curve(parameters: &[u8]) -> Option<&[u8]> {
    Reader::new(parameters)
        .field(OID)
        .ok()
        .filter(|oid| der::object_identifier(oid).is_ok())
}

/// Go's ML-DSA branch of `ParsePKCS8PrivateKey`
/// (`crypto/x509/pkcs8.go:83-111`), on the key's bytes as they are: no
/// parameters, a first byte that is the seed's implicit `[0]`, 34 bytes in
/// all, and a seed's length in the second.  Go's `mldsa.NewPrivateKey`
/// takes any 32-byte seed, so a key that passes is one Go loads.
fn ml_dsa(set: MlDsa, key: &Pkcs8<'_>) -> Result<Read, Cause> {
    if key.parameters.is_some() {
        return Err(Cause::Text("x509: invalid ML-DSA private key parameters"));
    }
    let private_key = key.private_key;
    match private_key.first() {
        None => return Err(Cause::MlDsaLength(0)),
        Some(0x80) => {}
        Some(0x04) => {
            return Err(Cause::Text(
                "x509: semi-expanded ML-DSA private keys without seed are not supported",
            ));
        }
        Some(0x30) => {
            return Err(Cause::Text(
                "x509: ML-DSA private keys with both seed and expanded key are not supported, use \
                 e.g. \"openssl pkey -provparam ml-dsa.output_formats=seed-only\" to convert to a \
                 seed-only key",
            ));
        }
        Some(&tag) => return Err(Cause::MlDsaTag(tag)),
    }
    if private_key.len() != usize::from(ML_DSA_SEED_LEN) + 2 {
        return Err(Cause::MlDsaLength(private_key.len()));
    }
    if private_key.get(1) != Some(&ML_DSA_SEED_LEN) {
        return Err(Cause::Text(
            "x509: invalid ML-DSA private key ASN.1 encoding",
        ));
    }
    Ok(Err(KeyError::MlDsa(set)))
}

/// Go's `ParsePKCS1PrivateKey` (`crypto/x509/pkcs1.go:54-122`), as far as
/// the key's structure, what follows it and its version: the key is RSA
/// when this returns `Ok`.
fn parse_pkcs1(der: &[u8]) -> Result<(), Cause> {
    let (version, rest) = match pkcs1_structure(der) {
        Ok(read) => read,
        Err(error) => {
            if ec_structure(der).is_ok() {
                return Err(Cause::Text(SEC1_HINT));
            }
            if pkcs8_structure(der).is_ok() {
                return Err(Cause::Text(PKCS8_HINT));
            }
            return Err(Cause::Asn1(error));
        }
    };
    if !rest.is_empty() {
        return Err(Cause::Asn1(Asn1Error::Syntax("trailing data")));
    }
    if version > 1 {
        return Err(Cause::Text("x509: unsupported private key version"));
    }
    Ok(())
}

/// Go's `parseECPrivateKey` (`crypto/x509/sec1.go:87-130`): SEC 1 on the
/// curve `outer_curve` names when PKCS#8's parameters name one, else on
/// the curve of its own `[0]`.
fn parse_ec(outer_curve: Option<&[u8]>, der: &[u8]) -> Result<Read, Cause> {
    let key = match ec_structure(der) {
        Ok(key) => key,
        Err(error) => {
            if pkcs8_structure(der).is_ok() {
                return Err(Cause::Text(PKCS8_HINT));
            }
            if pkcs1_structure(der).is_ok() {
                return Err(Cause::Text(PKCS1_HINT));
            }
            return Err(within(
                "x509: failed to parse EC private key: ",
                Cause::Asn1(error),
            ));
        }
    };
    if key.version != 1 {
        return Err(Cause::EcVersion(key.version));
    }
    match outer_curve.or(key.curve) {
        Some(P256) => signing_key(key.scalar, &P256_ORDER).map(|key| Ok(ParsedKey::EcdsaP256(key))),
        Some(P384) => signing_key(key.scalar, &P384_ORDER).map(|key| Ok(ParsedKey::EcdsaP384(key))),
        Some(P521) => signing_key(key.scalar, &P521_ORDER).map(|key| Ok(ParsedKey::EcdsaP521(key))),
        Some(P224) => {
            let scalar = field_length(key.scalar, P224_ORDER.len())?;
            match scalar_refused(&scalar, &P224_ORDER) {
                Some(cause) => Err(cause),
                None => Ok(Err(KeyError::P224)),
            }
        }
        _ => Err(Cause::Text("x509: unknown elliptic curve")),
    }
}

/// The signing key for a SEC 1 scalar on the curve `C`, of order `order`:
/// the scalar at the order's length, which must be in `[1, n)`.  The
/// curve crate checks that in constant time; only a scalar it refuses is
/// looked at again, for Go's text.
fn signing_key<C>(scalar: &[u8], order: &[u8]) -> Result<ecdsa::SigningKey<C>, Cause>
where
    C: ecdsa::EcdsaCurve + ecdsa::elliptic_curve::CurveArithmetic,
{
    let scalar = field_length(scalar, order.len())?;
    ecdsa::SigningKey::<C>::from_slice(&scalar).map_err(|_| {
        let refused = scalar_refused(&scalar, order);
        debug_assert!(
            refused.is_some(),
            "the curve crate refused a scalar in [1, n)"
        );
        refused.unwrap_or(Cause::Text(OVERFLOWS_THE_MODULUS))
    })
}

/// Go's text for a scalar at or above the order and no multiple of it.
const OVERFLOWS_THE_MODULUS: &str = "input overflows the modulus";

/// Go's refusal of a scalar at the order's length, when it is outside
/// `[1, n)`, from `ecdsa.ParseRawPrivateKey`
/// (`crypto/ecdsa/ecdsa.go:261-271`): Go multiplies the generator by the
/// scalar before it checks the scalar, so one that is zero or a multiple
/// of n gives the point at infinity, which `NewPublicKey` refuses
/// (`crypto/internal/fips140/ecdsa/ecdsa.go:189-191`), and any other at
/// or above n is refused by `bigmod`'s `SetBytes`
/// (`crypto/internal/fips140/bigmod/nat.go:187-189`).  A multiple of n
/// other than n itself fits only P-521's 66 bytes.  `None` for a scalar
/// in `[1, n)`, decided on the bytes, big-endian at the same length, so
/// that only a scalar that is no key is copied into an integer, which is
/// not wiped.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "the remainder by a curve's order, which is not zero"
)]
fn scalar_refused(scalar: &[u8], order: &[u8]) -> Option<Cause> {
    debug_assert_eq!(
        scalar.len(),
        order.len(),
        "a scalar not at the order's length"
    );
    if scalar.iter().any(|&byte| byte != 0) && scalar < order {
        return None;
    }
    let scalar = BigUint::from_bytes_be(scalar);
    let order = BigUint::from_bytes_be(order);
    Some(Cause::Text(if &scalar % &order == BigUint::ZERO {
        "ecdsa: invalid public key encoding"
    } else {
        OVERFLOWS_THE_MODULUS
    }))
}

/// A SEC 1 scalar at `len` bytes, as Go reads it
/// (`crypto/x509/sec1.go:112-127`): leading zero bytes dropped while it
/// is longer, any other excess byte refused, and zeros added in front
/// while it is shorter.
fn field_length(scalar: &[u8], len: usize) -> Result<Zeroizing<Vec<u8>>, Cause> {
    let invalid = || Cause::Text("x509: invalid private key length");
    let mut scalar = scalar;
    while scalar.len() > len {
        match scalar.split_first() {
            Some((0, rest)) => scalar = rest,
            _ => return Err(invalid()),
        }
    }
    let mut padded = Zeroizing::new(vec![0; len]);
    let start = len.checked_sub(scalar.len()).ok_or_else(invalid)?;
    padded
        .get_mut(start..)
        .ok_or_else(invalid)?
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

    /// An INTEGER of `content`.
    fn int(content: &[u8]) -> Vec<u8> {
        tlv(0x02, content)
    }

    /// An OCTET STRING of `content`.
    fn octets(content: &[u8]) -> Vec<u8> {
        tlv(0x04, content)
    }

    /// An OBJECT IDENTIFIER of `content`.
    fn oid(content: &[u8]) -> Vec<u8> {
        tlv(0x06, content)
    }

    /// A NULL.
    const NULL: [u8; 2] = [0x05, 0x00];

    /// Go's parameters in a "tags don't match" text.
    const P0: &str = "{optional:false explicit:false application:false private:false \
                      defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false \
                      omitEmpty:false}";

    /// The verdict on `der`: a loaded key's type by name, or the text it
    /// is refused with.
    fn verdict(der: &[u8]) -> String {
        match parse(der) {
            Ok(ParsedKey::EcdsaP256(_)) => "P-256".to_owned(),
            Ok(ParsedKey::EcdsaP384(_)) => "P-384".to_owned(),
            Ok(ParsedKey::EcdsaP521(_)) => "P-521".to_owned(),
            Ok(ParsedKey::Ed25519(_)) => "Ed25519".to_owned(),
            Ok(ParsedKey::Rsa) => "RSA".to_owned(),
            Err(error) => error.to_string(),
        }
    }

    /// Each row's verdict, against the text it names: a row whose text
    /// holds `{P0}` takes Go's parameters there, and one that starts with
    /// `: ` takes Go's "tls: failed to parse private key" before it.
    fn check(rows: &[(&str, Vec<u8>, &str)]) {
        for (label, der, want) in rows {
            let want = want.replace("{P0}", P0);
            let want = match want.strip_prefix(": ") {
                Some(cause) => format!("tls: failed to parse private key: {cause}"),
                None => want,
            };
            assert_eq!(verdict(der), want, "{label}: {der:02x?}");
        }
    }

    /// A SEC 1 key: version 1, `scalar`, then `rest` inside.
    fn sec1_key(scalar: &[u8], rest: &[&[u8]]) -> Vec<u8> {
        seq(&[&[&int(&[1])[..], &octets(scalar)][..], rest].concat())
    }

    /// A `[0]` naming `curve`.
    fn curve(oid_content: &[u8]) -> Vec<u8> {
        tlv(0xa0, &oid(oid_content))
    }

    /// A PKCS#8 key: version 0, `algorithm`, and `key` in its OCTET
    /// STRING.
    fn pkcs8_key(algorithm: &[&[u8]], key: &[u8]) -> Vec<u8> {
        seq(&[&int(&[0]), &seq(algorithm), &octets(key)])
    }

    /// A PKCS#1 key of `version` with small values, then `rest` inside.
    fn rsa(version: &[u8], rest: &[&[u8]]) -> Vec<u8> {
        seq(&[
            &[&int(version)[..], &int(&[0x00, 0xc5]), &int(&[3])][..],
            &[&int(&[5])[..], &int(&[7]), &int(&[11])],
            rest,
        ]
        .concat())
    }

    /// The verdicts and texts of each rule of the module doc, so that the
    /// parser is pinned where no oracle runs; `tests/go_differential.rs`
    /// holds the verdicts of all of them, and many more, to Go's.
    #[test]
    fn keys_read_as_go_reads_them() {
        let one = [0x01];
        let p256 = sec1_key(&one, &[&curve(P256)]);
        let ec = oid(EC_PUBLIC_KEY);
        let p384_params = oid(P384);
        let ed = oid(ED25519);
        let x = oid(X25519);
        let seed = octets(&[7; 32]);
        check(&[
            ("SEC 1", p256.clone(), "P-256"),
            (
                "SEC 1, 33 bytes, the first zero",
                sec1_key(&[&[0; 32][..], &one].concat(), &[&curve(P256)]),
                "P-256",
            ),
            (
                "SEC 1, 33 bytes, the first not zero",
                sec1_key(&[1; 33], &[&curve(P256)]),
                ": x509: failed to parse private key (use ParseECPrivateKey instead for this key \
                 format)",
            ),
            (
                "SEC 1, scalar zero",
                sec1_key(&[], &[&curve(P256)]),
                ": x509: failed to parse private key (use ParseECPrivateKey instead for this key \
                 format)",
            ),
            (
                "SEC 1, no curve",
                sec1_key(&one, &[]),
                ": x509: failed to parse private key (use ParseECPrivateKey instead for this key \
                 format)",
            ),
            (
                "SEC 1, version 0",
                seq(&[&int(&[0]), &octets(&one), &curve(P256)]),
                ": x509: failed to parse private key (use ParseECPrivateKey instead for this key \
                 format)",
            ),
            (
                "SEC 1, version 2",
                seq(&[&int(&[2]), &octets(&one), &curve(P256)]),
                ": x509: failed to parse private key (use ParseECPrivateKey instead for this key \
                 format)",
            ),
            ("SEC 1, P-384", sec1_key(&one, &[&curve(P384)]), "P-384"),
            ("SEC 1, P-521", sec1_key(&one, &[&curve(P521)]), "P-521"),
            (
                "SEC 1, P-224",
                sec1_key(&one, &[&curve(P224)]),
                "unsupported private key: ECDSA P-224",
            ),
            (
                "SEC 1, P-224, scalar the order",
                sec1_key(&P224_ORDER, &[&curve(P224)]),
                ": x509: failed to parse private key (use ParseECPrivateKey instead for this key \
                 format)",
            ),
            (
                "SEC 1, [0] holding an INTEGER",
                sec1_key(&one, &[&tlv(0xa0, &int(&one))]),
                ": x509: failed to parse private key (use ParseECPrivateKey instead for this key \
                 format)",
            ),
            (
                "SEC 1, [1] with a bad bit string",
                sec1_key(&one, &[&curve(P256), &tlv(0xa1, &tlv(0x03, &[1]))]),
                ": asn1: structure error: tags don't match (16 vs {class:0 tag:4 length:1 \
                 isCompound:false}) {P0} AlgorithmIdentifier @5",
            ),
            (
                "SEC 1, trailing data after it",
                [&p256[..], &[0xff, 0xff]].concat(),
                "P-256",
            ),
            (
                "SEC 1, a NULL closing it after [0]",
                sec1_key(&one, &[&curve(P256), &NULL]),
                ": asn1: structure error: tags don't match (16 vs {class:0 tag:4 length:1 \
                 isCompound:false}) {P0} AlgorithmIdentifier @5",
            ),
            (
                "PKCS#8 EC, no inner curve",
                pkcs8_key(&[&ec, &oid(P256)], &sec1_key(&one, &[])),
                "P-256",
            ),
            (
                "PKCS#8 EC, outer curve wins",
                pkcs8_key(&[&ec, &p384_params], &sec1_key(&one, &[&curve(P256)])),
                "P-384",
            ),
            (
                "PKCS#8 EC, NULL parameters, inner curve",
                pkcs8_key(&[&ec, &NULL], &sec1_key(&one, &[&curve(P521)])),
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
                pkcs8_key(&[&ed, &NULL], &seed),
                ": x509: invalid Ed25519 private key parameters",
            ),
            (
                "PKCS#8 Ed25519, 31 bytes",
                pkcs8_key(&[&ed], &octets(&[7; 31])),
                ": x509: invalid Ed25519 private key length: 31",
            ),
            (
                "PKCS#8 Ed25519, 33 bytes",
                pkcs8_key(&[&ed], &octets(&[7; 33])),
                ": x509: invalid Ed25519 private key length: 33",
            ),
            (
                "PKCS#8 X25519",
                pkcs8_key(&[&x], &seed),
                "tls: found unknown private key type in PKCS#8 wrapping",
            ),
            (
                "PKCS#8 X25519, 31 bytes",
                pkcs8_key(&[&x], &octets(&[7; 31])),
                ": crypto/ecdh: invalid private key size",
            ),
            ("PKCS#1", rsa(&[0], &[]), "RSA"),
            ("PKCS#1, negative version", rsa(&[0xff], &[]), "RSA"),
            (
                "PKCS#1, version 2",
                rsa(&[2], &[]),
                ": x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this \
                 key format)",
            ),
            (
                "PKCS#1, trailing data after it",
                [&rsa(&[0], &[])[..], &[0x00]].concat(),
                ": x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this \
                 key format)",
            ),
        ]);
    }

    /// PKCS#1's optional values: the CRT values only as INTEGERs, the
    /// additional primes only as a SEQUENCE whose elements are each a
    /// SEQUENCE of three INTEGERs, and anything after them ignored but for
    /// a header that does not read.  And the version and E each held to
    /// the eight bytes of a 64-bit Go's `int`
    /// (`encoding/asn1/asn1.go:959-963`), on a key that is whole but for
    /// that one value.  A key refused gets Go's `ParsePKCS1PrivateKey`
    /// error.
    #[test]
    fn pkcs1_reads_as_go_reads_it() {
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
        for (label, der, want) in [
            ("no CRT values", key(&[]), ""),
            ("Dp alone", key(&[&int(&[1])]), ""),
            ("CRT values", key(&[&int(&[1]), &int(&[1]), &int(&[1])]), ""),
            ("a prime", key(&[&seq(&[&prime])]), ""),
            ("no primes", key(&[&seq(&[])]), ""),
            ("a NULL after it", key(&[&NULL]), ""),
            (
                "a prime of two values",
                key(&[&seq(&[&seq(&[&int(&[13]), &int(&[1])])])]),
                "asn1: syntax error: sequence truncated",
            ),
            (
                "a prime that is an INTEGER",
                key(&[&seq(&[&int(&[13])])]),
                "asn1: structure error: sequence tag mismatch",
            ),
            (
                "a bad header after it",
                key(&[&[0xff]]),
                "asn1: syntax error: truncated base 128 integer",
            ),
            (
                "an E of eight bytes",
                with(2, &[1, 0, 0, 0, 0, 0, 0, 0]),
                "",
            ),
            (
                "an E of nine bytes",
                with(2, &[1, 0, 0, 0, 0, 0, 0, 0, 1]),
                "asn1: structure error: integer too large",
            ),
            (
                "a negative version of eight bytes",
                with(0, &[0xff, 0, 0, 0, 0, 0, 0, 0]),
                "",
            ),
            (
                "a negative version of nine bytes",
                with(0, &[0xff, 0, 0, 0, 0, 0, 0, 0, 0]),
                "asn1: structure error: integer too large",
            ),
            (
                "a CRT value not minimal",
                key(&[&int(&[0, 1])]),
                "asn1: structure error: integer not minimally-encoded",
            ),
        ] {
            let got = parse_pkcs1(&der)
                .err()
                .map_or_else(String::new, |cause| cause.to_string());
            assert_eq!(got, want, "{label}: {der:02x?}");
        }
    }

    /// One row per text Go gives on this path: each `encoding/asn1` text
    /// at the top level and inside the algorithm identifier and the
    /// embedded keys, each type name Go prints for a field of another tag,
    /// with the offset Go counts, the hints, and each `crypto/x509` and
    /// `crypto/ecdsa` text, written out as Go 1.27.3 gives them; but for
    /// the three ML-DSA seeds, which Go loads and this provider refuses
    /// with its own text.
    #[test]
    fn each_cause_reads_as_go_gives_it() {
        let ec = oid(EC_PUBLIC_KEY);
        let rsa_encryption = oid(RSA_ENCRYPTION);
        let in_rsa = |inner: &[u8]| pkcs8_key(&[&rsa_encryption], inner);
        let in_ec = |inner: &[u8]| pkcs8_key(&[&ec, &oid(P256)], inner);
        let in_ec_bare = |inner: &[u8]| pkcs8_key(&[&ec], inner);
        let in_ed = |inner: &[u8]| pkcs8_key(&[&oid(ED25519)], inner);
        let in_x = |inner: &[u8]| pkcs8_key(&[&oid(X25519)], inner);
        let ml65 = oid(ML_DSA_65);
        let in_ml65 = |inner: &[u8]| pkcs8_key(&[&ml65], inner);
        let ml_seed = [&[0x80, 0x20][..], &[9; 32]].concat();
        let rsa_base = [
            int(&[0]),
            int(&[0x00, 0xc5]),
            int(&[3]),
            int(&[5]),
            int(&[7]),
            int(&[11]),
        ]
        .concat();
        let rsa_with = |rest: &[u8]| seq(&[&rsa_base, rest]);
        let bad_int = int(&[0, 1]);
        check(&[
            // The PKCS#8 structure, at the top level.
            ("empty", vec![], ": asn1: syntax error: sequence truncated"),
            (
                "an identifier alone",
                vec![0x30],
                ": asn1: syntax error: truncated tag or length",
            ),
            (
                "an indefinite length",
                vec![0x30, 0x80],
                ": asn1: syntax error: indefinite length found (not DER)",
            ),
            (
                "a length of 2^31",
                vec![0x30, 0x84, 0x80, 0x00, 0x00, 0x00],
                ": asn1: structure error: length too large",
            ),
            (
                "a length with a leading zero",
                vec![0x30, 0x82, 0x00, 0x80],
                ": asn1: structure error: superfluous leading zeros in length",
            ),
            (
                "a long length under 128",
                [&[0x30, 0x81, 0x03][..], &int(&[0])].concat(),
                ": asn1: structure error: non-minimal length",
            ),
            (
                "a length cut short",
                vec![0x30, 0x82, 0x01],
                ": asn1: syntax error: truncated tag or length",
            ),
            (
                "a high tag under 31",
                vec![0x3f, 0x10, 0x00],
                ": asn1: syntax error: non-minimal tag",
            ),
            (
                "a high tag led by 0x80",
                vec![0x3f, 0x80, 0x1f, 0x00],
                ": asn1: syntax error: integer is not minimally encoded",
            ),
            (
                "a high tag cut short",
                vec![0x3f, 0x81],
                ": asn1: syntax error: truncated base 128 integer",
            ),
            (
                "a high tag of 2^31",
                vec![0x3f, 0x88, 0x80, 0x80, 0x80, 0x00, 0x00],
                ": asn1: structure error: base 128 integer too large",
            ),
            (
                "a high tag of six groups",
                vec![0x3f, 0x81, 0x81, 0x81, 0x81, 0x81, 0x01, 0x00],
                ": asn1: structure error: base 128 integer too large",
            ),
            (
                "a high tag of 31",
                vec![0x3f, 0x1f, 0x00],
                ": asn1: structure error: tags don't match (16 vs {class:0 tag:31 length:0 \
                 isCompound:true}) {P0} pkcs8 @3",
            ),
            (
                "text",
                b"not a key".to_vec(),
                ": asn1: structure error: tags don't match (16 vs {class:1 tag:14 length:111 \
                 isCompound:true}) {P0} pkcs8 @2",
            ),
            (
                "a SET",
                tlv(0x31, &int(&[0])),
                ": asn1: structure error: tags don't match (16 vs {class:0 tag:17 length:3 \
                 isCompound:true}) {P0} pkcs8 @2",
            ),
            (
                "a primitive SEQUENCE",
                tlv(0x10, &int(&[0])),
                ": asn1: structure error: tags don't match (16 vs {class:0 tag:16 length:3 \
                 isCompound:false}) {P0} pkcs8 @2",
            ),
            (
                "content cut short",
                vec![0x30, 0x05, 0x02, 0x01, 0x00],
                ": asn1: syntax error: data truncated",
            ),
            (
                "an empty SEQUENCE",
                seq(&[]),
                ": asn1: syntax error: sequence truncated",
            ),
            (
                "an empty version",
                seq(&[&int(&[])]),
                ": asn1: structure error: empty integer",
            ),
            (
                "a version not minimal",
                seq(&[&bad_int]),
                ": asn1: structure error: integer not minimally-encoded",
            ),
            (
                "a version of nine bytes",
                seq(&[&int(&[1; 9])]),
                ": asn1: structure error: integer too large",
            ),
            (
                "a version of another tag",
                seq(&[&NULL]),
                ": asn1: structure error: tags don't match (2 vs {class:0 tag:5 length:0 \
                 isCompound:false}) {P0} int @2",
            ),
            (
                "an INTEGER for the algorithm",
                seq(&[&int(&[0]), &int(&[1])]),
                ": asn1: structure error: tags don't match (16 vs {class:0 tag:2 length:1 \
                 isCompound:false}) {P0} AlgorithmIdentifier @5",
            ),
            (
                "no algorithm",
                seq(&[&int(&[0])]),
                ": asn1: syntax error: sequence truncated",
            ),
            (
                "an empty algorithm",
                seq(&[&int(&[0]), &seq(&[])]),
                ": asn1: syntax error: sequence truncated",
            ),
            (
                "an algorithm of another tag",
                seq(&[&int(&[0]), &seq(&[&NULL])]),
                ": asn1: structure error: tags don't match (6 vs {class:0 tag:5 length:0 \
                 isCompound:false}) {P0} ObjectIdentifier @2",
            ),
            (
                "an empty algorithm identifier, and no key",
                seq(&[&int(&[0]), &seq(&[&oid(&[])])]),
                ": asn1: syntax error: zero length OBJECT IDENTIFIER",
            ),
            (
                "an algorithm identifier led by 0x80",
                pkcs8_key(&[&oid(&[0x80, 0x01])], &[]),
                ": asn1: syntax error: integer is not minimally encoded",
            ),
            (
                "an algorithm identifier cut short",
                pkcs8_key(&[&oid(&[0x2b, 0x81])], &[]),
                ": asn1: syntax error: truncated base 128 integer",
            ),
            (
                "an algorithm identifier of 2^31",
                pkcs8_key(&[&oid(&[0x2b, 0x88, 0x80, 0x80, 0x80, 0x00])], &[]),
                ": asn1: structure error: base 128 integer too large",
            ),
            (
                "parameters cut short",
                seq(&[&int(&[0]), &seq(&[&ec, &[0x05]])]),
                ": asn1: syntax error: truncated tag or length",
            ),
            (
                "parameters running past the end",
                seq(&[&int(&[0]), &seq(&[&ec, &[0x05, 0x02]])]),
                ": asn1: syntax error: data truncated",
            ),
            (
                "no key",
                seq(&[&int(&[0]), &seq(&[&ec])]),
                ": asn1: syntax error: sequence truncated",
            ),
            (
                "a key of another tag",
                seq(&[&int(&[0]), &seq(&[&ec]), &int(&[1])]),
                ": asn1: structure error: tags don't match (4 vs {class:0 tag:2 length:1 \
                 isCompound:false}) {P0}  @16",
            ),
            (
                "a key running past the end",
                seq(&[&int(&[0]), &seq(&[&ec]), &[0x04, 0x05]]),
                ": asn1: syntax error: data truncated",
            ),
            // The hints, for input of another shape.
            (
                "SEC 1, P-256, version 2",
                seq(&[&int(&[2]), &octets(&[1]), &curve(P256)]),
                ": x509: failed to parse private key (use ParseECPrivateKey instead for this key \
                 format)",
            ),
            (
                "SEC 1, an unknown curve",
                sec1_key(&[1], &[&curve(&[0x2a, 0x03])]),
                ": x509: failed to parse private key (use ParseECPrivateKey instead for this key \
                 format)",
            ),
            (
                "PKCS#1, version 2",
                rsa(&[2], &[]),
                ": x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this \
                 key format)",
            ),
            (
                "PKCS#1, trailing data",
                [&rsa(&[0], &[])[..], &NULL].concat(),
                ": x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this \
                 key format)",
            ),
            // A PKCS#1 key inside PKCS#8.
            (
                "RSA holding SEC 1",
                in_rsa(&sec1_key(&[1], &[&curve(P256)])),
                ": x509: failed to parse RSA private key embedded in PKCS#8: x509: failed to \
                 parse private key (use ParseECPrivateKey instead for this key format)",
            ),
            (
                "RSA holding PKCS#8",
                in_rsa(&in_ed(&octets(&[7; 32]))),
                ": x509: failed to parse RSA private key embedded in PKCS#8: x509: failed to \
                 parse private key (use ParsePKCS8PrivateKey instead for this key format)",
            ),
            (
                "RSA, trailing data",
                in_rsa(&[&rsa(&[0], &[])[..], &[0x00]].concat()),
                ": x509: failed to parse RSA private key embedded in PKCS#8: asn1: syntax error: \
                 trailing data",
            ),
            (
                "RSA, version 2",
                in_rsa(&rsa(&[2], &[])),
                ": x509: failed to parse RSA private key embedded in PKCS#8: x509: unsupported \
                 private key version",
            ),
            (
                "RSA, empty",
                in_rsa(&[]),
                ": x509: failed to parse RSA private key embedded in PKCS#8: asn1: syntax error: \
                 sequence truncated",
            ),
            (
                "RSA, an indefinite length",
                in_rsa(&[0x30, 0x80]),
                ": x509: failed to parse RSA private key embedded in PKCS#8: asn1: syntax error: \
                 indefinite length found (not DER)",
            ),
            (
                "RSA, N of another tag",
                in_rsa(&seq(&[&int(&[0]), &NULL])),
                ": x509: failed to parse RSA private key embedded in PKCS#8: asn1: structure \
                 error: tags don't match (2 vs {class:0 tag:5 length:0 isCompound:false}) {P0}  \
                 @5",
            ),
            (
                "RSA, E of another tag",
                in_rsa(&seq(&[&int(&[0]), &int(&[0x00, 0xc5]), &octets(&[3])])),
                ": x509: failed to parse RSA private key embedded in PKCS#8: asn1: structure \
                 error: tags don't match (2 vs {class:0 tag:4 length:1 isCompound:false}) {P0} \
                 int @9",
            ),
            (
                "RSA, E of a high tag",
                in_rsa(&seq(&[
                    &int(&[0]),
                    &int(&[0x00, 0xc5]),
                    &[0x3f, 0x1f, 0x00],
                ])),
                ": x509: failed to parse RSA private key embedded in PKCS#8: asn1: structure \
                 error: tags don't match (2 vs {class:0 tag:31 length:0 isCompound:true}) {P0} \
                 int @10",
            ),
            (
                "RSA, E of nine bytes",
                in_rsa(&seq(&[&int(&[0]), &int(&[0x00, 0xc5]), &int(&[1; 9])])),
                ": x509: failed to parse RSA private key embedded in PKCS#8: asn1: structure \
                 error: integer too large",
            ),
            (
                "RSA, a CRT value not minimal",
                in_rsa(&rsa_with(&bad_int)),
                ": x509: failed to parse RSA private key embedded in PKCS#8: asn1: structure \
                 error: integer not minimally-encoded",
            ),
            (
                "RSA, primes: an INTEGER",
                in_rsa(&rsa_with(&seq(&[&int(&[1])]))),
                ": x509: failed to parse RSA private key embedded in PKCS#8: asn1: structure \
                 error: sequence tag mismatch",
            ),
            (
                "RSA, primes: a prime of two",
                in_rsa(&rsa_with(&seq(&[&seq(&[&int(&[13]), &int(&[1])])]))),
                ": x509: failed to parse RSA private key embedded in PKCS#8: asn1: syntax error: \
                 sequence truncated",
            ),
            (
                "RSA, primes: first element a bad INTEGER",
                in_rsa(&rsa_with(&seq(&[&seq(&[
                    &bad_int,
                    &int(&[1]),
                    &int(&[1]),
                ])]))),
                ": x509: failed to parse RSA private key embedded in PKCS#8: asn1: structure \
                 error: integer not minimally-encoded",
            ),
            (
                "RSA, primes: first element a bad INTEGER, second of another tag",
                in_rsa(&rsa_with(&seq(&[
                    &seq(&[&bad_int, &int(&[1]), &int(&[1])]),
                    &int(&[5]),
                ]))),
                ": x509: failed to parse RSA private key embedded in PKCS#8: asn1: structure \
                 error: sequence tag mismatch",
            ),
            (
                "RSA, primes: an element cut short",
                in_rsa(&rsa_with(&seq(&[&[0x30, 0x05, 0x02]]))),
                ": x509: failed to parse RSA private key embedded in PKCS#8: asn1: syntax error: \
                 truncated sequence",
            ),
            (
                "RSA, primes: a prime of another tag",
                in_rsa(&rsa_with(&seq(&[&seq(&[&NULL, &int(&[1]), &int(&[1])])]))),
                ": x509: failed to parse RSA private key embedded in PKCS#8: asn1: structure \
                 error: tags don't match (2 vs {class:0 tag:5 length:0 isCompound:false}) {P0}  \
                 @2",
            ),
            // A SEC 1 key inside PKCS#8.
            (
                "EC holding PKCS#8",
                in_ec(&in_ed(&octets(&[7; 32]))),
                ": x509: failed to parse EC private key embedded in PKCS#8: x509: failed to parse \
                 private key (use ParsePKCS8PrivateKey instead for this key format)",
            ),
            (
                "EC holding PKCS#1",
                in_ec(&rsa(&[0], &[])),
                ": x509: failed to parse EC private key embedded in PKCS#8: x509: failed to parse \
                 private key (use ParsePKCS1PrivateKey instead for this key format)",
            ),
            (
                "EC, empty",
                in_ec(&[]),
                ": x509: failed to parse EC private key embedded in PKCS#8: x509: failed to parse \
                 EC private key: asn1: syntax error: sequence truncated",
            ),
            (
                "EC, an identifier alone",
                in_ec(&[0x30]),
                ": x509: failed to parse EC private key embedded in PKCS#8: x509: failed to parse \
                 EC private key: asn1: syntax error: truncated tag or length",
            ),
            (
                "EC, a version of another tag",
                in_ec(&seq(&[&NULL])),
                ": x509: failed to parse EC private key embedded in PKCS#8: x509: failed to parse \
                 EC private key: asn1: structure error: tags don't match (2 vs {class:0 tag:5 \
                 length:0 isCompound:false}) {P0} int @2",
            ),
            (
                "EC, a scalar of another tag",
                in_ec(&seq(&[&int(&[1]), &NULL])),
                ": x509: failed to parse EC private key embedded in PKCS#8: x509: failed to parse \
                 EC private key: asn1: structure error: tags don't match (4 vs {class:0 tag:5 \
                 length:0 isCompound:false}) {P0}  @5",
            ),
            (
                "EC, an element after the scalar ending it",
                in_ec(&sec1_key(&[1], &[&NULL])),
                ": x509: failed to parse EC private key embedded in PKCS#8: x509: failed to parse \
                 EC private key: asn1: structure error: explicit tag has no child",
            ),
            (
                "EC, an empty [0]",
                in_ec(&sec1_key(&[1], &[&[0xa0, 0x00], &NULL])),
                ": x509: failed to parse EC private key embedded in PKCS#8: x509: failed to parse \
                 EC private key: asn1: structure error: zero length explicit tag was not an \
                 asn1.Flag",
            ),
            (
                "EC, [0] an empty identifier",
                in_ec_bare(&sec1_key(&[1], &[&curve(&[])])),
                ": x509: failed to parse EC private key embedded in PKCS#8: x509: failed to parse \
                 EC private key: asn1: syntax error: zero length OBJECT IDENTIFIER",
            ),
            (
                "EC, [0] an identifier cut short",
                in_ec_bare(&sec1_key(&[1], &[&curve(&[0x2b, 0x81])])),
                ": x509: failed to parse EC private key embedded in PKCS#8: x509: failed to parse \
                 EC private key: asn1: syntax error: truncated base 128 integer",
            ),
            (
                "EC, [0] an identifier of six groups",
                in_ec_bare(&sec1_key(
                    &[1],
                    &[&curve(&[0x81, 0x81, 0x81, 0x81, 0x81, 0x01])],
                )),
                ": x509: failed to parse EC private key embedded in PKCS#8: x509: failed to parse \
                 EC private key: asn1: structure error: base 128 integer too large",
            ),
            (
                "EC, [0] an identifier running past the end",
                in_ec_bare(&sec1_key(&[1], &[&[0xa0, 0x03, 0x06, 0x05, 0x2a]])),
                ": x509: failed to parse EC private key embedded in PKCS#8: x509: failed to parse \
                 EC private key: asn1: syntax error: data truncated",
            ),
            (
                "EC, [1] an empty bit string",
                in_ec(&sec1_key(
                    &[1],
                    &[&curve(P256), &tlv(0xa1, &tlv(0x03, &[]))],
                )),
                ": x509: failed to parse EC private key embedded in PKCS#8: x509: failed to parse \
                 EC private key: asn1: syntax error: zero length BIT STRING",
            ),
            (
                "EC, [1] with bad padding bits",
                in_ec(&sec1_key(
                    &[1],
                    &[&curve(P256), &tlv(0xa1, &tlv(0x03, &[1, 1]))],
                )),
                ": x509: failed to parse EC private key embedded in PKCS#8: x509: failed to parse \
                 EC private key: asn1: syntax error: invalid padding bits in BIT STRING",
            ),
            (
                "EC, version 0",
                in_ec(&seq(&[&int(&[0]), &octets(&[1])])),
                ": x509: failed to parse EC private key embedded in PKCS#8: x509: unknown EC \
                 private key version 0",
            ),
            (
                "EC, version -1",
                in_ec(&seq(&[&int(&[0xff]), &octets(&[1])])),
                ": x509: failed to parse EC private key embedded in PKCS#8: x509: unknown EC \
                 private key version -1",
            ),
            (
                "EC, version -128",
                in_ec(&seq(&[&int(&[0x80]), &octets(&[1])])),
                ": x509: failed to parse EC private key embedded in PKCS#8: x509: unknown EC \
                 private key version -128",
            ),
            (
                "EC, the largest version",
                in_ec(&seq(&[
                    &int(&[0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
                    &octets(&[1]),
                ])),
                ": x509: failed to parse EC private key embedded in PKCS#8: x509: unknown EC \
                 private key version 9223372036854775807",
            ),
            (
                "EC, parameters naming no curve Go knows",
                pkcs8_key(
                    &[&ec, &oid(&[0x2a, 0x03])],
                    &sec1_key(&[1], &[&curve(P256)]),
                ),
                ": x509: failed to parse EC private key embedded in PKCS#8: x509: unknown \
                 elliptic curve",
            ),
            (
                "EC, no curve",
                in_ec_bare(&sec1_key(&[1], &[])),
                ": x509: failed to parse EC private key embedded in PKCS#8: x509: unknown \
                 elliptic curve",
            ),
            (
                "EC, a scalar a byte too long",
                in_ec(&sec1_key(&[1; 33], &[])),
                ": x509: failed to parse EC private key embedded in PKCS#8: x509: invalid private \
                 key length",
            ),
            // An Ed25519 key inside PKCS#8.
            (
                "Ed25519, NULL parameters",
                pkcs8_key(&[&oid(ED25519), &NULL], &octets(&[7; 32])),
                ": x509: invalid Ed25519 private key parameters",
            ),
            (
                "Ed25519, the seed bare",
                in_ed(&[7; 32]),
                ": x509: invalid Ed25519 private key: asn1: structure error: tags don't match (4 \
                 vs {class:0 tag:7 length:7 isCompound:false}) {P0}  @2",
            ),
            (
                "Ed25519, empty",
                in_ed(&[]),
                ": x509: invalid Ed25519 private key: asn1: syntax error: sequence truncated",
            ),
            (
                "Ed25519, a length of 2^31",
                in_ed(&[0x04, 0x84, 0x80, 0, 0, 0]),
                ": x509: invalid Ed25519 private key: asn1: structure error: length too large",
            ),
            (
                "Ed25519, the seed running past the end",
                in_ed(&[0x04, 0x21, 7]),
                ": x509: invalid Ed25519 private key: asn1: syntax error: data truncated",
            ),
            (
                "Ed25519, an empty seed",
                in_ed(&octets(&[])),
                ": x509: invalid Ed25519 private key length: 0",
            ),
            // An X25519 key inside PKCS#8.
            (
                "X25519, NULL parameters",
                pkcs8_key(&[&oid(X25519), &NULL], &octets(&[7; 32])),
                ": x509: invalid X25519 private key parameters",
            ),
            (
                "X25519, the key bare",
                in_x(&[7; 32]),
                ": x509: invalid X25519 private key: asn1: structure error: tags don't match (4 \
                 vs {class:0 tag:7 length:7 isCompound:false}) {P0}  @2",
            ),
            (
                "X25519, 33 bytes",
                in_x(&octets(&[7; 33])),
                ": crypto/ecdh: invalid private key size",
            ),
            // An ML-DSA key inside PKCS#8.
            (
                "ML-DSA-44, a seed",
                pkcs8_key(&[&oid(ML_DSA_44)], &ml_seed),
                "unsupported private key: ML-DSA-44",
            ),
            (
                "ML-DSA-65, a seed",
                in_ml65(&ml_seed),
                "unsupported private key: ML-DSA-65",
            ),
            (
                "ML-DSA-87, a seed",
                pkcs8_key(&[&oid(ML_DSA_87)], &ml_seed),
                "unsupported private key: ML-DSA-87",
            ),
            (
                "ML-DSA-65, NULL parameters",
                pkcs8_key(&[&ml65, &NULL], &ml_seed),
                ": x509: invalid ML-DSA private key parameters",
            ),
            (
                "ML-DSA-65, empty",
                in_ml65(&[]),
                ": x509: invalid ML-DSA private key length: 0",
            ),
            (
                "ML-DSA-65, the expanded key alone",
                in_ml65(&octets(&[0; 10])),
                ": x509: semi-expanded ML-DSA private keys without seed are not supported",
            ),
            (
                "ML-DSA-65, both",
                in_ml65(&seq(&[])),
                ": x509: ML-DSA private keys with both seed and expanded key are not supported, \
                 use e.g. \"openssl pkey -provparam ml-dsa.output_formats=seed-only\" to convert \
                 to a seed-only key",
            ),
            (
                "ML-DSA-65, the seed under [1]",
                in_ml65(&[&[0x81, 0x20][..], &[9; 32]].concat()),
                ": x509: invalid ML-DSA private key: invalid ASN.1 tag 81",
            ),
            (
                "ML-DSA-65, a seed of 31 bytes",
                in_ml65(&[&[0x80, 0x1f][..], &[9; 31]].concat()),
                ": x509: invalid ML-DSA private key length: 33",
            ),
            (
                "ML-DSA-65, a seed of 32 bytes said to be 31",
                in_ml65(&[&[0x80, 0x1f][..], &[9; 32]].concat()),
                ": x509: invalid ML-DSA private key ASN.1 encoding",
            ),
            (
                "ML-DSA-87, NULL parameters",
                pkcs8_key(&[&oid(ML_DSA_87), &NULL], &ml_seed),
                ": x509: invalid ML-DSA private key parameters",
            ),
            // Algorithms Go does not know, named as Go names them.
            (
                "algorithm 0.39",
                pkcs8_key(&[&oid(&[0x27])], &[]),
                ": x509: PKCS#8 wrapping contained private key with unknown algorithm: 0.39",
            ),
            (
                "algorithm 2.47",
                pkcs8_key(&[&oid(&[0x7f])], &[]),
                ": x509: PKCS#8 wrapping contained private key with unknown algorithm: 2.47",
            ),
            (
                "algorithm 1.2.3",
                pkcs8_key(&[&oid(&[0x2a, 0x03])], &[]),
                ": x509: PKCS#8 wrapping contained private key with unknown algorithm: 1.2.3",
            ),
            (
                "algorithm 2.999",
                pkcs8_key(&[&oid(&[0x88, 0x37])], &[]),
                ": x509: PKCS#8 wrapping contained private key with unknown algorithm: 2.999",
            ),
            (
                "algorithm 2.999.1",
                pkcs8_key(&[&oid(&[0x88, 0x37, 0x01])], &[]),
                ": x509: PKCS#8 wrapping contained private key with unknown algorithm: 2.999.1",
            ),
            (
                "algorithm 2.2147483567",
                pkcs8_key(&[&oid(&[0x87, 0xff, 0xff, 0xff, 0x7f])], &[]),
                ": x509: PKCS#8 wrapping contained private key with unknown algorithm: \
                 2.2147483567",
            ),
            (
                "algorithm Ed448",
                pkcs8_key(&[&oid(&[0x2b, 0x65, 0x71])], &[]),
                ": x509: PKCS#8 wrapping contained private key with unknown algorithm: 1.3.101.113",
            ),
        ]);
    }

    /// A scalar outside `[1, n)` once Go has stripped or padded it: Go's
    /// "ecdsa: invalid public key encoding" when it is zero or a multiple
    /// of n, which only P-521's 66 bytes hold past n itself, and "input
    /// overflows the modulus" for any other at or above n; on P-224 as on
    /// the curves the provider signs on.
    #[test]
    fn a_scalar_outside_the_order_reads_as_go_refuses_it() {
        let ec = oid(EC_PUBLIC_KEY);
        let add = |value: &[u8], small: u8| {
            let sum = BigUint::from_bytes_be(value) + small;
            let bytes = sum.to_bytes_be();
            [vec![0; value.len() - bytes.len()], bytes].concat()
        };
        let times = |value: &[u8], factor: u8| {
            let product = BigUint::from_bytes_be(value) * factor;
            let bytes = product.to_bytes_be();
            [vec![0; value.len() - bytes.len()], bytes].concat()
        };
        let mut rows = Vec::new();
        for (name, curve_oid, order) in [
            ("P-224", P224, &P224_ORDER[..]),
            ("P-256", P256, &P256_ORDER[..]),
            ("P-384", P384, &P384_ORDER[..]),
            ("P-521", P521, &P521_ORDER[..]),
        ] {
            let mut scalars = vec![
                ("zero", vec![0; order.len()]),
                ("empty", vec![]),
                ("n", order.to_vec()),
                ("n + 1", add(order, 1)),
                ("all ones", vec![0xff; order.len()]),
            ];
            if name == "P-521" {
                scalars.push(("2n", times(order, 2)));
                scalars.push(("2n + 1", add(&times(order, 2), 1)));
                scalars.push(("3n", times(order, 3)));
                scalars.push(("127n", times(order, 127)));
            }
            for (label, scalar) in scalars {
                rows.push((
                    format!("{name}, {label}"),
                    pkcs8_key(&[&ec, &oid(curve_oid)], &sec1_key(&scalar, &[])),
                ));
            }
        }
        let encoding = ": x509: failed to parse EC private key embedded in PKCS#8: ecdsa: invalid \
                        public key encoding";
        let overflows = ": x509: failed to parse EC private key embedded in PKCS#8: input \
                         overflows the modulus";
        let rows: Vec<(&str, Vec<u8>, &str)> = rows
            .iter()
            .map(|(label, der)| {
                let multiple = ["zero", "empty", "n", "2n", "3n", "127n"]
                    .iter()
                    .any(|end| label.ends_with(&format!(", {end}")));
                (
                    label.as_str(),
                    der.clone(),
                    if multiple { encoding } else { overflows },
                )
            })
            .collect();
        check(&rows);
    }

    /// Each curve the provider signs on takes a scalar of n - 1, at the
    /// field's length or stripped to it, and refuses n: the top of
    /// `[1, n)`, which the curve crate checks
    /// (`elliptic-curve-0.14.3/src/scalar/value.rs:69-79`) where Go's
    /// `NewPrivateKey` does
    /// (`crypto/internal/fips140/ecdsa/ecdsa.go:172-178`).  So the orders
    /// written out here are the curve crates' own.
    #[test]
    fn each_signing_curve_takes_scalars_below_its_order() {
        for (oid, order, name) in [
            (P256, &P256_ORDER[..], "P-256"),
            (P384, &P384_ORDER[..], "P-384"),
            (P521, &P521_ORDER[..], "P-521"),
        ] {
            let mut n_minus_one = order.to_vec();
            *n_minus_one.last_mut().expect("an order") -= 1;
            let key = |scalar: &[u8]| verdict(&sec1_key(scalar, &[&curve(oid)]));
            assert_eq!(key(&n_minus_one), name);
            assert_eq!(key(&[&[0][..], &n_minus_one].concat()), name);
            assert!(
                parse(&sec1_key(order, &[&curve(oid)])).is_err(),
                "{name}: n"
            );
        }
    }

    /// A P-224 scalar is refused as P-224 only where Go loads it: in
    /// `[1, n)` once Go has stripped or padded it.
    #[test]
    fn p224_is_refused_only_where_go_loads_it() {
        let n_minus_one = unhex("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3c");
        let key = |scalar: &[u8]| parse(&sec1_key(scalar, &[&curve(P224)])).err();
        assert_eq!(key(&n_minus_one), Some(KeyError::P224));
        assert_eq!(
            key(&[&[0, 0][..], &n_minus_one].concat()),
            Some(KeyError::P224)
        );
        assert_eq!(key(&[1]), Some(KeyError::P224));
        for refused in [&[0; 28][..], &P224_ORDER, &[1; 29]] {
            assert!(
                matches!(key(refused), Some(KeyError::Unparsable(_))),
                "{refused:02x?}"
            );
        }
    }
}
