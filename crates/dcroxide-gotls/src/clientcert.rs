// SPDX-License-Identifier: ISC
//! The client certificate verifier Go's `crypto/tls` server runs for
//! `RequireAndVerifyClientCert`: `x509.Certificate.Verify` over the
//! `ClientCAs` pool with the client's other certificates as
//! intermediates and `ExtKeyUsageClientAuth` asked for
//! (`processCertsFromClient`, `crypto/tls/handshake_server.go`), in Go's
//! order and with Go's verdicts where webpki's would differ
//! ([`GoClientCertVerifier`]).
//!
//! dcrd runs it under `--authtype=clientcert` over the `--clientcafile`
//! pool (`newTLSConfig`, `server.go:3689-3699`); dcrwallet runs it on its
//! gRPC listener always and on its JSON-RPC listener under
//! `--jsonrpcauthtype=clientcert`, over the `--clientcafile` pool and the
//! authority `--issueclientcert` adds (`rpcserver.go:272-322`).  Both
//! build a [`ClientCaPool`] and hand it to [`GoClientCertVerifier::new`];
//! dcrd's refusal of a file that added nothing is
//! [`GoClientCertVerifier::from_pem`].
//!
//! Certificates are read by Go's parser's rules as far as the verdicts
//! need ([`CertFacts::parse`]), chains are searched as Go's `buildChains`
//! searches them, budget included ([`go_build_chains`]), and the path
//! webpki then verifies is held to Go's path length, extended key usage,
//! policy, name and distrust rules.  PARITY.md's clientcert entry lists
//! what still differs.

use std::sync::Arc;

use crate::pem::go_pem_decode;

/// The error for a client CA file that added no certificate
/// ([`GoClientCertVerifier::from_pem`]); a caller that knows the file's
/// path turns it into dcrd's `no certificates found in %q`
/// (`newTLSConfig`, `server.go:3696-3698`).
pub const NO_CLIENT_CAS: &str = "no certificates found in the client CA file";

/// A minimal DER reader over the certificate fields Go's client
/// verification reads: low-tag-number elements of a definite length
/// written in the fewest octets, which is every shape cryptobyte, and so
/// Go's own parser, accepts.
struct DerReader<'a> {
    data: &'a [u8],
}

impl<'a> DerReader<'a> {
    fn new(data: &'a [u8]) -> DerReader<'a> {
        DerReader { data }
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// The next element's tag and content.  A long-form length must
    /// need its form and open with a nonzero octet, as cryptobyte's
    /// `readASN1` requires (`vendor/golang.org/x/crypto/cryptobyte/asn1.go`).
    // A length of at most four bytes, checked against the input.
    #[allow(clippy::arithmetic_side_effects)]
    fn read(&mut self) -> Option<(u8, &'a [u8])> {
        let (&tag, rest) = self.data.split_first()?;
        if tag & 0x1f == 0x1f {
            return None;
        }
        let (&first, mut rest) = rest.split_first()?;
        let len = if first & 0x80 == 0 {
            usize::from(first)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 4 || rest.len() < n || rest[0] == 0 {
                return None;
            }
            let (len_bytes, tail) = rest.split_at(n);
            rest = tail;
            let len = len_bytes
                .iter()
                .fold(0usize, |len, &b| (len << 8) | usize::from(b));
            if len < 0x80 {
                return None;
            }
            len
        };
        if rest.len() < len {
            return None;
        }
        let (content, tail) = rest.split_at(len);
        self.data = tail;
        Some((tag, content))
    }

    /// The next element's content, which must carry `want`.
    fn read_tag(&mut self, want: u8) -> Option<&'a [u8]> {
        match self.read()? {
            (tag, content) if tag == want => Some(content),
            _ => None,
        }
    }

    /// The next element, whatever its tag, with its content and the
    /// whole element, as cryptobyte's `ReadAnyASN1Element` reads it.
    // The element is the prefix of the input the read consumed.
    #[allow(clippy::arithmetic_side_effects)]
    fn read_any_raw(&mut self) -> Option<(u8, &'a [u8], &'a [u8])> {
        let before = self.data;
        let (tag, content) = self.read()?;
        Some((tag, content, &before[..before.len() - self.data.len()]))
    }

    /// [`DerReader::read_tag`], with the whole element as well.
    // The element is the prefix of the input the read consumed.
    #[allow(clippy::arithmetic_side_effects)]
    fn read_raw(&mut self, want: u8) -> Option<(u8, &'a [u8], &'a [u8])> {
        let before = self.data;
        let content = self.read_tag(want)?;
        Some((want, content, &before[..before.len() - self.data.len()]))
    }
}

/// Whether `content` is an AlgorithmIdentifier's contents Go's `parseAI`
/// (`crypto/x509/parser.go`) reads: an OBJECT IDENTIFIER cryptobyte
/// reads ("x509: malformed OID"), then, if anything follows, one
/// well-formed element ("x509: malformed parameters"), after which
/// nothing is read.
fn go_parse_ai(content: &[u8]) -> bool {
    let mut ai = DerReader::new(content);
    if !ai.read_tag(0x06).is_some_and(go_oid_ok) {
        return false;
    }
    ai.is_empty() || ai.read().is_some()
}

/// A BIT STRING's content as cryptobyte's `ReadASN1BitString` reads it:
/// the count of unused bits, at most seven and none in an empty string,
/// which must all be zero, then the octets.
// A shift of at most seven.
#[allow(clippy::arithmetic_side_effects)]
fn go_bit_string(content: &[u8]) -> Option<(u8, &[u8])> {
    let (&unused, bytes) = content.split_first()?;
    if unused > 7
        || (bytes.is_empty() && unused != 0)
        || bytes
            .last()
            .is_some_and(|last| last & ((1u8 << unused) - 1) != 0)
    {
        return None;
    }
    Some((unused, bytes))
}

/// A subject public key info's algorithm identifier contents and key
/// bits, when its algorithm is one Go 1.27's `x509` gives a key
/// (`getPublicKeyAlgorithmFromOID`: RSA, DSA, ECDSA, Ed25519 and the
/// three ML-DSA parameter sets) and the key bits leave no bit unused;
/// `None` otherwise, which for an algorithm Go does not know is Go's nil
/// `PublicKey`.
fn go_public_key(spki: &[u8]) -> Option<(&[u8], &[u8])> {
    const KNOWN: [&[u8]; 7] = [
        RSA_ENCRYPTION,
        &[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01],
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
        &[0x2b, 0x65, 0x70],
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11],
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12],
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13],
    ];
    let mut spki = DerReader::new(spki);
    let algorithm = spki.read_tag(0x30)?;
    let oid = DerReader::new(algorithm).read_tag(0x06)?;
    if !KNOWN.contains(&oid) {
        return None;
    }
    match go_bit_string(spki.read_tag(0x03)?)? {
        (0, key) => Some((algorithm, key)),
        _ => None,
    }
}

/// The three ML-DSA parameter sets' key algorithms, as DER object
/// identifier contents (`crypto/x509/x509.go:519-532`), with the length
/// of each set's public key (FIPS 204, table 2).
const ML_DSA_KEYS: [(&[u8], usize); 3] = [
    (
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11],
        1312,
    ),
    (
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12],
        1952,
    ),
    (
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13],
        2592,
    ),
];

/// DSA's key algorithm, 1.2.840.10040.4.1, as DER object identifier
/// contents.
const DSA_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01];

/// Whether `content`, an INTEGER's, is one cryptobyte's `ReadASN1Integer`
/// reads (`checkASN1Integer`): at least one octet, minimally encoded.
fn go_asn1_integer_ok(content: &[u8]) -> bool {
    match content {
        [] => false,
        [0x00, next, ..] => next & 0x80 != 0,
        [0xff, next, ..] => next & 0x80 == 0,
        _ => true,
    }
}

/// Whether a minimally encoded INTEGER's content ([`go_asn1_integer_ok`])
/// is above zero, as Go's `Sign() > 0` asks of the value it holds.
fn go_asn1_integer_positive(content: &[u8]) -> bool {
    content.first().is_some_and(|first| first & 0x80 == 0) && content != [0x00]
}

/// A BIT STRING's bits as Go's `asn1.BitString.RightAlign` gives them,
/// which `parsePublicKey` reads a key from (`crypto/x509/parser.go:309-312`):
/// the octets as they are when no bit is unused, and otherwise shifted
/// right by the unused count, the same number of octets.
// A shift of one to seven.
#[allow(clippy::arithmetic_side_effects)]
fn go_right_align(unused: u8, bytes: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    if unused == 0 || bytes.is_empty() {
        return std::borrow::Cow::Borrowed(bytes);
    }
    let shift = u32::from(unused);
    let mut out = Vec::with_capacity(bytes.len());
    let mut carry = 0u8;
    for &b in bytes {
        out.push(carry | (b >> shift));
        carry = b.checked_shl(8 - shift).unwrap_or(0);
    }
    std::borrow::Cow::Owned(out)
}

/// Go 1.27.3's refusal of a certificate's subject public key info, the
/// contents of its SEQUENCE, in Go's words (`parseCertificate` and
/// `parsePublicKey`, `crypto/x509/parser.go:1071-1099`, `:309-411`), or
/// `None` where Go reads the key or, for an algorithm it does not know
/// (`getPublicKeyAlgorithmFromOID`, X25519's among them), leaves
/// `PublicKey` nil and reads nothing more.  The structure first: an
/// AlgorithmIdentifier SEQUENCE ("x509: malformed public key algorithm
/// identifier") that `parseAI` reads, an OBJECT IDENTIFIER cryptobyte
/// takes ("x509: malformed OID") and, if anything follows it, one element
/// as the parameters ("x509: malformed parameters"); then the key's BIT
/// STRING ("x509: malformed subjectPublicKey").  Then the key, its bits
/// right-aligned ([`go_right_align`]), by its algorithm:
///
/// * RSA: NULL parameters, then an `RSAPublicKey` SEQUENCE of a modulus
///   and an exponent, each an INTEGER cryptobyte reads, the exponent into
///   an `int`, at most eight octets on the 64-bit builds dcrd ships, and
///   each above zero; bytes after either are not read.
/// * DSA: the key an INTEGER, the parameters a SEQUENCE of three, all
///   above zero.
/// * ECDSA: parameters that read as an OBJECT IDENTIFIER, naming P-224,
///   P-256, P-384 or P-521, and a point `ecdsa.ParseUncompressedPublicKey`
///   takes on it (`dcroxide_tlscrypto::point`), so that a compressed or
///   hybrid point, one off its curve and one with a coordinate at or above
///   p are refused here, before any signature is checked with them.
/// * Ed25519: no parameters, and 32 bytes.
/// * ML-DSA: no parameters, and the set's length (`mldsa.NewPublicKey`
///   checks no more).
fn go_public_key_refusal(spki: &[u8]) -> Option<&'static str> {
    let mut spki = DerReader::new(spki);
    let Some(algorithm) = spki.read_tag(0x30) else {
        return Some("x509: malformed public key algorithm identifier");
    };
    let mut ai = DerReader::new(algorithm);
    let Some(oid) = ai.read_tag(0x06).filter(|oid| go_oid_ok(oid)) else {
        return Some("x509: malformed OID");
    };
    let params: &[u8] = if ai.is_empty() {
        &[]
    } else {
        match ai.read_any_raw() {
            Some((_, _, element)) => element,
            None => return Some("x509: malformed parameters"),
        }
    };
    let Some((unused, bits)) = spki.read_tag(0x03).and_then(go_bit_string) else {
        return Some("x509: malformed subjectPublicKey");
    };
    let data = go_right_align(unused, bits);
    let data = data.as_ref();
    if oid == RSA_ENCRYPTION {
        if params != [0x05, 0x00] {
            return Some("x509: RSA key missing NULL parameters");
        }
        let Some(mut key) = DerReader::new(data).read_tag(0x30).map(DerReader::new) else {
            return Some("x509: invalid RSA public key");
        };
        let Some(modulus) = key.read_tag(0x02).filter(|n| go_asn1_integer_ok(n)) else {
            return Some("x509: invalid RSA modulus");
        };
        let Some(exponent) = key.read_tag(0x02).filter(|e| go_asn1_int64(e).is_some()) else {
            return Some("x509: invalid RSA public exponent");
        };
        if !go_asn1_integer_positive(modulus) {
            return Some("x509: RSA modulus is not a positive number");
        }
        if !go_asn1_integer_positive(exponent) {
            return Some("x509: RSA public exponent is not a positive number");
        }
        return None;
    }
    if oid == EC_PUBLIC_KEY {
        let Some(curve) = DerReader::new(params)
            .read_tag(0x06)
            .filter(|curve| go_oid_ok(curve))
        else {
            return Some("x509: invalid ECDSA parameters");
        };
        let Some(curve) = dcroxide_tlscrypto::point::NistCurve::from_oid(curve) else {
            return Some("x509: unsupported elliptic curve");
        };
        return dcroxide_tlscrypto::point::go_parse_uncompressed_public_key(curve, data).err();
    }
    if oid == ED25519_KEY {
        if !params.is_empty() {
            return Some("x509: Ed25519 key encoded with illegal parameters");
        }
        if data.len() != 32 {
            return Some("x509: wrong Ed25519 public key size");
        }
        return None;
    }
    if let Some(&(_, len)) = ML_DSA_KEYS.iter().find(|&&(known, _)| known == oid) {
        if !params.is_empty() {
            return Some("x509: ML-DSA key encoded with illegal parameters");
        }
        if data.len() != len {
            return Some("mldsa: invalid public key length");
        }
        return None;
    }
    if oid == DSA_KEY {
        let Some(y) = DerReader::new(data)
            .read_tag(0x02)
            .filter(|y| go_asn1_integer_ok(y))
        else {
            return Some("x509: invalid DSA public key");
        };
        let mut group = DerReader::new(params).read_tag(0x30).map(DerReader::new);
        let mut next = || {
            group
                .as_mut()?
                .read_tag(0x02)
                .filter(|v| go_asn1_integer_ok(v))
        };
        let (Some(p), Some(q), Some(g)) = (next(), next(), next()) else {
            return Some("x509: invalid DSA parameters");
        };
        if ![y, p, q, g].into_iter().all(go_asn1_integer_positive) {
            return Some("x509: zero or negative DSA parameter");
        }
        return None;
    }
    None
}

/// The bit length of an RSA key's modulus, as Go's `N.BitLen()` gives it
/// to `checkKeySize` (`crypto/tls/handshake_server.go:952-957`), for the
/// subject public key info, the whole element, of a certificate Go
/// parses; `None` for a key of another algorithm.
// Bit counts of a slice's length, which fits.
#[allow(clippy::arithmetic_side_effects)]
fn go_rsa_modulus_bits(spki: &[u8]) -> Option<usize> {
    let mut spki = DerReader::new(DerReader::new(spki).read_tag(0x30)?);
    let mut algorithm = DerReader::new(spki.read_tag(0x30)?);
    if algorithm.read_tag(0x06)? != RSA_ENCRYPTION {
        return None;
    }
    let (unused, bits) = go_bit_string(spki.read_tag(0x03)?)?;
    let data = go_right_align(unused, bits);
    let modulus = DerReader::new(DerReader::new(data.as_ref()).read_tag(0x30)?).read_tag(0x02)?;
    let digits = modulus.strip_prefix(&[0x00]).unwrap_or(modulus);
    let first = digits.first()?;
    Some(digits.len() * 8 - first.leading_zeros() as usize)
}

/// The largest RSA key Go's TLS takes in a certificate a client sends,
/// `defaultMaxRSAKeySize` (`crypto/tls/handshake_client.go:1086-1101`),
/// which no `GODEBUG` dcrd or dcrwallet sets changes.
const GO_MAX_RSA_KEY_BITS: usize = 8192;

/// Unix seconds from a proleptic Gregorian civil date and time.
// Calendar arithmetic over four-digit years.
#[allow(clippy::arithmetic_side_effects)]
fn unix_from_civil(year: i64, month: i64, day: i64, hh: i64, mm: i64, ss: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + hh * 3600 + mm * 60 + ss
}

/// A certificate validity time in unix seconds, as cryptobyte's
/// `ReadASN1UTCTime` (`060102150405Z0700`, falling back to minute
/// precision, years 50-99 in the 1900s) and `ReadASN1GeneralizedTime`
/// (`20060102150405Z0700`) read it: `time.Parse` with the layout, then
/// the round-trip requirement that `Format` gives the input back.  So
/// a fraction of a second, which `time.Parse` reads after the seconds
/// but neither layout writes, a `+0000` or `-0000` zone and a zone
/// minute of 60 are refused, while a zone hour of 24, which
/// `time.Parse` allows, is not.
// Digit and calendar arithmetic over at most four-digit fields.
#[allow(clippy::arithmetic_side_effects)]
fn parse_asn1_time(tag: u8, content: &[u8]) -> Option<i64> {
    let digits = |s: &[u8]| -> Option<i64> {
        if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some(s.iter().fold(0i64, |v, &d| v * 10 + i64::from(d - b'0')))
    };
    let (year, rest) = match tag {
        0x17 => {
            let yy = digits(content.get(..2)?)?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &content[2..])
        }
        0x18 => (digits(content.get(..4)?)?, &content[4..]),
        _ => return None,
    };
    let month = digits(rest.get(..2)?)?;
    let day = digits(rest.get(2..4)?)?;
    let hour = digits(rest.get(4..6)?)?;
    let minute = digits(rest.get(6..8)?)?;
    let mut rest = &rest[8..];
    // UTCTime's seconds are optional (the minute-precision fallback);
    // GeneralizedTime's are not.
    let second = match rest.get(..2) {
        Some(s) if s.iter().all(u8::is_ascii_digit) => {
            rest = &rest[2..];
            digits(s)?
        }
        _ if tag == 0x17 => 0,
        _ => return None,
    };
    let offset = match rest {
        b"Z" => 0,
        [sign @ (b'+' | b'-'), zone @ ..] if zone.len() == 4 => {
            let hh = digits(&zone[..2])?;
            let mm = digits(&zone[2..])?;
            let offset = hh * 3600 + mm * 60;
            if offset == 0 || hh > 24 || mm > 59 {
                return None;
            }
            if *sign == b'-' { -offset } else { offset }
        }
        _ => return None,
    };
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => return None,
    };
    if day < 1 || day > days_in_month || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some(unix_from_civil(year, month, day, hour, minute, second) - offset)
}

/// The facts Go's `x509` package reads from a certificate for a client
/// chain (`crypto/x509/parser.go`, `verify.go`): the validity window,
/// whether it carries an unhandled critical extension, whether its
/// extended key usage admits `ExtKeyUsageClientAuth`, and its path
/// length constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CertFacts {
    not_before: i64,
    not_after: i64,
    /// Go's `UnhandledCriticalExtensions` is not empty.
    unhandled_critical: bool,
    /// Go's `checkChainForKeyUsage` over this certificate alone passes
    /// for `ExtKeyUsageClientAuth`: no extended key usage at all,
    /// `anyExtendedKeyUsage`, or `clientAuth`.
    client_auth: bool,
    /// Go's `MaxPathLen` when `BasicConstraintsValid` and it is not
    /// negative, which is when the basic constraints carry a
    /// `pathLenConstraint`: the most intermediates a chain below this
    /// certificate may hold.
    max_path_len: Option<u64>,
    /// Go's `Version`: 1, 2 or 3.
    version: u8,
    /// Go's `BasicConstraintsValid`: the certificate carries basic
    /// constraints.
    basic_constraints: bool,
    /// Go's `IsCA`: the basic constraints assert cA.
    is_ca: bool,
    /// Go's `KeyUsage`: the first nine bits of the key usage extension,
    /// as `parseKeyUsageExtension` keeps them, and zero without one.
    key_usage: u16,
    /// Go's `hasNameConstraints`: the certificate carries a name
    /// constraints extension, whatever it holds.
    name_constraints: bool,
}

/// What Go's `buildChains` reads from a certificate to find and check
/// the certificates that may have issued it (`crypto/x509/verify.go`,
/// `cert_pool.go`): the issuer and subject names its pools index and
/// compare, as DER contents; the subject and authority key identifiers
/// that order the candidates, empty where absent, as Go's nil and empty
/// slices compare equal; the signed `TBSCertificate`, whole, with its
/// signature algorithm's contents and its signature, `None` when the
/// signature's last octet carries unused bits; and the certificate's
/// own key, as its algorithm identifier's contents and its key bits,
/// `None` where Go's parser leaves `PublicKey` nil, an algorithm it does
/// not know, or where this reader cannot read the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChainLinks<'a> {
    issuer: &'a [u8],
    subject: &'a [u8],
    subject_key_id: &'a [u8],
    authority_key_id: &'a [u8],
    tbs: &'a [u8],
    signature_algorithm: &'a [u8],
    signature: Option<&'a [u8]>,
    key: Option<(&'a [u8], &'a [u8])>,
}

/// The facts Go's `policiesValid` (`crypto/x509/verify.go`) reads from
/// one certificate of a client chain, as `processExtensions` parses the
/// four policy extensions whatever their critical flag says: the policy
/// identifiers, as DER object identifier contents, in order; the policy
/// mappings, issuer domain then subject domain; the policy constraints'
/// two values and inhibit any policy's, `None` where absent; and whether
/// the certificate is self-issued, its issuer and subject names equal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PolicyFacts {
    policies: Vec<Vec<u8>>,
    mappings: Vec<(Vec<u8>, Vec<u8>)>,
    require_explicit_policy: Option<i64>,
    inhibit_policy_mapping: Option<i64>,
    inhibit_any_policy: Option<i64>,
    self_issued: bool,
}

/// What Go's `alreadyInChain` (`crypto/x509/verify.go`) compares to
/// keep a certificate off a chain that holds its like: the subject, as
/// DER contents, the subject public key info, as the whole element, and
/// the value of the subject alternative name extension where there is
/// one.  The whole element is `RawSubjectPublicKeyInfo`, which Go also
/// hashes to find a distrusted key ([`go_distrusted_spki`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChainIdentity<'a> {
    subject: &'a [u8],
    spki: &'a [u8],
    san: Option<&'a [u8]>,
}

impl ChainIdentity<'_> {
    /// Go's `alreadyInChain(candidate, chain)`: a certificate of `chain`
    /// has the candidate's subject and key, and either neither carries a
    /// subject alternative name or both carry the same one; the first
    /// with the subject and key whose name only one of the two carries
    /// ends the walk with `false`, as Go's loop returns there.
    fn already_in(&self, chain: &[ChainIdentity<'_>]) -> bool {
        for cert in chain {
            if cert.subject != self.subject || cert.spki != self.spki {
                continue;
            }
            match (self.san, cert.san) {
                (None, None) => return true,
                (None, Some(_)) | (Some(_), None) => return false,
                (Some(ours), Some(theirs)) if ours == theirs => return true,
                (Some(_), Some(_)) => {}
            }
        }
        false
    }
}

/// An INTEGER's content as cryptobyte's `ReadASN1Int64WithTag` and
/// `ReadASN1Integer` read it into an `int64`: at least one octet,
/// minimally encoded (`checkASN1Integer`), and no more than eight
/// (`asn1Signed`).
// Shifts over at most eight bytes.
#[allow(clippy::arithmetic_side_effects)]
fn go_asn1_int64(content: &[u8]) -> Option<i64> {
    match content {
        [] => return None,
        [0x00, next, ..] if next & 0x80 == 0 => return None,
        [0xff, next, ..] if next & 0x80 != 0 => return None,
        _ if content.len() > 8 => return None,
        _ => {}
    }
    let negative = content[0] & 0x80 != 0;
    let start = if negative { -1i64 } else { 0 };
    Some(
        content
            .iter()
            .fold(start, |value, &b| (value << 8) | i64::from(b)),
    )
}

/// Whether `der` is an object identifier Go's `newOIDFromDER`
/// (`crypto/x509/oid.go`) accepts, as `parseCertificatePoliciesExtension`
/// requires of each policy: not empty, ending a subidentifier, and no
/// subidentifier opening with 0x80.
fn go_new_oid_from_der(der: &[u8]) -> bool {
    if der.last().is_none_or(|last| last & 0x80 != 0) {
        return false;
    }
    let mut start = true;
    for &b in der {
        if start && b == 0x80 {
            return false;
        }
        start = b & 0x80 == 0;
    }
    true
}

/// A basic constraints `pathLenConstraint` as Go's
/// `parseBasicConstraintsExtension` reads it (the same in 1.26.2, 1.27.1
/// and 1.27.3), through cryptobyte's `ReadASN1Integer` into a `uint`: a
/// minimally encoded, non-negative integer no larger than `math.MaxInt`.
/// `None` is Go's `x509: invalid basic constraints`.
// Byte shifts over at most eight bytes.
#[allow(clippy::arithmetic_side_effects)]
fn der_path_len(content: &[u8]) -> Option<u64> {
    match content {
        [] => return None,
        [first, ..] if first & 0x80 != 0 => return None,
        [0x00, next, ..] if next & 0x80 == 0 => return None,
        _ => {}
    }
    let digits = content.strip_prefix(&[0x00]).unwrap_or(content);
    if digits.len() > 8 {
        return None;
    }
    let value = digits
        .iter()
        .fold(0u64, |value, &b| (value << 8) | u64::from(b));
    (value <= i64::MAX as u64).then_some(value)
}

/// Whether `content` is an OBJECT IDENTIFIER cryptobyte's
/// `ReadASN1ObjectIdentifier` reads: not empty, and every subidentifier
/// as `readBase128Int` takes it, minimally encoded in at most five
/// bytes and below 2^31.
// Shifts of a value checked below 2^24 first.
#[allow(clippy::arithmetic_side_effects)]
fn go_oid_ok(content: &[u8]) -> bool {
    let mut rest = content;
    if rest.is_empty() {
        return false;
    }
    while !rest.is_empty() {
        let mut ret = 0u32;
        let mut i = 0;
        loop {
            let Some((&b, tail)) = rest.split_first() else {
                return false;
            };
            if i == 5 || ret >= 1 << (31 - 7) || (i == 0 && b == 0x80) {
                return false;
            }
            rest = tail;
            ret = (ret << 7) | u32::from(b & 0x7f);
            if b & 0x80 == 0 {
                break;
            }
            i += 1;
        }
    }
    true
}

/// Whether a 16-byte address is an IPv4-mapped IPv6 address, one for
/// which Go's `net.IP.To4` is not nil (`net/ip.go:217-228`): ten zero
/// bytes, then two of 0xff.
fn ipv4_mapped(ip: &[u8]) -> bool {
    <[u8; 16]>::try_from(ip).is_ok_and(|ip| std::net::Ipv6Addr::from(ip).to_ipv4_mapped().is_some())
}

/// Whether Go 1.27.3's `parseSANExtension` takes an iPAddress name
/// (`crypto/x509/parser.go:497-507`): four bytes, or sixteen that are
/// not an IPv4-mapped address.  Go refuses any other length (`x509:
/// cannot parse IP address of length N`) and, since 1.27, a mapped
/// address (`x509: SAN iPAddress contains IPv4-mapped IPv6 address`).
fn go_san_ip_ok(ip: &[u8]) -> bool {
    match ip.len() {
        4 => true,
        16 => !ipv4_mapped(ip),
        _ => false,
    }
}

/// Whether Go 1.27.3's `parseNameConstraintsExtension` takes an IP
/// constraint (`crypto/x509/parser.go:670-695`): an address and a mask
/// of four bytes each or sixteen each, the mask some one bits followed
/// only by zero bits (`isValidIPMask`, `:583-605`), and, since 1.27, a
/// sixteen-byte address that is not IPv4-mapped.
fn go_ip_constraint_ok(value: &[u8]) -> bool {
    let half = match value.len() {
        8 => 4,
        32 => 16,
        _ => return false,
    };
    let (ip, mask) = value.split_at(half);
    let mut seen_zero = false;
    for &b in mask {
        if seen_zero {
            if b != 0 {
                return false;
            }
            continue;
        }
        match b {
            0x00 | 0x80 | 0xc0 | 0xe0 | 0xf0 | 0xf8 | 0xfc | 0xfe => seen_zero = true,
            0xff => {}
            _ => return false,
        }
    }
    !ipv4_mapped(ip)
}

/// Go's `domainNameValid` (`crypto/x509/parser.go:1378-1433`): empty, or
/// labels of the characters 33 to 126 that are none of them empty and
/// end with no trailing period, one leading period allowed in a
/// constraint.
fn go_domain_name_valid(name: &[u8], constraint: bool) -> bool {
    if name.is_empty() {
        return true;
    }
    if name.last() == Some(&b'.') {
        return false;
    }
    let name = match name {
        [b'.', rest @ ..] if constraint => rest,
        _ => name,
    };
    name.split(|&b| b == b'.')
        .all(|label| !label.is_empty() && label.iter().all(|b| (33..=126).contains(b)))
}

/// Whether Go 1.27.3's `parseRFC2821Mailbox` reads `mailbox`
/// (`crypto/x509/verify.go:267-406`): [`go_rfc2821_domain`] reads it,
/// and its domain holds no `@`, which Go refuses since 1.27
/// (`:398-401`).
fn go_rfc2821_mailbox(mailbox: &[u8]) -> bool {
    go_rfc2821_domain(mailbox).is_some_and(|domain| !domain.contains(&b'@'))
}

/// Whether `mailbox` is one Go 1.26.2's `parseRFC2821Mailbox` read and
/// Go 1.27.3's does not: [`go_rfc2821_domain`] reads it, and its domain
/// holds `@`.  That is the only change between the two: go1.26.2 checked
/// the domain with `domainToReverseLabels` alone, which takes the same
/// domains as `domainNameValid`, and go1.27.3 adds the `@` refusal
/// (`crypto/x509/verify.go:394-401`).
fn go_mailbox_domain_holds_at(mailbox: &[u8]) -> bool {
    go_rfc2821_domain(mailbox).is_some_and(|domain| domain.contains(&b'@'))
}

/// The domain of `mailbox` as Go's `parseRFC2821Mailbox` reads it
/// (`crypto/x509/verify.go:267-406`), short of the `@` refusal: a quoted
/// string or dot-separated atoms, with backslash escapes in either, then
/// `@` and a domain that passes [`go_domain_name_valid`], which may hold
/// `@`.  `None` where Go refuses the mailbox for anything else.
fn go_rfc2821_domain(mailbox: &[u8]) -> Option<&[u8]> {
    let mut rest = mailbox;
    match rest.split_first() {
        None => return None,
        Some((b'"', tail)) => {
            // qcontent up to the closing quote: qtext, or a backslash and
            // the character it quotes.
            rest = tail;
            loop {
                let (&c, tail) = rest.split_first()?;
                rest = tail;
                match c {
                    b'"' => break,
                    b'\\' => match rest.split_first() {
                        Some((1..=9 | 11 | 12 | 14..=127, tail)) => rest = tail,
                        _ => return None,
                    },
                    1..=8 | 11 | 12 | 14..=33 | 35..=91 | 93..=127 => {}
                    _ => return None,
                }
            }
        }
        Some(_) => {
            // atext and periods, a backslash taking the next character
            // whatever it is, which may not start or end the local part
            // nor stand twice in a row as periods.
            let mut local = Vec::new();
            while let Some((&c, tail)) = rest.split_first() {
                if c == b'\\' {
                    let (&escaped, tail) = tail.split_first()?;
                    local.push(escaped);
                    rest = tail;
                } else if c.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~.".contains(&c) {
                    local.push(c);
                    rest = tail;
                } else {
                    break;
                }
            }
            if local.first().is_none_or(|&b| b == b'.')
                || local.last() == Some(&b'.')
                || local.windows(2).any(|pair| pair == b"..")
            {
                return None;
            }
        }
    }
    rest.strip_prefix(b"@")
        .filter(|domain| go_domain_name_valid(domain, false))
}

/// Whether Go 1.27.3's `checkChainConstraints` refuses a chain for a
/// mailbox whose domain holds `@` (`crypto/x509/constraints.go:515-571`).
/// `chain` holds, leaf first and root last, whether each certificate
/// carries a name constraints extension ([`CertFacts`]) and the value of
/// its subject alternative name extension, where it has one
/// ([`ChainIdentity`]).  Go reads every mailbox in the subject
/// alternative name of a certificate below one with name constraints,
/// whatever their forms, and refuses the chain on a mailbox it cannot
/// read (`:542-561`, `parseMailboxes` at `:609-620`).  Of those, this
/// takes only the ones Go 1.26.2 still read
/// ([`go_mailbox_domain_holds_at`]); the older refusals stay webpki's,
/// which makes none of them under a subtree of another form (PARITY.md,
/// the clientcert entry).
fn go_chain_names_an_at_domain_mailbox(chain: &[(bool, Option<&[u8]>)]) -> bool {
    let Some(top) = chain.iter().rposition(|&(constrained, _)| constrained) else {
        return false;
    };
    chain
        .iter()
        .take(top)
        .filter_map(|&(_, san)| san)
        .any(|san| {
            let names_one = || -> Option<bool> {
                let mut names = DerReader::new(DerReader::new(san).read_tag(0x30)?);
                let mut found = false;
                while !names.is_empty() {
                    let (tag, name) = names.read()?;
                    found |= tag == 0x81 && go_mailbox_domain_holds_at(name);
                }
                Some(found)
            };
            // `CertFacts::parse` has read the extension, so this reads it
            // too; were it not to, the chain would be refused.
            names_one().unwrap_or(true)
        })
}

/// Whether Go 1.27.3's `parseNameConstraintsExtension` takes an
/// rfc822Name constraint (`crypto/x509/parser.go:697-714`): ASCII
/// (`isIA5String`), and a mailbox [`go_rfc2821_mailbox`] reads when it
/// holds `@`, a domain [`go_domain_name_valid`] takes as a constraint
/// when it does not.  Go 1.26 took a mailbox whose domain held `@`.
fn go_email_constraint_ok(value: &[u8]) -> bool {
    value.is_ascii()
        && if value.contains(&b'@') {
            go_rfc2821_mailbox(value)
        } else {
            go_domain_name_valid(value, true)
        }
}

impl CertFacts {
    /// Read the facts from a DER certificate, or `None` where Go's
    /// `ParseCertificate` (`crypto/x509/parser.go`) fails on what this
    /// reads: nothing after the certificate, the version (its [0] holding
    /// the INTEGER alone), inner and outer signature algorithms that are
    /// the same and read as `parseAI` reads them, the validity times,
    /// the signature's BIT STRING, the extension list (`parseExtension`
    /// and no OID twice), the critical marking `processExtensions`
    /// refuses on the key identifiers and the authority information
    /// access, and the extensions whose facts are kept, the key
    /// identifiers and the key usage among them.  Of the names in the
    /// subject alternative name and name constraints extensions, the IP
    /// addresses and the rfc822Name constraints are read as Go 1.27.3
    /// reads them ([`go_san_ip_ok`], [`go_ip_constraint_ok`],
    /// [`go_email_constraint_ok`]), and so is the subject public key
    /// info, whole, by Go's `parsePublicKey` rules for each algorithm
    /// ([`go_public_key_refusal`]).  Go's other checks (the serial
    /// number, the subject and issuer names, the other names of those two
    /// extensions, and the contents of other extensions) are not ported,
    /// so `Some` does not promise Go parses the certificate.
    /// The four policy extensions are among those read, with Go's rules,
    /// though only [`CertFacts::parse_all`] keeps what they say.
    fn parse(der: &[u8]) -> Option<CertFacts> {
        Self::parse_all(der).map(|(facts, _, _)| facts)
    }

    /// [`CertFacts::parse`], with the policy facts Go's `policiesValid`
    /// reads and what Go's `alreadyInChain` compares.
    fn parse_all(der: &[u8]) -> Option<(CertFacts, PolicyFacts, ChainIdentity<'_>)> {
        Self::parse_full(der).map(|(facts, policies, identity, _)| (facts, policies, identity))
    }

    /// [`CertFacts::parse_all`], with what Go's `buildChains` reads to
    /// place the certificate in a chain ([`ChainLinks`]).
    fn parse_full(
        der: &[u8],
    ) -> Option<(CertFacts, PolicyFacts, ChainIdentity<'_>, ChainLinks<'_>)> {
        Self::parse_noting(der, &mut None)
    }

    /// [`CertFacts::parse_full`], noting in `refusal` Go's words for a
    /// certificate it refuses for its key, Go's first refusal of it
    /// among those this reads ([`go_public_key_refusal`]); `refusal` is
    /// left as it was when the certificate is refused for anything else.
    // The version is at most 2 before the increment, and a bit index is
    // below nine.
    #[allow(clippy::arithmetic_side_effects)]
    fn parse_noting<'d>(
        der: &'d [u8],
        refusal: &mut Option<&'static str>,
    ) -> Option<(CertFacts, PolicyFacts, ChainIdentity<'d>, ChainLinks<'d>)> {
        // The certificate policies, policy mappings, policy constraints
        // and inhibit any policy extensions, as DER OID contents.
        const POLICIES: &[u8] = &[0x55, 0x1d, 0x20];
        const POLICY_MAPPINGS: &[u8] = &[0x55, 0x1d, 0x21];
        const POLICY_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x24];
        const INHIBIT_ANY_POLICY: &[u8] = &[0x55, 0x1d, 0x36];
        // id-ce-basicConstraints, id-ce-extKeyUsage,
        // anyExtendedKeyUsage, id-kp-clientAuth and
        // id-pe-authorityInfoAccess, as DER OID contents.
        const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
        const EKU: &[u8] = &[0x55, 0x1d, 0x25];
        const EKU_ANY: &[u8] = &[0x55, 0x1d, 0x25, 0x00];
        const EKU_CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
        const AIA: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];
        // The GeneralName forms Go collects: rfc822Name, dNSName,
        // uniformResourceIdentifier and iPAddress.
        let known_name = |tag: u8| matches!(tag, 0x81 | 0x82 | 0x86 | 0x87);

        // id-ce-subjectKeyIdentifier, id-ce-keyUsage and
        // id-ce-authorityKeyIdentifier, as DER OID contents.
        const SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1d, 0x0e];
        const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
        const AUTHORITY_KEY_ID: &[u8] = &[0x55, 0x1d, 0x23];

        // `ParseCertificate`: the certificate and nothing after it
        // ("x509: trailing data"), then the TBSCertificate, the
        // signature algorithm, which must equal the one the
        // TBSCertificate names ("x509: inner and outer signature
        // algorithm identifiers don't match") and read as `parseAI`
        // reads it, and the signature, a BIT STRING cryptobyte's
        // `ReadASN1BitString` reads.
        //
        // Go reads the TBSCertificate through the subject public key info
        // before it reads what follows the TBSCertificate, so the checks
        // here run in that order, and the key's, whose words are known
        // ([`go_public_key_refusal`]), come before the others whose words
        // are not.
        let mut whole = DerReader::new(der);
        let certificate = whole.read_tag(0x30)?;
        let mut outer = DerReader::new(certificate);
        let (_, tbs_content, tbs_element) = outer.read_raw(0x30)?;
        let mut tbs = DerReader::new(tbs_content);
        // `ReadOptionalASN1Integer`: the [0] holds the INTEGER and
        // nothing after it ("x509: malformed version").
        let version = if tbs.peek_tag() == Some(0xa0) {
            let mut wrapped = DerReader::new(tbs.read()?.1);
            let value = wrapped.read_tag(0x02)?;
            if !wrapped.is_empty() {
                return None;
            }
            match value {
                [v @ 0..=2] => v + 1,
                _ => return None,
            }
        } else {
            1
        };
        tbs.read_tag(0x02)?; // serialNumber
        let (_, inner_content, inner_algorithm) = tbs.read_raw(0x30)?;
        if !go_parse_ai(inner_content) {
            return None;
        }
        let issuer = tbs.read_tag(0x30)?;
        let mut validity = DerReader::new(tbs.read_tag(0x30)?);
        let (tag, content) = validity.read()?;
        let not_before = parse_asn1_time(tag, content)?;
        let (tag, content) = validity.read()?;
        let not_after = parse_asn1_time(tag, content)?;
        let subject = tbs.read_tag(0x30)?;
        let (_, spki_content, spki) = tbs.read_raw(0x30)?;
        if let Some(words) = go_public_key_refusal(spki_content) {
            *refusal = Some(words);
            return None;
        }
        let (_, signature_algorithm, outer_algorithm) = outer.read_raw(0x30)?;
        let signature = go_bit_string(outer.read_tag(0x03)?)?;
        if !whole.is_empty() || outer_algorithm != inner_algorithm {
            return None;
        }

        let mut facts = CertFacts {
            not_before,
            not_after,
            unhandled_critical: false,
            client_auth: true,
            max_path_len: None,
            version,
            basic_constraints: false,
            is_ca: false,
            key_usage: 0,
            name_constraints: false,
        };
        let mut links = ChainLinks {
            issuer,
            subject,
            subject_key_id: &[],
            authority_key_id: &[],
            tbs: tbs_element,
            signature_algorithm,
            signature: (signature.0 == 0).then_some(signature.1),
            key: go_public_key(spki_content),
        };
        let mut policies = PolicyFacts {
            self_issued: issuer == subject,
            ..PolicyFacts::default()
        };
        let mut identity = ChainIdentity {
            subject,
            spki,
            san: None,
        };
        // Go reads the unique identifiers from v2 on and the extensions
        // only from a v3 certificate.
        if version < 2 {
            return Some((facts, policies, identity, links));
        }
        for unique_id in [0x81, 0x82] {
            if tbs.peek_tag() == Some(unique_id) {
                tbs.read()?;
            }
        }
        if version < 3 || tbs.peek_tag() != Some(0xa3) {
            return Some((facts, policies, identity, links));
        }
        let mut extensions = DerReader::new(DerReader::new(tbs.read()?.1).read_tag(0x30)?);
        let mut seen: Vec<&[u8]> = Vec::new();
        while !extensions.is_empty() {
            let mut extension = DerReader::new(extensions.read_tag(0x30)?);
            // Go's `parseExtension`: an OID cryptobyte reads, a critical
            // flag that is a DER BOOLEAN, and the value; then
            // `parseCertificate` refuses an OID seen before.  An OID
            // cryptobyte reads has one encoding, so comparing the bytes
            // compares the OIDs.
            let oid = extension.read_tag(0x06)?;
            if !go_oid_ok(oid) || seen.contains(&oid) {
                return None;
            }
            seen.push(oid);
            let critical = if extension.peek_tag() == Some(0x01) {
                match extension.read_tag(0x01)? {
                    [0x00] => false,
                    [0xff] => true,
                    _ => return None,
                }
            } else {
                false
            };
            let value = extension.read_tag(0x04)?;
            // Go's `processExtensions`: which extensions it handles.
            let unhandled = match oid {
                &[0x55, 0x1d, id] if id < 0x80 => match id {
                    // "incorrectly marked critical"
                    14 | 35 if critical => return None,
                    14 | 15 | 19 | 31 | 32 | 33 | 35 | 36 | 37 | 54 => false,
                    // A subject alternative name counts as handled only
                    // when Go collected a name from it, and an IP
                    // address Go refuses fails the parse.
                    17 => {
                        identity.san = Some(value);
                        let mut names = DerReader::new(DerReader::new(value).read_tag(0x30)?);
                        let mut any_known = false;
                        while !names.is_empty() {
                            let (tag, name) = names.read()?;
                            if tag == 0x87 && !go_san_ip_ok(name) {
                                return None;
                            }
                            any_known |= known_name(tag);
                        }
                        !any_known
                    }
                    // Name constraints are unhandled when a subtree's
                    // base is a form Go does not enforce, and an IP or
                    // rfc822Name base Go refuses fails the parse.
                    30 => {
                        facts.name_constraints = true;
                        let mut top = DerReader::new(DerReader::new(value).read_tag(0x30)?);
                        let mut unhandled = false;
                        while !top.is_empty() {
                            let mut subtrees = DerReader::new(top.read()?.1);
                            while !subtrees.is_empty() {
                                let subtree = subtrees.read_tag(0x30)?;
                                let (tag, base) = DerReader::new(subtree).read()?;
                                let refused = match tag {
                                    0x87 => !go_ip_constraint_ok(base),
                                    0x81 => !go_email_constraint_ok(base),
                                    _ => false,
                                };
                                if refused {
                                    return None;
                                }
                                unhandled |= !known_name(tag);
                            }
                        }
                        unhandled
                    }
                    _ => true,
                },
                // "incorrectly marked critical"
                _ if oid == AIA && critical => return None,
                _ => oid != AIA,
            };
            if oid == EKU {
                let mut usages = DerReader::new(DerReader::new(value).read_tag(0x30)?);
                let mut client_auth = usages.is_empty();
                while !usages.is_empty() {
                    let usage = usages.read_tag(0x06)?;
                    if !go_oid_ok(usage) {
                        return None;
                    }
                    client_auth |= usage == EKU_ANY || usage == EKU_CLIENT_AUTH;
                }
                facts.client_auth = client_auth;
            }
            if oid == BASIC_CONSTRAINTS {
                // An optional cA boolean, then the optional
                // pathLenConstraint (`parseBasicConstraintsExtension`).
                let mut constraints = DerReader::new(DerReader::new(value).read_tag(0x30)?);
                facts.basic_constraints = true;
                if constraints.peek_tag() == Some(0x01) {
                    facts.is_ca = match constraints.read_tag(0x01)? {
                        [0x00] => false,
                        [0xff] => true,
                        _ => return None,
                    };
                }
                if constraints.peek_tag() == Some(0x02) {
                    facts.max_path_len = Some(der_path_len(constraints.read_tag(0x02)?)?);
                }
            }
            // The key identifiers (`processExtensions`): the subject's an
            // OCTET STRING, the authority's a SEQUENCE whose optional [0]
            // is the identifier Go keeps.
            if oid == SUBJECT_KEY_ID {
                links.subject_key_id = DerReader::new(value).read_tag(0x04)?;
            }
            if oid == AUTHORITY_KEY_ID {
                let mut akid = DerReader::new(DerReader::new(value).read_tag(0x30)?);
                if akid.peek_tag() == Some(0x80) {
                    links.authority_key_id = akid.read_tag(0x80)?;
                }
            }
            // `parseKeyUsageExtension`: a BIT STRING, of which the first
            // nine bits are kept.
            if oid == KEY_USAGE {
                let (_, bits) = go_bit_string(DerReader::new(value).read_tag(0x03)?)?;
                for i in 0..9usize {
                    if bits
                        .get(i / 8)
                        .is_some_and(|byte| byte & (0x80 >> (i % 8)) != 0)
                    {
                        facts.key_usage |= 1 << i;
                    }
                }
            }
            // `processExtensions` for the policy extensions, each read
            // as far as Go reads it, trailing bytes left unread as Go
            // leaves them.
            if oid == POLICIES {
                // `parseCertificatePoliciesExtension`: each policy's
                // identifier, its qualifiers unread, none twice.
                let mut infos = DerReader::new(DerReader::new(value).read_tag(0x30)?);
                while !infos.is_empty() {
                    let mut info = DerReader::new(infos.read_tag(0x30)?);
                    let policy = info.read_tag(0x06)?;
                    if policies
                        .policies
                        .iter()
                        .any(|seen| seen.as_slice() == policy)
                        || !go_new_oid_from_der(policy)
                    {
                        return None;
                    }
                    policies.policies.push(policy.to_vec());
                }
            }
            if oid == POLICY_MAPPINGS {
                let mut mappings = DerReader::new(DerReader::new(value).read_tag(0x30)?);
                while !mappings.is_empty() {
                    let mut mapping = DerReader::new(mappings.read_tag(0x30)?);
                    let issuer_domain = mapping.read_tag(0x06)?;
                    let subject_domain = mapping.read_tag(0x06)?;
                    policies
                        .mappings
                        .push((issuer_domain.to_vec(), subject_domain.to_vec()));
                }
            }
            if oid == POLICY_CONSTRAINTS {
                // requireExplicitPolicy [0] and inhibitPolicyMapping [1],
                // each an implicitly tagged INTEGER.
                let mut constraints = DerReader::new(DerReader::new(value).read_tag(0x30)?);
                if constraints.peek_tag() == Some(0x80) {
                    policies.require_explicit_policy =
                        Some(go_asn1_int64(constraints.read_tag(0x80)?)?);
                }
                if constraints.peek_tag() == Some(0x81) {
                    policies.inhibit_policy_mapping =
                        Some(go_asn1_int64(constraints.read_tag(0x81)?)?);
                }
            }
            if oid == INHIBIT_ANY_POLICY {
                policies.inhibit_any_policy =
                    Some(go_asn1_int64(DerReader::new(value).read_tag(0x02)?)?);
            }
            facts.unhandled_critical |= critical && unhandled;
        }
        Some((facts, policies, identity, links))
    }

    /// Go's `isValid` for this certificate at `now` (`verify.go`
    /// `isValid`): no unhandled critical extension, and `now` inside
    /// the validity window.  The path-length and name checks it also
    /// makes depend on the chain.
    fn valid_at(&self, now: i64) -> Result<(), rustls::CertificateError> {
        if self.unhandled_critical {
            return Err(rustls::CertificateError::UnhandledCriticalExtension);
        }
        if now < self.not_before {
            return Err(rustls::CertificateError::NotValidYet);
        }
        if now > self.not_after {
            return Err(rustls::CertificateError::Expired);
        }
        Ok(())
    }
}

/// The most signature checks one of Go's chain searches makes (Go's
/// `maxChainSignatureChecks`, `crypto/x509/verify.go`).
const MAX_CHAIN_SIGNATURE_CHECKS: usize = 100;

/// Go's `KeyUsageCertSign`, bit 5 of `KeyUsage`.
const KEY_USAGE_CERT_SIGN: u16 = 1 << 5;

/// A certificate Go's chain search can place, a pool certificate or one
/// the client sent, with what the search reads from it.
struct ChainCandidate<'a> {
    der: &'a [u8],
    facts: CertFacts,
    identity: ChainIdentity<'a>,
    links: ChainLinks<'a>,
}

impl<'a> ChainCandidate<'a> {
    /// The candidate for a certificate [`CertFacts::parse_full`] reads.
    fn parse(der: &'a [u8]) -> Option<ChainCandidate<'a>> {
        let (facts, _, identity, links) = CertFacts::parse_full(der)?;
        Some(ChainCandidate {
            der,
            facts,
            identity,
            links,
        })
    }
}

/// How Go's `buildChains` ended for a client certificate.
#[derive(Debug, PartialEq, Eq)]
enum GoChains<'a> {
    /// The chains it built, each as the DER of its certificates from the
    /// leaf's issuer to the root.  `certain` says whether they are all
    /// Go's: whether every candidate the replay considered was decided as
    /// Go decides it, so that Go built no chain through a candidate whose
    /// signature the provider cannot verify (`SignatureCheck::Unverifiable`).
    Built {
        /// The chains.
        chains: Vec<Vec<&'a [u8]>>,
        /// Whether the replay followed Go's search throughout.
        certain: bool,
    },
    /// It built none, and returned `error`.  `certain` says whether the
    /// replay vouches for that: whether every candidate it considered was
    /// decided as Go decides it, none of them one whose signature Go may
    /// verify where the provider cannot (`SignatureCheck::Unverifiable`).
    NoChain {
        /// Go's error.
        error: GoChainError,
        /// Whether the replay followed Go's search throughout.
        certain: bool,
    },
    /// Its signature check budget ran out before it built one
    /// (`errSignatureLimit`).
    SignatureLimit,
}

/// The error Go's `buildChains` returns when it builds no chain and its
/// budget has not run out (`crypto/x509/verify.go:736-817`).  Each
/// candidate whose signature checks writes its `isValid` result to the
/// function's named result `err`, and each intermediate that passes
/// writes the result of the search above it there, so the error is the
/// one the last such candidate left: an `isValid` refusal, or the search
/// above an intermediate, or nothing, which with no chain built becomes
/// `UnknownAuthorityError`.  A candidate passed over before that, for its
/// signature, a missing key or `alreadyInChain`, writes nothing (its
/// `CheckSignatureFrom` error goes to the hint `UnknownAuthorityError`
/// prints, which the port does not render).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GoChainError {
    /// `UnknownAuthorityError`: `x509: certificate signed by unknown
    /// authority`.
    UnknownAuthority,
    /// A candidate's `isValid` refusal.
    Invalid(GoInvalid),
}

/// Go's `isValid` refusals of a root or intermediate candidate
/// (`crypto/x509/verify.go:451-516`), in the order it makes them; its
/// `NameMismatch` cannot arise for a candidate `findPotentialParents`
/// gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GoInvalid {
    /// `UnhandledCriticalExtension`.
    UnhandledCriticalExtension,
    /// `Expired`, the time before the candidate's `notBefore`.
    NotYetValid {
        /// The candidate's `notBefore`, Unix seconds.
        not_before: i64,
    },
    /// `Expired`, the time after the candidate's `notAfter`.
    Expired {
        /// The candidate's `notAfter`, Unix seconds.
        not_after: i64,
    },
    /// `NotAuthorizedToSign`: an intermediate whose basic constraints are
    /// absent or do not assert cA.
    NotAuthorizedToSign,
    /// `TooManyIntermediates`: the candidate's path length constraint is
    /// below the intermediates under it.
    TooManyIntermediates,
}

impl GoInvalid {
    /// The error the verifier reports for Go's refusal at `now`, Unix
    /// seconds: the rustls error whose alert is Go's where rustls has one,
    /// `certificate_expired` for `Expired` and `bad_certificate` for an
    /// unhandled critical extension, and otherwise the error carrying
    /// Go's text, which `server::go_error_text` gives (its alert is
    /// `certificate_unknown`, where Go sends `bad_certificate`).  A
    /// validity refusal carries rustls's text, as a leaf's does.
    fn to_rustls(self, now: i64) -> rustls::Error {
        let unix = |secs: i64| {
            rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                u64::try_from(secs).unwrap_or(0),
            ))
        };
        let error = match self {
            GoInvalid::UnhandledCriticalExtension => {
                rustls::CertificateError::UnhandledCriticalExtension
            }
            GoInvalid::NotYetValid { not_before } => rustls::CertificateError::NotValidYetContext {
                time: unix(now),
                not_before: unix(not_before),
            },
            GoInvalid::Expired { not_after } => rustls::CertificateError::ExpiredContext {
                time: unix(now),
                not_after: unix(not_after),
            },
            GoInvalid::NotAuthorizedToSign => {
                rustls::CertificateError::Other(rustls::OtherError(Arc::new(NotAuthorizedToSign)))
            }
            GoInvalid::TooManyIntermediates => {
                return go_pki_error(webpki::Error::PathLenConstraintViolated);
            }
        };
        rustls::Error::InvalidCertificate(error)
    }
}

/// Go's `CertificateInvalidError` with reason `NotAuthorizedToSign`
/// (`crypto/x509/verify.go:77-78`): a chain search whose last candidate
/// was an intermediate without basic constraints asserting cA, which Go's
/// `CheckSignatureFrom` lets sign only when it is a version 1 or 2
/// certificate.  Carried to the handshake's error text
/// (`server::go_error_text`).
#[derive(Debug)]
pub struct NotAuthorizedToSign;

impl std::fmt::Display for NotAuthorizedToSign {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("x509: certificate is not authorized to sign other certificates")
    }
}

impl std::error::Error for NotAuthorizedToSign {}

/// How the replay's `CheckSignatureFrom` ended for one candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignatureCheck {
    /// It passed, as it does in Go.
    Passed,
    /// It failed, as it does in Go: a constraint on the parent, Go's RSA
    /// exponent limit, an ML-DSA signature Go refuses as well, or a
    /// signature that does not verify under an algorithm the provider
    /// shares with Go for a key that is not RSA.
    Failed,
    /// It failed where Go may pass it: no algorithm of the provider's
    /// names the signature and the key, the signature or key bits could
    /// not be read, or an RSA key's signature did not verify, which ring's
    /// key size limits, kept by the provider, can cause where Go verifies
    /// it (ADR-0015, T4).
    Unverifiable,
}

/// Go's `buildChains` for `leaf` (`crypto/x509/verify.go`, the same text in
/// 1.26.2, 1.27.1 and 1.27.3), over the `--clientcafile` pool and the pool
/// of certificates the client sent, each deduplicated and in the order it
/// was filled, as Go's `CertPool.AddCert` leaves them, at `now`.
///
/// It looks for the leaf's issuer among the roots and then among the
/// sent certificates, in the order `findPotentialParents` gives (those
/// named as the issuer, the ones whose subject key identifier matches
/// the child's authority key identifier first, then those where only
/// one of the two is present, then the rest), and goes into each
/// intermediate it accepts before the next candidate.  Each candidate
/// costs one of the 100 signature checks before anything else is asked
/// of it, so one passed over for its missing key, or because
/// `alreadyInChain` finds its like on the chain, costs one too; then it
/// must pass `CheckSignatureFrom` (a version 3 parent must carry basic
/// constraints, which must assert cA, a parent's key usage, when it has
/// one, must include certificate signing, and the parent's key must
/// verify the child's signature) and `isValid` (no unhandled critical
/// extension, the validity window, basic constraints asserting cA for an
/// intermediate, and its path length constraint over the intermediates
/// below it).  The search ends when the budget runs out, keeping the
/// chains built by then.
///
/// The signature is verified with `sig_algs`, the algorithms webpki uses,
/// the listener's set of `dcroxide-tlscrypto` (ring's, ML-DSA's and the
/// ECDSA pairs ring lacked), by
/// the first one naming both the child's signature algorithm and the
/// parent's key algorithm, as webpki picks it, after the RSA public
/// exponent limit Go's verification applies and ring's set does not
/// (`go_rsa_exponent_fits`).  An ML-DSA signature is verified as Go
/// 1.27.3's `checkSignature` verifies it, with an empty context, and an
/// ML-DSA signature algorithm identifier with parameters, or of another
/// set than the key's, finds no algorithm, as Go refuses both
/// (`crypto/x509/x509.go:433-444`, `:1115-1136`).  ECDSA on P-256, P-384
/// and P-521, each with SHA-256, SHA-384 or SHA-512, is verified as Go
/// verifies it (ADR-0015, T4).  Go verifies some signatures the set
/// cannot, among them RSA keys of 1024 to 2040 bits or over 8192, P-224
/// keys, a signature algorithm identifier Go matches by its OID alone,
/// and a signature or
/// key BIT STRING with unused bits, which Go right-aligns, an ML-DSA key
/// with them being a key whenever its octets are its set's length; such a
/// candidate is taken here as failing its signature check, where Go would
/// go on through it.
fn go_build_chains<'a>(
    leaf: &ChainCandidate<'a>,
    roots: &[ChainCandidate<'a>],
    sent: &[ChainCandidate<'a>],
    now: i64,
    sig_algs: &[&'static dyn rustls::pki_types::SignatureVerificationAlgorithm],
) -> GoChains<'a> {
    let mut search = ChainSearch {
        roots,
        sent,
        now,
        sig_algs,
        checks: 0,
        chains: Vec::new(),
        uncertain: false,
    };
    let mut chain = vec![leaf];
    match search.build(&mut chain) {
        Err(SignatureLimit) if search.chains.is_empty() => GoChains::SignatureLimit,
        Ok(Some(error)) if search.chains.is_empty() => GoChains::NoChain {
            error,
            certain: !search.uncertain,
        },
        _ => GoChains::Built {
            chains: search.chains,
            certain: !search.uncertain,
        },
    }
}

/// Go's `errSignatureLimit`, which ends a chain search at every level.
struct SignatureLimit;

/// The state of one [`go_build_chains`] search.
struct ChainSearch<'s, 'a> {
    roots: &'s [ChainCandidate<'a>],
    sent: &'s [ChainCandidate<'a>],
    now: i64,
    sig_algs: &'s [&'static dyn rustls::pki_types::SignatureVerificationAlgorithm],
    /// The signature checks spent, Go's `sigChecks`.
    checks: usize,
    chains: Vec<Vec<&'a [u8]>>,
    /// Whether a candidate's signature check failed where Go's may pass
    /// ([`SignatureCheck::Unverifiable`]), or a candidate's key could not
    /// be read, so that Go's search may have gone otherwise.
    uncertain: bool,
}

impl<'s, 'a> ChainSearch<'s, 'a> {
    /// `buildChains` for the last certificate of `chain`, which runs
    /// from the leaf: the error that level of Go's search returns
    /// ([`GoChainError`]), `None` when it built a chain; or
    /// [`SignatureLimit`] once the budget has run out, which ends the
    /// search at every level, as Go's `errSignatureLimit` breaks each
    /// level's loop.
    // `chain` holds the leaf, so its length is at least one.
    #[allow(clippy::arithmetic_side_effects)]
    fn build(
        &mut self,
        chain: &mut Vec<&'s ChainCandidate<'a>>,
    ) -> Result<Option<GoChainError>, SignatureLimit> {
        let child = chain[chain.len() - 1];
        let chains_before = self.chains.len();
        // Go's named result `err`, as each candidate leaves it.
        let mut err: Option<GoChainError> = None;
        for (is_root, pool) in [(true, self.roots), (false, self.sent)] {
            for candidate in potential_parents(pool, child) {
                self.checks += 1;
                if self.checks > MAX_CHAIN_SIGNATURE_CHECKS {
                    return Err(SignatureLimit);
                }
                let identities: Vec<ChainIdentity<'a>> =
                    chain.iter().map(|cert| cert.identity).collect();
                if candidate.links.key.is_none() {
                    // Go leaves the key nil for an algorithm it does not
                    // know, and passes over the candidate; this reader
                    // leaves it out also for a key it cannot read.
                    self.uncertain = true;
                    continue;
                }
                if candidate.identity.already_in(&identities) {
                    continue;
                }
                match go_check_signature_from(child, candidate, self.sig_algs) {
                    SignatureCheck::Passed => {}
                    SignatureCheck::Failed => continue,
                    SignatureCheck::Unverifiable => {
                        self.uncertain = true;
                        continue;
                    }
                }
                if let Err(invalid) = go_is_valid(candidate, is_root, chain.len(), self.now) {
                    err = Some(GoChainError::Invalid(invalid));
                    continue;
                }
                err = None;
                if is_root {
                    let mut built: Vec<&'a [u8]> = chain[1..].iter().map(|cert| cert.der).collect();
                    built.push(candidate.der);
                    self.chains.push(built);
                } else {
                    chain.push(candidate);
                    let above = self.build(chain);
                    chain.pop();
                    err = above?;
                }
            }
        }
        if self.chains.len() > chains_before {
            return Ok(None);
        }
        Ok(Some(err.unwrap_or(GoChainError::UnknownAuthority)))
    }
}

/// Go's `CertPool.findPotentialParents` for `child`: the certificates
/// of `pool` named as its issuer, in the pool's order, those whose
/// subject key identifier equals the child's authority key identifier
/// first (two empty ones are equal, as Go's nil and empty slices are),
/// then those where only one of the two is present, then the rest.
fn potential_parents<'s, 'a>(
    pool: &'s [ChainCandidate<'a>],
    child: &ChainCandidate<'a>,
) -> Vec<&'s ChainCandidate<'a>> {
    let named = || {
        pool.iter()
            .filter(|c| c.links.subject == child.links.issuer)
    };
    let akid = child.links.authority_key_id;
    let matching = named().filter(|c| c.links.subject_key_id == akid);
    let one = named().filter(|c| {
        c.links.subject_key_id != akid && (c.links.subject_key_id.is_empty() != akid.is_empty())
    });
    let mismatch = named().filter(|c| {
        c.links.subject_key_id != akid && c.links.subject_key_id.is_empty() == akid.is_empty()
    });
    matching.chain(one).chain(mismatch).collect()
}

/// Go's `CheckSignatureFrom(parent)` for `child` (`crypto/x509/x509.go`),
/// with the signature verified as [`go_build_chains`] says: whether it
/// passes.
#[cfg(test)]
fn check_signature_from(
    child: &ChainCandidate<'_>,
    parent: &ChainCandidate<'_>,
    sig_algs: &[&'static dyn rustls::pki_types::SignatureVerificationAlgorithm],
) -> bool {
    go_check_signature_from(child, parent, sig_algs) == SignatureCheck::Passed
}

/// Whether an algorithm identifier's contents name an ML-DSA parameter
/// set.
fn names_ml_dsa(algorithm: &[u8]) -> bool {
    DerReader::new(algorithm)
        .read_tag(0x06)
        .is_some_and(|oid| ML_DSA_KEYS.iter().any(|&(known, _)| known == oid))
}

/// [`check_signature_from`], with a failure told apart by whether Go's
/// own check may pass where the replay's fails ([`SignatureCheck`]).
fn go_check_signature_from(
    child: &ChainCandidate<'_>,
    parent: &ChainCandidate<'_>,
    sig_algs: &[&'static dyn rustls::pki_types::SignatureVerificationAlgorithm],
) -> SignatureCheck {
    let facts = &parent.facts;
    if (facts.version == 3 && !facts.basic_constraints)
        || (facts.basic_constraints && !facts.is_ca)
        || (facts.key_usage != 0 && facts.key_usage & KEY_USAGE_CERT_SIGN == 0)
    {
        return SignatureCheck::Failed;
    }
    // A signature whose BIT STRING has unused bits, which Go right-aligns,
    // or a key this reader cannot read.
    let (Some((key_algorithm, key)), Some(signature)) = (parent.links.key, child.links.signature)
    else {
        return SignatureCheck::Unverifiable;
    };
    // Go's RSA verification refuses a public exponent above 2^31 - 1
    // ("crypto/rsa: public exponent too large"), where the provider takes
    // one up to 2^33 - 1, as ring did, until Go's RSA rules move into it
    // (ADR-0015, T4).
    let rsa = DerReader::new(key_algorithm).read_tag(0x06) == Some(RSA_ENCRYPTION);
    if rsa && !go_rsa_exponent_fits(key) {
        return SignatureCheck::Failed;
    }
    let algorithm = sig_algs.iter().find(|alg| {
        alg.signature_alg_id().as_ref() == child.links.signature_algorithm
            && alg.public_key_alg_id().as_ref() == key_algorithm
    });
    match algorithm {
        Some(alg)
            if alg
                .verify_signature(key, child.links.tbs, signature)
                .is_ok() =>
        {
            SignatureCheck::Passed
        }
        // ring's RSA key sizes, which the provider keeps, are narrower than
        // Go's, and its key parse stricter.
        Some(_) if rsa => SignatureCheck::Unverifiable,
        Some(_) => SignatureCheck::Failed,
        // Go refuses an ML-DSA signature algorithm with parameters, or of
        // another set than the key's, as the provider does.
        None if names_ml_dsa(key_algorithm) || names_ml_dsa(child.links.signature_algorithm) => {
            SignatureCheck::Failed
        }
        None => SignatureCheck::Unverifiable,
    }
}

/// rsaEncryption, as DER object identifier contents.
const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// Whether an RSA public key's exponent is one Go's RSA verification
/// takes, at most 2^31 - 1 (`crypto/internal/fips140/rsa`
/// `checkPublicKey`); a key that does not read as `RSAPublicKey` is
/// refused too.  The exponent's other limits, odd and at least 3, are
/// the provider's as well, which keeps ring's.
// Shifts over at most eight bytes.
#[allow(clippy::arithmetic_side_effects)]
fn go_rsa_exponent_fits(key: &[u8]) -> bool {
    let Some(mut fields) = DerReader::new(key).read_tag(0x30).map(DerReader::new) else {
        return false;
    };
    let (Some(_modulus), Some(exponent)) = (fields.read_tag(0x02), fields.read_tag(0x02)) else {
        return false;
    };
    let digits = exponent.strip_prefix(&[0x00]).unwrap_or(exponent);
    digits.len() <= 4
        && exponent.first().is_some_and(|first| first & 0x80 == 0)
        && digits
            .iter()
            .fold(0u64, |value, &b| (value << 8) | u64::from(b))
            <= 0x7fff_ffff
}

/// Go's `isValid` for a root or intermediate `candidate` placed above a
/// chain of `chain_len` certificates (`crypto/x509/verify.go`, the same
/// text in 1.26.2, 1.27.1 and 1.27.3); the name check it opens with holds
/// for every candidate [`potential_parents`] gives.
// `chain_len` counts the leaf, so it is at least one.
#[allow(clippy::arithmetic_side_effects)]
fn go_is_valid(
    candidate: &ChainCandidate<'_>,
    is_root: bool,
    chain_len: usize,
    now: i64,
) -> Result<(), GoInvalid> {
    let facts = &candidate.facts;
    if facts.unhandled_critical {
        return Err(GoInvalid::UnhandledCriticalExtension);
    }
    if now < facts.not_before {
        return Err(GoInvalid::NotYetValid {
            not_before: facts.not_before,
        });
    }
    if now > facts.not_after {
        return Err(GoInvalid::Expired {
            not_after: facts.not_after,
        });
    }
    if !is_root && !(facts.basic_constraints && facts.is_ca) {
        return Err(GoInvalid::NotAuthorizedToSign);
    }
    let intermediates = u64::try_from(chain_len - 1).unwrap_or(u64::MAX);
    if facts
        .max_path_len
        .is_some_and(|max_path_len| intermediates > max_path_len)
    {
        return Err(GoInvalid::TooManyIntermediates);
    }
    Ok(())
}

/// One certificate `--clientcafile` added to the pool.
#[derive(Debug)]
struct ClientCa {
    der: Vec<u8>,
    anchor: rustls::pki_types::TrustAnchor<'static>,
    facts: CertFacts,
}

/// The client certificate verifier under `--authtype=clientcert`,
/// deciding as Go's `x509.Certificate.Verify` does for
/// `tls.RequireAndVerifyClientCert` (`crypto/tls/handshake_server.go`
/// `processCertsFromClient`) where webpki would decide otherwise:
///
/// - A presented certificate that is itself in the pool is accepted
///   on its own checks alone (`opts.Roots.contains(c)` making the chain
///   `[c]`): validity, no unhandled critical extension, and a client
///   extended key usage.  webpki refuses such a certificate when it is
///   a CA, which is exactly what dcrd's `gencerts` and `certgen`
///   produce, so the simplest clientcert setup would otherwise fail.
/// - Any other certificate is chain-verified by webpki in one search,
///   as Go's `buildChains` is one search, within webpki's one budget of
///   100 signature checks and 200,000 path-building steps.  It runs over
///   only the pool certificates Go's search ended a chain at, which
///   `isValid(rootCertificate)` passed (below), or, when the replay of
///   that search cannot vouch for it, over those `isValid` passes now and
///   whose own extended key usage `checkChainForKeyUsage` admits.  Each
///   path the search builds is held to its root's path length constraint
///   in webpki's path callback, each certificate on it to Go's extended
///   key usage rule (`GoClientAuthUsage`, the root's own in the
///   callback), and the path to Go's policy validation
///   (`go_policies_valid`); a path holding a certificate
///   Go's `alreadyInChain` takes for its root, a copy of the root the
///   client sent, say, is refused, as Go builds no such chain.  Then a
///   path on which a certificate below one with name constraints names
///   a mailbox whose domain holds `@` is refused, as Go 1.27 refuses it
///   (`go_chain_names_an_at_domain_mailbox`); the other name
///   constraint checks are webpki's.  Last, a path holding a key Go
///   1.27.3 distrusts is refused (`go_distrusted_spki`), and so is a
///   pooled certificate with one.
///   The search runs over one copy of each certificate sent, as Go's
///   pool of intermediates keeps one.  webpki's trust anchors carry
///   no validity window or extensions, so an expired, not yet valid,
///   unhandled-critical, server-only or `pathlen:0` root used to anchor
///   chains dcrd refuses.
/// - Before that search, Go's own is replayed (`go_build_chains`),
///   with its budget of 100 signature checks charged for every
///   candidate it considers.  A replay whose budget runs out before it
///   builds a chain refuses the client with Go's error, where webpki,
///   which verifies no candidate that leads to no root, would go on.
///   A replay that builds no chain refuses the client with the error
///   Go's search ends with (`GoChainError`), which `Verify` returns
///   before it looks at any chain's key usage: an unknown authority, or
///   the `isValid` refusal of the last candidate whose signature checked,
///   such as a pooled root outside its validity, refused with
///   `certificate_expired` as Go refuses it.  webpki alone would refuse a
///   leaf whose extended key usage leaves out client authentication for
///   that before it looked for an issuer, and would pass such a root over
///   without a word.  The replay vouches for that error only when it
///   followed Go's search throughout: a candidate whose signature Go may
///   verify where the provider cannot (`SignatureCheck::Unverifiable`)
///   leaves the refusal to webpki's search, which then refuses every path,
///   with the error it ranks first.  Otherwise webpki searches only over
///   the chains the replay built and accepts only a path that is one of
///   them; and a root Go's `CheckSignatureFrom` lets sign nothing, a
///   version 3 root without basic constraints, one whose basic
///   constraints do not assert cA, or one whose key usage leaves out
///   certificate signing, anchors nothing, though webpki's anchors check
///   none of it.
///
/// The root hints and the handshake signature checks are webpki's over
/// the whole pool, but for a TLS 1.2 client whose key is ML-DSA, which is
/// refused as Go refuses it.
///
/// The pool may be empty ([`GoClientCertVerifier::new`]), as Go's
/// `ClientCAs` may be: dcrwallet keeps a pool to which its client CA file
/// added nothing, warns, and requires a client certificate all the same
/// (`rpcserver.go:283-286`, `:320-322`).  Go then names no authority in
/// its CertificateRequest and refuses every certificate a client sends:
/// one outside its validity or with an unhandled critical extension for
/// that, in `isValid(leafCertificate)` before its search, and every other
/// with `x509: certificate signed by unknown authority`, its search
/// building no chain, whatever the certificate's extended key usage; and
/// so does this.
#[derive(Debug)]
pub struct GoClientCertVerifier {
    /// The pool, each certificate once, in the order it was added.
    cas: Vec<ClientCa>,
    /// webpki's client verifier over the whole pool, for the root hints
    /// and the handshake signatures, or for an empty pool [`EmptyPool`].
    all: Arc<dyn rustls::server::danger::ClientCertVerifier>,
    /// The signature algorithms chains are verified with:
    /// `dcroxide-tlscrypto`'s `RPC_SIG_ALGS`, which the verifier over the
    /// whole pool uses too.
    sig_algs: &'static [&'static dyn rustls::pki_types::SignatureVerificationAlgorithm],
    /// The keys whose chains are dropped, as Go 1.27.3 drops them:
    /// [`GO_DISTRUSTED_SPKI_SHA256`], which only the tests replace.
    distrusted: &'static [&'static str],
}

/// Go's extended key usage rule for one certificate of a client chain
/// (`checkChainForKeyUsage` asked for `ExtKeyUsageClientAuth`,
/// `crypto/x509/verify.go`): no extended key usage, or one listing
/// `clientAuth` or `anyExtendedKeyUsage`.  webpki's
/// `KeyUsage::client_auth` refuses `anyExtendedKeyUsage`; a refusal here
/// is the error webpki's rule returns, so it reads the same.  Every
/// entry is read before the rule is applied, as Go's parser reads the
/// whole list, so an entry that is not an object identifier refuses the
/// certificate wherever it stands; an identifier's own encoding has
/// been checked against Go's reader before the search, by
/// [`CertFacts::parse`].
struct GoClientAuthUsage;

impl webpki::ExtendedKeyUsageValidator for GoClientAuthUsage {
    fn validate(&self, usages: webpki::KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        // id-kp-clientAuth and anyExtendedKeyUsage, as DER OID contents.
        const CLIENT_AUTH: webpki::KeyPurposeId<'static> =
            webpki::KeyPurposeId::new(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02]);
        const ANY: webpki::KeyPurposeId<'static> =
            webpki::KeyPurposeId::new(&[0x55, 0x1d, 0x25, 0x00]);
        let mut present = Vec::new();
        let mut admitted = false;
        for usage in usages {
            let usage = usage?;
            admitted |= usage == CLIENT_AUTH || usage == ANY;
            present.push(usage.to_decoded_oid());
        }
        if admitted || present.is_empty() {
            return Ok(());
        }
        Err(webpki::Error::RequiredEkuNotFoundContext(
            webpki::RequiredEkuNotFoundContext {
                required: webpki::KeyUsage::client_auth(),
                present,
            },
        ))
    }
}

/// anyPolicy, 2.5.29.32.0, as DER object identifier contents.
const ANY_POLICY: &[u8] = &[0x55, 0x1d, 0x20, 0x00];

/// A node of Go's valid policy graph (`policyGraphNode`): its valid
/// policy, the policies it expects of a child, and its edges, by index
/// into [`PolicyGraph::nodes`].
#[derive(Debug)]
struct PolicyNode {
    valid: Vec<u8>,
    expected: Vec<Vec<u8>>,
    parents: std::collections::BTreeSet<usize>,
    children: std::collections::BTreeSet<usize>,
}

/// Go's valid policy graph (`policyGraph`, RFC 9618): the nodes, each
/// stratum's nodes by valid policy, and the previous stratum's nodes by
/// the policies they expect.  The maps keep their entries in order where
/// Go's iterate in any, and nothing the graph answers depends on it.
#[derive(Debug)]
struct PolicyGraph {
    nodes: Vec<PolicyNode>,
    strata: Vec<std::collections::BTreeMap<Vec<u8>, usize>>,
    parent_index: std::collections::BTreeMap<Vec<u8>, Vec<usize>>,
    depth: usize,
}

impl PolicyGraph {
    /// `newPolicyGraph`: the anyPolicy root, alone in stratum zero.
    fn new() -> PolicyGraph {
        PolicyGraph {
            nodes: vec![PolicyNode {
                valid: ANY_POLICY.to_vec(),
                expected: vec![ANY_POLICY.to_vec()],
                parents: std::collections::BTreeSet::new(),
                children: std::collections::BTreeSet::new(),
            }],
            strata: vec![std::collections::BTreeMap::from([(ANY_POLICY.to_vec(), 0)])],
            parent_index: std::collections::BTreeMap::new(),
            depth: 0,
        }
    }

    /// `newPolicyGraphNode`: a node for `valid`, expecting it, linked
    /// under `parents`; [`PolicyGraph::insert`] places it.
    fn new_node(&mut self, valid: Vec<u8>, parents: &[usize]) -> usize {
        let id = self.nodes.len();
        for &parent in parents {
            self.nodes[parent].children.insert(id);
        }
        self.nodes.push(PolicyNode {
            expected: vec![valid.clone()],
            valid,
            parents: parents.iter().copied().collect(),
            children: std::collections::BTreeSet::new(),
        });
        id
    }

    fn insert(&mut self, id: usize) {
        let key = self.nodes[id].valid.clone();
        self.strata[self.depth].insert(key, id);
    }

    fn parents_with_expected(&self, expected: &[u8]) -> Vec<usize> {
        if self.depth == 0 {
            return Vec::new();
        }
        self.parent_index.get(expected).cloned().unwrap_or_default()
    }

    fn parent_with_any_policy(&self) -> Option<usize> {
        let below = self.depth.checked_sub(1)?;
        self.strata[below].get(ANY_POLICY).copied()
    }

    fn parents(&self) -> Vec<usize> {
        match self.depth.checked_sub(1) {
            Some(below) => self.strata[below].values().copied().collect(),
            None => Vec::new(),
        }
    }

    fn leaf_with_policy(&self, policy: &[u8]) -> Option<usize> {
        self.strata[self.depth].get(policy).copied()
    }

    fn delete_leaf(&mut self, policy: &[u8]) {
        let Some(id) = self.strata[self.depth].remove(policy) else {
            return;
        };
        for parent in std::mem::take(&mut self.nodes[id].parents) {
            self.nodes[parent].children.remove(&id);
        }
        for child in std::mem::take(&mut self.nodes[id].children) {
            self.nodes[child].parents.remove(&id);
        }
    }

    /// The nodes other than anyPolicy whose one parent is anyPolicy, in
    /// every stratum.
    fn valid_policy_nodes(&self) -> Vec<usize> {
        let mut valid = Vec::new();
        for stratum in self.strata.iter().rev() {
            for &id in stratum.values() {
                let node = &self.nodes[id];
                if node.valid == ANY_POLICY {
                    continue;
                }
                if node.parents.len() == 1
                    && node
                        .parents
                        .iter()
                        .all(|&parent| self.nodes[parent].valid == ANY_POLICY)
                {
                    valid.push(id);
                }
            }
        }
        valid
    }

    /// Remove every childless node in the strata between the root's and
    /// the leaves', from the stratum next to the leaves toward the root,
    /// each stratum's childless nodes taken together.  A node's removal
    /// can leave childless its parents in the stratum nearer the root,
    /// taken next, and, where 6.1.4 (b) (2) put the node under its own
    /// stratum's anyPolicy node, that anyPolicy node, which Go's pass
    /// removes or keeps as its map's order falls.  Kept, it has no child,
    /// and the anyPolicy nodes nearer the root that it keeps in turn have
    /// none but anyPolicy nodes, all of which `valid_policy_nodes` skips,
    /// so it finds the same nodes either way.
    fn prune(&mut self) {
        for i in (1..self.depth).rev() {
            let childless: Vec<usize> = self.strata[i]
                .values()
                .copied()
                .filter(|&id| self.nodes[id].children.is_empty())
                .collect();
            for id in childless {
                for parent in std::mem::take(&mut self.nodes[id].parents) {
                    self.nodes[parent].children.remove(&id);
                }
                let key = self.nodes[id].valid.clone();
                self.strata[i].remove(&key);
            }
        }
    }

    // The depth is at most the chain's length.
    #[allow(clippy::arithmetic_side_effects)]
    fn incr_depth(&mut self) {
        let mut index: std::collections::BTreeMap<Vec<u8>, Vec<usize>> =
            std::collections::BTreeMap::new();
        for &id in self.strata[self.depth].values() {
            for expected in &self.nodes[id].expected {
                index.entry(expected.clone()).or_default().push(id);
            }
        }
        self.parent_index = index;
        self.depth += 1;
        self.strata.push(std::collections::BTreeMap::new());
    }
}

/// The options Go's `policiesValid` reads from `VerifyOptions`: the
/// initial policy set, as DER object identifier contents, empty for any
/// policy, and the three initial flags.  Go's TLS server verifies a
/// client chain under dcrd's `tls.Config` with all of them at their zero
/// values, [`PolicyOptions::default`]; the others are for the vectors
/// Go's own tests check `policiesValid` with.
#[derive(Debug, Clone, Default)]
struct PolicyOptions {
    policies: Vec<Vec<u8>>,
    require_explicit_policy: bool,
    inhibit_policy_mapping: bool,
    inhibit_any_policy: bool,
}

/// Go's `policiesValid` (`crypto/x509/verify.go`: RFC 5280's policy
/// processing, as RFC 9618 replaces parts of it) over a client chain,
/// the leaf first and the trust anchor left out.  The step numbers are
/// RFC 5280's, as Go's comments give them.
// Counters bounded by the chain's length, plus one.
#[allow(clippy::arithmetic_side_effects)]
fn go_policies_valid(chain: &[&PolicyFacts], opts: &PolicyOptions) -> bool {
    // A chain of the trust anchor alone.
    if chain.is_empty() {
        return true;
    }
    // n is the length of the chain minus the trust anchor.
    let n = i64::try_from(chain.len()).unwrap_or(i64::MAX - 1);
    let initial = |inhibited: bool| if inhibited { 0 } else { n + 1 };
    let mut graph = Some(PolicyGraph::new());
    let mut inhibit_any_policy = initial(opts.inhibit_any_policy);
    let mut explicit_policy = initial(opts.require_explicit_policy);
    let mut policy_mapping = initial(opts.inhibit_policy_mapping);
    // No initial policy set stands for anyPolicy.
    let mut initial_policies: std::collections::BTreeSet<Vec<u8>> =
        opts.policies.iter().cloned().collect();
    if initial_policies.is_empty() {
        initial_policies.insert(ANY_POLICY.to_vec());
    }
    for (i, cert) in chain.iter().enumerate().rev() {
        // 6.1.3 (e)
        if cert.policies.is_empty() {
            graph = None;
        }
        // 6.1.3 (f)
        if explicit_policy == 0 && graph.is_none() {
            return false;
        }
        if let Some(pg) = graph.as_mut() {
            pg.incr_depth();
            // 6.1.3 (d) (1)
            for policy in &cert.policies {
                if policy.as_slice() == ANY_POLICY {
                    continue;
                }
                let mut parents = pg.parents_with_expected(policy);
                if parents.is_empty()
                    && let Some(any) = pg.parent_with_any_policy()
                {
                    parents = vec![any];
                }
                if !parents.is_empty() {
                    let node = pg.new_node(policy.clone(), &parents);
                    pg.insert(node);
                }
            }
            // 6.1.3 (d) (2)
            if cert
                .policies
                .iter()
                .any(|policy| policy.as_slice() == ANY_POLICY)
                && (inhibit_any_policy > 0 || (i > 0 && cert.self_issued))
            {
                let mut missing: std::collections::BTreeMap<Vec<u8>, Vec<usize>> =
                    std::collections::BTreeMap::new();
                for parent in pg.parents() {
                    for expected in &pg.nodes[parent].expected {
                        if pg.leaf_with_policy(expected).is_none() {
                            missing.entry(expected.clone()).or_default().push(parent);
                        }
                    }
                }
                for (policy, parents) in missing {
                    let node = pg.new_node(policy, &parents);
                    pg.insert(node);
                }
            }
            // 6.1.3 (d) (3)
            pg.prune();
            // 6.1.4 (b)
            if i != 0 && !cert.mappings.is_empty() {
                let mut mappings: std::collections::BTreeMap<Vec<u8>, Vec<Vec<u8>>> =
                    std::collections::BTreeMap::new();
                for (issuer, subject) in &cert.mappings {
                    if policy_mapping > 0 {
                        if issuer.as_slice() == ANY_POLICY || subject.as_slice() == ANY_POLICY {
                            // An invalid mapping.
                            return false;
                        }
                        mappings
                            .entry(issuer.clone())
                            .or_default()
                            .push(subject.clone());
                    } else {
                        pg.delete_leaf(issuer);
                    }
                }
                pg.prune();
                for (issuer, subjects) in mappings {
                    if let Some(matching) = pg.leaf_with_policy(&issuer) {
                        pg.nodes[matching].expected = subjects;
                    } else if let Some(any) = pg.leaf_with_policy(ANY_POLICY) {
                        let node = pg.new_node(issuer, &[any]);
                        pg.nodes[node].expected = subjects;
                        pg.insert(node);
                    }
                }
            }
        }
        if i != 0 {
            // 6.1.4 (h)
            if !cert.self_issued {
                for counter in [
                    &mut explicit_policy,
                    &mut policy_mapping,
                    &mut inhibit_any_policy,
                ] {
                    if *counter > 0 {
                        *counter -= 1;
                    }
                }
            }
            // 6.1.4 (i) and (j): a value present and not negative that
            // is below the counter lowers it.
            for (counter, value) in [
                (&mut explicit_policy, cert.require_explicit_policy),
                (&mut policy_mapping, cert.inhibit_policy_mapping),
                (&mut inhibit_any_policy, cert.inhibit_any_policy),
            ] {
                if let Some(value) = value
                    && value >= 0
                    && value < *counter
                {
                    *counter = value;
                }
            }
        }
    }
    // 6.1.5 (a)
    if explicit_policy > 0 {
        explicit_policy -= 1;
    }
    // 6.1.5 (b)
    if chain
        .first()
        .is_some_and(|leaf| leaf.require_explicit_policy == Some(0))
    {
        explicit_policy = 0;
    }
    // 6.1.5 (g) (1) to (4): the authority-constrained policy set, the
    // valid policies and anyPolicy if it is a leaf.
    let mut authority = std::collections::BTreeSet::new();
    if let Some(pg) = &graph {
        for id in pg.valid_policy_nodes() {
            authority.insert(pg.nodes[id].valid.clone());
        }
        if let Some(any) = pg.leaf_with_policy(ANY_POLICY) {
            authority.insert(pg.nodes[any].valid.clone());
        }
    }
    // 6.1.5 (g) (5) and (6): intersected with the initial policy set
    // unless that is anyPolicy alone.
    let mut user = authority.clone();
    if initial_policies.len() != 1 || !initial_policies.contains(ANY_POLICY) {
        user.retain(|policy| initial_policies.contains(policy));
        if authority.contains(ANY_POLICY) {
            user.extend(initial_policies);
        }
    }
    !(explicit_policy == 0 && user.is_empty())
}

/// Go's error when every chain its search built fails `policiesValid`
/// (`Verify`, `crypto/x509/verify.go`: `NoValidChains` with this
/// detail), carried to the handshake's error text (`server::go_error_text`).
#[derive(Debug)]
pub struct InvalidPolicies(
    /// How many chains the search built, every one refused.
    pub usize,
);

impl std::fmt::Display for InvalidPolicies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "x509: no valid chains built: {} candidate chains with invalid policies",
            self.0
        )
    }
}

impl std::error::Error for InvalidPolicies {}

/// Go's error when every chain its search built was dropped, some for
/// their key usage and some for their policies (`Verify`,
/// `crypto/x509/verify.go`: `NoValidChains` with both counts), carried to
/// the handshake's error text (`server::go_error_text`).
#[derive(Debug)]
pub struct DroppedChains {
    /// The chains dropped for their key usage.
    pub key_usage: usize,
    /// The chains dropped for their policies.
    pub policies: usize,
}

impl std::fmt::Display for DroppedChains {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "x509: no valid chains built: {} candidate chains with incompatible key usage, {} \
             candidate chains with invalid policies",
            self.key_usage, self.policies
        )
    }
}

impl std::error::Error for DroppedChains {}

/// What Go's `Verify` returns when `policiesValid` or, after it,
/// `checkChainForKeyUsage` drops every chain in `chains`, the chains its
/// search built for a leaf with `leaf_facts` and `leaf_policies`
/// (`crypto/x509/verify.go:620-670`): a chain either drops goes no
/// further, so no name constraint or distrusted key is asked of any, and
/// the error is `IncompatibleUsage` when no chain was dropped for its
/// policies, Go's `NoValidChains` with the policies' count when none was
/// dropped for its usage, and with both counts otherwise.  `None` when a
/// chain passes both, or one cannot be read, which leaves the verdict to
/// the search and the path callback.
fn go_usage_or_policy_verdict(
    leaf_der: &[u8],
    leaf_facts: &CertFacts,
    leaf_policies: &PolicyFacts,
    chains: &[Vec<&[u8]>],
) -> Option<rustls::Error> {
    if chains.is_empty() {
        return None;
    }
    let mut key_usage = 0usize;
    let mut policies = 0usize;
    let mut first_refused_usage: Option<&[u8]> = None;
    for chain in chains {
        let parsed: Vec<(CertFacts, PolicyFacts, ChainIdentity<'_>)> = chain
            .iter()
            .map(|der| CertFacts::parse_all(der))
            .collect::<Option<_>>()?;
        // `policiesValid` reads the chain below its root
        // (`verify.go:1208-1234`), as the path callback hands it over;
        // `checkChainForKeyUsage` reads the root too.
        let below_root = parsed.split_last().map_or(&[][..], |(_, below)| below);
        let policy_chain: Vec<&PolicyFacts> = std::iter::once(leaf_policies)
            .chain(below_root.iter().map(|(_, policies, _)| policies))
            .collect();
        if !go_policies_valid(&policy_chain, &PolicyOptions::default()) {
            policies = policies.saturating_add(1);
        } else if leaf_facts.client_auth && parsed.iter().all(|(facts, _, _)| facts.client_auth) {
            return None;
        } else {
            key_usage = key_usage.saturating_add(1);
            // The usage webpki would report, a certificate below the root
            // whose usage leaves out client authentication, on the first
            // chain dropped for it, the leaf before the intermediates.
            if first_refused_usage.is_none() {
                first_refused_usage = Some(if !leaf_facts.client_auth {
                    leaf_der
                } else {
                    parsed
                        .split_last()
                        .and_then(|(_, below)| {
                            below
                                .iter()
                                .zip(chain.iter())
                                .find(|((facts, _, _), _)| !facts.client_auth)
                                .map(|(_, der)| *der)
                        })
                        .unwrap_or_default()
                });
            }
        }
    }
    let other = |error: Arc<dyn std::error::Error + Send + Sync>| {
        rustls::Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(
            error,
        )))
    };
    Some(match (key_usage, policies) {
        // Go's `IncompatibleUsage`, which names no certificate, given as
        // the error webpki gives for a usage refusal, with its context
        // when a certificate below the root refused it and without when
        // the root alone did (as the path callback refuses a root's), so
        // that it reads as the refusals webpki makes.
        (_, 0) => match first_refused_usage.and_then(go_extended_key_usages) {
            Some(present) => go_pki_error(webpki::Error::RequiredEkuNotFoundContext(
                webpki::RequiredEkuNotFoundContext {
                    required: webpki::KeyUsage::client_auth(),
                    present,
                },
            )),
            None => rustls::Error::InvalidCertificate(rustls::CertificateError::InvalidPurpose),
        },
        (0, policies) => other(Arc::new(InvalidPolicies(policies))),
        (key_usage, policies) => other(Arc::new(DroppedChains {
            key_usage,
            policies,
        })),
    })
}

/// The extended key usages `der` lists, each as the decoded arcs of its
/// object identifier, as webpki reports them in a usage refusal; `None`
/// when it has no extended key usage extension or one that cannot be
/// read, which [`CertFacts::parse`] has read before this is asked.
fn go_extended_key_usages(der: &[u8]) -> Option<Vec<Vec<usize>>> {
    const EKU: &[u8] = &[0x55, 0x1d, 0x25];
    let mut tbs =
        DerReader::new(DerReader::new(DerReader::new(der).read_tag(0x30)?).read_tag(0x30)?);
    let extensions = loop {
        let (tag, content) = tbs.read()?;
        if tag == 0xa3 {
            break content;
        }
    };
    let mut extensions = DerReader::new(DerReader::new(extensions).read_tag(0x30)?);
    while !extensions.is_empty() {
        let mut extension = DerReader::new(extensions.read_tag(0x30)?);
        if extension.read_tag(0x06)? != EKU {
            continue;
        }
        if extension.peek_tag() == Some(0x01) {
            extension.read_tag(0x01)?;
        }
        let mut usages = DerReader::new(DerReader::new(extension.read_tag(0x04)?).read_tag(0x30)?);
        let mut present = Vec::new();
        while !usages.is_empty() {
            present.push(webpki::KeyPurposeId::new(usages.read_tag(0x06)?).to_decoded_oid());
        }
        return Some(present);
    }
    None
}

/// Go's error when every chain its search built was dropped, and none
/// for its policies, key usage or a name constraint (`Verify`,
/// `crypto/x509/verify.go`: `NoValidChains` with no detail): a search
/// whose chains all hold a distrusted key (`go_distrusted_spki`).
/// Carried to the handshake's error text (`server::go_error_text`).
#[derive(Debug)]
pub struct NoValidChains;

impl std::fmt::Display for NoValidChains {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("x509: no valid chains built")
    }
}

impl std::error::Error for NoValidChains {}

/// The SHA-256 hashes, in hex, of the subject public key infos Go 1.27.3
/// drops every chain through (`distrustedSPKIHashes`,
/// `crypto/x509/verify.go:1417-1426`), as written there.
const GO_DISTRUSTED_SPKI_SHA256: &[&str] = &[
    "ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105",
    "49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f",
    "e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41",
    "5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0",
    "43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b",
    "63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8",
    "ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6",
    "92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30",
];

/// The SHA-256 of `data` in lower-case hex, as Go's
/// `hex.EncodeToString(sha256.Sum256(data))` gives it, with the
/// provider's SHA-256, the hash of its `TLS13_AES_128_GCM_SHA256`; `None`
/// if that suite were ever to hash otherwise.
fn go_sha256_hex(data: &[u8]) -> Option<String> {
    use std::fmt::Write as _;
    let hash = dcroxide_tlscrypto::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()?
        .common
        .hash_provider;
    if hash.algorithm() != rustls::crypto::hash::HashAlgorithm::SHA256 {
        return None;
    }
    let mut hex = String::with_capacity(64);
    for byte in hash.hash(data).as_ref() {
        write!(hex, "{byte:02x}").ok()?;
    }
    Some(hex)
}

/// Whether `spki`, a whole SubjectPublicKeyInfo element, is a key
/// `distrusted` lists, as Go's `containsDistrustedSPKIHash` asks it of
/// each certificate on a chain (`crypto/x509/verify.go:1430-1438`).
/// Without the hash the key is taken as distrusted, so the check fails
/// closed.  The verifier's table is [`GO_DISTRUSTED_SPKI_SHA256`]; only
/// the tests give it another, naming keys they generate.
fn go_distrusted_spki(spki: &[u8], distrusted: &[&str]) -> bool {
    go_sha256_hex(spki).is_none_or(|hex| distrusted.contains(&hex.as_str()))
}

/// A webpki error as rustls's client verifier reports it (rustls
/// `webpki/mod.rs` `pki_error`), so a chain [`GoClientCertVerifier`]
/// refuses fails with the error rustls's own verifier gives, and the
/// handshake is refused and logged the same (`server::go_error_text`).
/// The revocation and name errors are left to the last arm: no
/// revocation list or name is checked.
fn go_pki_error(error: webpki::Error) -> rustls::Error {
    use rustls::{CertificateError, ExtendedKeyPurpose};
    use webpki::Error::*;
    let purpose = |values: Vec<usize>| match values.as_slice() {
        webpki::KeyUsage::CLIENT_AUTH_REPR => ExtendedKeyPurpose::ClientAuth,
        webpki::KeyUsage::SERVER_AUTH_REPR => ExtendedKeyPurpose::ServerAuth,
        _ => ExtendedKeyPurpose::Other(values),
    };
    match error {
        BadDer | BadDerTime | TrailingData(_) => CertificateError::BadEncoding.into(),
        CertNotValidYet { time, not_before } => {
            CertificateError::NotValidYetContext { time, not_before }.into()
        }
        CertExpired { time, not_after } => {
            CertificateError::ExpiredContext { time, not_after }.into()
        }
        InvalidCertValidity => CertificateError::Expired.into(),
        UnknownIssuer => CertificateError::UnknownIssuer.into(),
        InvalidSignatureForPublicKey => CertificateError::BadSignature.into(),
        #[allow(deprecated)]
        UnsupportedSignatureAlgorithm | UnsupportedSignatureAlgorithmForPublicKey => {
            CertificateError::UnsupportedSignatureAlgorithm.into()
        }
        UnsupportedSignatureAlgorithmContext(cx) => {
            CertificateError::UnsupportedSignatureAlgorithmContext {
                signature_algorithm_id: cx.signature_algorithm_id,
                supported_algorithms: cx.supported_algorithms,
            }
            .into()
        }
        UnsupportedSignatureAlgorithmForPublicKeyContext(cx) => {
            CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext {
                signature_algorithm_id: cx.signature_algorithm_id,
                public_key_algorithm_id: cx.public_key_algorithm_id,
            }
            .into()
        }
        #[allow(deprecated)]
        RequiredEkuNotFound => CertificateError::InvalidPurpose.into(),
        RequiredEkuNotFoundContext(webpki::RequiredEkuNotFoundContext { required, present }) => {
            CertificateError::InvalidPurposeContext {
                required: purpose(required.oid_values().collect()),
                presented: present.into_iter().map(purpose).collect(),
            }
            .into()
        }
        _ => CertificateError::Other(rustls::OtherError(Arc::new(error))).into(),
    }
}

/// A pool of client certificate authorities, as Go's `x509.CertPool` is
/// filled for `tls.Config.ClientCAs`: from PEM through
/// [`ClientCaPool::append_certs_from_pem`], as dcrd and dcrwallet read a
/// client CA file, or one DER certificate at a time through
/// [`ClientCaPool::add_cert`], as dcrwallet adds the authority it issues
/// under `--issueclientcert` (`rpcserver.go:304`).  It keeps one copy of
/// each certificate, as `addCertFunc` does.
#[derive(Debug, Default)]
pub struct ClientCaPool {
    cas: Vec<ClientCa>,
}

impl ClientCaPool {
    /// An empty pool, Go's `x509.NewCertPool()`.
    pub fn new() -> ClientCaPool {
        ClientCaPool::default()
    }

    /// Add the certificates of `pem` as Go's
    /// `CertPool.AppendCertsFromPEM` does (`crypto/x509/cert_pool.go`):
    /// every well-formed `CERTIFICATE` block without headers whose
    /// certificate parses, skipping everything else, in the file's order.
    /// webpki's anchor parser and `CertFacts::parse` together stand in
    /// for Go's `ParseCertificate`: a certificate either refuses is
    /// skipped.  Returns Go's `ok`: whether any certificate parsed, one
    /// the pool held already among them.
    pub fn append_certs_from_pem(&mut self, pem: &[u8]) -> bool {
        let mut added = false;
        let mut rest = pem;
        while !rest.is_empty() {
            let Some((block, next)) = go_pem_decode(rest) else {
                break;
            };
            rest = next;
            if block.block_type == b"CERTIFICATE" && !block.has_headers {
                added |= self.add_cert(block.bytes);
            }
        }
        added
    }

    /// Add one DER certificate, as Go's `CertPool.AddCert` adds a parsed
    /// one, parsing it as [`ClientCaPool::append_certs_from_pem`] does.
    /// Returns whether it parsed; one the pool holds already is not added
    /// again.  Go's `AddCert` takes a certificate already parsed, so a
    /// certificate refused here is one Go's `ParseCertificate` would have
    /// refused before `AddCert` was reached, as far as the two parsers
    /// agree.
    pub fn add_cert(&mut self, der: Vec<u8>) -> bool {
        if self.cas.iter().any(|ca| ca.der == der) {
            return true;
        }
        let mut one = rustls::RootCertStore::empty();
        if one
            .add(rustls::pki_types::CertificateDer::from(der.as_slice()))
            .is_err()
        {
            return false;
        }
        let Some(anchor) = one.roots.pop() else {
            return false;
        };
        let Some(facts) = CertFacts::parse(&der) else {
            return false;
        };
        self.cas.push(ClientCa { der, anchor, facts });
        true
    }

    /// How many certificates the pool holds.
    pub fn len(&self) -> usize {
        self.cas.len()
    }

    /// Whether the pool holds no certificate.
    pub fn is_empty(&self) -> bool {
        self.cas.is_empty()
    }
}

/// The verifier [`GoClientCertVerifier`] defers to for an empty pool,
/// where webpki's builder refuses to make one: a client certificate is
/// asked for and required, no authority is named, and the handshake
/// signatures are checked with the same set and the same functions
/// webpki's verifier calls.  It accepts no certificate; the chain itself
/// is verified by [`GoClientCertVerifier`], which over an empty pool
/// builds no chain.
#[derive(Debug)]
struct EmptyPool;

impl rustls::server::danger::ClientCertVerifier for EmptyPool {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &dcroxide_tlscrypto::RPC_SIG_ALGS,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &dcroxide_tlscrypto::RPC_SIG_ALGS,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        dcroxide_tlscrypto::RPC_SIG_ALGS.supported_schemes()
    }
}

impl GoClientCertVerifier {
    /// The verifier over `pool`, for a `tls.Config` whose `ClientAuth`
    /// is `RequireAndVerifyClientCert` and whose `ClientCAs` is the pool.
    /// An empty pool is allowed, as Go allows it: the CertificateRequest
    /// then names no authority, and every client certificate is refused.
    pub fn new(pool: ClientCaPool) -> Result<GoClientCertVerifier, String> {
        let cas = pool.cas;
        let all: Arc<dyn rustls::server::danger::ClientCertVerifier> = if cas.is_empty() {
            Arc::new(EmptyPool)
        } else {
            Self::webpki_over(cas.iter().map(|ca| ca.anchor.clone()).collect())?
        };
        Ok(GoClientCertVerifier {
            cas,
            all,
            sig_algs: dcroxide_tlscrypto::RPC_SIG_ALGS.all,
            distrusted: GO_DISTRUSTED_SPKI_SHA256,
        })
    }

    /// The verifier over the certificates of a client CA file, read as
    /// [`ClientCaPool::append_certs_from_pem`] reads it, failing with
    /// [`NO_CLIENT_CAS`] when nothing was added, as dcrd's `newTLSConfig`
    /// fails (`server.go:3694-3698`).
    pub fn from_pem(cas_pem: &[u8]) -> Result<GoClientCertVerifier, String> {
        let mut pool = ClientCaPool::new();
        if !pool.append_certs_from_pem(cas_pem) {
            return Err(NO_CLIENT_CAS.to_string());
        }
        Self::new(pool)
    }

    /// [`GoClientCertVerifier::from_pem`] for the DER certificates of a
    /// file's `CERTIFICATE` blocks without headers, in the file's order.
    fn from_certificates(ders: Vec<Vec<u8>>) -> Result<GoClientCertVerifier, String> {
        let mut pool = ClientCaPool::new();
        let mut added = false;
        for der in ders {
            added |= pool.add_cert(der);
        }
        if !added {
            return Err(NO_CLIENT_CAS.to_string());
        }
        Self::new(pool)
    }

    /// The verifier with `distrusted` in place of Go's table, for tests
    /// of the check, whose certificates carry keys of their own.
    #[cfg(test)]
    fn distrusting(self, distrusted: &'static [&'static str]) -> GoClientCertVerifier {
        GoClientCertVerifier { distrusted, ..self }
    }

    /// webpki's client verifier over the given anchors, on
    /// `dcroxide-tlscrypto`'s provider with the listener's verification
    /// set, `RPC_SIG_ALGS`, which adds ML-DSA and the ECDSA pairs ring
    /// lacked, P-521's among them, to ring's set and lists the
    /// schemes in Go's order, and so is the list the CertificateRequest
    /// offers.
    fn webpki_over(
        roots: Vec<rustls::pki_types::TrustAnchor<'static>>,
    ) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>, String> {
        rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(rustls::RootCertStore { roots }),
            Arc::new(rustls::crypto::CryptoProvider {
                signature_verification_algorithms: dcroxide_tlscrypto::RPC_SIG_ALGS,
                ..dcroxide_tlscrypto::default_provider()
            }),
        )
        .build()
        .map_err(|e| format!("unable to build the RPC client verifier: {e}"))
    }

    /// Go's `certs[0].Verify(opts)` over the pool, with the client's
    /// other certificates as intermediates and client authentication as
    /// the usage (`crypto/tls/handshake_server.go:970-998`), for
    /// certificates [`go_read_client_certificates`] has read.
    fn verify_chain(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let now_secs = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
        // The facts Go's `isValid` reads below.
        let Some((leaf_facts, leaf_policies, leaf_identity)) =
            CertFacts::parse_all(end_entity.as_ref())
        else {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        };

        // A certificate in the pool is its own chain: Go checks it with
        // `isValid(leafCertificate)` and the key usage walk over `[c]`,
        // and nothing else.
        if let Some(facts) = self
            .cas
            .iter()
            .find(|ca| ca.der == end_entity.as_ref())
            .map(|ca| ca.facts)
        {
            facts
                .valid_at(now_secs)
                .map_err(rustls::Error::InvalidCertificate)?;
            if !facts.client_auth {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::InvalidPurpose,
                ));
            }
            // Go then drops `[c]` if its key is distrusted, and no chain
            // is left.
            if go_distrusted_spki(leaf_identity.spki, self.distrusted) {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::Other(rustls::OtherError(Arc::new(NoValidChains))),
                ));
            }
            return Ok(rustls::server::danger::ClientCertVerified::assertion());
        }

        // Otherwise one chain search, over the roots Go would accept at
        // the end of a chain: `isValid(rootCertificate)` in `buildChains`
        // (validity, critical extensions, and `MaxPathLen` against the
        // chain's intermediates), and the root's own extended key usage
        // in `checkChainForKeyUsage`.  webpki's anchors keep none of
        // this, so the roots are chosen here, each path webpki builds is
        // held to its root's path length constraint in the callback, and
        // when the replay below has built chains, to the root's extended
        // key usage there too.  A path refused there sends webpki on to the next
        // within the same search and the same budgets, where the code
        // this replaced made a whole search, with budgets of its own,
        // for each of up to 100 choices of the intermediates sent.
        // webpki counts its 100 signature checks over each path it
        // verifies at an anchor, where Go counts one for each candidate
        // issuer, so refused paths that share intermediates Go counts
        // once spend it sooner than Go's; the other way round, Go's
        // budget is held by replaying Go's own search first (below).  A
        // chain the constraint refuses
        // fails with webpki's own error for it, which is logged as Go's
        // `TooManyIntermediates`, unless another path the search tried
        // failed in a way webpki ranks higher, on a signature, a validity
        // window or a usage (PARITY.md, the clientcert entry).
        //
        // Go's `isValid` refuses a leaf, and passes over an intermediate,
        // that carries an unhandled critical extension, which webpki
        // takes as understood when it is a subject alternative name or
        // name constraints extension of a form Go does not handle
        // ([`CertFacts::parse`]): the leaf is refused here, before the
        // search, as Go refuses it before its own, and a path through
        // such an intermediate is refused in the callback.  A search that
        // fails on such a refusal is reported as Go reports it.  webpki's
        // own refusal of a critical extension it does not support is the
        // same error, raised also while it parses a sent certificate no
        // path uses, where Go reports no issuer, so it keeps rustls's
        // error unless the callback refused a path too.
        if leaf_facts.unhandled_critical {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnhandledCriticalExtension,
            ));
        }
        // Go adds the sent certificates to a pool of intermediates
        // (`processCertsFromClient`), which keeps one copy of each, so a
        // certificate sent twice makes no second chain.
        let mut sent: Vec<rustls::pki_types::CertificateDer<'_>> = Vec::new();
        for cert in intermediates {
            if !sent.iter().any(|seen| seen.as_ref() == cert.as_ref()) {
                sent.push(cert.clone());
            }
        }
        // Go's own search, replayed ([`go_build_chains`]), decides which
        // chains there are, and webpki's search below then accepts only
        // a path that is one of them.  Go's budget charges every
        // candidate it considers, where webpki's counts the signatures of
        // the paths it verifies at an anchor, so candidates named as an
        // issuer that lead to no root, which webpki never verifies, can
        // spend Go's before it builds a chain, and Go then refuses what
        // webpki alone would accept.  Go checks the leaf's own validity
        // before it searches (`isValid(leafCertificate)` in `Verify`);
        // for a leaf outside its window webpki's search fails on that,
        // so the replay is not run for it.
        //
        // When the replay builds no chain, Go's `Verify` returns the
        // error its search ended with ([`GoChainError`]) before it looks
        // at any chain's key usage, and that is the refusal, where webpki
        // would check the leaf's extended key usage before it looked for
        // an issuer, and would pass over a pooled root outside its
        // validity without a word.  A replay that met a candidate whose
        // signature Go may verify where the provider cannot
        // ([`SignatureCheck::Unverifiable`]) does not vouch for Go's
        // error, and webpki's search then gives it, as before.
        let allowed = if leaf_facts.valid_at(now_secs).is_ok() {
            let leaf = ChainCandidate::parse(end_entity.as_ref());
            let pool: Vec<ChainCandidate<'_>> = self
                .cas
                .iter()
                .filter_map(|ca| ChainCandidate::parse(&ca.der))
                .collect();
            let sent_candidates: Vec<ChainCandidate<'_>> = sent
                .iter()
                .filter_map(|cert| ChainCandidate::parse(cert.as_ref()))
                .collect();
            match leaf.map(|leaf| {
                go_build_chains(&leaf, &pool, &sent_candidates, now_secs, self.sig_algs)
            }) {
                Some(GoChains::SignatureLimit) => {
                    return Err(go_pki_error(webpki::Error::MaximumSignatureChecksExceeded));
                }
                Some(GoChains::NoChain {
                    error,
                    certain: true,
                }) => {
                    return Err(match error {
                        GoChainError::UnknownAuthority => rustls::Error::InvalidCertificate(
                            rustls::CertificateError::UnknownIssuer,
                        ),
                        GoChainError::Invalid(invalid) => invalid.to_rustls(now_secs),
                    });
                }
                Some(GoChains::Built { chains, certain }) => {
                    // Go holds each chain to its policies and then its
                    // key usage before anything else; when those two drop
                    // every chain it built, its error is decided by them
                    // alone, and webpki's search, which ranks a signature
                    // failure on a path Go never built above a usage
                    // refusal, is not asked.
                    if certain
                        && let Some(err) = go_usage_or_policy_verdict(
                            end_entity.as_ref(),
                            &leaf_facts,
                            &leaf_policies,
                            &chains,
                        )
                    {
                        return Err(err);
                    }
                    Some(chains)
                }
                Some(GoChains::NoChain { certain: false, .. }) | None => Some(Vec::new()),
            }
        } else {
            None
        };
        // When the replay built chains, webpki searches only over them:
        // the sent certificates on one, and the roots that end one.  A
        // path webpki builds and the callback then refuses still spends
        // webpki's budget, and webpki tries the sent certificates in the
        // order sent where Go puts the key identifiers' matches first, so
        // paths Go never builds, through certificates the pool's roots
        // did sign or through forged ones, could spend it before webpki
        // reached a chain Go built.  With no chain built, which reaches
        // here only from a replay that cannot vouch for Go's error, webpki
        // searches everything, for the error it ranks, and the callback
        // refuses every path.
        let built = allowed.as_ref().filter(|chains| !chains.is_empty());
        let chain_ends: Option<Vec<&[u8]>> = built.map(|chains| {
            chains
                .iter()
                .filter_map(|chain| chain.last().copied())
                .collect()
        });
        let chain_below: Option<Vec<&[u8]>> = built.map(|chains| {
            chains
                .iter()
                .flat_map(|chain| chain.split_last().map_or(&[][..], |(_, below)| below))
                .copied()
                .collect()
        });
        // With chains built, the roots are those they end at, which Go's
        // `isValid(rootCertificate)` passed, a root's own extended key
        // usage being held to Go's rule in the callback, after the
        // policies, where `checkChainForKeyUsage` holds it.  Otherwise the
        // roots Go would accept at the end of a chain.
        let usable: Vec<&ClientCa> = self
            .cas
            .iter()
            .filter(|ca| match &chain_ends {
                Some(ends) => ends.contains(&ca.der.as_slice()),
                None => ca.facts.valid_at(now_secs).is_ok() && ca.facts.client_auth,
            })
            .collect();
        let searched: Vec<rustls::pki_types::CertificateDer<'_>> = match &chain_below {
            Some(below) => sent
                .iter()
                .filter(|cert| below.contains(&cert.as_ref()))
                .cloned()
                .collect(),
            None => sent.clone(),
        };
        let anchors: Vec<rustls::pki_types::TrustAnchor<'_>> =
            usable.iter().map(|ca| ca.anchor.clone()).collect();
        // The pool parsed each of these when it was loaded.
        let roots: Vec<Option<ChainIdentity<'_>>> = usable
            .iter()
            .map(|ca| CertFacts::parse_all(&ca.der).map(|(_, _, identity)| identity))
            .collect();
        let refused_unhandled = std::cell::Cell::new(false);
        let refused_policies = std::cell::Cell::new(0usize);
        let refused_distrusted = std::cell::Cell::new(false);
        let refused_mailbox = std::cell::Cell::new(false);
        let within_path_len = |path: &webpki::VerifiedPath<'_>| {
            let ders: Vec<rustls::pki_types::CertificateDer<'_>> = path
                .intermediate_certificates()
                .map(|cert| cert.der())
                .collect();
            let parsed: Option<Vec<(CertFacts, PolicyFacts, ChainIdentity<'_>)>> = ders
                .iter()
                .map(|der| CertFacts::parse_all(der.as_ref()))
                .collect();
            let Some(parsed) = parsed
                .filter(|parsed| parsed.iter().all(|(facts, _, _)| !facts.unhandled_critical))
            else {
                refused_unhandled.set(true);
                return Err(webpki::Error::UnsupportedCriticalExtension);
            };
            let held = parsed.len();
            // webpki hands back the anchor from the slice it was given;
            // any other is refused rather than left unconstrained.
            let Some(i) = anchors
                .iter()
                .position(|anchor| std::ptr::eq(anchor, path.anchor()))
            else {
                return Err(webpki::Error::UnknownIssuer);
            };
            // Go passes over a root already on the chain before it checks
            // the root's signature (`alreadyInChain` in `buildChains`), so
            // a path that reaches the root through a copy of it the client
            // sent is no chain to Go.  webpki keeps that rule for the
            // intermediates it adds, not for the anchor; the copy would
            // otherwise be held to the policy rules as an intermediate,
            // and one without a policies extension would pass a path whose
            // mapping Go refuses on the chain that ends at the root itself.
            let chain: Vec<ChainIdentity<'_>> = std::iter::once(leaf_identity)
                .chain(parsed.iter().map(|&(_, _, identity)| identity))
                .collect();
            if roots[i].is_none_or(|root| root.already_in(&chain)) {
                return Err(webpki::Error::UnknownIssuer);
            }
            if let Some(limit) = usable[i].facts.max_path_len
                && u64::try_from(held).unwrap_or(u64::MAX) > limit
            {
                return Err(webpki::Error::PathLenConstraintViolated);
            }
            // A path that is no chain Go's search built is none to Go:
            // it lies past the point where Go's budget ran out, or runs
            // through a certificate Go passes over.  This comes before the
            // policies, so a path Go never built is not counted among the
            // chains they dropped.
            if let Some(allowed) = &allowed {
                let path: Vec<&[u8]> = ders
                    .iter()
                    .map(|der| der.as_ref())
                    .chain(std::iter::once(usable[i].der.as_slice()))
                    .collect();
                if !allowed.contains(&path) {
                    return Err(webpki::Error::UnknownIssuer);
                }
            }
            // Go's `Verify` drops each chain its search built that
            // `policiesValid` refuses, and keeps the rest.
            let chain: Vec<&PolicyFacts> = std::iter::once(&leaf_policies)
                .chain(parsed.iter().map(|(_, policies, _)| policies))
                .collect();
            if !go_policies_valid(&chain, &PolicyOptions::default()) {
                refused_policies.set(refused_policies.get().saturating_add(1));
                return Err(webpki::Error::UnknownIssuer);
            }
            // Go's `checkChainForKeyUsage` then holds every certificate on
            // the chain to its extended key usage rule, the root's too;
            // webpki has held the leaf and the intermediates to it before
            // the callback (`GoClientAuthUsage`), and its anchors carry no
            // extensions, so the root is held to it here.  Go reports a
            // chain dropped for it as `IncompatibleUsage`, which webpki's
            // error for a usage reads as (`server::go_error_text`).
            if !usable[i].facts.client_auth {
                #[allow(deprecated)]
                return Err(webpki::Error::RequiredEkuNotFound);
            }
            // Go then holds the chain's names to its name constraints
            // (`checkChainConstraints`, `verify.go:641-646`), after the
            // key usage, which webpki has checked before the callback.
            // webpki has made its own name constraint checks there too;
            // the one Go 1.27 added is made here, in Go's place after
            // the policies: a mailbox whose domain holds `@` below a
            // certificate with name constraints of any form.
            let named: Vec<(bool, Option<&[u8]>)> =
                std::iter::once((leaf_facts.name_constraints, leaf_identity.san))
                    .chain(
                        parsed
                            .iter()
                            .map(|(facts, _, identity)| (facts.name_constraints, identity.san)),
                    )
                    .chain(std::iter::once((
                        usable[i].facts.name_constraints,
                        roots[i].and_then(|root| root.san),
                    )))
                    .collect();
            if go_chain_names_an_at_domain_mailbox(&named) {
                refused_mailbox.set(true);
                return Err(webpki::Error::NameConstraintViolation);
            }
            // Go 1.27.3 then drops a chain on which the leaf, an
            // intermediate or the root has a distrusted key, and keeps no
            // count of it (`verify.go:647-649`).
            if std::iter::once(&leaf_identity)
                .chain(parsed.iter().map(|(_, _, identity)| identity))
                .chain(roots[i].iter())
                .any(|identity| go_distrusted_spki(identity.spki, self.distrusted))
            {
                refused_distrusted.set(true);
                return Err(webpki::Error::UnknownIssuer);
            }
            Ok(())
        };
        let cert = webpki::EndEntityCert::try_from(end_entity).map_err(go_pki_error)?;
        cert.verify_for_usage(
            self.sig_algs,
            &anchors,
            &searched,
            now,
            GoClientAuthUsage,
            None,
            Some(&within_path_len),
        )
        .map(|_| rustls::server::danger::ClientCertVerified::assertion())
        .map_err(|err| match err {
            // A chain Go built that broke a name constraint gives Go's
            // error for that, whatever dropped the others
            // (`verify.go:653-656`); the port gives webpki's for every
            // name constraint refusal.
            _ if refused_mailbox.get() => go_pki_error(webpki::Error::NameConstraintViolation),
            // Once Go's search has built a chain it drops its signature
            // limit (`buildChains`) and the errors of the candidates that
            // made none, and `Verify` reports what dropped every chain it
            // built: `NoValidChains` when that was `policiesValid`.  A
            // chain is built here when the callback sees it.  A search in
            // which Go's budget runs out before it builds a chain is
            // refused above, by the replay; webpki's budgets can still run
            // out before Go's, and webpki's other two have no Go
            // counterpart, where Go's search would go on.  Go reports
            // instead the name
            // constraint broken by a chain that passed the policies and
            // the key usage, which webpki refuses during its search
            // (PARITY.md, the clientcert entry).
            _ if refused_policies.get() > 0 => {
                rustls::Error::InvalidCertificate(rustls::CertificateError::Other(
                    rustls::OtherError(Arc::new(InvalidPolicies(refused_policies.get()))),
                ))
            }
            // Otherwise a chain Go built and dropped for a distrusted key
            // leaves Go's bare `NoValidChains` (`verify.go:653-668`),
            // whatever the candidates that made no chain met, and whether
            // or not a budget of webpki's then ran out; but a chain
            // dropped for its key usage gives Go's `IncompatibleUsage`, and
            // one that broke a name constraint Go's error for that, which
            // webpki ranks above the callback's refusal and reports.
            #[allow(deprecated)]
            _ if refused_distrusted.get()
                && !matches!(
                    err,
                    webpki::Error::RequiredEkuNotFound
                        | webpki::Error::RequiredEkuNotFoundContext(_)
                        | webpki::Error::NameConstraintViolation
                ) =>
            {
                rustls::Error::InvalidCertificate(rustls::CertificateError::Other(
                    rustls::OtherError(Arc::new(NoValidChains)),
                ))
            }
            // Go's search ended without a chain and without running out,
            // so a budget webpki ran out of is not Go's reason.
            webpki::Error::MaximumSignatureChecksExceeded
            | webpki::Error::MaximumPathBuildCallsExceeded
            | webpki::Error::MaximumNameConstraintComparisonsExceeded
                if allowed.as_ref().is_some_and(Vec::is_empty) =>
            {
                go_pki_error(webpki::Error::UnknownIssuer)
            }
            // A budget that ran out ended the search before it was done.
            webpki::Error::MaximumSignatureChecksExceeded
            | webpki::Error::MaximumPathBuildCallsExceeded
            | webpki::Error::MaximumNameConstraintComparisonsExceeded => go_pki_error(err),
            webpki::Error::UnsupportedCriticalExtension if refused_unhandled.get() => {
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnhandledCriticalExtension,
                )
            }
            err => go_pki_error(err),
        })
    }
}

/// Go's reading of the certificates a client sends, before it checks any
/// (`processCertsFromClient`, `crypto/tls/handshake_server.go:943-958`):
/// each in turn, the leaf first, is parsed ([`CertFacts::parse`], as the
/// pool's certificates are), and a certificate `ParseCertificate` refuses
/// ends the handshake, used by a chain or not, as does an RSA key of more
/// than [`GO_MAX_RSA_KEY_BITS`] in any of them, checked as each is read.
/// The refusal is rustls's bad encoding either way, with Go's words noted
/// where they are known ([`take_client_refusal`]): the parser's error for
/// a certificate refused for its key ([`go_public_key_refusal`]) and
/// Go's for the RSA limit.
fn go_read_client_certificates(
    end_entity: &rustls::pki_types::CertificateDer<'_>,
    intermediates: &[rustls::pki_types::CertificateDer<'_>],
) -> Result<(), rustls::Error> {
    let refused = || rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding);
    for cert in std::iter::once(end_entity).chain(intermediates) {
        let mut words = None;
        let Some((_, _, identity, _)) = CertFacts::parse_noting(cert.as_ref(), &mut words) else {
            note_client_refusal(words.map(ClientRefusal::Unparsable));
            return Err(refused());
        };
        if go_rsa_modulus_bits(identity.spki).is_some_and(|bits| bits > GO_MAX_RSA_KEY_BITS) {
            note_client_refusal(Some(ClientRefusal::RsaTooLarge));
            return Err(refused());
        }
    }
    Ok(())
}

/// The Go type of a client's leaf key, as `%T` prints it, when the key is
/// of none of the kinds Go's TLS takes a client's signature from, ECDSA,
/// RSA, Ed25519 and ML-DSA, which Go refuses once the chain has verified
/// and before it reads a CertificateVerify, with
/// `unsupported_certificate` (`crypto/tls/handshake_server.go:1005-1016`):
/// `*dsa.PublicKey` for a DSA key, and `<nil>` for an algorithm Go's
/// `x509` gives no key, X25519's among them; `None` otherwise, and for a
/// leaf [`CertFacts::parse`] refuses.
fn go_unsupported_leaf_key(der: &[u8]) -> Option<&'static str> {
    let (_, _, identity) = CertFacts::parse_all(der)?;
    if ClientKey::of_spki(identity.spki).is_some() {
        return None;
    }
    let oid = DerReader::new(DerReader::new(identity.spki).read_tag(0x30)?)
        .read_tag(0x30)
        .and_then(|algorithm| DerReader::new(algorithm).read_tag(0x06));
    Some(if oid == Some(DSA_KEY) {
        "*dsa.PublicKey"
    } else {
        "<nil>"
    })
}

impl rustls::server::danger::ClientCertVerifier for GoClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        self.all.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.all.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.all.root_hint_subjects()
    }

    // Go's `processCertsFromClient` (`crypto/tls/handshake_server.go:943-1016`)
    // as far as a certificate verifier sees it: every certificate read
    // (`go_read_client_certificates`), the chain verified
    // (`GoClientCertVerifier::verify_chain`), and the leaf's key held to
    // the kinds Go's TLS takes a signature from (`go_unsupported_leaf_key`).
    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        clear_client_refusal();
        go_read_client_certificates(end_entity, intermediates)?;
        let verified = self.verify_chain(end_entity, intermediates, now)?;
        if let Some(go_type) = go_unsupported_leaf_key(end_entity.as_ref()) {
            note_client_refusal(Some(ClientRefusal::UnsupportedKey(go_type)));
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::InvalidPurpose,
            ));
        }
        Ok(verified)
    }

    /// Go refuses a client whose certificate has an ML-DSA key in TLS 1.2,
    /// asking only of the leaf, after its chain checks
    /// (`crypto/tls/handshake_server.go:1005-1012`), and so does this,
    /// whatever the scheme, with `ML_DSA_CLIENT_KEY_IN_TLS12`, which
    /// rustls answers with Go's `illegal_parameter` and the RPC log gives
    /// in Go's words.  webpki alone refuses such a client too, in words of
    /// its own: an ML-DSA scheme, which names no TLS 1.2 algorithm, as one
    /// never offered, with the same alert
    /// (`rustls-0.23.46/src/webpki/verify.rs:161-163`), and any other as a
    /// scheme that does not fit the key, with `decrypt_error`.
    ///
    /// Go's TLS 1.2 server asks no more of a scheme than that its own
    /// CertificateRequest listed it (`handshake_server.go:779-782`), which
    /// rustls asks too, with the same alert and error as
    /// `CLIENT_SCHEME_REFUSED`; an ECDSA scheme is then verified with a
    /// key on any curve, as here.  A signature that fails, or whose
    /// scheme is of another kind than the key, is noted in Go's words for
    /// the handshake's error (`note_client_signature_refusal`).
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let key = ClientKey::of_leaf(cert.as_ref());
        if matches!(key, Some(ClientKey::MlDsa(_))) {
            return Err(rustls::Error::PeerMisbehaved(ML_DSA_CLIENT_KEY_IN_TLS12));
        }
        self.all
            .verify_tls12_signature(message, cert, dss)
            .inspect_err(|err| note_client_signature_refusal(err, key, dss.scheme))
    }

    /// Go's TLS 1.3 server takes a CertificateVerify only under a scheme
    /// its own list has and that fits the leaf's key, the one scheme of an
    /// ECDSA, Ed25519 or ML-DSA key (`signatureSchemesForPublicKey`,
    /// `crypto/tls/auth.go:208-255`), and refuses any other with
    /// `illegal_parameter` and `tls: client certificate used with invalid
    /// signature algorithm` before it verifies anything
    /// (`handshake_server_tls13.go:1086-1092`).  This makes the key's half
    /// of that check first (`ClientKey::fits_tls13`), refusing with
    /// `CLIENT_SCHEME_REFUSED`, which rustls answers with Go's alert and
    /// raises itself for the list's half.  webpki alone would try the
    /// scheme's algorithm on the key and refuse a misfit with
    /// `decrypt_error`.  A signature that fails is noted in Go's words for
    /// the handshake's error (`note_client_signature_refusal`).
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let key = ClientKey::of_leaf(cert.as_ref());
        if key.is_some_and(|key| !key.fits_tls13(dss.scheme)) {
            return Err(rustls::Error::PeerMisbehaved(CLIENT_SCHEME_REFUSED));
        }
        self.all
            .verify_tls13_signature(message, cert, dss)
            .inspect_err(|err| note_client_signature_refusal(err, key, dss.scheme))
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.all.supported_verify_schemes()
    }
}

/// The refusal of a TLS 1.2 client whose certificate has an ML-DSA key
/// (`GoClientCertVerifier::verify_tls12_signature`), for which rustls has
/// no error of its own.  rustls's server never raises this one, which is
/// a client's refusal of a ServerKeyExchange
/// (`rustls-0.23.46/src/client/tls12.rs:906`, `:923`), so the RPC log reads it
/// as Go's text for the refusal, and rustls sends `illegal_parameter` for
/// it, as for every `PeerMisbehaved` a verifier returns
/// (`rustls-0.23.46/src/common_state.rs:622-631`), Go's alert here.
pub(crate) const ML_DSA_CLIENT_KEY_IN_TLS12: rustls::PeerMisbehaved =
    rustls::PeerMisbehaved::SignedKxWithWrongAlgorithm;

/// The refusal of a client CertificateVerify under a scheme Go's server
/// refuses before it verifies anything: one its list lacks, in either
/// version, or, in TLS 1.3, one that does not fit the leaf's key
/// (`GoClientCertVerifier::verify_tls13_signature`).  It is the error
/// rustls's webpki functions raise for a scheme the mapping lacks or TLS
/// 1.3 forbids (`rustls-0.23.46/src/webpki/verify.rs:95-104`, `:161-163`,
/// `:198-200`), which rustls's server raises nowhere else, so the RPC log
/// reads it as Go's text for all of those, `tls: client certificate used
/// with invalid signature algorithm`, and rustls sends
/// `illegal_parameter` for it, Go's alert
/// (`rustls-0.23.46/src/common_state.rs:622-631`).
pub(crate) const CLIENT_SCHEME_REFUSED: rustls::PeerMisbehaved =
    rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme;

/// id-ecPublicKey, as DER object identifier contents.
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

/// Ed25519's key algorithm, as DER object identifier contents.
const ED25519_KEY: &[u8] = &[0x2b, 0x65, 0x70];

/// The three curves Go's `x509` gives an ECDSA key on and `crypto/tls`
/// signs a TLS 1.3 handshake with, as DER object identifier contents,
/// with each one's scheme there (`crypto/tls/auth.go:221-230`).
const ECDSA_CURVES: [(&[u8], rustls::SignatureScheme); 3] = [
    (
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
    ),
    (
        &[0x2b, 0x81, 0x04, 0x00, 0x22],
        rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
    ),
    (
        &[0x2b, 0x81, 0x04, 0x00, 0x23],
        rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
    ),
];

/// A client certificate's key as Go's `crypto/tls` sorts it when it
/// checks a CertificateVerify, read from the leaf's subject public key
/// info by its algorithm alone; the key itself is the provider's to read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClientKey {
    /// An ECDSA key, with its curve's TLS 1.3 scheme, or none for a curve
    /// Go's `crypto/tls` names no scheme for: P-224, the one such curve a
    /// leaf that parses ([`go_public_key_refusal`]) can carry, whose key Go
    /// verifies a TLS 1.2 signature with and the provider does not.
    Ecdsa(Option<rustls::SignatureScheme>),
    /// An Ed25519 key.
    Ed25519,
    /// An RSA key.
    Rsa,
    /// An ML-DSA key, with its parameter set's scheme.
    MlDsa(rustls::SignatureScheme),
}

impl ClientKey {
    /// The key of `der`, a leaf certificate, or none when the certificate
    /// does not parse or its key is of another algorithm.
    pub(crate) fn of_leaf(der: &[u8]) -> Option<ClientKey> {
        let (_, _, identity) = CertFacts::parse_all(der)?;
        ClientKey::of_spki(identity.spki)
    }

    /// The key of `spki`, a whole subject public key info element.
    fn of_spki(spki: &[u8]) -> Option<ClientKey> {
        use rustls::SignatureScheme as S;
        let mut algorithm = DerReader::new(DerReader::new(spki).read_tag(0x30)?)
            .read_tag(0x30)
            .map(DerReader::new)?;
        let oid = algorithm.read_tag(0x06)?;
        if oid == EC_PUBLIC_KEY {
            let curve = algorithm.read_tag(0x06);
            let scheme = ECDSA_CURVES
                .iter()
                .find(|&&(known, _)| Some(known) == curve)
                .map(|&(_, scheme)| scheme);
            return Some(ClientKey::Ecdsa(scheme));
        }
        if oid == ED25519_KEY {
            return Some(ClientKey::Ed25519);
        }
        if oid == RSA_ENCRYPTION {
            return Some(ClientKey::Rsa);
        }
        let sets = [S::ML_DSA_44, S::ML_DSA_65, S::ML_DSA_87];
        ML_DSA_KEYS
            .iter()
            .zip(sets)
            .find(|&(&(known, _), _)| known == oid)
            .map(|(_, scheme)| ClientKey::MlDsa(scheme))
    }

    /// Whether Go's TLS 1.3 server takes `scheme` from this key
    /// (`signatureSchemesForPublicKey`, `crypto/tls/auth.go:208-255`): an
    /// ECDSA, Ed25519 or ML-DSA key its one scheme; an RSA key every RSA
    /// scheme Go lists for its size, which for the keys the provider
    /// verifies, 2048 bits and up, is every one, PKCS#1 v1.5's included,
    /// which Go's list for TLS 1.3 then refuses, as rustls does.
    fn fits_tls13(self, scheme: rustls::SignatureScheme) -> bool {
        use rustls::SignatureScheme as S;
        match self {
            ClientKey::Ecdsa(own) => own == Some(scheme),
            ClientKey::Ed25519 => scheme == S::ED25519,
            ClientKey::MlDsa(own) => own == scheme,
            ClientKey::Rsa => matches!(
                scheme,
                S::RSA_PSS_SHA256
                    | S::RSA_PSS_SHA384
                    | S::RSA_PSS_SHA512
                    | S::RSA_PKCS1_SHA256
                    | S::RSA_PKCS1_SHA384
                    | S::RSA_PKCS1_SHA512
            ),
        }
    }

    /// The key's kind as Go's `verifyHandshakeSignature` names the kind
    /// a scheme expects (`crypto/tls/auth.go:23-78`).
    fn go_kind(self) -> &'static str {
        match self {
            ClientKey::Ecdsa(_) => "ECDSA",
            ClientKey::Ed25519 => "Ed25519",
            ClientKey::Rsa => "RSA",
            ClientKey::MlDsa(_) => "ML-DSA",
        }
    }

    /// The key's Go type as `%T` prints it.
    fn go_type(self) -> &'static str {
        match self {
            ClientKey::Ecdsa(_) => "*ecdsa.PublicKey",
            ClientKey::Ed25519 => "ed25519.PublicKey",
            ClientKey::Rsa => "*rsa.PublicKey",
            ClientKey::MlDsa(_) => "*mldsa.PublicKey",
        }
    }
}

/// Why Go's server refuses a client's certificates or its handshake
/// signature, in Go's words, where rustls's error lacks what the words
/// name: a certificate Go's `ParseCertificate` refuses for its key, or an
/// RSA key over Go's limit in any certificate sent, and a leaf whose key
/// Go's TLS takes no signature from (`processCertsFromClient`,
/// `crypto/tls/handshake_server.go:943-1016`); and, as Go's
/// `verifyHandshakeSignature` says it (`crypto/tls/auth.go:23-78`), the
/// two failures of a signature whose words do not depend on the
/// signature: a signature an ECDSA or Ed25519 key does not verify, and,
/// in TLS 1.2, where Go does not match the scheme to the key, a scheme of
/// another kind than the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientRefusal {
    /// A certificate Go fails to parse, with `ParseCertificate`'s error.
    Unparsable(&'static str),
    /// A certificate with an RSA key over [`GO_MAX_RSA_KEY_BITS`].
    RsaTooLarge,
    /// A leaf whose key is of none of the four kinds Go's TLS signs with,
    /// with the key's Go type as `%T` prints it.
    UnsupportedKey(&'static str),
    /// `ECDSA verification failure` or `Ed25519 verification failure`.
    Failed(&'static str),
    /// `expected an <kind> public key, got <type>`.
    Mismatch {
        /// The scheme's kind: `ECDSA`, `Ed25519` or `RSA`.
        expected: &'static str,
        /// The key's Go type ([`ClientKey::go_type`]).
        got: &'static str,
    },
}

thread_local! {
    /// The last client refusal noted on this thread
    /// ([`note_client_refusal`], [`note_client_signature_refusal`]).
    /// rustls calls the verifier
    /// from the `process_new_packets` that then fails, on the thread that
    /// runs the handshake, so the handshake reads it there
    /// ([`take_client_refusal`]), having cleared it when it
    /// began ([`clear_client_refusal`]).
    static CLIENT_REFUSAL: std::cell::Cell<Option<ClientRefusal>> =
        const { std::cell::Cell::new(None) };
}

/// Note in Go's words why a client's handshake signature under `scheme`
/// by `key` failed with `err`, where Go's words are known: rustls's
/// error carries the reason but not the key, which Go's words name.  A
/// signature an RSA or ML-DSA key does not verify is left to rustls's
/// words: Go gives the RSA or ML-DSA package's error there, which
/// depends on the signature.  So is a scheme of the key's own kind that
/// the provider has no algorithm for with that key, as for an ECDSA key
/// on P-224: Go's type assertion passes there and Go goes on to verify
/// (`crypto/tls/auth.go:33-40`), so `expected an ECDSA public key, got
/// *ecdsa.PublicKey` is no text Go prints, and the refusal itself is the
/// port's (PARITY.md, the clientcert entry).
fn note_client_signature_refusal(
    err: &rustls::Error,
    key: Option<ClientKey>,
    scheme: rustls::SignatureScheme,
) {
    use rustls::CertificateError as C;
    use rustls::SignatureScheme as S;
    let noted = match (err, key) {
        (rustls::Error::InvalidCertificate(C::BadSignature), Some(ClientKey::Ecdsa(_))) => {
            Some(ClientRefusal::Failed("ECDSA verification failure"))
        }
        (rustls::Error::InvalidCertificate(C::BadSignature), Some(ClientKey::Ed25519)) => {
            Some(ClientRefusal::Failed("Ed25519 verification failure"))
        }
        (
            rustls::Error::InvalidCertificate(
                C::UnsupportedSignatureAlgorithmForPublicKeyContext { .. },
            ),
            Some(key),
        ) => {
            let expected = match scheme {
                S::ECDSA_NISTP256_SHA256 | S::ECDSA_NISTP384_SHA384 | S::ECDSA_NISTP521_SHA512 => {
                    Some("ECDSA")
                }
                S::ED25519 => Some("Ed25519"),
                S::RSA_PSS_SHA256
                | S::RSA_PSS_SHA384
                | S::RSA_PSS_SHA512
                | S::RSA_PKCS1_SHA256
                | S::RSA_PKCS1_SHA384
                | S::RSA_PKCS1_SHA512 => Some("RSA"),
                _ => None,
            };
            expected
                .filter(|&expected| expected != key.go_kind())
                .map(|expected| ClientRefusal::Mismatch {
                    expected,
                    got: key.go_type(),
                })
        }
        _ => None,
    };
    note_client_refusal(noted);
}

/// Note `refusal` as the last client refusal on this thread, or, with
/// `None`, forget any noted before.
fn note_client_refusal(refusal: Option<ClientRefusal>) {
    CLIENT_REFUSAL.with(|cell| cell.set(refusal));
}

/// Forget any client refusal noted on this thread, as a handshake
/// begins.
pub(crate) fn clear_client_refusal() {
    note_client_refusal(None);
}

/// Go's text for a handshake rustls refused with `err`, when `err` is the
/// error of a client refusal this thread noted in Go's words
/// ([`ClientRefusal`]); the note is taken either way.  A certificate Go
/// fails to parse is `tls: failed to parse client certificate: ` and the
/// parser's error (`handshake_server.go:947-951`), refused with rustls's
/// bad encoding, which rustls answers with `bad_certificate`, where Go
/// sends `decode_error` (PARITY.md, the clientcert entry); an RSA key
/// over the limit is `tls: client sent certificate containing RSA key
/// larger than 8192 bits` (`:952-957`), refused the same way, Go's
/// `bad_certificate` too; a leaf of a key Go's TLS does not take is `tls:
/// client certificate contains an unsupported public key of type ` and
/// the type (`:1005-1016`), refused with rustls's invalid purpose, which
/// rustls answers with `unsupported_certificate`, Go's alert
/// (`rustls-0.23.46/src/error.rs:625-660`).  A client signature's refusal
/// is `tls: invalid signature by the client certificate: ` and the reason
/// (`handshake_server.go:796-797`, `handshake_server_tls13.go:1101-1104`),
/// which Go sends `decrypt_error` for, as rustls does for both errors it
/// is noted with.
pub(crate) fn take_client_refusal(err: &rustls::Error) -> Option<String> {
    use rustls::CertificateError as C;
    let noted = CLIENT_REFUSAL.with(std::cell::Cell::take)?;
    let rustls::Error::InvalidCertificate(err) = err else {
        return None;
    };
    let reason = match (noted, err) {
        (ClientRefusal::Unparsable(words), C::BadEncoding) => {
            return Some(format!("tls: failed to parse client certificate: {words}"));
        }
        (ClientRefusal::RsaTooLarge, C::BadEncoding) => {
            return Some(format!(
                "tls: client sent certificate containing RSA key larger than \
                 {GO_MAX_RSA_KEY_BITS} bits"
            ));
        }
        (ClientRefusal::UnsupportedKey(go_type), C::InvalidPurpose) => {
            return Some(format!(
                "tls: client certificate contains an unsupported public key of type {go_type}"
            ));
        }
        (
            ClientRefusal::Failed(reason),
            C::BadSignature | C::UnsupportedSignatureAlgorithmForPublicKeyContext { .. },
        ) => reason.to_string(),
        (
            ClientRefusal::Mismatch { expected, got },
            C::BadSignature | C::UnsupportedSignatureAlgorithmForPublicKeyContext { .. },
        ) => format!("expected an {expected} public key, got {got}"),
        _ => return None,
    };
    Some(format!(
        "tls: invalid signature by the client certificate: {reason}"
    ))
}

/// The time the client-certificate fuzz body verifies at, inside its
/// certificates' validity, 2024 through 2049.
const FUZZ_CLIENT_CERT_NOW: u64 = 1_790_000_000;

/// The client-certificate fuzz body's pool and chains, built once.  The
/// pool is one root, a self-signed ML-DSA-44 authority, and each chain,
/// one for each ML-DSA set, is an authority on that set's key, issued by
/// the root, over a leaf on the same set, issued by it.  Every key is the
/// set's key of zero bytes, which is a key (its t1 zero), and every
/// signature the set's signature that decodes with z zero and no hints
/// (`dcroxide_tlscrypto::verify::fuzz_ml_dsa_signature`), so each check
/// runs whole.  Beside them, for the handshake signature checks alone,
/// are leaves on an ECDSA key on P-256, P-384 and P-521 and on an Ed25519
/// key, issued by the root under a signature that is not checked there:
/// each ECDSA key is the curve's generator, the key of the secret scalar
/// 1, and the Ed25519 key that of the seed of 32 zero bytes.
struct FuzzClientCerts {
    verifier: GoClientCertVerifier,
    chains: Vec<FuzzClientChain>,
    handshake_leaves: Vec<Vec<u8>>,
}

/// One of [`FuzzClientCerts`]' chains, with where its leaf's signature
/// and its authority's key start in their DER.
struct FuzzClientChain {
    authority: Vec<u8>,
    authority_key_at: usize,
    leaf: Vec<u8>,
    leaf_signature_at: usize,
}

/// A DER element, its length in the fewest octets, for the fuzz body's
/// certificates, which are under 64 KiB.
fn fuzz_der(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let content = parts.concat();
    let len = content.len();
    let mut der = vec![tag];
    match (u8::try_from(len), u16::try_from(len)) {
        (Ok(short), _) if short < 0x80 => der.push(short),
        (Ok(byte), _) => der.extend([0x81, byte]),
        (_, Ok(two)) => {
            der.push(0x82);
            der.extend(two.to_be_bytes());
        }
        _ => return Vec::new(),
    }
    der.extend(content);
    der
}

impl FuzzClientCerts {
    fn new() -> Option<FuzzClientCerts> {
        // basicConstraints and keyUsage, critical, for an authority:
        // cA, and digitalSignature with keyCertSign.
        let authority_extensions = fuzz_der(
            0xa3,
            &[&fuzz_der(
                0x30,
                &[
                    &fuzz_der(
                        0x30,
                        &[
                            &fuzz_der(0x06, &[&[0x55, 0x1d, 0x13]]),
                            &fuzz_der(0x01, &[&[0xff]]),
                            &fuzz_der(0x04, &[&fuzz_der(0x30, &[&fuzz_der(0x01, &[&[0xff]])])]),
                        ],
                    ),
                    &fuzz_der(
                        0x30,
                        &[
                            &fuzz_der(0x06, &[&[0x55, 0x1d, 0x0f]]),
                            &fuzz_der(0x01, &[&[0xff]]),
                            &fuzz_der(0x04, &[&fuzz_der(0x03, &[&[0x02, 0x84]])]),
                        ],
                    ),
                ],
            )],
        );
        let algorithm = |oid: &[u8]| fuzz_der(0x30, &[&fuzz_der(0x06, &[oid])]);
        // `set`'s zero key, as a subject public key info, and its length.
        let ml_dsa_spki = |set: usize| -> Option<(Vec<u8>, usize)> {
            let (key_oid, key_len) = *ML_DSA_KEYS.get(set)?;
            let key = vec![0u8; key_len];
            let spki = fuzz_der(0x30, &[&algorithm(key_oid), &fuzz_der(0x03, &[&[0], &key])]);
            Some((spki, key_len))
        };
        // A certificate on `spki`, whose key is its last `key_len` bytes,
        // for `subject`, issued by `issuer` with `issuer_set`'s algorithm,
        // and where its key and its signature start.
        let certificate = |serial: u8,
                           subject: &[u8],
                           (spki, key_len): (Vec<u8>, usize),
                           issuer: &[u8],
                           issuer_set: usize,
                           extensions: &[u8]|
         -> Option<(Vec<u8>, usize, usize)> {
            let (signature_oid, _) = *ML_DSA_KEYS.get(issuer_set)?;
            let name = |cn: &[u8]| {
                fuzz_der(
                    0x30,
                    &[&fuzz_der(
                        0x31,
                        &[&fuzz_der(
                            0x30,
                            &[
                                &fuzz_der(0x06, &[&[0x55, 0x04, 0x03]]),
                                &fuzz_der(0x0c, &[cn]),
                            ],
                        )],
                    )],
                )
            };
            let validity = fuzz_der(
                0x30,
                &[
                    &fuzz_der(0x17, &[b"240101000000Z"]),
                    &fuzz_der(0x17, &[b"491231235959Z"]),
                ],
            );
            let tbs = fuzz_der(
                0x30,
                &[
                    &fuzz_der(0xa0, &[&fuzz_der(0x02, &[&[2]])]),
                    &fuzz_der(0x02, &[&[serial]]),
                    &algorithm(signature_oid),
                    &name(issuer),
                    &validity,
                    &name(subject),
                    &spki,
                    extensions,
                ],
            );
            let signature = dcroxide_tlscrypto::verify::fuzz_ml_dsa_signature(issuer_set, &[]);
            let der = fuzz_der(
                0x30,
                &[
                    &tbs,
                    &algorithm(signature_oid),
                    &fuzz_der(0x03, &[&[0], &signature]),
                ],
            );
            let key_at = der.windows(spki.len()).position(|w| w == spki)?;
            let key_at = key_at.checked_add(spki.len())?.checked_sub(key_len)?;
            let signature_at = der.len().checked_sub(signature.len())?;
            Some((der, key_at, signature_at))
        };
        let (root, _, _) = certificate(
            1,
            b"root",
            ml_dsa_spki(0)?,
            b"root",
            0,
            &authority_extensions,
        )?;
        let verifier = GoClientCertVerifier::from_certificates(vec![root]).ok()?;
        let mut chains = Vec::new();
        for (set, serial) in [(0usize, 2u8), (1, 4), (2, 6)] {
            let (authority, authority_key_at, _) = certificate(
                serial,
                b"authority",
                ml_dsa_spki(set)?,
                b"root",
                0,
                &authority_extensions,
            )?;
            let (leaf, _, leaf_signature_at) = certificate(
                serial.checked_add(1)?,
                b"leaf",
                ml_dsa_spki(set)?,
                b"authority",
                set,
                &[],
            )?;
            chains.push(FuzzClientChain {
                authority,
                authority_key_at,
                leaf,
                leaf_signature_at,
            });
        }
        // The handshake leaves' keys, from PKCS#8 keys of the secret
        // scalar 1 on each curve and of the zero Ed25519 seed, as the
        // provider gives their subject public key infos.
        let ecdsa_pkcs8 = |curve: &[u8], width: usize| {
            let mut scalar = vec![0u8; width];
            if let Some(last) = scalar.last_mut() {
                *last = 1;
            }
            fuzz_der(
                0x30,
                &[
                    &fuzz_der(0x02, &[&[0]]),
                    &fuzz_der(
                        0x30,
                        &[&fuzz_der(0x06, &[EC_PUBLIC_KEY]), &fuzz_der(0x06, &[curve])],
                    ),
                    &fuzz_der(
                        0x04,
                        &[&fuzz_der(
                            0x30,
                            &[&fuzz_der(0x02, &[&[1]]), &fuzz_der(0x04, &[&scalar])],
                        )],
                    ),
                ],
            )
        };
        let ed25519_pkcs8 = fuzz_der(
            0x30,
            &[
                &fuzz_der(0x02, &[&[0]]),
                &algorithm(ED25519_KEY),
                &fuzz_der(0x04, &[&fuzz_der(0x04, &[&[0u8; 32]])]),
            ],
        );
        let mut handshake_leaves = Vec::new();
        for (serial, pkcs8) in [
            (8u8, ecdsa_pkcs8(ECDSA_CURVES[0].0, 32)),
            (9, ecdsa_pkcs8(ECDSA_CURVES[1].0, 48)),
            (10, ecdsa_pkcs8(ECDSA_CURVES[2].0, 66)),
            (11, ed25519_pkcs8),
        ] {
            let spki = dcroxide_tlscrypto::sign::load_der(&pkcs8)
                .ok()?
                .public_key()?
                .as_ref()
                .to_vec();
            let (leaf, _, _) = certificate(serial, b"leaf", (spki, 0), b"root", 0, &[])?;
            handshake_leaves.push(leaf);
        }
        Some(FuzzClientCerts {
            verifier,
            chains,
            handshake_leaves,
        })
    }
}

/// Signature schemes the client-certificate fuzz body's handshake
/// signatures name beside the listener's: SHA-1's two, which Go's list
/// leaves out, Ed448, which neither side verifies, and a code point no
/// scheme has.
const FUZZ_REFUSED_SCHEMES: [rustls::SignatureScheme; 4] = [
    rustls::SignatureScheme::ECDSA_SHA1_Legacy,
    rustls::SignatureScheme::RSA_PKCS1_SHA1,
    rustls::SignatureScheme::ED448,
    rustls::SignatureScheme::Unknown(0x0a0a),
];

/// `bytes` laid over `template` from `at`, cut where `template` ends.
fn fuzz_lay(template: &[u8], at: usize, bytes: &[u8]) -> Vec<u8> {
    let mut laid = template.to_vec();
    if let Some(tail) = laid.get_mut(at..) {
        for (to, from) in tail.iter_mut().zip(bytes) {
            *to = *from;
        }
    }
    laid
}

/// The body of the `rpc_client_cert` fuzz target: what the RPC listener
/// does with a client's certificates and its handshake signature under
/// `--authtype=clientcert` before the client is authenticated
/// ([`GoClientCertVerifier`]: the reader every certificate goes through,
/// the replay of Go's chain search, webpki's search, and the handshake
/// signature checks), over a pool of one ML-DSA-44 root
/// ([`FuzzClientCerts`]).  Whether the client was accepted, which a key of
/// zero bytes allows, since anyone can sign for it.
///
/// The first byte picks one of the three ML-DSA sets, by its value modulo
/// three, and one of four uses for the rest, by its value divided by three,
/// modulo four:
///
/// - 0: the client's certificates, each a two-byte big-endian length and
///   that many bytes, the leaf first;
/// - 1: the set's chain, with the rest laid over its leaf's signature, so
///   that the signature reaches the authority's key's checks, in the replay
///   and in webpki's search;
/// - 2: the set's chain, with the rest laid over its authority's key, so
///   that the leaf's signature is checked with that key;
/// - 3: a handshake signature by a leaf, the set's when the first byte
///   divided by twelve is 0 modulo five and otherwise the P-256, P-384,
///   P-521 or Ed25519 handshake leaf, for 1 to 4; its scheme the one the
///   rest's first byte picks, modulo their number, of the listener's list
///   followed by four schemes the listener refuses (SHA-1's two, Ed448
///   and a code point no scheme has); and its signature what follows,
///   laid over the set's signature when the scheme is ML-DSA, checked as
///   TLS 1.3 and as TLS 1.2 check it, so that the key's fit to the
///   scheme, the ECDSA and Ed25519 signature decoders and verifiers, and
///   the notes of a refusal in Go's words all run.
///
/// For the `rpc_client_cert` fuzz target only; not part of the API.
#[doc(hidden)]
pub fn fuzz_client_cert(data: &[u8]) -> bool {
    // `DigitallySignedStruct` has no public constructor, so mode 3 decodes
    // one with rustls's hidden `internal` codec, which is outside rustls's
    // stable interface: a rustls update may need to touch this (the
    // dependency ledger's rustls row).
    use rustls::internal::msgs::codec::{Codec, Reader};
    use rustls::pki_types::CertificateDer;
    use rustls::server::danger::ClientCertVerifier;
    static FIXTURE: std::sync::OnceLock<Option<FuzzClientCerts>> = std::sync::OnceLock::new();
    let Some(fixture) = FIXTURE.get_or_init(FuzzClientCerts::new).as_ref() else {
        return false;
    };
    let Some((&pick, rest)) = data.split_first() else {
        return false;
    };
    let Some(chain) = fixture.chains.get(usize::from(pick % 3)) else {
        return false;
    };
    let now = rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(
        FUZZ_CLIENT_CERT_NOW,
    ));
    let verify = |leaf: &[u8], sent: &[&[u8]]| {
        let sent: Vec<CertificateDer<'_>> =
            sent.iter().map(|der| CertificateDer::from(*der)).collect();
        fixture
            .verifier
            .verify_client_cert(&CertificateDer::from(leaf), &sent, now)
            .is_ok()
    };
    match (pick / 3) % 4 {
        0 => {
            let mut certs: Vec<&[u8]> = Vec::new();
            let mut rest = rest;
            while let Some((len, tail)) = rest.split_first_chunk::<2>() {
                let (cert, tail) =
                    tail.split_at(usize::from(u16::from_be_bytes(*len)).min(tail.len()));
                certs.push(cert);
                rest = tail;
            }
            match certs.split_first() {
                Some((leaf, sent)) => verify(leaf, sent),
                None => false,
            }
        }
        1 => verify(
            &fuzz_lay(&chain.leaf, chain.leaf_signature_at, rest),
            &[&chain.authority],
        ),
        2 => {
            let authority = fuzz_lay(&chain.authority, chain.authority_key_at, rest);
            verify(&chain.leaf, &[&authority])
        }
        _ => {
            let Some((&scheme_pick, signature)) = rest.split_first() else {
                return false;
            };
            let schemes: Vec<rustls::SignatureScheme> = dcroxide_tlscrypto::RPC_SIG_ALGS
                .mapping
                .iter()
                .map(|&(scheme, _)| scheme)
                .chain(FUZZ_REFUSED_SCHEMES)
                .collect();
            let Some(&scheme) = usize::from(scheme_pick)
                .checked_rem(schemes.len())
                .and_then(|at| schemes.get(at))
            else {
                return false;
            };
            let set = [
                rustls::SignatureScheme::ML_DSA_44,
                rustls::SignatureScheme::ML_DSA_65,
                rustls::SignatureScheme::ML_DSA_87,
            ]
            .iter()
            .position(|&ml_dsa| ml_dsa == scheme);
            let signature = match set {
                Some(set) => dcroxide_tlscrypto::verify::fuzz_ml_dsa_signature(set, signature),
                None => signature.to_vec(),
            };
            let Ok(len) = u16::try_from(signature.len()) else {
                return false;
            };
            let encoded = [
                &u16::from(scheme).to_be_bytes()[..],
                &len.to_be_bytes(),
                &signature,
            ]
            .concat();
            let Ok(dss) = rustls::DigitallySignedStruct::read(&mut Reader::init(&encoded)) else {
                return false;
            };
            // The rest of the first byte picks the signing leaf: the set's,
            // or one of the handshake leaves.
            let leaf = match usize::from(pick / 12) % 5 {
                0 => chain.leaf.as_slice(),
                at => match fixture.handshake_leaves.get(at.saturating_sub(1)) {
                    Some(leaf) => leaf.as_slice(),
                    None => return false,
                },
            };
            let leaf = CertificateDer::from(leaf);
            let message = b"the client's handshake transcript";
            let tls13 = fixture
                .verifier
                .verify_tls13_signature(message, &leaf, &dss)
                .is_ok();
            let tls12 = fixture
                .verifier
                .verify_tls12_signature(message, &leaf, &dss)
                .is_ok();
            tls13 || tls12
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// The four curves Go 1.27.3's `x509` gives an ECDSA key on
    /// (`namedCurveFromOID`, `crypto/x509/x509.go:583-595`), P-224, P-256,
    /// P-384 and P-521, as DER object identifier contents.
    const GO_X509_CURVES: [&[u8]; 4] = [
        &[0x2b, 0x81, 0x04, 0x00, 0x21],
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        &[0x2b, 0x81, 0x04, 0x00, 0x22],
        &[0x2b, 0x81, 0x04, 0x00, 0x23],
    ];

    /// cryptobyte's UTCTime and GeneralizedTime readers, as Go's
    /// certificate parser reads the validity window.  Every row is Go
    /// 1.27's `ParseCertificate` over a certificate with that notAfter,
    /// whose time readers go1.27.3, the reference Go, and 1.26.2 share: a
    /// fraction of a second is refused in either form, and a zone hour of
    /// 24 is accepted.
    #[test]
    fn asn1_times_parse_as_go_reads_them() {
        let cases: [(u8, &str, Option<i64>); 21] = [
            (0x17, "491231235959Z", Some(2_524_607_999)),
            (0x17, "500101000000Z", Some(-631_152_000)),
            (0x17, "4912312359Z", Some(2_524_607_940)),
            (0x17, "491231235959+0100", Some(2_524_604_399)),
            (0x17, "491231235959-0130", Some(2_524_613_399)),
            (0x17, "491231235959+0000", None),
            (0x17, "491231235959-0000", None),
            (0x17, "491231235959+2400", Some(2_524_521_599)),
            (0x17, "491231235959-2459", Some(2_524_697_939)),
            (0x17, "491231235959+2500", None),
            (0x17, "491231235959+0060", None),
            (0x17, "491231235959.5Z", None),
            (0x17, "491331235959Z", None),
            (0x18, "20500101000000Z", Some(2_524_608_000)),
            (0x18, "20500101000000.5Z", None),
            (0x18, "20500101000000,5Z", None),
            (0x18, "20500101000000.50Z", None),
            (0x18, "20500101000000+2430", Some(2_524_519_800)),
            (0x18, "20240229120000Z", Some(1_709_208_000)),
            (0x18, "20230229120000Z", None),
            (0x18, "205001010000Z", None),
        ];
        for (tag, text, want) in cases {
            assert_eq!(parse_asn1_time(tag, text.as_bytes()), want, "{text}");
        }
    }

    /// A DER element: tag, definite length, content.
    fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match content.len() {
            len @ 0..0x80 => out.push(len as u8),
            len @ 0x80..0x100 => out.extend([0x81, len as u8]),
            len => out.extend([0x82, (len >> 8) as u8, len as u8]),
        }
        out.extend_from_slice(content);
        out
    }

    /// An X.509 extension element.
    fn der_extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
        let mut ext = der_tlv(0x06, oid);
        if critical {
            ext.extend(der_tlv(0x01, &[0xff]));
        }
        ext.extend(der_tlv(0x04, value));
        der_tlv(0x30, &ext)
    }

    /// A certificate skeleton carrying the given version and extensions
    /// (the fact reader checks no signature), its key an X25519 key, an
    /// algorithm Go's `x509` parses without reading the key.
    fn der_certificate(version: Option<u8>, extensions: &[Vec<u8>]) -> Vec<u8> {
        der_certificate_until(version, der_tlv(0x18, b"20500101000000Z"), extensions)
    }

    /// [`der_certificate`] with the given notAfter element.
    fn der_certificate_until(
        version: Option<u8>,
        not_after: Vec<u8>,
        extensions: &[Vec<u8>],
    ) -> Vec<u8> {
        // ecdsa-with-SHA256, an identifier Go's `parseAI` reads.
        let algorithm = der_tlv(
            0x30,
            &der_tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]),
        );
        let mut tbs = Vec::new();
        if let Some(version) = version {
            tbs.extend(der_tlv(0xa0, &der_tlv(0x02, &[version])));
        }
        tbs.extend(der_tlv(0x02, &[1]));
        tbs.extend(algorithm.clone());
        tbs.extend(der_tlv(0x30, &[]));
        tbs.extend(der_tlv(
            0x30,
            &[der_tlv(0x17, b"240101000000Z"), not_after].concat(),
        ));
        tbs.extend(der_tlv(0x30, &[]));
        tbs.extend(der_tlv(
            0x30,
            &[
                der_tlv(0x30, &der_tlv(0x06, &[0x2b, 0x65, 0x6e])),
                der_tlv(0x03, &[0u8; 33]),
            ]
            .concat(),
        ));
        if !extensions.is_empty() {
            tbs.extend(der_tlv(0xa3, &der_tlv(0x30, &extensions.concat())));
        }
        der_tlv(
            0x30,
            &[der_tlv(0x30, &tbs), algorithm, der_tlv(0x03, &[0])].concat(),
        )
    }

    /// The facts Go's parser and verifier read from a certificate: its
    /// validity, which critical extensions it leaves unhandled
    /// (`processExtensions`), whether its extended key usage admits
    /// client authentication (`checkChainForKeyUsage`), and its path
    /// length constraint (`parseBasicConstraintsExtension`).
    #[test]
    fn certificate_facts_follow_gos_parser() {
        const UNKNOWN: &[u8] = &[0x2a, 0x03, 0x04];
        const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
        const UNKNOWN_CE: &[u8] = &[0x55, 0x1d, 0x63];
        const SAN: &[u8] = &[0x55, 0x1d, 0x11];
        const NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];
        const EKU: &[u8] = &[0x55, 0x1d, 0x25];
        let eku = |usages: &[&[u8]]| {
            der_tlv(
                0x30,
                &usages
                    .iter()
                    .flat_map(|usage| der_tlv(0x06, usage))
                    .collect::<Vec<_>>(),
            )
        };
        let server_auth: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
        let client_auth: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
        let any: &[u8] = &[0x55, 0x1d, 0x25, 0x00];
        let facts = |extensions: &[Vec<u8>]| {
            CertFacts::parse(&der_certificate(Some(2), extensions)).expect("facts")
        };

        let plain = facts(&[]);
        assert_eq!(
            plain,
            CertFacts {
                not_before: 1_704_067_200,
                not_after: 2_524_608_000,
                unhandled_critical: false,
                client_auth: true,
                max_path_len: None,
                version: 3,
                basic_constraints: false,
                is_ca: false,
                key_usage: 0,
                name_constraints: false,
            }
        );

        // Critical extensions Go does not handle, and ones it does.
        assert!(facts(&[der_extension(UNKNOWN, true, &[0x05, 0x00])]).unhandled_critical);
        assert!(!facts(&[der_extension(UNKNOWN, false, &[0x05, 0x00])]).unhandled_critical);
        assert!(facts(&[der_extension(UNKNOWN_CE, true, &[0x05, 0x00])]).unhandled_critical);
        assert!(
            !facts(&[der_extension(
                KEY_USAGE,
                true,
                &der_tlv(0x03, &[0x07, 0x80])
            )])
            .unhandled_critical
        );
        // A subject alternative name with no name Go collects, and one
        // with a DNS name.
        let other_name = der_tlv(0x30, &der_tlv(0xa0, &[0x06, 0x01, 0x2a]));
        assert!(facts(&[der_extension(SAN, true, &other_name)]).unhandled_critical);
        let dns = der_tlv(0x30, &der_tlv(0x82, b"example.com"));
        assert!(!facts(&[der_extension(SAN, true, &dns)]).unhandled_critical);
        // Name constraints over a directory name, and over a DNS name.
        let subtrees = |base: Vec<u8>| der_tlv(0x30, &der_tlv(0xa0, &der_tlv(0x30, &base)));
        assert!(
            facts(&[der_extension(
                NAME_CONSTRAINTS,
                true,
                &subtrees(der_tlv(0xa4, &der_tlv(0x30, &[])))
            )])
            .unhandled_critical
        );
        assert!(
            !facts(&[der_extension(
                NAME_CONSTRAINTS,
                true,
                &subtrees(der_tlv(0x82, b"example.com"))
            )])
            .unhandled_critical
        );

        // Extended key usage.
        for (usages, want) in [
            (vec![], true),
            (vec![client_auth], true),
            (vec![any], true),
            (vec![server_auth, client_auth], true),
            (vec![server_auth], false),
            (vec![UNKNOWN], false),
        ] {
            assert_eq!(
                facts(&[der_extension(EKU, false, &eku(&usages))]).client_auth,
                want,
                "{usages:?}"
            );
        }

        // The basic constraints' path length, read as Go reads it (the same
        // in 1.26.2, 1.27.1 and 1.27.3): absent is no constraint, and a
        // negative or non-minimal integer fails the parse.
        const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
        let constraints = |content: &[u8]| {
            CertFacts::parse(&der_certificate(
                Some(2),
                &[der_extension(
                    BASIC_CONSTRAINTS,
                    true,
                    &der_tlv(0x30, content),
                )],
            ))
        };
        let ca = der_tlv(0x01, &[0xff]);
        for (content, want) in [
            (Vec::new(), Some(None)),
            (ca.clone(), Some(None)),
            ([ca.clone(), der_tlv(0x02, &[0])].concat(), Some(Some(0))),
            ([ca.clone(), der_tlv(0x02, &[2])].concat(), Some(Some(2))),
            (der_tlv(0x02, &[0x00, 0x80]), Some(Some(128))),
            ([ca.clone(), der_tlv(0x02, &[0xff])].concat(), None),
            ([ca.clone(), der_tlv(0x02, &[0x00, 0x01])].concat(), None),
            ([ca, der_tlv(0x02, &[])].concat(), None),
        ] {
            let got = constraints(&content).map(|facts| facts.max_path_len);
            assert_eq!(got, want, "{content:02x?}");
            if let Some(facts) = constraints(&content) {
                assert!(!facts.unhandled_critical, "{content:02x?}");
            }
        }

        // Go reads no extensions from a v1 or v2 certificate.
        for version in [None, Some(1)] {
            let facts = CertFacts::parse(&der_certificate(
                version,
                &[der_extension(UNKNOWN, true, &[0x05, 0x00])],
            ))
            .expect("facts");
            assert!(!facts.unhandled_critical, "{version:?}");
        }

        // What Go's parser refuses outright, so that the client CA file
        // skips it, each checked against Go 1.27's `ParseCertificate`,
        // whose code for these go1.27.3, the reference Go, and 1.26.2
        // share: a fractional validity time, a key identifier or authority
        // information access marked critical, an extension twice, a
        // critical flag or cA boolean that is not a DER BOOLEAN, and an
        // OID cryptobyte does not read.
        let parses = |extensions: &[Vec<u8>]| {
            CertFacts::parse(&der_certificate(Some(2), extensions)).is_some()
        };
        let fractional = der_tlv(0x18, b"20500101000000.5Z");
        assert_eq!(
            CertFacts::parse(&der_certificate_until(Some(2), fractional, &[])),
            None
        );
        const SKI: &[u8] = &[0x55, 0x1d, 0x0e];
        const AKI: &[u8] = &[0x55, 0x1d, 0x23];
        const AIA: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];
        const OCSP: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
        let access = [der_tlv(0x06, OCSP), der_tlv(0x86, b"http://x/")].concat();
        for (oid, value) in [
            (SKI, der_tlv(0x04, &[1, 2, 3])),
            (AKI, der_tlv(0x30, &der_tlv(0x80, &[1, 2, 3]))),
            (AIA, der_tlv(0x30, &der_tlv(0x30, &access))),
        ] {
            assert!(parses(&[der_extension(oid, false, &value)]), "{oid:02x?}");
            assert!(!parses(&[der_extension(oid, true, &value)]), "{oid:02x?}");
        }
        let unknown = der_extension(UNKNOWN, false, &[0x05, 0x00]);
        assert!(!parses(&[unknown.clone(), unknown]));
        let client_eku = der_extension(EKU, false, &eku(&[client_auth]));
        assert!(!parses(&[client_eku.clone(), client_eku]));
        let flagged = |flag: &[u8]| {
            let extension = [
                der_tlv(0x06, UNKNOWN),
                der_tlv(0x01, flag),
                der_tlv(0x04, &[0x05, 0x00]),
            ];
            CertFacts::parse(&der_certificate(
                Some(2),
                &[der_tlv(0x30, &extension.concat())],
            ))
            .map(|facts| facts.unhandled_critical)
        };
        assert_eq!(flagged(&[0x00]), Some(false));
        assert_eq!(flagged(&[0xff]), Some(true));
        for flag in [&[0x01][..], &[], &[0xff, 0xff]] {
            assert_eq!(flagged(flag), None, "{flag:02x?}");
        }
        for (flag, want) in [(0x00, Some(None)), (0xff, Some(None)), (0x01, None)] {
            assert_eq!(
                constraints(&der_tlv(0x01, &[flag])).map(|facts| facts.max_path_len),
                want,
                "cA {flag:02x}"
            );
        }
        for (oid, want) in [
            (&[][..], false),
            (&[0x80, 0x01], false),
            (&[0x2a, 0x80, 0x01], false),
            (&[0x2a, 0x83], false),
            // 2^31, and a subidentifier of six bytes.
            (&[0x2a, 0x88, 0x80, 0x80, 0x80, 0x00], false),
            (&[0x2a, 0x81, 0x80, 0x80, 0x80, 0x80, 0x00], false),
            // 2^31 - 1, and 2^28 in five bytes.
            (&[0x2a, 0x87, 0xff, 0xff, 0xff, 0x7f], true),
            (&[0x2a, 0x81, 0x80, 0x80, 0x80, 0x00], true),
        ] {
            assert_eq!(
                parses(&[der_extension(oid, false, &[0x05, 0x00])]),
                want,
                "{oid:02x?}"
            );
            assert_eq!(
                parses(&[der_extension(EKU, false, &eku(&[oid]))]),
                want,
                "EKU {oid:02x?}"
            );
        }
    }

    /// The `gencerts` environment for generated test certificates.
    struct GenTestEnv {
        now: i64,
        serial: u8,
    }

    impl dcroxide_certgen::gentool::GenEnv for GenTestEnv {
        fn now_unix(&mut self) -> i64 {
            self.now
        }

        fn serial_bytes(&mut self) -> Vec<u8> {
            self.serial = self.serial.wrapping_add(1);
            vec![self.serial]
        }
    }

    /// A `gencerts`-default self-signed authority valid for `years`
    /// from `now`, as PEM and DER, with its key.
    fn gencerts_authority(
        now: i64,
        years: i64,
    ) -> (
        dcroxide_certgen::gentool::GenCert,
        dcroxide_certgen::gentool::ToolKeyPair,
    ) {
        use dcroxide_certgen::gentool;
        let key = gentool::generate_key("P-256").expect("key");
        let cert = gentool::generate_authority(
            &mut GenTestEnv { now, serial: 0 },
            &key,
            &[],
            "gencerts",
            years,
            true,
        )
        .expect("authority");
        (cert, key)
    }

    /// A client certificate issued at `now` by the given authority,
    /// valid past the authority's own validity.
    fn gencerts_issued(
        now: i64,
        ca: &dcroxide_certgen::gentool::GenCert,
        ca_key: &dcroxide_certgen::gentool::ToolKeyPair,
    ) -> Vec<u8> {
        use dcroxide_certgen::gentool;
        let key_pem = gentool::pem_private_key(&ca_key.marshal_pkcs8().expect("pkcs8"));
        let (mut loaded, ca_key) = gentool::load_ca_pair(&ca.pem, &key_pem).expect("ca pair");
        // gencerts clamps an issued certificate to its parent's
        // validity; OpenSSL does not, which is the case pinned here.
        loaded.not_after_unix = 2_524_607_999;
        let key = gentool::generate_key("P-256").expect("key");
        gentool::create_issued_cert(
            &mut GenTestEnv { now, serial: 100 },
            &key,
            &loaded,
            &ca_key,
            &[],
            "client",
            5,
            false,
        )
        .expect("issued")
        .der
    }

    /// Verify a client chain at `now` against a client CA file.
    fn verify_client_at(
        cas_pem: &[u8],
        leaf: &[u8],
        now: i64,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        use rustls::server::danger::ClientCertVerifier;
        let verifier = GoClientCertVerifier::from_pem(cas_pem).expect("verifier");
        verifier.verify_client_cert(
            &rustls::pki_types::CertificateDer::from(leaf),
            &[],
            rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(now as u64)),
        )
    }

    /// A certificate presented from the pool is its own chain, as Go's
    /// `opts.Roots.contains(c)` makes it (review finding GAP06#1): the
    /// self-signed CA certificate `gencerts` writes by default is
    /// accepted inside its validity window, though webpki refuses a CA
    /// as an end entity, and refused outside it.
    #[test]
    fn a_pool_certificate_is_its_own_chain() {
        let now = 1_790_000_000;
        let (ca, _) = gencerts_authority(now, 1);
        verify_client_at(&ca.pem, &ca.der, now).expect("a pooled CA certificate authenticates");
        assert!(matches!(
            verify_client_at(&ca.pem, &ca.der, now - 3 * 86_400),
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidYet
            ))
        ));
        assert!(matches!(
            verify_client_at(&ca.pem, &ca.der, now + 2 * 365 * 86_400),
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Expired
            ))
        ));

        // webpki alone refuses the same certificate, which is what the
        // listener used to hand the handshake to.
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(ca.der.as_slice()))
            .expect("root");
        let webpki = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(dcroxide_tlscrypto::default_provider()),
        )
        .build()
        .expect("webpki verifier");
        assert!(
            webpki
                .verify_client_cert(
                    &rustls::pki_types::CertificateDer::from(ca.der.as_slice()),
                    &[],
                    rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(now as u64)),
                )
                .is_err()
        );
    }

    /// Only a root Go's `isValid(rootCertificate)` accepts now may anchor
    /// a client chain (review finding GAP06#2): a leaf inside its own
    /// validity that chains to an expired or not yet valid authority
    /// is refused, and the same leaf under a valid authority is not.
    #[test]
    fn a_root_outside_its_validity_anchors_no_chain() {
        let now = 1_790_000_000;
        let year = 365 * 86_400;

        let (valid, valid_key) = gencerts_authority(now - year, 3);
        let leaf = gencerts_issued(now, &valid, &valid_key);
        verify_client_at(&valid.pem, &leaf, now).expect("a valid root anchors the chain");

        let (expired, expired_key) = gencerts_authority(now - 3 * year, 1);
        let leaf = gencerts_issued(now, &expired, &expired_key);
        assert!(verify_client_at(&expired.pem, &leaf, now).is_err());
        // Alongside a valid but unrelated root, the expired one still
        // anchors nothing.
        let both = [valid.pem.as_slice(), expired.pem.as_slice()].concat();
        assert!(verify_client_at(&both, &leaf, now).is_err());

        let (future, future_key) = gencerts_authority(now + year, 1);
        let leaf = gencerts_issued(now, &future, &future_key);
        assert!(verify_client_at(&future.pem, &leaf, now).is_err());
    }

    /// A P-256 certificate for `subject` over `subject_key`, issued by
    /// `issuer` and signed with `issuer_key` (ecdsa-with-SHA256), valid
    /// from 2024 through 2049 and carrying `extensions`: the chain
    /// shapes gencerts does not make.
    fn signed_p256_certificate(
        serial: u8,
        subject: &str,
        subject_key: &dcroxide_certgen::gentool::ToolKeyPair,
        issuer: &str,
        issuer_key: &dcroxide_certgen::gentool::ToolKeyPair,
        extensions: &[Vec<u8>],
    ) -> Vec<u8> {
        signed_p256_certificate_until(
            serial,
            subject,
            subject_key,
            issuer,
            issuer_key,
            der_tlv(0x17, b"491231235959Z"),
            extensions,
        )
    }

    /// [`signed_p256_certificate`] with the given notAfter element.
    fn signed_p256_certificate_until(
        serial: u8,
        subject: &str,
        subject_key: &dcroxide_certgen::gentool::ToolKeyPair,
        issuer: &str,
        issuer_key: &dcroxide_certgen::gentool::ToolKeyPair,
        not_after: Vec<u8>,
        extensions: &[Vec<u8>],
    ) -> Vec<u8> {
        // id-ecPublicKey and prime256v1.
        const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
        const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
        let spki = der_tlv(
            0x30,
            &[
                der_tlv(
                    0x30,
                    &[der_tlv(0x06, EC_PUBLIC_KEY), der_tlv(0x06, P256)].concat(),
                ),
                der_tlv(0x03, &[&[0u8][..], &subject_key.public_bytes()].concat()),
            ]
            .concat(),
        );
        signed_certificate_with_spki(
            serial, subject, spki, issuer, issuer_key, not_after, extensions,
        )
    }

    /// A certificate for the subject public key info `spki`, signed with
    /// ECDSA P-256 by `issuer_key`.
    fn signed_certificate_with_spki(
        serial: u8,
        subject: &str,
        spki: Vec<u8>,
        issuer: &str,
        issuer_key: &dcroxide_certgen::gentool::ToolKeyPair,
        not_after: Vec<u8>,
        extensions: &[Vec<u8>],
    ) -> Vec<u8> {
        // ecdsa-with-SHA256 and commonName.
        const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
        const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
        let name = |cn: &str| {
            let attribute = [der_tlv(0x06, COMMON_NAME), der_tlv(0x0c, cn.as_bytes())].concat();
            der_tlv(0x30, &der_tlv(0x31, &der_tlv(0x30, &attribute)))
        };
        let algorithm = der_tlv(0x30, &der_tlv(0x06, ECDSA_SHA256));
        let validity = [der_tlv(0x17, b"240101000000Z"), not_after].concat();
        let tbs = der_tlv(
            0x30,
            &[
                der_tlv(0xa0, &der_tlv(0x02, &[2])),
                der_tlv(0x02, &[serial]),
                algorithm.clone(),
                name(issuer),
                der_tlv(0x30, &validity),
                name(subject),
                spki,
                der_tlv(0xa3, &der_tlv(0x30, &extensions.concat())),
            ]
            .concat(),
        );
        // A TLS ECDSA signature is the same DER `ECDSA-Sig-Value` an
        // X.509 signature carries.
        let key = issuer_key.marshal_pkcs8().expect("pkcs8");
        let signature = dcroxide_tlscrypto::sign::load_der(&key)
            .expect("signing key")
            .choose_scheme(&[rustls::SignatureScheme::ECDSA_NISTP256_SHA256])
            .expect("scheme")
            .sign(&tbs)
            .expect("sign");
        der_tlv(
            0x30,
            &[
                tbs,
                algorithm,
                der_tlv(0x03, &[&[0u8][..], &signature].concat()),
            ]
            .concat(),
        )
    }

    /// A DER certificate as a PEM block.
    fn certificate_pem(der: &[u8]) -> Vec<u8> {
        String::from_utf8(dcroxide_certgen::gentool::pem_private_key(der))
            .expect("pem")
            .replace("PRIVATE KEY", "CERTIFICATE")
            .into_bytes()
    }

    /// The rest of Go's `isValid(rootCertificate)`, and the root's own
    /// place in `checkChainForKeyUsage`, bound the chains a root anchors
    /// (review finding GAP06#2), where webpki's trust anchors keep none
    /// of it: a `pathlen:0` root anchors a leaf it signs but not one
    /// under an intermediate, however many intermediates the client
    /// sends; a `pathlen:1` root anchors a chain through one of several
    /// sent; and a root with a server-only extended key usage or an
    /// unknown critical extension anchors nothing.
    #[test]
    fn a_roots_constraints_bound_the_chains_it_anchors() {
        use dcroxide_certgen::gentool::generate_key;
        use rustls::server::danger::ClientCertVerifier;
        const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
        const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
        const EKU: &[u8] = &[0x55, 0x1d, 0x25];
        const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
        const CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
        let now = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(1_790_000_000));
        let key = || generate_key("P-256").expect("key");
        let (root_key, int_key, other_key, leaf_key, direct_key) =
            (key(), key(), key(), key(), key());

        // An authority's extensions: CA, with the given path length,
        // allowed to sign certificates.
        let authority = |path_len: Option<u8>| {
            let mut constraints = der_tlv(0x01, &[0xff]);
            if let Some(path_len) = path_len {
                constraints.extend(der_tlv(0x02, &[path_len]));
            }
            vec![
                der_extension(BASIC_CONSTRAINTS, true, &der_tlv(0x30, &constraints)),
                der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x02, 0x84])),
            ]
        };
        let eku = |usage: &[u8]| der_extension(EKU, false, &der_tlv(0x30, &der_tlv(0x06, usage)));
        let leaf_extensions = [der_extension(
            KEY_USAGE,
            true,
            &der_tlv(0x03, &[0x07, 0x80]),
        )];

        let intermediate =
            signed_p256_certificate(2, "int", &int_key, "root", &root_key, &authority(None));
        let other =
            signed_p256_certificate(3, "other", &other_key, "root", &root_key, &authority(None));
        let leaf = signed_p256_certificate(4, "leaf", &leaf_key, "int", &int_key, &leaf_extensions);
        let direct = signed_p256_certificate(
            5,
            "direct",
            &direct_key,
            "root",
            &root_key,
            &leaf_extensions,
        );
        let verify = |root_extensions: &[Vec<u8>], end_entity: &[u8], sent: &[&[u8]]| {
            let root =
                signed_p256_certificate(1, "root", &root_key, "root", &root_key, root_extensions);
            let verifier =
                GoClientCertVerifier::from_pem(&certificate_pem(&root)).expect("verifier");
            let sent: Vec<_> = sent
                .iter()
                .map(|der| rustls::pki_types::CertificateDer::from(*der))
                .collect();
            verifier
                .verify_client_cert(
                    &rustls::pki_types::CertificateDer::from(end_entity),
                    &sent,
                    now,
                )
                .is_ok()
        };

        // The path length constraint counts the chain's intermediates.
        for (path_len, through_one) in [(None, true), (Some(1), true), (Some(0), false)] {
            let root = authority(path_len);
            assert_eq!(
                verify(&root, &leaf, &[&intermediate]),
                through_one,
                "{path_len:?}"
            );
            assert_eq!(
                verify(&root, &leaf, &[&other, &intermediate]),
                through_one,
                "{path_len:?}, an unrelated intermediate first"
            );
            assert!(verify(&root, &direct, &[]), "{path_len:?}");
            assert!(
                verify(&root, &direct, &[&intermediate, &other]),
                "{path_len:?}"
            );
        }

        // The root's own extended key usage takes part in the chain's.
        let with = |extension: Vec<u8>| [authority(None), vec![extension]].concat();
        assert!(verify(&with(eku(CLIENT_AUTH)), &direct, &[]));
        assert!(!verify(&with(eku(SERVER_AUTH)), &direct, &[]));
        assert!(!verify(&with(eku(SERVER_AUTH)), &leaf, &[&intermediate]));

        // A critical extension Go does not handle disqualifies the root;
        // the same extension marked non-critical does not.
        let critical = der_extension(&[0x2a, 0x03, 0x04], true, &[0x05, 0x00]);
        assert!(!verify(&with(critical), &direct, &[]));
        let non_critical = der_extension(&[0x2a, 0x03, 0x04], false, &[0x05, 0x00]);
        assert!(verify(&with(non_critical), &direct, &[]));
    }

    /// When Go's chain search builds no chain, the refusal is the error
    /// the search ended with (`GoChainError`), held to Go's own `Verify`
    /// through the oracle's `x509_verify_client`, and the alert rustls
    /// sends for it to the one Go's `processCertsFromClient` sends
    /// (`unknown_ca` for an unknown authority, `certificate_expired` for
    /// `Expired`, `bad_certificate` otherwise) where rustls has it: a leaf
    /// whose extended key usage leaves out client authentication and that
    /// chains to nothing, over an empty pool and a full one, which webpki
    /// refused for its usage before it looked for an issuer; a leaf whose
    /// only issuer in the pool is expired or not yet valid, which webpki
    /// passed over without a word; a root with an unhandled critical
    /// extension; and a `pathlen:0` root behind another of its name whose
    /// signature fails.  A chain Go builds and drops for a usage, the
    /// leaf's or the root's, is Go's `IncompatibleUsage`, in Go's words
    /// with rustls's `unsupported_certificate`.  And a leaf whose issuer's
    /// signature fails under ecdsa-with-SHA512, which the provider
    /// verifies since Go's client-certificate set (ADR-0015, T4) and whose
    /// refusal was left to webpki before it, is Go's unknown authority.
    #[test]
    fn a_search_without_a_chain_is_refused_with_gos_error() {
        use dcroxide_certgen::gentool::generate_key;
        use rustls::AlertDescription as A;
        use rustls::server::danger::ClientCertVerifier;
        const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
        const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
        const EKU: &[u8] = &[0x55, 0x1d, 0x25];
        const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
        const CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
        let now: i64 = 1_790_000_000;
        let year = 365 * 86_400;
        let mut oracle = dcroxide_testutil::oracle_or_skip();
        let key = || generate_key("P-256").expect("key");
        let (root_key, other_key, int_key, leaf_key) = (key(), key(), key(), key());
        let authority = |path_len: Option<u8>| {
            let mut constraints = der_tlv(0x01, &[0xff]);
            if let Some(path_len) = path_len {
                constraints.extend(der_tlv(0x02, &[path_len]));
            }
            vec![
                der_extension(BASIC_CONSTRAINTS, true, &der_tlv(0x30, &constraints)),
                der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x02, 0x84])),
            ]
        };
        let eku = |usage: &[u8]| der_extension(EKU, false, &der_tlv(0x30, &der_tlv(0x06, usage)));
        let root = |key: &dcroxide_certgen::gentool::ToolKeyPair, extra: Vec<Vec<u8>>| {
            signed_p256_certificate(
                1,
                "root",
                key,
                "root",
                key,
                &[authority(None), extra].concat(),
            )
        };
        let issued = |issuer: &str, usage: &[u8]| {
            signed_p256_certificate(9, "leaf", &leaf_key, issuer, &root_key, &[eku(usage)])
        };
        let (expired, expired_key) = gencerts_authority(now - 3 * year, 1);
        let (future, future_key) = gencerts_authority(now + year, 1);
        let int = signed_p256_certificate(2, "int", &int_key, "root", &root_key, &authority(None));
        let under_int =
            signed_p256_certificate(3, "leaf", &leaf_key, "int", &int_key, &[eku(CLIENT_AUTH)]);
        let pathlen0 =
            signed_p256_certificate(1, "root", &root_key, "root", &root_key, &authority(Some(0)));
        let critical = der_extension(&[0x2a, 0x03, 0x04], true, &[0x05, 0x00]);

        // A leaf whose signature algorithm, in its TBS and outside it, is
        // patched from ecdsa-with-SHA256 to ecdsa-with-SHA512, so that its
        // issuer's SHA-256 signature is checked as a SHA-512 one and fails.
        // The provider verifies ecdsa-with-SHA512 as Go does (ADR-0015,
        // T4), so the replay followed Go's search throughout and vouches
        // for Go's error, where before T4 it left the refusal to webpki,
        // which named the algorithm.
        let mut sha512 = issued("root", CLIENT_AUTH);
        let sha256_oid = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
        let mut patched = 0;
        let mut at_byte = 0;
        while let Some(found) = sha512[at_byte..]
            .windows(sha256_oid.len())
            .position(|window| window == sha256_oid)
        {
            let end = at_byte + found + sha256_oid.len();
            sha512[end - 1] = 0x04;
            at_byte = end;
            patched += 1;
        }
        assert_eq!(patched, 2, "the TBS and outer signature algorithms");

        let unknown = "x509: certificate signed by unknown authority";
        let usage = "x509: certificate specifies an incompatible key usage";
        let has_expired = "x509: certificate has expired or is not yet valid: current time ";
        // Each row: the pool, the leaf, the certificates sent, the start
        // of Go's error and whether the port gives all of it, and rustls's
        // alert for the port's.
        type Row<'r> = (
            &'r str,
            Vec<Vec<u8>>,
            Vec<u8>,
            Vec<Vec<u8>>,
            &'r str,
            bool,
            A,
        );
        let rows: Vec<Row<'_>> = vec![
            (
                "an empty pool, a server-only leaf",
                vec![],
                signed_p256_certificate(
                    9,
                    "leaf",
                    &leaf_key,
                    "leaf",
                    &leaf_key,
                    &[eku(SERVER_AUTH)],
                ),
                vec![],
                unknown,
                true,
                A::UnknownCA,
            ),
            (
                "a server-only leaf whose issuer is not in the pool",
                vec![root(&root_key, vec![])],
                issued("elsewhere", SERVER_AUTH),
                vec![],
                unknown,
                true,
                A::UnknownCA,
            ),
            (
                "an expired authority",
                vec![expired.der.clone()],
                gencerts_issued(now, &expired, &expired_key),
                vec![],
                has_expired,
                false,
                A::CertificateExpired,
            ),
            (
                "an authority not yet valid",
                vec![future.der.clone()],
                gencerts_issued(now, &future, &future_key),
                vec![],
                has_expired,
                false,
                A::CertificateExpired,
            ),
            (
                "an authority not yet valid, after a valid one of another name",
                vec![root(&root_key, vec![]), future.der.clone()],
                gencerts_issued(now, &future, &future_key),
                vec![],
                has_expired,
                false,
                A::CertificateExpired,
            ),
            (
                "an authority with an unhandled critical extension",
                vec![root(&root_key, vec![critical.clone()])],
                issued("root", CLIENT_AUTH),
                vec![],
                "x509: unhandled critical extension",
                true,
                A::BadCertificate,
            ),
            (
                "a pathlen:0 root after another of its name",
                vec![root(&other_key, vec![]), pathlen0.clone()],
                under_int.clone(),
                vec![int.clone()],
                "x509: too many intermediates for path length constraint",
                true,
                A::CertificateUnknown,
            ),
            (
                "a server-only leaf under a pooled authority",
                vec![root(&root_key, vec![])],
                issued("root", SERVER_AUTH),
                vec![],
                usage,
                true,
                A::UnsupportedCertificate,
            ),
            (
                "a server-only authority",
                vec![root(&root_key, vec![eku(SERVER_AUTH)])],
                issued("root", CLIENT_AUTH),
                vec![],
                usage,
                true,
                A::UnsupportedCertificate,
            ),
            (
                "an ecdsa-with-SHA512 signature that does not verify",
                vec![root(&root_key, vec![])],
                sha512,
                vec![],
                unknown,
                true,
                A::UnknownCA,
            ),
        ];
        let at = |secs: i64| {
            rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(
                u64::try_from(secs).expect("after 1970"),
            ))
        };
        for (what, pool, leaf, sent, go_error, whole, alert) in rows {
            let mut cas = ClientCaPool::new();
            for der in &pool {
                assert!(cas.add_cert(der.clone()), "{what}: the pool");
            }
            let verifier = GoClientCertVerifier::new(cas).expect("the verifier");
            let sent_ders: Vec<_> = sent
                .iter()
                .map(|der| rustls::pki_types::CertificateDer::from(der.as_slice()))
                .collect();
            let err = verifier
                .verify_client_cert(
                    &rustls::pki_types::CertificateDer::from(leaf.as_slice()),
                    &sent_ders,
                    at(now),
                )
                .expect_err(what);
            let rustls::Error::InvalidCertificate(certificate_error) = &err else {
                panic!("{what}: {err:?}");
            };
            assert_eq!(A::from(certificate_error.clone()), alert, "{what}: {err:?}");
            let ours = crate::server::go_error_text_for_tests(&err);
            if whole {
                assert_eq!(
                    ours,
                    format!("tls: failed to verify certificate: {go_error}"),
                    "{what}"
                );
            } else {
                assert!(
                    matches!(
                        certificate_error,
                        rustls::CertificateError::ExpiredContext { .. }
                            | rustls::CertificateError::NotValidYetContext { .. }
                    ),
                    "{what}: {err:?}"
                );
            }
            let roots: Vec<&[u8]> = pool.iter().map(Vec::as_slice).collect();
            let sent: Vec<&[u8]> = sent.iter().map(Vec::as_slice).collect();
            if let Some(go) = go_client_verdict(
                &mut oracle,
                &roots,
                &leaf,
                &sent,
                u64::try_from(now).expect("after 1970"),
            ) {
                assert!(
                    go.verdict.starts_with(go_error),
                    "{what}: Go {}",
                    go.verdict
                );
                if whole && go_error != unknown {
                    assert_eq!(go.verdict, go_error, "{what}");
                }
            }
        }
    }

    /// A leaf whose only issuer in the pool signed it under a key Go
    /// verifies with and the provider does not, a P-224 key or an RSA-1024
    /// one (`tests/data/unverifiable-issuer`), is accepted by Go's `Verify`
    /// and refused here, as PARITY.md's clientcert entry records.  The
    /// replay of Go's search cannot check that signature
    /// (`SignatureCheck::Unverifiable`, the arm of an RSA key the provider
    /// refuses and the arm of a key no algorithm takes), so it does not
    /// vouch for Go's unknown authority, which Go would not give, and the
    /// refusal is webpki's, in rustls's words.  Go's acceptance is held
    /// through the oracle when it is present.
    #[test]
    fn a_search_through_an_issuer_the_provider_cannot_verify_is_left_to_webpki() {
        use rustls::server::danger::ClientCertVerifier;
        let now: u64 = 1_790_000_000;
        let at = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(now));
        let mut oracle = dcroxide_testutil::oracle_or_skip();
        let one = |pem: &[u8]| -> Vec<u8> {
            let (block, rest) = crate::pem::go_pem_decode(pem).expect("a PEM block");
            assert!(crate::pem::go_pem_decode(rest).is_none(), "one block");
            block.bytes
        };
        let unknown = "tls: failed to verify certificate: x509: certificate signed by unknown \
                       authority";
        for (what, root, leaf) in [
            (
                "a P-224 issuer",
                one(include_bytes!(
                    "../tests/data/unverifiable-issuer/p224-root.pem"
                )),
                one(include_bytes!(
                    "../tests/data/unverifiable-issuer/p224-leaf.pem"
                )),
            ),
            (
                "an RSA-1024 issuer",
                one(include_bytes!(
                    "../tests/data/unverifiable-issuer/rsa1024-root.pem"
                )),
                one(include_bytes!(
                    "../tests/data/unverifiable-issuer/rsa1024-leaf.pem"
                )),
            ),
        ] {
            // The replay itself: one candidate, whose check is
            // unverifiable, so the search is uncertain and built nothing.
            let roots = [ChainCandidate::parse(&root).expect("the root")];
            let leaf_candidate = ChainCandidate::parse(&leaf).expect("the leaf");
            assert_eq!(
                go_check_signature_from(
                    &leaf_candidate,
                    &roots[0],
                    dcroxide_tlscrypto::RPC_SIG_ALGS.all
                ),
                SignatureCheck::Unverifiable,
                "{what}"
            );

            let mut cas = ClientCaPool::new();
            assert!(cas.add_cert(root.clone()), "{what}: the pool");
            let err = GoClientCertVerifier::new(cas)
                .expect("the verifier")
                .verify_client_cert(
                    &rustls::pki_types::CertificateDer::from(leaf.as_slice()),
                    &[],
                    at,
                )
                .expect_err(what);
            let rustls::Error::InvalidCertificate(certificate_error) = &err else {
                panic!("{what}: {err:?}");
            };
            assert_ne!(
                rustls::AlertDescription::from(certificate_error.clone()),
                rustls::AlertDescription::UnknownCA,
                "{what}: {err:?}"
            );
            assert_ne!(
                crate::server::go_error_text_for_tests(&err),
                unknown,
                "{what}: {err:?}"
            );
            if let Some(go) = go_client_verdict(&mut oracle, &[&root], &leaf, &[], now) {
                assert_eq!(go.verdict, "ok", "{what}: Go accepts the chain");
            }
        }
    }

    /// When Go's search builds chains and `Verify` drops every one for its
    /// policies or its key usage, the two checks it makes first, the
    /// refusal is Go's error for that, decided before webpki's search,
    /// which ranks a signature failure on a path Go never built above a
    /// usage refusal: the chain of `tests/data/key-usage-chain`, where an
    /// intermediate and the root leave out client authentication and
    /// webpki reaches the root also through an intermediate whose
    /// signature on the next fails, is Go's `IncompatibleUsage`, where it
    /// was logged as a bad signature with `decrypt_error`; and two chains
    /// through one name, one dropped for its usage and one for its
    /// policies, give Go's `NoValidChains` with both counts.  Each is held
    /// to Go's own verdict through the oracle when it is present.
    #[test]
    fn a_chain_go_drops_for_its_usage_is_refused_for_it() {
        use dcroxide_certgen::gentool::generate_key;
        use rustls::AlertDescription as A;
        use rustls::server::danger::ClientCertVerifier;
        const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
        const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
        const EKU: &[u8] = &[0x55, 0x1d, 0x25];
        const POLICY_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x24];
        const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
        const CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
        let now: i64 = 1_790_000_000;
        let at = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(
            u64::try_from(now).expect("after 1970"),
        ));
        let mut oracle = dcroxide_testutil::oracle_or_skip();
        let blocks = |pem: &[u8]| -> Vec<Vec<u8>> {
            let mut rest = pem;
            let mut ders = Vec::new();
            while let Some((block, after)) = crate::pem::go_pem_decode(rest) {
                ders.push(block.bytes);
                rest = after;
            }
            ders
        };

        let key = || generate_key("P-256").expect("key");
        let (root_key, int_key, leaf_key) = (key(), key(), key());
        let authority = vec![
            der_extension(
                BASIC_CONSTRAINTS,
                true,
                &der_tlv(0x30, &der_tlv(0x01, &[0xff])),
            ),
            der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x02, 0x84])),
        ];
        let eku = |usage: &[u8]| der_extension(EKU, false, &der_tlv(0x30, &der_tlv(0x06, usage)));
        let root = signed_p256_certificate(1, "root", &root_key, "root", &root_key, &authority);
        let server_only = signed_p256_certificate(
            2,
            "int",
            &int_key,
            "root",
            &root_key,
            &[authority.clone(), vec![eku(SERVER_AUTH)]].concat(),
        );
        let explicit_policy = signed_p256_certificate(
            3,
            "int",
            &int_key,
            "root",
            &root_key,
            &[
                authority.clone(),
                vec![der_extension(
                    POLICY_CONSTRAINTS,
                    true,
                    &der_tlv(0x30, &der_tlv(0x80, &[0])),
                )],
            ]
            .concat(),
        );
        let leaf =
            signed_p256_certificate(9, "leaf", &leaf_key, "int", &int_key, &[eku(CLIENT_AUTH)]);

        let usage = "x509: certificate specifies an incompatible key usage";
        // Each row: the pool, the leaf, the certificates sent, Go's error,
        // and rustls's alert for the port's.
        type Row<'r> = (&'r str, Vec<Vec<u8>>, Vec<u8>, Vec<Vec<u8>>, &'r str, A);
        let rows: Vec<Row<'_>> = vec![
            (
                "the review's chain",
                blocks(include_bytes!("../tests/data/key-usage-chain/roots.pem")),
                blocks(include_bytes!("../tests/data/key-usage-chain/leaf.pem"))
                    .pop()
                    .expect("the leaf"),
                blocks(include_bytes!("../tests/data/key-usage-chain/sent.pem")),
                usage,
                A::UnsupportedCertificate,
            ),
            (
                "one chain dropped for its usage, one for its policies",
                vec![root.clone()],
                leaf.clone(),
                vec![server_only.clone(), explicit_policy.clone()],
                "x509: no valid chains built: 1 candidate chains with incompatible key usage, 1 \
                 candidate chains with invalid policies",
                A::CertificateUnknown,
            ),
            (
                "one chain, dropped for its policies",
                vec![root.clone()],
                leaf.clone(),
                vec![explicit_policy.clone()],
                "x509: no valid chains built: 1 candidate chains with invalid policies",
                A::CertificateUnknown,
            ),
            (
                "one chain, dropped for its usage",
                vec![root.clone()],
                leaf.clone(),
                vec![server_only.clone()],
                usage,
                A::UnsupportedCertificate,
            ),
        ];
        for (what, pool, leaf, sent, go_error, alert) in rows {
            let mut cas = ClientCaPool::new();
            for der in &pool {
                assert!(cas.add_cert(der.clone()), "{what}: the pool");
            }
            let verifier = GoClientCertVerifier::new(cas).expect("the verifier");
            let sent_ders: Vec<_> = sent
                .iter()
                .map(|der| rustls::pki_types::CertificateDer::from(der.as_slice()))
                .collect();
            let err = verifier
                .verify_client_cert(
                    &rustls::pki_types::CertificateDer::from(leaf.as_slice()),
                    &sent_ders,
                    at,
                )
                .expect_err(what);
            let rustls::Error::InvalidCertificate(certificate_error) = &err else {
                panic!("{what}: {err:?}");
            };
            assert_eq!(A::from(certificate_error.clone()), alert, "{what}: {err:?}");
            assert_eq!(
                crate::server::go_error_text_for_tests(&err),
                format!("tls: failed to verify certificate: {go_error}"),
                "{what}"
            );
            let roots: Vec<&[u8]> = pool.iter().map(Vec::as_slice).collect();
            let sent: Vec<&[u8]> = sent.iter().map(Vec::as_slice).collect();
            if let Some(go) = go_client_verdict(
                &mut oracle,
                &roots,
                &leaf,
                &sent,
                u64::try_from(now).expect("after 1970"),
            ) {
                assert_eq!(go.verdict, go_error, "{what}: Go");
            }
        }
    }

    /// A pooled certificate presented as the client's is checked only as
    /// Go checks the chain `[c]` (review findings GAP06#1 and GAP06#4):
    /// `anyExtendedKeyUsage` admits it, as `checkChainForKeyUsage` does,
    /// and its own signature is never verified, so a self-signature
    /// webpki cannot check (SHA-1, or simply broken) does not refuse it.
    /// A server-only extended key usage still does.
    #[test]
    fn a_pooled_leaf_is_checked_as_go_checks_it() {
        use dcroxide_certgen::gentool::generate_key;
        const EKU: &[u8] = &[0x55, 0x1d, 0x25];
        const ANY: &[u8] = &[0x55, 0x1d, 0x25, 0x00];
        const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
        let now = 1_790_000_000;
        let key = generate_key("P-256").expect("key");
        let self_signed = |usage: &[u8]| {
            let eku = der_extension(EKU, false, &der_tlv(0x30, &der_tlv(0x06, usage)));
            signed_p256_certificate(1, "client", &key, "client", &key, &[eku])
        };

        let any = self_signed(ANY);
        verify_client_at(&certificate_pem(&any), &any, now).expect("anyExtendedKeyUsage");

        // Flip the last byte of the signature value.
        let mut broken = any.clone();
        let last = broken.len() - 1;
        broken[last] ^= 0x01;
        verify_client_at(&certificate_pem(&broken), &broken, now)
            .expect("unchecked self-signature");

        let server = self_signed(SERVER_AUTH);
        assert!(matches!(
            verify_client_at(&certificate_pem(&server), &server, now),
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::InvalidPurpose
            ))
        ));
    }

    /// A chained certificate is held to Go's extended key usage rule
    /// (review finding GAP06#4): a leaf, or an intermediate, listing
    /// `anyExtendedKeyUsage` authenticates, as `checkChainForKeyUsage`
    /// lets it, where webpki's `KeyUsage::client_auth` refused it, and a
    /// list naming `clientAuth` anywhere authenticates as before.  A leaf
    /// or intermediate listing neither, a list with an entry that is not
    /// an object identifier, wherever it stands, and a certificate no
    /// pool certificate signs are refused, with the errors rustls's own
    /// client verifier gives.
    #[test]
    fn a_chained_certificate_takes_gos_extended_key_usage_rule() {
        use dcroxide_certgen::gentool::generate_key;
        use rustls::pki_types::CertificateDer;
        use rustls::server::danger::ClientCertVerifier;
        const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
        const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
        const EKU: &[u8] = &[0x55, 0x1d, 0x25];
        const ANY: &[u8] = &[0x55, 0x1d, 0x25, 0x00];
        const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
        const CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
        const CODE_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
        let now = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(1_790_000_000));
        let key = || generate_key("P-256").expect("key");
        let (root_key, int_key, leaf_key, stranger_key) = (key(), key(), key(), key());
        let authority = vec![
            der_extension(
                BASIC_CONSTRAINTS,
                true,
                &der_tlv(0x30, &der_tlv(0x01, &[0xff])),
            ),
            der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x02, 0x84])),
        ];
        // An extended key usage of the given DER elements, each an
        // object identifier unless built otherwise.
        let eku_of =
            |elements: &[Vec<u8>]| der_extension(EKU, false, &der_tlv(0x30, &elements.concat()));
        let eku = |usages: &[&[u8]]| {
            eku_of(
                &usages
                    .iter()
                    .map(|usage| der_tlv(0x06, usage))
                    .collect::<Vec<_>>(),
            )
        };
        let signing = der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x07, 0x80]));

        let root = signed_p256_certificate(1, "root", &root_key, "root", &root_key, &authority);
        let ours = GoClientCertVerifier::from_pem(&certificate_pem(&root)).expect("verifier");
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(root.as_slice()))
            .expect("the root");
        let theirs = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(dcroxide_tlscrypto::default_provider()),
        )
        .build()
        .expect("webpki's verifier");
        let check = |verifier: &dyn ClientCertVerifier, leaf: &[u8], sent: &[&[u8]]| {
            let sent: Vec<_> = sent.iter().map(|der| CertificateDer::from(*der)).collect();
            verifier
                .verify_client_cert(&CertificateDer::from(leaf), &sent, now)
                .map(|_| ())
        };
        let intermediate = |extensions: &[Vec<u8>]| {
            signed_p256_certificate(2, "int", &int_key, "root", &root_key, extensions)
        };
        let leaf_with = |usage: Vec<u8>| {
            signed_p256_certificate(
                3,
                "leaf",
                &leaf_key,
                "int",
                &int_key,
                &[signing.clone(), usage],
            )
        };
        let leaf = |usages: &[&[u8]]| leaf_with(eku(usages));
        let plain = intermediate(&authority);

        let any_leaf = leaf(&[ANY]);
        assert!(
            check(&*theirs, &any_leaf, &[&plain]).is_err(),
            "webpki's rule refuses anyExtendedKeyUsage on the leaf"
        );
        check(&ours, &any_leaf, &[&plain]).expect("Go's rule admits it on the leaf");

        let any_intermediate = intermediate(&[authority.clone(), vec![eku(&[ANY])]].concat());
        let client_leaf = leaf(&[CLIENT_AUTH]);
        assert!(
            check(&*theirs, &client_leaf, &[&any_intermediate]).is_err(),
            "webpki's rule refuses anyExtendedKeyUsage on an intermediate"
        );
        check(&ours, &client_leaf, &[&any_intermediate])
            .expect("Go's rule admits it on an intermediate");
        check(&ours, &client_leaf, &[&plain]).expect("clientAuth");

        // The whole list counts: `clientAuth` or `anyExtendedKeyUsage`
        // after another usage still admits.
        let server_then_client = leaf(&[SERVER_AUTH, CLIENT_AUTH]);
        check(&*theirs, &server_then_client, &[&plain]).expect("webpki: clientAuth second");
        check(&ours, &server_then_client, &[&plain]).expect("Go: clientAuth second");
        check(&ours, &leaf(&[SERVER_AUTH, ANY]), &[&plain]).expect("Go: any second");

        let server_leaf = leaf(&[SERVER_AUTH]);
        let not_an_oid = leaf_with(eku_of(&[der_tlv(0x06, ANY), der_tlv(0x02, &[0x01])]));
        let neither_intermediate =
            intermediate(&[authority.clone(), vec![eku(&[SERVER_AUTH, CODE_SIGNING])]].concat());
        let stranger = signed_p256_certificate(
            4,
            "stranger",
            &stranger_key,
            "nobody",
            &stranger_key,
            std::slice::from_ref(&signing),
        );
        for (refused, sent) in [
            (&server_leaf, vec![plain.as_slice()]),
            (&not_an_oid, vec![plain.as_slice()]),
            (&client_leaf, vec![neither_intermediate.as_slice()]),
            (&stranger, vec![]),
        ] {
            let want = check(&*theirs, refused, &sent).expect_err("refused by webpki");
            assert_eq!(check(&ours, refused, &sent), Err(want));
        }
    }

    /// A client chain is one search, held to its root's path length
    /// constraint within that search, as Go's `buildChains` holds it: a
    /// chain through one intermediate under a `pathlen:1` root is found
    /// among 120 unrelated intermediates sent before it; a longer path
    /// the constraint refuses sends the search on to a shorter one; a
    /// chain through two is refused under that root with the error
    /// logged as Go's `TooManyIntermediates`, and accepted under a
    /// `pathlen:2` root of the same name and key; and each pooled root
    /// is held to its own constraint, an unusable one lending none and a
    /// refusal at one sending the search on to the next.  The verifier
    /// this replaced made a whole webpki search for each choice of one
    /// intermediate, up to 100 choices, and refused the first chain when
    /// they ran out.
    #[test]
    fn a_chain_within_the_path_length_is_found_in_one_search() {
        use dcroxide_certgen::gentool::generate_key;
        use rustls::pki_types::CertificateDer;
        use rustls::server::danger::ClientCertVerifier;
        const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
        const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
        let now = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(1_790_000_000));
        let key = || generate_key("P-256").expect("key");
        let (root_key, int_key, inner_key, leaf_key, decoy_key, mid_key) =
            (key(), key(), key(), key(), key(), key());
        let authority = |path_len: Option<u8>| {
            let mut constraints = der_tlv(0x01, &[0xff]);
            if let Some(path_len) = path_len {
                constraints.extend(der_tlv(0x02, &[path_len]));
            }
            vec![
                der_extension(BASIC_CONSTRAINTS, true, &der_tlv(0x30, &constraints)),
                der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x02, 0x84])),
            ]
        };
        let signing = [der_extension(
            KEY_USAGE,
            true,
            &der_tlv(0x03, &[0x07, 0x80]),
        )];
        let verify = |path_len: u8, leaf: &[u8], sent: &[&[u8]]| {
            let root = signed_p256_certificate(
                1,
                "root",
                &root_key,
                "root",
                &root_key,
                &authority(Some(path_len)),
            );
            let verifier =
                GoClientCertVerifier::from_pem(&certificate_pem(&root)).expect("verifier");
            let sent: Vec<_> = sent.iter().map(|der| CertificateDer::from(*der)).collect();
            verifier
                .verify_client_cert(&CertificateDer::from(leaf), &sent, now)
                .map(|_| ())
        };

        let int = signed_p256_certificate(2, "int", &int_key, "root", &root_key, &authority(None));
        let leaf = signed_p256_certificate(3, "leaf", &leaf_key, "int", &int_key, &signing);
        // Serials stay below 0x80, which the helper would encode as a
        // negative INTEGER that Go's parser refuses.
        let decoys: Vec<Vec<u8>> = (0..120u8)
            .map(|i| {
                signed_p256_certificate(
                    6 + i,
                    &format!("decoy {i}"),
                    &decoy_key,
                    "root",
                    &root_key,
                    &authority(None),
                )
            })
            .collect();
        let mut sent: Vec<&[u8]> = decoys.iter().map(Vec::as_slice).collect();
        sent.push(&int);
        verify(1, &leaf, &sent).expect("the chain is found among the decoys");

        let inner =
            signed_p256_certificate(4, "inner", &inner_key, "int", &int_key, &authority(None));
        let deep_leaf =
            signed_p256_certificate(5, "deep", &leaf_key, "inner", &inner_key, &signing);
        let too_many = |err: &rustls::Error| {
            matches!(
                err,
                rustls::Error::InvalidCertificate(rustls::CertificateError::Other(other))
                    if other.0.downcast_ref::<webpki::Error>()
                        == Some(&webpki::Error::PathLenConstraintViolated)
            )
        };
        let err = verify(1, &deep_leaf, &[&inner, &int]).expect_err("two under pathlen:1");
        assert!(too_many(&err), "{err:?}");
        verify(2, &deep_leaf, &[&inner, &int]).expect("two intermediates under pathlen:2");

        // `int` again, under a `mid` the root signs: the path through it
        // holds two intermediates, which pathlen:1 refuses, and the
        // search goes on to the `int` the root signs itself.
        let mid =
            signed_p256_certificate(126, "mid", &mid_key, "root", &root_key, &authority(None));
        let long_int =
            signed_p256_certificate(127, "int", &int_key, "mid", &mid_key, &authority(None));
        verify(1, &leaf, &[&long_int, &mid, &int]).expect("the shorter path after the longer");
        let err = verify(0, &leaf, &[&long_int, &mid, &int]).expect_err("pathlen:0");
        assert!(too_many(&err), "{err:?}");

        // Each pooled root is held to its own constraint: an expired
        // root of the same name and key listed first anchors nothing,
        // and the `pathlen:0` one after it refuses the chain an
        // unconstrained one accepts.
        let expired = signed_p256_certificate_until(
            1,
            "root",
            &root_key,
            "root",
            &root_key,
            der_tlv(0x17, b"200101000000Z"),
            &authority(None),
        );
        let pooled = |path_len: Option<u8>, leaf: &[u8], sent: &[&[u8]]| {
            let root = signed_p256_certificate(
                1,
                "root",
                &root_key,
                "root",
                &root_key,
                &authority(path_len),
            );
            let pem = [certificate_pem(&expired), certificate_pem(&root)].concat();
            let verifier = GoClientCertVerifier::from_pem(&pem).expect("verifier");
            let sent: Vec<_> = sent.iter().map(|der| CertificateDer::from(*der)).collect();
            verifier
                .verify_client_cert(&CertificateDer::from(leaf), &sent, now)
                .map(|_| ())
        };
        let err = pooled(Some(0), &leaf, &[&int]).expect_err("the second root's pathlen:0");
        assert!(too_many(&err), "{err:?}");
        pooled(None, &leaf, &[&int]).expect("an unconstrained second root");

        // Two usable roots of one name.  With another key and no
        // constraint listed first, the `pathlen:0` root that signed the
        // chain still refuses it; with the same key and no constraint
        // listed after a `pathlen:0` one, the chain verifies through the
        // second once the first refuses it.
        let two = |first: Vec<u8>, second: Vec<u8>| {
            let pem = [certificate_pem(&first), certificate_pem(&second)].concat();
            let verifier = GoClientCertVerifier::from_pem(&pem).expect("verifier");
            verifier
                .verify_client_cert(
                    &CertificateDer::from(leaf.as_slice()),
                    &[CertificateDer::from(int.as_slice())],
                    now,
                )
                .map(|_| ())
        };
        let root_with = |key: &dcroxide_certgen::gentool::ToolKeyPair, path_len: Option<u8>| {
            signed_p256_certificate(1, "root", key, "root", key, &authority(path_len))
        };
        // The refusal reports the constraint, as Go does: Go's search
        // passes over the first root for its signature, which writes
        // nothing to the error it returns, and the second's `isValid`
        // refusal is the last word.  webpki alone ranks the failed
        // signature above the constraint and reported that.
        let err = two(root_with(&mid_key, None), root_with(&root_key, Some(0)))
            .expect_err("the signing root's pathlen:0, after another root of its name");
        assert!(too_many(&err), "{err:?}");
        two(root_with(&root_key, Some(0)), root_with(&root_key, None))
            .expect("the unconstrained twin after the pathlen:0 root");
    }

    /// The parts of a certificate for [`chain_facts_follow_gos_parser`],
    /// starting from one Go's `ParseCertificate` accepts.
    #[derive(Clone)]
    struct CertParts {
        /// The contents of the version's [0], absent for version 1.
        version: Option<Vec<u8>>,
        inner: Vec<u8>,
        outer: Vec<u8>,
        spki: Vec<u8>,
        signature: Vec<u8>,
        trailing: Vec<u8>,
        extensions: Vec<Vec<u8>>,
    }

    impl CertParts {
        fn base(public_key: &[u8]) -> CertParts {
            let ecdsa_sha256 = der_tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);
            let ec_p256 = [
                der_tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
                der_tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
            ]
            .concat();
            CertParts {
                version: Some(der_tlv(0x02, &[2])),
                inner: ecdsa_sha256.clone(),
                outer: ecdsa_sha256,
                spki: der_tlv(
                    0x30,
                    &[
                        der_tlv(0x30, &ec_p256),
                        der_tlv(0x03, &[&[0u8][..], public_key].concat()),
                    ]
                    .concat(),
                ),
                signature: vec![0, 1, 2],
                trailing: Vec::new(),
                extensions: Vec::new(),
            }
        }

        fn der(&self) -> Vec<u8> {
            let name = der_tlv(0x30, &[]);
            let mut tbs = self
                .version
                .as_ref()
                .map(|v| der_tlv(0xa0, v))
                .unwrap_or_default();
            tbs.extend(der_tlv(0x02, &[1]));
            tbs.extend(der_tlv(0x30, &self.inner));
            tbs.extend(name.clone());
            tbs.extend(der_tlv(
                0x30,
                &[
                    der_tlv(0x17, b"240101000000Z"),
                    der_tlv(0x18, b"20500101000000Z"),
                ]
                .concat(),
            ));
            tbs.extend(name);
            tbs.extend(self.spki.clone());
            if !self.extensions.is_empty() {
                tbs.extend(der_tlv(0xa3, &der_tlv(0x30, &self.extensions.concat())));
            }
            let mut der = der_tlv(
                0x30,
                &[
                    der_tlv(0x30, &tbs),
                    der_tlv(0x30, &self.outer),
                    der_tlv(0x03, &self.signature),
                ]
                .concat(),
            );
            der.extend_from_slice(&self.trailing);
            der
        }
    }

    /// Whether Go's `ParseCertificate` accepts `der`, through the oracle's
    /// `x509_verify_client`, which parses the leaf first; `None` without
    /// an oracle.
    fn go_parses(oracle: &mut Option<dcroxide_testutil::Oracle>, der: &[u8]) -> Option<bool> {
        let hex: String = der.iter().map(|b| format!("{b:02x}")).collect();
        let request = format!(r#"{{"roots":[],"leaf":"{hex}","intermediates":[],"time":0}}"#);
        let response = oracle
            .as_mut()?
            .call("x509_verify_client", request.as_bytes());
        Some(
            !response["error"]
                .as_str()
                .is_some_and(|err| err.starts_with("x509_verify_client: leaf: ")),
        )
    }

    /// What the chain search reads, read as Go's parser reads it: the
    /// version, basic constraints, cA and key usage bits; the key
    /// identifiers, the signed `TBSCertificate`, its signature algorithm
    /// and signature, and the key of an algorithm Go knows.  A
    /// certificate Go's `ParseCertificate` refuses on any of them is
    /// refused: trailing data, a version's [0] holding more than the
    /// INTEGER, inner and outer signature algorithms that differ or that
    /// `parseAI` does not read, a signature or key usage BIT STRING
    /// cryptobyte does not read, and a key identifier of the wrong form.
    /// Each case starts from a certificate Go parses, and where the
    /// oracle runs, Go's own verdict on each is compared.
    #[test]
    fn chain_facts_follow_gos_parser() {
        const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
        const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
        const SKI: &[u8] = &[0x55, 0x1d, 0x0e];
        const AKI: &[u8] = &[0x55, 0x1d, 0x23];
        let mut oracle = dcroxide_testutil::oracle_or_skip();
        let key = dcroxide_certgen::gentool::generate_key("P-256").expect("key");
        let base = CertParts::base(&key.public_bytes());
        let with = |change: &dyn Fn(&mut CertParts)| {
            let mut parts = base.clone();
            change(&mut parts);
            parts.der()
        };
        let mut agrees = |label: &str, der: &[u8], parses: bool| {
            assert_eq!(CertFacts::parse(der).is_some(), parses, "{label}");
            if let Some(go) = go_parses(&mut oracle, der) {
                assert_eq!(go, parses, "{label}: Go's verdict");
            }
        };

        agrees("the base certificate", &base.der(), true);
        let ca = with(&|c| {
            c.extensions = vec![
                der_extension(
                    BASIC_CONSTRAINTS,
                    true,
                    &der_tlv(0x30, &der_tlv(0x01, &[0xff])),
                ),
                der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x02, 0x84])),
                der_extension(SKI, false, &der_tlv(0x04, &[7; 4])),
                der_extension(AKI, false, &der_tlv(0x30, &der_tlv(0x80, &[8; 4]))),
            ]
        });
        agrees("a CA certificate", &ca, true);
        let (facts, _, _, links) = CertFacts::parse_full(&ca).expect("a CA certificate");
        assert_eq!(
            (facts.version, facts.basic_constraints, facts.is_ca),
            (3, true, true)
        );
        assert_eq!(
            facts.key_usage,
            1 | KEY_USAGE_CERT_SIGN,
            "digitalSignature and keyCertSign"
        );
        assert_eq!(
            (links.subject_key_id, links.authority_key_id),
            (&[7u8; 4][..], &[8u8; 4][..])
        );
        assert_eq!(links.signature, Some(&[1u8, 2][..]));
        assert_eq!(links.signature_algorithm, base.inner.as_slice());
        let ec_p256 = [
            der_tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
            der_tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
        ]
        .concat();
        let public_key = key.public_bytes();
        assert_eq!(
            links.key,
            Some((ec_p256.as_slice(), &public_key[..])),
            "the P-256 key and its algorithm identifier"
        );

        let end_entity = with(&|c| {
            c.extensions = vec![
                der_extension(BASIC_CONSTRAINTS, true, &der_tlv(0x30, &[])),
                der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x07, 0x00, 0x80])),
                der_extension(AKI, false, &der_tlv(0x30, &der_tlv(0x82, &[1]))),
            ]
        });
        agrees("an end entity", &end_entity, true);
        let (facts, _, _, links) = CertFacts::parse_full(&end_entity).expect("an end entity");
        assert_eq!((facts.basic_constraints, facts.is_ca), (true, false));
        assert_eq!(facts.key_usage, 1 << 8, "decipherOnly, the ninth bit");
        assert!(
            links.subject_key_id.is_empty() && links.authority_key_id.is_empty(),
            "no identifier, and an authority without [0]"
        );
        let version_1 = with(&|c| c.version = None);
        agrees("version 1", &version_1, true);
        assert_eq!(
            CertFacts::parse(&version_1).map(|f| (f.version, f.basic_constraints)),
            Some((1, false))
        );
        // A key usage bit past the ninth is dropped, as Go drops it.
        let bit_9 = with(&|c| {
            c.extensions = vec![der_extension(
                KEY_USAGE,
                true,
                &der_tlv(0x03, &[0x06, 0x00, 0x40]),
            )]
        });
        agrees("bit 9 of the key usage", &bit_9, true);
        assert_eq!(CertFacts::parse(&bit_9).map(|f| f.key_usage), Some(0));
        // A signature whose last octet carries unused bits, all zero,
        // parses; Go right-aligns it, and the chain search verifies
        // nothing with it (webpki refuses it too).
        let unused = with(&|c| c.signature = vec![2, 0x04]);
        agrees("a signature with unused bits", &unused, true);
        assert_eq!(
            CertFacts::parse_full(&unused).map(|(_, _, _, l)| l.signature),
            Some(None)
        );
        // Bytes after the subject key identifier, and after an algorithm
        // identifier's parameters, are not read, as Go reads none.
        agrees(
            "bytes after the subject key identifier",
            &with(&|c| {
                c.extensions = vec![der_extension(
                    SKI,
                    false,
                    &[der_tlv(0x04, &[1]), vec![0]].concat(),
                )]
            }),
            true,
        );
        let with_params = [base.inner.clone(), der_tlv(0x05, &[]), vec![0x05, 0x00]].concat();
        agrees(
            "bytes after the parameters",
            &with(&|c| {
                c.inner = with_params.clone();
                c.outer = with_params.clone();
            }),
            true,
        );

        agrees("trailing data", &with(&|c| c.trailing = vec![0]), false);
        agrees(
            "a version holding more than its INTEGER",
            &with(&|c| c.version = Some([der_tlv(0x02, &[2]), der_tlv(0x05, &[])].concat())),
            false,
        );
        agrees(
            "an outer algorithm that differs",
            &with(&|c| c.outer = der_tlv(0x06, &[0x2a, 0x03])),
            false,
        );
        for (label, ai) in [
            ("an empty algorithm identifier", Vec::new()),
            (
                "an algorithm identifier opening with no OID",
                der_tlv(0x05, &[]),
            ),
            ("a malformed OID", der_tlv(0x06, &[0x80, 0x01])),
            (
                "malformed parameters",
                [base.inner.clone(), vec![0x05, 0x05]].concat(),
            ),
        ] {
            agrees(
                label,
                &with(&|c| {
                    c.inner = ai.clone();
                    c.outer = ai.clone();
                }),
                false,
            );
        }
        for bits in [&[][..], &[8, 0], &[1], &[1, 0x01]] {
            agrees(
                &format!("signature {bits:02x?}"),
                &with(&|c| c.signature = bits.to_vec()),
                false,
            );
            agrees(
                &format!("key usage {bits:02x?}"),
                &with(&|c| {
                    c.extensions = vec![der_extension(KEY_USAGE, true, &der_tlv(0x03, bits))]
                }),
                false,
            );
        }
        agrees(
            "a subject key identifier that is no OCTET STRING",
            &with(&|c| c.extensions = vec![der_extension(SKI, false, &der_tlv(0x30, &[]))]),
            false,
        );
        for value in [der_tlv(0x04, &[1]), der_tlv(0x30, &[0x80, 0x05, 0x01])] {
            agrees(
                &format!("authority key identifier {value:02x?}"),
                &with(&|c| c.extensions = vec![der_extension(AKI, false, &value)]),
                false,
            );
        }

        // The key of every algorithm Go 1.27 gives one, and none for an
        // algorithm it does not know or for key bits with unused bits.
        // These keys are not well formed, so Go is not asked.
        for (label, oid, known) in [
            (
                "RSA",
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01][..],
                true,
            ),
            ("DSA", &[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01], true),
            ("ECDSA", &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01], true),
            ("Ed25519", &[0x2b, 0x65, 0x70], true),
            (
                "ML-DSA-44",
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11],
                true,
            ),
            (
                "ML-DSA-65",
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12],
                true,
            ),
            (
                "ML-DSA-87",
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13],
                true,
            ),
            (
                "X25519, which Go 1.27 leaves without a key",
                &[0x2b, 0x65, 0x6e],
                false,
            ),
        ] {
            let algorithm = der_tlv(0x06, oid);
            let spki = |bits: &[u8]| {
                der_tlv(
                    0x30,
                    &[der_tlv(0x30, &algorithm), der_tlv(0x03, bits)].concat(),
                )
            };
            assert_eq!(
                go_public_key(
                    DerReader::new(&spki(&[0, 9, 9]))
                        .read_tag(0x30)
                        .expect("spki")
                ),
                known.then_some((algorithm.as_slice(), &[9u8, 9][..])),
                "{label}"
            );
            assert_eq!(
                go_public_key(
                    DerReader::new(&spki(&[1, 9, 8]))
                        .read_tag(0x30)
                        .expect("spki")
                ),
                None,
                "{label} with an unused bit"
            );
        }
    }

    /// The IP addresses of a subject alternative name and of name
    /// constraints, and rfc822Name constraints, are read as Go 1.27.3's
    /// `ParseCertificate` reads them.  An IPv4-mapped address, which Go
    /// 1.27 refuses in either, fails the parse, and so do an address or
    /// constraint of another length, a mask that is not ones then zeros,
    /// and a mailbox constraint Go cannot read, one whose domain holds
    /// `@` among them, which Go 1.26 took.  Where the oracle runs, Go's
    /// own verdict on each is compared.
    #[test]
    fn ip_names_and_mailbox_constraints_follow_gos_parser() {
        const SAN: &[u8] = &[0x55, 0x1d, 0x11];
        const NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];
        let mut oracle = dcroxide_testutil::oracle_or_skip();
        let key = dcroxide_certgen::gentool::generate_key("P-256").expect("key");
        let base = CertParts::base(&key.public_bytes());
        let with_extension = |oid: &[u8], value: Vec<u8>| {
            let mut parts = base.clone();
            parts.extensions = vec![der_extension(oid, false, &value)];
            parts.der()
        };
        let mut agrees = |label: &str, der: &[u8], parses: bool| {
            assert_eq!(CertFacts::parse(der).is_some(), parses, "{label}");
            if let Some(go) = go_parses(&mut oracle, der) {
                assert_eq!(go, parses, "{label}: Go's verdict");
            }
        };
        let mapped = |v4: [u8; 4]| [[0u8; 10].as_slice(), &[0xff, 0xff], &v4].concat();
        let v6 = |head: &[u8], tail: &[u8]| {
            let mut ip = [0u8; 16];
            ip[..head.len()].copy_from_slice(head);
            ip[16 - tail.len()..].copy_from_slice(tail);
            ip.to_vec()
        };

        let san = |names: &[Vec<u8>]| with_extension(SAN, der_tlv(0x30, &names.concat()));
        for (label, ip, parses) in [
            ("a SAN 192.0.2.1", vec![192, 0, 2, 1], true),
            ("a SAN ::1", v6(&[], &[1]), true),
            (
                "a SAN ::fffe:102:304",
                v6(&[], &[0xff, 0xfe, 1, 2, 3, 4]),
                true,
            ),
            ("a SAN ::1.2.3.4", v6(&[], &[1, 2, 3, 4]), true),
            ("a SAN ::ffff:1.2.3.4", mapped([1, 2, 3, 4]), false),
            ("a SAN ::ffff:0.0.0.0", mapped([0; 4]), false),
            ("a SAN of five bytes", vec![192, 0, 2, 1, 0], false),
            ("an empty SAN iPAddress", Vec::new(), false),
        ] {
            agrees(label, &san(&[der_tlv(0x87, &ip)]), parses);
        }
        agrees(
            "a mapped SAN after a DNS name",
            &san(&[
                der_tlv(0x82, b"client.example"),
                der_tlv(0x87, &mapped([1, 2, 3, 4])),
            ]),
            false,
        );

        // A constraint as the only subtree of the permitted [0] or the
        // excluded [1] subtrees.
        let constraint = |list: u8, base: Vec<u8>| {
            with_extension(
                NAME_CONSTRAINTS,
                der_tlv(0x30, &der_tlv(list, &der_tlv(0x30, &base))),
            )
        };
        let ones = |count: usize| {
            let mut mask = [0u8; 16];
            mask[..count].fill(0xff);
            mask.to_vec()
        };
        for (label, value, parses) in [
            ("10.0.0.0/8", vec![10, 0, 0, 0, 0xff, 0, 0, 0], true),
            ("0.0.0.0/0", vec![0; 8], true),
            (
                "10.0.0.0/255.0.255.0",
                vec![10, 0, 0, 0, 0xff, 0, 0xff, 0],
                false,
            ),
            (
                "fe80::/10",
                [v6(&[0xfe, 0x80], &[]), v6(&[0xff, 0xc0], &[])].concat(),
                true,
            ),
            (
                "::ffff:10.0.0.0/104",
                [mapped([10, 0, 0, 0]), ones(13)].concat(),
                false,
            ),
            (
                "::ffff:0.0.0.0/0",
                [mapped([0; 4]), vec![0; 16]].concat(),
                false,
            ),
            (
                "a constraint of nine bytes",
                vec![10, 0, 0, 0, 0xff, 0, 0, 0, 0],
                false,
            ),
            ("a constraint of sixteen bytes", ones(16), false),
        ] {
            agrees(
                &format!("permitted {label}"),
                &constraint(0xa0, der_tlv(0x87, &value)),
                parses,
            );
            agrees(
                &format!("excluded {label}"),
                &constraint(0xa1, der_tlv(0x87, &value)),
                parses,
            );
        }

        for (value, parses) in [
            (&b"a@example.com"[..], true),
            (b"example.com", true),
            (b".example.com", true),
            (b"", true),
            (b"a@", true),
            (b"\"a b\"@example.com", true),
            (b"a\\@b@example.com", true),
            (b"a@b@example.com", false),
            (b"\"a\"@b@example.com", false),
            (b"a..b@example.com", false),
            (b".a@example.com", false),
            (b"a@example.com.", false),
            (b"example..com", false),
            (b"example.com.", false),
            (b"a b@example.com", false),
            (b"\"a@example.com", false),
            (b"a\\\xe9@example.com", false),
        ] {
            let shown = String::from_utf8_lossy(value);
            agrees(
                &format!("a permitted rfc822Name constraint {shown}"),
                &constraint(0xa0, der_tlv(0x81, value)),
                parses,
            );
            agrees(
                &format!("an excluded rfc822Name constraint {shown}"),
                &constraint(0xa1, der_tlv(0x81, value)),
                parses,
            );
        }
    }

    /// rsaEncryption and sha256WithRSAEncryption identifiers' contents,
    /// each with its NULL parameters.
    const RSA_AI: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    const SHA256_RSA_AI: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
    ];

    /// An RSA algorithm that takes every signature, so that only the
    /// checks around it decide.
    #[derive(Debug)]
    struct EveryRsaSignature;

    impl rustls::pki_types::SignatureVerificationAlgorithm for EveryRsaSignature {
        fn verify_signature(
            &self,
            _public_key: &[u8],
            _message: &[u8],
            _signature: &[u8],
        ) -> Result<(), rustls::pki_types::InvalidSignature> {
            Ok(())
        }
        fn public_key_alg_id(&self) -> rustls::pki_types::AlgorithmIdentifier {
            rustls::pki_types::AlgorithmIdentifier::from_slice(RSA_AI)
        }
        fn signature_alg_id(&self) -> rustls::pki_types::AlgorithmIdentifier {
            rustls::pki_types::AlgorithmIdentifier::from_slice(SHA256_RSA_AI)
        }
    }

    /// The replay's signature check refuses an RSA parent whose
    /// public exponent Go's RSA verification refuses, above 2^31 - 1,
    /// though the provider, keeping ring's limit, would take it: with
    /// an algorithm that takes every signature, a CA with exponent
    /// 65537 or 2^31 - 1 signs and one with 2^31 + 1 or 2^32 + 1 does
    /// not.
    #[test]
    fn an_rsa_parent_past_gos_exponent_limit_signs_nothing() {
        const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
        let key = dcroxide_certgen::gentool::generate_key("P-256").expect("key");
        let ca = vec![der_extension(
            BASIC_CONSTRAINTS,
            true,
            &der_tlv(0x30, &der_tlv(0x01, &[0xff])),
        )];
        let mut child = CertParts::base(&key.public_bytes());
        child.inner = SHA256_RSA_AI.to_vec();
        child.outer = SHA256_RSA_AI.to_vec();
        let child_der = child.der();
        let child = ChainCandidate::parse(&child_der).expect("the child");
        let algorithms: [&'static dyn rustls::pki_types::SignatureVerificationAlgorithm; 1] =
            [&EveryRsaSignature];
        for (exponent, signs) in [
            (&[0x01, 0x00, 0x01][..], true),
            (&[0x7f, 0xff, 0xff, 0xff], true),
            (&[0x00, 0x80, 0x00, 0x00, 0x01], false),
            (&[0x01, 0x00, 0x00, 0x00, 0x01], false),
        ] {
            let rsa_key = der_tlv(
                0x30,
                &[der_tlv(0x02, &[0x00, 0xc1, 0x05]), der_tlv(0x02, exponent)].concat(),
            );
            let mut parent = CertParts::base(&key.public_bytes());
            parent.spki = der_tlv(
                0x30,
                &[
                    der_tlv(0x30, RSA_AI),
                    der_tlv(0x03, &[&[0u8][..], &rsa_key].concat()),
                ]
                .concat(),
            );
            parent.extensions = ca.clone();
            let parent_der = parent.der();
            let parent = ChainCandidate::parse(&parent_der).expect("the parent");
            assert_eq!(
                check_signature_from(&child, &parent, &algorithms),
                signs,
                "exponent {exponent:02x?}"
            );
        }
    }

    /// The exponent rule itself.
    #[test]
    fn an_rsa_exponent_past_gos_limit_signs_nothing() {
        let key = |exponent: &[u8]| {
            der_tlv(
                0x30,
                &[der_tlv(0x02, &[0x00, 0xc1, 0x05]), der_tlv(0x02, exponent)].concat(),
            )
        };
        assert!(go_rsa_exponent_fits(&key(&[0x01, 0x00, 0x01])), "65537");
        assert!(
            go_rsa_exponent_fits(&key(&[0x7f, 0xff, 0xff, 0xff])),
            "2^31 - 1"
        );
        assert!(
            !go_rsa_exponent_fits(&key(&[0x00, 0x80, 0x00, 0x00, 0x01])),
            "2^31 + 1"
        );
        assert!(
            !go_rsa_exponent_fits(&key(&[0x01, 0x00, 0x00, 0x00, 0x01])),
            "2^32 + 1"
        );
        assert!(!go_rsa_exponent_fits(&key(&[0xff])), "a negative exponent");
        assert!(!go_rsa_exponent_fits(&der_tlv(0x30, &[])), "no fields");
    }

    /// Go's verdict on a client chain from the oracle's
    /// `x509_verify_client`.
    struct GoVerdict {
        /// `"ok"`, or the text of Go's refusal.
        verdict: String,
        /// Whether that Go charges a candidate before `alreadyInChain`
        /// and the missing-key check, as the verifier does.  Of the
        /// toolchains checked, go1.24.13, go1.25.4 and go1.26.0 charge
        /// after them, and go1.25.14, go1.26.2 and later and go1.27 first;
        /// go1.26.1 and the 1.25 point release between were not checked,
        /// and count as charging after.
        charges_first: bool,
    }

    /// Go's verdict on a client chain, `None` without an oracle.  A Go
    /// version that cannot be read fails the test under
    /// `DCROXIDE_REQUIRE_ORACLE`, and is otherwise taken as no oracle.
    fn go_client_verdict(
        oracle: &mut Option<dcroxide_testutil::Oracle>,
        roots: &[&[u8]],
        leaf: &[u8],
        sent: &[&[u8]],
        now: u64,
    ) -> Option<GoVerdict> {
        let hex = |der: &[u8]| der.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let list = |ders: &[&[u8]]| {
            ders.iter()
                .map(|der| format!("\"{}\"", hex(der)))
                .collect::<Vec<_>>()
                .join(",")
        };
        let request = format!(
            r#"{{"roots":[{}],"leaf":"{}","intermediates":[{}],"time":{now}}}"#,
            list(roots),
            hex(leaf),
            list(sent)
        );
        let response = oracle
            .as_mut()?
            .call("x509_verify_client", request.as_bytes());
        let result = response["result"]
            .as_str()
            .unwrap_or_else(|| panic!("the oracle's x509_verify_client answered {response}"));
        let version = response["go_version"].as_str().unwrap_or_default();
        let Some((minor, patch)) = go_version_numbers(version) else {
            assert!(
                std::env::var_os("DCROXIDE_REQUIRE_ORACLE").is_none(),
                "the oracle's Go version {version:?} cannot be read"
            );
            return None;
        };
        Some(GoVerdict {
            verdict: result
                .strip_prefix("refused: ")
                .unwrap_or(result)
                .to_string(),
            charges_first: minor >= 27
                || (minor == 26 && patch >= 2)
                || (minor == 25 && patch >= 14),
        })
    }

    /// The minor and patch numbers of a `runtime.Version()` string, from
    /// its first word that opens `go1.`: `go1.27.1-X:nodwarf5` gives
    /// (27, 1), and a development build's `devel go1.28-abcdef ...` gives
    /// (28, 0).
    fn go_version_numbers(version: &str) -> Option<(u32, u32)> {
        let word = version
            .split_whitespace()
            .find_map(|w| w.strip_prefix("go1."))?;
        let mut numbers = word.split(|c: char| !c.is_ascii_digit());
        let minor = numbers.next()?.parse().ok()?;
        let patch = if word[word
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(word.len())..]
            .starts_with('.')
        {
            numbers.next()?.parse().ok()?
        } else {
            0
        };
        Some((minor, patch))
    }

    /// The oracle's Go version strings read as their release numbers.
    #[test]
    fn go_version_strings_read_as_numbers() {
        for (version, want) in [
            ("go1.27.1", Some((27, 1))),
            ("go1.27.1-X:nodwarf5", Some((27, 1))),
            ("go1.27.1-foo X:bar", Some((27, 1))),
            ("go1.26", Some((26, 0))),
            (
                "devel go1.28-abcdef Mon Oct 26 00:00:00 2026 +0000",
                Some((28, 0)),
            ),
            ("go1.25.14", Some((25, 14))),
            ("weekly", None),
            ("", None),
        ] {
            assert_eq!(go_version_numbers(version), want, "{version:?}");
        }
    }

    /// Go's chain search is replayed before webpki's, and its budget of
    /// 100 signature checks charges every candidate it considers (Go's
    /// `buildChains`, the same in 1.26.2, 1.27.1 and 1.27.3): certificates
    /// named as the leaf's issuer that lead to no root cost Go a check each
    /// and webpki none, so 98 of them sent ahead of the real intermediate
    /// leave room for the chain, the intermediate's check being the 99th
    /// and the root's the 100th, and 99 do not, where webpki alone accepted
    /// both.  The candidates go in Go's order: those whose subject key
    /// identifier matches the child's authority key identifier first, then
    /// those where only one of the two is present, then the rest; so the
    /// same flood is no obstacle to an intermediate whose identifier
    /// matches and the whole obstacle to one that comes after the matching
    /// decoys.  Each verdict is the reference Go's, go1.27.3's, as it is
    /// 1.26.2's, and is compared with the oracle's Go, of whatever release,
    /// where it runs.
    #[test]
    fn gos_signature_budget_charges_every_candidate() {
        use dcroxide_certgen::gentool::generate_key;
        use rustls::pki_types::CertificateDer;
        use rustls::server::danger::ClientCertVerifier;
        const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
        const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
        const SKI: &[u8] = &[0x55, 0x1d, 0x0e];
        const AKI: &[u8] = &[0x55, 0x1d, 0x23];
        let secs = 1_790_000_000u64;
        let now = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(secs));
        let mut oracle = dcroxide_testutil::oracle_or_skip();
        let key = || generate_key("P-256").expect("key");
        let (root_key, int_key, leaf_key, decoy_key) = (key(), key(), key(), key());
        let ca = || {
            vec![
                der_extension(
                    BASIC_CONSTRAINTS,
                    true,
                    &der_tlv(0x30, &der_tlv(0x01, &[0xff])),
                ),
                der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x02, 0x84])),
            ]
        };
        let ski = |id: u8| der_extension(SKI, false, &der_tlv(0x04, &[id; 20]));
        let aki = |id: u8| der_extension(AKI, false, &der_tlv(0x30, &der_tlv(0x80, &[id; 20])));
        let root = signed_p256_certificate(1, "root", &root_key, "root", &root_key, &ca());
        let verify = |leaf: &[u8], sent: &[&[u8]]| {
            let verifier =
                GoClientCertVerifier::from_pem(&certificate_pem(&root)).expect("verifier");
            let sent_ders: Vec<_> = sent.iter().map(|der| CertificateDer::from(*der)).collect();
            verifier
                .verify_client_cert(&CertificateDer::from(leaf), &sent_ders, now)
                .map(|_| ())
        };
        let mut check = |label: &str, leaf: &[u8], sent: &[&[u8]], go_accepts: bool| {
            let got = verify(leaf, sent);
            assert_eq!(got.is_ok(), go_accepts, "{label}: {got:?}");
            if let Err(err) = &got
                && label.ends_with("limit")
            {
                assert!(
                    crate::server::go_error_text_for_tests(err).ends_with(
                        "x509: signature check attempts limit reached while verifying certificate chain"
                    ),
                    "{label}: {err:?}"
                );
            }
            if let Some(GoVerdict { verdict, .. }) =
                go_client_verdict(&mut oracle, &[&root], leaf, sent, secs)
            {
                assert_eq!(verdict == "ok", go_accepts, "{label}: Go says {verdict}");
                if label.ends_with("limit") {
                    assert_eq!(
                        verdict,
                        "x509: signature check attempts limit reached while verifying certificate chain",
                        "{label}"
                    );
                }
            }
        };

        // Decoys named `int`, under a key of their own and issued by a
        // name no pool certificate holds.  Serials stay below 0x80.
        let decoys = |extensions: &dyn Fn() -> Vec<Vec<u8>>| -> Vec<Vec<u8>> {
            (0..120u8)
                .map(|i| {
                    signed_p256_certificate(
                        6 + i,
                        "int",
                        &decoy_key,
                        "nowhere",
                        &decoy_key,
                        &extensions(),
                    )
                })
                .collect()
        };
        let plain = decoys(&ca);
        let int = signed_p256_certificate(2, "int", &int_key, "root", &root_key, &ca());
        let leaf = signed_p256_certificate(3, "leaf", &leaf_key, "int", &int_key, &[]);
        let ahead = |decoys: &[Vec<u8>], n: usize, int: &[u8]| -> Vec<Vec<u8>> {
            let mut sent: Vec<Vec<u8>> = decoys[..n].to_vec();
            sent.push(int.to_vec());
            sent
        };
        let refs = |sent: &[Vec<u8>]| -> Vec<Vec<u8>> { sent.to_vec() };
        for (n, accepts) in [(98, true), (99, false)] {
            let sent = refs(&ahead(&plain, n, &int));
            let sent: Vec<&[u8]> = sent.iter().map(Vec::as_slice).collect();
            let label = if accepts {
                format!("{n} decoys")
            } else {
                format!("{n} decoys: limit")
            };
            check(&label, &leaf, &sent, accepts);
        }

        // Key identifiers reorder the candidates.  The leaf names key 7 as
        // its authority's; an intermediate with that subject key
        // identifier goes before 120 decoys with another, or none.
        let leaf7 = signed_p256_certificate(4, "leaf", &leaf_key, "int", &int_key, &[aki(7)]);
        let int7 = signed_p256_certificate(
            2,
            "int",
            &int_key,
            "root",
            &root_key,
            &[ca(), vec![ski(7)]].concat(),
        );
        for (label, extensions) in [
            (
                "mismatched decoys",
                &(|| [ca(), vec![ski(8)]].concat()) as &dyn Fn() -> Vec<Vec<u8>>,
            ),
            ("decoys without an identifier", &ca),
        ] {
            let sent = ahead(&decoys(extensions), 120, &int7);
            let sent: Vec<&[u8]> = sent.iter().map(Vec::as_slice).collect();
            check(label, &leaf7, &sent, true);
        }
        // Decoys whose identifier matches go first, and the intermediate
        // without one after them.
        let matching = decoys(&|| [ca(), vec![ski(7)]].concat());
        for (n, accepts) in [(98, true), (99, false)] {
            let sent = ahead(&matching, n, &int);
            let sent: Vec<&[u8]> = sent.iter().map(Vec::as_slice).collect();
            let label = if accepts {
                format!("{n} matching decoys")
            } else {
                format!("{n} matching decoys: limit")
            };
            check(&label, &leaf7, &sent, accepts);
        }
    }

    /// More of how Go's candidate order and checks shape its budget, each
    /// verdict the reference Go's, go1.27.3's, as it is 1.26.2's, and,
    /// where the oracle runs, Go's own:
    /// - the one-identifier group goes before the mismatched one, and two
    ///   absent identifiers count as matching, so 99 decoys behind
    ///   either do not keep the chain from its first two checks;
    /// - the roots are searched before the sent certificates, so 100
    ///   decoys sent under the root's name cost nothing;
    /// - a candidate `isValid` refuses for its path length is not gone
    ///   into, so the subtree behind it costs nothing;
    /// - a candidate whose key algorithm Go does not know is charged
    ///   (from the Go releases that charge first), so 99 of them ahead
    ///   of the intermediate run the budget out, and 98 do not;
    /// - a certificate sent many times is one candidate;
    /// - intermediates the root signed whose key usage leaves out
    ///   certificate signing fail `CheckSignatureFrom`, and 50 of them
    ///   ahead of the right one stay within Go's budget; webpki, which
    ///   ignores key usage, would spend its own on their paths, so its
    ///   search runs over the chains Go built only;
    /// - forged copies of the intermediate sent ahead of it, which webpki
    ///   would try in the order sent, come after it in Go's order when
    ///   its identifier matches the leaf's.
    /// - an expired leaf is refused for its validity before any search,
    ///   however many decoys follow it.
    #[test]
    fn gos_candidate_order_and_checks_shape_its_budget() {
        use dcroxide_certgen::gentool::generate_key;
        use rustls::pki_types::CertificateDer;
        use rustls::server::danger::ClientCertVerifier;
        const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
        const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
        const SKI: &[u8] = &[0x55, 0x1d, 0x0e];
        const AKI: &[u8] = &[0x55, 0x1d, 0x23];
        let secs = 1_790_000_000u64;
        let now = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(secs));
        let mut oracle = dcroxide_testutil::oracle_or_skip();
        let key = || generate_key("P-256").expect("key");
        let (root_key, int_key, leaf_key, decoy_key, x_key, forger) =
            (key(), key(), key(), key(), key(), key());
        let constraints = |path_len: Option<u8>| {
            let mut content = der_tlv(0x01, &[0xff]);
            if let Some(path_len) = path_len {
                content.extend(der_tlv(0x02, &[path_len]));
            }
            der_extension(BASIC_CONSTRAINTS, true, &der_tlv(0x30, &content))
        };
        let ca = || {
            vec![
                constraints(None),
                der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x02, 0x84])),
            ]
        };
        let ski = |id: u8| der_extension(SKI, false, &der_tlv(0x04, &[id; 20]));
        let aki = |id: u8| der_extension(AKI, false, &der_tlv(0x30, &der_tlv(0x80, &[id; 20])));
        let root = signed_p256_certificate(1, "root", &root_key, "root", &root_key, &ca());
        let mut check = |label: &str,
                         leaf: &[u8],
                         sent: &[&[u8]],
                         go_accepts: bool,
                         needs_charge_first: bool| {
            let verifier =
                GoClientCertVerifier::from_pem(&certificate_pem(&root)).expect("verifier");
            let ders: Vec<_> = sent.iter().map(|der| CertificateDer::from(*der)).collect();
            let got = verifier
                .verify_client_cert(&CertificateDer::from(leaf), &ders, now)
                .map(|_| ());
            assert_eq!(got.is_ok(), go_accepts, "{label}: {got:?}");
            if let Some(go) = go_client_verdict(&mut oracle, &[&root], leaf, sent, secs)
                && (go.charges_first || !needs_charge_first)
            {
                assert_eq!(
                    go.verdict == "ok",
                    go_accepts,
                    "{label}: Go says {}",
                    go.verdict
                );
            }
            got
        };
        let decoys = |n: u8, name: &str, extensions: &dyn Fn() -> Vec<Vec<u8>>| -> Vec<Vec<u8>> {
            (0..n)
                .map(|i| {
                    signed_p256_certificate(
                        10 + i,
                        name,
                        &decoy_key,
                        "nowhere",
                        &decoy_key,
                        &extensions(),
                    )
                })
                .collect()
        };
        let refs = |certs: &[Vec<u8>]| -> Vec<Vec<u8>> { certs.to_vec() };
        let int = signed_p256_certificate(2, "int", &int_key, "root", &root_key, &ca());
        let leaf = signed_p256_certificate(3, "leaf", &leaf_key, "int", &int_key, &[]);
        let leaf7 = signed_p256_certificate(4, "leaf", &leaf_key, "int", &int_key, &[aki(7)]);
        let mismatched = decoys(99, "int", &|| [ca(), vec![ski(8)]].concat());

        let mut sent = refs(&mismatched);
        sent.push(int.clone());
        let sent: Vec<&[u8]> = sent.iter().map(Vec::as_slice).collect();
        let _ = check(
            "one identifier before a mismatch",
            &leaf7,
            &sent,
            true,
            false,
        );
        let _ = check("two absent identifiers match", &leaf, &sent, true, false);

        let by_root = signed_p256_certificate(5, "leaf", &leaf_key, "root", &root_key, &[]);
        let root_named = decoys(100, "root", &ca);
        let sent: Vec<&[u8]> = root_named.iter().map(Vec::as_slice).collect();
        let _ = check(
            "roots before the sent certificates",
            &by_root,
            &sent,
            true,
            false,
        );

        // leaf <- a <- x, where the x the client sends first allows no
        // intermediate below it and the second leads to the root.
        let a = signed_p256_certificate(6, "a", &int_key, "x", &x_key, &ca());
        let leaf_a = signed_p256_certificate(7, "leaf", &leaf_key, "a", &int_key, &[]);
        let x_bad = signed_p256_certificate(
            8,
            "x",
            &x_key,
            "y",
            &x_key,
            &[constraints(Some(0)), ca()[1].clone()],
        );
        let x_good = signed_p256_certificate(9, "x", &x_key, "root", &root_key, &ca());
        let y_named = decoys(97, "y", &ca);
        let mut sent: Vec<&[u8]> = vec![&a, &x_bad];
        sent.extend(y_named.iter().map(Vec::as_slice));
        sent.push(&x_good);
        let _ = check(
            "a candidate isValid refuses is not gone into",
            &leaf_a,
            &sent,
            true,
            false,
        );

        // Decoys under X25519, a key algorithm Go leaves without a key,
        // in go1.27.3, the reference, as in 1.26.2.
        let x25519 = |i: u8| {
            der_tlv(
                0x30,
                &[
                    der_tlv(0x30, &der_tlv(0x06, &[0x2b, 0x65, 0x6e])),
                    der_tlv(0x03, &[&[0u8][..], &[i; 32]].concat()),
                ]
                .concat(),
            )
        };
        let keyless: Vec<Vec<u8>> = (0..99u8)
            .map(|i| {
                signed_certificate_with_spki(
                    10 + i,
                    "int",
                    x25519(i),
                    "nowhere",
                    &decoy_key,
                    der_tlv(0x17, b"491231235959Z"),
                    &ca(),
                )
            })
            .collect();
        for (n, accepts) in [(98usize, true), (99, false)] {
            let mut sent: Vec<&[u8]> = keyless[..n].iter().map(Vec::as_slice).collect();
            sent.push(&int);
            let _ = check(&format!("{n} keyless decoys"), &leaf, &sent, accepts, true);
        }

        let one = decoys(1, "int", &ca);
        let mut sent: Vec<&[u8]> = vec![&one[0]; 99];
        sent.push(&int);
        let _ = check("a decoy sent 99 times", &leaf, &sent, true, false);

        // Intermediates the root signed, under int's name and key, whose
        // key usage is digital signature only.
        let sign_only: Vec<Vec<u8>> = (0..50u8)
            .map(|i| {
                signed_p256_certificate(
                    20 + i,
                    "int",
                    &int_key,
                    "root",
                    &root_key,
                    &[
                        constraints(None),
                        der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x07, 0x80])),
                    ],
                )
            })
            .collect();
        let mut sent: Vec<&[u8]> = sign_only.iter().map(Vec::as_slice).collect();
        sent.push(&int);
        let _ = check(
            "50 intermediates that may not sign",
            &leaf,
            &sent,
            true,
            false,
        );

        // Forged copies of int, signed by a key of the client's own, ahead
        // of the int whose identifier matches the leaf's.
        let forged: Vec<Vec<u8>> = (0..99u8)
            .map(|i| signed_p256_certificate(20 + i, "int", &int_key, "root", &forger, &ca()))
            .collect();
        let int7 = signed_p256_certificate(
            2,
            "int",
            &int_key,
            "root",
            &root_key,
            &[ca(), vec![ski(7)]].concat(),
        );
        let mut sent: Vec<&[u8]> = forged.iter().map(Vec::as_slice).collect();
        sent.push(&int7);
        let _ = check("99 forged copies ahead", &leaf7, &sent, true, false);

        let expired = signed_p256_certificate_until(
            9,
            "leaf",
            &leaf_key,
            "int",
            &int_key,
            der_tlv(0x17, b"250101000000Z"),
            &[],
        );
        let flood = decoys(100, "int", &ca);
        let mut sent: Vec<&[u8]> = flood.iter().map(Vec::as_slice).collect();
        sent.push(&int);
        let err = check("an expired leaf", &expired, &sent, false, false).expect_err("expired");
        assert!(
            matches!(
                err,
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::Expired
                        | rustls::CertificateError::ExpiredContext { .. }
                )
            ),
            "refused for its validity, not the budget: {err:?}"
        );
        if let Some(go) = go_client_verdict(&mut oracle, &[&root], &expired, &sent, secs) {
            assert!(
                go.verdict
                    .starts_with("x509: certificate has expired or is not yet valid"),
                "{}",
                go.verdict
            );
        }
    }

    /// A candidate Go's `alreadyInChain` passes over still costs a
    /// signature check (go1.27.3, the reference, and go1.26.2; go1.24.13,
    /// go1.25.4 and go1.26.0 counted it only after).  The leaf's issuer
    /// `a` and a `b` sign each other, and a second `a` under the same key
    /// leads to the root.  Go goes into the first `a`, then `b`, where
    /// both `a`s are already on the chain, then back to the decoys and
    /// the second `a`: with `d` decoys named `a` sent between `b` and the
    /// second `a`, the chain costs 6 + 2d checks, so 47 leave room and 48
    /// do not, where 1.24's count would have allowed 48 and webpki alone
    /// accepted both.
    #[test]
    fn a_candidate_already_on_the_chain_costs_a_check() {
        use dcroxide_certgen::gentool::generate_key;
        use rustls::pki_types::CertificateDer;
        use rustls::server::danger::ClientCertVerifier;
        const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
        const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
        let secs = 1_790_000_000u64;
        let now = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(secs));
        let mut oracle = dcroxide_testutil::oracle_or_skip();
        let key = || generate_key("P-256").expect("key");
        let (root_key, a_key, b_key, leaf_key, decoy_key) = (key(), key(), key(), key(), key());
        let ca = || {
            vec![
                der_extension(
                    BASIC_CONSTRAINTS,
                    true,
                    &der_tlv(0x30, &der_tlv(0x01, &[0xff])),
                ),
                der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x02, 0x84])),
            ]
        };
        let root = signed_p256_certificate(1, "root", &root_key, "root", &root_key, &ca());
        let a = signed_p256_certificate(2, "a", &a_key, "b", &b_key, &ca());
        let b = signed_p256_certificate(3, "b", &b_key, "a", &a_key, &ca());
        let a2 = signed_p256_certificate(4, "a", &a_key, "root", &root_key, &ca());
        let leaf = signed_p256_certificate(5, "leaf", &leaf_key, "a", &a_key, &[]);
        let decoys: Vec<Vec<u8>> = (0..48u8)
            .map(|i| signed_p256_certificate(10 + i, "a", &decoy_key, "nowhere", &decoy_key, &ca()))
            .collect();
        for (d, go_accepts) in [(47usize, true), (48, false)] {
            let mut sent: Vec<&[u8]> = vec![&a, &b];
            sent.extend(decoys[..d].iter().map(Vec::as_slice));
            sent.push(&a2);
            let verifier =
                GoClientCertVerifier::from_pem(&certificate_pem(&root)).expect("verifier");
            let ders: Vec<_> = sent.iter().map(|der| CertificateDer::from(*der)).collect();
            let got = verifier
                .verify_client_cert(&CertificateDer::from(leaf.as_slice()), &ders, now)
                .map(|_| ());
            assert_eq!(got.is_ok(), go_accepts, "{d} decoys: {got:?}");
            if let Some(go) = go_client_verdict(&mut oracle, &[&root], &leaf, &sent, secs) {
                // A Go that charges a candidate only after `alreadyInChain`
                // counts 4 + 2d checks, and accepts both.
                let go_should = if go.charges_first {
                    go_accepts
                } else {
                    d <= 48
                };
                assert_eq!(
                    go.verdict == "ok",
                    go_should,
                    "{d} decoys: Go says {}",
                    go.verdict
                );
            }
        }
    }

    /// webpki's search accepts only a path that is a chain Go's search
    /// built.  An intermediate whose extended key usage admits only server
    /// authentication makes Go's first chain, which its key usage check
    /// then drops; past 97 decoys the second intermediate, which admits
    /// client authentication, lies beyond Go's budget and makes no chain,
    /// so Go refuses where webpki alone found the second path.  With 96
    /// the second chain fits, and both accept.
    #[test]
    fn webpki_accepts_only_a_chain_gos_search_built() {
        use dcroxide_certgen::gentool::generate_key;
        use rustls::pki_types::CertificateDer;
        use rustls::server::danger::ClientCertVerifier;
        const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
        const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
        const EKU: &[u8] = &[0x55, 0x1d, 0x25];
        const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
        let secs = 1_790_000_000u64;
        let now = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(secs));
        let mut oracle = dcroxide_testutil::oracle_or_skip();
        let key = || generate_key("P-256").expect("key");
        let (root_key, int_key, leaf_key, decoy_key) = (key(), key(), key(), key());
        let ca = || {
            vec![
                der_extension(
                    BASIC_CONSTRAINTS,
                    true,
                    &der_tlv(0x30, &der_tlv(0x01, &[0xff])),
                ),
                der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x02, 0x84])),
            ]
        };
        let root = signed_p256_certificate(1, "root", &root_key, "root", &root_key, &ca());
        let server_only = signed_p256_certificate(
            2,
            "int",
            &int_key,
            "root",
            &root_key,
            &[
                ca(),
                vec![der_extension(
                    EKU,
                    false,
                    &der_tlv(0x30, &der_tlv(0x06, SERVER_AUTH)),
                )],
            ]
            .concat(),
        );
        let any_use = signed_p256_certificate(3, "int", &int_key, "root", &root_key, &ca());
        let leaf = signed_p256_certificate(4, "leaf", &leaf_key, "int", &int_key, &[]);
        let decoys: Vec<Vec<u8>> = (0..97u8)
            .map(|i| {
                signed_p256_certificate(10 + i, "int", &decoy_key, "nowhere", &decoy_key, &ca())
            })
            .collect();
        for (d, go_accepts) in [(96usize, true), (97, false)] {
            let mut sent: Vec<&[u8]> = vec![&server_only];
            sent.extend(decoys[..d].iter().map(Vec::as_slice));
            sent.push(&any_use);
            let verifier =
                GoClientCertVerifier::from_pem(&certificate_pem(&root)).expect("verifier");
            let ders: Vec<_> = sent.iter().map(|der| CertificateDer::from(*der)).collect();
            let got = verifier
                .verify_client_cert(&CertificateDer::from(leaf.as_slice()), &ders, now)
                .map(|_| ());
            assert_eq!(got.is_ok(), go_accepts, "{d} decoys: {got:?}");
            if let Some(GoVerdict { verdict, .. }) =
                go_client_verdict(&mut oracle, &[&root], &leaf, &sent, secs)
            {
                assert_eq!(verdict == "ok", go_accepts, "{d} decoys: Go says {verdict}");
            }
        }
    }

    /// A root signs a chain only when Go's `CheckSignatureFrom` lets it:
    /// a version 3 root without basic constraints, one whose basic
    /// constraints do not assert cA, and one whose key usage leaves out
    /// certificate signing sign nothing to Go, though webpki's trust
    /// anchors check none of it and accepted each.
    #[test]
    fn a_root_signs_only_as_gos_check_signature_from_allows() {
        use dcroxide_certgen::gentool::generate_key;
        use rustls::pki_types::CertificateDer;
        use rustls::server::danger::ClientCertVerifier;
        const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
        const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
        let secs = 1_790_000_000u64;
        let now = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(secs));
        let mut oracle = dcroxide_testutil::oracle_or_skip();
        let key = || generate_key("P-256").expect("key");
        let (root_key, leaf_key) = (key(), key());
        let constraints = |ca: bool| {
            der_extension(
                BASIC_CONSTRAINTS,
                true,
                &der_tlv(
                    0x30,
                    &if ca {
                        der_tlv(0x01, &[0xff])
                    } else {
                        Vec::new()
                    },
                ),
            )
        };
        let usage = |bits: &[u8]| der_extension(KEY_USAGE, true, &der_tlv(0x03, bits));
        let leaf = signed_p256_certificate(9, "leaf", &leaf_key, "root", &root_key, &[]);
        for (label, extensions, go_accepts) in [
            (
                "a CA root",
                vec![constraints(true), usage(&[0x02, 0x84])],
                true,
            ),
            ("a CA root without key usage", vec![constraints(true)], true),
            ("no basic constraints", vec![usage(&[0x02, 0x84])], false),
            (
                "cA not asserted",
                vec![constraints(false), usage(&[0x02, 0x84])],
                false,
            ),
            (
                "no certificate signing",
                vec![constraints(true), usage(&[0x07, 0x80])],
                false,
            ),
        ] {
            let root =
                signed_p256_certificate(1, "root", &root_key, "root", &root_key, &extensions);
            let verifier =
                GoClientCertVerifier::from_pem(&certificate_pem(&root)).expect("verifier");
            let got = verifier
                .verify_client_cert(&CertificateDer::from(leaf.as_slice()), &[], now)
                .map(|_| ());
            assert_eq!(got.is_ok(), go_accepts, "{label}: {got:?}");
            if let Some(GoVerdict { verdict, .. }) =
                go_client_verdict(&mut oracle, &[&root], &leaf, &[], secs)
            {
                assert_eq!(verdict == "ok", go_accepts, "{label}: Go says {verdict}");
            }
        }
    }

    /// An ML-DSA key of the set at `set` in [`ML_DSA_KEYS`], from a seed of
    /// 32 `seed` bytes: its PKCS#8 seed form, as Go's
    /// `MarshalPKCS8PrivateKey` writes it, and its subject public key info.
    fn ml_dsa_test_key(set: usize, seed: u8) -> (Vec<u8>, Vec<u8>) {
        let (oid, _) = ML_DSA_KEYS[set];
        let pkcs8 = der_tlv(
            0x30,
            &[
                der_tlv(0x02, &[0]),
                der_tlv(0x30, &der_tlv(0x06, oid)),
                der_tlv(0x04, &der_tlv(0x80, &[seed; 32])),
            ]
            .concat(),
        );
        let spki = dcroxide_tlscrypto::sign::load_der(&pkcs8)
            .expect("an ML-DSA key")
            .public_key()
            .expect("its public key")
            .as_ref()
            .to_vec();
        (pkcs8, spki)
    }

    /// The TLS signature scheme of the ML-DSA set at `set`.
    const ML_DSA_SCHEMES: [rustls::SignatureScheme; 3] = [
        rustls::SignatureScheme::ML_DSA_44,
        rustls::SignatureScheme::ML_DSA_65,
        rustls::SignatureScheme::ML_DSA_87,
    ];

    /// A certificate for `spki`, valid from 2024 through 2049 and carrying
    /// `extensions`, issued by `issuer` and signed by the PKCS#8 key
    /// `issuer_key` under `scheme`, whose signature an X.509 signature
    /// carries as it is, naming `algorithm`, an AlgorithmIdentifier's
    /// contents, as its signature algorithm.
    #[allow(clippy::too_many_arguments)]
    fn certificate_signed_by(
        serial: u8,
        subject: &str,
        spki: Vec<u8>,
        issuer: &str,
        issuer_key: &[u8],
        scheme: rustls::SignatureScheme,
        algorithm: &[u8],
        extensions: &[Vec<u8>],
    ) -> Vec<u8> {
        const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
        let name = |cn: &str| {
            let attribute = [der_tlv(0x06, COMMON_NAME), der_tlv(0x0c, cn.as_bytes())].concat();
            der_tlv(0x30, &der_tlv(0x31, &der_tlv(0x30, &attribute)))
        };
        let algorithm = der_tlv(0x30, algorithm);
        let validity = [
            der_tlv(0x17, b"240101000000Z"),
            der_tlv(0x17, b"491231235959Z"),
        ]
        .concat();
        let mut tbs = [
            der_tlv(0xa0, &der_tlv(0x02, &[2])),
            der_tlv(0x02, &[serial]),
            algorithm.clone(),
            name(issuer),
            der_tlv(0x30, &validity),
            name(subject),
            spki,
        ]
        .concat();
        if !extensions.is_empty() {
            tbs.extend(der_tlv(0xa3, &der_tlv(0x30, &extensions.concat())));
        }
        let tbs = der_tlv(0x30, &tbs);
        let signature = dcroxide_tlscrypto::sign::load_der(issuer_key)
            .expect("signing key")
            .choose_scheme(&[scheme])
            .expect("scheme")
            .sign(&tbs)
            .expect("sign");
        der_tlv(
            0x30,
            &[
                tbs,
                algorithm,
                der_tlv(0x03, &[&[0u8][..], &signature].concat()),
            ]
            .concat(),
        )
    }

    /// The subject public key info of a P-256 key.
    fn p256_spki(key: &dcroxide_certgen::gentool::ToolKeyPair) -> Vec<u8> {
        // id-ecPublicKey and prime256v1.
        const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
        const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
        der_tlv(
            0x30,
            &[
                der_tlv(
                    0x30,
                    &[der_tlv(0x06, EC_PUBLIC_KEY), der_tlv(0x06, P256)].concat(),
                ),
                der_tlv(0x03, &[&[0u8][..], &key.public_bytes()].concat()),
            ]
            .concat(),
        )
    }

    /// A CA's critical basic constraints, asserting cA, and its critical
    /// key usage, digitalSignature with keyCertSign.
    fn ca_extensions() -> Vec<Vec<u8>> {
        const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
        const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
        vec![
            der_extension(
                BASIC_CONSTRAINTS,
                true,
                &der_tlv(0x30, &der_tlv(0x01, &[0xff])),
            ),
            der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x02, 0x84])),
        ]
    }

    /// A handshake signature as rustls hands it to a verifier, which only
    /// rustls builds: decoded from its encoding.
    fn digitally_signed(
        scheme: rustls::SignatureScheme,
        signature: &[u8],
    ) -> rustls::DigitallySignedStruct {
        use rustls::internal::msgs::codec::{Codec, Reader};
        let len = u16::try_from(signature.len()).expect("a short signature");
        let encoded = [
            &u16::from(scheme).to_be_bytes()[..],
            &len.to_be_bytes(),
            signature,
        ]
        .concat();
        rustls::DigitallySignedStruct::read(&mut Reader::init(&encoded)).expect("a signature")
    }

    /// An ML-DSA key in a certificate is read as Go 1.27.3's parser reads
    /// it (`crypto/x509/parser.go:366-374`): with no parameters and at its
    /// set's length, 1312, 1952 or 2592 bytes, and refused otherwise, one
    /// byte short or long, empty, at another set's length, or with NULL or
    /// other parameters.  A refused certificate ends the handshake when the
    /// client sends it, and is skipped in the client CA file, as Go's
    /// `ParseCertificate` refuses it.  Each verdict is Go's, and is
    /// compared with the oracle's where it runs Go 1.27 or later.
    #[test]
    fn ml_dsa_keys_in_certificates_follow_gos_parser() {
        use dcroxide_certgen::gentool::generate_key;
        use rustls::pki_types::CertificateDer;
        use rustls::server::danger::ClientCertVerifier;
        let now = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(1_790_000_000));
        let mut oracle = dcroxide_testutil::ml_dsa_oracle_or_skip();
        let root_key = generate_key("P-256").expect("key");
        let leaf_key = generate_key("P-256").expect("key");
        let root =
            signed_p256_certificate(1, "root", &root_key, "root", &root_key, &ca_extensions());
        let leaf = signed_p256_certificate(2, "leaf", &leaf_key, "root", &root_key, &[]);
        let not_after = || der_tlv(0x17, b"491231235959Z");
        for (set, &(oid, len)) in ML_DSA_KEYS.iter().enumerate() {
            let spki = |parameters: &[u8], key_len: usize| {
                der_tlv(
                    0x30,
                    &[
                        der_tlv(0x30, &[&der_tlv(0x06, oid)[..], parameters].concat()),
                        der_tlv(0x03, &[vec![0u8], vec![0x5a; key_len]].concat()),
                    ]
                    .concat(),
                )
            };
            let other = ML_DSA_KEYS[(set + 1) % 3].1;
            for (label, spki, go_parses_it) in [
                ("the set's length", spki(&[], len), true),
                ("one byte short", spki(&[], len - 1), false),
                ("one byte long", spki(&[], len + 1), false),
                ("empty", spki(&[], 0), false),
                ("another set's length", spki(&[], other), false),
                ("NULL parameters", spki(&[0x05, 0x00], len), false),
                (
                    "an OID as parameters",
                    spki(&der_tlv(0x06, oid), len),
                    false,
                ),
            ] {
                let what = format!("{:?}, {label}", ML_DSA_SCHEMES[set]);
                let named = signed_certificate_with_spki(
                    3,
                    "named",
                    spki.clone(),
                    "root",
                    &root_key,
                    not_after(),
                    &[],
                );
                assert_eq!(CertFacts::parse(&named).is_some(), go_parses_it, "{what}");
                if let Some(go) = go_parses(&mut oracle, &named) {
                    assert_eq!(go, go_parses_it, "{what}: Go");
                }
                let authority = signed_certificate_with_spki(
                    4,
                    "authority",
                    spki,
                    "root",
                    &root_key,
                    not_after(),
                    &ca_extensions(),
                );
                let verifier =
                    GoClientCertVerifier::from_pem(&certificate_pem(&root)).expect("verifier");
                let got = verifier.verify_client_cert(
                    &CertificateDer::from(leaf.as_slice()),
                    &[CertificateDer::from(authority.as_slice())],
                    now,
                );
                if go_parses_it {
                    got.expect("an unused intermediate Go parses");
                } else {
                    assert!(
                        matches!(
                            got,
                            Err(rustls::Error::InvalidCertificate(
                                rustls::CertificateError::BadEncoding
                            ))
                        ),
                        "{what}: sent {got:?}"
                    );
                }
                assert_eq!(
                    GoClientCertVerifier::from_pem(&certificate_pem(&authority)).is_ok(),
                    go_parses_it,
                    "{what}: in the client CA file"
                );
            }
        }
    }

    /// Client chains with ML-DSA keys verify as Go 1.27.3's `Verify`
    /// verifies them (`crypto/x509/x509.go:1115-1136`): an ML-DSA root,
    /// intermediate or leaf of each set, mixed with P-256 ones, and refused
    /// for a signature algorithm of another set than the key's, for
    /// parameters on an ML-DSA signature algorithm, on the leaf or on an
    /// intermediate (`x509.go:433-444`), for a signature that does not
    /// verify, and under a root of the wrong length, which the client CA
    /// file skips.  Each verdict is Go's, and is compared with the
    /// oracle's where it runs Go 1.27 or later.
    #[test]
    fn ml_dsa_client_chains_verify_as_go_verifies() {
        use dcroxide_certgen::gentool::generate_key;
        use rustls::pki_types::CertificateDer;
        use rustls::server::danger::ClientCertVerifier;
        let secs = 1_790_000_000u64;
        let now = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(secs));
        let mut oracle = dcroxide_testutil::ml_dsa_oracle_or_skip();
        let oid = |set: usize| der_tlv(0x06, ML_DSA_KEYS[set].0);
        let (ml44, ml44_spki) = ml_dsa_test_key(0, 0x44);
        let (ml65, ml65_spki) = ml_dsa_test_key(1, 0x65);
        let (_, ml87_spki) = ml_dsa_test_key(2, 0x87);
        let p256 = generate_key("P-256").expect("key");
        let p256_key = p256.marshal_pkcs8().expect("pkcs8");
        let leaf_key = generate_key("P-256").expect("key");
        // ecdsa-with-SHA256.
        let ecdsa = der_tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);
        let ecdsa_scheme = rustls::SignatureScheme::ECDSA_NISTP256_SHA256;
        let ca = ca_extensions();
        let ml_root = certificate_signed_by(
            1,
            "ml-root",
            ml44_spki.clone(),
            "ml-root",
            &ml44,
            ML_DSA_SCHEMES[0],
            &oid(0),
            &ca,
        );
        let p256_root = certificate_signed_by(
            2,
            "p256-root",
            p256_spki(&p256),
            "p256-root",
            &p256_key,
            ecdsa_scheme,
            &ecdsa,
            &ca,
        );
        let ml_int = certificate_signed_by(
            3,
            "ml-int",
            ml65_spki.clone(),
            "ml-root",
            &ml44,
            ML_DSA_SCHEMES[0],
            &oid(0),
            &ca,
        );
        let ml_int_under_p256 = certificate_signed_by(
            4,
            "ml-int",
            ml65_spki.clone(),
            "p256-root",
            &p256_key,
            ecdsa_scheme,
            &ecdsa,
            &ca,
        );
        let null = |set: usize| [oid(set), vec![0x05, 0x00]].concat();
        let ml_int_null = certificate_signed_by(
            5,
            "ml-int",
            ml65_spki.clone(),
            "ml-root",
            &ml44,
            ML_DSA_SCHEMES[0],
            &null(0),
            &ca,
        );
        let ml87_leaf = |serial: u8, issuer: &str, key: &[u8], set: usize, algorithm: &[u8]| {
            certificate_signed_by(
                serial,
                "leaf",
                ml87_spki.clone(),
                issuer,
                key,
                ML_DSA_SCHEMES[set],
                algorithm,
                &[],
            )
        };
        let p256_leaf_under_ml_int = certificate_signed_by(
            6,
            "leaf",
            p256_spki(&leaf_key),
            "ml-int",
            &ml65,
            ML_DSA_SCHEMES[1],
            &oid(1),
            &[],
        );
        let ml44_leaf_under_p256 = certificate_signed_by(
            7,
            "leaf",
            ml44_spki.clone(),
            "p256-root",
            &p256_key,
            ecdsa_scheme,
            &ecdsa,
            &[],
        );
        let mut flipped = ml87_leaf(8, "ml-root", &ml44, 0, &oid(0));
        let last = flipped.len() - 1;
        flipped[last] ^= 0x01;
        // The ML-DSA-44 root with NULL parameters on its key, which the
        // client CA file skips.
        let with_parameters = |spki: &[u8], set: usize| {
            let mut reader = DerReader::new(DerReader::new(spki).read_tag(0x30).expect("an SPKI"));
            reader.read_tag(0x30).expect("its algorithm");
            let (_, _, bits) = reader.read_raw(0x03).expect("its key");
            der_tlv(0x30, &[der_tlv(0x30, &null(set)), bits.to_vec()].concat())
        };
        let skipped_root = certificate_signed_by(
            13,
            "ml-root",
            with_parameters(&ml44_spki, 0),
            "ml-root",
            &ml44,
            ML_DSA_SCHEMES[0],
            &oid(0),
            &ca,
        );
        for (label, roots, leaf, sent, go_accepts) in [
            (
                "an ML-DSA-87 leaf under an ML-DSA-44 root",
                vec![&ml_root],
                ml87_leaf(9, "ml-root", &ml44, 0, &oid(0)),
                vec![],
                true,
            ),
            (
                "a P-256 leaf under an ML-DSA-65 intermediate under an ML-DSA-44 root",
                vec![&ml_root],
                p256_leaf_under_ml_int.clone(),
                vec![&ml_int],
                true,
            ),
            (
                "an ML-DSA-87 leaf under an ML-DSA-65 intermediate under a P-256 root",
                vec![&p256_root],
                ml87_leaf(10, "ml-int", &ml65, 1, &oid(1)),
                vec![&ml_int_under_p256],
                true,
            ),
            (
                "an ML-DSA-44 leaf under a P-256 root",
                vec![&p256_root],
                ml44_leaf_under_p256.clone(),
                vec![],
                true,
            ),
            (
                "a signature naming ML-DSA-65 by an ML-DSA-44 key",
                vec![&ml_root],
                ml87_leaf(11, "ml-root", &ml44, 0, &oid(1)),
                vec![],
                false,
            ),
            (
                "NULL parameters on the leaf's ML-DSA signature algorithm",
                vec![&ml_root],
                ml87_leaf(12, "ml-root", &ml44, 0, &null(0)),
                vec![],
                false,
            ),
            (
                "NULL parameters on the intermediate's ML-DSA signature algorithm",
                vec![&ml_root],
                p256_leaf_under_ml_int.clone(),
                vec![&ml_int_null],
                false,
            ),
            (
                "an ML-DSA signature with a bit flipped",
                vec![&ml_root],
                flipped.clone(),
                vec![],
                false,
            ),
            (
                "an ML-DSA root with parameters on its key",
                vec![&skipped_root, &p256_root],
                ml87_leaf(14, "ml-root", &ml44, 0, &oid(0)),
                vec![],
                false,
            ),
        ] {
            let pem: Vec<u8> = roots
                .iter()
                .flat_map(|root| certificate_pem(root))
                .collect();
            let verifier = GoClientCertVerifier::from_pem(&pem).expect("verifier");
            let ders: Vec<_> = sent
                .iter()
                .map(|der| CertificateDer::from(der.as_slice()))
                .collect();
            let got = verifier
                .verify_client_cert(&CertificateDer::from(leaf.as_slice()), &ders, now)
                .map(|_| ());
            assert_eq!(got.is_ok(), go_accepts, "{label}: {got:?}");
            let roots: Vec<&[u8]> = roots.iter().map(|root| root.as_slice()).collect();
            let sent: Vec<&[u8]> = sent.iter().map(|der| der.as_slice()).collect();
            if let Some(GoVerdict { verdict, .. }) =
                go_client_verdict(&mut oracle, &roots, &leaf, &sent, secs)
            {
                assert_eq!(verdict == "ok", go_accepts, "{label}: Go says {verdict}");
            }
        }
    }

    /// A candidate whose ML-DSA signature verifies is gone into, as Go
    /// 1.27.3's chain search goes into it, at the one check of Go's budget
    /// of 100: certificates named as the leaf's issuer that hold the
    /// ML-DSA-65 key that signed it and lead to no root each verify the
    /// leaf's signature, and 98 of them sent ahead of the real intermediate
    /// leave room for the chain where 99 run the budget out, as the P-256
    /// decoys of `gos_signature_budget_charges_every_candidate`, whose
    /// signatures fail, do.  Each verdict is Go's, and is compared with the
    /// oracle's where it runs Go 1.27 or later.
    #[test]
    fn verified_ml_dsa_candidates_spend_gos_budget() {
        use dcroxide_certgen::gentool::generate_key;
        use rustls::pki_types::CertificateDer;
        use rustls::server::danger::ClientCertVerifier;
        const LIMIT: &str =
            "x509: signature check attempts limit reached while verifying certificate chain";
        let secs = 1_790_000_000u64;
        let now = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(secs));
        let mut oracle = dcroxide_testutil::ml_dsa_oracle_or_skip();
        let (ml65, ml65_spki) = ml_dsa_test_key(1, 0x65);
        let p256 = generate_key("P-256").expect("key");
        let p256_key = p256.marshal_pkcs8().expect("pkcs8");
        let leaf_key = generate_key("P-256").expect("key");
        // ecdsa-with-SHA256.
        let ecdsa = der_tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);
        let ecdsa_scheme = rustls::SignatureScheme::ECDSA_NISTP256_SHA256;
        let ca = ca_extensions();
        let by_root = |serial: u8, subject: &str, spki: Vec<u8>, issuer: &str| {
            certificate_signed_by(
                serial,
                subject,
                spki,
                issuer,
                &p256_key,
                ecdsa_scheme,
                &ecdsa,
                &ca,
            )
        };
        let root = by_root(1, "root", p256_spki(&p256), "root");
        let int = by_root(2, "int", ml65_spki.clone(), "root");
        let leaf = certificate_signed_by(
            3,
            "leaf",
            p256_spki(&leaf_key),
            "int",
            &ml65,
            ML_DSA_SCHEMES[1],
            &der_tlv(0x06, ML_DSA_KEYS[1].0),
            &[],
        );
        // The intermediate's name and key, issued by a name no certificate
        // holds.  Serials stay below 0x80.
        let decoys: Vec<Vec<u8>> = (0..99u8)
            .map(|i| by_root(4 + i, "int", ml65_spki.clone(), "nowhere"))
            .collect();
        let verifier = GoClientCertVerifier::from_pem(&certificate_pem(&root)).expect("verifier");
        for (n, go_accepts) in [(98, true), (99, false)] {
            let mut sent: Vec<&[u8]> = decoys[..n].iter().map(Vec::as_slice).collect();
            sent.push(&int);
            let ders: Vec<_> = sent.iter().map(|der| CertificateDer::from(*der)).collect();
            let got = verifier
                .verify_client_cert(&CertificateDer::from(leaf.as_slice()), &ders, now)
                .map(|_| ());
            assert_eq!(got.is_ok(), go_accepts, "{n} decoys: {got:?}");
            if let Err(err) = &got {
                assert!(
                    crate::server::go_error_text_for_tests(err).ends_with(LIMIT),
                    "{n} decoys: {err:?}"
                );
            }
            if let Some(GoVerdict { verdict, .. }) =
                go_client_verdict(&mut oracle, &[&root], &leaf, &sent, secs)
            {
                let want = if go_accepts { "ok" } else { LIMIT };
                assert_eq!(verdict, want, "{n} decoys: Go");
            }
        }
    }

    /// A client key is sorted by its subject public key info's algorithm
    /// as Go's `crypto/tls` sorts it, and fits in TLS 1.3 the schemes
    /// Go's `signatureSchemesForPublicKey` gives it
    /// (`crypto/tls/auth.go:208-255`): an ECDSA key on P-256, P-384 or
    /// P-521 its curve's one scheme, one on another curve or none named
    /// no scheme, an Ed25519 or ML-DSA key its own, an RSA key every RSA
    /// scheme; an algorithm Go gives no key, or an element that does not
    /// parse, is no client key.
    #[test]
    fn client_keys_fit_the_tls13_schemes_go_takes_from_them() {
        use rustls::SignatureScheme as S;
        let spki = |algorithm: Vec<u8>| {
            der_tlv(
                0x30,
                &[der_tlv(0x30, &algorithm), der_tlv(0x03, &[0, 4, 1, 2])].concat(),
            )
        };
        let ec = |curve: Option<&[u8]>| {
            let mut algorithm = der_tlv(0x06, EC_PUBLIC_KEY);
            if let Some(curve) = curve {
                algorithm.extend(der_tlv(0x06, curve));
            }
            spki(algorithm)
        };
        let all = [
            S::ECDSA_NISTP256_SHA256,
            S::ECDSA_NISTP384_SHA384,
            S::ECDSA_NISTP521_SHA512,
            S::ED25519,
            S::ML_DSA_44,
            S::ML_DSA_65,
            S::ML_DSA_87,
            S::RSA_PSS_SHA256,
            S::RSA_PSS_SHA384,
            S::RSA_PSS_SHA512,
            S::RSA_PKCS1_SHA256,
            S::RSA_PKCS1_SHA384,
            S::RSA_PKCS1_SHA512,
            S::ECDSA_SHA1_Legacy,
            S::RSA_PKCS1_SHA1,
        ];
        let rsa = &all[7..13];
        // What each case is, its key, its sort, the schemes it fits and
        // its Go type.
        type Case<'a> = (&'a str, Vec<u8>, Option<ClientKey>, &'a [S], &'a str);
        let cases: Vec<Case<'_>> = vec![
            (
                "P-256",
                ec(Some(ECDSA_CURVES[0].0)),
                Some(ClientKey::Ecdsa(Some(S::ECDSA_NISTP256_SHA256))),
                &all[0..1],
                "*ecdsa.PublicKey",
            ),
            (
                "P-384",
                ec(Some(ECDSA_CURVES[1].0)),
                Some(ClientKey::Ecdsa(Some(S::ECDSA_NISTP384_SHA384))),
                &all[1..2],
                "*ecdsa.PublicKey",
            ),
            (
                "P-521",
                ec(Some(ECDSA_CURVES[2].0)),
                Some(ClientKey::Ecdsa(Some(S::ECDSA_NISTP521_SHA512))),
                &all[2..3],
                "*ecdsa.PublicKey",
            ),
            (
                "P-224",
                ec(Some(GO_X509_CURVES[0])),
                Some(ClientKey::Ecdsa(None)),
                &[],
                "*ecdsa.PublicKey",
            ),
            (
                "secp256k1",
                ec(Some(&[0x2b, 0x81, 0x04, 0x00, 0x0a])),
                Some(ClientKey::Ecdsa(None)),
                &[],
                "*ecdsa.PublicKey",
            ),
            (
                "no curve",
                ec(None),
                Some(ClientKey::Ecdsa(None)),
                &[],
                "*ecdsa.PublicKey",
            ),
            (
                "Ed25519",
                spki(der_tlv(0x06, ED25519_KEY)),
                Some(ClientKey::Ed25519),
                &all[3..4],
                "ed25519.PublicKey",
            ),
            (
                "RSA",
                spki([der_tlv(0x06, RSA_ENCRYPTION), der_tlv(0x05, &[])].concat()),
                Some(ClientKey::Rsa),
                rsa,
                "*rsa.PublicKey",
            ),
            (
                "ML-DSA-44",
                spki(der_tlv(0x06, ML_DSA_KEYS[0].0)),
                Some(ClientKey::MlDsa(S::ML_DSA_44)),
                &all[4..5],
                "*mldsa.PublicKey",
            ),
            (
                "ML-DSA-65",
                spki(der_tlv(0x06, ML_DSA_KEYS[1].0)),
                Some(ClientKey::MlDsa(S::ML_DSA_65)),
                &all[5..6],
                "*mldsa.PublicKey",
            ),
            (
                "ML-DSA-87",
                spki(der_tlv(0x06, ML_DSA_KEYS[2].0)),
                Some(ClientKey::MlDsa(S::ML_DSA_87)),
                &all[6..7],
                "*mldsa.PublicKey",
            ),
            (
                "Ed448",
                spki(der_tlv(0x06, &[0x2b, 0x65, 0x71])),
                None,
                &[],
                "",
            ),
            ("not DER", vec![0x30, 0x05, 0x30], None, &[], ""),
        ];
        for (label, spki, want, fits, go_type) in cases {
            let key = ClientKey::of_spki(&spki);
            assert_eq!(key, want, "{label}");
            let Some(key) = key else {
                continue;
            };
            for scheme in all {
                assert_eq!(
                    key.fits_tls13(scheme),
                    fits.contains(&scheme),
                    "{label}, {scheme:?}"
                );
            }
            assert_eq!(key.go_type(), go_type, "{label}");
            let go_kind = match go_type {
                "*ecdsa.PublicKey" => "ECDSA",
                "ed25519.PublicKey" => "Ed25519",
                "*rsa.PublicKey" => "RSA",
                _ => "ML-DSA",
            };
            assert_eq!(key.go_kind(), go_kind, "{label}");
        }
    }

    /// A certificate whose ECDSA key is on a curve Go's `x509` does not
    /// give a key on, or names no curve, is refused when it is read, as
    /// Go's `ParseCertificate` refuses it (`x509: unsupported elliptic
    /// curve`, `x509: invalid ECDSA parameters`), so a client presenting
    /// one is refused before its CertificateVerify, with rustls's bad
    /// encoding and Go's words, `tls: failed to parse client certificate:
    /// ...` (PARITY.md, the clientcert entry); a pool skips one as Go's
    /// `AppendCertsFromPEM` does.  A leaf on P-224, which Go parses,
    /// chains, and in TLS 1.2 is refused under an ECDSA scheme, the
    /// provider having no P-224 algorithm where Go verifies the signature:
    /// that refusal stays in rustls's words, since Go's `expected an ECDSA
    /// public key` is for a key of another kind, which a scheme of another
    /// kind than the key's still is noted as.  In TLS 1.3 an ECDSA scheme
    /// does not fit a P-224 key, as in Go.  Where the oracle runs, Go's
    /// own parse of each certificate is compared.
    #[test]
    fn an_ecdsa_key_go_does_not_parse_refuses_its_certificate() {
        use dcroxide_certgen::gentool::generate_key;
        use rustls::SignatureScheme as S;
        use rustls::pki_types::CertificateDer;
        use rustls::server::danger::ClientCertVerifier;
        let now = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(1_790_000_000));
        let mut oracle = dcroxide_testutil::oracle_or_skip();
        let root_key = generate_key("P-256").expect("key");
        let root =
            signed_p256_certificate(1, "root", &root_key, "root", &root_key, &ca_extensions());
        let leaf_key = generate_key("P-256").expect("key");
        let spki = |algorithm: Vec<u8>, point: Vec<u8>| {
            der_tlv(
                0x30,
                &[
                    der_tlv(0x30, &algorithm),
                    der_tlv(0x03, &[&[0u8][..], &point].concat()),
                ]
                .concat(),
            )
        };
        let ec_with = |params: &[u8]| [der_tlv(0x06, EC_PUBLIC_KEY), params.to_vec()].concat();
        // The generator of P-224 and of secp256k1, uncompressed: points on
        // their curves.
        let p224_g = dcroxide_testutil::unhex(
            "04b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21bd376388b5f723fb4c22dfe6\
             cd4375a05a07476444d5819985007e34",
        );
        let secp256k1_g = dcroxide_testutil::unhex(
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c465\
             5da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        );
        let p256_point = leaf_key.public_bytes();
        // Each case: what it is, the leaf's subject public key info, and
        // whether Go parses it.
        let cases = [
            (
                "P-256",
                spki(
                    ec_with(&der_tlv(0x06, GO_X509_CURVES[1])),
                    p256_point.clone(),
                ),
                true,
            ),
            (
                "P-224",
                spki(ec_with(&der_tlv(0x06, GO_X509_CURVES[0])), p224_g.clone()),
                true,
            ),
            (
                "secp256k1",
                spki(
                    ec_with(&der_tlv(0x06, &[0x2b, 0x81, 0x04, 0x00, 0x0a])),
                    secp256k1_g,
                ),
                false,
            ),
            ("no curve", spki(ec_with(&[]), p256_point.clone()), false),
            (
                "NULL parameters",
                spki(ec_with(&der_tlv(0x05, &[])), p256_point.clone()),
                false,
            ),
            (
                "a curve given by its parameters",
                spki(
                    ec_with(&der_tlv(0x30, &der_tlv(0x02, &[1]))),
                    p256_point.clone(),
                ),
                false,
            ),
        ];
        let verifier = GoClientCertVerifier::from_pem(&certificate_pem(&root)).expect("verifier");
        for (label, spki, go_parses_it) in cases {
            let leaf = signed_certificate_with_spki(
                2,
                "leaf",
                spki,
                "root",
                &root_key,
                der_tlv(0x17, b"491231235959Z"),
                &[],
            );
            assert_eq!(CertFacts::parse(&leaf).is_some(), go_parses_it, "{label}");
            if let Some(go) = go_parses(&mut oracle, &leaf) {
                assert_eq!(go, go_parses_it, "{label}: Go's parse");
            }
            let verified =
                verifier.verify_client_cert(&CertificateDer::from(leaf.as_slice()), &[], now);
            if go_parses_it {
                verified.unwrap_or_else(|err| panic!("{label}: {err:?}"));
            } else {
                assert_eq!(
                    verified.expect_err(label),
                    rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding),
                    "{label}"
                );
                // A pool takes no such certificate as an authority.
                let mut pool = ClientCaPool::new();
                assert!(!pool.add_cert(leaf.clone()), "{label}: the pool");
            }
        }

        // The P-224 leaf's handshake signatures.
        let p224_leaf = signed_certificate_with_spki(
            3,
            "leaf",
            spki(ec_with(&der_tlv(0x06, GO_X509_CURVES[0])), p224_g),
            "root",
            &root_key,
            der_tlv(0x17, b"491231235959Z"),
            &[],
        );
        let p224_leaf = CertificateDer::from(p224_leaf.as_slice());
        let message = b"a handshake transcript";
        // A well-formed signature, r = 1 and s = 1, which the provider
        // never gets to verify.
        let signature = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        for scheme in [
            S::ECDSA_NISTP256_SHA256,
            S::ECDSA_NISTP384_SHA384,
            S::ECDSA_NISTP521_SHA512,
        ] {
            clear_client_refusal();
            let err = verifier
                .verify_tls12_signature(message, &p224_leaf, &digitally_signed(scheme, &signature))
                .expect_err("no P-224 algorithm");
            assert!(
                matches!(
                    err,
                    rustls::Error::InvalidCertificate(
                        rustls::CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext {
                            ..
                        }
                    )
                ),
                "TLS 1.2, {scheme:?}: {err:?}"
            );
            assert_eq!(
                take_client_refusal(&err),
                None,
                "TLS 1.2, {scheme:?}: no Go words for the port's refusal"
            );
            let words = crate::server::go_error_text_for_tests(&err);
            assert!(
                !words.contains("expected an ECDSA public key"),
                "TLS 1.2, {scheme:?}: {words}"
            );
            let err = verifier
                .verify_tls13_signature(message, &p224_leaf, &digitally_signed(scheme, &signature))
                .expect_err("no scheme fits a P-224 key");
            assert_eq!(
                err,
                rustls::Error::PeerMisbehaved(CLIENT_SCHEME_REFUSED),
                "TLS 1.3, {scheme:?}"
            );
        }
        clear_client_refusal();
        let err = verifier
            .verify_tls12_signature(
                message,
                &p224_leaf,
                &digitally_signed(S::ED25519, &signature),
            )
            .expect_err("an Ed25519 scheme from an ECDSA key");
        assert_eq!(
            take_client_refusal(&err),
            Some(
                "tls: invalid signature by the client certificate: expected an Ed25519 public \
                 key, got *ecdsa.PublicKey"
                    .to_string()
            )
        );
    }

    /// Go's words for a certificate its `ParseCertificate` refuses, as the
    /// oracle's `x509_verify_client` gives them, or `None` where Go parses
    /// it or the oracle does not run.
    fn go_parse_error(
        oracle: &mut Option<dcroxide_testutil::Oracle>,
        der: &[u8],
    ) -> Option<String> {
        let hex: String = der.iter().map(|b| format!("{b:02x}")).collect();
        let request = format!(r#"{{"roots":[],"leaf":"{hex}","intermediates":[],"time":0}}"#);
        let response = oracle
            .as_mut()?
            .call("x509_verify_client", request.as_bytes());
        response["error"]
            .as_str()
            .and_then(|err| err.strip_prefix("x509_verify_client: leaf: "))
            .map(str::to_string)
    }

    /// A subject public key info of `algorithm`, an AlgorithmIdentifier's
    /// contents, and `key`, a BIT STRING's.
    fn spki_of(algorithm: &[u8], key: &[u8]) -> Vec<u8> {
        der_tlv(
            0x30,
            &[der_tlv(0x30, algorithm), der_tlv(0x03, key)].concat(),
        )
    }

    /// An RSA subject public key info whose `RSAPublicKey` holds
    /// `modulus` and `exponent`, INTEGER contents as given.
    fn rsa_spki(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
        let key = der_tlv(
            0x30,
            &[der_tlv(0x02, modulus), der_tlv(0x02, exponent)].concat(),
        );
        spki_of(
            &[der_tlv(0x06, RSA_ENCRYPTION), der_tlv(0x05, &[])].concat(),
            &[&[0u8][..], &key].concat(),
        )
    }

    /// A positive modulus of `bits` bits, 2^(bits-1) + 1, as INTEGER
    /// contents: no RSA key, but one Go's parser reads, which checks only
    /// that the modulus is above zero.
    // Byte and bit arithmetic over a length of at least one byte.
    #[allow(clippy::arithmetic_side_effects)]
    fn modulus_of_bits(bits: usize) -> Vec<u8> {
        let len = bits.div_ceil(8);
        let mut modulus = vec![0u8; len];
        modulus[0] = 1 << ((bits - 1) % 8);
        modulus[len - 1] |= 1;
        if modulus[0] & 0x80 != 0 {
            modulus.insert(0, 0);
        }
        modulus
    }

    /// A client certificate is refused when it is read, as Go's
    /// `ParseCertificate` refuses it, for every way Go's `parsePublicKey`
    /// and the reading of the subject public key info before it refuse a
    /// key (`crypto/x509/parser.go:309-411`, `:1071-1099`), and Go's words
    /// for it are the handshake's error: `tls: failed to parse client
    /// certificate: ` and the parser's (`handshake_server.go:947-951`).
    /// So is a client sending such a certificate after a leaf that
    /// verifies, which no chain uses, as Go parses every certificate a
    /// client sends; a pool takes none of them, as Go's
    /// `AppendCertsFromPEM` skips them.  Each key Go takes is taken, its
    /// leaf verifying under the root, but for one of a kind Go's TLS takes
    /// no signature from, refused once its chain verifies with Go's words
    /// and `unsupported_certificate`'s error (`handshake_server.go:1005-1016`).
    /// The texts are written out, and where the oracle runs each is
    /// compared with Go's own parse of the certificate.  The P-256 text for
    /// a coordinate at or above p is that of Go's assembly P-256, which
    /// x86_64 builds.
    #[test]
    fn public_keys_go_does_not_parse_refuse_their_certificates() {
        use dcroxide_certgen::gentool::generate_key;
        use rustls::pki_types::CertificateDer;
        use rustls::server::danger::ClientCertVerifier;
        let now = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(1_790_000_000));
        let mut oracle = dcroxide_testutil::oracle_or_skip();
        let root_key = generate_key("P-256").expect("key");
        let root =
            signed_p256_certificate(1, "root", &root_key, "root", &root_key, &ca_extensions());
        let verifier = GoClientCertVerifier::from_pem(&certificate_pem(&root)).expect("verifier");
        let good_key = generate_key("P-256").expect("key");
        let good_leaf = signed_p256_certificate(2, "good", &good_key, "root", &root_key, &[]);

        let ec = |curve: Option<&[u8]>| {
            let mut algorithm = der_tlv(0x06, EC_PUBLIC_KEY);
            if let Some(curve) = curve {
                algorithm.extend(der_tlv(0x06, curve));
            }
            algorithm
        };
        let bits = |key: &[u8]| [&[0u8][..], key].concat();
        let p256 = generate_key("P-256").expect("key").public_bytes();
        let p384 = generate_key("P-384").expect("key").public_bytes();
        let p521 = generate_key("P-521").expect("key").public_bytes();
        let p224_g = dcroxide_testutil::unhex(
            "04b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21bd376388b5f723fb4c22dfe6\
             cd4375a05a07476444d5819985007e34",
        );
        let ed25519 = generate_key("Ed25519").expect("key").public_bytes();
        let mut compressed = p256[..33].to_vec();
        compressed[0] = 2 | (p256[64] & 1);
        let mut hybrid = p256.clone();
        hybrid[0] = 6 | (p256[64] & 1);
        let mut p256_y_is_p = p256.clone();
        p256_y_is_p[33..].copy_from_slice(&[
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ]);
        let mut p521_x_is_p = p521.clone();
        p521_x_is_p[1..67].fill(0xff);
        p521_x_is_p[1] = 0x01;
        let mut p224_off = p224_g.clone();
        p224_off[56] ^= 1;
        // P-224's generator ends in 0x34, two zero bits: its bits read with
        // two unused, which Go right-aligns to a first octet of 0x01.
        let p224_unused = [&[2u8][..], &p224_g].concat();
        let p384_short = &p384[..p384.len() - 1];
        let secp256k1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x0a];
        let ed = der_tlv(0x06, ED25519_KEY);
        let ml_dsa_44 = der_tlv(0x06, ML_DSA_KEYS[0].0);
        let ml_dsa_key = vec![0u8; 1 + 1312];
        let dsa_params = der_tlv(
            0x30,
            &[
                der_tlv(0x02, &[23]),
                der_tlv(0x02, &[11]),
                der_tlv(0x02, &[4]),
            ]
            .concat(),
        );
        let dsa = |params: &[u8], y: &[u8]| {
            spki_of(
                &[der_tlv(0x06, DSA_KEY), params.to_vec()].concat(),
                &bits(y),
            )
        };
        let modulus = modulus_of_bits(2048);
        let mut padded_modulus = modulus.clone();
        padded_modulus.insert(0, 0);
        let rsa_trailing = {
            let key = der_tlv(
                0x30,
                &[
                    der_tlv(0x02, &modulus),
                    der_tlv(0x02, &[1, 0, 1]),
                    vec![0x05, 0x00],
                ]
                .concat(),
            );
            spki_of(
                &[der_tlv(0x06, RSA_ENCRYPTION), der_tlv(0x05, &[])].concat(),
                &bits(&key),
            )
        };
        let invalid_point = "ecdsa: invalid uncompressed public key";
        let cases: Vec<(&str, Vec<u8>, Option<&str>)> = vec![
            (
                "P-256",
                spki_of(&ec(Some(GO_X509_CURVES[1])), &bits(&p256)),
                None,
            ),
            (
                "P-384",
                spki_of(&ec(Some(GO_X509_CURVES[2])), &bits(&p384)),
                None,
            ),
            (
                "P-521",
                spki_of(&ec(Some(GO_X509_CURVES[3])), &bits(&p521)),
                None,
            ),
            (
                "P-224",
                spki_of(&ec(Some(GO_X509_CURVES[0])), &bits(&p224_g)),
                None,
            ),
            (
                "compressed",
                spki_of(&ec(Some(GO_X509_CURVES[1])), &bits(&compressed)),
                Some(invalid_point),
            ),
            (
                "hybrid",
                spki_of(&ec(Some(GO_X509_CURVES[1])), &bits(&hybrid)),
                Some(invalid_point),
            ),
            (
                "an empty point",
                spki_of(&ec(Some(GO_X509_CURVES[1])), &[0]),
                Some(invalid_point),
            ),
            (
                "unused bits",
                spki_of(&ec(Some(GO_X509_CURVES[0])), &p224_unused),
                Some(invalid_point),
            ),
            (
                "a P-384 point a byte short",
                spki_of(&ec(Some(GO_X509_CURVES[2])), &bits(p384_short)),
                Some("invalid P384 point encoding"),
            ),
            (
                "P-256's y = p",
                spki_of(&ec(Some(GO_X509_CURVES[1])), &bits(&p256_y_is_p)),
                Some("invalid P256 element encoding"),
            ),
            (
                "P-521's x = p",
                spki_of(&ec(Some(GO_X509_CURVES[3])), &bits(&p521_x_is_p)),
                Some("invalid P521Element encoding"),
            ),
            (
                "off P-224",
                spki_of(&ec(Some(GO_X509_CURVES[0])), &bits(&p224_off)),
                Some("P224 point not on curve"),
            ),
            (
                "a P-384 point on P-256",
                spki_of(&ec(Some(GO_X509_CURVES[1])), &bits(&p384)),
                Some("invalid P256 point encoding"),
            ),
            (
                "no curve",
                spki_of(&ec(None), &bits(&p256)),
                Some("x509: invalid ECDSA parameters"),
            ),
            (
                "NULL parameters",
                spki_of(&[ec(None), der_tlv(0x05, &[])].concat(), &bits(&p256)),
                Some("x509: invalid ECDSA parameters"),
            ),
            (
                "a curve OID cryptobyte refuses",
                spki_of(
                    &[ec(None), der_tlv(0x06, &[0x80, 0x01])].concat(),
                    &bits(&p256),
                ),
                Some("x509: invalid ECDSA parameters"),
            ),
            (
                "secp256k1",
                spki_of(&ec(Some(secp256k1)), &bits(&p256)),
                Some("x509: unsupported elliptic curve"),
            ),
            ("Ed25519", spki_of(&ed, &bits(&ed25519)), None),
            (
                "Ed25519 with NULL parameters",
                spki_of(&[ed.clone(), der_tlv(0x05, &[])].concat(), &bits(&ed25519)),
                Some("x509: Ed25519 key encoded with illegal parameters"),
            ),
            (
                "Ed25519 of 31 bytes",
                spki_of(&ed, &bits(&ed25519[..31])),
                Some("x509: wrong Ed25519 public key size"),
            ),
            (
                "Ed25519 of 33 bytes",
                spki_of(&ed, &bits(&[&ed25519[..], &[0]].concat())),
                Some("x509: wrong Ed25519 public key size"),
            ),
            ("RSA", rsa_spki(&modulus, &[1, 0, 1]), None),
            ("RSA with bytes after its exponent", rsa_trailing, None),
            (
                "RSA without NULL parameters",
                spki_of(
                    &der_tlv(0x06, RSA_ENCRYPTION),
                    &bits(&der_tlv(
                        0x30,
                        &[der_tlv(0x02, &modulus), der_tlv(0x02, &[1, 0, 1])].concat(),
                    )),
                ),
                Some("x509: RSA key missing NULL parameters"),
            ),
            (
                "RSA, no SEQUENCE",
                spki_of(
                    &[der_tlv(0x06, RSA_ENCRYPTION), der_tlv(0x05, &[])].concat(),
                    &bits(&der_tlv(0x02, &modulus)),
                ),
                Some("x509: invalid RSA public key"),
            ),
            (
                "RSA, a modulus with a needless zero",
                rsa_spki(&padded_modulus, &[1, 0, 1]),
                Some("x509: invalid RSA modulus"),
            ),
            (
                "RSA, an exponent of nine bytes",
                rsa_spki(&modulus, &[1, 0, 0, 0, 0, 0, 0, 0, 1]),
                Some("x509: invalid RSA public exponent"),
            ),
            (
                "RSA, a negative modulus",
                rsa_spki(&modulus[1..], &[1, 0, 1]),
                Some("x509: RSA modulus is not a positive number"),
            ),
            (
                "RSA, a zero modulus",
                rsa_spki(&[0], &[1, 0, 1]),
                Some("x509: RSA modulus is not a positive number"),
            ),
            (
                "RSA, an exponent of -1",
                rsa_spki(&modulus, &[0xff]),
                Some("x509: RSA public exponent is not a positive number"),
            ),
            ("DSA", dsa(&dsa_params, &der_tlv(0x02, &[2])), None),
            (
                "DSA, a key that is no INTEGER",
                dsa(&dsa_params, &der_tlv(0x04, &[2])),
                Some("x509: invalid DSA public key"),
            ),
            (
                "DSA without parameters",
                dsa(&[], &der_tlv(0x02, &[2])),
                Some("x509: invalid DSA parameters"),
            ),
            (
                "DSA, g zero",
                dsa(
                    &der_tlv(
                        0x30,
                        &[
                            der_tlv(0x02, &[23]),
                            der_tlv(0x02, &[11]),
                            der_tlv(0x02, &[0]),
                        ]
                        .concat(),
                    ),
                    &der_tlv(0x02, &[2]),
                ),
                Some("x509: zero or negative DSA parameter"),
            ),
            ("ML-DSA-44", spki_of(&ml_dsa_44, &ml_dsa_key), None),
            (
                "ML-DSA-44 with NULL parameters",
                spki_of(
                    &[ml_dsa_44.clone(), der_tlv(0x05, &[])].concat(),
                    &ml_dsa_key,
                ),
                Some("x509: ML-DSA key encoded with illegal parameters"),
            ),
            (
                "ML-DSA-44 a byte short",
                spki_of(&ml_dsa_44, &ml_dsa_key[..1312]),
                Some("mldsa: invalid public key length"),
            ),
            (
                "X25519",
                spki_of(&der_tlv(0x06, &[0x2b, 0x65, 0x6e]), &bits(&[9; 32])),
                None,
            ),
            (
                "an algorithm that is no SEQUENCE",
                der_tlv(
                    0x30,
                    &[der_tlv(0x06, ED25519_KEY), der_tlv(0x03, &bits(&ed25519))].concat(),
                ),
                Some("x509: malformed public key algorithm identifier"),
            ),
            (
                "an empty algorithm OID",
                spki_of(&der_tlv(0x06, &[]), &bits(&ed25519)),
                Some("x509: malformed OID"),
            ),
            (
                "parameters cut short",
                spki_of(&[ed.clone(), vec![0x05]].concat(), &bits(&ed25519)),
                Some("x509: malformed parameters"),
            ),
            (
                "no key",
                der_tlv(0x30, &der_tlv(0x30, &ed)),
                Some("x509: malformed subjectPublicKey"),
            ),
            (
                "eight unused bits",
                spki_of(&ed, &[&[8u8][..], &ed25519].concat()),
                Some("x509: malformed subjectPublicKey"),
            ),
        ];
        let mut serial = 3u8;
        for (label, spki, words) in cases {
            serial = serial.wrapping_add(1);
            let leaf = signed_certificate_with_spki(
                serial,
                "leaf",
                spki.clone(),
                "root",
                &root_key,
                der_tlv(0x17, b"491231235959Z"),
                &[],
            );
            let spki_content = DerReader::new(&spki).read_tag(0x30).expect("an spki");
            assert_eq!(go_public_key_refusal(spki_content), words, "{label}");
            assert_eq!(
                CertFacts::parse(&leaf).is_none(),
                words.is_some(),
                "{label}"
            );
            if oracle.is_some() {
                assert_eq!(
                    go_parse_error(&mut oracle, &leaf).as_deref(),
                    words,
                    "{label}: Go's parse"
                );
            }
            let leaf_der = CertificateDer::from(leaf.as_slice());
            let good = CertificateDer::from(good_leaf.as_slice());
            let mut pool = ClientCaPool::new();
            assert_eq!(
                pool.add_cert(leaf.clone()),
                words.is_none(),
                "{label}: the pool"
            );
            if let Some(words) = words {
                let text = format!("tls: failed to parse client certificate: {words}");
                for chain in [
                    (&leaf_der, &[][..]),
                    (&good, std::slice::from_ref(&leaf_der)),
                ] {
                    let err = verifier
                        .verify_client_cert(chain.0, chain.1, now)
                        .expect_err(label);
                    assert_eq!(
                        err,
                        rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding),
                        "{label}"
                    );
                    assert_eq!(take_client_refusal(&err), Some(text.clone()), "{label}");
                }
                continue;
            }
            let verified = verifier.verify_client_cert(&leaf_der, &[], now);
            match ClientKey::of_leaf(&leaf) {
                Some(_) => {
                    verified.unwrap_or_else(|err| panic!("{label}: {err:?}"));
                }
                None => {
                    let err = verified.expect_err(label);
                    assert_eq!(
                        err,
                        rustls::Error::InvalidCertificate(rustls::CertificateError::InvalidPurpose),
                        "{label}"
                    );
                    let go_type = if label == "DSA" {
                        "*dsa.PublicKey"
                    } else {
                        "<nil>"
                    };
                    assert_eq!(
                        take_client_refusal(&err),
                        Some(format!(
                            "tls: client certificate contains an unsupported public key of type \
                             {go_type}"
                        )),
                        "{label}"
                    );
                }
            }
            // A good leaf with this one after it, unused.
            verifier
                .verify_client_cert(&good, std::slice::from_ref(&leaf_der), now)
                .unwrap_or_else(|err| panic!("{label}, unused: {err:?}"));
        }
    }

    /// Go refuses a client that sends a certificate with an RSA key of
    /// more than 8192 bits, used or not, as it reads each certificate,
    /// with `bad_certificate` and its words
    /// (`crypto/tls/handshake_server.go:952-957`), which this does with
    /// rustls's bad encoding, rustls's `bad_certificate`, and Go's words;
    /// 8192 bits are taken.  A pool takes such a key, as Go's does, the
    /// limit being on what a client sends.  A certificate that fails to
    /// parse after one over the limit is refused for the limit, as Go
    /// checks each certificate as it reads it.
    #[test]
    fn a_client_rsa_key_over_8192_bits_is_refused_as_go_refuses_it() {
        use dcroxide_certgen::gentool::generate_key;
        use rustls::pki_types::CertificateDer;
        use rustls::server::danger::ClientCertVerifier;
        let now = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(1_790_000_000));
        let root_key = generate_key("P-256").expect("key");
        let root =
            signed_p256_certificate(1, "root", &root_key, "root", &root_key, &ca_extensions());
        let verifier = GoClientCertVerifier::from_pem(&certificate_pem(&root)).expect("verifier");
        let good_key = generate_key("P-256").expect("key");
        let good_leaf = signed_p256_certificate(2, "good", &good_key, "root", &root_key, &[]);
        let good = CertificateDer::from(good_leaf.as_slice());
        let rsa_leaf = |serial: u8, bits: usize| {
            signed_certificate_with_spki(
                serial,
                "rsa",
                rsa_spki(&modulus_of_bits(bits), &[1, 0, 1]),
                "root",
                &root_key,
                der_tlv(0x17, b"491231235959Z"),
                &[],
            )
        };
        let unparsable = signed_certificate_with_spki(
            3,
            "unparsable",
            spki_of(&der_tlv(0x06, ED25519_KEY), &[0, 1, 2]),
            "root",
            &root_key,
            der_tlv(0x17, b"491231235959Z"),
            &[],
        );
        let unparsable = CertificateDer::from(unparsable.as_slice());
        let too_large = "tls: client sent certificate containing RSA key larger than 8192 bits";
        for (bits, refused) in [(8192, false), (8193, true), (16384, true)] {
            let rsa = rsa_leaf(4, bits);
            let spki = CertFacts::parse_all(&rsa).expect("parses").2.spki;
            assert_eq!(go_rsa_modulus_bits(spki), Some(bits));
            let rsa = CertificateDer::from(rsa.as_slice());
            let mut pool = ClientCaPool::new();
            assert!(pool.add_cert(rsa.to_vec()), "{bits}: the pool");
            for chain in [
                (&rsa, &[][..]),
                (&good, std::slice::from_ref(&rsa)),
                (&rsa, std::slice::from_ref(&unparsable)),
            ] {
                let verified = verifier.verify_client_cert(chain.0, chain.1, now);
                if refused {
                    let err = verified.expect_err("over the limit");
                    assert_eq!(
                        err,
                        rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding),
                        "{bits}"
                    );
                    assert_eq!(
                        take_client_refusal(&err).as_deref(),
                        Some(too_large),
                        "{bits}"
                    );
                } else if chain.1.first() == Some(&unparsable) {
                    let err = verified.expect_err("an unparsable certificate after it");
                    assert_eq!(
                        take_client_refusal(&err).as_deref(),
                        Some(
                            "tls: failed to parse client certificate: x509: wrong Ed25519 public key size"
                        ),
                        "{bits}"
                    );
                } else {
                    verified.unwrap_or_else(|err| panic!("{bits}: {err:?}"));
                }
            }
        }
        assert_eq!(
            go_rsa_modulus_bits(CertFacts::parse_all(&good_leaf).expect("parses").2.spki),
            None
        );
    }

    /// Go's `BitString.RightAlign`: the octets as they are with no bit
    /// unused, and shifted right by the unused count otherwise.
    #[test]
    fn bit_strings_are_right_aligned_as_go_aligns_them() {
        assert_eq!(go_right_align(0, &[0x12, 0x34]).as_ref(), &[0x12, 0x34]);
        assert_eq!(go_right_align(4, &[0x12, 0x30]).as_ref(), &[0x01, 0x23]);
        assert_eq!(go_right_align(1, &[0x81, 0x02]).as_ref(), &[0x40, 0x81]);
        assert_eq!(go_right_align(7, &[0x80]).as_ref(), &[0x01]);
        assert_eq!(go_right_align(3, &[]).as_ref(), &[] as &[u8]);
    }

    /// An ML-DSA client key signs a TLS 1.3 handshake with its own set's
    /// scheme alone, as Go checks it (`crypto/tls/handshake_server_tls13.go:1086-1100`),
    /// and is refused in TLS 1.2 whatever the scheme and whether or not the
    /// signature verifies, with Go's text and `illegal_parameter`
    /// (`handshake_server.go:1005-1012`), which keys on the leaf alone: a
    /// P-256 leaf under ML-DSA authorities signs a TLS 1.2 handshake.  The
    /// schemes the CertificateRequest lists are the listener's set's, Go
    /// 1.27.3's in Go's order, P-521's last, with PKCS#1 v1.5's three, which
    /// Go's TLS 1.3 list leaves out (PARITY.md, the ML-DSA entry).
    #[test]
    fn an_ml_dsa_client_key_signs_in_tls13_alone() {
        use dcroxide_certgen::gentool::generate_key;
        use rustls::SignatureScheme as S;
        use rustls::pki_types::CertificateDer;
        use rustls::server::danger::ClientCertVerifier;
        let now = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(1_790_000_000));
        let oid = |set: usize| der_tlv(0x06, ML_DSA_KEYS[set].0);
        let ca = ca_extensions();
        let (ml44, ml44_spki) = ml_dsa_test_key(0, 1);
        let (ml87, ml87_spki) = ml_dsa_test_key(2, 2);
        let root = certificate_signed_by(
            1,
            "root",
            ml44_spki.clone(),
            "root",
            &ml44,
            ML_DSA_SCHEMES[0],
            &oid(0),
            &ca,
        );
        let leaf = certificate_signed_by(
            2,
            "leaf",
            ml87_spki,
            "root",
            &ml44,
            ML_DSA_SCHEMES[0],
            &oid(0),
            &[],
        );
        let p256 = generate_key("P-256").expect("key");
        let p256_key = p256.marshal_pkcs8().expect("pkcs8");
        let p256_leaf = certificate_signed_by(
            3,
            "leaf",
            p256_spki(&p256),
            "root",
            &ml44,
            ML_DSA_SCHEMES[0],
            &oid(0),
            &[],
        );
        let verifier = GoClientCertVerifier::from_pem(&certificate_pem(&root)).expect("verifier");
        let leaf = CertificateDer::from(leaf.as_slice());
        let p256_leaf = CertificateDer::from(p256_leaf.as_slice());
        verifier
            .verify_client_cert(&leaf, &[], now)
            .expect("the ML-DSA-87 chain");
        verifier
            .verify_client_cert(&p256_leaf, &[], now)
            .expect("the P-256 leaf's chain");

        let message = b"a handshake transcript";
        let sign = |key: &[u8], scheme: S| {
            dcroxide_tlscrypto::sign::load_der(key)
                .expect("key")
                .choose_scheme(&[scheme])
                .expect("scheme")
                .sign(message)
                .expect("sign")
        };
        let ml87_signature = sign(&ml87, S::ML_DSA_87);
        verifier
            .verify_tls13_signature(
                message,
                &leaf,
                &digitally_signed(S::ML_DSA_87, &ml87_signature),
            )
            .expect("the leaf's own scheme in TLS 1.3");
        // A scheme that does not fit the key is refused as Go refuses it,
        // before anything is verified; the leaf's own scheme over another
        // message fails as a bad signature, which is left to rustls's
        // words for an ML-DSA key.
        for (label, scheme, message, misfit) in [
            ("another set's scheme", S::ML_DSA_65, &message[..], true),
            ("the first set's scheme", S::ML_DSA_44, &message[..], true),
            (
                "an ECDSA scheme",
                S::ECDSA_NISTP256_SHA256,
                &message[..],
                true,
            ),
            (
                "a PKCS#1 v1.5 scheme",
                S::RSA_PKCS1_SHA256,
                &message[..],
                true,
            ),
            (
                "another message",
                S::ML_DSA_87,
                &b"another transcript"[..],
                false,
            ),
        ] {
            clear_client_refusal();
            let err = verifier
                .verify_tls13_signature(message, &leaf, &digitally_signed(scheme, &ml87_signature))
                .expect_err("refused");
            if misfit {
                assert_eq!(
                    err,
                    rustls::Error::PeerMisbehaved(CLIENT_SCHEME_REFUSED),
                    "TLS 1.3, {label}"
                );
                assert_eq!(
                    crate::server::go_error_text_for_tests(&err),
                    "tls: client certificate used with invalid signature algorithm"
                );
            } else {
                assert_eq!(
                    err,
                    rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature),
                    "TLS 1.3, {label}"
                );
            }
            assert_eq!(take_client_refusal(&err), None, "TLS 1.3, {label}");
        }
        for scheme in [S::ML_DSA_87, S::ECDSA_NISTP256_SHA256] {
            let err = verifier
                .verify_tls12_signature(message, &leaf, &digitally_signed(scheme, &ml87_signature))
                .expect_err("an ML-DSA client key in TLS 1.2");
            assert_eq!(
                err,
                rustls::Error::PeerMisbehaved(ML_DSA_CLIENT_KEY_IN_TLS12),
                "TLS 1.2, {scheme:?}"
            );
            assert_eq!(
                crate::server::go_error_text_for_tests(&err),
                "tls: client certificate uses ML-DSA, which requires TLS 1.3"
            );
        }
        verifier
            .verify_tls12_signature(
                message,
                &p256_leaf,
                &digitally_signed(
                    S::ECDSA_NISTP256_SHA256,
                    &sign(&p256_key, S::ECDSA_NISTP256_SHA256),
                ),
            )
            .expect("a P-256 leaf under ML-DSA authorities in TLS 1.2");

        // The P-256 leaf's refusals in Go's words: in TLS 1.3 a P-521
        // scheme, which does not fit the key, and its own scheme over
        // another message, an ECDSA signature that fails; in TLS 1.2,
        // where an ECDSA scheme is not tied to a curve, the Ed25519 scheme,
        // which is of another kind than the key.
        let p256_signature = sign(&p256_key, S::ECDSA_NISTP256_SHA256);
        let err = verifier
            .verify_tls13_signature(
                message,
                &p256_leaf,
                &digitally_signed(S::ECDSA_NISTP521_SHA512, &p256_signature),
            )
            .expect_err("a P-521 scheme from a P-256 key in TLS 1.3");
        assert_eq!(err, rustls::Error::PeerMisbehaved(CLIENT_SCHEME_REFUSED));
        let failed = "tls: invalid signature by the client certificate: ";
        for (version, scheme, words) in [
            (
                "TLS 1.3",
                S::ECDSA_NISTP256_SHA256,
                "ECDSA verification failure",
            ),
            (
                "TLS 1.2",
                S::ECDSA_NISTP256_SHA256,
                "ECDSA verification failure",
            ),
            (
                "TLS 1.2",
                S::ED25519,
                "expected an Ed25519 public key, got *ecdsa.PublicKey",
            ),
        ] {
            clear_client_refusal();
            let dss = digitally_signed(scheme, &p256_signature);
            let other = b"another transcript";
            let err = if version == "TLS 1.3" {
                verifier.verify_tls13_signature(other, &p256_leaf, &dss)
            } else {
                verifier.verify_tls12_signature(other, &p256_leaf, &dss)
            }
            .expect_err("refused");
            assert_eq!(
                take_client_refusal(&err),
                Some(format!("{failed}{words}")),
                "{version}, {scheme:?}"
            );
            // The note is taken once, and a note is not read for another
            // error than the one it was noted for.
            assert_eq!(take_client_refusal(&err), None);
        }
        clear_client_refusal();
        let err = verifier
            .verify_tls13_signature(
                b"another transcript",
                &p256_leaf,
                &digitally_signed(S::ECDSA_NISTP256_SHA256, &p256_signature),
            )
            .expect_err("refused");
        assert_eq!(
            take_client_refusal(&rustls::Error::PeerMisbehaved(CLIENT_SCHEME_REFUSED)),
            None
        );
        assert_eq!(take_client_refusal(&err), None, "taken already");

        assert_eq!(
            verifier.supported_verify_schemes(),
            [
                S::ML_DSA_44,
                S::ML_DSA_65,
                S::ML_DSA_87,
                S::RSA_PSS_SHA256,
                S::ECDSA_NISTP256_SHA256,
                S::ED25519,
                S::RSA_PSS_SHA384,
                S::RSA_PSS_SHA512,
                S::RSA_PKCS1_SHA256,
                S::RSA_PKCS1_SHA384,
                S::RSA_PKCS1_SHA512,
                S::ECDSA_NISTP384_SHA384,
                S::ECDSA_NISTP521_SHA512,
            ]
        );
    }

    /// The client-certificate fuzz body's chains are what it says: each
    /// certificate parses as Go's parser reads it, the leaf's signature
    /// starts where the body lays its input, over the set's template, and
    /// is checked by the authority's key of zero bytes with the set's
    /// algorithm, in the replay and in webpki's search.  Inputs of each
    /// use run, and a forged certificate list, a laid signature or key, or
    /// a laid handshake signature authenticates no one.
    #[test]
    fn the_client_cert_fuzz_body_reaches_ml_dsa() {
        let fixture = FuzzClientCerts::new().expect("the fixture");
        assert_eq!(fixture.chains.len(), 3);
        for (set, chain) in fixture.chains.iter().enumerate() {
            let (_, key_len) = ML_DSA_KEYS[set];
            let leaf = ChainCandidate::parse(&chain.leaf).expect("the leaf parses");
            let authority = ChainCandidate::parse(&chain.authority).expect("the authority parses");
            assert_eq!(
                &chain.leaf[chain.leaf_signature_at..],
                dcroxide_tlscrypto::verify::fuzz_ml_dsa_signature(set, &[]),
                "set {set}: the leaf's signature"
            );
            assert_eq!(
                chain
                    .authority
                    .get(chain.authority_key_at..chain.authority_key_at + key_len),
                Some(&vec![0u8; key_len][..]),
                "set {set}: the authority's key"
            );
            let (key_algorithm, _) = authority.links.key.expect("the authority's key");
            assert!(
                dcroxide_tlscrypto::RPC_SIG_ALGS.all.iter().any(|alg| {
                    alg.signature_alg_id().as_ref() == leaf.links.signature_algorithm
                        && alg.public_key_alg_id().as_ref() == key_algorithm
                }),
                "set {set}: an algorithm checks the leaf's signature"
            );
            assert!(
                !check_signature_from(&leaf, &authority, dcroxide_tlscrypto::RPC_SIG_ALGS.all),
                "set {set}: the template signature does not verify"
            );
        }
        let len = |cert: &[u8]| u16::try_from(cert.len()).expect("short").to_be_bytes();
        let listed = [
            &[0u8][..],
            &len(&fixture.chains[0].leaf),
            &fixture.chains[0].leaf,
            &len(&fixture.chains[0].authority),
            &fixture.chains[0].authority,
        ]
        .concat();
        for input in [
            vec![],
            listed,
            vec![0, 0xff, 0xff, 0x30],
            vec![1, 0x12, 0x34],
            vec![4, 0x56],
            [vec![8], vec![0xff; 40]].concat(),
            vec![9, 0],
            vec![10, 1, 2, 3],
            vec![11, 11],
            vec![255; 300],
        ] {
            assert!(
                !fuzz_client_cert(&input),
                "{:02x?}",
                &input[..input.len().min(8)]
            );
        }
    }

    /// The client-certificate fuzz body's handshake leaves are what it
    /// says: on the P-256, P-384 and P-521 generators and the zero seed's
    /// Ed25519 key, picked by the first byte divided by twelve, so that a
    /// handshake signature by the key of the secret scalar 1, or of the
    /// zero seed, under the leaf's own scheme, picked from the list, is
    /// accepted, and one under another curve's scheme, one under a scheme
    /// the listener refuses, or one with a bit flipped, is not.
    #[test]
    fn the_client_cert_fuzz_body_reaches_ecdsa_and_ed25519() {
        use rustls::SignatureScheme as S;
        let fixture = FuzzClientCerts::new().expect("the fixture");
        let ecdsa = |curve: &[u8], width: usize| {
            let mut scalar = vec![0u8; width];
            scalar[width - 1] = 1;
            der_tlv(
                0x30,
                &[
                    der_tlv(0x02, &[0]),
                    der_tlv(
                        0x30,
                        &[der_tlv(0x06, EC_PUBLIC_KEY), der_tlv(0x06, curve)].concat(),
                    ),
                    der_tlv(
                        0x04,
                        &der_tlv(
                            0x30,
                            &[der_tlv(0x02, &[1]), der_tlv(0x04, &scalar)].concat(),
                        ),
                    ),
                ]
                .concat(),
            )
        };
        let ed25519 = der_tlv(
            0x30,
            &[
                der_tlv(0x02, &[0]),
                der_tlv(0x30, &der_tlv(0x06, ED25519_KEY)),
                der_tlv(0x04, &der_tlv(0x04, &[0u8; 32])),
            ]
            .concat(),
        );
        let leaves = [
            (ecdsa(ECDSA_CURVES[0].0, 32), S::ECDSA_NISTP256_SHA256),
            (ecdsa(ECDSA_CURVES[1].0, 48), S::ECDSA_NISTP384_SHA384),
            (ecdsa(ECDSA_CURVES[2].0, 66), S::ECDSA_NISTP521_SHA512),
            (ed25519, S::ED25519),
        ];
        assert_eq!(fixture.handshake_leaves.len(), leaves.len());
        let schemes: Vec<S> = dcroxide_tlscrypto::RPC_SIG_ALGS
            .mapping
            .iter()
            .map(|&(scheme, _)| scheme)
            .chain(FUZZ_REFUSED_SCHEMES)
            .collect();
        let at = |scheme: S| {
            u8::try_from(schemes.iter().position(|&s| s == scheme).expect("listed")).expect("few")
        };
        for (n, ((pkcs8, scheme), leaf)) in leaves.iter().zip(&fixture.handshake_leaves).enumerate()
        {
            let key = ClientKey::of_leaf(leaf).expect("a client key");
            let want = if *scheme == S::ED25519 {
                ClientKey::Ed25519
            } else {
                ClientKey::Ecdsa(Some(*scheme))
            };
            assert_eq!(key, want, "leaf {n}");
            let signature = dcroxide_tlscrypto::sign::load_der(pkcs8)
                .expect("the key")
                .choose_scheme(&[*scheme])
                .expect("its scheme")
                .sign(b"the client's handshake transcript")
                .expect("signed");
            // Mode 3 with the leaf picked: 12 (n + 1) + 9.
            let pick = u8::try_from(12 * (n + 1) + 9).expect("a byte");
            let input = |scheme: S, signature: &[u8]| [&[pick, at(scheme)][..], signature].concat();
            assert!(fuzz_client_cert(&input(*scheme, &signature)), "leaf {n}");
            let mut flipped = signature.clone();
            *flipped.last_mut().expect("a byte") ^= 1;
            assert!(
                !fuzz_client_cert(&input(*scheme, &flipped)),
                "leaf {n}, flipped"
            );
            let another = if *scheme == S::ECDSA_NISTP384_SHA384 {
                S::ECDSA_NISTP521_SHA512
            } else {
                S::ECDSA_NISTP384_SHA384
            };
            // In TLS 1.2 an ECDSA key takes another curve's scheme, whose
            // hash its signature was not made over.
            assert!(
                !fuzz_client_cert(&input(another, &signature)),
                "leaf {n}, {another:?}"
            );
            for refused in FUZZ_REFUSED_SCHEMES {
                assert!(
                    !fuzz_client_cert(&input(refused, &signature)),
                    "leaf {n}, {refused:?}"
                );
            }
        }
    }

    /// Name constraints on a chain are webpki's, which evaluates those on
    /// IP addresses and DNS names and fails closed on the rest, where Go
    /// evaluates mailboxes and URIs too (PARITY.md, the clientcert entry).
    /// An IP subtree with host bits set covers what its masked network
    /// covers, in both.  An rfc822Name, URI or otherName subtree refuses
    /// every leaf naming a name of the subtree's own form, covered or
    /// not, and a directoryName subtree in a constraints extension that
    /// is not critical refuses every leaf, where Go accepts each.  The
    /// other way round, a DNS name or a mailbox Go cannot read, or a URI
    /// whose host is an IP address, refuses the chain under a constraint
    /// of any form, and passes webpki under one of another form, a
    /// mailbox with two periods in a row among them.  These divergent rows
    /// are the recorded ones.  A mailbox whose domain holds `@`, which Go
    /// 1.27 cannot read, refuses the chain in both under a constraint of
    /// any form, permitted or excluded, a registeredID subtree among them,
    /// on a certificate above the one naming it, the leaf or an
    /// intermediate, even one with constraints of its own, and after
    /// another name or a quoted local part; not when no certificate above
    /// it carries constraints, nor when only the one naming it does, and
    /// an `@` quoted or escaped in the local part is read.
    #[test]
    fn name_constraints_on_a_chain_are_webpkis() {
        use dcroxide_certgen::gentool::generate_key;
        use rustls::pki_types::CertificateDer;
        use rustls::server::danger::ClientCertVerifier;
        const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
        const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
        const SAN: &[u8] = &[0x55, 0x1d, 0x11];
        const NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];
        let secs = 1_790_000_000u64;
        let now = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(secs));
        let mut oracle = dcroxide_testutil::oracle_or_skip();
        let key = || generate_key("P-256").expect("key");
        let (root_key, int_key, leaf_key) = (key(), key(), key());
        // A subtree list ([0] permitted or [1] excluded) of one base.
        let subtrees = |tag: u8, base: Vec<u8>| der_tlv(tag, &der_tlv(0x30, &base));
        let permitted = |base: Vec<u8>| subtrees(0xa0, base);
        let excluded = |base: Vec<u8>| subtrees(0xa1, base);
        let ip = |bytes: &[u8]| der_tlv(0x87, bytes);
        let email = |name: &[u8]| der_tlv(0x81, name);
        let dns = |name: &[u8]| der_tlv(0x82, name);
        let uri = |name: &[u8]| der_tlv(0x86, name);
        let directory = der_tlv(0xa4, &der_tlv(0x30, &[]));
        // A user principal name (1.3.6.1.4.1.311.20.2.3), an otherName.
        let upn = || {
            let upn_oid = [
                0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03,
            ];
            let value = der_tlv(0xa0, &der_tlv(0x0c, b"a@example.com"));
            der_tlv(0xa0, &[&upn_oid[..], &value].concat())
        };
        let mask8 = [10, 0, 0, 1, 0xff, 0, 0, 0];
        // A CA's extensions, with name constraints and whether they are
        // critical, and a subject alternative name of one name.
        let authority = |constraints: Option<(&[u8], bool)>, name: Option<&[u8]>| {
            let mut extensions = vec![
                der_extension(
                    BASIC_CONSTRAINTS,
                    true,
                    &der_tlv(0x30, &der_tlv(0x01, &[0xff])),
                ),
                der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x02, 0x84])),
            ];
            if let Some((constraints, critical)) = constraints {
                extensions.push(der_extension(
                    NAME_CONSTRAINTS,
                    critical,
                    &der_tlv(0x30, constraints),
                ));
            }
            if let Some(name) = name {
                extensions.push(der_extension(SAN, false, &der_tlv(0x30, name)));
            }
            extensions
        };
        let leaf_below = |issuer: &str, issuer_key, name: &[u8]| {
            signed_p256_certificate(
                2,
                "leaf",
                &leaf_key,
                issuer,
                issuer_key,
                &[
                    der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x07, 0x80])),
                    der_extension(SAN, false, &der_tlv(0x30, name)),
                ],
            )
        };
        // Whether a certificate names a mailbox whose domain holds `@`.
        let names_an_at_domain = |der: &[u8]| {
            let (_, _, identity) = CertFacts::parse_all(der).expect("parses");
            identity.san.is_some_and(|san| {
                let mut names = DerReader::new(DerReader::new(san).read_tag(0x30).expect("names"));
                std::iter::from_fn(|| names.read())
                    .any(|(tag, name)| tag == 0x81 && go_mailbox_domain_holds_at(name))
            })
        };
        // The port's verdict on a chain and Go's, `sent` the certificates
        // the client sends beside the leaf.  Where Go refuses a chain
        // naming such a mailbox, it says it cannot read it.
        let mut judge = |label: &str,
                         root: &[u8],
                         sent: &[&[u8]],
                         leaf: &[u8],
                         port_accepts: bool,
                         go_accepts: bool| {
            let verifier =
                GoClientCertVerifier::from_pem(&certificate_pem(root)).expect("verifier");
            let presented: Vec<CertificateDer<'_>> =
                sent.iter().map(|der| CertificateDer::from(*der)).collect();
            let got = verifier
                .verify_client_cert(&CertificateDer::from(leaf), &presented, now)
                .map(|_| ());
            if port_accepts {
                assert!(got.is_ok(), "{label}: {got:?}");
            } else {
                assert!(
                    matches!(
                        &got,
                        Err(rustls::Error::InvalidCertificate(rustls::CertificateError::Other(other)))
                            if other.0.downcast_ref::<webpki::Error>()
                                == Some(&webpki::Error::NameConstraintViolation)
                    ),
                    "{label}: {got:?}"
                );
            }
            if let Some(GoVerdict { verdict, .. }) =
                go_client_verdict(&mut oracle, &[root], leaf, sent, secs)
            {
                assert_eq!(verdict == "ok", go_accepts, "{label}: Go says {verdict}");
                if !go_accepts
                    && std::iter::once(leaf)
                        .chain(sent.iter().copied())
                        .any(names_an_at_domain)
                {
                    assert!(
                        verdict.contains("cannot parse rfc822Name"),
                        "{label}: Go says {verdict}"
                    );
                }
            }
        };
        // label, constraints, whether critical, the leaf's one name, and
        // the verdicts of the port and of Go.
        for (label, constraints, critical, name, port_accepts, go_accepts) in [
            (
                "an IP inside a subtree with host bits",
                permitted(ip(&mask8)),
                true,
                ip(&[10, 1, 2, 3]),
                true,
                true,
            ),
            (
                "an IP outside it",
                permitted(ip(&mask8)),
                true,
                ip(&[11, 1, 2, 3]),
                false,
                false,
            ),
            (
                "a mailbox a permitted subtree covers",
                permitted(email(b"example.com")),
                true,
                email(b"a@example.com"),
                false,
                true,
            ),
            (
                "a mailbox no excluded subtree covers",
                excluded(email(b"other.example")),
                true,
                email(b"a@example.com"),
                false,
                true,
            ),
            (
                "a DNS name under a mailbox subtree",
                permitted(email(b"example.com")),
                true,
                dns(b"client.example.com"),
                true,
                true,
            ),
            (
                "a URI a permitted subtree covers",
                permitted(uri(b"example.com")),
                true,
                uri(b"https://example.com/"),
                false,
                true,
            ),
            (
                "a directoryName subtree, not critical",
                permitted(directory),
                false,
                dns(b"client.example.com"),
                false,
                true,
            ),
            (
                "an otherName subtree, not critical, over an otherName",
                permitted(upn()),
                false,
                upn(),
                false,
                true,
            ),
            (
                "a mailbox under a DNS subtree",
                permitted(dns(b"example.com")),
                true,
                email(b"a@example.com"),
                true,
                true,
            ),
            (
                "a mailbox whose domain holds @ under a DNS subtree",
                permitted(dns(b"example.com")),
                true,
                email(b"a@b@example.com"),
                false,
                false,
            ),
            (
                "a mailbox whose domain holds @ under an IP subtree",
                permitted(ip(&mask8)),
                true,
                email(b"a@b@example.com"),
                false,
                false,
            ),
            (
                "a mailbox whose domain holds @ under an excluded subtree",
                excluded(dns(b"other.example")),
                true,
                email(b"a@b@example.com"),
                false,
                false,
            ),
            (
                "a mailbox whose domain holds @ under a constraint not critical",
                permitted(dns(b"example.com")),
                false,
                email(b"a@b@example.com"),
                false,
                false,
            ),
            (
                "a mailbox whose domain holds @ under a registeredID subtree not critical",
                permitted(der_tlv(0x88, &[0x2a, 0x03])),
                false,
                email(b"a@b@example.com"),
                false,
                false,
            ),
            (
                "a mailbox whose domain holds @ after a DNS name",
                permitted(dns(b"example.com")),
                true,
                [&dns(b"client.example.com")[..], &email(b"a@b@example.com")].concat(),
                false,
                false,
            ),
            (
                "a quoted local part, then a domain holding @",
                permitted(dns(b"example.com")),
                true,
                email(br#""a@b"@c@example.com"#),
                false,
                false,
            ),
            (
                "a quoted local part holding @",
                permitted(dns(b"example.com")),
                true,
                email(br#""a@b"@example.com"#),
                true,
                true,
            ),
            (
                "an escaped @ in the local part",
                permitted(dns(b"example.com")),
                true,
                email(br"a\@b@example.com"),
                true,
                true,
            ),
            (
                "an escaped backslash, then a domain holding @",
                permitted(dns(b"example.com")),
                true,
                email(br"a\\@b@example.com"),
                false,
                false,
            ),
            (
                "a mailbox Go 1.26 could not read either under a DNS subtree",
                permitted(dns(b"example.com")),
                true,
                email(b"a..b@example.com"),
                true,
                false,
            ),
            (
                "a DNS name with an empty label under an IP subtree",
                permitted(ip(&mask8)),
                true,
                dns(b"a..example.com"),
                true,
                false,
            ),
            (
                "a URI whose host is an IP under a DNS subtree",
                permitted(dns(b"example.com")),
                true,
                uri(b"https://1.2.3.4/"),
                true,
                false,
            ),
        ] {
            let root = signed_p256_certificate(
                1,
                "root",
                &root_key,
                "root",
                &root_key,
                &authority(Some((&constraints, critical)), None),
            );
            let leaf = leaf_below("root", &root_key, &name);
            judge(label, &root, &[], &leaf, port_accepts, go_accepts);
        }
        // The same through an intermediate: label, the constraints on the
        // root and on the intermediate, the intermediate's one name and
        // the leaf's, and the verdicts of the port and of Go.
        for (label, root_constraints, int_constraints, int_name, name, port_accepts, go_accepts) in [
            (
                "a mailbox whose domain holds @ named by an intermediate below a \
                 constrained root",
                Some(permitted(dns(b"example.com"))),
                None,
                Some(email(b"a@b@example.com")),
                dns(b"client.example.com"),
                false,
                false,
            ),
            (
                "a mailbox whose domain holds @ named by a constrained intermediate \
                 below a constrained root",
                Some(permitted(dns(b"example.com"))),
                Some(permitted(dns(b"example.com"))),
                Some(email(b"a@b@example.com")),
                dns(b"client.example.com"),
                false,
                false,
            ),
            (
                "a mailbox whose domain holds @ named by the constrained intermediate",
                None,
                Some(permitted(dns(b"example.com"))),
                Some(email(b"a@b@example.com")),
                dns(b"client.example.com"),
                true,
                true,
            ),
            (
                "a mailbox whose domain holds @ below a constrained intermediate",
                None,
                Some(permitted(dns(b"example.com"))),
                None,
                email(b"a@b@example.com"),
                false,
                false,
            ),
            (
                "a mailbox whose domain holds @ with no constraints above it",
                None,
                None,
                None,
                email(b"a@b@example.com"),
                true,
                true,
            ),
        ] {
            let root = signed_p256_certificate(
                1,
                "root",
                &root_key,
                "root",
                &root_key,
                &authority(root_constraints.as_deref().map(|c| (c, true)), None),
            );
            let int = signed_p256_certificate(
                3,
                "int",
                &int_key,
                "root",
                &root_key,
                &authority(
                    int_constraints.as_deref().map(|c| (c, true)),
                    int_name.as_deref(),
                ),
            );
            let leaf = leaf_below("int", &int_key, &name);
            judge(label, &root, &[&int], &leaf, port_accepts, go_accepts);
        }
    }

    /// A chain refused for a mailbox whose domain holds `@` is refused in
    /// Go's order (`verify.go:630-668`): after the policies, so the only
    /// chain failing both is logged with the policy count; after the key
    /// usage, which webpki checks first; ahead of a distrusted key; and
    /// ahead of every other reason the other chains were dropped for, so
    /// one chain dropped for its policies beside it leaves the name
    /// constraint error, whichever comes first.  Each verdict is compared
    /// with Go's, the distrusted key's chain with Go's verdict on the same
    /// chain, whose table does not hold the key.
    #[test]
    fn a_mailbox_whose_domain_holds_at_is_refused_in_gos_order() {
        use dcroxide_certgen::gentool::generate_key;
        use rustls::pki_types::CertificateDer;
        use rustls::server::danger::ClientCertVerifier;
        const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
        const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
        const EKU: &[u8] = &[0x55, 0x1d, 0x25];
        const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
        const SAN: &[u8] = &[0x55, 0x1d, 0x11];
        const NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];
        const POLICIES: &[u8] = &[0x55, 0x1d, 0x20];
        const POLICY_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x24];
        const CONSTRAINT: &str = "x509: a root or intermediate certificate is not authorized to \
                                  sign for this name: cannot parse rfc822Name";
        let secs = 1_790_000_000u64;
        let now = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(secs));
        let mut oracle = dcroxide_testutil::oracle_or_skip();
        let key = || generate_key("P-256").expect("key");
        let (root_key, int_key, leaf_key) = (key(), key(), key());
        let authority = vec![
            der_extension(
                BASIC_CONSTRAINTS,
                true,
                &der_tlv(0x30, &der_tlv(0x01, &[0xff])),
            ),
            der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x02, 0x84])),
        ];
        let constrained = der_extension(
            NAME_CONSTRAINTS,
            true,
            &der_tlv(
                0x30,
                &der_tlv(0xa0, &der_tlv(0x30, &der_tlv(0x82, b"example.com"))),
            ),
        );
        // requireExplicitPolicy 0 and one policy, which the leaf does not
        // name.
        let requiring = [
            der_extension(
                POLICY_CONSTRAINTS,
                false,
                &der_tlv(0x30, &der_tlv(0x80, &[0])),
            ),
            der_extension(
                POLICIES,
                false,
                &der_tlv(
                    0x30,
                    &der_tlv(0x30, &der_tlv(0x06, &oid_contents(&[1, 2, 3, 1]))),
                ),
            ),
        ];
        let server_only = der_extension(EKU, false, &der_tlv(0x30, &der_tlv(0x06, SERVER_AUTH)));
        let root = signed_p256_certificate(1, "root", &root_key, "root", &root_key, &authority);
        // Copies of the leaf's issuer, each with the extensions given.
        let int = |serial: u8, extra: &[&Vec<u8>]| {
            let extensions: Vec<Vec<u8>> = authority
                .iter()
                .chain(extra.iter().copied())
                .cloned()
                .collect();
            signed_p256_certificate(serial, "int", &int_key, "root", &root_key, &extensions)
        };
        let int_constrained = int(3, &[&constrained]);
        let int_requiring = int(4, &[&requiring[0], &requiring[1]]);
        let int_both = int(5, &[&constrained, &requiring[0], &requiring[1]]);
        let int_server = int(6, &[&constrained, &server_only]);
        let leaf = signed_p256_certificate(
            2,
            "leaf",
            &leaf_key,
            "int",
            &int_key,
            &[
                der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x07, 0x80])),
                der_extension(
                    SAN,
                    false,
                    &der_tlv(0x30, &der_tlv(0x81, b"a@b@example.com")),
                ),
            ],
        );
        // The verifier over the root, with a table naming the keys of the
        // certificates given in place of Go's.
        let verifier = |distrusted: &[&[u8]]| {
            let hashes: Vec<&'static str> = distrusted
                .iter()
                .map(|der| {
                    let (_, _, identity) = CertFacts::parse_all(der).expect("parses");
                    &*Box::leak(
                        go_sha256_hex(identity.spki)
                            .expect("sha-256")
                            .into_boxed_str(),
                    )
                })
                .collect();
            GoClientCertVerifier::from_pem(&certificate_pem(&root))
                .expect("verifier")
                .distrusting(Box::leak(hashes.into_boxed_slice()))
        };
        let is_constraint = |got: &Result<(), rustls::Error>| {
            matches!(
                got,
                Err(rustls::Error::InvalidCertificate(rustls::CertificateError::Other(other)))
                    if other.0.downcast_ref::<webpki::Error>()
                        == Some(&webpki::Error::NameConstraintViolation)
            )
        };
        for (label, sent, distrusted, want_go) in [
            (
                "policies first",
                vec![&int_both],
                vec![],
                "x509: no valid chains built: 1 candidate chains with invalid policies",
            ),
            (
                "key usage first",
                vec![&int_server],
                vec![],
                "x509: certificate specifies an incompatible key usage",
            ),
            (
                "ahead of a distrusted key",
                vec![&int_constrained],
                vec![&int_constrained],
                CONSTRAINT,
            ),
            (
                "ahead of a chain dropped for its policies, sent after",
                vec![&int_constrained, &int_requiring],
                vec![],
                CONSTRAINT,
            ),
            (
                "ahead of a chain dropped for its policies, sent before",
                vec![&int_requiring, &int_constrained],
                vec![],
                CONSTRAINT,
            ),
        ] {
            let distrusted: Vec<&[u8]> = distrusted.iter().map(|der| der.as_slice()).collect();
            let sent: Vec<&[u8]> = sent.iter().map(|der| der.as_slice()).collect();
            let presented: Vec<CertificateDer<'_>> =
                sent.iter().map(|der| CertificateDer::from(*der)).collect();
            let got = verifier(&distrusted)
                .verify_client_cert(&CertificateDer::from(leaf.as_slice()), &presented, now)
                .map(|_| ());
            if want_go == CONSTRAINT {
                assert!(is_constraint(&got), "{label}: {got:?}");
            } else if want_go.contains("key usage") {
                assert!(
                    matches!(
                        got,
                        Err(rustls::Error::InvalidCertificate(
                            rustls::CertificateError::InvalidPurposeContext { .. }
                        ))
                    ),
                    "{label}: {got:?}"
                );
            } else {
                let err = got.expect_err(label);
                assert_eq!(
                    crate::server::go_error_text_for_tests(&err),
                    format!("tls: failed to verify certificate: {want_go}"),
                    "{label}"
                );
            }
            if let Some(GoVerdict { verdict, .. }) =
                go_client_verdict(&mut oracle, &[&root], &leaf, &sent, secs)
            {
                assert!(verdict.starts_with(want_go), "{label}: Go says {verdict}");
            }
        }
    }

    /// Every certificate a client presents is held to Go's
    /// `ParseCertificate`, as far as [`CertFacts::parse`] reads it, and to
    /// the unhandled critical extension rule of Go's `isValid`, where
    /// webpki takes a critical subject alternative name or name
    /// constraints extension of a form Go does not handle as understood.
    /// A leaf whose critical subject alternative name names only a
    /// registered identifier is refused, one naming a DNS name is not; a
    /// path through an intermediate whose critical name constraints hold
    /// a registered identifier subtree is passed over for another, and
    /// refused when it is the only one; and a certificate Go's parser
    /// refuses, here one carrying an extension twice or an IPv4-mapped
    /// address in its subject alternative name, ends the handshake even
    /// when no path uses it, as does an intermediate on the path whose
    /// mailbox constraint Go 1.27 cannot read.  rustls's own client
    /// verifier accepts each of the refused chains.
    #[test]
    fn a_presented_certificate_takes_gos_unhandled_critical_rule() {
        use dcroxide_certgen::gentool::generate_key;
        use rustls::pki_types::CertificateDer;
        use rustls::server::danger::ClientCertVerifier;
        const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
        const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
        const SAN: &[u8] = &[0x55, 0x1d, 0x11];
        const NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];
        // A registeredID GeneralName, 1.2.3, and a dNSName.
        let registered = der_tlv(0x88, &[0x2a, 0x03]);
        let dns = der_tlv(0x82, b"client.example");
        let now = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(1_790_000_000));
        let key = || generate_key("P-256").expect("key");
        let (root_key, int_key, leaf_key) = (key(), key(), key());
        let authority = vec![
            der_extension(
                BASIC_CONSTRAINTS,
                true,
                &der_tlv(0x30, &der_tlv(0x01, &[0xff])),
            ),
            der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x02, 0x84])),
        ];
        let signing = der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x07, 0x80]));

        let root = signed_p256_certificate(1, "root", &root_key, "root", &root_key, &authority);
        let ours = GoClientCertVerifier::from_pem(&certificate_pem(&root)).expect("verifier");
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(root.as_slice()))
            .expect("the root");
        let theirs = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(dcroxide_tlscrypto::default_provider()),
        )
        .build()
        .expect("webpki's verifier");
        let check = |verifier: &dyn ClientCertVerifier, leaf: &[u8], sent: &[&[u8]]| {
            let sent: Vec<_> = sent.iter().map(|der| CertificateDer::from(*der)).collect();
            verifier
                .verify_client_cert(&CertificateDer::from(leaf), &sent, now)
                .map(|_| ())
        };
        let unhandled = Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnhandledCriticalExtension,
        ));
        let unparsed = Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::BadEncoding,
        ));

        // A leaf the root signs, by the critical subject alternative
        // name it carries.
        let named = |serial: u8, name: &[u8]| {
            let san = der_extension(SAN, true, &der_tlv(0x30, name));
            signed_p256_certificate(
                serial,
                "leaf",
                &leaf_key,
                "root",
                &root_key,
                &[signing.clone(), san],
            )
        };
        let registered_leaf = named(2, &registered);
        check(&*theirs, &registered_leaf, &[]).expect("webpki takes the name as understood");
        assert_eq!(check(&ours, &registered_leaf, &[]), unhandled);
        check(&ours, &named(3, &dns), &[]).expect("a DNS name Go handles");

        // An intermediate whose critical name constraints permit only a
        // registered identifier subtree, beside one without them.
        let constrained = {
            let subtree = der_tlv(0x30, &registered);
            let constraints = der_extension(
                NAME_CONSTRAINTS,
                true,
                &der_tlv(0x30, &der_tlv(0xa0, &subtree)),
            );
            let extensions = [authority.clone(), vec![constraints]].concat();
            signed_p256_certificate(4, "int", &int_key, "root", &root_key, &extensions)
        };
        let plain = signed_p256_certificate(5, "int", &int_key, "root", &root_key, &authority);
        let leaf = signed_p256_certificate(
            6,
            "leaf",
            &leaf_key,
            "int",
            &int_key,
            std::slice::from_ref(&signing),
        );
        check(&*theirs, &leaf, &[&constrained]).expect("webpki takes the subtree as understood");
        assert_eq!(check(&ours, &leaf, &[&constrained]), unhandled);
        check(&ours, &leaf, &[&constrained, &plain]).expect("the path without it");

        // An extension twice, which Go's parser refuses: on the leaf, and
        // on an intermediate sent beside the path, which no path uses.
        let twice = der_extension(&[0x2a, 0x03, 0x04], false, &[0x05, 0x00]);
        let doubled_leaf = signed_p256_certificate(
            7,
            "leaf",
            &leaf_key,
            "int",
            &int_key,
            &[signing.clone(), twice.clone(), twice.clone()],
        );
        let doubled_spare = signed_p256_certificate(
            8,
            "spare",
            &int_key,
            "root",
            &root_key,
            &[authority.clone(), vec![twice.clone(), twice]].concat(),
        );
        check(&*theirs, &doubled_leaf, &[&plain]).expect("webpki ignores the repeated extension");
        assert_eq!(check(&ours, &doubled_leaf, &[&plain]), unparsed);
        check(&*theirs, &leaf, &[&plain, &doubled_spare])
            .expect("webpki builds no path through the spare");
        assert_eq!(check(&ours, &leaf, &[&plain, &doubled_spare]), unparsed);

        // Names Go 1.27 refuses at parse: an IPv4-mapped address in the
        // subject alternative name of an intermediate sent beside the
        // path, and a mailbox constraint whose domain holds `@` on the
        // only intermediate of the path, which webpki leaves alone while
        // the leaf names no mailbox.
        let mapped = der_tlv(0x87, &[&[0u8; 10][..], &[0xff, 0xff, 1, 2, 3, 4]].concat());
        let mapped_spare = signed_p256_certificate(
            9,
            "spare",
            &int_key,
            "root",
            &root_key,
            &[
                authority.clone(),
                vec![der_extension(SAN, false, &der_tlv(0x30, &mapped))],
            ]
            .concat(),
        );
        check(&*theirs, &leaf, &[&plain, &mapped_spare])
            .expect("webpki builds no path through the spare");
        assert_eq!(check(&ours, &leaf, &[&plain, &mapped_spare]), unparsed);
        let mailbox = {
            let subtree = der_tlv(0x30, &der_tlv(0x81, b"a@b@example.com"));
            let constraints = der_extension(
                NAME_CONSTRAINTS,
                true,
                &der_tlv(0x30, &der_tlv(0xa0, &subtree)),
            );
            let extensions = [authority.clone(), vec![constraints]].concat();
            signed_p256_certificate(10, "int", &int_key, "root", &root_key, &extensions)
        };
        check(&*theirs, &leaf, &[&mailbox]).expect("webpki takes the path");
        assert_eq!(check(&ours, &leaf, &[&mailbox]), unparsed);
    }

    /// One of Go's certificate policy vectors (`tests/data/x509-policy`),
    /// as DER.
    fn policy_vector(name: &str) -> Vec<u8> {
        let path = format!(
            "{}/tests/data/x509-policy/{name}.pem",
            env!("CARGO_MANIFEST_DIR")
        );
        let pem = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        go_pem_decode(&pem).expect("a PEM block").0.bytes
    }

    /// An object identifier's DER contents from its arcs.
    // Base-128 digits of each arc.
    #[allow(clippy::arithmetic_side_effects)]
    fn oid_contents(arcs: &[u64]) -> Vec<u8> {
        let mut out = Vec::new();
        for value in std::iter::once(arcs[0] * 40 + arcs[1]).chain(arcs[2..].iter().copied()) {
            let mut digits = vec![(value & 0x7f) as u8];
            let mut rest = value >> 7;
            while rest > 0 {
                digits.push(((rest & 0x7f) as u8) | 0x80);
                rest >>= 7;
            }
            digits.reverse();
            out.extend(digits);
        }
        out
    }

    /// `go_policies_valid` answers every case of Go's `TestPoliciesValid`
    /// (`crypto/x509/verify_test.go`, BoringSSL's before it) over the
    /// same certificates, read by `CertFacts::parse_all`: the
    /// chain with its trust anchor left out, the initial policy set and
    /// the three initial flags.
    #[test]
    fn go_policies_valid_matches_gos_vectors() {
        let test_oid = |n: u64| oid_contents(&[1, 2, 840, 113554, 4, 1, 72585, 2, n]);
        let facts = |name: &str| {
            CertFacts::parse_all(&policy_vector(name))
                .unwrap_or_else(|| panic!("{name} parses"))
                .1
        };
        // (chain without the trust anchor, initial policies,
        // requireExplicitPolicy, inhibitPolicyMapping, inhibitAnyPolicy,
        // valid)
        type Case = (Vec<&'static str>, Vec<u64>, bool, bool, bool, bool);
        let mut cases: Vec<Case> = vec![
            // The chain is good for oid1 and oid2, but not oid3.
            (
                vec!["policy_leaf", "policy_intermediate"],
                vec![],
                true,
                false,
                false,
                true,
            ),
            (
                vec!["policy_leaf", "policy_intermediate"],
                vec![1],
                true,
                false,
                false,
                true,
            ),
            (
                vec!["policy_leaf", "policy_intermediate"],
                vec![2],
                true,
                false,
                false,
                true,
            ),
            (
                vec!["policy_leaf", "policy_intermediate"],
                vec![3],
                true,
                false,
                false,
                false,
            ),
            (
                vec!["policy_leaf", "policy_intermediate"],
                vec![1, 2],
                true,
                false,
                false,
                true,
            ),
            (
                vec!["policy_leaf", "policy_intermediate"],
                vec![1, 3],
                true,
                false,
                false,
                true,
            ),
            // Without requireExplicitPolicy no valid policy is required.
            (
                vec!["policy_leaf", "policy_intermediate"],
                vec![1],
                false,
                false,
                false,
                true,
            ),
            (
                vec!["policy_leaf", "policy_intermediate"],
                vec![3],
                false,
                false,
                false,
                true,
            ),
            // A CA's policy constraints can require an explicit policy.
            (
                vec!["policy_leaf", "policy_intermediate_require"],
                vec![1],
                false,
                false,
                false,
                true,
            ),
            (
                vec!["policy_leaf", "policy_intermediate_require"],
                vec![3],
                false,
                false,
                false,
                false,
            ),
            (
                vec!["policy_leaf_none", "policy_intermediate_require"],
                vec![],
                true,
                false,
                false,
                false,
            ),
            // So can a leaf's.
            (
                vec!["policy_leaf_require", "policy_intermediate"],
                vec![],
                false,
                false,
                false,
                true,
            ),
            (
                vec!["policy_leaf_require", "policy_intermediate"],
                vec![1],
                false,
                false,
                false,
                true,
            ),
            (
                vec!["policy_leaf_require", "policy_intermediate"],
                vec![3],
                false,
                false,
                false,
                false,
            ),
            // requireExplicitPolicy counts certificates to skip.
            (
                vec!["policy_leaf", "policy_intermediate_require1"],
                vec![3],
                false,
                false,
                false,
                false,
            ),
            (
                vec!["policy_leaf", "policy_intermediate_require2"],
                vec![3],
                false,
                false,
                false,
                true,
            ),
            (
                vec!["policy_leaf_require1", "policy_intermediate"],
                vec![3],
                false,
                false,
                false,
                true,
            ),
            // The more constrained value wins.
            (
                vec!["policy_leaf_require1", "policy_intermediate_require1"],
                vec![3],
                false,
                false,
                false,
                false,
            ),
            (
                vec!["policy_leaf_require", "policy_intermediate_require2"],
                vec![3],
                false,
                false,
                false,
                false,
            ),
            // A CA requiring an explicit policy and naming none.
            (
                vec!["policy_leaf", "policy_intermediate_require_no_policies"],
                vec![1],
                false,
                false,
                false,
                false,
            ),
            // anyPolicy on the leaf, the intermediate, and both.
            (
                vec!["policy_leaf_any", "policy_intermediate"],
                vec![1],
                true,
                false,
                false,
                true,
            ),
            (
                vec!["policy_leaf_any", "policy_intermediate"],
                vec![3],
                true,
                false,
                false,
                false,
            ),
            (
                vec!["policy_leaf", "policy_intermediate_any"],
                vec![1],
                true,
                false,
                false,
                true,
            ),
            (
                vec!["policy_leaf", "policy_intermediate_any"],
                vec![3],
                true,
                false,
                false,
                false,
            ),
            (
                vec!["policy_leaf_any", "policy_intermediate_any"],
                vec![1],
                true,
                false,
                false,
                true,
            ),
            (
                vec!["policy_leaf_any", "policy_intermediate_any"],
                vec![3],
                true,
                false,
                false,
                true,
            ),
            // The trust anchor alone.
            (vec![], vec![1], true, false, false, true),
            // Many mappings, of which only oid3's are accepted.
            (
                vec!["policy_leaf_oid1", "policy_intermediate_mapped_oid3"],
                vec![3],
                true,
                false,
                false,
                true,
            ),
            (
                vec!["policy_leaf_oid4", "policy_intermediate_mapped_oid3"],
                vec![4],
                true,
                false,
                false,
                false,
            ),
            // Mapping inhibited by the caller, and by a certificate.
            (
                vec!["policy_leaf_oid1", "policy_intermediate_mapped_oid3"],
                vec![3],
                true,
                true,
                false,
                false,
            ),
            (
                vec![
                    "policy_leaf_oid1",
                    "policy_intermediate_mapped_oid3",
                    "policy_root_cross_inhibit_mapping",
                ],
                vec![3],
                true,
                false,
                false,
                false,
            ),
        ];
        for use_any in [false, true] {
            let mapped = if use_any {
                "policy_intermediate_mapped_any"
            } else {
                "policy_intermediate_mapped"
            };
            cases.extend([
                (
                    vec!["policy_leaf", mapped],
                    vec![3],
                    true,
                    false,
                    false,
                    true,
                ),
                (
                    vec!["policy_leaf_oid1", mapped],
                    vec![3],
                    true,
                    false,
                    false,
                    true,
                ),
                (
                    vec!["policy_leaf_oid2", mapped],
                    vec![3],
                    true,
                    false,
                    false,
                    true,
                ),
                (
                    vec!["policy_leaf_oid3", mapped],
                    vec![3],
                    true,
                    false,
                    false,
                    use_any,
                ),
                (
                    vec!["policy_leaf_oid1", mapped],
                    vec![1],
                    true,
                    false,
                    false,
                    !use_any,
                ),
                (
                    vec!["policy_leaf_oid4", mapped],
                    vec![4],
                    true,
                    false,
                    false,
                    true,
                ),
                (
                    vec!["policy_leaf_oid4", mapped],
                    vec![5],
                    true,
                    false,
                    false,
                    true,
                ),
                (
                    vec!["policy_leaf_oid5", mapped],
                    vec![4],
                    true,
                    false,
                    false,
                    true,
                ),
                (
                    vec!["policy_leaf_oid5", mapped],
                    vec![5],
                    true,
                    false,
                    false,
                    true,
                ),
                (
                    vec!["policy_leaf_oid4", mapped],
                    vec![4, 5],
                    true,
                    false,
                    false,
                    true,
                ),
            ]);
        }
        assert_eq!(
            cases.len(),
            51,
            "every case of Go's table, the mapped ten twice"
        );
        for (i, (chain, policies, require, inhibit_mapping, inhibit_any, valid)) in
            cases.into_iter().enumerate()
        {
            let chain_facts: Vec<PolicyFacts> = chain.iter().map(|name| facts(name)).collect();
            let chain_refs: Vec<&PolicyFacts> = chain_facts.iter().collect();
            let opts = PolicyOptions {
                policies: policies.iter().map(|&n| test_oid(n)).collect(),
                require_explicit_policy: require,
                inhibit_policy_mapping: inhibit_mapping,
                inhibit_any_policy: inhibit_any,
            };
            assert_eq!(
                go_policies_valid(&chain_refs, &opts),
                valid,
                "case {i}: {chain:?}, policies {policies:?}, require {require}"
            );
        }
    }

    /// The policy vectors Go's parser refuses, the two `TestParsePolicies`
    /// reads and the three intermediates no Go test reads, each listing a
    /// policy twice or carrying a certificate policies value that is not
    /// a SEQUENCE, are refused here, and so the pool skips them and a
    /// client presenting one gets no handshake.  Six of the others, the
    /// root among them, parse here, and the vectors the table's chains
    /// use parse in `go_policies_valid_matches_gos_vectors`.
    #[test]
    fn policies_go_refuses_to_parse_are_refused() {
        for name in [
            "policy_leaf_duplicate",
            "policy_leaf_invalid",
            "policy_intermediate_duplicate",
            "policy_intermediate_invalid",
            "policy_intermediate_require_duplicate",
        ] {
            assert!(CertFacts::parse(&policy_vector(name)).is_none(), "{name}");
        }
        for name in [
            "policy_root",
            "policy_intermediate",
            "policy_intermediate_mapped",
            "policy_intermediate_require",
            "policy_leaf",
            "policy_leaf_any",
        ] {
            assert!(CertFacts::parse(&policy_vector(name)).is_some(), "{name}");
        }
    }

    /// The four policy extensions are read as Go's `processExtensions`
    /// reads them through cryptobyte (`crypto/x509/parser.go`): a length
    /// in more octets than it needs, a policy identifier
    /// `newOIDFromDER` refuses, a policy listed twice, and an integer
    /// `checkASN1Integer` or `asn1Signed` refuses each fail the parse,
    /// while qualifiers, trailing bytes, a constructed element where an
    /// implicit integer may stand, and mapped identifiers of any shape
    /// are taken as Go takes them.
    #[test]
    fn policy_extensions_are_read_by_gos_rules() {
        const POLICIES: &[u8] = &[0x55, 0x1d, 0x20];
        const POLICY_MAPPINGS: &[u8] = &[0x55, 0x1d, 0x21];
        const POLICY_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x24];
        const INHIBIT_ANY_POLICY: &[u8] = &[0x55, 0x1d, 0x36];
        let read = |oid: &[u8], value: &[u8]| {
            CertFacts::parse_all(&der_certificate(
                Some(2),
                &[der_extension(oid, false, value)],
            ))
            .map(|(_, policies, _)| policies)
        };
        // Twenty policies of seven octets each, 140 in all, so the
        // SEQUENCE needs a long-form length.
        let many: Vec<u8> = (0..20u8)
            .flat_map(|n| der_tlv(0x30, &der_tlv(0x06, &[0x2a, 0x03, n])))
            .collect();
        let refused: &[(&[u8], Vec<u8>)] = &[
            (
                POLICIES,
                vec![0x30, 0x81, 0x05, 0x30, 0x03, 0x06, 0x01, 0x2a],
            ),
            (POLICIES, [&[0x30, 0x82, 0x00, 0x8c][..], &many].concat()),
            (POLICIES, vec![0x30, 0x04, 0x30, 0x02, 0x06, 0x00]),
            (
                POLICIES,
                vec![0x30, 0x06, 0x30, 0x04, 0x06, 0x02, 0x2a, 0x80],
            ),
            (
                POLICIES,
                vec![0x30, 0x06, 0x30, 0x04, 0x06, 0x02, 0x80, 0x01],
            ),
            (
                POLICIES,
                vec![0x30, 0x07, 0x30, 0x05, 0x06, 0x03, 0x2a, 0x80, 0x01],
            ),
            (
                POLICIES,
                vec![
                    0x30, 0x0a, 0x30, 0x03, 0x06, 0x01, 0x2a, 0x30, 0x03, 0x06, 0x01, 0x2a,
                ],
            ),
            (POLICIES, b"INVALID".to_vec()),
            (
                POLICY_MAPPINGS,
                vec![
                    0x30, 0x81, 0x08, 0x30, 0x06, 0x06, 0x01, 0x2a, 0x06, 0x01, 0x2b,
                ],
            ),
            (
                POLICY_MAPPINGS,
                vec![0x30, 0x05, 0x30, 0x03, 0x06, 0x01, 0x2a],
            ),
            (POLICY_CONSTRAINTS, vec![0x30, 0x02, 0x80, 0x00]),
            (POLICY_CONSTRAINTS, vec![0x30, 0x04, 0x80, 0x02, 0x00, 0x01]),
            (POLICY_CONSTRAINTS, vec![0x30, 0x04, 0x80, 0x02, 0xff, 0x80]),
            (POLICY_CONSTRAINTS, vec![0x30, 0x04, 0x80, 0x81, 0x01, 0x00]),
            (
                POLICY_CONSTRAINTS,
                [&[0x30, 0x0b, 0x81, 0x09, 0x01][..], &[0; 8]].concat(),
            ),
            (INHIBIT_ANY_POLICY, vec![0x02, 0x00]),
            (INHIBIT_ANY_POLICY, vec![0x02, 0x81, 0x01, 0x00]),
            (INHIBIT_ANY_POLICY, vec![0x04, 0x01, 0x00]),
        ];
        for (oid, value) in refused {
            assert_eq!(read(oid, value), None, "{oid:02x?} {value:02x?}");
        }

        let facts = |policies: Vec<Vec<u8>>| PolicyFacts {
            policies,
            self_issued: true,
            ..PolicyFacts::default()
        };
        // A subidentifier of 2^32 - 1, which `newOIDFromDER` takes though
        // cryptobyte's `ReadASN1ObjectIdentifier` would not.
        let wide = vec![0x2a, 0x8f, 0xff, 0xff, 0xff, 0x7f];
        assert_eq!(
            read(
                POLICIES,
                &der_tlv(0x30, &der_tlv(0x30, &der_tlv(0x06, &wide)))
            ),
            Some(facts(vec![wide]))
        );
        // A qualifier after the identifier, and bytes after the SEQUENCE.
        let qualified = der_tlv(
            0x30,
            &[der_tlv(0x06, &[0x2a]), der_tlv(0x30, &[0x05, 0x00])].concat(),
        );
        assert_eq!(
            read(
                POLICIES,
                &[der_tlv(0x30, &qualified), vec![0xff, 0xff]].concat()
            ),
            Some(facts(vec![vec![0x2a]]))
        );
        assert_eq!(
            read(POLICIES, &[&[0x30, 0x81, 0x8c][..], &many].concat()),
            Some(facts((0..20u8).map(|n| vec![0x2a, 0x03, n]).collect()))
        );
        assert_eq!(
            read(
                POLICY_MAPPINGS,
                &[0x30, 0x06, 0x30, 0x04, 0x06, 0x00, 0x06, 0x00]
            ),
            Some(PolicyFacts {
                mappings: vec![(vec![], vec![])],
                ..facts(vec![])
            })
        );
        assert_eq!(
            read(
                POLICY_CONSTRAINTS,
                &[0x30, 0x06, 0x80, 0x01, 0xff, 0x81, 0x01, 0x7f]
            ),
            Some(PolicyFacts {
                require_explicit_policy: Some(-1),
                inhibit_policy_mapping: Some(127),
                ..facts(vec![])
            })
        );
        // A constructed [0] is not the implicit INTEGER, and stops the
        // read of [1] behind it, as cryptobyte's `PeekASN1Tag` does.
        assert_eq!(
            read(
                POLICY_CONSTRAINTS,
                &[0x30, 0x08, 0xa0, 0x03, 0x02, 0x01, 0x00, 0x81, 0x01, 0x00]
            ),
            Some(facts(vec![]))
        );
        assert_eq!(
            read(
                INHIBIT_ANY_POLICY,
                &[0x02, 0x08, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
            ),
            Some(PolicyFacts {
                inhibit_any_policy: Some(i64::MAX),
                ..facts(vec![])
            })
        );
        assert_eq!(
            read(INHIBIT_ANY_POLICY, &[0x02, 0x01, 0x80]),
            Some(PolicyFacts {
                inhibit_any_policy: Some(-128),
                ..facts(vec![])
            })
        );
    }

    /// Go's `alreadyInChain`: the subject and key must match, and the
    /// subject alternative names must both be absent or both be equal,
    /// the walk ending at the first match of subject and key that has a
    /// name on one side only.
    #[test]
    fn chain_identity_follows_gos_already_in_chain() {
        let id = |subject: &'static [u8], spki: &'static [u8], san: Option<&'static [u8]>| {
            ChainIdentity { subject, spki, san }
        };
        let root = id(b"root", b"key", None);
        let chain = [id(b"leaf", b"other", None), id(b"root", b"key", None)];
        assert!(root.already_in(&chain));
        assert!(!root.already_in(&chain[..1]));
        assert!(!id(b"root", b"key2", None).already_in(&chain));
        assert!(!id(b"root2", b"key", None).already_in(&chain));
        assert!(!id(b"root", b"key", Some(b"a")).already_in(&chain));
        let named = [id(b"root", b"key", Some(b"a"))];
        assert!(id(b"root", b"key", Some(b"a")).already_in(&named));
        assert!(!id(b"root", b"key", Some(b"b")).already_in(&named));
        assert!(!root.already_in(&named));
        // Go returns at the first certificate with the subject and key
        // when only one of the two carries a name, and walks on past one
        // whose name differs.
        let both = [id(b"root", b"key", Some(b"a")), id(b"root", b"key", None)];
        assert!(!root.already_in(&both));
        let renamed = [
            id(b"root", b"key", Some(b"b")),
            id(b"root", b"key", Some(b"a")),
        ];
        assert!(id(b"root", b"key", Some(b"a")).already_in(&renamed));
    }

    /// A client chain is held to Go's policy validation, with the options
    /// dcrd's TLS server leaves Go's: an intermediate whose policy
    /// constraints require an explicit policy refuses a leaf that names
    /// none, or names one the intermediate does not, and accepts one
    /// naming its policy; an intermediate mapping anyPolicy refuses the
    /// chain; a refused path sends the search on to another; and the
    /// refusal is logged as Go's `NoValidChains`.  rustls's own client
    /// verifier accepts the refused chains it is shown.  The chains
    /// counted are those Go builds: none through a copy of the root the
    /// client sent, which would otherwise pass the anyPolicy mapping, and
    /// one for a certificate sent twice or a root the pool lists twice.
    /// Once a chain has been refused for its policies, a signature
    /// budget that then runs out leaves the refusal logged as Go logs it.
    #[test]
    fn a_client_chain_takes_gos_policy_validation() {
        use dcroxide_certgen::gentool::generate_key;
        use rustls::pki_types::CertificateDer;
        use rustls::server::danger::ClientCertVerifier;
        const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
        const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
        const POLICIES: &[u8] = &[0x55, 0x1d, 0x20];
        const POLICY_MAPPINGS: &[u8] = &[0x55, 0x1d, 0x21];
        const POLICY_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x24];
        let now = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(1_790_000_000));
        let key = || generate_key("P-256").expect("key");
        let (root_key, int_key, leaf_key) = (key(), key(), key());
        let (one, two) = (oid_contents(&[1, 2, 3, 1]), oid_contents(&[1, 2, 3, 2]));
        let policies = |oids: &[&[u8]]| {
            let infos: Vec<u8> = oids
                .iter()
                .flat_map(|oid| der_tlv(0x30, &der_tlv(0x06, oid)))
                .collect();
            der_extension(POLICIES, false, &der_tlv(0x30, &infos))
        };
        // requireExplicitPolicy 0.
        let require = der_extension(
            POLICY_CONSTRAINTS,
            false,
            &der_tlv(0x30, &der_tlv(0x80, &[0])),
        );
        let authority = vec![
            der_extension(
                BASIC_CONSTRAINTS,
                true,
                &der_tlv(0x30, &der_tlv(0x01, &[0xff])),
            ),
            der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x02, 0x84])),
        ];
        let signing = der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x07, 0x80]));

        let root = signed_p256_certificate(1, "root", &root_key, "root", &root_key, &authority);
        let ours = GoClientCertVerifier::from_pem(&certificate_pem(&root)).expect("verifier");
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(root.as_slice()))
            .expect("the root");
        let theirs = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(dcroxide_tlscrypto::default_provider()),
        )
        .build()
        .expect("webpki's verifier");
        let check = |verifier: &dyn ClientCertVerifier, leaf: &[u8], sent: &[&[u8]]| {
            let sent: Vec<_> = sent.iter().map(|der| CertificateDer::from(*der)).collect();
            verifier
                .verify_client_cert(&CertificateDer::from(leaf), &sent, now)
                .map(|_| ())
        };
        let intermediate = |serial: u8, extensions: Vec<Vec<u8>>| {
            let extensions = [authority.clone(), extensions].concat();
            signed_p256_certificate(serial, "int", &int_key, "root", &root_key, &extensions)
        };
        let leaf = |serial: u8, extensions: Vec<Vec<u8>>| {
            let extensions = [vec![signing.clone()], extensions].concat();
            signed_p256_certificate(serial, "leaf", &leaf_key, "int", &int_key, &extensions)
        };
        let invalid = |err: rustls::Error, chains: usize| {
            let text = crate::server::go_error_text_for_tests(&err);
            assert_eq!(
                text,
                format!(
                    "tls: failed to verify certificate: x509: no valid chains built: {chains} \
                     candidate chains with invalid policies"
                ),
                "{err:?}"
            );
        };

        let requiring = intermediate(2, vec![require.clone(), policies(&[&one])]);
        let no_policy = leaf(3, vec![]);
        let named_one = leaf(4, vec![policies(&[&one])]);
        let named_two = leaf(5, vec![policies(&[&two])]);
        for refused in [&no_policy, &named_two] {
            check(&*theirs, refused, &[&requiring]).expect("webpki checks no policy");
            invalid(
                check(&ours, refused, &[&requiring]).expect_err("no explicit policy"),
                1,
            );
        }
        check(&ours, &named_one, &[&requiring]).expect("the required policy");
        check(
            &ours,
            &no_policy,
            &[&intermediate(6, vec![policies(&[&one])])],
        )
        .expect("no policy required");

        // An intermediate's mapping of anyPolicy is invalid while policy
        // mapping is not inhibited and the policy graph is not empty.
        let any_mapping = {
            let mapping = der_tlv(
                0x30,
                &[der_tlv(0x06, ANY_POLICY), der_tlv(0x06, &one)].concat(),
            );
            der_extension(POLICY_MAPPINGS, false, &der_tlv(0x30, &mapping))
        };
        let mapping_any = intermediate(7, vec![policies(&[&one]), any_mapping]);
        check(&*theirs, &named_one, &[&mapping_any]).expect("webpki reads no mapping");
        invalid(
            check(&ours, &named_one, &[&mapping_any]).expect_err("anyPolicy mapped"),
            1,
        );

        // The path through the requiring intermediate is refused and the
        // search goes on through one that requires nothing.
        let plain = intermediate(8, vec![]);
        check(&ours, &no_policy, &[&requiring, &plain]).expect("the other path");

        // A copy of the root sent behind the intermediate is a second
        // path to webpki, and none to Go.  The copy carries no policies
        // extension, so as an intermediate it would empty the policy
        // graph before the mapping was read and pass the path.
        check(&*theirs, &named_one, &[&mapping_any, &root]).expect("webpki reads no mapping");
        invalid(
            check(&ours, &named_one, &[&mapping_any, &root]).expect_err("no path past the root"),
            1,
        );
        invalid(
            check(&ours, &no_policy, &[&requiring, &root]).expect_err("no explicit policy"),
            1,
        );
        // A certificate sent twice, and a root listed twice, make one
        // chain each, as Go's pools keep one copy.
        invalid(
            check(&ours, &no_policy, &[&requiring, &requiring]).expect_err("sent twice"),
            1,
        );
        let doubled = GoClientCertVerifier::from_pem(
            &[certificate_pem(&root), certificate_pem(&root)].concat(),
        )
        .expect("verifier");
        assert_eq!(doubled.cas.len(), 1);
        invalid(
            check(&doubled, &no_policy, &[&requiring]).expect_err("listed twice"),
            1,
        );

        // Fifty-one intermediates of one name and key, each requiring a
        // policy the leaf does not name: each chain costs Go two
        // signature checks and webpki two, so both build fifty and stop
        // on the fifty-first, and Go, having built chains, drops its
        // signature limit and reports the fifty it refused.
        let requiring_many: Vec<Vec<u8>> = (10..61u8)
            .map(|serial| intermediate(serial, vec![require.clone(), policies(&[&one])]))
            .collect();
        let sent: Vec<&[u8]> = requiring_many.iter().map(Vec::as_slice).collect();
        invalid(
            check(&ours, &no_policy, &sent).expect_err("the budget ran out"),
            50,
        );
    }

    /// The table holds Go 1.27.3's eight hashes as `verify.go:1417-1426`
    /// writes them, and a key is matched as Go matches it: the SHA-256 of
    /// the whole SubjectPublicKeyInfo, in lower-case hex.
    #[test]
    fn the_distrusted_keys_are_gos_eight() {
        assert_eq!(
            GO_DISTRUSTED_SPKI_SHA256,
            [
                "ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105",
                "49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f",
                "e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41",
                "5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0",
                "43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b",
                "63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8",
                "ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6",
                "92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30",
            ]
        );
        assert_eq!(
            go_sha256_hex(b"abc").as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        let abc = ["ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"];
        assert!(go_distrusted_spki(b"abc", &abc));
        assert!(!go_distrusted_spki(b"abcd", &abc));
        assert!(!go_distrusted_spki(b"abc", GO_DISTRUSTED_SPKI_SHA256));
        // A certificate's identity holds the element Go hashes.
        let key = dcroxide_certgen::gentool::generate_key("P-256").expect("key");
        let der = signed_p256_certificate(1, "client", &key, "client", &key, &[]);
        let (_, _, identity) = CertFacts::parse_all(&der).expect("parses");
        let mut tbs = DerReader::new(DerReader::new(&der).read_tag(0x30).expect("certificate"));
        let mut fields = DerReader::new(tbs.read_tag(0x30).expect("tbs"));
        for tag in [0xa0, 0x02, 0x30, 0x30, 0x30, 0x30] {
            fields.read_tag(tag).expect("field");
        }
        assert_eq!(identity.spki, fields.read_raw(0x30).expect("spki").2);
        assert_eq!(identity.spki[0], 0x30);
    }

    /// A client chain on which the leaf, an intermediate or the root has
    /// a key Go 1.27.3 distrusts is dropped (`verify.go:647-649`), keys
    /// the test generates standing in for Go's eight: a pooled
    /// certificate with one is refused, after its key usage; the search
    /// goes on past a refused path to another; and when nothing else is
    /// left the refusal is logged as Go's bare `NoValidChains`.  Go
    /// keeps no count of these, so a search that also refused paths for
    /// their policies logs those alone, a path that fails both among
    /// them, since the policies come first; and Go's key usage and name
    /// constraint errors rank ahead of the bare text, as webpki's do
    /// ahead of the callback's refusal.  When webpki's signature budget
    /// runs out on the paths after one refused for its key, the refusal
    /// is still logged as Go's bare text, Go having built those chains
    /// and dropped every one.  Not compared with Go's own `Verify`, which
    /// would take a certificate with one of the eight keys.
    #[test]
    fn a_chain_through_a_distrusted_key_is_dropped() {
        use dcroxide_certgen::gentool::generate_key;
        use rustls::pki_types::CertificateDer;
        use rustls::server::danger::ClientCertVerifier;
        const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
        const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
        const EKU: &[u8] = &[0x55, 0x1d, 0x25];
        const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
        const SAN: &[u8] = &[0x55, 0x1d, 0x11];
        const NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];
        const POLICIES: &[u8] = &[0x55, 0x1d, 0x20];
        const POLICY_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x24];
        const BARE: &str = "tls: failed to verify certificate: x509: no valid chains built";
        let now = rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(1_790_000_000));
        let key = || generate_key("P-256").expect("key");
        let (root_key, int_key, cross_key, upper_key, leaf_key) =
            (key(), key(), key(), key(), key());
        let authority = vec![
            der_extension(
                BASIC_CONSTRAINTS,
                true,
                &der_tlv(0x30, &der_tlv(0x01, &[0xff])),
            ),
            der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x02, 0x84])),
        ];
        let with = |extra: Vec<Vec<u8>>| [authority.clone(), extra].concat();
        let signing = der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x07, 0x80]));
        let server_only = der_extension(EKU, false, &der_tlv(0x30, &der_tlv(0x06, SERVER_AUTH)));
        // requireExplicitPolicy 0 and one policy, which no leaf names.
        let requiring = vec![
            der_extension(
                POLICY_CONSTRAINTS,
                false,
                &der_tlv(0x30, &der_tlv(0x80, &[0])),
            ),
            der_extension(
                POLICIES,
                false,
                &der_tlv(
                    0x30,
                    &der_tlv(0x30, &der_tlv(0x06, &oid_contents(&[1, 2, 3, 1]))),
                ),
            ),
        ];

        // The table names the keys of the certificates given.
        let table = |ders: &[&[u8]]| -> &'static [&'static str] {
            let hashes: Vec<&'static str> = ders
                .iter()
                .map(|der| {
                    let (_, _, identity) = CertFacts::parse_all(der).expect("parses");
                    &*Box::leak(
                        go_sha256_hex(identity.spki)
                            .expect("sha-256")
                            .into_boxed_str(),
                    )
                })
                .collect();
            Box::leak(hashes.into_boxed_slice())
        };
        let verifier = |pool: &[u8], distrusted: &[&[u8]]| {
            GoClientCertVerifier::from_pem(&certificate_pem(pool))
                .expect("verifier")
                .distrusting(table(distrusted))
        };
        let check = |verifier: &GoClientCertVerifier, leaf: &[u8], sent: &[&[u8]]| {
            let sent: Vec<_> = sent.iter().map(|der| CertificateDer::from(*der)).collect();
            verifier
                .verify_client_cert(&CertificateDer::from(leaf), &sent, now)
                .map(|_| ())
        };
        let text = |label: &str, got: Result<(), rustls::Error>| {
            let err = got.expect_err(label);
            crate::server::go_error_text_for_tests(&err)
        };

        // A pooled certificate is its own chain, dropped once its key
        // usage has passed.
        let pooled =
            signed_p256_certificate(2, "client", &leaf_key, "client", &leaf_key, &authority);
        check(&verifier(&pooled, &[]), &pooled, &[]).expect("pooled");
        assert_eq!(
            text(
                "pooled",
                check(&verifier(&pooled, &[&pooled]), &pooled, &[])
            ),
            BARE
        );
        let pooled_server = signed_p256_certificate(
            3,
            "client",
            &leaf_key,
            "client",
            &leaf_key,
            &with(vec![server_only.clone()]),
        );
        let got = check(
            &verifier(&pooled_server, &[&pooled_server]),
            &pooled_server,
            &[],
        );
        assert!(
            matches!(
                got,
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::InvalidPurpose
                ))
            ),
            "{got:?}"
        );

        // A chain is dropped for the key of its leaf, its intermediate or
        // its root.
        let root = signed_p256_certificate(1, "root", &root_key, "root", &root_key, &authority);
        let int = signed_p256_certificate(4, "int", &int_key, "root", &root_key, &authority);
        let leaf = signed_p256_certificate(
            5,
            "leaf",
            &leaf_key,
            "int",
            &int_key,
            std::slice::from_ref(&signing),
        );
        check(&verifier(&root, &[]), &leaf, &[&int]).expect("no key distrusted");
        check(
            &GoClientCertVerifier::from_pem(&certificate_pem(&root)).expect("verifier"),
            &leaf,
            &[&int],
        )
        .expect("Go's table");
        for distrusted in [&leaf, &int, &root] {
            assert_eq!(
                text(
                    "distrusted",
                    check(&verifier(&root, &[distrusted]), &leaf, &[&int])
                ),
                BARE
            );
        }

        // The leaf's issuer issued by the root through `cross`, whose key
        // is distrusted: the only path is dropped, and with the direct
        // intermediate sent too the search goes on to it.
        let cross = signed_p256_certificate(6, "cross", &cross_key, "root", &root_key, &authority);
        let int_x = signed_p256_certificate(7, "int", &int_key, "cross", &cross_key, &authority);
        let crossed = verifier(&root, &[&cross]);
        assert_eq!(
            text("only path", check(&crossed, &leaf, &[&int_x, &cross])),
            BARE
        );
        check(&crossed, &leaf, &[&int_x, &cross, &int]).expect("the other path");

        // Policy refusals are counted and the distrusted path is not; a
        // path through a copy of `cross` that requires a policy fails the
        // policies before its key is asked, and is counted.
        let int_req = signed_p256_certificate(
            8,
            "int",
            &int_key,
            "root",
            &root_key,
            &with(requiring.clone()),
        );
        let cross_req = signed_p256_certificate(
            9,
            "cross",
            &cross_key,
            "root",
            &root_key,
            &with(requiring.clone()),
        );
        let policies = |label: &str, got, chains: usize| {
            assert_eq!(
                text(label, got),
                format!(
                    "tls: failed to verify certificate: x509: no valid chains built: {chains} \
                     candidate chains with invalid policies"
                ),
                "{label}"
            );
        };
        policies(
            "one policy refusal",
            check(&crossed, &leaf, &[&int_x, &cross, &int_req]),
            1,
        );
        policies(
            "policies first",
            check(&crossed, &leaf, &[&int_x, &cross, &cross_req, &int_req]),
            2,
        );

        // A chain dropped for its key usage beside it gives the usage
        // error, as Go's `IncompatibleUsage` ranks ahead.
        let int_server = signed_p256_certificate(
            10,
            "int",
            &int_key,
            "root",
            &root_key,
            &with(vec![server_only.clone()]),
        );
        let got = check(&crossed, &leaf, &[&int_x, &cross, &int_server]);
        assert!(
            matches!(
                got,
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::InvalidPurposeContext { .. }
                ))
            ),
            "{got:?}"
        );

        // So does one that breaks a name constraint, Go's constraint
        // error ranking ahead.
        let named = signed_p256_certificate(
            11,
            "leaf",
            &leaf_key,
            "int",
            &int_key,
            &[
                signing.clone(),
                der_extension(SAN, false, &der_tlv(0x30, &der_tlv(0x82, b"other.example"))),
            ],
        );
        let int_constrained = signed_p256_certificate(
            12,
            "int",
            &int_key,
            "root",
            &root_key,
            &with(vec![der_extension(
                NAME_CONSTRAINTS,
                true,
                &der_tlv(
                    0x30,
                    &der_tlv(0xa0, &der_tlv(0x30, &der_tlv(0x82, b"allowed.example"))),
                ),
            )]),
        );
        check(&crossed, &named, &[&int_x, &cross, &int]).expect("the other path");
        let got = check(&crossed, &named, &[&int_x, &cross, &int_constrained]);
        assert!(
            matches!(
                &got,
                Err(rustls::Error::InvalidCertificate(rustls::CertificateError::Other(other)))
                    if other.0.downcast_ref::<webpki::Error>()
                        == Some(&webpki::Error::NameConstraintViolation)
            ),
            "{got:?}"
        );

        // Sixty copies of the intermediate's issuer `upper`, which the
        // root signs: Go builds a chain through each of the first 49 and
        // then runs out of checks, keeping the chains, and drops them
        // all for the intermediate's key; webpki, checking three
        // signatures on each path, runs out of its 100 on the 34th, after
        // the callback has refused 33 of them.
        let int_up = signed_p256_certificate(13, "int", &int_key, "upper", &upper_key, &authority);
        let uppers: Vec<Vec<u8>> = (20..80u8)
            .map(|serial| {
                signed_p256_certificate(serial, "upper", &upper_key, "root", &root_key, &authority)
            })
            .collect();
        let sent: Vec<&[u8]> = std::iter::once(int_up.as_slice())
            .chain(uppers.iter().map(Vec::as_slice))
            .collect();
        check(&verifier(&root, &[]), &leaf, &sent).expect("no key distrusted");
        assert_eq!(
            text("budget", check(&verifier(&root, &[&int]), &leaf, &sent)),
            BARE
        );
    }

    /// The client CA file loads as Go's `AppendCertsFromPEM` loads it
    /// (review finding GAP06#3): malformed blocks, blocks with headers,
    /// other block types and certificates that do not parse are skipped
    /// beside a good certificate, and only a file with no certificate
    /// fails, with dcrd's text once the path is known.
    #[test]
    fn the_client_ca_file_skips_what_go_skips() {
        let (ca, key) = gencerts_authority(1_790_000_000, 1);
        let good = String::from_utf8(ca.pem.clone()).expect("pem");
        let key_pem = String::from_utf8(dcroxide_certgen::gentool::pem_private_key(
            &key.marshal_pkcs8().expect("pkcs8"),
        ))
        .expect("pem");
        let truncated: String = good.lines().take(3).map(|l| format!("{l}\n")).collect();
        let with_header = good.replacen("-----\n", "-----\nProc-Type: 4,ENCRYPTED\n\n", 1);
        for extra in [
            truncated.clone(),
            "-----BEGIN CERTIFICATE-----\nAQ!D\n-----END CERTIFICATE-----\n".to_string(),
            with_header,
            good.replacen("-----\n", "----- x\n", 1),
            "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n".to_string(),
            key_pem,
        ] {
            for file in [format!("{good}{extra}"), format!("{extra}{good}")] {
                let verifier = GoClientCertVerifier::from_pem(file.as_bytes())
                    .unwrap_or_else(|e| panic!("{e}: {file}"));
                assert_eq!(verifier.cas.len(), 1, "{file}");
            }
        }

        for file in [&b""[..], b"not a certificate at all", truncated.as_bytes()] {
            let err = GoClientCertVerifier::from_pem(file).expect_err("no certificate");
            assert_eq!(err, NO_CLIENT_CAS);
        }
    }

    /// A certificate webpki takes as a trust anchor but Go's
    /// `ParseCertificate` refuses (here a fractional notAfter, and a
    /// subject key identifier marked critical) is skipped, as
    /// `AppendCertsFromPEM` skips it: it neither authenticates as a
    /// pooled certificate nor anchors a chain, and a file holding only
    /// such certificates fails with dcrd's text.  The fact reader used
    /// to read both, so they were pooled and authenticated.  So is an
    /// authority whose name constraints Go 1.27 refuses, which then
    /// anchors no chain.
    #[test]
    fn a_certificate_gos_parser_refuses_stays_out_of_the_pool() {
        use dcroxide_certgen::gentool::generate_key;
        const SKI: &[u8] = &[0x55, 0x1d, 0x0e];
        let now = 1_790_000_000;
        let key = generate_key("P-256").expect("key");
        let ski = |critical: bool| der_extension(SKI, critical, &der_tlv(0x04, &[1, 2, 3]));
        let parsed = signed_p256_certificate(1, "client", &key, "client", &key, &[ski(false)]);
        verify_client_at(&certificate_pem(&parsed), &parsed, now)
            .expect("the certificate Go parses authenticates");

        let fractional = signed_p256_certificate_until(
            2,
            "client",
            &key,
            "client",
            &key,
            der_tlv(0x18, b"20491231235959.5Z"),
            &[],
        );
        let critical_ski = signed_p256_certificate(3, "client", &key, "client", &key, &[ski(true)]);
        let (ca, _) = gencerts_authority(now, 1);
        for refused in [&fractional, &critical_ski] {
            // webpki's anchor parser alone would keep it.
            rustls::RootCertStore::empty()
                .add(rustls::pki_types::CertificateDer::from(refused.as_slice()))
                .expect("a webpki trust anchor");
            let pem = certificate_pem(refused);
            assert_eq!(
                GoClientCertVerifier::from_pem(&pem).expect_err("nothing Go parses"),
                NO_CLIENT_CAS
            );
            let file = [ca.pem.as_slice(), &pem].concat();
            let verifier = GoClientCertVerifier::from_pem(&file).expect("the authority");
            assert_eq!(verifier.cas.len(), 1);
            assert!(verify_client_at(&file, refused, now).is_err());
        }

        // An authority whose name constraints Go 1.27 refuses, an
        // IPv4-mapped address or a mailbox whose domain holds `@`, is
        // skipped too, so a leaf it signed finds no root, where with a
        // constraint Go takes the leaf authenticates.
        const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
        const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
        const NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];
        let leaf_key = generate_key("P-256").expect("key");
        let signing = der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x07, 0x80]));
        let leaf = signed_p256_certificate(4, "leaf", &leaf_key, "authority", &key, &[signing]);
        let authority = |serial: u8, base: Vec<u8>| {
            let subtrees = der_tlv(0x30, &der_tlv(0xa0, &der_tlv(0x30, &base)));
            let extensions = [
                der_extension(
                    BASIC_CONSTRAINTS,
                    true,
                    &der_tlv(0x30, &der_tlv(0x01, &[0xff])),
                ),
                der_extension(KEY_USAGE, true, &der_tlv(0x03, &[0x02, 0x84])),
                der_extension(NAME_CONSTRAINTS, true, &subtrees),
            ];
            certificate_pem(&signed_p256_certificate(
                serial,
                "authority",
                &key,
                "authority",
                &key,
                &extensions,
            ))
        };
        let ten = der_tlv(0x87, &[10, 0, 0, 0, 0xff, 0, 0, 0]);
        let file = [ca.pem.as_slice(), &authority(5, ten)].concat();
        verify_client_at(&file, &leaf, now).expect("a leaf under an authority Go parses");
        let mapped_ten = [
            &[0u8; 10][..],
            &[0xff, 0xff, 10, 0, 0, 0],
            &[0xff; 13],
            &[0; 3],
        ]
        .concat();
        for (serial, base) in [
            (6, der_tlv(0x87, &mapped_ten)),
            (7, der_tlv(0x81, b"a@b@example.com")),
        ] {
            let pem = authority(serial, base);
            assert_eq!(
                GoClientCertVerifier::from_pem(&pem).expect_err("nothing Go parses"),
                NO_CLIENT_CAS
            );
            let file = [ca.pem.as_slice(), &pem].concat();
            assert!(verify_client_at(&file, &leaf, now).is_err());
        }
    }

    /// A pool filled as Go fills one: `AppendCertsFromPEM`'s answer is
    /// whether any certificate parsed, a duplicate among them, and
    /// `AddCert` keeps one copy of each.
    #[test]
    fn the_pool_fills_as_gos_cert_pool() {
        let now = 1_790_000_000;
        let (ca, _) = gencerts_authority(now, 1);
        let (other, _) = gencerts_authority(now, 1);
        let mut pool = ClientCaPool::new();
        assert!(pool.is_empty());
        assert!(!pool.append_certs_from_pem(b""));
        assert!(!pool.append_certs_from_pem(
            b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n"
        ));
        assert!(pool.is_empty());
        assert!(pool.append_certs_from_pem(&ca.pem));
        assert!(pool.append_certs_from_pem(&ca.pem), "a duplicate parses");
        assert_eq!(pool.len(), 1);
        assert!(pool.add_cert(other.der.clone()));
        assert!(pool.add_cert(ca.der.clone()));
        assert_eq!(pool.len(), 2);
        assert!(!pool.add_cert(vec![0x30, 0x00]));
        assert_eq!(pool.len(), 2);
        let verifier = GoClientCertVerifier::new(pool).expect("the verifier");
        assert_eq!(verifier.cas.len(), 2);
    }

    /// An empty pool, as dcrwallet keeps one when its client CA file adds
    /// nothing: the verifier asks for a certificate, requires one, names
    /// no authority, and refuses every certificate in Go's words: a leaf
    /// outside its validity, or with an unhandled critical extension, as
    /// Go's `isValid(leafCertificate)` refuses it before the search, and
    /// every other, its extended key usage whatever it is, as signed by
    /// an unknown authority, the search having built no chain.
    #[test]
    fn an_empty_pool_requires_and_refuses_every_certificate() {
        use rustls::server::danger::ClientCertVerifier;
        let now = 1_790_000_000;
        let verifier = GoClientCertVerifier::new(ClientCaPool::new()).expect("an empty pool");
        assert!(verifier.offer_client_auth());
        assert!(verifier.client_auth_mandatory());
        assert!(verifier.root_hint_subjects().is_empty());
        assert_eq!(
            verifier.supported_verify_schemes(),
            dcroxide_tlscrypto::RPC_SIG_ALGS.supported_schemes()
        );
        let (ca, ca_key) = gencerts_authority(now, 1);
        let leaf = rustls::pki_types::CertificateDer::from(gencerts_issued(now, &ca, &ca_key));
        let at =
            |secs: u64| rustls::pki_types::UnixTime::since_unix_epoch(Duration::from_secs(secs));
        let err = verifier
            .verify_client_cert(&leaf, &[], at(1_790_000_000))
            .expect_err("no authority");
        assert_eq!(
            crate::server::go_error_text_for_tests(&err),
            "tls: failed to verify certificate: x509: certificate signed by unknown authority"
        );
        // Sending the authority along changes nothing: it is no root.
        let err = verifier
            .verify_client_cert(
                &leaf,
                &[rustls::pki_types::CertificateDer::from(ca.der.clone())],
                at(1_790_000_000),
            )
            .expect_err("no authority");
        assert_eq!(
            err,
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
        );
        // A leaf whose extended key usage leaves out client
        // authentication is refused for want of an authority too: Go's
        // `Verify` builds no chain over an empty pool and returns that
        // before it looks at any certificate's key usage.
        let server_only = {
            const EKU: &[u8] = &[0x55, 0x1d, 0x25];
            const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
            let key = dcroxide_certgen::gentool::generate_key("P-256").expect("key");
            let eku = der_extension(EKU, false, &der_tlv(0x30, &der_tlv(0x06, SERVER_AUTH)));
            signed_p256_certificate(1, "client", &key, "client", &key, &[eku])
        };
        let err = verifier
            .verify_client_cert(
                &rustls::pki_types::CertificateDer::from(server_only),
                &[],
                at(1_790_000_000),
            )
            .expect_err("no authority");
        assert_eq!(
            err,
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
        );
        // A leaf outside its window fails on that first, as Go's `Verify`
        // checks `isValid(leafCertificate)` before it searches.
        let err = verifier
            .verify_client_cert(&leaf, &[], at(4_000_000_000))
            .expect_err("expired");
        assert!(
            matches!(
                err,
                rustls::Error::InvalidCertificate(rustls::CertificateError::ExpiredContext { .. })
            ),
            "{err:?}"
        );
    }
}
