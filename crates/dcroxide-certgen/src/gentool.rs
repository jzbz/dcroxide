// SPDX-License-Identifier: ISC
//! The `gencerts` tool's certificate machinery (dcrd `cmd/gencerts`):
//! the template Go's `newTemplate` builds (IDNA-converted hostnames
//! and parsed IPs into the SAN, the first host or the organization as
//! the common name, a day of backdating, and the 2049 UTCTime clamp),
//! self-signed authority generation, CA-issued certificates with the
//! parent checks Go's `x509.CreateCertificate` performs, PKCS#8 key
//! marshaling for every supported algorithm, and the CA pair loading
//! `tls.LoadX509KeyPair` performs (PEM decode, the key/certificate
//! match check, and both PKCS#8 and SEC 1 private key forms).
//!
//! Documented divergences: the IDNA conversion is UTS-46 where Go's
//! `idna.ToASCII` is the bare Punycode profile (case-preserving, no
//! validation); the CA key loader accepts the forms the Decred tools
//! emit rather than every ` PRIVATE KEY` suffix Go probes (a PKCS#1
//! `RSA PRIVATE KEY` block is not recognized); the elapsed-validity
//! error renders the date as whole-second UTC where Go renders the
//! local zone with the monotonic-clock suffix; and OS error texts use
//! Rust's rendering rather than Go's `*PathError` form.

// The assembly mirrors Go's arithmetic over bounded buffers and
// calendar math over euclidean division outputs.
#![allow(clippy::arithmetic_side_effects)]

use p256::ecdsa::signature::Signer;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::traits::PublicKeyParts;

use crate::x509::SigAlg;
use crate::{der, pem};

/// End of ASN.1 UTCTime: 2049-12-31 23:59:59 UTC (Go `endOfTime`).
const END_OF_TIME_UNIX: i64 = 2_524_607_999;

/// The environment the tool draws on: the wall clock and the serial
/// randomness (Go `time.Now` and `crypto/rand`); the binary supplies
/// the real sources and tests script them.
pub trait GenEnv {
    /// The current time in unix seconds.
    fn now_unix(&mut self) -> i64;
    /// The big-endian magnitude of a fresh serial number below 2^128
    /// (dcrd `rand.BigInt`).
    fn serial_bytes(&mut self) -> Vec<u8>;
}

/// A generated or loaded private key for one of the tool's
/// algorithms.
pub enum ToolKeyPair {
    /// NIST P-256 ECDSA.
    P256(p256::ecdsa::SigningKey),
    /// NIST P-384 ECDSA.
    P384(p384::ecdsa::SigningKey),
    /// NIST P-521 ECDSA.
    P521(p521::ecdsa::SigningKey),
    /// Ed25519, held as its seed.
    Ed25519([u8; 32]),
    /// RSA (the tool generates 4096-bit keys).
    Rsa(Box<rsa::RsaPrivateKey>),
}

impl ToolKeyPair {
    /// The certificate algorithm for this key.
    pub fn sig_alg(&self) -> SigAlg {
        match self {
            ToolKeyPair::P256(_) => SigAlg::EcdsaP256,
            ToolKeyPair::P384(_) => SigAlg::EcdsaP384,
            ToolKeyPair::P521(_) => SigAlg::EcdsaP521,
            ToolKeyPair::Ed25519(_) => SigAlg::Ed25519,
            ToolKeyPair::Rsa(_) => SigAlg::RsaSha256,
        }
    }

    /// The SubjectPublicKeyInfo bit-string content: the uncompressed
    /// point for EC keys, the raw public key for Ed25519, and the
    /// PKCS#1 `RSAPublicKey` for RSA.
    pub fn public_bytes(&self) -> Vec<u8> {
        match self {
            ToolKeyPair::P256(key) => key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            ToolKeyPair::P384(key) => key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            ToolKeyPair::P521(key) => p521::ecdsa::VerifyingKey::from(key)
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            ToolKeyPair::Ed25519(seed) => dcroxide_dcrec::edwards::SecretKey::from_seed(*seed)
                .public_key()
                .serialize()
                .to_vec(),
            ToolKeyPair::Rsa(key) => {
                // PKCS#1 RSAPublicKey ::= SEQUENCE { modulus, exponent }.
                let n = key.n().to_bytes_be();
                let e = key.e().to_bytes_be();
                der::sequence(
                    &[
                        der::integer_from_unsigned(&n),
                        der::integer_from_unsigned(&e),
                    ]
                    .concat(),
                )
            }
        }
    }

    /// Sign the to-be-signed bytes with Go's hash selection: SHA-256/
    /// 384/512 by curve, pure Ed25519, and PKCS#1 v1.5 SHA-256 for
    /// RSA.
    fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, String> {
        Ok(match self {
            ToolKeyPair::P256(key) => {
                let sig: p256::ecdsa::Signature = key.sign(tbs);
                sig.to_der().as_bytes().to_vec()
            }
            ToolKeyPair::P384(key) => {
                let sig: p384::ecdsa::Signature = key.sign(tbs);
                sig.to_der().as_bytes().to_vec()
            }
            ToolKeyPair::P521(key) => {
                let sig: p521::ecdsa::Signature = key.sign(tbs);
                sig.to_der().as_bytes().to_vec()
            }
            ToolKeyPair::Ed25519(seed) => {
                let secret = dcroxide_dcrec::edwards::SecretKey::from_seed(*seed);
                dcroxide_dcrec::edwards::sign(&secret, tbs)
                    .serialize()
                    .to_vec()
            }
            ToolKeyPair::Rsa(key) => {
                let signing = rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new((**key).clone());
                let sig: rsa::pkcs1v15::Signature = signing.sign(tbs);
                rsa::signature::SignatureEncoding::to_vec(&sig)
            }
        })
    }

    /// Go `x509.MarshalPKCS8PrivateKey` for this key.
    pub fn marshal_pkcs8(&self) -> Result<Vec<u8>, String> {
        let ec = |scalar: &[u8], key_len: usize, curve_oid: &[u64], public: &[u8]| {
            // The inner ECPrivateKey omits the curve parameters when
            // wrapped in PKCS#8 (Go `marshalECPrivateKeyWithOID` with
            // a nil OID); the curve rides the AlgorithmIdentifier.
            let mut padded = vec![0u8; key_len.saturating_sub(scalar.len())];
            padded.extend_from_slice(scalar);
            let inner = der::sequence(
                &[
                    der::integer_u64(1),
                    der::octet_string(&padded),
                    der::context(1, &der::bit_string(public)),
                ]
                .concat(),
            );
            let mut alg = der::oid(&[1, 2, 840, 10045, 2, 1]);
            alg.extend_from_slice(&der::oid(curve_oid));
            der::sequence(
                &[
                    der::integer_u64(0),
                    der::sequence(&alg),
                    der::octet_string(&inner),
                ]
                .concat(),
            )
        };
        Ok(match self {
            ToolKeyPair::P256(key) => ec(
                &key.to_bytes(),
                32,
                &[1, 2, 840, 10045, 3, 1, 7],
                &self.public_bytes(),
            ),
            ToolKeyPair::P384(key) => ec(
                &key.to_bytes(),
                48,
                &[1, 3, 132, 0, 34],
                &self.public_bytes(),
            ),
            ToolKeyPair::P521(key) => ec(
                &key.to_bytes(),
                66,
                &[1, 3, 132, 0, 35],
                &self.public_bytes(),
            ),
            ToolKeyPair::Ed25519(seed) => der::sequence(
                &[
                    der::integer_u64(0),
                    der::sequence(&der::oid(&[1, 3, 101, 112])),
                    der::octet_string(&der::octet_string(seed)),
                ]
                .concat(),
            ),
            ToolKeyPair::Rsa(key) => key
                .to_pkcs8_der()
                .map_err(|e| format!("failed to marshal private key: {e}"))?
                .as_bytes()
                .to_vec(),
        })
    }
}

/// Generate a fresh key for the selected algorithm (`None` for an
/// unknown one).  The EC scalars use rejection sampling over system
/// randomness like Go's `ecdsa.GenerateKey`; the RSA generation is
/// the rsa crate's over the system rng.
pub fn generate_key(algo: &str) -> Option<ToolKeyPair> {
    let scalar = |len: usize| -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        getrandom::fill(&mut bytes).expect("system randomness");
        bytes
    };
    match algo {
        "P-256" => loop {
            if let Ok(key) = p256::ecdsa::SigningKey::from_slice(&scalar(32)) {
                return Some(ToolKeyPair::P256(key));
            }
        },
        "P-384" => loop {
            if let Ok(key) = p384::ecdsa::SigningKey::from_slice(&scalar(48)) {
                return Some(ToolKeyPair::P384(key));
            }
        },
        "P-521" => loop {
            if let Ok(key) = p521::ecdsa::SigningKey::from_slice(&scalar(66)) {
                return Some(ToolKeyPair::P521(key));
            }
        },
        "Ed25519" => {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).expect("system randomness");
            Some(ToolKeyPair::Ed25519(seed))
        }
        "RSA4096" => {
            let mut rng = rsa::rand_core::OsRng;
            let key = rsa::RsaPrivateKey::new(&mut rng, 4096).expect("generate random RSA key");
            Some(ToolKeyPair::Rsa(Box::new(key)))
        }
        _ => None,
    }
}

/// The PEM block the tool writes for a PKCS#8 key.
pub fn pem_private_key(key_der: &[u8]) -> Vec<u8> {
    pem::encode("PRIVATE KEY", key_der)
}

/// A generated certificate: the PEM block the tool writes and the DER
/// it wraps.
pub struct GenCert {
    /// The PEM-encoded certificate.
    pub pem: Vec<u8>,
    /// The raw certificate.
    pub der: Vec<u8>,
}

/// The gencerts template (Go `newTemplate` output plus the caller's
/// key usage): hosts split into SAN names and IPs with IDNA
/// conversion, the first host (or the organization) as the CN.
struct GenTemplate {
    serial: Vec<u8>,
    organization: String,
    common_name: String,
    not_before_unix: i64,
    not_after_unix: i64,
    dns_names: Vec<String>,
    ip_addresses: Vec<[u8; 16]>,
}

fn is_ascii_str(s: &str) -> bool {
    s.chars().all(|c| (c as u32) <= 0x7f)
}

/// Parse an IP like Go's `net.ParseIP`, normalized to 16 bytes.
fn parse_ip(host: &str) -> Option<[u8; 16]> {
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let mut ip = [0u8; 16];
            ip[10] = 0xff;
            ip[11] = 0xff;
            ip[12..16].copy_from_slice(&v4.octets());
            Some(ip)
        }
        Ok(std::net::IpAddr::V6(v6)) => Some(v6.octets()),
        Err(_) => None,
    }
}

/// Go's default `time.Time` rendering for a whole-second time, pinned
/// to UTC (the elapsed-validity error embeds it).
fn go_time_utc_string(unix: i64) -> String {
    let (year, month, day, hour, min, sec) = der::civil_from_unix(unix);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02} +0000 UTC")
}

/// Go `newTemplate`: clamp to the end of ASN.1 UTCTime, refuse an
/// already-elapsed validity, draw the serial, pick the CN, and split
/// the hosts into SAN names and IPs with IDNA conversion.
fn new_template<E: GenEnv>(
    env: &mut E,
    hosts: &[String],
    org: &str,
    valid_until_unix: i64,
) -> Result<GenTemplate, String> {
    let now = env.now_unix();
    let valid_until = valid_until_unix.min(END_OF_TIME_UNIX);
    if valid_until < now {
        return Err(format!(
            "valid until date {} already elapsed",
            go_time_utc_string(valid_until)
        ));
    }
    let serial = env.serial_bytes();
    let mut cn = if hosts.is_empty() {
        org.to_string()
    } else {
        hosts[0].clone()
    };

    let mut dns_names = Vec::new();
    let mut ip_addresses = Vec::new();
    for h in hosts {
        let mut h = h.clone();
        if !is_ascii_str(&h) {
            h = idna::domain_to_ascii(&h).map_err(|e| e.to_string())?;
        }
        match parse_ip(&h) {
            Some(ip) => ip_addresses.push(ip),
            None => dns_names.push(h),
        }
    }
    if !is_ascii_str(&cn) {
        cn = idna::domain_to_ascii(&cn).map_err(|e| e.to_string())?;
    }

    Ok(GenTemplate {
        serial,
        organization: org.to_string(),
        common_name: cn,
        not_before_unix: now - 24 * 3600,
        not_after_unix: valid_until,
        dns_names,
        ip_addresses,
    })
}

/// Go's `time.Now().Add(time.Hour*24*365*time.Duration(years))` in
/// unix seconds, with the nanosecond int64 wrap kept.
fn valid_until(now_unix: i64, years: i64) -> i64 {
    let nanos = 365i64
        .wrapping_mul(24 * 3600 * 1_000_000_000)
        .wrapping_mul(years);
    now_unix.wrapping_add(nanos / 1_000_000_000)
}

/// The subject/issuer RDN sequence Go marshals for a `pkix.Name` with
/// CommonName and Organization.
fn name(org: &str, cn: &str) -> Vec<u8> {
    let org_atv = der::sequence(&[der::oid(&[2, 5, 4, 10]), der::directory_string(org)].concat());
    let cn_atv = der::sequence(&[der::oid(&[2, 5, 4, 3]), der::directory_string(cn)].concat());
    der::sequence(&[der::set(&org_atv), der::set(&cn_atv)].concat())
}

/// The IPv4 form of a 16-byte address when it is IPv4-mapped.
fn to4(ip: &[u8; 16]) -> Option<[u8; 4]> {
    if ip[..10] == [0u8; 10] && ip[10] == 0xff && ip[11] == 0xff {
        let mut out = [0u8; 4];
        out.copy_from_slice(&ip[12..16]);
        return Some(out);
    }
    None
}

/// The gencerts extension block in Go's emission order: KeyUsage
/// (critical), BasicConstraints (critical; the CA boolean only for an
/// authority), the SHA-1 SubjectKeyIdentifier Go auto-computes for CA
/// certificates, the AuthorityKeyIdentifier copied from the parent
/// for issued certificates, and the SubjectAlternativeName only when
/// hosts were given.
fn extensions(
    template: &GenTemplate,
    signs: bool,
    is_ca: bool,
    public_key_bytes: &[u8],
    authority_key_id: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    let mut exts = Vec::new();

    // KeyUsage: digitalSignature (bit 0) plus keyCertSign (bit 5)
    // with -S.
    let mut bits = [false; 6];
    bits[0] = true;
    bits[5] = signs;
    let key_usage = der::sequence(
        &[
            der::oid(&[2, 5, 29, 15]),
            der::boolean(true),
            der::octet_string(&der::bit_string_named(&bits)),
        ]
        .concat(),
    );
    exts.extend_from_slice(&key_usage);

    // BasicConstraints: critical; Go omits the default-false CA
    // boolean for an issued certificate.
    let constraints = if is_ca {
        der::sequence(&der::boolean(true))
    } else {
        der::sequence(&[])
    };
    let basic = der::sequence(
        &[
            der::oid(&[2, 5, 29, 19]),
            der::boolean(true),
            der::octet_string(&constraints),
        ]
        .concat(),
    );
    exts.extend_from_slice(&basic);

    // SubjectKeyIdentifier: Go computes it for CA certificates only.
    if is_ca {
        use sha1::{Digest, Sha1};
        let skid = Sha1::digest(public_key_bytes);
        exts.extend_from_slice(&der::sequence(
            &[
                der::oid(&[2, 5, 29, 14]),
                der::octet_string(&der::octet_string(&skid)),
            ]
            .concat(),
        ));
    }

    // AuthorityKeyIdentifier: the parent's SubjectKeyId for a
    // non-self-signed certificate.
    if let Some(akid) = authority_key_id {
        exts.extend_from_slice(&der::sequence(
            &[
                der::oid(&[2, 5, 29, 35]),
                der::octet_string(&der::sequence(&der::tlv(0x80, akid))),
            ]
            .concat(),
        ));
    }

    // SubjectAlternativeName, only when any host was provided.
    if !template.dns_names.is_empty() || !template.ip_addresses.is_empty() {
        let mut san_inner = Vec::new();
        for dns in &template.dns_names {
            if !is_ascii_str(dns) {
                return Err(format!("x509: \"{dns}\" cannot be encoded as an IA5String"));
            }
            san_inner.extend_from_slice(&der::tlv(0x82, dns.as_bytes()));
        }
        for ip in &template.ip_addresses {
            match to4(ip) {
                Some(v4) => san_inner.extend_from_slice(&der::tlv(0x87, &v4)),
                None => san_inner.extend_from_slice(&der::tlv(0x87, ip)),
            }
        }
        exts.extend_from_slice(&der::sequence(
            &[
                der::oid(&[2, 5, 29, 17]),
                der::octet_string(&der::sequence(&san_inner)),
            ]
            .concat(),
        ));
    }

    Ok(der::context(3, &der::sequence(&exts)))
}

/// Build and sign a gencerts certificate: self-signed when no issuer
/// is given, issued by the CA otherwise.
#[allow(clippy::too_many_arguments)]
fn build_cert(
    template: &GenTemplate,
    subject_key: &ToolKeyPair,
    signing_key: &ToolKeyPair,
    issuer_raw: Option<&[u8]>,
    signs: bool,
    is_ca: bool,
    authority_key_id: Option<&[u8]>,
) -> Result<GenCert, String> {
    let public = subject_key.public_bytes();
    let alg = subject_key.sig_alg();
    let subject = name(&template.organization, &template.common_name);
    let issuer = issuer_raw
        .map(<[u8]>::to_vec)
        .unwrap_or_else(|| subject.clone());

    let mut tbs = Vec::new();
    tbs.extend_from_slice(&der::context(0, &der::integer_u64(2)));
    tbs.extend_from_slice(&der::integer_from_unsigned(&template.serial));
    // The TBS signature algorithm is the SIGNER's.
    tbs.extend_from_slice(&signing_key.sig_alg().signature_algorithm());
    tbs.extend_from_slice(&issuer);
    tbs.extend_from_slice(&der::sequence(
        &[
            der::utc_time(template.not_before_unix),
            der::utc_time(template.not_after_unix),
        ]
        .concat(),
    ));
    tbs.extend_from_slice(&subject);
    tbs.extend_from_slice(&der::sequence(
        &[alg.spki_algorithm(), der::bit_string(&public)].concat(),
    ));
    tbs.extend_from_slice(&extensions(
        template,
        signs,
        is_ca,
        &public,
        authority_key_id,
    )?);
    let tbs = der::sequence(&tbs);

    let signature = signing_key.sign(&tbs)?;
    let mut cert = Vec::new();
    cert.extend_from_slice(&tbs);
    cert.extend_from_slice(&signing_key.sig_alg().signature_algorithm());
    cert.extend_from_slice(&der::bit_string(&signature));
    let cert_der = der::sequence(&cert);
    Ok(GenCert {
        pem: pem::encode("CERTIFICATE", &cert_der),
        der: cert_der,
    })
}

/// Generate a self-signed certificate authority (dcrd gencerts
/// `generateAuthority`).
pub fn generate_authority<E: GenEnv>(
    env: &mut E,
    key: &ToolKeyPair,
    hosts: &[String],
    org: &str,
    years: i64,
    signs: bool,
) -> Result<GenCert, String> {
    let now = env.now_unix();
    let template = new_template(env, hosts, org, valid_until(now, years))?;
    build_cert(&template, key, key, None, signs, true, None)
}

/// The CA fields the issuance and pairing checks read from a loaded
/// certificate.
pub struct LoadedCa {
    /// The raw subject name (becomes the issued certificate's issuer).
    pub raw_subject: Vec<u8>,
    /// The SubjectKeyIdentifier, if present.
    pub subject_key_id: Option<Vec<u8>>,
    /// NotAfter in unix seconds (clamps the issued validity).
    pub not_after_unix: i64,
    /// Whether the KeyUsage includes keyCertSign.
    pub cert_sign: bool,
    /// The SubjectPublicKeyInfo bit-string content, for the pair
    /// match check.
    pub public_bytes: Vec<u8>,
}

/// Create a certificate issued by the CA (dcrd gencerts
/// `createIssuedCert`): refuse a parent without keyCertSign, clamp
/// the validity to the parent's, and carry the parent's subject and
/// key identifier.
#[allow(clippy::too_many_arguments)]
pub fn create_issued_cert<E: GenEnv>(
    env: &mut E,
    key: &ToolKeyPair,
    ca: &LoadedCa,
    ca_key: &ToolKeyPair,
    hosts: &[String],
    org: &str,
    years: i64,
    signs: bool,
) -> Result<GenCert, String> {
    if !ca.cert_sign {
        return Err("parent certificate cannot sign other certificates".to_string());
    }
    let now = env.now_unix();
    let until = valid_until(now, years).min(ca.not_after_unix);
    let template = new_template(env, hosts, org, until)?;
    // Go's CreateCertificate only copies the parent's SubjectKeyId
    // into an AuthorityKeyIdentifier when the marshaled subject
    // differs from the issuer, so a leaf whose subject matches the
    // CA's carries no AKID.
    let subject = name(&template.organization, &template.common_name);
    let akid = if subject == ca.raw_subject {
        None
    } else {
        ca.subject_key_id.as_deref()
    };
    build_cert(
        &template,
        key,
        ca_key,
        Some(&ca.raw_subject),
        signs,
        false,
        akid,
    )
}

// ---------------------------------------------------------------------------
// CA pair loading (the slice of Go's `tls.LoadX509KeyPair` the tool
// exercises: PEM decode, certificate field extraction, PKCS#8 or
// SEC 1 private keys, and the pair match check).
// ---------------------------------------------------------------------------

/// Decode the first PEM block with the given types.
fn pem_decode(data: &[u8], types: &[&str]) -> Option<(String, Vec<u8>)> {
    let text = String::from_utf8_lossy(data);
    for block_type in types {
        let begin = format!("-----BEGIN {block_type}-----");
        let end = format!("-----END {block_type}-----");
        let Some(start) = text.find(&begin) else {
            continue;
        };
        let after = &text[start + begin.len()..];
        let Some(stop) = after.find(&end) else {
            continue;
        };
        let b64: String = after[..stop]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        return base64_decode(&b64).map(|der| ((*block_type).to_string(), der));
    }
    None
}

/// Strict standard base64 decoding.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let value = |c: u8| ALPHABET.iter().position(|a| *a == c);
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().filter(|c| **c == b'=').count();
        let mut acc: u32 = 0;
        for (i, c) in chunk.iter().enumerate() {
            let v = if *c == b'=' {
                if i < 2 {
                    return None;
                }
                0
            } else {
                value(*c)? as u32
            };
            acc = (acc << 6) | v;
        }
        out.push((acc >> 16) as u8);
        if pad < 2 {
            out.push((acc >> 8) as u8);
        }
        if pad < 1 {
            out.push(acc as u8);
        }
    }
    Some(out)
}

/// A minimal DER reader over the shapes the tool loads back.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, pos: 0 }
    }

    fn done(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    /// Read one TLV, returning the tag, the content, and the raw
    /// element including its header.
    fn tlv(&mut self) -> Result<(u8, &'a [u8], &'a [u8]), String> {
        let start = self.pos;
        let err = || "malformed DER".to_string();
        let tag = *self.data.get(self.pos).ok_or_else(err)?;
        self.pos += 1;
        let first = *self.data.get(self.pos).ok_or_else(err)?;
        self.pos += 1;
        let len = if first & 0x80 == 0 {
            first as usize
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 {
                return Err(err());
            }
            let mut len = 0usize;
            for _ in 0..n {
                let b = *self.data.get(self.pos).ok_or_else(err)?;
                self.pos += 1;
                len = (len << 8) | b as usize;
            }
            len
        };
        let content = self.data.get(self.pos..self.pos + len).ok_or_else(err)?;
        self.pos += len;
        Ok((tag, content, &self.data[start..self.pos]))
    }

    fn expect(&mut self, want: u8) -> Result<(&'a [u8], &'a [u8]), String> {
        let (tag, content, raw) = self.tlv()?;
        if tag != want {
            return Err(format!("malformed DER: tag {tag:#x}, want {want:#x}"));
        }
        Ok((content, raw))
    }
}

/// Unix seconds from a civil date (the inverse of
/// [`der::civil_from_unix`]).
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

/// Parse a UTCTime or GeneralizedTime element into unix seconds.
fn parse_time(tag: u8, content: &[u8]) -> Result<i64, String> {
    let s = std::str::from_utf8(content).map_err(|_| "malformed time".to_string())?;
    let digits = |r: std::ops::Range<usize>| -> Result<i64, String> {
        s.get(r)
            .and_then(|d| d.parse::<i64>().ok())
            .ok_or_else(|| "malformed time".to_string())
    };
    match tag {
        0x17 => {
            // UTCTime YYMMDDHHMMSSZ with the RFC 5280 century split.
            let yy = digits(0..2)?;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            Ok(unix_from_civil(
                year,
                digits(2..4)?,
                digits(4..6)?,
                digits(6..8)?,
                digits(8..10)?,
                digits(10..12)?,
            ))
        }
        0x18 => Ok(unix_from_civil(
            digits(0..4)?,
            digits(4..6)?,
            digits(6..8)?,
            digits(8..10)?,
            digits(10..12)?,
            digits(12..14)?,
        )),
        _ => Err("malformed validity".to_string()),
    }
}

/// The curve OIDs the EC key loader recognizes.
fn ec_key_from_scalar(curve_oid: &[u8], scalar: &[u8]) -> Result<ToolKeyPair, String> {
    let p256_oid = der::oid(&[1, 2, 840, 10045, 3, 1, 7]);
    let p384_oid = der::oid(&[1, 3, 132, 0, 34]);
    let p521_oid = der::oid(&[1, 3, 132, 0, 35]);
    if curve_oid == &p256_oid[..] {
        Ok(ToolKeyPair::P256(
            p256::ecdsa::SigningKey::from_slice(scalar).map_err(|e| e.to_string())?,
        ))
    } else if curve_oid == &p384_oid[..] {
        Ok(ToolKeyPair::P384(
            p384::ecdsa::SigningKey::from_slice(scalar).map_err(|e| e.to_string())?,
        ))
    } else if curve_oid == &p521_oid[..] {
        Ok(ToolKeyPair::P521(
            p521::ecdsa::SigningKey::from_slice(scalar).map_err(|e| e.to_string())?,
        ))
    } else {
        Err("tls: failed to parse private key".to_string())
    }
}

/// Parse a private key from its PEM block (PKCS#8 `PRIVATE KEY` or
/// SEC 1 `EC PRIVATE KEY`, the forms Go's `tls.X509KeyPair` accepts
/// that the Decred tools emit).
fn parse_private_key(block_type: &str, key_der: &[u8]) -> Result<ToolKeyPair, String> {
    let parse_err = || "tls: failed to parse private key".to_string();
    if block_type == "EC PRIVATE KEY" {
        // SEC 1 ECPrivateKey with the [0] curve parameters inside.
        let mut r = Reader::new(key_der);
        let (seq, _) = r.expect(0x30)?;
        let mut r = Reader::new(seq);
        r.expect(0x02)?;
        let (scalar, _) = r.expect(0x04)?;
        let (params, _) = r.expect(0xa0)?;
        return ec_key_from_scalar(params, scalar);
    }

    // PKCS#8: version, AlgorithmIdentifier, key octets.
    let mut r = Reader::new(key_der);
    let (seq, _) = r.expect(0x30)?;
    let mut r = Reader::new(seq);
    r.expect(0x02)?;
    let (alg, _) = r.expect(0x30)?;
    let (key_octets, _) = r.expect(0x04)?;
    let mut alg_r = Reader::new(alg);
    let (alg_oid, _) = alg_r.expect(0x06)?;

    let ec_oid = &der::oid(&[1, 2, 840, 10045, 2, 1])[2..];
    let ed_oid = &der::oid(&[1, 3, 101, 112])[2..];
    let rsa_oid = &der::oid(&[1, 2, 840, 113549, 1, 1, 1])[2..];
    if alg_oid == ec_oid {
        let (params, _) = alg_r.expect(0x06).map_err(|_| parse_err())?;
        let curve = der::tlv(0x06, params);
        let mut inner = Reader::new(key_octets);
        let (ec_seq, _) = inner.expect(0x30)?;
        let mut inner = Reader::new(ec_seq);
        inner.expect(0x02)?;
        let (scalar, _) = inner.expect(0x04)?;
        ec_key_from_scalar(&curve, scalar)
    } else if alg_oid == ed_oid {
        let mut inner = Reader::new(key_octets);
        let (seed, _) = inner.expect(0x04)?;
        let seed: [u8; 32] = seed.try_into().map_err(|_| parse_err())?;
        Ok(ToolKeyPair::Ed25519(seed))
    } else if alg_oid == rsa_oid {
        let key = rsa::RsaPrivateKey::from_pkcs8_der(key_der).map_err(|_| parse_err())?;
        Ok(ToolKeyPair::Rsa(Box::new(key)))
    } else {
        Err(parse_err())
    }
}

/// Load and pair a CA certificate and key (the gencerts slice of Go's
/// `tls.LoadX509KeyPair`): decode both PEM blocks, extract the fields
/// issuance needs, parse the private key, and require the key to
/// match the certificate's public key.
pub fn load_ca_pair(cert_pem: &[u8], key_pem: &[u8]) -> Result<(LoadedCa, ToolKeyPair), String> {
    let (_, cert_der) = pem_decode(cert_pem, &["CERTIFICATE"])
        .ok_or_else(|| "tls: failed to find any PEM data in certificate input".to_string())?;
    let (block_type, key_der) = pem_decode(key_pem, &["PRIVATE KEY", "EC PRIVATE KEY"])
        .ok_or_else(|| "tls: failed to find any PEM data in key input".to_string())?;

    let ca = parse_certificate(&cert_der)?;
    let key = parse_private_key(&block_type, &key_der)?;
    // Go's X509KeyPair distinguishes a key of the wrong algorithm
    // family from a same-family mismatch.
    let key_is_rsa = matches!(key, ToolKeyPair::Rsa(_));
    let cert_is_rsa = ca.public_bytes.first() == Some(&0x30);
    if key_is_rsa != cert_is_rsa {
        return Err("tls: private key type does not match public key type".to_string());
    }
    if key.public_bytes() != ca.public_bytes {
        return Err("tls: private key does not match public key".to_string());
    }
    Ok((ca, key))
}

/// Extract the CA fields from a certificate.
fn parse_certificate(cert_der: &[u8]) -> Result<LoadedCa, String> {
    let malformed = |_| "x509: malformed certificate".to_string();
    let mut r = Reader::new(cert_der);
    let (cert, _) = r.expect(0x30).map_err(malformed)?;
    let mut r = Reader::new(cert);
    let (tbs, _) = r.expect(0x30).map_err(malformed)?;
    let mut r = Reader::new(tbs);
    // [0] version (optional), serial, signature algorithm.
    if r.peek_tag() == Some(0xa0) {
        r.tlv().map_err(malformed)?;
    }
    r.expect(0x02).map_err(malformed)?;
    r.expect(0x30).map_err(malformed)?;
    // Issuer, validity, subject (raw), SPKI.
    r.expect(0x30).map_err(malformed)?;
    let (validity, _) = r.expect(0x30).map_err(malformed)?;
    let (_, subject_raw) = r.expect(0x30).map_err(malformed)?;
    let (spki, _) = r.expect(0x30).map_err(malformed)?;

    // NotAfter is the second validity element.
    let mut v = Reader::new(validity);
    v.tlv().map_err(malformed)?;
    let (tag, content, _) = v.tlv().map_err(malformed)?;
    let not_after_unix = parse_time(tag, content)?;

    // The SPKI bit-string content (skipping the unused-bits byte).
    let mut s = Reader::new(spki);
    s.expect(0x30).map_err(malformed)?;
    let (bits, _) = s.expect(0x03).map_err(malformed)?;
    let public_bytes = bits.get(1..).unwrap_or_default().to_vec();

    // Walk the extensions for KeyUsage and SubjectKeyId.
    let mut cert_sign = false;
    let mut subject_key_id = None;
    while !r.done() {
        let (tag, content, _) = r.tlv().map_err(malformed)?;
        if tag != 0xa3 {
            continue;
        }
        let mut exts = Reader::new(content);
        let (ext_seq, _) = exts.expect(0x30).map_err(malformed)?;
        let mut exts = Reader::new(ext_seq);
        while !exts.done() {
            let (ext, _) = exts.expect(0x30).map_err(malformed)?;
            let mut e = Reader::new(ext);
            let (oid, _) = e.expect(0x06).map_err(malformed)?;
            if e.peek_tag() == Some(0x01) {
                e.tlv().map_err(malformed)?;
            }
            let (value, _) = e.expect(0x04).map_err(malformed)?;
            let key_usage_oid = &der::oid(&[2, 5, 29, 15])[2..];
            let skid_oid = &der::oid(&[2, 5, 29, 14])[2..];
            if oid == key_usage_oid {
                // BIT STRING: unused-bits byte then the bits; bit 5
                // is keyCertSign.
                let mut b = Reader::new(value);
                let (bits, _) = b.expect(0x03).map_err(malformed)?;
                if let Some(byte) = bits.get(1) {
                    cert_sign = byte & 0x04 != 0;
                }
            } else if oid == skid_oid {
                let mut b = Reader::new(value);
                let (skid, _) = b.expect(0x04).map_err(malformed)?;
                subject_key_id = Some(skid.to_vec());
            }
        }
    }

    Ok(LoadedCa {
        raw_subject: subject_raw.to_vec(),
        subject_key_id,
        not_after_unix,
        cert_sign,
        public_bytes,
    })
}
