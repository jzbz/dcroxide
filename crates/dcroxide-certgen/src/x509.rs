// SPDX-License-Identifier: ISC
//! Assembly of the self-signed certificate dcrd's certgen templates
//! produce, reproducing Go `x509.CreateCertificate` byte for byte for
//! this shape.

// Bounded assembly arithmetic over small buffers.
#![allow(clippy::arithmetic_side_effects)]

use sha1::{Digest, Sha1};

use crate::der;

/// The signature and public key algorithm of a certificate.
pub enum SigAlg {
    /// Ed25519 (OID 1.3.101.112).
    Ed25519,
    /// ECDSA with SHA-256 over P-256.
    EcdsaP256,
    /// ECDSA with SHA-384 over P-384 (the gencerts tool's `P-384`).
    EcdsaP384,
    /// ECDSA with SHA-512 over P-521.
    EcdsaP521,
}

impl SigAlg {
    /// The AlgorithmIdentifier for the signature.
    pub(crate) fn signature_algorithm(&self) -> Vec<u8> {
        let oid = match self {
            SigAlg::Ed25519 => der::oid(&[1, 3, 101, 112]),
            SigAlg::EcdsaP256 => der::oid(&[1, 2, 840, 10045, 4, 3, 2]),
            SigAlg::EcdsaP384 => der::oid(&[1, 2, 840, 10045, 4, 3, 3]),
            SigAlg::EcdsaP521 => der::oid(&[1, 2, 840, 10045, 4, 3, 4]),
        };
        // Go omits the parameters for Ed25519 and ECDSA signature
        // algorithms.
        der::sequence(&oid)
    }

    /// The SubjectPublicKeyInfo AlgorithmIdentifier.
    pub(crate) fn spki_algorithm(&self) -> Vec<u8> {
        match self {
            SigAlg::Ed25519 => der::sequence(&der::oid(&[1, 3, 101, 112])),
            SigAlg::EcdsaP256 => {
                let mut inner = der::oid(&[1, 2, 840, 10045, 2, 1]);
                inner.extend_from_slice(&der::oid(&[1, 2, 840, 10045, 3, 1, 7]));
                der::sequence(&inner)
            }
            SigAlg::EcdsaP384 => {
                let mut inner = der::oid(&[1, 2, 840, 10045, 2, 1]);
                inner.extend_from_slice(&der::oid(&[1, 3, 132, 0, 34]));
                der::sequence(&inner)
            }
            SigAlg::EcdsaP521 => {
                let mut inner = der::oid(&[1, 2, 840, 10045, 2, 1]);
                inner.extend_from_slice(&der::oid(&[1, 3, 132, 0, 35]));
                der::sequence(&inner)
            }
        }
    }
}

/// The template fields dcrd's certgen fills in.
pub struct Template {
    /// The big-endian serial number magnitude.
    pub serial: Vec<u8>,
    /// The subject/issuer organization.
    pub organization: String,
    /// The subject/issuer common name.
    pub common_name: String,
    /// NotBefore as unix seconds.
    pub not_before_unix: i64,
    /// NotAfter as unix seconds.
    pub not_after_unix: i64,
    /// The SAN DNS names in order.
    pub dns_names: Vec<String>,
    /// The SAN IP addresses in order, in Go's 16-byte form with a
    /// flag for addresses that render as IPv4.
    pub ip_addresses: Vec<[u8; 16]>,
}

/// The subject/issuer RDN sequence: Organization then CommonName,
/// exactly as Go marshals a pkix.Name with those fields.
fn name(template: &Template) -> Vec<u8> {
    let org_atv = der::sequence(
        &[
            der::oid(&[2, 5, 4, 10]),
            der::directory_string(&template.organization),
        ]
        .concat(),
    );
    let cn_atv = der::sequence(
        &[
            der::oid(&[2, 5, 4, 3]),
            der::directory_string(&template.common_name),
        ]
        .concat(),
    );
    der::sequence(&[der::set(&org_atv), der::set(&cn_atv)].concat())
}

/// The IPv4 form of a 16-byte address when it is IPv4-mapped (Go
/// `net.IP.To4` used by SAN marshaling).
fn to4(ip: &[u8; 16]) -> Option<[u8; 4]> {
    if ip[..10] == [0u8; 10] && ip[10] == 0xff && ip[11] == 0xff {
        let mut out = [0u8; 4];
        out.copy_from_slice(&ip[12..16]);
        return Some(out);
    }
    None
}

/// The extensions block: KeyUsage (critical), BasicConstraints
/// (critical, CA), the auto-computed SubjectKeyIdentifier, and the
/// SubjectAlternativeName, in Go's emission order.
fn extensions(template: &Template, public_key_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut exts = Vec::new();

    // KeyUsage: digitalSignature (bit 0), keyEncipherment (bit 2),
    // keyCertSign (bit 5).
    let mut bits = [false; 6];
    bits[0] = true;
    bits[2] = true;
    bits[5] = true;
    let key_usage = der::sequence(
        &[
            der::oid(&[2, 5, 29, 15]),
            der::boolean(true),
            der::octet_string(&der::bit_string_named(&bits)),
        ]
        .concat(),
    );
    exts.extend_from_slice(&key_usage);

    // BasicConstraints: critical, CA true, no path length.
    let basic = der::sequence(
        &[
            der::oid(&[2, 5, 29, 19]),
            der::boolean(true),
            der::octet_string(&der::sequence(&der::boolean(true))),
        ]
        .concat(),
    );
    exts.extend_from_slice(&basic);

    // SubjectKeyIdentifier: Go computes SHA-1 over the public key
    // bytes for CA certificates when the template leaves it unset.
    let skid = Sha1::digest(public_key_bytes);
    let skid_ext = der::sequence(
        &[
            der::oid(&[2, 5, 29, 14]),
            der::octet_string(&der::octet_string(&skid)),
        ]
        .concat(),
    );
    exts.extend_from_slice(&skid_ext);

    // SubjectAlternativeName: DNS names then IP addresses.  Go
    // rejects names that do not fit an IA5String.
    let mut san_inner = Vec::new();
    for dns in &template.dns_names {
        if !dns.chars().all(|c| (c as u32) <= 0x7f) {
            return Err(format!(
                "failed to create certificate: x509: \"{dns}\" cannot be encoded as an IA5String"
            ));
        }
        san_inner.extend_from_slice(&der::tlv(0x82, dns.as_bytes()));
    }
    for ip in &template.ip_addresses {
        match to4(ip) {
            Some(v4) => san_inner.extend_from_slice(&der::tlv(0x87, &v4)),
            None => san_inner.extend_from_slice(&der::tlv(0x87, ip)),
        }
    }
    let san_ext = der::sequence(
        &[
            der::oid(&[2, 5, 29, 17]),
            der::octet_string(&der::sequence(&san_inner)),
        ]
        .concat(),
    );
    exts.extend_from_slice(&san_ext);

    Ok(der::context(3, &der::sequence(&exts)))
}

/// Build the to-be-signed certificate bytes.
pub fn build_tbs(
    template: &Template,
    alg: &SigAlg,
    public_key_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let mut tbs = Vec::new();
    // Version 3 ([0] EXPLICIT INTEGER 2).
    tbs.extend_from_slice(&der::context(0, &der::integer_u64(2)));
    tbs.extend_from_slice(&der::integer_from_unsigned(&template.serial));
    tbs.extend_from_slice(&alg.signature_algorithm());
    let name_der = name(template);
    tbs.extend_from_slice(&name_der); // issuer
    tbs.extend_from_slice(&der::sequence(
        &[
            der::utc_time(template.not_before_unix),
            der::utc_time(template.not_after_unix),
        ]
        .concat(),
    ));
    tbs.extend_from_slice(&name_der); // subject (self-signed)
    // SubjectPublicKeyInfo.
    tbs.extend_from_slice(&der::sequence(
        &[alg.spki_algorithm(), der::bit_string(public_key_bytes)].concat(),
    ));
    tbs.extend_from_slice(&extensions(template, public_key_bytes)?);
    Ok(der::sequence(&tbs))
}

/// Assemble the certificate from its signed parts.
pub fn assemble(tbs: &[u8], alg: &SigAlg, signature: &[u8]) -> Vec<u8> {
    let mut cert = Vec::new();
    cert.extend_from_slice(tbs);
    cert.extend_from_slice(&alg.signature_algorithm());
    cert.extend_from_slice(&der::bit_string(signature));
    der::sequence(&cert)
}
