// SPDX-License-Identifier: ISC
//! TLS certificate pair generation (dcrd certgen `certgen.go` and
//! `certgen_ed25519.go`).

// Bounded assembly arithmetic over small buffers.
#![allow(clippy::arithmetic_side_effects)]

use p256::ecdsa::signature::Signer;

use crate::x509::{SigAlg, Template};
use crate::{der, pem, x509};

/// End of ASN.1 UTCTime: 2049-12-31 23:59:59 UTC (Go `endOfTime`).
const END_OF_TIME_UNIX: i64 = 2_524_607_999;

/// The elliptic curves dcrd's configuration accepts for TLS key
/// generation (`--tlscurve`: P-256 or P-521).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Curve {
    /// NIST P-256 (the default).
    P256,
    /// NIST P-521.
    P521,
}

/// The environment certgen draws on: the wall clock, key and serial
/// randomness, and the machine identity.  dcrd reads these from
/// `time.Now`, `crypto/rand`, `os.Hostname`, and
/// `net.InterfaceAddrs`; the daemon supplies those sources and tests
/// script them.
pub trait CertEnv {
    /// The current time in unix seconds.
    fn now_unix(&mut self) -> i64;
    /// A fresh Ed25519 seed.
    fn ed25519_seed(&mut self) -> [u8; 32];
    /// A fresh private scalar for the curve (32 bytes for P-256, 66
    /// for P-521).
    fn ec_private_scalar(&mut self, curve: Curve) -> Vec<u8>;
    /// The big-endian magnitude of a fresh serial number below 2^128
    /// (dcrd `rand.BigInt`).
    fn serial_bytes(&mut self) -> Vec<u8>;
    /// The machine hostname (Go `os.Hostname`).
    fn hostname(&mut self) -> Result<String, String>;
    /// The system's interface addresses in Go's `net.Addr.String`
    /// CIDR forms (Go `net.InterfaceAddrs`).
    fn interface_addrs(&mut self) -> Result<Vec<String>, String>;
}

/// A generated PEM-encoded certificate and key pair.
pub struct CertPair {
    /// The PEM-encoded certificate.
    pub cert: Vec<u8>,
    /// The PEM-encoded private key.
    pub key: Vec<u8>,
}

fn is_ascii_str(s: &str) -> bool {
    // dcrd `isASCII`: every rune within 7-bit ASCII.
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

/// The address part of a CIDR like Go's `net.ParseCIDR` (invalid
/// forms are skipped by the caller exactly as dcrd skips them).
fn parse_cidr_ip(s: &str) -> Option<[u8; 16]> {
    let (ip_str, mask_str) = s.rsplit_once('/')?;
    let ip = parse_ip(ip_str)?;
    let bits: u32 = mask_str.parse().ok()?;
    let max = if ip_str.contains(':') { 128 } else { 32 };
    if bits > max {
        return None;
    }
    Some(ip)
}

/// Split host and port like Go's `net.SplitHostPort` for the shapes
/// extra hosts take; any error simply keeps the original string.
fn split_host(host_str: &str) -> Option<String> {
    if let Some(stripped) = host_str.strip_prefix('[') {
        let end = stripped.find(']')?;
        let rest = &stripped[end + 1..];
        let port = rest.strip_prefix(':')?;
        if port.contains(':') {
            return None;
        }
        return Some(stripped[..end].to_string());
    }
    let colon = host_str.rfind(':')?;
    let host = &host_str[..colon];
    if host.contains(':') || host.contains('[') || host.contains(']') {
        return None;
    }
    Some(host.to_string())
}

/// The shared host and address gathering both generators perform.
/// `use_idna` selects the ECDSA variant's behavior, which converts
/// non-ASCII names with IDNA; the Ed25519 variant uses names as-is.
type GatheredHosts = (String, Vec<String>, Vec<[u8; 16]>);

fn gather_hosts<E: CertEnv>(
    env: &mut E,
    extra_hosts: &[String],
    use_idna: bool,
) -> Result<GatheredHosts, String> {
    let mut host = env.hostname()?;
    if use_idna && !is_ascii_str(&host) {
        host = idna::domain_to_ascii(&host).map_err(|e| e.to_string())?;
    }

    let mut ip_addresses: Vec<[u8; 16]> = vec![
        parse_ip("127.0.0.1").expect("localhost v4"),
        parse_ip("::1").expect("localhost v6"),
    ];
    let mut dns_names = vec![host.clone()];
    if host != "localhost" {
        dns_names.push("localhost".to_string());
    }

    let add_ip = |ip_addresses: &mut Vec<[u8; 16]>, ip_addr: [u8; 16]| {
        for ip in ip_addresses.iter() {
            if *ip == ip_addr {
                return;
            }
        }
        ip_addresses.push(ip_addr);
    };
    let add_host = |dns_names: &mut Vec<String>, host: &str| {
        for dns_name in dns_names.iter() {
            if host == dns_name {
                return;
            }
        }
        let mut host = host.to_string();
        if use_idna && !is_ascii_str(&host) {
            match idna::domain_to_ascii(&host) {
                Ok(converted) => host = converted,
                Err(_) => return,
            }
        }
        dns_names.push(host);
    };

    for a in env.interface_addrs()? {
        if let Some(ip) = parse_cidr_ip(&a) {
            add_ip(&mut ip_addresses, ip);
        }
    }

    for host_str in extra_hosts {
        let host = split_host(host_str).unwrap_or_else(|| host_str.clone());
        match parse_ip(&host) {
            Some(ip) => add_ip(&mut ip_addresses, ip),
            None => add_host(&mut dns_names, &host),
        }
    }

    Ok((host, dns_names, ip_addresses))
}

fn build_template<E: CertEnv>(
    env: &mut E,
    now: i64,
    organization: &str,
    valid_until_unix: i64,
    extra_hosts: &[String],
    use_idna: bool,
) -> Result<Template, String> {
    // End of ASN.1 time.
    let valid_until = valid_until_unix.min(END_OF_TIME_UNIX);
    let serial = env.serial_bytes();
    let (host, dns_names, ip_addresses) = gather_hosts(env, extra_hosts, use_idna)?;

    Ok(Template {
        serial,
        organization: organization.to_string(),
        common_name: host,
        not_before_unix: now - 24 * 3600,
        not_after_unix: valid_until,
        dns_names,
        ip_addresses,
    })
}

/// The DER-level output of a generation, exposed for the frozen
/// vectors.
#[doc(hidden)]
pub struct CertParts {
    pub cert_der: Vec<u8>,
    pub tbs_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

/// Generate a new PEM-encoded x.509 certificate pair with new ECDSA
/// keys (dcrd `NewTLSCertPair`).
pub fn new_tls_cert_pair<E: CertEnv>(
    env: &mut E,
    curve: Curve,
    organization: &str,
    valid_until_unix: i64,
    extra_hosts: &[String],
) -> Result<CertPair, String> {
    let parts = new_tls_cert_pair_parts(env, curve, organization, valid_until_unix, extra_hosts)?;
    Ok(CertPair {
        cert: pem::encode("CERTIFICATE", &parts.cert_der),
        key: pem::encode("EC PRIVATE KEY", &parts.key_der),
    })
}

#[doc(hidden)]
pub fn new_tls_cert_pair_parts<E: CertEnv>(
    env: &mut E,
    curve: Curve,
    organization: &str,
    valid_until_unix: i64,
    extra_hosts: &[String],
) -> Result<CertParts, String> {
    // dcrd checks the expiry, then generates the key, then draws the
    // serial and gathers the hosts.
    let now = env.now_unix();
    if valid_until_unix < now {
        return Err("validUntil would create an already-expired certificate".to_string());
    }
    let scalar = env.ec_private_scalar(curve);
    let template = build_template(env, now, organization, valid_until_unix, extra_hosts, true)?;

    match curve {
        Curve::P256 => {
            let key = p256::ecdsa::SigningKey::from_slice(&scalar)
                .map_err(|e| format!("invalid P-256 scalar: {e}"))?;
            let public = key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec();
            let alg = SigAlg::EcdsaP256;
            let tbs = x509::build_tbs(&template, &alg, &public)?;
            let sig: p256::ecdsa::Signature = key.sign(&tbs);
            let cert_der = x509::assemble(&tbs, &alg, sig.to_der().as_bytes());
            let key_der = sec1_key(&scalar, 32, &[1, 2, 840, 10045, 3, 1, 7], &public);
            Ok(CertParts {
                cert_der,
                tbs_der: tbs,
                key_der,
            })
        }
        Curve::P521 => {
            let key = p521::ecdsa::SigningKey::from_slice(&scalar)
                .map_err(|e| format!("invalid P-521 scalar: {e}"))?;
            let public = p521::ecdsa::VerifyingKey::from(&key)
                .to_encoded_point(false)
                .as_bytes()
                .to_vec();
            let alg = SigAlg::EcdsaP521;
            let tbs = x509::build_tbs(&template, &alg, &public)?;
            let sig: p521::ecdsa::Signature = key.sign(&tbs);
            let cert_der = x509::assemble(&tbs, &alg, sig.to_der().as_bytes());
            let key_der = sec1_key(&scalar, 66, &[1, 3, 132, 0, 35], &public);
            Ok(CertParts {
                cert_der,
                tbs_der: tbs,
                key_der,
            })
        }
    }
}

/// Generate a new PEM-encoded x.509 certificate pair with new Ed25519
/// keys (dcrd `NewEd25519TLSCertPair`).
pub fn new_ed25519_tls_cert_pair<E: CertEnv>(
    env: &mut E,
    organization: &str,
    valid_until_unix: i64,
    extra_hosts: &[String],
) -> Result<CertPair, String> {
    let parts = new_ed25519_tls_cert_pair_parts(env, organization, valid_until_unix, extra_hosts)?;
    Ok(CertPair {
        cert: pem::encode("CERTIFICATE", &parts.cert_der),
        key: pem::encode("PRIVATE KEY", &parts.key_der),
    })
}

#[doc(hidden)]
pub fn new_ed25519_tls_cert_pair_parts<E: CertEnv>(
    env: &mut E,
    organization: &str,
    valid_until_unix: i64,
    extra_hosts: &[String],
) -> Result<CertParts, String> {
    let now = env.now_unix();
    if valid_until_unix < now {
        return Err("validUntil would create an already-expired certificate".to_string());
    }
    let seed = env.ed25519_seed();
    // The Ed25519 variant performs no IDNA conversion, so a non-ASCII
    // hostname flows into the SAN and fails certificate creation.
    let template = build_template(env, now, organization, valid_until_unix, extra_hosts, false)?;

    let secret = dcroxide_dcrec::edwards::SecretKey::from_seed(seed);
    let public = secret.public_key().serialize().to_vec();
    let alg = SigAlg::Ed25519;
    let tbs = x509::build_tbs(&template, &alg, &public)?;
    let sig = dcroxide_dcrec::edwards::sign(&secret, &tbs);
    let cert_der = x509::assemble(&tbs, &alg, &sig.serialize());
    let key_der = pkcs8_ed25519_key(&seed);
    Ok(CertParts {
        cert_der,
        tbs_der: tbs,
        key_der,
    })
}

/// RFC 5915 ECPrivateKey encoding (Go `x509.MarshalECPrivateKey`).
fn sec1_key(scalar: &[u8], key_len: usize, curve_oid: &[u64], public: &[u8]) -> Vec<u8> {
    let mut padded = vec![0u8; key_len.saturating_sub(scalar.len())];
    padded.extend_from_slice(scalar);
    der::sequence(
        &[
            der::integer_u64(1),
            der::octet_string(&padded),
            der::context(0, &der::oid(curve_oid)),
            der::context(1, &der::bit_string(public)),
        ]
        .concat(),
    )
}

/// PKCS#8 encoding of an Ed25519 private key (Go
/// `x509.MarshalPKCS8PrivateKey`).
fn pkcs8_ed25519_key(seed: &[u8; 32]) -> Vec<u8> {
    der::sequence(
        &[
            der::integer_u64(0),
            der::sequence(&der::oid(&[1, 3, 101, 112])),
            der::octet_string(&der::octet_string(seed)),
        ]
        .concat(),
    )
}
