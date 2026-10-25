// SPDX-License-Identifier: ISC
//! The RPC listener's TLS handshake as dcrd's Go server conducts it: the
//! key exchanges and cipher suites on offer, the choice among them for
//! each ClientHello, and the text logged when a handshake fails.
//!
//! dcrd's RPC `tls.Config` sets the certificate, `MinVersion` and, under
//! `--authtype=clientcert`, the client CAs, and nothing else
//! (`newTLSConfig`, `server.go:3685-3699`; the outer config adds only
//! `GetConfigForClient`, `:3818-3821`), so every negotiation choice is
//! Go's default.  dcrd 2.1.7's release binaries are built with Go 1.27,
//! whose server makes these choices for that configuration:
//!
//! * It offers X25519MLKEM768, X25519, P-256, P-384 and P-521, in that
//!   order (`crypto/tls/defaults.go:23-43`), the hybrid in TLS 1.3 only.
//!   Go 1.26 added SecP256r1MLKEM768 and SecP384r1MLKEM1024 after the
//!   first hybrid, behind the `tlssecpmlkem` setting, and 2.1.7 keeps them
//!   off: its `debug.go` sets `//go:debug default=go1.25`, which restores
//!   Go 1.25's value of every setting changed since, `tlssecpmlkem=0`
//!   among them (`internal/godebugs/table.go`).  At `3360ae4d`, the parity
//!   pin, as on master, `debug.go` sets `default=go1.26`, so a build
//!   there offers all three hybrids.
//! * In TLS 1.3 it takes the first of those the client supports, after
//!   moving the groups the client sent a key share for ahead of the rest
//!   and the hybrids ahead of everything, and asks for a key share with a
//!   HelloRetryRequest when the winner has none
//!   (`handshake_server_tls13.go:201-246`).  In TLS 1.2 it takes the
//!   client's first supported curve (`key_agreement.go:158-163`).
//! * It picks the cipher suite in its own order, never the client's:
//!   AES-128-GCM, AES-256-GCM and then ChaCha20-Poly1305 when the machine
//!   has AES-GCM hardware and the first suite of the client's that Go
//!   knows is an AES-GCM one, and ChaCha20-Poly1305 first otherwise
//!   (`defaults.go:69-118`, `cipher_suites.go:284-336`, `:361-398`;
//!   applied in TLS 1.3 at `handshake_server_tls13.go:179-197` and in
//!   TLS 1.2 at `handshake_server.go:398-422`).
//!
//! rustls with the `ring` provider offers only X25519, P-256 and P-384,
//! and it picks the group, and by default the suite, in the client's
//! order.  The port closes most of that gap in three parts.
//! [`P521_KX_GROUP`] adds P-521 over the `p521` crate.  A certificate pair
//! is served by [`RpcTlsConfigs`], a set of rustls configurations, one for
//! each cipher-suite order and TLS 1.3 key exchange Go can settle on, all
//! with `ignore_client_order` set.  And [`handshake`] reads the ClientHello
//! through `rustls::server::Acceptor` before it picks one of them, so the
//! configuration a connection gets leaves rustls only Go's choice to
//! make.  The ClientHello's key shares and offered versions, which
//! rustls's `ClientHello` does not expose, are read from the raw records
//! ([`HelloFacts`]).
//!
//! The handshake runs to completion before the request is read, as
//! `conn.serve` runs it (`net/http/server.go:1962-1987`), and a failure
//! comes back as the text Go's error would print, for the
//! `http: TLS handshake error` line the caller logs.
//!
//! What still differs is recorded in PARITY.md: the hybrid post-quantum
//! groups, which need an ML-KEM implementation the build
//! does not carry; Go's four TLS 1.2 CBC suites, which rustls does not
//! implement; and the text of the failures that have no counterpart below.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::crypto::{
    ActiveKeyExchange, CryptoProvider, GetRandomFailed, SharedSecret, SupportedKxGroup,
};
use rustls::{NamedGroup, ServerConfig, SupportedCipherSuite};

/// The IANA code of X25519 (RFC 8446 §4.2.7).
const X25519_ID: u16 = 0x001d;
/// The IANA code of secp256r1.
const SECP256R1_ID: u16 = 0x0017;
/// The IANA code of secp384r1.
const SECP384R1_ID: u16 = 0x0018;
/// The IANA code of secp521r1.
const SECP521R1_ID: u16 = 0x0019;

/// The key exchanges the RPC server offers, as IANA codes, in Go 1.27's
/// preference order (`curvePreferenceOrder`, `crypto/tls/defaults.go:38-43`)
/// less the post-quantum groups ahead of them, which the build cannot
/// offer.  [`rpc_kx_groups`] holds the implementations in the same order.
const RPC_KX_GROUP_IDS: [u16; 4] = [X25519_ID, SECP256R1_ID, SECP384R1_ID, SECP521R1_ID];

/// The key exchanges the RPC server offers, in the order of
/// [`RPC_KX_GROUP_IDS`]: ring's three and [`P521_KX_GROUP`].
fn rpc_kx_groups() -> [&'static dyn SupportedKxGroup; 4] {
    use rustls::crypto::ring::kx_group;
    [
        kx_group::X25519,
        kx_group::SECP256R1,
        kx_group::SECP384R1,
        P521_KX_GROUP,
    ]
}

/// ECDHE over P-521 (secp521r1), which Go's server offers by default
/// (`defaultCurveEnabled`, `crypto/tls/defaults.go:23-34`) and rustls's
/// `ring` provider does not (`rustls/src/crypto/ring/mod.rs:177-181`).
///
/// Without it a client that offers nothing else gets a `handshake_failure`
/// alert where dcrd completes the handshake, and Decrediton is such a
/// client: it pins `ecdhCurve: "secp521r1"` on its requests to a remote
/// daemon.
pub(crate) static P521_KX_GROUP: &dyn SupportedKxGroup = &P521KxGroup;

/// The [`SupportedKxGroup`] behind [`P521_KX_GROUP`].
#[derive(Debug)]
struct P521KxGroup;

impl SupportedKxGroup for P521KxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        Ok(Box::new(P521KeyExchange::new(p521_ephemeral_secret()?)))
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::secp521r1
    }
}

/// An uncompressed SEC 1 P-521 point: the `0x04` tag and two 66-byte
/// coordinates, the only encoding TLS 1.3 allows a key share
/// (RFC 8446 §4.2.8.2) and the only one Go accepts.
const P521_UNCOMPRESSED_POINT_LEN: usize = 133;

/// A fresh P-521 ephemeral key, drawn as Go draws one: 66 bytes with the
/// seven bits above the order's top bit cleared, tried until they are a
/// scalar in `[1, n)` (`GenerateKey`,
/// `crypto/internal/fips140/ecdh/ecdh.go`, which `crypto/tls` reaches
/// through `crypto/ecdh` with `config.rand()`).
///
/// The bytes come from the kernel, through the `getrandom` crate, where
/// Go's come from its standard library's `crypto/rand`, and not from the
/// process-wide generator the handshake signer draws from.  The signer can
/// take that generator because RFC 6979 hedges it, while this scalar is the
/// session's whole secret: the generator keeps its ChaCha20 key for up to
/// 4 MiB of draws, so a later read of the process's memory would recover
/// every scalar drawn since it was last keyed, where the kernel's
/// generator erases its key as it goes.  A failed read fails this
/// handshake, as a failed read fails ring's own groups, and cannot abort
/// the process.  `tests/entropy_policy.rs` lists the call.
fn p521_ephemeral_secret() -> Result<p521::SecretKey, rustls::Error> {
    use p521::elliptic_curve::zeroize::Zeroize;
    loop {
        let mut bytes = p521::FieldBytes::default();
        getrandom::fill(bytes.as_mut_slice()).map_err(|_| GetRandomFailed)?;
        // The order is just under 2^521, so this rarely draws again.
        if let Some(top) = bytes.first_mut() {
            *top &= 0x01;
        }
        let secret = p521::SecretKey::from_bytes(&bytes);
        bytes.as_mut_slice().zeroize();
        if let Ok(secret) = secret {
            return Ok(secret);
        }
    }
}

/// One P-521 key exchange in progress: the ephemeral secret and its
/// public key as the key share carries it.
struct P521KeyExchange {
    /// The ephemeral scalar, zeroed when the exchange is dropped.
    secret: p521::SecretKey,
    /// The uncompressed SEC 1 encoding of the public point.
    pub_key: Vec<u8>,
}

impl P521KeyExchange {
    /// The exchange for an ephemeral secret.
    fn new(secret: p521::SecretKey) -> P521KeyExchange {
        use p521::elliptic_curve::sec1::ToSec1Point;
        let pub_key = secret.public_key().to_sec1_point(false).as_bytes().to_vec();
        P521KeyExchange { secret, pub_key }
    }

    /// The shared secret with the peer's key share: the x-coordinate of
    /// the product, all 66 bytes, as RFC 8446 §7.4.2 and Go's
    /// `crypto/ecdh` take it.
    ///
    /// The share must be an uncompressed point on the curve, which is what
    /// Go's `NewPublicKey` enforces (`crypto/internal/fips140/ecdh`); the
    /// compressed form and the identity are refused, as RFC 8446 requires.
    /// A refusal is rustls's `InvalidKeyShare`, which it answers with an
    /// `illegal_parameter` alert, as Go answers its own.
    fn shared_secret(&self, peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
        use p521::elliptic_curve::group::Group;
        use p521::elliptic_curve::point::AffineCoordinates;
        let invalid = || rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare);
        if peer.len() != P521_UNCOMPRESSED_POINT_LEN || peer.first() != Some(&0x04) {
            return Err(invalid());
        }
        let peer = p521::PublicKey::from_sec1_bytes(peer).map_err(|_| invalid())?;
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "scalar multiplication of a curve point, which cannot overflow"
        )]
        let product = peer.to_projective() * *self.secret.to_nonzero_scalar();
        // A point of the prime-order group times a non-zero scalar below the
        // order is never the identity; checked anyway, as Go checks it.
        if bool::from(product.is_identity()) {
            return Err(invalid());
        }
        Ok(SharedSecret::from(&product.to_affine().x()[..]))
    }
}

impl ActiveKeyExchange for P521KeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
        self.shared_secret(peer_pub_key)
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::secp521r1
    }
}

/// Every TLS 1.0-1.2 cipher suite Go implements, disabled ones included:
/// the suites `cipherSuiteByID` finds (`cipherSuites`,
/// `crypto/tls/cipher_suites.go:152-175`), which are the ones
/// `isAESGCMPreferred` looks past the unknown ones for.
const GO_TLS12_SUITE_IDS: [u16; 22] = [
    0xcca8, 0xcca9, 0xc02f, 0xc02b, 0xc030, 0xc02c, 0xc027, 0xc013, 0xc023, 0xc009, 0xc014, 0xc00a,
    0x009c, 0x009d, 0x003c, 0x002f, 0x0035, 0xc012, 0x000a, 0x0005, 0xc011, 0xc007,
];

/// The TLS 1.3 suites Go implements (`cipherSuitesTLS13`,
/// `cipher_suites.go:214-218`).
const GO_TLS13_SUITE_IDS: [u16; 3] = [0x1301, 0x1302, 0x1303];

/// The AES-GCM suites (`aesgcmCiphers`, `cipher_suites.go:371-380`).
const GO_AES_GCM_SUITE_IDS: [u16; 6] = [0xc02f, 0xc030, 0xc02b, 0xc02c, 0x1301, 0x1302];

/// Whether Go would take this machine to have AES-GCM hardware
/// (`hasAESGCMHardwareSupport`, `crypto/tls/cipher_suites.go:361-369`).
///
/// Go asks for AES, PCLMULQDQ, SSE4.1 and SSSE3 on x86 (its check reads
/// `cpu.X86`, which 386 fills as well as amd64), AES and PMULL on arm64,
/// and nothing on ppc64 and ppc64le.  Its s390x test reads the CPACF
/// function codes, which Rust's feature detection does not name, so an
/// s390x build answers no; nothing else Go builds for has the hardware.
fn go_has_aes_gcm_hardware() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        std::arch::is_x86_feature_detected!("aes")
            && std::arch::is_x86_feature_detected!("pclmulqdq")
            && std::arch::is_x86_feature_detected!("sse4.1")
            && std::arch::is_x86_feature_detected!("ssse3")
    }
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("aes")
            && std::arch::is_aarch64_feature_detected!("pmull")
    }
    #[cfg(target_arch = "powerpc64")]
    {
        true
    }
    #[cfg(not(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "powerpc64"
    )))]
    {
        false
    }
}

/// Go's `isAESGCMPreferred` (`crypto/tls/cipher_suites.go:385-398`): the
/// hardware is there, and the first suite in the client's list that Go
/// knows is an AES-GCM one, which Go reads as the client having the
/// hardware too.  Suites Go does not know, GREASE and the signalling
/// values among them, are passed over.
fn go_aes_gcm_preferred(aes_gcm_hardware: bool, client_suites: &[u16]) -> bool {
    aes_gcm_hardware
        && client_suites
            .iter()
            .find(|id| GO_TLS12_SUITE_IDS.contains(id) || GO_TLS13_SUITE_IDS.contains(id))
            .is_some_and(|id| GO_AES_GCM_SUITE_IDS.contains(id))
}

/// The suites the RPC server offers, in the order Go's server prefers
/// them: `defaultCipherSuitesTLS13` and `cipherSuitesPreferenceOrder` when
/// AES-GCM is preferred, `defaultCipherSuitesTLS13NoAES` and
/// `cipherSuitesPreferenceOrderNoAES` otherwise (`crypto/tls/defaults.go:98-118`,
/// `cipher_suites.go:284-336`), less Go's TLS 1.2 CBC suites, which rustls
/// does not implement.  ECDSA ahead of RSA at each step, as Go lists them;
/// the certificate decides which half applies.
fn rpc_cipher_suites(aes_gcm_first: bool) -> Vec<SupportedCipherSuite> {
    use rustls::crypto::ring::cipher_suite::{
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
    };
    if aes_gcm_first {
        vec![
            TLS13_AES_128_GCM_SHA256,
            TLS13_AES_256_GCM_SHA384,
            TLS13_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ]
    } else {
        vec![
            TLS13_CHACHA20_POLY1305_SHA256,
            TLS13_AES_128_GCM_SHA256,
            TLS13_AES_256_GCM_SHA384,
            TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ]
    }
}

/// Go's TLS 1.3 key exchange for a ClientHello, as an index into
/// [`RPC_KX_GROUP_IDS`] (`handshake_server_tls13.go:201-246`): the groups
/// in Go's order that the client lists in `supported_groups`, the first
/// one the client sent a key share for, else the first of them, which
/// Go then asks for with a HelloRetryRequest.  `None` when there is no
/// group in common, which Go refuses with
/// `tls: no key exchanges supported by both client and server`.
///
/// Go sorts the hybrid post-quantum groups ahead of even a group with a
/// key share.  The port offers none of them, so a client that supports
/// X25519MLKEM768 gets X25519 here where dcrd would negotiate the hybrid,
/// asking for its share if need be; PARITY records it.
fn go_tls13_group(supported_groups: &[u16], key_shares: &[u16]) -> Option<usize> {
    let mut mutual = RPC_KX_GROUP_IDS
        .iter()
        .enumerate()
        .filter(|(_, id)| supported_groups.contains(id));
    let first = mutual.clone().next();
    mutual
        .find(|(_, id)| key_shares.contains(id))
        .or(first)
        .map(|(index, _)| index)
}

/// The configurations for one cipher-suite order: one offering every key
/// exchange, for TLS 1.2 and for a ClientHello with no group in common,
/// and one for each of [`rpc_kx_groups`] offering that group alone.
#[derive(Debug)]
struct ConfigsByGroup {
    /// Every key exchange.
    any: Arc<ServerConfig>,
    /// One key exchange each, in the order of [`RPC_KX_GROUP_IDS`].
    only: Vec<Arc<ServerConfig>>,
}

/// The rustls configurations one certificate pair is served with, one for
/// each choice Go's server can make that rustls cannot be configured to make
/// otherwise (see the module documentation).
///
/// Each is built by the same closure from the same certificate, key and
/// client verifier, so they differ only in the provider's cipher-suite
/// order and key exchanges, and they rotate together.  rustls takes the
/// suite in the configuration's order (`ignore_client_order`) and the
/// group in the client's, so a configuration that offers only the group
/// Go would pick leaves rustls Go's choice, including the
/// HelloRetryRequest when the client sent no share for it.  In TLS 1.2,
/// where Go also takes the client's first curve, the configuration
/// offering every group already agrees.
#[derive(Debug)]
pub struct RpcTlsConfigs {
    /// AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305.
    aes_gcm_first: ConfigsByGroup,
    /// ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM.
    chacha_first: ConfigsByGroup,
    /// Whether this machine has the hardware Go's AES-GCM preference
    /// turns on, read once.
    aes_gcm_hardware: bool,
}

impl RpcTlsConfigs {
    /// Build the set, calling `build` once for each provider: ring's, with
    /// the suites in one of Go's two orders and the key exchanges cut to
    /// those the configuration offers.
    pub(crate) fn build(
        mut build: impl FnMut(Arc<CryptoProvider>) -> Result<ServerConfig, String>,
    ) -> Result<RpcTlsConfigs, String> {
        Ok(RpcTlsConfigs {
            aes_gcm_first: Self::by_group(true, &mut build)?,
            chacha_first: Self::by_group(false, &mut build)?,
            aes_gcm_hardware: go_has_aes_gcm_hardware(),
        })
    }

    /// The configurations for one cipher-suite order.
    fn by_group(
        aes_gcm_first: bool,
        build: &mut impl FnMut(Arc<CryptoProvider>) -> Result<ServerConfig, String>,
    ) -> Result<ConfigsByGroup, String> {
        let mut provider = |kx_groups: Vec<&'static dyn SupportedKxGroup>| {
            let mut provider = rustls::crypto::ring::default_provider();
            provider.cipher_suites = rpc_cipher_suites(aes_gcm_first);
            provider.kx_groups = kx_groups;
            build(Arc::new(provider)).map(Arc::new)
        };
        let any = provider(rpc_kx_groups().to_vec())?;
        let only = rpc_kx_groups()
            .into_iter()
            .map(|group| provider(vec![group]))
            .collect::<Result<Vec<_>, String>>()?;
        Ok(ConfigsByGroup { any, only })
    }

    /// The configuration for a connection whose ClientHello is `hello`.
    pub(crate) fn for_hello(&self, hello: &HelloFacts) -> Arc<ServerConfig> {
        let by_group = if go_aes_gcm_preferred(self.aes_gcm_hardware, &hello.cipher_suites) {
            &self.aes_gcm_first
        } else {
            &self.chacha_first
        };
        if !hello.offers_tls13() {
            return Arc::clone(&by_group.any);
        }
        let chosen = go_tls13_group(&hello.supported_groups, &hello.key_shares)
            .and_then(|index| by_group.only.get(index));
        Arc::clone(chosen.unwrap_or(&by_group.any))
    }

    /// Every configuration in the set.
    pub fn configs(&self) -> impl Iterator<Item = &Arc<ServerConfig>> {
        [&self.aes_gcm_first, &self.chacha_first]
            .into_iter()
            .flat_map(|by_group| std::iter::once(&by_group.any).chain(&by_group.only))
    }
}

/// What a ClientHello offers, read from its raw records: the fields
/// Go's server negotiates on, among them the two rustls's `ClientHello`
/// does not expose, the key shares and the offered versions.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct HelloFacts {
    /// `legacy_version`.
    legacy_version: u16,
    /// The cipher suites, in the client's order.
    cipher_suites: Vec<u16>,
    /// The `supported_versions` extension, when present.
    supported_versions: Option<Vec<u16>>,
    /// The `supported_groups` extension, in the client's order.
    supported_groups: Vec<u16>,
    /// The group of each `key_share` entry, in the client's order.
    key_shares: Vec<u16>,
}

/// A cursor over ClientHello bytes, every read bounds-checked.
struct HelloReader<'a>(&'a [u8]);

impl<'a> HelloReader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.0.len() {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    fn u16(&mut self) -> Option<u16> {
        match *self.take(2)? {
            [hi, lo] => Some(u16::from_be_bytes([hi, lo])),
            _ => None,
        }
    }

    /// A vector with a one-byte length.
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let len = self.u8()?;
        self.take(usize::from(len))
    }

    /// A vector with a two-byte length.
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let len = self.u16()?;
        self.take(usize::from(len))
    }

    /// The bytes as two-byte values.
    fn u16s(bytes: &[u8]) -> Option<Vec<u16>> {
        let (pairs, rest) = bytes.as_chunks::<2>();
        rest.is_empty()
            .then(|| pairs.iter().map(|&pair| u16::from_be_bytes(pair)).collect())
    }
}

impl HelloFacts {
    /// The ClientHello at the start of `records`, the bytes a connection
    /// opened with, reassembled from the handshake records it spans.
    /// `None` when they do not hold a whole, well-formed one.
    pub(crate) fn parse(records: &[u8]) -> Option<HelloFacts> {
        let mut rest = HelloReader(records);
        let mut message = Vec::new();
        let body = loop {
            let content_type = rest.u8()?;
            let _record_version = rest.u16()?;
            let fragment = rest.vec16()?;
            if content_type != 22 {
                return None;
            }
            message.extend_from_slice(fragment);
            if let [msg_type, a, b, c, ..] = message[..] {
                if msg_type != 1 {
                    return None;
                }
                let len = usize::try_from(u32::from_be_bytes([0, a, b, c])).ok()?;
                if let Some(body) = message.get(4..len.checked_add(4)?) {
                    break body.to_vec();
                }
            }
        };

        let mut hello = HelloReader(&body);
        let legacy_version = hello.u16()?;
        hello.take(32)?;
        hello.vec8()?;
        let cipher_suites = HelloReader::u16s(hello.vec16()?)?;
        hello.vec8()?;
        let mut facts = HelloFacts {
            legacy_version,
            cipher_suites,
            ..HelloFacts::default()
        };
        // A ClientHello may end before its extensions.
        if hello.0.is_empty() {
            return Some(facts);
        }
        let mut extensions = HelloReader(hello.vec16()?);
        while !extensions.0.is_empty() {
            let extension_type = extensions.u16()?;
            let mut data = HelloReader(extensions.vec16()?);
            match extension_type {
                10 => facts.supported_groups = HelloReader::u16s(data.vec16()?)?,
                43 => facts.supported_versions = Some(HelloReader::u16s(data.vec8()?)?),
                51 => {
                    let mut shares = HelloReader(data.vec16()?);
                    while !shares.0.is_empty() {
                        facts.key_shares.push(shares.u16()?);
                        shares.vec16()?;
                    }
                }
                _ => {}
            }
        }
        Some(facts)
    }

    /// The facts rustls's `ClientHello` exposes, for a ClientHello the raw
    /// records could not be read back for: the suites and groups, without
    /// the key shares or versions, so the TLS 1.2 choice is made.
    fn from_rustls(hello: &rustls::server::ClientHello<'_>) -> HelloFacts {
        HelloFacts {
            cipher_suites: hello
                .cipher_suites()
                .iter()
                .map(|&suite| u16::from(suite))
                .collect(),
            supported_groups: hello
                .named_groups()
                .unwrap_or_default()
                .iter()
                .map(|&group| u16::from(group))
                .collect(),
            ..HelloFacts::default()
        }
    }

    /// Whether the client offers TLS 1.3, which is when Go and rustls
    /// both negotiate it: both take the highest version they share with
    /// the client's `supported_versions` (`mutualVersion`,
    /// `crypto/tls/common.go:1312-1320`).
    fn offers_tls13(&self) -> bool {
        self.supported_versions
            .as_ref()
            .is_some_and(|versions| versions.contains(&0x0304))
    }

    /// The versions Go reads the client as offering, for its refusal
    /// (`readClientHello`, `crypto/tls/handshake_server.go:178-195`): the
    /// `supported_versions` extension, else every version up to
    /// `legacy_version`, capped at TLS 1.2.
    fn go_client_versions(&self) -> Vec<u16> {
        match &self.supported_versions {
            Some(versions) => versions.clone(),
            None => {
                let max = self.legacy_version.min(0x0303);
                [0x0304, 0x0303, 0x0302, 0x0301]
                    .into_iter()
                    .filter(|&version| version <= max)
                    .collect()
            }
        }
    }
}

/// The most a connection's opening bytes are kept for [`HelloFacts`]:
/// above the largest ClientHello rustls accepts (a 64 KiB handshake
/// message over at least five records), so only a ClientHello rustls is
/// about to refuse is ever cut short.
const MAX_RECORDED_HELLO: usize = 1 << 17;

/// What the handshake has read from the client: its opening bytes, kept
/// until the ClientHello is in, and where the record boundaries fell, so
/// an early close reads as Go reports it.
#[derive(Default)]
struct HandshakeTap {
    /// The connection's first bytes.
    recorded: Vec<u8>,
    /// Whether the ClientHello is in and recording has stopped.
    recording_done: bool,
    /// The current record's header bytes read so far.
    header_len: usize,
    /// The current record's header.
    header: [u8; 5],
    /// The current record's body bytes still to come.
    body_left: usize,
    /// Whether the last failed read was the socket's own.
    socket_failed: bool,
}

impl HandshakeTap {
    /// Account for `bytes`, just read from the client.
    fn feed(&mut self, mut bytes: &[u8]) {
        if !self.recording_done {
            let room = MAX_RECORDED_HELLO.saturating_sub(self.recorded.len());
            self.recorded
                .extend_from_slice(bytes.get(..room.min(bytes.len())).unwrap_or_default());
        }
        while !bytes.is_empty() {
            if self.body_left > 0 {
                let n = self.body_left.min(bytes.len());
                self.body_left = self.body_left.saturating_sub(n);
                bytes = bytes.get(n..).unwrap_or_default();
                continue;
            }
            let n = self
                .header
                .len()
                .saturating_sub(self.header_len)
                .min(bytes.len());
            if let (Some(to), Some(from)) = (
                self.header
                    .get_mut(self.header_len..self.header_len.saturating_add(n)),
                bytes.get(..n),
            ) {
                to.copy_from_slice(from);
            }
            self.header_len = self.header_len.saturating_add(n);
            bytes = bytes.get(n..).unwrap_or_default();
            if self.header_len == self.header.len() {
                self.body_left = usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
                self.header_len = 0;
            }
        }
    }

    /// Go's text for the client closing now (`readRecordOrCCS`,
    /// `crypto/tls/conn.go:625-637`): `EOF` on a record boundary,
    /// `unexpected EOF` inside a record.
    fn eof_reason(&self) -> &'static str {
        if self.header_len > 0 || self.body_left > 0 {
            "unexpected EOF"
        } else {
            "EOF"
        }
    }

    /// Go's refusal of the connection's first record, checked on its
    /// header before anything is parsed (`readRecordOrCCS`,
    /// `crypto/tls/conn.go:641-676`).
    fn first_record_refusal(&self) -> Option<FirstRecordRefusal> {
        let header: [u8; 5] = self.recorded.get(..5)?.try_into().ok()?;
        let [content_type, version_hi, version_lo, len_hi, len_lo] = header;
        if content_type == 0x80 {
            return Some(FirstRecordRefusal::SslV2);
        }
        if (content_type != 21 && content_type != 22)
            || u16::from_be_bytes([version_hi, version_lo]) >= 0x1000
        {
            return Some(if looks_like_http(&header) {
                FirstRecordRefusal::Http
            } else {
                FirstRecordRefusal::NotTls
            });
        }
        let len = u16::from_be_bytes([len_hi, len_lo]);
        (len > MAX_CIPHERTEXT).then_some(FirstRecordRefusal::Oversized(len))
    }
}

/// The longest record Go reads before it has negotiated a version, 2^14
/// plus 2048 (`maxCiphertext`, `crypto/tls/common.go`).
const MAX_CIPHERTEXT: u16 = 18432;

/// net/http's `tlsRecordHeaderLooksLikeHTTP` (`net/http/server.go:4277-4283`).
fn looks_like_http(header: &[u8; 5]) -> bool {
    matches!(header, b"GET /" | b"HEAD " | b"POST " | b"PUT /" | b"OPTIO")
}

/// A first record Go refuses on its header.
#[derive(Debug, PartialEq)]
enum FirstRecordRefusal {
    /// A plaintext HTTP request, which net/http answers with a 400 on the
    /// bare connection (`net/http/server.go:1976-1981`).
    Http,
    /// Anything else that is not a TLS handshake or alert, refused with
    /// no answer at all.
    NotTls,
    /// An SSLv2-style ClientHello, refused with a `protocol_version` alert.
    SslV2,
    /// A record longer than any TLS record, refused with `record_overflow`.
    Oversized(u16),
}

impl FirstRecordRefusal {
    /// Answer the client as Go does and return Go's text for the refusal.
    fn answer(&self, sock: &mut TcpStream) -> String {
        // A fatal alert in the record version Go writes before it has
        // negotiated one, TLS 1.0 (`writeRecordLocked`,
        // `crypto/tls/conn.go`).
        let alert = |description: u8| [0x15, 0x03, 0x01, 0x00, 0x02, 0x02, description];
        match self {
            FirstRecordRefusal::Http => {
                let _ = sock.write_all(
                    b"HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n",
                );
                "client sent an HTTP request to an HTTPS server".to_string()
            }
            FirstRecordRefusal::NotTls => {
                "tls: first record does not look like a TLS handshake".to_string()
            }
            FirstRecordRefusal::SslV2 => {
                let _ = sock.write_all(&alert(70));
                "tls: unsupported SSLv2 handshake received".to_string()
            }
            FirstRecordRefusal::Oversized(len) => {
                let _ = sock.write_all(&alert(22));
                format!("tls: oversized record received with length {len}")
            }
        }
    }
}

/// The connection's two ends and network, as Go's `net.OpError` names them
/// in a failed read or write: `tcp4` or `tcp6` after the listener's
/// address family, as dcrd listens on each separately
/// (`parseListeners`, `server.go`).
struct GoConnName {
    net: &'static str,
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
}

impl GoConnName {
    fn of(sock: &TcpStream) -> GoConnName {
        let local = sock.local_addr().ok();
        GoConnName {
            net: if local.is_some_and(|addr| addr.is_ipv6()) {
                "tcp6"
            } else {
                "tcp4"
            },
            local,
            remote: sock.peer_addr().ok(),
        }
    }

    /// `net.OpError.Error` (`net/net.go:501-522`) for `op` failing with
    /// `what`.
    fn op_error(&self, op: &str, what: &str) -> String {
        let mut text = format!("{op} {}", self.net);
        if let Some(local) = self.local {
            text.push(' ');
            text.push_str(&local.to_string());
        }
        if let Some(remote) = self.remote {
            text.push_str(if self.local.is_some() { "->" } else { " " });
            text.push_str(&remote.to_string());
        }
        text.push_str(": ");
        text.push_str(what);
        text
    }

    /// Go's text for the handshake deadline passing.
    fn timeout(&self) -> String {
        self.op_error("read", "i/o timeout")
    }

    /// Go's text for a socket error during `op`: an `os.SyscallError`
    /// naming the system call, around the error's description, which
    /// Go's own errno table spells as the C library does but in lower
    /// case.
    fn io_error(&self, op: &str, err: &std::io::Error) -> String {
        let description = match err.raw_os_error() {
            Some(code) => {
                let text = std::io::Error::from_raw_os_error(code).to_string();
                let text = text
                    .strip_suffix(&format!(" (os error {code})"))
                    .unwrap_or(&text)
                    .to_string();
                let mut chars = text.chars();
                match chars.next() {
                    Some(first) => first.to_lowercase().chain(chars).collect(),
                    None => text,
                }
            }
            None => err.to_string(),
        };
        self.op_error(op, &format!("{op}: {description}"))
    }
}

/// The client's bytes on their way into rustls, through the tap.
struct TapReader<'a> {
    sock: &'a mut TcpStream,
    tap: &'a mut HandshakeTap,
}

impl Read for TapReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.sock.read(buf) {
            Ok(n) => {
                self.tap.feed(buf.get(..n).unwrap_or_default());
                Ok(n)
            }
            Err(e) => {
                self.tap.socket_failed = true;
                Err(e)
            }
        }
    }
}

/// One read of the client's bytes into rustls under the handshake
/// deadline, in receives of at most `poll` so a socket shut down under
/// this thread is noticed (see `read_exact_by_deadline` in `rpcrun.rs`).
/// A receive that runs out its slice is not a timeout; only the deadline
/// is.
fn read_by_deadline(
    sock: &mut TcpStream,
    tap: &mut HandshakeTap,
    name: &GoConnName,
    deadline: Instant,
    poll: Duration,
    mut read_tls: impl FnMut(&mut dyn Read) -> std::io::Result<usize>,
) -> Result<(), String> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(name.timeout());
        }
        let _ = sock.set_read_timeout(Some(remaining.min(poll)));
        tap.socket_failed = false;
        match read_tls(&mut TapReader {
            sock: &mut *sock,
            tap: &mut *tap,
        }) {
            // The watchdog shuts the socket down at the deadline, which
            // reads as a close.
            Ok(0) if Instant::now() >= deadline => return Err(name.timeout()),
            Ok(0) => return Err(tap.eof_reason().to_string()),
            Ok(_) => return Ok(()),
            Err(ref e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) if tap.socket_failed => return Err(name.io_error("read", &e)),
            // rustls's own refusal to buffer more, which Go has no
            // counterpart for.
            Err(e) => return Err(e.to_string()),
        }
    }
}

/// Write everything rustls has queued, an alert included.
fn flush_tls(
    conn: &mut rustls::ServerConnection,
    sock: &mut TcpStream,
    name: &GoConnName,
) -> Result<(), String> {
    while conn.wants_write() {
        match conn.write_tls(sock) {
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(name.io_error("write", &e)),
        }
    }
    Ok(())
}

/// Run an accepted RPC connection's TLS handshake to completion, as Go's
/// `conn.serve` does before it reads a request
/// (`net/http/server.go:1962-1987`), under the deadline the connection's
/// watchdog enforces.
///
/// The ClientHello is read through `rustls::server::Acceptor`, and only
/// then is `configs` asked for the configurations, which is where dcrd's
/// `GetConfigForClient` runs (`readClientHello`,
/// `crypto/tls/handshake_server.go:166-176`), so a client that never sends
/// one does not reach the certificate reload check.
///
/// On failure the error is the text Go's error would print, the `%v` of
/// net/http's `http: TLS handshake error from %s: %v`.  The common
/// failures are rendered as Go renders them: an early close, the
/// deadline, a reset, a first record that is not TLS (with net/http's 400
/// for a plaintext HTTP request), an alert from the client, and the
/// refusals Go and rustls share; anything else carries rustls's own
/// description of it.
pub(crate) fn handshake(
    mut sock: TcpStream,
    deadline: Instant,
    poll: Duration,
    configs: impl FnOnce() -> Arc<RpcTlsConfigs>,
) -> Result<rustls::StreamOwned<rustls::ServerConnection, TcpStream>, String> {
    let name = GoConnName::of(&sock);
    let mut tap = HandshakeTap::default();
    let mut acceptor = rustls::server::Acceptor::default();
    let accepted = loop {
        read_by_deadline(&mut sock, &mut tap, &name, deadline, poll, |rd| {
            acceptor.read_tls(rd)
        })?;
        if let Some(refusal) = tap.first_record_refusal() {
            return Err(refusal.answer(&mut sock));
        }
        match acceptor.accept() {
            Ok(Some(accepted)) => break accepted,
            Ok(None) => {}
            Err((err, mut alert)) => {
                let _ = alert.write_all(&mut sock);
                return Err(go_error_text(&err, None));
            }
        }
    };
    tap.recording_done = true;
    let hello = HelloFacts::parse(&tap.recorded)
        .unwrap_or_else(|| HelloFacts::from_rustls(&accepted.client_hello()));
    tap.recorded = Vec::new();

    let config = configs().for_hello(&hello);
    let mut conn = accepted
        .into_connection(config)
        .map_err(|(err, mut alert)| {
            let _ = alert.write_all(&mut sock);
            go_error_text(&err, Some(&hello))
        })?;
    loop {
        flush_tls(&mut conn, &mut sock, &name)?;
        if !conn.is_handshaking() {
            break;
        }
        read_by_deadline(&mut sock, &mut tap, &name, deadline, poll, |rd| {
            conn.read_tls(rd)
        })?;
        if let Err(err) = conn.process_new_packets() {
            // rustls queues the alert Go would send for most refusals.
            let _ = flush_tls(&mut conn, &mut sock, &name);
            return Err(go_error_text(&err, Some(&hello)));
        }
    }
    Ok(rustls::StreamOwned::new(conn, sock))
}

/// Go's alert descriptions (`alertText`, `crypto/tls/alert.go:66-101`).
const GO_ALERT_TEXT: [(u8, &str); 34] = [
    (0, "close notify"),
    (10, "unexpected message"),
    (20, "bad record MAC"),
    (21, "decryption failed"),
    (22, "record overflow"),
    (30, "decompression failure"),
    (40, "handshake failure"),
    (42, "bad certificate"),
    (43, "unsupported certificate"),
    (44, "revoked certificate"),
    (45, "expired certificate"),
    (46, "unknown certificate"),
    (47, "illegal parameter"),
    (48, "unknown certificate authority"),
    (49, "access denied"),
    (50, "error decoding message"),
    (51, "error decrypting message"),
    (60, "export restriction"),
    (70, "protocol version not supported"),
    (71, "insufficient security level"),
    (80, "internal error"),
    (86, "inappropriate fallback"),
    (90, "user canceled"),
    (100, "no renegotiation"),
    (109, "missing extension"),
    (110, "unsupported extension"),
    (111, "certificate unobtainable"),
    (112, "unrecognized name"),
    (113, "bad certificate status response"),
    (114, "bad certificate hash value"),
    (115, "unknown PSK identity"),
    (116, "certificate required"),
    (120, "no application protocol"),
    (121, "encrypted client hello required"),
];

/// Go's `alert.String` (`crypto/tls/alert.go:103-109`).
fn go_alert(code: u8) -> String {
    match GO_ALERT_TEXT.iter().find(|(known, _)| *known == code) {
        Some((_, text)) => format!("tls: {text}"),
        None => format!("tls: alert({code})"),
    }
}

/// A `[]uint16` as Go's `%x` prints it: `[1301 c02b]`.
fn go_hex_list(values: &[u16]) -> String {
    let items: Vec<String> = values.iter().map(|value| format!("{value:x}")).collect();
    format!("[{}]", items.join(" "))
}

/// [`go_error_text`] for a refusal that does not depend on the
/// ClientHello, for the client certificate verifier's tests.
#[cfg(test)]
pub(crate) fn go_error_text_for_tests(err: &rustls::Error) -> String {
    go_error_text(err, None)
}

/// Go's error text for a handshake rustls refused, as far as the two
/// refusals correspond (`crypto/tls/handshake_server.go`,
/// `handshake_server_tls13.go`, `conn.go`); rustls's own description
/// otherwise.  `hello` is the ClientHello, once it has been read.
fn go_error_text(err: &rustls::Error, hello: Option<&HelloFacts>) -> String {
    use rustls::{CertificateError, Error, InvalidMessage, PeerIncompatible, PeerMisbehaved};
    let tls13 = hello.is_some_and(HelloFacts::offers_tls13);
    let no_suite = || {
        format!(
            "tls: no cipher suite supported by both client and server; client offered: {}",
            go_hex_list(
                hello
                    .map(|hello| hello.cipher_suites.as_slice())
                    .unwrap_or_default()
            )
        )
    };
    match err {
        // `readRecordOrCCS` (`conn.go:713-744`): a close_notify reads as a
        // close, anything else as a remote error.
        Error::AlertReceived(alert) if u8::from(*alert) == 0 => "EOF".to_string(),
        Error::AlertReceived(alert) => format!("remote error: {}", go_alert(u8::from(*alert))),
        Error::PeerIncompatible(PeerIncompatible::NoCipherSuitesInCommon) => no_suite(),
        // rustls looks for a group before a suite, and Go's TLS 1.3 server
        // the other way round (`handshake_server_tls13.go:179-196`, then
        // `:209-216`), so a TLS 1.3 client with neither in common hears
        // about the suite.  In TLS 1.2 Go finds no curve, so no ECDHE
        // suite, and RSA key exchange is off by default: it reports no
        // suite in common.
        Error::PeerIncompatible(PeerIncompatible::NoKxGroupsInCommon) => {
            let shares_a_suite = hello.is_some_and(|hello| {
                hello
                    .cipher_suites
                    .iter()
                    .any(|id| GO_TLS13_SUITE_IDS.contains(id))
            });
            if tls13 && shares_a_suite {
                "tls: no key exchanges supported by both client and server".to_string()
            } else {
                no_suite()
            }
        }
        Error::PeerIncompatible(
            PeerIncompatible::Tls12NotOffered | PeerIncompatible::Tls12NotOfferedOrEnabled,
        ) => format!(
            "tls: client offered only unsupported versions: {}",
            go_hex_list(
                &hello
                    .map(HelloFacts::go_client_versions)
                    .unwrap_or_default()
            )
        ),
        Error::PeerIncompatible(PeerIncompatible::NullCompressionRequired) => {
            "tls: client does not support uncompressed connections".to_string()
        }
        Error::PeerMisbehaved(PeerMisbehaved::OfferedIncorrectCompressions) => {
            "tls: TLS 1.3 client supports illegal compression methods".to_string()
        }
        Error::PeerIncompatible(PeerIncompatible::NoSignatureSchemesInCommon) => {
            "tls: peer doesn't support any of the certificate's signature algorithms".to_string()
        }
        Error::PeerIncompatible(PeerIncompatible::UncompressedEcPointsRequired) => {
            "tls: client offered only incompatible point formats".to_string()
        }
        // A key share that fails, in TLS 1.3
        // (`handshake_server_tls13.go:254-258`).  In TLS 1.2 Go gives one
        // text for a ClientKeyExchange whose point fails and for one with
        // bytes after its point (`processClientKeyExchange`,
        // `key_agreement.go:254-269`, reported at
        // `handshake_server.go:731-734`); rustls reports the point as an
        // invalid key share too, and the trailing bytes as bad DH params.
        Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare) if tls13 => {
            "tls: invalid client key share".to_string()
        }
        Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)
        | Error::InvalidMessage(InvalidMessage::InvalidDhParams) => {
            "tls: invalid ClientKeyExchange message".to_string()
        }
        Error::NoCertificatesPresented => "tls: client didn't provide a certificate".to_string(),
        Error::InvalidCertificate(CertificateError::UnknownIssuer) => {
            "tls: failed to verify certificate: x509: certificate signed by unknown authority"
                .to_string()
        }
        // Every chain the search completed failed Go's policy
        // validation (`GoClientCertVerifier`).
        Error::InvalidCertificate(CertificateError::Other(other))
            if other
                .0
                .downcast_ref::<crate::rpcrun::InvalidPolicies>()
                .is_some() =>
        {
            format!("tls: failed to verify certificate: {}", other.0)
        }
        // A certificate with a critical extension Go does not handle, as
        // Go's `isValid` refuses it (`GoClientCertVerifier`).
        Error::InvalidCertificate(CertificateError::UnhandledCriticalExtension) => {
            "tls: failed to verify certificate: x509: unhandled critical extension".to_string()
        }
        // webpki's refusal of a path past a path length constraint, an
        // intermediate's own or the root's (`GoClientCertVerifier`'s
        // path callback): Go's `TooManyIntermediates`.
        Error::InvalidCertificate(CertificateError::Other(other))
            if other.0.downcast_ref::<webpki::Error>()
                == Some(&webpki::Error::PathLenConstraintViolated) =>
        {
            "tls: failed to verify certificate: x509: too many intermediates for path length \
             constraint"
                .to_string()
        }
        // webpki's limit on the signature checks of one chain search: Go's
        // `errSignatureLimit`, though the two count their checks
        // differently (PARITY.md, the clientcert entry).
        Error::InvalidCertificate(CertificateError::Other(other))
            if other.0.downcast_ref::<webpki::Error>()
                == Some(&webpki::Error::MaximumSignatureChecksExceeded) =>
        {
            "tls: failed to verify certificate: x509: signature check attempts limit reached \
             while verifying certificate chain"
                .to_string()
        }
        // Go answers a record that fails to decrypt with `bad_record_mac`
        // and a message that fails to parse with `decode_error`, and
        // reports the alert it sent.
        Error::DecryptError => "local error: tls: bad record MAC".to_string(),
        Error::InvalidMessage(_) => "local error: tls: error decoding message".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
// Test-harness arithmetic over fixed deadlines.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use dcroxide_testutil::unhex;

    /// The P-521 vector Go's `crypto/ecdh` tests against
    /// (`crypto/ecdh/ecdh_test.go`), from NIST's CAVS 14.1 ECC CDH
    /// Primitive (SP 800-56A) set, with the two leading zero bytes the
    /// published field elements carry removed, as Go removes them.
    const CAVS_PRIVATE: &str = "017eecc07ab4b329068fba65e56a1f8890aa935e57134ae0ffcce802735151f4eac6564f6ee9974c5e6887a1fefee5743ae2241bfeb95d5ce31ddcb6f9edb4d6fc47";
    const CAVS_PUBLIC: &str = "0400602f9d0cf9e526b29e22381c203c48a886c2b0673033366314f1ffbcba240ba42f4ef38a76174635f91e6b4ed34275eb01c8467d05ca80315bf1a7bbd945f550a501b7c85f26f5d4b2d7355cf6b02117659943762b6d1db5ab4f1dbc44ce7b2946eb6c7de342962893fd387d1b73d7a8672d1f236961170b7eb3579953ee5cdc88cd2d";
    const CAVS_PEER: &str = "0400685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a9490340854334b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2046d01ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b739884a83bde99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302f676";
    const CAVS_SHARED: &str = "005fc70477c3e63bc3954bd0df3ea0d1f41ee21746ed95fc5e1fdf90930d5e136672d72cc770742d1711c3c3a4c334a0ad9759436a4d3c5bf6e74b9578fac148c831";

    fn cavs_exchange() -> P521KeyExchange {
        P521KeyExchange::new(
            p521::SecretKey::from_slice(&unhex(CAVS_PRIVATE)).expect("the vector's private key"),
        )
    }

    /// The key share and the shared secret match the NIST vector.
    #[test]
    fn p521_key_exchange_matches_the_nist_cdh_vector() {
        let exchange = cavs_exchange();
        assert_eq!(exchange.pub_key, unhex(CAVS_PUBLIC), "the key share");
        assert_eq!(exchange.pub_key.len(), P521_UNCOMPRESSED_POINT_LEN);
        let shared = Box::new(exchange)
            .complete(&unhex(CAVS_PEER))
            .expect("the vector's peer key is valid");
        assert_eq!(shared.secret_bytes(), unhex(CAVS_SHARED).as_slice());
    }

    /// Two fresh exchanges agree with each other, and each fresh key share
    /// is an uncompressed point on the curve.
    #[test]
    fn fresh_p521_exchanges_agree() {
        let ours = P521_KX_GROUP.start().expect("start ours");
        let theirs = P521_KX_GROUP.start().expect("start theirs");
        assert_eq!(ours.group(), NamedGroup::secp521r1);
        for share in [ours.pub_key(), theirs.pub_key()] {
            assert_eq!(share.len(), P521_UNCOMPRESSED_POINT_LEN);
            assert_eq!(share.first(), Some(&0x04));
            p521::PublicKey::from_sec1_bytes(share).expect("on the curve");
        }
        assert_ne!(ours.pub_key(), theirs.pub_key(), "fresh ephemeral keys");
        let (ours_pub, theirs_pub) = (ours.pub_key().to_vec(), theirs.pub_key().to_vec());
        let a = ours.complete(&theirs_pub).expect("ours completes");
        let b = theirs.complete(&ours_pub).expect("theirs completes");
        assert_eq!(a.secret_bytes(), b.secret_bytes());
        assert_eq!(a.secret_bytes().len(), 66, "the whole x-coordinate");
    }

    /// The compressed form, an off-curve point, a short share and the
    /// identity's encoding are all refused as invalid key shares.
    #[test]
    fn p521_key_exchange_refuses_invalid_shares() {
        use p521::elliptic_curve::sec1::ToSec1Point;
        let peer = p521::PublicKey::from_sec1_bytes(&unhex(CAVS_PEER)).expect("valid peer");
        let compressed = peer.to_sec1_point(true).as_bytes().to_vec();
        let mut off_curve = unhex(CAVS_PEER);
        if let Some(last) = off_curve.last_mut() {
            *last ^= 1;
        }
        let short = unhex(CAVS_PEER)
            .get(..P521_UNCOMPRESSED_POINT_LEN - 1)
            .expect("shorter")
            .to_vec();
        for (label, share) in [
            ("compressed", compressed),
            ("off the curve", off_curve),
            ("short", short),
            ("identity", vec![0x00]),
            ("empty", Vec::new()),
        ] {
            let err = Box::new(cavs_exchange())
                .complete(&share)
                .err()
                .unwrap_or_else(|| panic!("{label}: refused"));
            assert!(
                matches!(
                    err,
                    rustls::Error::PeerMisbehaved(rustls::PeerMisbehaved::InvalidKeyShare)
                ),
                "{label}: {err:?}"
            );
        }
    }

    /// The implementations follow the codes the choice indexes.
    #[test]
    fn the_offered_groups_follow_gos_order() {
        let names: Vec<u16> = rpc_kx_groups()
            .iter()
            .map(|group| u16::from(group.name()))
            .collect();
        assert_eq!(names, RPC_KX_GROUP_IDS);
    }

    /// Go's TLS 1.3 group choice: a group with a key share before one
    /// without, Go's order among equals, and none without a group in
    /// common.
    #[test]
    fn tls13_group_choice_follows_go() {
        let index = |id| RPC_KX_GROUP_IDS.iter().position(|&known| known == id);
        for (supported, shares, expected) in [
            // The common case: the client's first group, with its share.
            (
                vec![X25519_ID, SECP256R1_ID],
                vec![X25519_ID],
                Some(X25519_ID),
            ),
            // A share wins over Go's order...
            (
                vec![SECP521R1_ID, X25519_ID],
                vec![SECP521R1_ID],
                Some(SECP521R1_ID),
            ),
            (
                vec![X25519_ID, SECP384R1_ID],
                vec![SECP384R1_ID],
                Some(SECP384R1_ID),
            ),
            // ...where rustls would retry for the client's first group.
            (
                vec![SECP256R1_ID, SECP384R1_ID],
                vec![SECP384R1_ID],
                Some(SECP384R1_ID),
            ),
            // Among groups with shares, Go's order, not the client's.
            (
                vec![SECP384R1_ID, SECP256R1_ID],
                vec![SECP384R1_ID, SECP256R1_ID],
                Some(SECP256R1_ID),
            ),
            // No usable share: Go's first, by HelloRetryRequest.
            (vec![SECP521R1_ID, SECP384R1_ID], vec![], Some(SECP384R1_ID)),
            // A share for a group Go would not take is no share at all,
            // and the hybrid is one the port cannot take.
            (vec![0x11ec, SECP521R1_ID], vec![0x11ec], Some(SECP521R1_ID)),
            (vec![0x001e, 0x11ec], vec![0x001e], None),
            (vec![], vec![X25519_ID], None),
        ] {
            assert_eq!(
                go_tls13_group(&supported, &shares),
                expected.and_then(index),
                "{supported:x?} with shares {shares:x?}"
            );
        }
    }

    /// Go's AES-GCM preference reads the first suite it knows.
    #[test]
    fn aes_gcm_preference_follows_go() {
        for (suites, expected) in [
            // OpenSSL's default offer, AES-256 first.
            (vec![0x1302, 0x1303, 0x1301, 0xc02c], true),
            (vec![0x1301, 0x1302, 0x1303], true),
            (vec![0x1303, 0x1301], false),
            // GREASE, the renegotiation SCSV and a suite Go lacks are
            // passed over.
            (vec![0x0a0a, 0x00ff, 0x009f, 0xc02b], true),
            (vec![0x0a0a, 0xcca9, 0xc02b], false),
            // A known suite that is not AES-GCM decides as well.
            (vec![0xc013, 0xc02f], false),
            (vec![0x0a0a], false),
            (vec![], false),
        ] {
            assert_eq!(go_aes_gcm_preferred(true, &suites), expected, "{suites:x?}");
            assert!(
                !go_aes_gcm_preferred(false, &suites),
                "{suites:x?} without hardware"
            );
        }
    }

    /// The two orders are Go's, less its CBC suites.
    #[test]
    fn cipher_suite_orders_are_gos() {
        let ids = |aes_gcm_first| -> Vec<u16> {
            rpc_cipher_suites(aes_gcm_first)
                .iter()
                .map(|suite| u16::from(suite.suite()))
                .collect()
        };
        assert_eq!(
            ids(true),
            [
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8
            ]
        );
        assert_eq!(
            ids(false),
            [
                0x1303, 0x1301, 0x1302, 0xcca9, 0xcca8, 0xc02b, 0xc02f, 0xc02c, 0xc030
            ]
        );
    }

    /// A ClientHello as a rustls client writes it, cut into records of
    /// at most `fragment` bytes.
    fn client_hello(
        versions: &[&'static rustls::SupportedProtocolVersion],
        kx_groups: Vec<&'static dyn SupportedKxGroup>,
        fragment: usize,
    ) -> Vec<u8> {
        #[derive(Debug)]
        struct NoVerifier;
        impl rustls::client::danger::ServerCertVerifier for NoVerifier {
            fn verify_server_cert(
                &self,
                _end_entity: &rustls::pki_types::CertificateDer<'_>,
                _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                _server_name: &rustls::pki_types::ServerName<'_>,
                _ocsp: &[u8],
                _now: rustls::pki_types::UnixTime,
            ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                Err(rustls::Error::General("unused".into()))
            }
            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Err(rustls::Error::General("unused".into()))
            }
            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Err(rustls::Error::General("unused".into()))
            }
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                vec![rustls::SignatureScheme::ECDSA_NISTP256_SHA256]
            }
        }
        let mut provider = rustls::crypto::ring::default_provider();
        provider.kx_groups = kx_groups;
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(versions)
            .expect("versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        config.max_fragment_size = Some(fragment);
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
        let mut conn = rustls::ClientConnection::new(Arc::new(config), name).expect("client");
        let mut out = Vec::new();
        while conn.wants_write() {
            conn.write_tls(&mut out).expect("write the ClientHello");
        }
        out
    }

    /// The raw read finds what the client sent: its suites, groups, key
    /// share and versions, through one record or several.
    #[test]
    fn hello_facts_read_a_client_hello() {
        use rustls::crypto::ring::kx_group;
        for fragment in [16384, 64] {
            let both = client_hello(
                rustls::DEFAULT_VERSIONS,
                vec![P521_KX_GROUP, kx_group::X25519],
                fragment,
            );
            let facts = HelloFacts::parse(&both).expect("parses");
            assert!(facts.offers_tls13(), "{facts:?}");
            assert_eq!(facts.supported_groups, [SECP521R1_ID, X25519_ID]);
            assert_eq!(
                facts.key_shares,
                [SECP521R1_ID],
                "a share for the first group"
            );
            assert!(facts.cipher_suites.contains(&0x1301), "{facts:?}");
            assert_eq!(facts.legacy_version, 0x0303);

            let tls12 = client_hello(
                &[&rustls::version::TLS12],
                vec![kx_group::SECP384R1],
                fragment,
            );
            let facts = HelloFacts::parse(&tls12).expect("parses");
            assert!(!facts.offers_tls13(), "{facts:?}");
            assert_eq!(facts.supported_versions, Some(vec![0x0303]));
            assert_eq!(facts.supported_groups, [SECP384R1_ID]);
            assert!(facts.key_shares.is_empty());
            assert_eq!(facts.go_client_versions(), [0x0303]);
        }
        // Cut short, or not a handshake at all, it reads as nothing.
        let whole = client_hello(rustls::DEFAULT_VERSIONS, vec![kx_group::X25519], 16384);
        assert_eq!(
            HelloFacts::parse(whole.get(..whole.len() - 1).expect("cut")),
            None
        );
        assert_eq!(HelloFacts::parse(b"GET / HTTP/1.1\r\n\r\n"), None);
    }

    /// Go's offered versions for a ClientHello without the extension.
    #[test]
    fn go_client_versions_follow_the_legacy_version() {
        for (legacy, expected) in [
            (0x0304, vec![0x0303, 0x0302, 0x0301]),
            (0x0303, vec![0x0303, 0x0302, 0x0301]),
            (0x0302, vec![0x0302, 0x0301]),
            (0x0300, vec![]),
        ] {
            let facts = HelloFacts {
                legacy_version: legacy,
                ..HelloFacts::default()
            };
            assert_eq!(facts.go_client_versions(), expected, "{legacy:x}");
        }
        assert_eq!(go_hex_list(&[0x0302, 0x0301]), "[302 301]");
        assert_eq!(go_hex_list(&[]), "[]");
    }

    /// An early close reads as Go reads it: `EOF` between records,
    /// `unexpected EOF` inside a header or a body.
    #[test]
    fn eof_reason_follows_record_boundaries() {
        let mut tap = HandshakeTap::default();
        assert_eq!(tap.eof_reason(), "EOF");
        tap.feed(&[22, 3, 1]);
        assert_eq!(tap.eof_reason(), "unexpected EOF", "inside a header");
        tap.feed(&[0, 3, 1]);
        assert_eq!(tap.eof_reason(), "unexpected EOF", "inside a body");
        tap.feed(&[2, 3]);
        assert_eq!(tap.eof_reason(), "EOF", "on a boundary");
        // Two records and part of a third in one read.
        tap.feed(&[21, 3, 3, 0, 2, 2, 40, 22, 3, 3, 0, 0, 22]);
        assert_eq!(tap.eof_reason(), "unexpected EOF");
        assert_eq!(tap.recorded.len(), 21);
    }

    /// The first record is refused on its header exactly where Go refuses
    /// it.
    #[test]
    fn first_record_refusals_follow_go() {
        let refusal = |bytes: &[u8]| {
            let mut tap = HandshakeTap::default();
            tap.feed(bytes);
            tap.first_record_refusal()
        };
        assert_eq!(refusal(b"GET / HTTP/1.1"), Some(FirstRecordRefusal::Http));
        assert_eq!(refusal(b"POST /"), Some(FirstRecordRefusal::Http));
        assert_eq!(refusal(b"OPTIONS *"), Some(FirstRecordRefusal::Http));
        assert_eq!(refusal(b"GET /x"), Some(FirstRecordRefusal::Http));
        assert_eq!(refusal(b"get / "), Some(FirstRecordRefusal::NotTls));
        assert_eq!(refusal(b"SSH-2.0-x"), Some(FirstRecordRefusal::NotTls));
        assert_eq!(refusal(&[23, 3, 3, 0, 5]), Some(FirstRecordRefusal::NotTls));
        assert_eq!(
            refusal(&[22, 0x10, 0, 0, 5]),
            Some(FirstRecordRefusal::NotTls)
        );
        assert_eq!(
            refusal(&[0x80, 0x2e, 1, 0, 2]),
            Some(FirstRecordRefusal::SslV2)
        );
        assert_eq!(
            refusal(&[22, 3, 1, 0x48, 0x01]),
            Some(FirstRecordRefusal::Oversized(0x4801))
        );
        assert_eq!(
            refusal(&[22, 3, 1, 0x48, 0x00]),
            None,
            "2^14 + 2048 is allowed"
        );
        assert_eq!(refusal(&[21, 3, 1, 0, 2]), None, "an alert may come first");
        assert_eq!(refusal(&[22, 3, 1, 0]), None, "not a whole header yet");
    }

    /// Go's texts for the refusals the two stacks share.
    #[test]
    fn handshake_error_texts_follow_go() {
        use rustls::{AlertDescription, Error, InvalidMessage, PeerIncompatible, PeerMisbehaved};
        let tls13 = HelloFacts {
            cipher_suites: vec![0x1301, 0x0a0a],
            supported_versions: Some(vec![0x0304, 0x0303]),
            ..HelloFacts::default()
        };
        // TLS 1.3 offered, but only with TLS 1.2 suites.
        let tls13_without_its_suites = HelloFacts {
            cipher_suites: vec![0xc02b, 0x0a0a],
            supported_versions: Some(vec![0x0304, 0x0303]),
            ..HelloFacts::default()
        };
        let tls12 = HelloFacts {
            legacy_version: 0x0303,
            cipher_suites: vec![0xc02b],
            supported_versions: Some(vec![0x0303]),
            ..HelloFacts::default()
        };
        let tls11 = HelloFacts {
            legacy_version: 0x0302,
            cipher_suites: vec![0xc013],
            ..HelloFacts::default()
        };
        for (err, hello, expected) in [
            (
                Error::AlertReceived(AlertDescription::IllegalParameter),
                None,
                "remote error: tls: illegal parameter",
            ),
            (
                Error::AlertReceived(AlertDescription::UnknownCA),
                None,
                "remote error: tls: unknown certificate authority",
            ),
            (
                Error::AlertReceived(AlertDescription::Unknown(200)),
                None,
                "remote error: tls: alert(200)",
            ),
            (
                Error::AlertReceived(AlertDescription::CloseNotify),
                None,
                "EOF",
            ),
            (
                Error::PeerIncompatible(PeerIncompatible::NoCipherSuitesInCommon),
                Some(&tls13),
                "tls: no cipher suite supported by both client and server; client offered: [1301 a0a]",
            ),
            (
                Error::PeerIncompatible(PeerIncompatible::NoKxGroupsInCommon),
                Some(&tls13),
                "tls: no key exchanges supported by both client and server",
            ),
            (
                Error::PeerIncompatible(PeerIncompatible::NoKxGroupsInCommon),
                Some(&tls13_without_its_suites),
                "tls: no cipher suite supported by both client and server; client offered: [c02b a0a]",
            ),
            (
                Error::PeerIncompatible(PeerIncompatible::NoKxGroupsInCommon),
                Some(&tls11),
                "tls: no cipher suite supported by both client and server; client offered: [c013]",
            ),
            (
                Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare),
                Some(&tls13),
                "tls: invalid client key share",
            ),
            (
                Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare),
                Some(&tls12),
                "tls: invalid ClientKeyExchange message",
            ),
            (
                Error::InvalidMessage(InvalidMessage::InvalidDhParams),
                Some(&tls12),
                "tls: invalid ClientKeyExchange message",
            ),
            (
                Error::PeerIncompatible(PeerIncompatible::Tls12NotOffered),
                Some(&tls11),
                "tls: client offered only unsupported versions: [302 301]",
            ),
            (
                Error::NoCertificatesPresented,
                Some(&tls13),
                "tls: client didn't provide a certificate",
            ),
            (
                Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(
                    std::sync::Arc::new(webpki::Error::PathLenConstraintViolated),
                ))),
                Some(&tls13),
                "tls: failed to verify certificate: x509: too many intermediates for path length constraint",
            ),
            (
                Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(
                    std::sync::Arc::new(crate::rpcrun::InvalidPolicies(2)),
                ))),
                Some(&tls13),
                "tls: failed to verify certificate: x509: no valid chains built: 2 candidate chains with invalid policies",
            ),
            (
                Error::InvalidCertificate(rustls::CertificateError::UnhandledCriticalExtension),
                Some(&tls13),
                "tls: failed to verify certificate: x509: unhandled critical extension",
            ),
            (
                Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(
                    std::sync::Arc::new(webpki::Error::MaximumSignatureChecksExceeded),
                ))),
                Some(&tls13),
                "tls: failed to verify certificate: x509: signature check attempts limit reached while verifying certificate chain",
            ),
        ] {
            assert_eq!(go_error_text(&err, hello), expected, "{err:?}");
        }
    }

    /// Each ClientHello gets the configuration that leaves rustls Go's
    /// choice: the one key exchange Go would take in TLS 1.3, every one in
    /// TLS 1.2 or with none in common, and the suites in the order Go's
    /// AES-GCM preference picks, always in the server's order.
    #[test]
    fn each_client_hello_gets_the_configuration_for_gos_choice() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (cert, key) = crate::rpcrun::load_or_generate_cert_pair(
            &dir.path().join("rpc.cert"),
            &dir.path().join("rpc.key"),
            &[],
            dcroxide_certgen::Curve::P256,
        )
        .expect("a cert pair");
        let configs = crate::rpcrun::tls_server_config(&cert, &key, None).expect("the set");
        assert_eq!(configs.configs().count(), 10);
        assert!(configs.configs().all(|config| config.ignore_client_order));

        let groups = |config: &ServerConfig| -> Vec<u16> {
            config
                .crypto_provider()
                .kx_groups
                .iter()
                .map(|group| u16::from(group.name()))
                .collect()
        };
        let first_suite = |config: &ServerConfig| {
            config
                .crypto_provider()
                .cipher_suites
                .first()
                .map(|suite| u16::from(suite.suite()))
        };
        let hello = |suites: &[u16], tls13: bool, supported: &[u16], shares: &[u16]| HelloFacts {
            legacy_version: 0x0303,
            cipher_suites: suites.to_vec(),
            supported_versions: Some(if tls13 {
                vec![0x0304, 0x0303]
            } else {
                vec![0x0303]
            }),
            supported_groups: supported.to_vec(),
            key_shares: shares.to_vec(),
        };
        let aes_first = if configs.aes_gcm_hardware {
            Some(0x1301)
        } else {
            Some(0x1303)
        };

        // Decrediton's offer: P-521 alone, over TLS 1.3.
        let config = configs.for_hello(&hello(
            &[0x1302, 0x1301],
            true,
            &[SECP521R1_ID],
            &[SECP521R1_ID],
        ));
        assert_eq!(groups(&config), [SECP521R1_ID]);
        assert_eq!(first_suite(&config), aes_first);
        // No share for a group Go takes: Go's first, by retry.
        let config = configs.for_hello(&hello(
            &[0x1303, 0x1301],
            true,
            &[0x001e, SECP256R1_ID, X25519_ID],
            &[0x001e],
        ));
        assert_eq!(groups(&config), [X25519_ID]);
        assert_eq!(
            first_suite(&config),
            Some(0x1303),
            "a ChaCha20-first client"
        );
        // TLS 1.2 and no group in common both offer everything.
        let every = RPC_KX_GROUP_IDS.to_vec();
        let config = configs.for_hello(&hello(&[0xc02c], false, &[SECP384R1_ID], &[]));
        assert_eq!(groups(&config), every);
        let config = configs.for_hello(&hello(&[0x1301], true, &[0x001e], &[0x001e]));
        assert_eq!(groups(&config), every);
    }

    /// A connected pair of loopback sockets, the server's end first.
    fn loopback() -> (TcpStream, TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let client = TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        (server, client)
    }

    /// The handshake's refusal when the client sends `bytes` and then
    /// either closes or, with `linger`, waits; and what the client read.
    fn refusal(bytes: &'static [u8], linger: bool, deadline: Duration) -> (String, Vec<u8>) {
        let (server, mut client) = loopback();
        let talking = std::thread::spawn(move || {
            client.write_all(bytes).expect("send");
            if !linger {
                let _ = client.shutdown(std::net::Shutdown::Write);
            }
            let mut answer = Vec::new();
            let _ = client.read_to_end(&mut answer);
            answer
        });
        let reason = handshake(
            server,
            Instant::now() + deadline,
            Duration::from_millis(50),
            || unreachable!("no ClientHello arrives"),
        )
        .expect_err("refused");
        (reason, talking.join().expect("the client finishes"))
    }

    /// The handshake's failures as Go's server reports and answers them:
    /// a close between records and inside one, the deadline, a plaintext
    /// HTTP request (answered with net/http's 400), a first record that is
    /// not TLS (unanswered) and an SSLv2 ClientHello (a `protocol_version`
    /// alert).
    #[test]
    fn handshake_failures_read_as_gos() {
        let long = Duration::from_secs(10);
        assert_eq!(refusal(b"", false, long), ("EOF".to_string(), Vec::new()));
        assert_eq!(
            refusal(&[22, 3, 1, 0, 9, 1], false, long).0,
            "unexpected EOF"
        );
        assert_eq!(
            refusal(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", true, long),
            (
                "client sent an HTTP request to an HTTPS server".to_string(),
                b"HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n"
                    .to_vec()
            )
        );
        assert_eq!(
            refusal(b"SSH-2.0-OpenSSH_9.9\r\n", true, long),
            (
                "tls: first record does not look like a TLS handshake".to_string(),
                Vec::new()
            )
        );
        assert_eq!(
            refusal(&[0x80, 0x2e, 0x01, 0x00, 0x02], true, long),
            (
                "tls: unsupported SSLv2 handshake received".to_string(),
                vec![0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x46]
            )
        );

        // Nothing at all until the deadline: Go's read timeout, naming
        // both ends.
        let (server, client) = loopback();
        let expected = format!(
            "read tcp4 {}->{}: i/o timeout",
            server.local_addr().expect("local"),
            client.local_addr().expect("peer")
        );
        let reason = handshake(
            server,
            Instant::now() + Duration::from_millis(300),
            Duration::from_millis(50),
            || unreachable!("no ClientHello arrives"),
        )
        .expect_err("refused");
        assert_eq!(reason, expected);
        drop(client);
    }

    /// `net.OpError`'s shape, with and without its addresses.
    #[test]
    fn op_errors_read_as_gos() {
        let local: SocketAddr = "127.0.0.1:9109".parse().expect("local");
        let remote: SocketAddr = "[::1]:50000".parse().expect("remote");
        let name = GoConnName {
            net: "tcp4",
            local: Some(local),
            remote: Some(remote),
        };
        assert_eq!(
            name.timeout(),
            "read tcp4 127.0.0.1:9109->[::1]:50000: i/o timeout"
        );
        #[cfg(unix)]
        assert_eq!(
            name.io_error("read", &std::io::Error::from_raw_os_error(libc::ECONNRESET)),
            "read tcp4 127.0.0.1:9109->[::1]:50000: read: connection reset by peer"
        );
        let unnamed = GoConnName {
            net: "tcp6",
            local: None,
            remote: Some(remote),
        };
        assert_eq!(unnamed.timeout(), "read tcp6 [::1]:50000: i/o timeout");
    }
}
