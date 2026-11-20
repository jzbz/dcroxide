// SPDX-License-Identifier: ISC
//! The TLS server as Go's `crypto/tls` conducts it for dcrd's and
//! dcrwallet's RPC listeners: the configurations a certificate pair is
//! served with, the key exchanges and cipher suites on offer, the choice
//! among them for each ClientHello, and the text logged when a handshake
//! fails.
//!
//! dcrd's RPC `tls.Config` sets the certificate, `MinVersion` and, under
//! `--authtype=clientcert`, the client CAs, and nothing else
//! (`newTLSConfig`, `server.go:3685-3699`; the outer config adds only
//! `GetConfigForClient`, `:3818-3821`), so every negotiation choice is
//! Go's default.  dcrwallet's sets the same three, its client CAs always
//! (`rpcserver.go:272-276`), and its gRPC listener's adds `h2` to
//! `NextProtos` through grpc-go's `credentials.NewTLS`; the two differ
//! only in what [`GoServerOptions`] holds.  Go 1.26.2, the reference Go until the `46e9df48` move
//! (ADR-0001's 2026-10-26 addendum on the reference Go), makes these
//! choices for that configuration, and Go 1.27, which built dcrd 2.1.7's
//! published linux-amd64 binary and is the reference from that move on as
//! go1.27.3, the release the citations below are read in, makes the same
//! ones:
//!
//! * At `46e9df48`, the parity pin, as on master, dcrd's `debug.go` sets
//!   `//go:debug default=go1.26`, and a build there offers X25519MLKEM768,
//!   SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519, P-256, P-384 and
//!   P-521, in that order (`crypto/tls/defaults.go:23-43`), the hybrids in
//!   TLS 1.3 only.  2.1.7's `debug.go` sets `default=go1.25`, which
//!   restores Go 1.25's value of every setting changed since,
//!   `tlssecpmlkem=0` among them (`internal/godebugs/table.go`), so 2.1.7
//!   offers X25519MLKEM768 alone ahead of the classical groups
//!   (`defaults.go:29-30`): Go 1.26 added the other two hybrids.
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
//! dcrwallet at its pin builds with `//go:debug default=go1.25`
//! (`debug.go`), which differs from dcrd's `default=go1.26` in
//! `crypto/tls` only by `tlssecpmlkem=0`, so it offers X25519MLKEM768
//! alone among the hybrids; the classical groups and the suites are the
//! same for both, and so is everything below.
//!
//! rustls picks the group, and by default the suite, in the client's
//! order.  The port closes most of that gap in three parts.  The suites
//! and groups come from `dcroxide-tlscrypto`, the in-tree provider the
//! node's TLS runs on (ADR-0015), each an item of its own, so both of Go's
//! suite orders can be built from them, and P-521 among the groups, whose
//! exchanges take a peer's share and draw their ephemeral keys as Go's
//! `crypto/ecdh` does.  A certificate pair is served by [`GoServerConfigs`],
//! a set of rustls configurations, one for each cipher-suite order and
//! TLS 1.3 key exchange Go can settle on, all with `ignore_client_order`
//! set.  And [`handshake`] reads the ClientHello through
//! `rustls::server::Acceptor` before it picks one of them, so the
//! configuration a connection gets leaves rustls only Go's choice to
//! make.  The ClientHello's key shares and offered versions, which
//! rustls's `ClientHello` does not expose, are read from the raw records
//! ([`HelloFacts`]).
//!
//! An ML-DSA `rpc.key`, which Go 1.27.3 serves in TLS 1.3 alone, is
//! refused to a client that would negotiate TLS 1.2 as Go refuses it: with
//! `internal_error` and Go's text, after the refusals Go makes first, each
//! with its own alert and text, and before any suite or curve is chosen
//! (`crypto/tls/handshake_server.go:216-318`), where rustls would find no
//! TLS 1.2 suite for the key and send `handshake_failure`.
//!
//! The handshake runs to completion before the request is read, as
//! `conn.serve` runs it (`net/http/server.go:1976-2007`), and a failure
//! comes back as the text Go's error would print, for the
//! `http: TLS handshake error` line the caller logs.
//!
//! A server with `NextProtos` set takes the protocol in its own order, as
//! Go's `negotiateALPN` and rustls both do, and refuses a client whose
//! protocols share none with `no_application_protocol`, as both do; Go's
//! one exception, a client offering `http/1.1` to a server offering
//! `h2`, which Go serves as though it had sent no ALPN extension, is
//! made here by serving that client a configuration without protocols
//! ([`GoServerConfigs::for_hello`]).  Go refuses a TLS 1.2 client's
//! protocols before it chooses a suite, where rustls chooses the suite
//! first, so that refusal is made before rustls sees the ClientHello, in
//! Go's place among its other refusals
//! ([`HelloFacts::go_tls12_refusal`]).  In TLS 1.3 the two refuse
//! protocols at the same point, after the suite, the group and any
//! HelloRetryRequest, with one exception: a ClientHello without
//! signature_algorithms, which rustls refuses as it reads it, with
//! `handshake_failure`, where Go refuses it after ALPN, with
//! `missing_extension`, or refuses its protocols first (PARITY.md, the
//! open entry on ClientHello refusals).  Under [`GoServerOptions::grpc`], dcrwallet's gRPC
//! listener, a completed handshake that negotiated no protocol is then
//! closed as grpc-go closes it ([`GoServerConfigs::after_handshake`]).
//!
//! What still differs is recorded in PARITY.md: the hybrid post-quantum
//! groups, which need an ML-KEM implementation the build
//! does not carry; Go's four TLS 1.2 CBC suites, which rustls does not
//! implement; and the text of the failures that have no counterpart below.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::{ServerConfig, SupportedCipherSuite};

use crate::clientcert::GoClientCertVerifier;
use crate::pem::{go_certificate_blocks, go_key_block};
use crate::records::{GoRecordChecks, first_handshake_message};

/// The IANA code of X25519 (RFC 8446 §4.2.7).
const X25519_ID: u16 = 0x001d;
/// The IANA code of secp256r1.
const SECP256R1_ID: u16 = 0x0017;
/// The IANA code of secp384r1.
const SECP384R1_ID: u16 = 0x0018;
/// The IANA code of secp521r1.
const SECP521R1_ID: u16 = 0x0019;

/// The key exchanges the RPC server offers, as IANA codes, in Go's
/// preference order (`curvePreferenceOrder`, `crypto/tls/defaults.go:38-43`)
/// less the post-quantum groups ahead of them, which the build cannot
/// offer.  [`rpc_kx_groups`] holds the implementations in the same order.
const RPC_KX_GROUP_IDS: [u16; 4] = [X25519_ID, SECP256R1_ID, SECP384R1_ID, SECP521R1_ID];

/// The key exchanges the RPC server offers, in the order of
/// [`RPC_KX_GROUP_IDS`]: `dcroxide-tlscrypto`'s four, P-521 among them,
/// which Go's server offers by default (`defaultCurveEnabled`,
/// `crypto/tls/defaults.go:23-34`) and the provider's default list, kept
/// to ring's three for the seeders' ClientHello, leaves out.
///
/// Without P-521 a client that offers nothing else gets a
/// `handshake_failure` alert where dcrd completes the handshake, and
/// Decrediton is such a client: it pins `ecdhCurve: "secp521r1"` on its
/// requests to a remote daemon.
fn rpc_kx_groups() -> [&'static dyn SupportedKxGroup; 4] {
    use dcroxide_tlscrypto::kx_group;
    [
        kx_group::X25519,
        kx_group::SECP256R1,
        kx_group::SECP384R1,
        kx_group::SECP521R1,
    ]
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
    use dcroxide_tlscrypto::cipher_suite::{
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
///
/// The set also says whether its key is one Go serves in TLS 1.3 alone,
/// an ML-DSA key, which `handshake` refuses to a client that would
/// negotiate TLS 1.2 before rustls looks for a suite, as Go does.
#[derive(Debug)]
pub struct GoServerConfigs {
    /// AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305.
    aes_gcm_first: ConfigsByGroup,
    /// ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM.
    chacha_first: ConfigsByGroup,
    /// Whether this machine has the hardware Go's AES-GCM preference
    /// turns on, read once.
    aes_gcm_hardware: bool,
    /// Whether the key is one Go serves in TLS 1.3 alone
    /// (`KeyAlgorithm::tls13_only`).
    tls13_only: bool,
    /// The configurations' ALPN protocols, Go's `NextProtos`, which a
    /// TLS 1.2 client is refused against before rustls sees it, at the
    /// point in Go's order where Go refuses it
    /// ([`HelloFacts::go_tls12_refusal`]).
    next_protos: Vec<Vec<u8>>,
    /// Whether the configurations offer `h2`, and so take Go's
    /// `http/1.1` exception to an ALPN refusal.
    alpn_h2: bool,
    /// Whether a completed handshake that negotiated no protocol is
    /// closed, as grpc-go's `ServerHandshake` closes it
    /// ([`GoServerOptions::grpc`], [`GoServerConfigs::after_handshake`]).
    grpc_alpn_required: bool,
}

impl GoServerConfigs {
    /// Build the set, calling `build` once for each provider:
    /// `dcroxide-tlscrypto`'s, with the suites in one of Go's two orders and
    /// the key exchanges cut to those the configuration offers.
    /// `tls13_only` says whether the key the configurations serve is one Go
    /// serves in TLS 1.3 alone.
    fn build<E>(
        tls13_only: bool,
        next_protos: Vec<Vec<u8>>,
        grpc_alpn_required: bool,
        mut build: impl FnMut(Arc<CryptoProvider>) -> Result<ServerConfig, E>,
    ) -> Result<GoServerConfigs, E> {
        let alpn_h2 = next_protos.iter().any(|proto| proto.as_slice() == b"h2");
        Ok(GoServerConfigs {
            aes_gcm_first: Self::by_group(true, &mut build)?,
            chacha_first: Self::by_group(false, &mut build)?,
            aes_gcm_hardware: go_has_aes_gcm_hardware(),
            tls13_only,
            next_protos,
            alpn_h2,
            grpc_alpn_required,
        })
    }

    /// The configurations Go's server holding `key_pair` and configured
    /// as `options` say negotiates with: TLS 1.2 and TLS 1.3, Go's
    /// `MinVersion` of `tls.VersionTLS12` in dcrd and dcrwallet alike, and
    /// its default maximum; Go's suites in its two orders and its groups,
    /// those the build has; the suite in the server's order; the client
    /// certificate as `options.client_auth` says; `options.next_protos`
    /// for ALPN, with `h2` after them under `options.grpc`; and no
    /// stateful resumption and no session tickets
    /// (`disable_stateful_resumption`).  The certificate, key and client
    /// verifier are shared by every configuration in the set, which differ
    /// only in their providers, each `dcroxide-tlscrypto`'s; no process
    /// default is installed or read.
    pub fn new(
        key_pair: &KeyPair,
        options: &GoServerOptions,
    ) -> Result<GoServerConfigs, rustls::Error> {
        let next_protos = options.effective_next_protos();
        let protocols = next_protos.clone();
        GoServerConfigs::build(key_pair.tls13_only, next_protos, options.grpc, |provider| {
            let builder = rustls::ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(rustls::DEFAULT_VERSIONS)?;
            let builder = match &options.client_auth {
                ClientAuth::RequireAndVerifyClientCert(verifier) => {
                    let verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> =
                        Arc::clone(verifier) as _;
                    builder.with_client_cert_verifier(verifier)
                }
                ClientAuth::NoClientCert => builder.with_no_client_auth(),
            };
            let mut config = builder.with_cert_resolver(Arc::clone(&key_pair.resolver));
            // Go's server picks the cipher suite in its own order
            // (`selectCipherSuite` over its preference list,
            // `crypto/tls/handshake_server.go:398-422`, and the TLS 1.3 loop at
            // `handshake_server_tls13.go:179-197`), where rustls defaults to
            // the client's.  The provider holds Go's order.
            config.ignore_client_order = true;
            config.alpn_protocols = protocols.clone();
            disable_stateful_resumption(&mut config);
            Ok(config)
        })
    }

    /// The configurations for one cipher-suite order.
    fn by_group<E>(
        aes_gcm_first: bool,
        build: &mut impl FnMut(Arc<CryptoProvider>) -> Result<ServerConfig, E>,
    ) -> Result<ConfigsByGroup, E> {
        let mut provider = |kx_groups: Vec<&'static dyn SupportedKxGroup>| {
            let mut provider = dcroxide_tlscrypto::default_provider();
            provider.cipher_suites = rpc_cipher_suites(aes_gcm_first);
            provider.kx_groups = kx_groups;
            build(Arc::new(provider)).map(Arc::new)
        };
        let any = provider(rpc_kx_groups().to_vec())?;
        let only = rpc_kx_groups()
            .into_iter()
            .map(|group| provider(vec![group]))
            .collect::<Result<Vec<_>, E>>()?;
        Ok(ConfigsByGroup { any, only })
    }

    /// The configuration for a connection whose ClientHello is `hello`.
    ///
    /// A client that offers `http/1.1` and no protocol of the server's,
    /// to a server that offers `h2`, gets the configuration without ALPN,
    /// as Go's `negotiateALPN` serves it (`crypto/tls/handshake_server.go`,
    /// where a comment says to "let http/1.1 clients connect to h2 servers
    /// as if they didn't support ALPN"), where rustls would refuse it.
    /// The copy is made for that connection alone, so the set holds one
    /// configuration for each choice it makes otherwise.
    pub(crate) fn for_hello(&self, hello: &HelloFacts) -> Arc<ServerConfig> {
        let by_group = if go_aes_gcm_preferred(self.aes_gcm_hardware, &hello.cipher_suites) {
            &self.aes_gcm_first
        } else {
            &self.chacha_first
        };
        let config = if !hello.offers_tls13() {
            &by_group.any
        } else {
            let chosen = go_tls13_group(&hello.supported_groups, &hello.key_shares)
                .and_then(|index| by_group.only.get(index));
            chosen.unwrap_or(&by_group.any)
        };
        if self.alpn_h2 && go_alpn_http11_fallback(&config.alpn_protocols, &hello.alpn) {
            let mut without = ServerConfig::clone(config);
            without.alpn_protocols = Vec::new();
            return Arc::new(without);
        }
        Arc::clone(config)
    }

    /// The configuration Go's choices for `hello` leave rustls, the one
    /// [`handshake`] serves it, or the refusal Go makes of it before it
    /// chooses a suite or a curve ([`GoRefusal`]): a client that offers
    /// neither TLS 1.2 nor TLS 1.3 ([`HelloFacts::go_version_refusal`]); a
    /// client that would negotiate TLS 1.2 and shares no protocol with
    /// `NextProtos`, or that would negotiate TLS 1.2 with a key Go serves
    /// in TLS 1.3 alone, an ML-DSA key, each with the refusals Go makes
    /// ahead of it, in Go's order.  For a caller that drives rustls
    /// itself, which then also asks [`GoServerConfigs::after_handshake`]
    /// about the completed handshake.  A caller that reads the ClientHello
    /// through rustls's `Acceptor` asks this also when `accept` refuses
    /// one with `PeerIncompatible`, as [`handshake`] does: rustls refuses a
    /// ClientHello without signature_algorithms, which no TLS 1.0 or 1.1
    /// client sends, before it looks at the versions, where Go refuses the
    /// versions first.
    pub fn choose(&self, hello: &HelloFacts) -> Result<Arc<ServerConfig>, GoRefusal> {
        if let Some(refusal) = self.go_refusal(hello) {
            return Err(refusal);
        }
        Ok(self.for_hello(hello))
    }

    /// Go's refusal of `hello` before it chooses a suite or a curve, in
    /// Go's order: [`HelloFacts::go_version_refusal`], in
    /// `readClientHello`, and then [`HelloFacts::go_tls12_refusal`] for
    /// this set's key and protocols, in `processClientHello`.
    fn go_refusal(&self, hello: &HelloFacts) -> Option<GoRefusal> {
        hello.go_version_refusal().or_else(|| {
            hello
                .go_tls12_refusal(self.tls13_only, &self.next_protos)
                .map(|(alert, text)| GoRefusal {
                    alert,
                    text,
                    record_version: 0x0303,
                })
        })
    }

    /// What grpc-go's `ServerHandshake` makes of a handshake crypto/tls
    /// completed (`credentials/tls.go:168-185`, grpc-go v1.83.2, the
    /// version dcrwallet requires at its pin): for a set built with
    /// [`GoServerOptions::grpc`], a connection that negotiated no
    /// application protocol is closed with grpc-go's error, its default
    /// `GRPC_ENFORCE_ALPN_ENABLED` in force; every other connection, and
    /// every connection of a set built without it, is kept.  [`handshake`]
    /// asks this itself, sending close_notify before it gives the error,
    /// as the `tls.Conn.Close` grpc-go calls does.  A client reaches this
    /// by sending no ALPN extension, or by offering `http/1.1` and no
    /// protocol of the server's, which Go serves without ALPN.
    pub fn after_handshake(&self, conn: &rustls::ServerConnection) -> Result<(), &'static str> {
        if self.grpc_alpn_required && conn.alpn_protocol().is_none() {
            return Err(GRPC_MISSING_ALPN);
        }
        Ok(())
    }

    /// Every configuration in the set.
    pub fn configs(&self) -> impl Iterator<Item = &Arc<ServerConfig>> {
        [&self.aes_gcm_first, &self.chacha_first]
            .into_iter()
            .flat_map(|by_group| std::iter::once(&by_group.any).chain(&by_group.only))
    }
}

/// What a ClientHello offers, read from its raw records: the fields
/// Go's server negotiates on, among them those rustls's `ClientHello`
/// does not expose, the key shares, the offered versions and the two
/// extensions Go checks before it refuses an ML-DSA key in TLS 1.2.
///
/// [`handshake`] reads it itself.  A caller that drives rustls over
/// another transport, an async one through rustls's `Acceptor` say, records
/// the connection's opening bytes as they go to rustls, reads them with
/// [`HelloFacts::parse`] once rustls has the ClientHello, and asks
/// [`GoServerConfigs::choose`] for the configuration.
#[derive(Debug, Default, PartialEq)]
pub struct HelloFacts {
    /// `legacy_version`.
    legacy_version: u16,
    /// The cipher suites, in the client's order.
    cipher_suites: Vec<u16>,
    /// The `renegotiation_info` extension's `renegotiated_connection`,
    /// empty when the extension is absent, as Go's
    /// `clientHelloMsg.secureRenegotiation` is.
    renegotiation: Vec<u8>,
    /// The `ec_point_formats` extension's formats, empty when it is
    /// absent.
    point_formats: Vec<u8>,
    /// The `supported_versions` extension, when present.
    supported_versions: Option<Vec<u16>>,
    /// The `supported_groups` extension, in the client's order.
    supported_groups: Vec<u16>,
    /// The group of each `key_share` entry, in the client's order.
    key_shares: Vec<u16>,
    /// The `application_layer_protocol_negotiation` extension's protocols,
    /// in the client's order, empty when it is absent or malformed (rustls
    /// refuses a malformed one itself).
    alpn: Vec<Vec<u8>>,
    /// Whether these facts are the few rustls's `ClientHello` exposes
    /// ([`HelloFacts::from_rustls`]), without `legacy_version` or
    /// `supported_versions`, so that the versions offered are unknown.
    versions_unknown: bool,
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
    pub fn parse(records: &[u8]) -> Option<HelloFacts> {
        let (message, _) = first_handshake_message(records)?;
        if message.first() != Some(&1) {
            return None;
        }
        let mut hello = HelloReader(message.get(4..)?);
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
                11 => facts.point_formats = data.vec8()?.to_vec(),
                43 => facts.supported_versions = Some(HelloReader::u16s(data.vec8()?)?),
                0xff01 => facts.renegotiation = data.vec8()?.to_vec(),
                // Read leniently: a malformed list leaves the facts as they
                // were before ALPN was read, and rustls refuses it.
                16 => facts.alpn = HelloFacts::alpn_list(&mut data).unwrap_or_default(),
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

    /// An ALPN extension's `ProtocolNameList` (RFC 7301 §3.1), `None` when
    /// it is malformed.
    fn alpn_list(data: &mut HelloReader<'_>) -> Option<Vec<Vec<u8>>> {
        let mut names = HelloReader(data.vec16()?);
        let mut alpn = Vec::new();
        while !names.0.is_empty() {
            alpn.push(names.vec8()?.to_vec());
        }
        Some(alpn)
    }

    /// The facts rustls's `ClientHello` exposes, for a ClientHello the raw
    /// records could not be read back for: the suites and groups, without
    /// the key shares or versions, so the TLS 1.2 choice is made, and the
    /// TLS 1.2 refusal of an ML-DSA key is left to rustls, which reports
    /// no suite in common.
    pub fn from_rustls(hello: &rustls::server::ClientHello<'_>) -> HelloFacts {
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
            alpn: hello
                .alpn()
                .map(|protocols| protocols.map(<[u8]>::to_vec).collect())
                .unwrap_or_default(),
            versions_unknown: true,
            ..HelloFacts::default()
        }
    }

    /// The refusal Go's server makes, first of all, of a client that
    /// offers no version it supports (`readClientHello`,
    /// `crypto/tls/handshake_server.go:178-194`): with dcrd's and
    /// dcrwallet's `MinVersion` of TLS 1.2 and no `MaxVersion`, a client
    /// whose offered versions hold neither TLS 1.2 nor TLS 1.3, which is
    /// every TLS 1.0 and TLS 1.1 client.  Go reads the offered versions
    /// from `supported_versions`, or without it as every version up to
    /// `legacy_version`, capped at TLS 1.2.  Go sends `protocol_version` in a record of version TLS
    /// 1.0, having negotiated none (`writeRecordLocked`,
    /// `crypto/tls/conn.go:1014-1023`), and its text lists the versions it
    /// read, `tls: client offered only unsupported versions: [302 301]`.
    /// `None` for facts without the versions ([`HelloFacts::from_rustls`]).
    ///
    /// Go makes it ahead of everything else it asks of the ClientHello,
    /// where rustls's `Acceptor` refuses a ClientHello without
    /// signature_algorithms as it reads it, before it looks at the
    /// versions; and a client that offers TLS 1.0 or 1.1 alone sends no
    /// signature_algorithms (Go's client sends it only from TLS 1.2,
    /// `crypto/tls/handshake_client.go:122-123`), so rustls alone would
    /// answer every such client with `handshake_failure` and its own text.
    pub fn go_version_refusal(&self) -> Option<GoRefusal> {
        if self.versions_unknown {
            return None;
        }
        let offered = self.go_client_versions();
        if offered
            .iter()
            .any(|&version| version == 0x0303 || version == 0x0304)
        {
            return None;
        }
        Some(GoRefusal {
            alert: 70,
            text: format!(
                "tls: client offered only unsupported versions: {}",
                go_hex_list(&offered)
            ),
            record_version: 0x0301,
        })
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

    /// The alert and the text Go's server refuses this client with in
    /// `processClientHello` (`crypto/tls/handshake_server.go:216-318`)
    /// before it chooses a suite or a curve, when the client offers TLS
    /// 1.2, which Go then negotiates, and not TLS 1.3, and the server
    /// either holds a key it serves in TLS 1.3 alone (`tls13_only`, an
    /// ML-DSA key) or shares no protocol with the client
    /// (`server_protocols`, Go's `NextProtos`); `None` otherwise.  Go
    /// refuses, in this order: a client without null compression
    /// (`:221-233`), which rustls refuses first as well, in
    /// `Acceptor::accept`, so it never reaches this; a non-empty
    /// `renegotiation_info` (`:253-256`); protocols that share none with
    /// the server's, but for Go's `http/1.1` exception (`negotiateALPN`,
    /// `:265-269`, `:336-363`); point formats that do not include the
    /// uncompressed one (`supportsECDHE`, `:287-291`, `:376-393`); and
    /// then the key (`:310-314`).  The certificate, which Go looks at
    /// after ALPN, refuses nothing for one configured certificate.  All of
    /// it comes before Go chooses a suite or a curve, so it is what a
    /// client with neither in common hears, where rustls would report the
    /// suite, having chosen it before ALPN; and before Go looks for
    /// signature_algorithms, which rustls requires as it reads the
    /// ClientHello, so [`handshake`] asks for this when rustls refuses a
    /// ClientHello for that.  A server with neither an ML-DSA key nor a
    /// protocol the client lacks leaves the rest to rustls, which refuses
    /// a renegotiation_info or point formats as it always has for the
    /// node.  In TLS 1.3 Go refuses ALPN after the suite, the group, any
    /// HelloRetryRequest and the client's key share
    /// (`handshake_server_tls13.go:179-264`), which is rustls's order too
    /// for a ClientHello rustls reads, so that is left to rustls (PARITY.md
    /// records how its alert differs on the wire).  rustls does not read
    /// a TLS 1.3 ClientHello without signature_algorithms: it refuses one
    /// as it reads it, with `handshake_failure` and its own words, where
    /// Go refuses the client's protocols first and otherwise sends
    /// `missing_extension`, `local error: tls: missing extension`, from
    /// `pickCertificate`, after ALPN (`:474-484`); this answers `None`
    /// for such a client and rustls's refusal stands, an open entry in
    /// PARITY.md.
    pub(crate) fn go_tls12_refusal(
        &self,
        tls13_only: bool,
        server_protocols: &[Vec<u8>],
    ) -> Option<(u8, String)> {
        if self.offers_tls13() || !self.go_client_versions().contains(&0x0303) {
            return None;
        }
        let alpn_refused = go_alpn_refusal(server_protocols, &self.alpn);
        if !tls13_only && alpn_refused.is_none() {
            return None;
        }
        if !self.renegotiation.is_empty() {
            return Some((
                40,
                "tls: initial handshake had non-empty renegotiation extension".to_string(),
            ));
        }
        if let Some(text) = alpn_refused {
            return Some((120, text));
        }
        Some(
            if !self.point_formats.is_empty() && !self.point_formats.contains(&0) {
                (
                    109,
                    "tls: client offered only incompatible point formats".to_string(),
                )
            } else {
                (80, TLS13_ONLY_KEY_REFUSED.to_string())
            },
        )
    }

    /// The versions Go reads the client as offering, for its refusal
    /// (`readClientHello`, `crypto/tls/handshake_server.go:179-195`): the
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

/// net/http's `tlsRecordHeaderLooksLikeHTTP` (`net/http/server.go:4300-4306`).
fn looks_like_http(header: &[u8; 5]) -> bool {
    matches!(header, b"GET /" | b"HEAD " | b"POST " | b"PUT /" | b"OPTIO")
}

/// A first record Go refuses on its header.
#[derive(Debug, PartialEq)]
enum FirstRecordRefusal {
    /// A plaintext HTTP request, which net/http answers with a 400 on the
    /// bare connection (`net/http/server.go:1996-2001`).
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
/// this thread is noticed (as the node's `read_exact_by_deadline` reads a
/// request).
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

/// Write everything rustls has queued, an alert included, telling
/// `checks` what went to the client.
fn flush_tls(
    conn: &mut rustls::ServerConnection,
    sock: &mut TcpStream,
    name: &GoConnName,
    checks: &mut GoRecordChecks,
) -> Result<(), String> {
    let mut queued = Vec::new();
    while conn.wants_write() {
        // Writing to a vector cannot fail.
        if conn.write_tls(&mut queued).is_err() {
            break;
        }
    }
    checks.server_sent(&queued);
    sock.write_all(&queued)
        .map_err(|e| name.io_error("write", &e))
}

/// A refusal Go's server makes before rustls sees the ClientHello through
/// to a configuration ([`GoServerConfigs::choose`]): the alert it sends,
/// the record version it sends it in, and the text its error prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoRefusal {
    /// The alert description, sent as a fatal alert.
    pub alert: u8,
    /// Go's error text, which net/http logs after
    /// `http: TLS handshake error from <addr>: `.
    pub text: String,
    /// The version of the record Go sends the alert in
    /// (`writeRecordLocked`, `crypto/tls/conn.go:1014-1023`): TLS 1.2 once
    /// Go has negotiated a version, TLS 1.0 for the refusal of the
    /// versions themselves, when it has negotiated none.
    pub record_version: u16,
}

impl GoRefusal {
    /// The alert record Go writes for it.
    pub fn record(&self) -> [u8; 7] {
        let [major, minor] = self.record_version.to_be_bytes();
        [0x15, major, minor, 0x00, 0x02, 0x02, self.alert]
    }
}

/// Send `sock` the alert record of `refusal` and give its text.
fn refuse(sock: &mut TcpStream, refusal: &GoRefusal) -> String {
    let _ = sock.write_all(&refusal.record());
    refusal.text.clone()
}

/// Run an accepted connection's TLS handshake to completion, as Go's
/// `conn.serve` does before it reads a request
/// (`net/http/server.go:1976-2007`), under `deadline`, reading the
/// socket in slices of at most `poll`.  A caller that shuts the socket
/// down from another thread at the deadline, as the node's watchdog does,
/// has the handshake end then with Go's timeout text.
///
/// The ClientHello is read through `rustls::server::Acceptor`, and only
/// then is `configs` asked for the configurations, which is where dcrd's
/// `GetConfigForClient` runs (`readClientHello`,
/// `crypto/tls/handshake_server.go:166-176`), so a client that never sends
/// one does not reach the certificate reload check.  It is asked once for
/// every ClientHello the handshake reads, whether rustls takes it or
/// refuses it as incompatible, for its compression methods, its versions
/// or a missing signature_algorithms, since Go calls `GetConfigForClient`
/// before any of those checks.
///
/// On failure the error is the text Go's error would print, the `%v` of
/// net/http's `http: TLS handshake error from %s: %v`.  The common
/// failures are rendered as Go renders them: an early close, the
/// deadline, a reset, a first record that is not TLS (with net/http's 400
/// for a plaintext HTTP request), an alert from the client, a client that
/// offers only TLS 1.0 or 1.1 ([`HelloFacts::go_version_refusal`]), an
/// ML-DSA key's refusal of a client that would negotiate TLS 1.2, a client
/// CertificateVerify under a scheme Go refuses or whose ECDSA or Ed25519
/// signature fails (`GoClientCertVerifier`), and the refusals Go and
/// rustls share; anything else carries rustls's own description of it.
///
/// After the ClientHello the client's bytes are read here and run through
/// [`GoRecordChecks`] before rustls is given them: a record in another
/// version than TLS 1.2's, or longer than Go reads, while Go would still
/// refuse it in the clear, and a second ClientHello Go's TLS 1.3 server
/// refuses after a HelloRetryRequest, are refused with Go's alert and
/// text, rustls having processed the records before it.  rustls processes
/// what each `read_tls` gave it before it is given more, as when it read
/// the socket itself, so a client certificate message is read whole up
/// to rustls's own limit: 64 KiB less one byte of wire data, record
/// headers and AEAD overhead included, so a little under that for the
/// message itself, and depending on how the client cuts its records.
pub fn handshake(
    mut sock: TcpStream,
    deadline: Instant,
    poll: Duration,
    configs: impl FnOnce() -> Arc<GoServerConfigs>,
) -> Result<rustls::StreamOwned<rustls::ServerConnection, TcpStream>, String> {
    let name = GoConnName::of(&sock);
    crate::clientcert::clear_client_refusal();
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
                // rustls refuses a ClientHello it finds incompatible as it
                // reads it, before it looks at the versions: one without
                // null compression, and one without signature_algorithms,
                // which no TLS 1.0 or 1.1 client sends.  Go refuses a
                // client offering neither TLS 1.2 nor 1.3 ahead of both, in
                // `readClientHello`; and it refuses a client that would
                // negotiate TLS 1.2 with a key it serves in TLS 1.3 alone,
                // in `processClientHello`, ahead of the check
                // `selectSignatureScheme` makes for signature_algorithms
                // (`crypto/tls/auth.go:273-281`), but behind the one for
                // null compression, which rustls makes first too.
                if let rustls::Error::PeerIncompatible(incompatible) = &err
                    && let Some(hello) = HelloFacts::parse(&tap.recorded)
                {
                    let configs = configs();
                    let refusal = match incompatible {
                        rustls::PeerIncompatible::SignatureAlgorithmsExtensionRequired => {
                            configs.go_refusal(&hello)
                        }
                        _ => hello.go_version_refusal(),
                    };
                    if let Some(refusal) = refusal {
                        return Err(refuse(&mut sock, &refusal));
                    }
                }
                let _ = alert.write_all(&mut sock);
                return Err(go_error_text(&err, None));
            }
        }
    };
    tap.recording_done = true;
    let hello = HelloFacts::parse(&tap.recorded)
        .unwrap_or_else(|| HelloFacts::from_rustls(&accepted.client_hello()));
    // Go's checks on the records after the ClientHello need every byte
    // after it, so they are off when the opening bytes were cut short.
    let mut checks = if tap.recorded.len() < MAX_RECORDED_HELLO {
        GoRecordChecks::new(&tap.recorded)
    } else {
        GoRecordChecks::off()
    };
    tap.recorded = Vec::new();

    let configs = configs();
    if let Some(refusal) = configs.go_refusal(&hello) {
        return Err(refuse(&mut sock, &refusal));
    }
    let config = configs.for_hello(&hello);
    let mut conn = accepted
        .into_connection(config)
        .map_err(|(err, mut alert)| {
            let _ = alert.write_all(&mut sock);
            go_error_text(&err, Some(&hello))
        })?;
    // The client's bytes are read here and checked as Go's record layer
    // and TLS 1.3 server check them before rustls is given them
    // (`GoRecordChecks`), so that rustls never processes a record Go
    // refuses, and does process those before it, as Go does.
    let mut chunk = vec![0u8; READ_CHUNK];
    loop {
        flush_tls(&mut conn, &mut sock, &name, &mut checks)?;
        if !conn.is_handshaking() {
            break;
        }
        let mut read = Vec::new();
        read_by_deadline(&mut sock, &mut tap, &name, deadline, poll, |rd| {
            let n = rd.read(&mut chunk)?;
            read.extend_from_slice(chunk.get(..n).unwrap_or_default());
            Ok(n)
        })?;
        let refused = checks.client_sent(&read);
        let upto = refused.as_ref().map_or(read.len(), |(at, _)| *at);
        let mut given = read.get(..upto).unwrap_or_default();
        while !given.is_empty() {
            // rustls takes what it has room for, and refuses to buffer
            // more than a handshake message's worth, which Go has no
            // counterpart for.  The room grows past one record's only
            // once rustls has processed the record that starts a
            // handshake message longer than it, so the records are
            // processed after every read, as they were when rustls read
            // the socket itself; a slice given whole before processing
            // would fill a buffer still one record long, and a client
            // certificate message of some 16 KiB would be refused before
            // its certificates were looked at.
            match conn.read_tls(&mut given) {
                Ok(0) => return Err("rustls took none of the handshake bytes".to_string()),
                Ok(_) => {}
                Err(err) => return Err(err.to_string()),
            }
            if let Err(err) = conn.process_new_packets() {
                // rustls queues the alert Go would send for most refusals.
                let _ = flush_tls(&mut conn, &mut sock, &name, &mut checks);
                // A client's handshake signature that failed was noted in
                // Go's words by the verifier, rustls's error lacking the
                // key they name.
                return Err(crate::clientcert::take_client_refusal(&err)
                    .unwrap_or_else(|| go_error_text(&err, Some(&hello))));
            }
        }
        if let Some((_, refusal)) = refused {
            return Err(refuse(&mut sock, &refusal));
        }
    }
    if let Err(text) = configs.after_handshake(&conn) {
        conn.send_close_notify();
        let _ = flush_tls(&mut conn, &mut sock, &name, &mut checks);
        return Err(text.to_string());
    }
    Ok(rustls::StreamOwned::new(conn, sock))
}

/// The most read from the socket at once during the handshake, rustls's
/// own read size (`READ_SIZE`, `rustls-0.23.46/src/msgs/deframer/buffers.rs:220`).
/// rustls may take less of it than that: its buffer holds one record
/// (`MAX_WIRE_SIZE`) until the records it has processed start a longer
/// handshake message, and 64 KiB less one byte then (`:218-236`), so
/// [`handshake`] processes what rustls took before it gives it the rest.
const READ_CHUNK: usize = 4096;

/// The error grpc-go v1.83.2's `ServerHandshake` returns for a completed
/// handshake that negotiated no application protocol, which it closes
/// (`credentials/tls.go:35`, `:176-182`), word for word.
pub const GRPC_MISSING_ALPN: &str = "credentials: cannot check peer: missing selected ALPN \
     property. If you upgraded from a grpc-go version earlier than 1.67, your TLS connections \
     may have stopped working due to ALPN enforcement. For more details, see: \
     https://github.com/grpc/grpc-go/issues/434";

/// Go's text for a client that negotiates TLS 1.2 with a server whose key
/// is ML-DSA (`crypto/tls/handshake_server.go:310-314`), always TLS 1.2,
/// since dcrd's and dcrwallet's `MinVersion` is TLS 1.2.
const TLS13_ONLY_KEY_REFUSED: &str =
    "tls: ML-DSA certificates require TLS 1.3, but client negotiated TLS 1.2";

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
pub fn go_error_text(err: &rustls::Error, hello: Option<&HelloFacts>) -> String {
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
        // `negotiateALPN` (`crypto/tls/handshake_server.go:362`), the
        // client's protocols as Go's `%q` prints a `[]string`.
        Error::NoApplicationProtocol => {
            go_alpn_refusal_text(hello.map(|hello| hello.alpn.as_slice()).unwrap_or_default())
        }
        // A TLS 1.2 client whose certificate has an ML-DSA key, which the
        // client certificate verifier refuses as Go refuses it
        // (`handshake_server.go:1005-1012`).
        Error::PeerMisbehaved(misbehaved)
            if *misbehaved == crate::clientcert::ML_DSA_CLIENT_KEY_IN_TLS12 =>
        {
            "tls: client certificate uses ML-DSA, which requires TLS 1.3".to_string()
        }
        // A client CertificateVerify under a scheme the listener's list
        // lacks, or in TLS 1.3 one that does not fit the leaf's key
        // (`handshake_server.go:779-782`, `handshake_server_tls13.go:1086-1092`).
        Error::PeerMisbehaved(misbehaved)
            if *misbehaved == crate::clientcert::CLIENT_SCHEME_REFUSED =>
        {
            "tls: client certificate used with invalid signature algorithm".to_string()
        }
        Error::InvalidCertificate(CertificateError::UnknownIssuer) => {
            "tls: failed to verify certificate: x509: certificate signed by unknown authority"
                .to_string()
        }
        // Every chain the search completed failed Go's policy
        // validation, or that and Go's key usage rule, or held a key Go
        // distrusts, or Go's search ended at
        // an intermediate that may not sign (`GoClientCertVerifier`).
        Error::InvalidCertificate(CertificateError::Other(other))
            if other
                .0
                .downcast_ref::<crate::clientcert::InvalidPolicies>()
                .is_some()
                || other
                    .0
                    .downcast_ref::<crate::clientcert::DroppedChains>()
                    .is_some()
                || other
                    .0
                    .downcast_ref::<crate::clientcert::NoValidChains>()
                    .is_some()
                || other
                    .0
                    .downcast_ref::<crate::clientcert::NotAuthorizedToSign>()
                    .is_some() =>
        {
            format!("tls: failed to verify certificate: {}", other.0)
        }
        // A certificate on a chain Go's search built, or a pooled one,
        // whose extended key usage leaves out client authentication: Go's
        // `IncompatibleUsage` (`crypto/x509/verify.go:653-662`).  rustls
        // sends `unsupported_certificate` for it, where Go sends
        // `bad_certificate`.
        Error::InvalidCertificate(
            CertificateError::InvalidPurpose | CertificateError::InvalidPurposeContext { .. },
        ) => "tls: failed to verify certificate: x509: certificate specifies an incompatible key \
              usage"
            .to_string(),
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

/// Go's `negotiateALPN` refusal (`crypto/tls/handshake_server.go:336-363`):
/// the text Go refuses a client with whose protocols, `client`, share none
/// with the server's, `server`, and that the `http/1.1` exception does not
/// serve; `None` when Go negotiates a protocol or none.  A server or a
/// client with no protocols negotiates none.
fn go_alpn_refusal(server: &[Vec<u8>], client: &[Vec<u8>]) -> Option<String> {
    let refused = !server.is_empty()
        && !client.is_empty()
        && !server.iter().any(|proto| client.contains(proto))
        && !go_alpn_http11_fallback(server, client);
    refused.then(|| go_alpn_refusal_text(client))
}

/// Go's text for an ALPN refusal, the client's protocols printed with
/// `%q` (`handshake_server.go:362`): `["spdy/3" "h3"]`.
fn go_alpn_refusal_text(client: &[Vec<u8>]) -> String {
    let quoted: Vec<String> = client.iter().map(|proto| go_quote(proto)).collect();
    format!(
        "tls: client requested unsupported application protocols ([{}])",
        quoted.join(" ")
    )
}

/// Go's `strconv.Quote` of a string holding `bytes`
/// (`strconv/quote.go`): double quotes; `"` and `\` escaped; a byte that
/// is not part of valid UTF-8 as `\xNN`; `\a`, `\b`, `\f`, `\n`, `\r`,
/// `\t` and `\v` for those controls, `\xNN` for the other ASCII ones and
/// DEL; printable ASCII as it is.  A character above ASCII is kept unless
/// it is a control, white space, a private-use character or a
/// noncharacter, which is written `\uNNNN` or `\UNNNNNNNN`; Go keeps
/// exactly those `unicode.IsPrint` accepts, a set that differs from this
/// one for format characters and unassigned code points, which Go escapes
/// and this keeps, since the Unicode tables that would tell them apart
/// are not in the build.  No ALPN protocol in use holds either (not
/// compared with Go).
fn go_quote(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::from("\"");
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\u{7}' => out.push_str("\\a"),
                '\u{8}' => out.push_str("\\b"),
                '\u{c}' => out.push_str("\\f"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\u{b}' => out.push_str("\\v"),
                ' '..='~' => out.push(c),
                c if c.is_ascii() => {
                    let _ = write!(out, "\\x{:02x}", u32::from(c));
                }
                c if c.is_control() || c.is_whitespace() || go_unprintable_range(c) => {
                    let code = u32::from(c);
                    let _ = if code < 0x10000 {
                        write!(out, "\\u{code:04x}")
                    } else {
                        write!(out, "\\U{code:08x}")
                    };
                }
                c => out.push(c),
            }
        }
        for byte in chunk.invalid() {
            let _ = write!(out, "\\x{byte:02x}");
        }
    }
    out.push('"');
    out
}

/// Whether `c` is a private-use character or a noncharacter, which Go's
/// `unicode.IsPrint` refuses (categories Co and Cn).
fn go_unprintable_range(c: char) -> bool {
    let code = u32::from(c);
    matches!(code, 0xe000..=0xf8ff | 0xf_0000..=0x10_ffff | 0xfdd0..=0xfdef)
        || code & 0xfffe == 0xfffe
}

/// Go's `negotiateALPN` exception (`crypto/tls/handshake_server.go`):
/// a server offering `h2` serves a client that offers `http/1.1` and
/// none of the server's protocols as though it had sent no ALPN
/// extension.  `server` is the configuration's `alpn_protocols`, `client`
/// the ClientHello's.
fn go_alpn_http11_fallback(server: &[Vec<u8>], client: &[Vec<u8>]) -> bool {
    !client.is_empty()
        && !server.iter().any(|proto| client.contains(proto))
        && server.iter().any(|proto| proto.as_slice() == b"h2")
        && client.iter().any(|proto| proto.as_slice() == b"http/1.1")
}

/// How Go's server asks for a client certificate (`tls.ClientAuthType`):
/// the two settings dcrd and dcrwallet use.
#[derive(Debug, Clone)]
pub enum ClientAuth {
    /// `tls.NoClientCert`, Go's default: no certificate is asked for.
    /// dcrd under every `--authtype` but `clientcert`, and dcrwallet's
    /// JSON-RPC listener under `--jsonrpcauthtype=basic`, where its
    /// `ClientCAs` pool is set but never consulted.
    NoClientCert,
    /// `tls.RequireAndVerifyClientCert` over the verifier's pool: dcrd
    /// under `--authtype=clientcert`, dcrwallet's gRPC listener always
    /// and its JSON-RPC listener under `--jsonrpcauthtype=clientcert`.
    RequireAndVerifyClientCert(Arc<GoClientCertVerifier>),
}

/// The settings of a Go server's `tls.Config` beyond its certificate in
/// which dcrd's and dcrwallet's listeners differ, and whether grpc-go's
/// credentials stand between the configuration and the listener.  Both
/// programs set `MinVersion` to `tls.VersionTLS12` and leave the maximum,
/// the curves and the suites at Go's defaults, which
/// [`GoServerConfigs::new`] always takes; the crate documentation says
/// what dcrwallet's `--issueclientcert` and client CA file come to here.
/// [`GoServerOptions::dcrwallet_jsonrpc`] and
/// [`GoServerOptions::dcrwallet_grpc`] are dcrwallet's two listeners.
#[derive(Debug, Clone)]
pub struct GoServerOptions {
    /// `ClientAuth` with `ClientCAs`.
    pub client_auth: ClientAuth,
    /// `NextProtos`, the ALPN protocols in the server's order: empty for
    /// dcrd and for both of dcrwallet's listeners, whose `tls.Config`
    /// sets none; [`GoServerOptions::grpc`] adds the `h2` grpc-go adds.
    pub next_protos: Vec<Vec<u8>>,
    /// Whether the configuration is served as grpc-go v1.83.2 serves the
    /// `tls.Config` given to `credentials.NewTLS`, as dcrwallet's gRPC
    /// listener does (`rpcserver.go:322-330`): `h2` appended to
    /// `next_protos` unless it is there already (`applyDefaults`,
    /// `credentials/tls.go:236-240`), and a completed handshake that
    /// negotiated no protocol closed with grpc-go's error
    /// (`ServerHandshake`, `:168-185`; [`GoServerConfigs::after_handshake`]).
    /// `applyDefaults` also sets `MinVersion` to TLS 1.2, which dcrwallet
    /// sets already, and, since dcrwallet names no suites, the suites to
    /// `tls.CipherSuites()` less those HTTP/2 forbids, which leaves Go's
    /// six TLS 1.2 ECDHE suites with AES-GCM or ChaCha20-Poly1305, in Go's
    /// order still: exactly the TLS 1.2 suites the set offers anyway,
    /// since rustls has none of the ECDHE CBC suites it drops, so nothing
    /// here changes for those two.
    pub grpc: bool,
}

impl Default for GoServerOptions {
    /// No client certificate, no ALPN and no grpc-go: dcrd's listener
    /// outside `--authtype=clientcert`.
    fn default() -> GoServerOptions {
        GoServerOptions {
            client_auth: ClientAuth::NoClientCert,
            next_protos: Vec::new(),
            grpc: false,
        }
    }
}

impl GoServerOptions {
    /// dcrwallet's JSON-RPC listener (`startRPCServers`,
    /// `rpcserver.go:272-313`, at the wallet's pin): its `tls.Config`
    /// served by `tls.Listen` with no ALPN, asking for no certificate
    /// unless `--jsonrpcauthtype=clientcert` (`client_cert_auth`), and
    /// then requiring one that verifies to `client_cas`, the pool the gRPC
    /// listener shares (its `--clientcafile` and `--issueclientcert`
    /// authority; [`ClientCaPool`](crate::ClientCaPool)).  Under basic
    /// authentication dcrwallet sets the pool all the same and Go never
    /// consults it.  dcrwallet starts the listener under clientcert only
    /// when the file exists or `--issueclientcert` is given
    /// (`:350-355`); that choice, and the warnings, are the wallet's.
    pub fn dcrwallet_jsonrpc(
        client_cas: &Arc<GoClientCertVerifier>,
        client_cert_auth: bool,
    ) -> GoServerOptions {
        GoServerOptions {
            client_auth: if client_cert_auth {
                ClientAuth::RequireAndVerifyClientCert(Arc::clone(client_cas))
            } else {
                ClientAuth::NoClientCert
            },
            next_protos: Vec::new(),
            grpc: false,
        }
    }

    /// dcrwallet's gRPC listener (`rpcserver.go:315-330`): a clone of the
    /// JSON-RPC listener's `tls.Config` with `RequireAndVerifyClientCert`
    /// over `client_cas`, empty or not, passed to grpc-go's
    /// `credentials.NewTLS` ([`GoServerOptions::grpc`]).  dcrwallet starts
    /// it only when its client CA file exists or `--issueclientcert` is
    /// given; that choice is the wallet's.
    pub fn dcrwallet_grpc(client_cas: &Arc<GoClientCertVerifier>) -> GoServerOptions {
        GoServerOptions {
            client_auth: ClientAuth::RequireAndVerifyClientCert(Arc::clone(client_cas)),
            next_protos: Vec::new(),
            grpc: true,
        }
    }

    /// The protocols the configurations offer: `next_protos`, and under
    /// [`GoServerOptions::grpc`] `h2` after them unless they hold it
    /// (`AppendH2ToNextProtos`, grpc-go's
    /// `internal/credentials/util.go:28-37`).
    fn effective_next_protos(&self) -> Vec<Vec<u8>> {
        let mut protocols = self.next_protos.clone();
        if self.grpc && !protocols.iter().any(|proto| proto.as_slice() == b"h2") {
            protocols.push(b"h2".to_vec());
        }
        protocols
    }
}

/// A certificate chain and its key as Go's `tls.X509KeyPair` reads them
/// (`crypto/tls/tls.go`), loaded for signing by `dcroxide-tlscrypto`.
#[derive(Debug, Clone)]
pub struct KeyPair {
    /// The chain and its signing key, served to every client.
    resolver: Arc<dyn rustls::server::ResolvesServerCert>,
    /// Whether the key is one Go serves in TLS 1.3 alone, an ML-DSA key.
    tls13_only: bool,
}

/// Why [`KeyPair::from_pem`] refused a pair.
#[derive(Debug)]
pub enum KeyPairError {
    /// A PEM refusal of `tls.X509KeyPair`'s, in Go's words: no
    /// certificate block, or no key block ([`go_certificate_blocks`],
    /// [`go_key_block`]).
    Pem(String),
    /// The key is an RSA key, which Go serves and `dcroxide-tlscrypto`
    /// signs with none of (ADR-0015, T6).  The caller words the refusal,
    /// with what an operator of its program can do about it.
    RsaKey,
    /// The key does not parse by Go's `parsePrivateKey`, or the
    /// certificate's key is not its public half: the provider's or
    /// rustls's error.
    Key(rustls::Error),
}

impl std::fmt::Display for KeyPairError {
    /// Go's words for a PEM refusal; for an RSA key, a statement that the
    /// provider signs with none, which a program words for its own
    /// operators ([`KeyPairError::rpc_text`] is the node's); otherwise the
    /// provider's or rustls's error, which for a key Go's
    /// `parsePrivateKey` cannot read is Go's `tls: failed to parse private
    /// key: ` and the parser's error (PARITY.md, the RPC key file entry).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyPairError::Pem(text) => f.write_str(text),
            KeyPairError::RsaKey => f.write_str(
                "the key is an RSA key, and dcroxide signs TLS handshakes with ECDSA, Ed25519 \
                 and ML-DSA keys only",
            ),
            KeyPairError::Key(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for KeyPairError {}

impl KeyPairError {
    /// The text an RPC listener reports the refusal with, the node's:
    /// Go's own words for a PEM refusal, otherwise `unable to build the
    /// RPC TLS configuration: ` and `rsa_refused` for an RSA key or the
    /// error.
    pub fn rpc_text(&self, rsa_refused: &str) -> String {
        match self {
            KeyPairError::Pem(text) => text.clone(),
            KeyPairError::RsaKey => {
                format!("unable to build the RPC TLS configuration: {rsa_refused}")
            }
            KeyPairError::Key(err) => format!("unable to build the RPC TLS configuration: {err}"),
        }
    }
}

impl KeyPair {
    /// Read the pair as Go's `tls.X509KeyPair` reads it: the certificate
    /// chain by [`go_certificate_blocks`], the key block by
    /// [`go_key_block`] and its DER by Go's `parsePrivateKey`, through
    /// `dcroxide-tlscrypto`'s loader, which signs with ECDSA, Ed25519 and
    /// ML-DSA keys, and then the check that the leaf's key is the key's
    /// public half.  An RSA key, which dcrd and dcrwallet serve, is
    /// refused ([`KeyPairError::RsaKey`]).  An ML-DSA key is served in TLS
    /// 1.3 alone, as Go serves it ([`handshake`]).
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<KeyPair, KeyPairError> {
        let certs = go_certificate_blocks(cert_pem).map_err(KeyPairError::Pem)?;
        // The key's DER is parsed whatever the label, as Go's
        // `parsePrivateKey` does, so no `PrivateKeyDer` variant is chosen
        // and `load_der` takes it, not the `KeyProvider`.  `keys_match` is
        // the certificate-against-key check `CertifiedKey::from_der` makes
        // (`crypto/signer.rs:159-174`).
        let key_der = go_key_block(key_pem).map_err(KeyPairError::Pem)?;
        let key_algorithm = dcroxide_tlscrypto::sign::key_algorithm(&key_der);
        if key_algorithm == Some(dcroxide_tlscrypto::sign::KeyAlgorithm::Rsa) {
            return Err(KeyPairError::RsaKey);
        }
        let signing = dcroxide_tlscrypto::sign::load_der(&key_der).map_err(KeyPairError::Key)?;
        drop(key_der);
        let certified = rustls::sign::CertifiedKey::new(certs, signing);
        certified.keys_match().map_err(KeyPairError::Key)?;
        Ok(KeyPair {
            resolver: Arc::new(rustls::sign::SingleCertAndKey::from(certified)),
            tls13_only: key_algorithm.is_some_and(|algorithm| algorithm.tls13_only()),
        })
    }
}

/// Turn off stateful session resumption, which Go's server does not have
/// and rustls enables by default, and the TLS1.3 tickets that would have
/// keyed it.
fn disable_stateful_resumption(config: &mut rustls::ServerConfig) {
    // Go resumes only from tickets: TLS1.2's `checkForResumption` reads
    // `clientHello.sessionTicket` and nothing else
    // (`crypto/tls/handshake_server.go:450-465`), and the session id is
    // echoed rather than used as a key (`:565`). rustls instead looks the
    // client's session id up in `session_storage`
    // (`server/tls12.rs:146-160`) behind `can_resume`, which compares the
    // cipher suite, extended master secret and SNI and nothing else
    // (`server/hs.rs:39-58`) -- no expiry check on the stored client
    // certificate and no re-verification, while the chain is restored
    // verbatim (`server/tls12.rs:289`). The default cache is bounded by
    // count and not by time, so on a quiet server an entry can outlive
    // the certificate that created it.
    //
    // Under `--authtype=clientcert` that is the port admitting a client
    // dcrd would turn away. `NoServerSessionStorage` also makes rustls
    // send an empty session id (`server/tls12.rs:177-178`), which is what
    // a server that cannot resume statefully should offer.
    //
    // What this does NOT do is add the ticket resumption Go has: rustls's
    // default ticketer is `NeverProducesTickets`, so the port resumes not
    // at all where dcrd resumes from tickets. That leaves it stricter
    // rather than weaker, and installing a ticketer would trade the one
    // for the other, since rustls skips on a ticket resumption
    // (`server/tls13.rs:371-376`) the client-certificate checks Go
    // performs on BOTH its paths -- re-verification against the current
    // roots, an expiry check, and a seven day cap on the ticket's age
    // (`crypto/tls/handshake_server_tls13.go:362-381` and
    // `handshake_server.go:479-482`, `:508-526`). That matters most
    // under `--authtype=clientcert`, where no Basic credentials are set
    // and the completed handshake is itself the authentication. See
    // PARITY.
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    // With nowhere to store a ticket, rustls would still prepare
    // `send_tls13_tickets` of them (two by default,
    // `server/builder.rs:123`) after every TLS1.3 handshake whose client
    // offers `psk_dhe_ke`. A rustls client offers it whenever it offers
    // TLS1.3 (`client/hs.rs:321-327`). A Go client offers it only when its
    // `tls.Config` has a `ClientSessionCache`
    // (`crypto/tls/handshake_client.go:357-361`, `:369-373`), which dcrd's
    // `rpcclient` does not set (`infrastructure.go:1234-1237`,
    // `:1265-1267`, v8.1.0); for a client that offers none, rustls
    // prepares no ticket already (`server/tls13.rs:341-349`). Each ticket
    // draws a 32-byte nonce, a four-byte `age_add` and a 32-byte id from
    // the provider's random source and derives a resumption secret
    // (`server/tls13.rs:1328-1358`, called at `:1420-1422`), only for
    // `NoServerSessionStorage::put` to refuse it
    // (`server/handy.rs:13-15`) and nothing to be sent. A count of zero
    // skips that work and leaves the wire as it was. `max_tls13_tickets`
    // stays at its default of zero, so a client's `ticket_request`
    // cannot raise the count again (`server/tls13.rs:355-368`).
    config.send_tls13_tickets = 0;
}

#[cfg(test)]
// Test-harness arithmetic over fixed deadlines.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

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
        let mut provider = dcroxide_tlscrypto::default_provider();
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
        use dcroxide_tlscrypto::kx_group;
        for fragment in [16384, 64] {
            let both = client_hello(
                rustls::DEFAULT_VERSIONS,
                vec![kx_group::SECP521R1, kx_group::X25519],
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
                    std::sync::Arc::new(crate::clientcert::InvalidPolicies(2)),
                ))),
                Some(&tls13),
                "tls: failed to verify certificate: x509: no valid chains built: 2 candidate chains with invalid policies",
            ),
            (
                Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(
                    std::sync::Arc::new(crate::clientcert::NoValidChains),
                ))),
                Some(&tls13),
                "tls: failed to verify certificate: x509: no valid chains built",
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
        let (cert, key) = cert_pair();
        let configs = tls_server_config(&cert, &key, None).expect("the set");
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
            ..HelloFacts::default()
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

    /// What [`hand_hello`] writes into a ClientHello besides its suites,
    /// compression methods and groups: each extension where given.
    struct HelloExtras<'a> {
        /// `legacy_version`.
        legacy_version: u16,
        /// supported_versions.
        versions: Option<&'a [u16]>,
        /// signature_algorithms.
        signature_algorithms: Option<&'a [u16]>,
        /// ec_point_formats.
        points: Option<&'a [u8]>,
        /// renegotiation_info's content.
        renegotiation: Option<&'a [u8]>,
    }

    /// The extras of a TLS 1.2 client: supported_versions of TLS 1.2
    /// alone and signature_algorithms the key's schemes are not among,
    /// without point formats or renegotiation_info.
    const TLS12: HelloExtras<'static> = HelloExtras {
        legacy_version: 0x0303,
        versions: Some(&[0x0303]),
        signature_algorithms: Some(&[0x0403, 0x0804, 0x0807]),
        points: None,
        renegotiation: None,
    };

    /// A ClientHello record, written by hand so that each field Go checks
    /// before it refuses an ML-DSA key, or a client's versions, can be set:
    /// `suites`, the compression methods, `groups`, and the
    /// `legacy_version` and extensions in `extras`.
    fn hand_hello(
        suites: &[u16],
        compression: &[u8],
        groups: &[u16],
        extras: &HelloExtras<'_>,
    ) -> Vec<u8> {
        fn len8(bytes: &[u8]) -> Vec<u8> {
            [&[u8::try_from(bytes.len()).expect("short")][..], bytes].concat()
        }
        fn len16(bytes: &[u8]) -> Vec<u8> {
            let len = u16::try_from(bytes.len()).expect("short").to_be_bytes();
            [&len[..], bytes].concat()
        }
        fn u16s(values: &[u16]) -> Vec<u8> {
            values
                .iter()
                .flat_map(|value| value.to_be_bytes())
                .collect()
        }
        let extension =
            |kind: u16, data: Vec<u8>| [&kind.to_be_bytes()[..], &len16(&data)].concat();
        let mut extensions = Vec::new();
        if let Some(algorithms) = extras.signature_algorithms {
            extensions.push(extension(13, len16(&u16s(algorithms))));
        }
        extensions.push(extension(10, len16(&u16s(groups))));
        if let Some(versions) = extras.versions {
            extensions.push(extension(43, len8(&u16s(versions))));
        }
        if let Some(points) = extras.points {
            extensions.push(extension(11, len8(points)));
        }
        if let Some(renegotiation) = extras.renegotiation {
            extensions.push(extension(0xff01, len8(renegotiation)));
        }
        let body = [
            &extras.legacy_version.to_be_bytes()[..],
            &[0x5a; 32],
            &len8(&[]),
            &len16(&u16s(suites)),
            &len8(compression),
            &len16(&extensions.concat()),
        ]
        .concat();
        let len = u32::try_from(body.len()).expect("short").to_be_bytes();
        let message = [&[1][..], &len[1..], &body].concat();
        [&[22, 3, 1][..], &len16(&message)].concat()
    }

    /// What a client sending `hello` reads before the server closes,
    /// for at most ten seconds.
    fn answer_to(sock: &mut TcpStream, hello: &[u8]) -> Vec<u8> {
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        sock.write_all(hello).expect("send");
        let mut answer = Vec::new();
        let _ = sock.read_to_end(&mut answer);
        answer
    }

    /// A rustls client's verifier that offers `schemes` alone in its
    /// signature_algorithms and takes no server.
    #[derive(Debug)]
    struct OffersOnly(Vec<rustls::SignatureScheme>);

    impl rustls::client::danger::ServerCertVerifier for OffersOnly {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Err(rustls::Error::General("no server is taken".into()))
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::General("no server is taken".into()))
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::General("no server is taken".into()))
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.clone()
        }
    }

    /// How a TLS 1.3 rustls client offering `schemes` alone fares over
    /// `sock`: the error it ends with, which is the server's refusal.
    fn tls13_client_ends(sock: &mut TcpStream, schemes: &[rustls::SignatureScheme]) -> String {
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            dcroxide_tlscrypto::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(OffersOnly(schemes.to_vec())))
        .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
        let mut conn = rustls::ClientConnection::new(Arc::new(config), name).expect("client");
        loop {
            while conn.wants_write() {
                if let Err(e) = conn.write_tls(sock) {
                    return format!("write: {e}");
                }
            }
            match conn.read_tls(sock) {
                Ok(0) => return "EOF".to_owned(),
                Ok(_) => {}
                Err(e) => return format!("read: {e}"),
            }
            if let Err(e) = conn.process_new_packets() {
                return format!("{e:?}");
            }
        }
    }

    /// An ML-DSA `rpc.key` is refused as Go 1.27.3's server refuses it,
    /// alert and text, held to Go's `tls_listen` serving the same pair:
    /// to a client held to TLS 1.2 with `internal_error`, whether or not
    /// it shares a suite or a curve, since Go refuses before it chooses
    /// either, and whether or not it sends signature_algorithms or
    /// supported_versions; with the refusal Go makes first for a client
    /// without null compression, with a non-empty renegotiation_info or
    /// with only compressed point formats, in Go's order where it sends
    /// more than one; and to a TLS 1.3 client that offers none of the
    /// key's schemes, another ML-DSA set's among them (critique F8), with
    /// Go's text and the handshake_failure the client hears.
    #[test]
    fn an_ml_dsa_key_is_refused_as_go_refuses_it() {
        use dcroxide_testutil::tls_interop::{TlsOracle, spec};
        use rustls::SignatureScheme as S;
        let Some(mut go) = TlsOracle::start_ml_dsa() else {
            return;
        };
        let pki = go.pki(&[spec("server", "ML-DSA-65", None, "server")]);
        let server = &pki["server"];
        let configs = tls_server_config(&server.cert_pem, &server.key_pem, None)
            .expect("the listener serves an ML-DSA key");
        assert!(configs.tls13_only);
        let alert = |description: u8| vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, description];
        let ml_dsa = TLS13_ONLY_KEY_REFUSED;
        let compression = "tls: client does not support uncompressed connections";
        let renegotiated = "tls: initial handshake had non-empty renegotiation extension";
        let incompatible = "tls: client offered only incompatible point formats";
        let tls12 = |extras: HelloExtras<'_>| hand_hello(&[0xc02b], &[0], &[X25519_ID], &extras);
        let rows: Vec<(&str, Vec<u8>, Vec<u8>, &str)> = vec![
            (
                "a suite and a curve in common",
                tls12(HelloExtras {
                    points: Some(&[0]),
                    renegotiation: Some(&[]),
                    ..TLS12
                }),
                alert(80),
                ml_dsa,
            ),
            (
                "no suite in common",
                hand_hello(&[0x009c], &[0], &[X25519_ID], &TLS12),
                alert(80),
                ml_dsa,
            ),
            (
                "no curve in common",
                hand_hello(&[0xc02b], &[0], &[0x001e], &TLS12),
                alert(80),
                ml_dsa,
            ),
            (
                "no signature_algorithms",
                tls12(HelloExtras {
                    signature_algorithms: None,
                    ..TLS12
                }),
                alert(80),
                ml_dsa,
            ),
            (
                "no supported_versions",
                tls12(HelloExtras {
                    versions: None,
                    ..TLS12
                }),
                alert(80),
                ml_dsa,
            ),
            (
                "the uncompressed point format after a compressed one",
                tls12(HelloExtras {
                    points: Some(&[1, 0]),
                    ..TLS12
                }),
                alert(80),
                ml_dsa,
            ),
            (
                "no null compression",
                hand_hello(&[0xc02b], &[1], &[X25519_ID], &TLS12),
                alert(47),
                compression,
            ),
            (
                "no null compression and a non-empty renegotiation_info",
                hand_hello(
                    &[0xc02b],
                    &[1],
                    &[X25519_ID],
                    &HelloExtras {
                        renegotiation: Some(&[7; 12]),
                        ..TLS12
                    },
                ),
                alert(47),
                compression,
            ),
            (
                "a non-empty renegotiation_info",
                tls12(HelloExtras {
                    points: Some(&[0]),
                    renegotiation: Some(&[7; 12]),
                    ..TLS12
                }),
                alert(40),
                renegotiated,
            ),
            (
                "a non-empty renegotiation_info and compressed point formats alone",
                tls12(HelloExtras {
                    points: Some(&[1, 2]),
                    renegotiation: Some(&[7; 12]),
                    ..TLS12
                }),
                alert(40),
                renegotiated,
            ),
            (
                "compressed point formats alone",
                tls12(HelloExtras {
                    points: Some(&[1, 2]),
                    ..TLS12
                }),
                alert(109),
                incompatible,
            ),
        ];
        for (what, hello, want_alert, want_text) in rows {
            let (sock, mut client) = loopback();
            let configs = Arc::clone(&configs);
            let serving = std::thread::spawn(move || {
                handshake(
                    sock,
                    Instant::now() + Duration::from_secs(10),
                    Duration::from_millis(50),
                    || configs,
                )
                .map(|_| ())
            });
            let ours = answer_to(&mut client, &hello);
            let text = serving.join().expect("the handshake").expect_err(what);
            assert_eq!(
                (ours.as_slice(), text.as_str()),
                (&want_alert[..], want_text),
                "{what}"
            );

            let (addr, id) = go.listen(serde_json::json!({
                "chain": [dcroxide_testutil::hex(&server.cert)],
                "key_pkcs8": dcroxide_testutil::hex(&server.key_pkcs8),
            }));
            let mut sock = TcpStream::connect(&addr).expect("Go's server");
            let theirs = answer_to(&mut sock, &hello);
            let served = go.served(&id);
            assert_eq!(theirs, want_alert, "{what}: Go's alert");
            go.assert_refused(what, &served, want_text);
        }

        for (what, schemes) in [
            (
                "TLS 1.3 without ML-DSA",
                vec![S::ECDSA_NISTP256_SHA256, S::ED25519, S::RSA_PSS_SHA256],
            ),
            ("TLS 1.3 with ML-DSA-44 alone", vec![S::ML_DSA_44]),
            ("TLS 1.3 with ML-DSA-87 alone", vec![S::ML_DSA_87]),
        ] {
            let want = "tls: peer doesn't support any of the certificate's signature algorithms";
            let (sock, mut client) = loopback();
            let serving = {
                let configs = Arc::clone(&configs);
                std::thread::spawn(move || {
                    handshake(
                        sock,
                        Instant::now() + Duration::from_secs(10),
                        Duration::from_millis(50),
                        || configs,
                    )
                    .map(|_| ())
                })
            };
            let ours = tls13_client_ends(&mut client, &schemes);
            drop(client);
            let text = serving.join().expect("the handshake").expect_err(what);
            assert_eq!(text, want, "{what}");

            let (addr, id) = go.listen(serde_json::json!({
                "chain": [dcroxide_testutil::hex(&server.cert)],
                "key_pkcs8": dcroxide_testutil::hex(&server.key_pkcs8),
            }));
            let mut sock = TcpStream::connect(&addr).expect("Go's server");
            let theirs = tls13_client_ends(&mut sock, &schemes);
            let served = go.served(&id);
            assert_eq!(ours, theirs, "{what}: what the client hears");
            assert_eq!(ours, "AlertReceived(HandshakeFailure)", "{what}");
            go.assert_refused(what, &served, want);
        }
        go.report("an_ml_dsa_key_is_refused_as_go_refuses_it");
    }

    /// The versions Go reads a ClientHello as offering, and its refusal of
    /// one that offers neither TLS 1.2 nor TLS 1.3, with its alert in a TLS
    /// 1.0 record; nothing for facts rustls gave, which hold no versions.
    #[test]
    fn a_client_without_tls12_or_tls13_is_refused_by_its_versions() {
        let facts = |legacy_version: u16, supported_versions: Option<Vec<u16>>| HelloFacts {
            legacy_version,
            supported_versions,
            cipher_suites: vec![0xc013],
            ..HelloFacts::default()
        };
        for (what, hello, want) in [
            ("TLS 1.1", facts(0x0302, None), Some("[302 301]")),
            ("TLS 1.0", facts(0x0301, None), Some("[301]")),
            ("SSL 3.0", facts(0x0300, None), Some("[]")),
            (
                "TLS 1.1 alone",
                facts(0x0303, Some(vec![0x0302])),
                Some("[302]"),
            ),
            ("TLS 1.2", facts(0x0303, None), None),
            ("TLS 1.2 alone", facts(0x0303, Some(vec![0x0303])), None),
            ("TLS 1.3 alone", facts(0x0303, Some(vec![0x0304])), None),
            ("a later legacy_version", facts(0x0305, None), None),
        ] {
            let refusal = hello.go_version_refusal();
            assert_eq!(
                refusal.as_ref().map(|refusal| refusal.text.as_str()),
                want.map(|versions| format!(
                    "tls: client offered only unsupported versions: {versions}"
                ))
                .as_deref(),
                "{what}"
            );
            if let Some(refusal) = refusal {
                assert_eq!(
                    refusal.record(),
                    [0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 70],
                    "{what}"
                );
            }
        }
        let unknown = HelloFacts {
            versions_unknown: true,
            ..HelloFacts::default()
        };
        assert_eq!(unknown.go_version_refusal(), None);
        let (cert, key) = cert_pair();
        let configs = tls_server_config(&cert, &key, None).expect("the set");
        let refusal = configs
            .choose(&facts(0x0302, None))
            .expect_err("a TLS 1.1 client");
        assert_eq!(refusal.alert, 70);
    }

    /// The configurations are asked for once for every connection whose
    /// ClientHello the handshake reads, which is where Go calls dcrd's
    /// `GetConfigForClient` (`readClientHello`,
    /// `crypto/tls/handshake_server.go:166-177`), before the version check
    /// and before `processClientHello`'s compression check: so for a
    /// ClientHello rustls refuses for its compression methods, for its
    /// versions, or for a missing signature_algorithms, as well as for one
    /// it takes; and never for a first record Go refuses on its header,
    /// or a connection that closes before its ClientHello is whole.  The
    /// node's callback is its certificate reload check, so this is when a
    /// client advances the reload clock.
    #[test]
    fn the_configurations_are_asked_for_once_a_client_hello_is_read() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (cert, key) = cert_pair();
        let configs = tls_server_config(&cert, &key, None).expect("the set");
        let suites = [0xc02b, 0x1301];
        let tls13 = HelloExtras {
            versions: Some(&[0x0304, 0x0303]),
            ..TLS12
        };
        let rows: Vec<(&str, Vec<u8>, usize)> = vec![
            (
                "compression methods without null",
                hand_hello(&suites, &[1], &[X25519_ID], &TLS12),
                1,
            ),
            (
                "compression methods null after another",
                hand_hello(&suites, &[1, 0], &[X25519_ID], &tls13),
                1,
            ),
            (
                "TLS 1.0 alone",
                hand_hello(
                    &suites,
                    &[0],
                    &[X25519_ID],
                    &HelloExtras {
                        legacy_version: 0x0301,
                        versions: None,
                        signature_algorithms: None,
                        ..TLS12
                    },
                ),
                1,
            ),
            (
                "no signature_algorithms",
                hand_hello(
                    &suites,
                    &[0],
                    &[X25519_ID],
                    &HelloExtras {
                        signature_algorithms: None,
                        ..TLS12
                    },
                ),
                1,
            ),
            (
                "TLS 1.2, taken",
                hand_hello(&suites, &[0], &[X25519_ID], &TLS12),
                1,
            ),
            ("SSLv2", vec![0x80, 0x2e, 0x01, 0x00, 0x02], 0),
            ("half a ClientHello", vec![22, 3, 1, 0, 9, 1], 0),
        ];
        for (what, hello, want) in rows {
            let calls = Arc::new(AtomicUsize::new(0));
            let (sock, mut client) = loopback();
            let serving = {
                let configs = Arc::clone(&configs);
                let calls = Arc::clone(&calls);
                std::thread::spawn(move || {
                    handshake(
                        sock,
                        Instant::now() + Duration::from_secs(10),
                        Duration::from_millis(50),
                        || {
                            calls.fetch_add(1, Ordering::SeqCst);
                            configs
                        },
                    )
                    .map(|_| ())
                })
            };
            client.write_all(&hello).expect("send");
            let _ = client.shutdown(std::net::Shutdown::Write);
            let mut answer = Vec::new();
            let _ = client.read_to_end(&mut answer);
            let _ = serving.join().expect("the handshake");
            assert_eq!(calls.load(Ordering::SeqCst), want, "{what}");
        }
    }

    /// A key exchange the server does not implement (x448), offered first
    /// with its key share, so that the server asks for X25519 in a
    /// HelloRetryRequest; never completed.
    #[derive(Debug)]
    struct UnservedX448;

    /// An [`UnservedX448`] share: 56 bytes the server never reads.
    struct UnservedX448Exchange([u8; 56]);

    impl SupportedKxGroup for UnservedX448 {
        fn start(&self) -> Result<Box<dyn rustls::crypto::ActiveKeyExchange>, rustls::Error> {
            Ok(Box::new(UnservedX448Exchange([9; 56])))
        }

        fn name(&self) -> rustls::NamedGroup {
            rustls::NamedGroup::X448
        }
    }

    impl rustls::crypto::ActiveKeyExchange for UnservedX448Exchange {
        fn complete(
            self: Box<Self>,
            _peer: &[u8],
        ) -> Result<rustls::crypto::SharedSecret, rustls::Error> {
            Err(rustls::Error::General("x448 is never negotiated".into()))
        }

        fn pub_key(&self) -> &[u8] {
            &self.0
        }

        fn group(&self) -> rustls::NamedGroup {
            rustls::NamedGroup::X448
        }
    }

    /// A client that keeps to the protocol through a HelloRetryRequest,
    /// rustls's, whose second ClientHello changes only its key share,
    /// completes the handshake through Go's checks of the second
    /// ClientHello (`GoRecordChecks`), in a TLS 1.2 record as rustls
    /// writes it, and in records cut to 64 bytes.
    #[test]
    fn a_client_keeping_to_the_protocol_completes_a_retry() {
        let (cert, key) = cert_pair();
        let configs = tls_server_config(&cert, &key, None).expect("the set");
        for fragment in [16384, 64] {
            let (sock, mut tcp) = loopback();
            let serving = {
                let configs = Arc::clone(&configs);
                std::thread::spawn(move || {
                    let mut tls = handshake(
                        sock,
                        Instant::now() + Duration::from_secs(10),
                        Duration::from_millis(50),
                        || configs,
                    )?;
                    let mut byte = [0u8; 1];
                    tls.read_exact(&mut byte).map_err(|e| e.to_string())?;
                    Ok::<u8, String>(byte[0])
                })
            };
            let mut provider = dcroxide_tlscrypto::default_provider();
            provider.kx_groups = vec![&UnservedX448, dcroxide_tlscrypto::kx_group::X25519];
            let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("TLS 1.3")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(TakesAny))
                .with_no_client_auth();
            config.max_fragment_size = Some(fragment);
            let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
            let mut conn = rustls::ClientConnection::new(Arc::new(config), name).expect("client");
            tcp.set_read_timeout(Some(Duration::from_secs(10)))
                .expect("timeout");
            let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
            tls.write_all(b"x").expect("the handshake and a byte");
            tls.flush().expect("flush");
            assert_eq!(
                serving.join().expect("the server"),
                Ok(b'x'),
                "fragment {fragment}"
            );
            assert_eq!(
                conn.negotiated_key_exchange_group()
                    .map(|group| group.name()),
                Some(rustls::NamedGroup::X25519),
                "fragment {fragment}"
            );
        }
    }

    /// A client verifier that takes any server.
    #[derive(Debug)]
    struct TakesAny;

    impl rustls::client::danger::ServerCertVerifier for TakesAny {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            dcroxide_tlscrypto::SUPPORTED_SIG_ALGS.supported_schemes()
        }
    }

    /// A client that offers TLS 1.0 or 1.1 alone is refused as Go 1.27's
    /// server refuses it, alert record and text, held to Go's `tls_listen`
    /// serving the same pair: first of all, with `protocol_version` in a
    /// TLS 1.0 record and `tls: client offered only unsupported versions`,
    /// whether or not it sends signature_algorithms, which a real TLS 1.0
    /// or 1.1 client does not send and without which rustls alone refuses
    /// the ClientHello with `handshake_failure`, and ahead of a missing
    /// null compression method, which rustls refuses first too.
    #[test]
    fn a_client_without_tls12_is_refused_as_go_refuses_it() {
        use dcroxide_testutil::tls_interop::{TlsOracle, spec};
        let Some(mut go) = TlsOracle::start() else {
            return;
        };
        let pki = go.pki(&[spec("server", "P-256", None, "server")]);
        let server = &pki["server"];
        let configs = tls_server_config(&server.cert_pem, &server.key_pem, None).expect("the set");
        let want_alert = [0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 70];
        // A TLS 1.0 or 1.1 client's offer, as Go's client makes it with
        // `MaxVersion` below TLS 1.2: no supported_versions and no
        // signature_algorithms.
        let old = |legacy_version: u16| HelloExtras {
            legacy_version,
            versions: None,
            signature_algorithms: None,
            points: Some(&[0]),
            renegotiation: Some(&[]),
        };
        let suites = [0xc009, 0xc013, 0xc00a, 0xc014, 0x002f, 0x0035];
        let groups = [X25519_ID, SECP256R1_ID];
        let rows: Vec<(&str, Vec<u8>, &str)> = vec![
            (
                "TLS 1.1",
                hand_hello(&suites, &[0], &groups, &old(0x0302)),
                "[302 301]",
            ),
            (
                "TLS 1.0",
                hand_hello(&suites, &[0], &groups, &old(0x0301)),
                "[301]",
            ),
            (
                "SSL 3.0",
                hand_hello(&suites, &[0], &groups, &old(0x0300)),
                "[]",
            ),
            (
                "TLS 1.1 with signature_algorithms",
                hand_hello(
                    &suites,
                    &[0],
                    &groups,
                    &HelloExtras {
                        signature_algorithms: Some(&[0x0403, 0x0804]),
                        ..old(0x0302)
                    },
                ),
                "[302 301]",
            ),
            (
                "supported_versions of TLS 1.1 alone",
                hand_hello(
                    &suites,
                    &[0],
                    &groups,
                    &HelloExtras {
                        legacy_version: 0x0303,
                        versions: Some(&[0x0302]),
                        ..old(0x0302)
                    },
                ),
                "[302]",
            ),
            (
                "TLS 1.1 without null compression",
                hand_hello(&suites, &[1], &groups, &old(0x0302)),
                "[302 301]",
            ),
        ];
        for (what, hello, versions) in rows {
            let want_text = format!("tls: client offered only unsupported versions: {versions}");
            let (sock, mut client) = loopback();
            let configs = Arc::clone(&configs);
            let serving = std::thread::spawn(move || {
                handshake(
                    sock,
                    Instant::now() + Duration::from_secs(10),
                    Duration::from_millis(50),
                    || configs,
                )
                .map(|_| ())
            });
            let ours = answer_to(&mut client, &hello);
            let text = serving.join().expect("the handshake").expect_err(what);
            assert_eq!(
                (ours.as_slice(), text.as_str()),
                (&want_alert[..], want_text.as_str()),
                "{what}"
            );

            let (addr, id) = go.listen(serde_json::json!({
                "chain": [dcroxide_testutil::hex(&server.cert)],
                "key_pkcs8": dcroxide_testutil::hex(&server.key_pkcs8),
            }));
            let mut sock = TcpStream::connect(&addr).expect("Go's server");
            let theirs = answer_to(&mut sock, &hello);
            let served = go.served(&id);
            assert_eq!(theirs, want_alert, "{what}: Go's alert");
            go.assert_refused(what, &served, &want_text);
        }
        go.report("a_client_without_tls12_is_refused_as_go_refuses_it");
    }

    /// The length of the DER element at the start of `der`, header and
    /// content, and where its content starts.
    fn der_extent(der: &[u8]) -> (usize, usize) {
        match der[1] {
            short @ 0..0x80 => (2 + usize::from(short), 2),
            long => {
                let count = usize::from(long & 0x7f);
                let len = der[2..2 + count]
                    .iter()
                    .fold(0, |len, &byte| len << 8 | usize::from(byte));
                (2 + count + len, 2 + count)
            }
        }
    }

    /// The elements inside the DER element `der`.
    fn der_children(der: &[u8]) -> Vec<&[u8]> {
        let (end, start) = der_extent(der);
        let mut rest = &der[start..end];
        let mut out = Vec::new();
        while !rest.is_empty() {
            let (element, after) = rest.split_at(der_extent(rest).0);
            out.push(element);
            rest = after;
        }
        out
    }

    /// A DER element of `tag` holding `content`.
    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let len = content.len();
        let header = match u8::try_from(len) {
            Ok(short @ 0..0x80) => vec![tag, short],
            _ => {
                let bytes = u32::try_from(len).expect("short").to_be_bytes();
                let skip = bytes.iter().take_while(|&&byte| byte == 0).count();
                let count = u8::try_from(4 - skip).expect("four bytes at most");
                [&[tag, 0x80 | count][..], &bytes[skip..]].concat()
            }
        };
        [&header[..], content].concat()
    }

    /// An ML-DSA `rpc.cert` whose key Go cannot parse, with parameters
    /// after its algorithm or a key a byte short, is refused at startup as
    /// a key that does not match its certificate, in rustls's words, where
    /// Go's `tls.X509KeyPair` refuses it with its parser's error, through
    /// the oracle's `x509_key_pair` (PARITY.md, the ML-DSA entry).  The
    /// certificate is the oracle's with the key's SubjectPublicKeyInfo
    /// changed; neither Go nor the listener checks its signature when it
    /// loads a pair.
    #[test]
    fn an_ml_dsa_certificate_go_cannot_parse_is_refused_as_a_mismatch() {
        use dcroxide_testutil::tls_interop::{TlsOracle, spec};
        let Some(mut go) = TlsOracle::start_ml_dsa() else {
            return;
        };
        let pki = go.pki(&[spec("server", "ML-DSA-65", None, "server")]);
        let server = &pki["server"];
        let certificate = der_children(&server.cert);
        let tbs = der_children(certificate[0]);
        // The version, serial, signature algorithm, issuer, validity and
        // subject come first.
        assert_eq!(tbs[0][0], 0xa0, "a version 3 certificate");
        let spki = der_children(tbs[6]);
        let algorithm = der_children(spki[0]);
        let bits = &spki[1][der_extent(spki[1]).1..];
        let with_spki = |spki: &[u8]| {
            let mut tbs = tbs.clone();
            tbs[6] = spki;
            let der = der(
                0x30,
                &[
                    &der(0x30, &tbs.concat())[..],
                    certificate[1],
                    certificate[2],
                ]
                .concat(),
            );
            String::from_utf8(certificate_pem(&der)).expect("pem")
        };
        let mismatch = "unable to build the RPC TLS configuration: keys may not be consistent: \
                        KeyMismatch";
        let rows = [
            (
                "the certificate as issued",
                with_spki(tbs[6]),
                None,
                "ok ML-DSA-65",
            ),
            (
                "NULL parameters",
                with_spki(&der(
                    0x30,
                    &[
                        &der(0x30, &[algorithm[0], &[0x05, 0x00]].concat())[..],
                        spki[1],
                    ]
                    .concat(),
                )),
                Some(mismatch),
                "refused: x509: ML-DSA key encoded with illegal parameters",
            ),
            (
                "a key a byte short",
                with_spki(&der(
                    0x30,
                    &[spki[0], &der(0x03, &bits[..bits.len() - 1])].concat(),
                )),
                Some(mismatch),
                "refused: mldsa: invalid public key length",
            ),
        ];
        for (what, cert_pem, want_ours, want_go) in rows {
            let ours = tls_server_config(cert_pem.as_bytes(), &server.key_pem, None).err();
            assert_eq!(ours.as_deref(), want_ours, "{what}");
            let answer = go.call(
                "x509_key_pair",
                &serde_json::json!({
                    "cert_pem": cert_pem,
                    "key_pem": String::from_utf8_lossy(&server.key_pem),
                }),
            );
            let answer = answer["result"].as_str().expect("x509_key_pair's verdict");
            if go.go_version() == dcroxide_testutil::REFERENCE_GO {
                assert_eq!(answer, want_go, "{what}: Go");
            } else {
                assert_eq!(
                    answer.starts_with("ok "),
                    want_go.starts_with("ok "),
                    "{what}: Go"
                );
            }
        }
    }

    /// The certgen environment of the tests: the clock, the kernel's
    /// random numbers, and a host named `localhost` with no interface
    /// addresses.
    struct TestCertEnv;

    impl dcroxide_certgen::CertEnv for TestCertEnv {
        fn now_unix(&mut self) -> i64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
                .unwrap_or(0)
        }

        fn ed25519_seed(&mut self) -> [u8; 32] {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).expect("random");
            seed
        }

        fn ec_private_scalar(&mut self, curve: dcroxide_certgen::Curve) -> Vec<u8> {
            let len = match curve {
                dcroxide_certgen::Curve::P256 => 32,
                dcroxide_certgen::Curve::P521 => 66,
            };
            let mut scalar = vec![0u8; len];
            getrandom::fill(&mut scalar).expect("random");
            scalar
        }

        fn serial_bytes(&mut self) -> Vec<u8> {
            let mut serial = vec![0u8; 16];
            getrandom::fill(&mut serial).expect("random");
            serial
        }

        fn hostname(&mut self) -> Result<String, String> {
            Ok("localhost".to_string())
        }

        fn interface_addrs(&mut self) -> Result<Vec<String>, String> {
            Ok(Vec::new())
        }
    }

    /// A P-256 pair as dcrd generates its `rpc.cert` and `rpc.key`, in
    /// PEM, as the node's `load_or_generate_cert_pair` writes them.
    pub(crate) fn cert_pair() -> (Vec<u8>, Vec<u8>) {
        let mut env = TestCertEnv;
        let valid_until = dcroxide_certgen::CertEnv::now_unix(&mut env) + 10 * 365 * 24 * 60 * 60;
        let pair = dcroxide_certgen::new_tls_cert_pair(
            &mut env,
            dcroxide_certgen::Curve::P256,
            "dcrd autogenerated cert",
            valid_until,
            &[],
        )
        .expect("a cert pair");
        (pair.cert, pair.key)
    }

    /// A DER certificate as a PEM block.
    fn certificate_pem(der: &[u8]) -> Vec<u8> {
        String::from_utf8(dcroxide_certgen::gentool::pem_private_key(der))
            .expect("pem")
            .replace("PRIVATE KEY", "CERTIFICATE")
            .into_bytes()
    }

    /// The node's `tls_server_config`: the set for a pair and, when given,
    /// a client CA file, with the node's texts for a refusal.
    pub(crate) fn tls_server_config(
        cert_pem: &[u8],
        key_pem: &[u8],
        client_cas_pem: Option<&[u8]>,
    ) -> Result<Arc<GoServerConfigs>, String> {
        let key_pair = KeyPair::from_pem(cert_pem, key_pem)
            .map_err(|e| e.rpc_text(dcroxide_tlscrypto::sign::RSA_KEY_REFUSED))?;
        let client_auth = match client_cas_pem {
            Some(cas_pem) => ClientAuth::RequireAndVerifyClientCert(Arc::new(
                GoClientCertVerifier::from_pem(cas_pem)?,
            )),
            None => ClientAuth::NoClientCert,
        };
        GoServerConfigs::new(
            &key_pair,
            &GoServerOptions {
                client_auth,
                ..GoServerOptions::default()
            },
        )
        .map(Arc::new)
        .map_err(|e| format!("unable to build the RPC TLS configuration: {e}"))
    }

    /// rpc.cert is read as `tls.X509KeyPair` reads it: every
    /// `CERTIFICATE` block Go's decoder finds, past malformed and
    /// other blocks, and Go's texts when there is none (review finding
    /// GAP06#3).
    #[test]
    fn the_rpc_certificate_skips_what_x509_key_pair_skips() {
        let (cert_pem, key_pem) = cert_pair();
        let cert = String::from_utf8(cert_pem).expect("pem");
        let junk = "-----BEGIN CERTIFICATE-----\nAQ!D\n-----END CERTIFICATE-----\n\
                    -----BEGIN CERTIFICATE-----\nAQID\n";
        tls_server_config(format!("{cert}{junk}").as_bytes(), &key_pem, None)
            .expect("a trailing malformed block is skipped");

        let err =
            |cert: &str| tls_server_config(cert.as_bytes(), &key_pem, None).expect_err("no cert");
        assert_eq!(
            err(""),
            "tls: failed to find any PEM data in certificate input"
        );
        assert_eq!(
            err(&String::from_utf8_lossy(&key_pem)),
            "tls: failed to find certificate PEM data in certificate input, but did find a \
             private key; PEM inputs may have been switched"
        );
        assert_eq!(
            err(
                "-----BEGIN A-----\nAQID\n-----END A-----\n-----BEGIN B-----\nAQID\n-----END B-----\n"
            ),
            "tls: failed to find \"CERTIFICATE\" PEM block in certificate input after skipping \
             PEM blocks of the following types: [A B]"
        );
    }

    /// A client's verifier that accepts any server certificate and
    /// handshake signature, for the tests about what a session does once
    /// it is up rather than how the server is authenticated.
    #[derive(Debug)]
    struct AnyCertificate;

    impl rustls::client::danger::ServerCertVerifier for AnyCertificate {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            dcroxide_tlscrypto::SUPPORTED_SIG_ALGS.supported_schemes()
        }
    }

    /// The RPC server prepares no TLS1.3 ticket: every configuration in
    /// the set has `send_tls13_tickets` at zero, and `max_tls13_tickets`
    /// at zero beside it, so no `ticket_request` raises the count.
    ///
    /// The wire is what it was at rustls's default of two, since the
    /// tickets `NoServerSessionStorage` refused were never sent. Against
    /// each configuration, in TLS1.3 and TLS1.2 and at either count, a
    /// handshake in memory completes, the server answers the client's
    /// Finished with the same number of bytes (none in TLS1.3; its own
    /// ChangeCipherSpec and Finished in TLS1.2), application data
    /// crosses both ways, and the client has received no ticket.
    #[test]
    fn the_rpc_server_prepares_no_tls13_tickets() {
        use rustls::pki_types::ServerName;

        /// Move every record `from` has to send into `to` and process
        /// them, returning how many bytes crossed.
        fn transfer<A, B>(
            from: &mut rustls::ConnectionCommon<A>,
            to: &mut rustls::ConnectionCommon<B>,
        ) -> usize {
            let mut wire = Vec::new();
            while from.wants_write() {
                from.write_tls(&mut wire).expect("write the records");
            }
            let mut rest = wire.as_slice();
            while !rest.is_empty() {
                to.read_tls(&mut rest).expect("read the records");
                to.process_new_packets().expect("process the records");
            }
            wire.len()
        }

        /// Run a handshake between fresh connections over the two
        /// configurations, send application data each way, and return
        /// the length of the server's answer to the client's Finished.
        fn answer_to_finished(
            server_config: &Arc<rustls::ServerConfig>,
            client_config: &Arc<rustls::ClientConfig>,
        ) -> usize {
            let name = ServerName::try_from("localhost").expect("server name");
            let mut client =
                rustls::ClientConnection::new(Arc::clone(client_config), name).expect("client");
            let mut server =
                rustls::ServerConnection::new(Arc::clone(server_config)).expect("server");
            // One round per client flight: two in a handshake, three
            // with a HelloRetryRequest.
            for _ in 0..3 {
                transfer(&mut client, &mut server);
                if !server.is_handshaking() {
                    break;
                }
                transfer(&mut server, &mut client);
            }
            assert!(
                !server.is_handshaking(),
                "the server has read the client's Finished"
            );
            let answer = transfer(&mut server, &mut client);
            assert!(!client.is_handshaking(), "the client has finished too");

            client
                .writer()
                .write_all(b"ping")
                .expect("the client writes");
            transfer(&mut client, &mut server);
            let mut ping = [0u8; 4];
            server
                .reader()
                .read_exact(&mut ping)
                .expect("the server reads");
            assert_eq!(&ping, b"ping");
            server
                .writer()
                .write_all(b"pong")
                .expect("the server writes");
            transfer(&mut server, &mut client);
            let mut pong = [0u8; 4];
            client
                .reader()
                .read_exact(&mut pong)
                .expect("the client reads");
            assert_eq!(&pong, b"pong");
            assert_eq!(client.tls13_tickets_received(), 0, "no ticket arrived");
            answer
        }

        let (cert, key) = cert_pair();
        let configs = tls_server_config(&cert, &key, None).expect("server config");
        // Every group the set offers, P-521 among them, so the client can
        // complete a handshake with each configuration.
        let provider = Arc::new(rustls::crypto::CryptoProvider {
            kx_groups: dcroxide_tlscrypto::ALL_KX_GROUPS.to_vec(),
            ..dcroxide_tlscrypto::default_provider()
        });

        for config in configs.configs() {
            assert_eq!(config.send_tls13_tickets, 0, "no ticket is prepared");
            assert_eq!(
                config.max_tls13_tickets, 0,
                "and no ticket_request asks for one"
            );
            let mut rustls_default = rustls::ServerConfig::clone(config);
            rustls_default.send_tls13_tickets = 2;
            let rustls_default = Arc::new(rustls_default);
            for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
                let client_config = Arc::new(
                    rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
                        .with_protocol_versions(&[version])
                        .expect("the version")
                        .dangerous()
                        .with_custom_certificate_verifier(Arc::new(AnyCertificate))
                        .with_no_client_auth(),
                );
                let answer = answer_to_finished(config, &client_config);
                assert_eq!(
                    answer,
                    answer_to_finished(&rustls_default, &client_config),
                    "{:?}: the same answer at rustls's default count",
                    version.version
                );
                assert_eq!(
                    answer == 0,
                    version.version == rustls::ProtocolVersion::TLSv1_3,
                    "{:?}: {answer} bytes after the client's Finished",
                    version.version
                );
            }
        }
    }

    /// Go's `negotiateALPN` exception, alone: only a client that offers
    /// `http/1.1` and nothing the server offers, to a server that offers
    /// `h2`, is served as though it had sent no ALPN extension.
    #[test]
    fn the_http11_exception_is_gos() {
        let protos = |names: &[&str]| -> Vec<Vec<u8>> {
            names.iter().map(|name| name.as_bytes().to_vec()).collect()
        };
        for (server, client, fallback) in [
            (&["h2"][..], &["http/1.1"][..], true),
            (&["h2"], &["http/1.0", "http/1.1"], true),
            (&["h2"], &["h2", "http/1.1"], false),
            (&["h2"], &[], false),
            (&["h2"], &["spdy/3"], false),
            (&["h3"], &["http/1.1"], false),
            (&[], &["http/1.1"], false),
            (&["h3", "h2"], &["http/1.1"], true),
            (&["h2", "http/1.1"], &["http/1.1"], false),
        ] {
            assert_eq!(
                go_alpn_http11_fallback(&protos(server), &protos(client)),
                fallback,
                "{server:?} {client:?}"
            );
        }
    }

    /// A server with `NextProtos` set, as dcrwallet's gRPC listener is
    /// with `h2`: every configuration in the set offers it, a client
    /// offering it negotiates it, a client offering none or only
    /// `http/1.1` completes without ALPN, as Go's `negotiateALPN` lets it,
    /// and a client offering only other protocols is refused with
    /// `no_application_protocol` and Go's text.  Without `NextProtos`, as
    /// dcrd's listener is, a client's ALPN is ignored.
    #[test]
    fn next_protos_negotiate_as_gos_alpn() {
        use rustls::pki_types::ServerName;
        let (cert, key) = cert_pair();
        let key_pair = KeyPair::from_pem(&cert, &key).expect("the pair");
        let h2 = Arc::new(
            GoServerConfigs::new(
                &key_pair,
                &GoServerOptions {
                    client_auth: ClientAuth::NoClientCert,
                    next_protos: vec![b"h2".to_vec()],
                    grpc: false,
                },
            )
            .expect("the set"),
        );
        assert!(
            h2.configs()
                .all(|config| config.alpn_protocols == [b"h2".to_vec()])
        );
        let none = Arc::new(
            GoServerConfigs::new(&key_pair, &GoServerOptions::default()).expect("the set"),
        );
        assert!(
            none.configs()
                .all(|config| config.alpn_protocols.is_empty())
        );

        let connect = |configs: &Arc<GoServerConfigs>,
                       version: &'static rustls::SupportedProtocolVersion,
                       alpn: &[&str]|
         -> (Result<Option<Vec<u8>>, String>, Option<rustls::Error>) {
            let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::CryptoProvider {
                    kx_groups: dcroxide_tlscrypto::ALL_KX_GROUPS.to_vec(),
                    ..dcroxide_tlscrypto::default_provider()
                },
            ))
            .with_protocol_versions(&[version])
            .expect("the version")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCertificate))
            .with_no_client_auth();
            client_config.alpn_protocols =
                alpn.iter().map(|proto| proto.as_bytes().to_vec()).collect();
            let (server_sock, client_sock) = loopback();
            let configs = Arc::clone(configs);
            let serving = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(10);
                handshake(server_sock, deadline, Duration::from_millis(50), || configs)
                    .map(|tls| tls.conn.alpn_protocol().map(<[u8]>::to_vec))
            });
            let name = ServerName::try_from("localhost").expect("server name");
            let mut client =
                rustls::ClientConnection::new(Arc::new(client_config), name).expect("the client");
            let mut sock = client_sock;
            let mut failed = None;
            while client.is_handshaking() {
                if let Err(err) = client.complete_io(&mut sock) {
                    failed = err
                        .into_inner()
                        .and_then(|inner| inner.downcast::<rustls::Error>().ok())
                        .map(|err| *err);
                    break;
                }
            }
            (serving.join().expect("the server thread"), failed)
        };

        for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
            let what = format!("{:?}", version.version);
            assert_eq!(
                connect(&h2, version, &["h2", "http/1.1"]).0,
                Ok(Some(b"h2".to_vec())),
                "{what}"
            );
            assert_eq!(connect(&h2, version, &[]).0, Ok(None), "{what}");
            assert_eq!(connect(&h2, version, &["http/1.1"]).0, Ok(None), "{what}");
            let (served, failed) = connect(&h2, version, &["spdy/3", "h3"]);
            assert_eq!(
                served,
                Err(
                    "tls: client requested unsupported application protocols ([\"spdy/3\" \"h3\"])"
                        .to_string()
                ),
                "{what}"
            );
            assert_eq!(
                failed,
                Some(rustls::Error::AlertReceived(
                    rustls::AlertDescription::NoApplicationProtocol
                )),
                "{what}"
            );
            assert_eq!(connect(&none, version, &["spdy/3"]).0, Ok(None), "{what}");
        }
    }

    /// A rustls client offering `alpn` in `version` against `configs`
    /// through [`handshake`]: the server's protocol or its error, and the
    /// client's error, if it failed.
    fn alpn_connect(
        configs: &Arc<GoServerConfigs>,
        version: &'static rustls::SupportedProtocolVersion,
        alpn: &[&str],
    ) -> (Result<Option<Vec<u8>>, String>, Option<rustls::Error>) {
        use rustls::pki_types::ServerName;
        let mut client_config =
            rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::CryptoProvider {
                kx_groups: dcroxide_tlscrypto::ALL_KX_GROUPS.to_vec(),
                ..dcroxide_tlscrypto::default_provider()
            }))
            .with_protocol_versions(&[version])
            .expect("the version")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCertificate))
            .with_no_client_auth();
        client_config.alpn_protocols = alpn.iter().map(|proto| proto.as_bytes().to_vec()).collect();
        let (server_sock, client_sock) = loopback();
        let configs = Arc::clone(configs);
        let serving = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            handshake(server_sock, deadline, Duration::from_millis(50), || configs)
                .map(|tls| tls.conn.alpn_protocol().map(<[u8]>::to_vec))
        });
        let name = ServerName::try_from("localhost").expect("server name");
        let mut client =
            rustls::ClientConnection::new(Arc::new(client_config), name).expect("the client");
        let mut sock = client_sock;
        let mut failed = None;
        while client.is_handshaking() {
            if let Err(err) = client.complete_io(&mut sock) {
                failed = err
                    .into_inner()
                    .and_then(|inner| inner.downcast::<rustls::Error>().ok())
                    .map(|err| *err);
                break;
            }
        }
        (serving.join().expect("the server thread"), failed)
    }

    /// dcrwallet's gRPC listener, grpc-go's credentials over its
    /// `tls.Config`: `h2` is offered, once, after any protocol set; a
    /// client that negotiates it is kept; a client that negotiates none,
    /// sending no ALPN extension or offering `http/1.1` alone, completes
    /// its handshake and is then closed with grpc-go's error; and a
    /// client sharing no protocol is refused as without grpc-go.  The
    /// JSON-RPC listener offers no protocol and keeps every client, with
    /// a certificate asked for under clientcert alone.
    #[test]
    fn the_grpc_listener_is_grpc_gos() {
        let (cert, key) = cert_pair();
        let key_pair = KeyPair::from_pem(&cert, &key).expect("the pair");
        let pool =
            Arc::new(GoClientCertVerifier::new(crate::ClientCaPool::new()).expect("an empty pool"));
        let options = GoServerOptions::dcrwallet_grpc(&pool);
        assert!(options.grpc && options.next_protos.is_empty());
        assert!(matches!(
            options.client_auth,
            ClientAuth::RequireAndVerifyClientCert(ref verifier) if Arc::ptr_eq(verifier, &pool)
        ));
        for (protocols, want) in [
            (&[][..], &["h2"][..]),
            (&["h2"], &["h2"]),
            (&["x", "h2"], &["x", "h2"]),
            (&["x"], &["x", "h2"]),
        ] {
            let options = GoServerOptions {
                next_protos: protocols.iter().map(|p| p.as_bytes().to_vec()).collect(),
                ..GoServerOptions::dcrwallet_grpc(&pool)
            };
            let want: Vec<Vec<u8>> = want.iter().map(|p| p.as_bytes().to_vec()).collect();
            assert_eq!(options.effective_next_protos(), want, "{protocols:?}");
        }
        for clientcert in [false, true] {
            let options = GoServerOptions::dcrwallet_jsonrpc(&pool, clientcert);
            assert!(!options.grpc && options.next_protos.is_empty());
            assert_eq!(
                matches!(
                    options.client_auth,
                    ClientAuth::RequireAndVerifyClientCert(_)
                ),
                clientcert
            );
        }

        // The handshakes, without a client certificate to ask for.
        let grpc = Arc::new(
            GoServerConfigs::new(
                &key_pair,
                &GoServerOptions {
                    client_auth: ClientAuth::NoClientCert,
                    ..GoServerOptions::dcrwallet_grpc(&pool)
                },
            )
            .expect("the set"),
        );
        assert!(
            grpc.configs()
                .all(|config| config.alpn_protocols == [b"h2".to_vec()])
        );
        for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
            let what = format!("{:?}", version.version);
            assert_eq!(
                alpn_connect(&grpc, version, &["h2"]),
                (Ok(Some(b"h2".to_vec())), None),
                "{what}"
            );
            for alpn in [&[][..], &["http/1.1"]] {
                let (served, failed) = alpn_connect(&grpc, version, alpn);
                assert_eq!(
                    served,
                    Err(GRPC_MISSING_ALPN.to_string()),
                    "{what} {alpn:?}"
                );
                assert_eq!(
                    failed, None,
                    "{what} {alpn:?}: the client's handshake completes"
                );
            }
            let (served, failed) = alpn_connect(&grpc, version, &["spdy/3"]);
            assert_eq!(
                served,
                Err(
                    "tls: client requested unsupported application protocols ([\"spdy/3\"])"
                        .to_string()
                ),
                "{what}"
            );
            assert_eq!(
                failed,
                Some(rustls::Error::AlertReceived(
                    rustls::AlertDescription::NoApplicationProtocol
                )),
                "{what}"
            );
        }
        let jsonrpc = Arc::new(
            GoServerConfigs::new(&key_pair, &GoServerOptions::dcrwallet_jsonrpc(&pool, false))
                .expect("the set"),
        );
        for alpn in [&[][..], &["h2"], &["spdy/3"]] {
            assert_eq!(
                alpn_connect(&jsonrpc, &rustls::version::TLS13, alpn),
                (Ok(None), None),
                "{alpn:?}"
            );
        }
    }

    /// A TLS 1.2 client is refused in Go's order: a renegotiation_info,
    /// then protocols sharing none with the server's, then, for an ML-DSA
    /// key alone, point formats and the key; a client Go serves by its
    /// `http/1.1` exception, or that sends no protocols, or a server that
    /// offers none, is no ALPN refusal; and a TLS 1.3 client is left to
    /// rustls, whose order is Go's there.
    #[test]
    fn tls12_refusals_follow_gos_order() {
        let protos = |names: &[&str]| -> Vec<Vec<u8>> {
            names.iter().map(|name| name.as_bytes().to_vec()).collect()
        };
        let h2 = protos(&["h2"]);
        let hello = |alpn: &[&str], renegotiation: bool, point_formats: &[u8]| HelloFacts {
            legacy_version: 0x0303,
            cipher_suites: vec![0xc009],
            renegotiation: if renegotiation { vec![1] } else { Vec::new() },
            point_formats: point_formats.to_vec(),
            alpn: protos(alpn),
            ..HelloFacts::default()
        };
        let alpn_text = |client: &str| {
            format!("tls: client requested unsupported application protocols ([\"{client}\"])")
        };
        let reneg = "tls: initial handshake had non-empty renegotiation extension";
        let points = "tls: client offered only incompatible point formats";
        let refusal = |alert: u8, text: &str| Some((alert, text.to_string()));
        for (what, facts, tls13_only, server, want) in [
            (
                "no ALPN in common",
                hello(&["spdy/3"], false, &[]),
                false,
                &h2,
                refusal(120, &alpn_text("spdy/3")),
            ),
            (
                "renegotiation first",
                hello(&["spdy/3"], true, &[]),
                false,
                &h2,
                refusal(40, reneg),
            ),
            (
                "ALPN before point formats",
                hello(&["spdy/3"], false, &[1]),
                true,
                &h2,
                refusal(120, &alpn_text("spdy/3")),
            ),
            (
                "ALPN before the key",
                hello(&["spdy/3"], false, &[]),
                true,
                &h2,
                refusal(120, &alpn_text("spdy/3")),
            ),
            (
                "the http/1.1 exception",
                hello(&["http/1.1"], false, &[]),
                false,
                &h2,
                None,
            ),
            (
                "the exception, then the key",
                hello(&["http/1.1"], false, &[1]),
                true,
                &h2,
                refusal(109, points),
            ),
            (
                "no client protocols",
                hello(&[], false, &[]),
                false,
                &h2,
                None,
            ),
            (
                "no server protocols",
                hello(&["spdy/3"], false, &[]),
                false,
                &Vec::new(),
                None,
            ),
            (
                "a protocol in common",
                hello(&["spdy/3", "h2"], true, &[]),
                false,
                &h2,
                None,
            ),
            (
                "the key alone",
                hello(&[], false, &[]),
                true,
                &Vec::new(),
                refusal(80, TLS13_ONLY_KEY_REFUSED),
            ),
        ] {
            assert_eq!(facts.go_tls12_refusal(tls13_only, server), want, "{what}");
        }
        let tls13 = HelloFacts {
            supported_versions: Some(vec![0x0304, 0x0303]),
            ..hello(&["spdy/3"], false, &[])
        };
        assert_eq!(tls13.go_tls12_refusal(true, &h2), None, "TLS 1.3");
    }

    /// Go's `strconv.Quote`, by Go's own test table where it applies
    /// (`strconv/quote_test.go`'s `quotetests`) and for bytes that are not
    /// UTF-8.
    #[test]
    fn go_quote_is_strconv_quote() {
        for (input, want) in [
            (&b"\x07\x08\x0c\r\n\t\x0b"[..], r#""\a\b\f\r\n\t\v""#),
            (b"\\", r#""\\""#),
            (b"abc\xffdef", r#""abc\xffdef""#),
            ("\u{263a}".as_bytes(), "\"\u{263a}\""),
            ("\u{10ffff}".as_bytes(), r#""\U0010ffff""#),
            (b"\x04", r#""\x04""#),
            (b"\x7f", r#""\x7f""#),
            (
                "!\u{a0}!\u{2000}!\u{3000}!".as_bytes(),
                r#""!\u00a0!\u2000!\u3000!""#,
            ),
            (b"\"h2\"", r#""\"h2\"""#),
            (b"spdy/3", r#""spdy/3""#),
            (b"\xe2\x82A", r#""\xe2\x82A""#),
        ] {
            assert_eq!(go_quote(input), want, "{input:?}");
        }
    }

    /// The ALPN extension is read into the facts, and a malformed one
    /// leaves them as they were before it was read.
    #[test]
    fn hello_facts_read_alpn_leniently() {
        let hello = |alpn: &[u8]| {
            // A TLS 1.2 ClientHello with one suite and the extension.
            let mut ext = vec![0x00, 0x10];
            ext.extend(u16::try_from(alpn.len()).expect("short").to_be_bytes());
            ext.extend(alpn);
            let mut body = vec![0x03, 0x03];
            body.extend([0u8; 32]);
            body.push(0);
            body.extend([0x00, 0x02, 0xc0, 0x2b, 0x01, 0x00]);
            body.extend(u16::try_from(ext.len()).expect("short").to_be_bytes());
            body.extend(ext);
            let mut message = vec![0x01, 0x00];
            message.extend(u16::try_from(body.len()).expect("short").to_be_bytes());
            message.extend(body);
            let mut record = vec![0x16, 0x03, 0x01];
            record.extend(u16::try_from(message.len()).expect("short").to_be_bytes());
            record.extend(message);
            HelloFacts::parse(&record).expect("parses")
        };
        assert_eq!(
            hello(&[
                0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'
            ])
            .alpn,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        let malformed = hello(&[0x00, 0x05, 0x02, b'h', b'2', 0x08, b'h']);
        assert!(malformed.alpn.is_empty());
        assert_eq!(malformed.cipher_suites, vec![0xc02b]);
    }

    /// `choose` gives the configuration `handshake` serves, or, for a key
    /// Go serves in TLS 1.3 alone, Go's refusal of a client that would
    /// negotiate TLS 1.2, with its alert record.
    #[test]
    fn choose_is_the_handshakes_choice() {
        let (cert, key) = cert_pair();
        let key_pair = KeyPair::from_pem(&cert, &key).expect("the pair");
        let mut configs =
            GoServerConfigs::new(&key_pair, &GoServerOptions::default()).expect("the set");
        let tls12 = HelloFacts {
            legacy_version: 0x0303,
            cipher_suites: vec![0xc02b],
            ..HelloFacts::default()
        };
        let tls13 = HelloFacts {
            legacy_version: 0x0303,
            cipher_suites: vec![0x1301],
            supported_versions: Some(vec![0x0304, 0x0303]),
            supported_groups: vec![0x0017],
            key_shares: vec![0x0017],
            ..HelloFacts::default()
        };
        for hello in [&tls12, &tls13] {
            let chosen = configs.choose(hello).expect("a configuration");
            assert!(Arc::ptr_eq(&chosen, &configs.for_hello(hello)));
        }
        configs.tls13_only = true;
        let refusal = configs.choose(&tls12).expect_err("refused");
        assert_eq!(refusal.text, TLS13_ONLY_KEY_REFUSED);
        assert_eq!(refusal.record(), [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 80]);
        assert!(configs.choose(&tls13).is_ok());
    }
}
