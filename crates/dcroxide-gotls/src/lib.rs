// SPDX-License-Identifier: ISC
//! Go's `crypto/tls` server as dcrd and dcrwallet configure it, over
//! rustls and `dcroxide-tlscrypto`: the client certificate verifier that
//! accepts and refuses as Go's does ([`GoClientCertVerifier`]), Go's
//! choice of cipher suite and key exchange for each ClientHello
//! ([`GoServerConfigs`], [`handshake`]), Go's checks on the records a
//! client sends after its ClientHello ([`GoRecordChecks`]), Go's reading
//! of PEM certificates and private keys ([`go_pem_decode`],
//! [`go_certificate_blocks`], [`go_key_block`], [`KeyPair`]), and the
//! texts Go's errors print.
//!
//! # Why a crate of its own
//!
//! The code was written for dcrd's RPC listener in `dcroxide-node`, and
//! the wallet, dcr-purse, needs the same behaviour for its JSON-RPC and
//! gRPC listeners, since a client of dcrwallet meets the same Go server.
//! The wallet's ADR-0006 rule 3 takes what it needs from dcroxide as a
//! library crate at the pinned revision, not as a copy, and nothing
//! outside the node could reach this code inside it.
//!
//! It is not part of `dcroxide-tlscrypto`.  That crate is the rustls
//! crypto provider of ADR-0015's T1: record protection, key exchange,
//! signing and signature verification, held to ring's choices and
//! verdicts, under the constant-time check and Wycheproof's vectors
//! (T10), and with no dependency on webpki.  This crate holds no
//! cryptography: it is protocol and policy, Go's X.509 chain search and
//! policy rules, its ClientHello handling and its PEM decoder, built on
//! the provider's items and on webpki, and it changes with the reference
//! Go's `crypto/tls`, `crypto/x509` and `encoding/pem` rather than with
//! the primitives.  Keeping the two apart keeps the provider's audit
//! surface (ADR-0015, Consequences) what it was.
//!
//! The crate depends on neither the node nor tokio.  [`handshake`] runs
//! on a blocking `std::net::TcpStream`, as the node's listener threads
//! do, and is the reference for a driver over another transport, such as
//! the tokio one under tonic, which dcr-purse's ADR-0004 chose for its
//! gRPC listener: such a driver records the connection's opening bytes as
//! they go to rustls's `Acceptor`, reads them with [`HelloFacts::parse`],
//! takes the configuration or Go's refusal from [`GoServerConfigs::choose`],
//! words a failure with [`go_error_text`], runs [`GoRecordChecks`] over
//! the bytes it passes between the socket and rustls after the
//! ClientHello, and asks [`GoServerConfigs::after_handshake`] about a
//! completed handshake.  Such a driver processes the records after each
//! `read_tls` before it gives rustls more: rustls's buffer holds one
//! record until the records it has processed start a longer handshake
//! message, so a driver that gave it a whole read first would refuse a
//! client certificate message of some 16 KiB, which Go reads
//! (`tests/certificate_size.rs`).
//! Such a driver also asks [`GoServerConfigs::choose`] when `Acceptor`
//! refuses a ClientHello with `PeerIncompatible`: rustls refuses one
//! without signature_algorithms, which no TLS 1.0 or 1.1 client sends,
//! before it looks at the versions, where Go refuses the versions first
//! ([`HelloFacts::go_version_refusal`]).  What [`handshake`] does beyond
//! that, Go's answers to a first record that is not TLS and its texts for
//! an early close or a deadline, is in its source, and no async driver is
//! in the crate.  Its
//! dependencies are rustls, webpki, zeroize and `dcroxide-tlscrypto`, all
//! already in the node's tree, so it holds to ADR-0012's rules unchanged:
//! no `ring`, no `aws-lc`, no `cc`.
//!
//! # dcrd and dcrwallet
//!
//! Both read `rpc.cert` and `rpc.key` with `tls.LoadX509KeyPair`
//! ([`KeyPair::from_pem`], with the file reading the program's own) and
//! set `MinVersion` to TLS 1.2, leaving the maximum, the curves and the
//! suites at Go's defaults, which [`GoServerConfigs::new`] always takes.
//! What differs is in [`GoServerOptions`]:
//!
//! - **dcrd** (`newTLSConfig`, `server.go:3679-3701`): no client
//!   certificate, or under `--authtype=clientcert` one required and
//!   verified against the `--clientcafile` pool, a file that adds nothing
//!   failing startup ([`GoClientCertVerifier::from_pem`]); no ALPN;
//!   [`GoServerOptions::default`] or `client_auth` alone.
//! - **dcrwallet** (`startRPCServers`, `rpcserver.go:252-330`, at the
//!   wallet's pin, `decred.org/dcrwallet/v5`
//!   `v5.0.1-0.20261105142009-54b85b336077`): `ClientCAs` is always a
//!   pool, filled from `--clientcafile` when that file exists, with only a
//!   warning when it adds nothing ([`ClientCaPool::append_certs_from_pem`]'s
//!   answer), and under `--issueclientcert` with the authority the wallet
//!   generates and announces over its pipe ([`ClientCaPool::add_cert`]).
//!   [`GoClientCertVerifier::new`] takes that pool, empty or not, and one
//!   verifier serves both listeners.  The JSON-RPC listener
//!   ([`GoServerOptions::dcrwallet_jsonrpc`]) asks for no client
//!   certificate unless `--jsonrpcauthtype=clientcert`, and has no ALPN.
//!   The gRPC listener ([`GoServerOptions::dcrwallet_grpc`]), started
//!   only when the file exists or `--issueclientcert` is given, always
//!   requires and verifies a client certificate, and its configuration
//!   goes through grpc-go's `credentials.NewTLS` and `ServerHandshake`
//!   ([`GoServerOptions::grpc`]): `h2` is offered, and a completed
//!   handshake that negotiated no protocol is closed with grpc-go's error
//!   ([`GoServerConfigs::after_handshake`], [`GRPC_MISSING_ALPN`]).
//!   grpc-go also names the suites, `tls.CipherSuites()` less those
//!   HTTP/2 forbids, which takes Go's ECDHE CBC suites out of TLS 1.2 and
//!   so leaves the six the set offers already.  Generating the authority
//!   and the client pair, and announcing them, are the wallet's to do.
//!   dcrwallet generates every key on `--tlscurve`, Ed25519 by default,
//!   or P-256, P-384 or P-521: the server's pair through dcrd's certgen,
//!   and the authority and client through its own templates
//!   (`rpcserver.go:133-209`).  [`KeyPair::from_pem`] serves a pair on any
//!   of the four.  `dcroxide-certgen` writes certgen's pairs on P-256,
//!   P-521 and Ed25519, not on P-384, and nothing in dcroxide writes
//!   dcrwallet's authority and client templates; the wallet needs both
//!   for `--tlscurve=P-384` and for `--issueclientcert`.
//! - **`GODEBUG`.**  dcrd builds with `//go:debug default=go1.26` and
//!   dcrwallet with `default=go1.25`, which differ in two settings that
//!   touch TLS: `tlssecpmlkem=0` in dcrwallet, which leaves
//!   X25519MLKEM768 the one hybrid its default server offers where dcrd's
//!   offers three, and `cryptocustomrand=1`, which has the random source
//!   dcrwallet passes used when it generates keys and changes no
//!   handshake.  No hybrid is offered here (below), so today the two
//!   configurations negotiate alike; when the hybrids land, which of them
//!   to offer becomes an option.
//!
//! `tests/wallet_interop.rs` holds each of dcrwallet's settings to Go's
//! server configured as dcrwallet's, under dcrwallet's `GODEBUG`, through
//! the oracle: the empty pool, a pool filled by `AddCert`, the JSON-RPC
//! listener under basic authentication, the `--issueclientcert` pair on
//! each `--tlscurve`, the gRPC listener's ALPN, suites and close, a TLS
//! 1.0 or 1.1 client on each listener and `--tlscurve`, the client
//! certificates Go's chain search refuses for an authority outside its
//! validity or a usage that leaves out client authentication, and a
//! client that breaks the protocol after its first ClientHello, by the
//! version of its records or by changing its ClientHello after a
//! HelloRetryRequest, which [`GoRecordChecks`] refuses as Go does.
//! `tests/certificate_size.rs` holds the size of a client certificate
//! message to Go's server configured as dcrd's: a valid chain of over 32
//! KiB is verified and accepted in TLS 1.3 and TLS 1.2, and one with a
//! leaf for servers alone refused by the verifier in Go's words; messages
//! just under rustls's limit (64 KiB less one byte of wire data, record
//! headers and AEAD overhead included) are accepted by both, those
//! between it and Go's 256 KiB refused here alone (PARITY.md's ML-DSA
//! entry), and those past Go's refused by both.
//!
//! # What ADR-0015's T3 and T4 leave open
//!
//! The wallet's ADR-0004 asks for both before its GUI acceptance.
//!
//! - **T3, the three hybrids, is not done.**  No ML-KEM implementation
//!   is in the tree; the provider offers X25519, P-256, P-384 and P-521
//!   alone, and a client that supports a hybrid negotiates a classical
//!   group where Go's server would negotiate the hybrid (PARITY.md's
//!   classical key exchange entry).  Go's own client offers
//!   X25519MLKEM768 by default, and so do the clients built on it, dcrctl
//!   and any gRPC client on grpc-go, so against dcrwallet such a client
//!   negotiates the hybrid and against the wallet X25519.  Decrediton is
//!   not one of them: it is an Electron application, whose gRPC client is
//!   Node.js's (dcrwallet's `rpc/documentation/clientusage.md` describes
//!   the `grpc` npm package over gRPC Core), and what it offers for the
//!   wallet's gRPC key exchange has not been checked.  Where it pins
//!   `ecdhCurve`, as it pins `secp521r1` on its requests to a remote dcrd
//!   (the reason the key exchanges served here include P-521), it offers
//!   no hybrid, and T3 would not change what it negotiates.
//!   What it takes: `ml-kem` as a new dependency with its ledger row; a
//!   hybrid `SupportedKxGroup` of the provider's own, completing on the
//!   client's share in one step, since rustls's is private to its
//!   aws-lc-rs module; SecP384r1MLKEM1024 under rustls's
//!   `NamedGroup::Unknown`, which no test has carried end to end; Go's
//!   rule of sorting a supported hybrid ahead of every other group, even
//!   one with a key share, in [`GoServerConfigs`]'s group choice, with a
//!   configuration per hybrid in the set; an option in
//!   [`GoServerOptions`] for which hybrids are offered (dcrd's three,
//!   dcrwallet's X25519MLKEM768 alone); the constant-time check over the
//!   new key exchange path; and the Go interop cells, the wallet's under
//!   its `GODEBUG`.  Estimated at 1,000 to 1,500 lines with tests, several
//!   days of work, not prototyped.
//! - **T4, Go's client certificate set, is not done.**  The provider
//!   verifies ECDSA on P-256 and P-384 with SHA-256 or SHA-384 only, and
//!   RSA keys of 2041 to 8192 bits (a modulus of at least 256 whole
//!   bytes, ring's floor), so a P-521 client key, a chain whose issuer
//!   signs with ecdsa-with-SHA512, and an RSA client key below 2041 bits,
//!   which Go accepts from 1024, are refused where Go accepts them
//!   (PARITY.md's clientcert entry).  For the wallet that is `--issueclientcert` under
//!   `--tlscurve=P-521`: dcrwallet's P-521 authority signs its client
//!   with ECDSA-SHA512 and the client's key is P-521, so the pair dcrwallet
//!   would accept is refused (`tests/wallet_interop.rs` holds the refusal
//!   beside Go's acceptance); the default Ed25519 pair and the P-256 and
//!   P-384 ones are accepted as Go accepts them.  The verification itself
//!   is small: the provider's ECDSA verifier is generic over the curve and
//!   the hash, and `p521` is already a dependency, so P-521 and SHA-512
//!   are table entries in `RPC_SIG_ALGS` and the scheme list of the
//!   CertificateRequest, with Wycheproof's P-521 vectors, which are not
//!   in the tree, and the RSA lower bound in `rsa.rs`; estimated at 200 to
//!   400 lines with tests.  It changes the node's verdicts, so it lands
//!   with the matrix cells it flips (the client-certificate verdicts
//!   `dcroxide-testutil`'s `tls_interop` holds, and the P-521 cells
//!   here), the PARITY entries it closes, and ADR-0015's record of it, in
//!   a change of its own.  It was left out of the change that made this
//!   crate, which changes no verdict of the node's for a client that
//!   keeps to the protocol: the node's Go interop matrix runs through the
//!   crate with its earlier cells unchanged, and `tests/certificate_size.rs`
//!   and the node's `a_go_client_chain_over_32_kib_under_clientcert_auth`
//!   hold client certificate messages up to rustls's limit (64 KiB less
//!   one byte of wire data, record headers and AEAD overhead included),
//!   the node's before the crate as well, which a first version of
//!   [`handshake`]'s own reading refused past some 16 KiB.  That change
//!   does change the node: its review fixes move the node's alerts and logged words toward Go's for a few
//!   refusals, and refuse, as Go does, a client that sends a record of
//!   another version than TLS 1.2's during the handshake, or changes its
//!   ClientHello after a HelloRetryRequest, which the node accepted
//!   (ADR-0015's addendum of 2026-11-19, its review fixes).

mod clientcert;
mod pem;
mod records;
mod server;

pub use clientcert::{
    ClientCaPool, DroppedChains, GoClientCertVerifier, InvalidPolicies, NO_CLIENT_CAS,
    NoValidChains, NotAuthorizedToSign, fuzz_client_cert,
};
pub use pem::{GoPemBlock, go_certificate_blocks, go_key_block, go_pem_decode};
pub use records::{GoRecordChecks, fuzz_record_checks};
pub use server::{
    ClientAuth, GRPC_MISSING_ALPN, GoRefusal, GoServerConfigs, GoServerOptions, HelloFacts,
    KeyPair, KeyPairError, go_error_text, handshake,
};
