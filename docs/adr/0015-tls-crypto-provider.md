# ADR-0015 — TLS crypto provider: an in-tree provider on RustCrypto

- **Status:** Accepted 2026-10-26. Step 1 is under way:
  `dcroxide-tlscrypto` holds the nine cipher suites' record protection,
  the four key exchange groups, the signing keys and ring's fourteen
  verification algorithms, RSA among them verified in tree (T5), put
  together in its `default_provider`; the node takes only its P-521
  group and its P-521 signer, which `ring` lacks. `ring` stays the
  node's TLS provider for everything else until the in-tree provider
  passes the Go interop matrix: every cipher suite, key exchange group,
  key type and TLS version, plus client certificates. Then `ring` goes
  in one change.
- **Date:** 2026-10-26

## Context

On 2026-10-26 the project owner approved ten recommendations on TLS and
pure Rust, numbered T1 to T10 here as they were put, with "go with your
recommendations". This record carries T1, T3, T4, T5, T6, T7 and T10. The
other three are [ADR-0012](0012-pure-rust.md)'s: what pure Rust allows
(T2), BLAKE3 (T8) and C in test tooling (T9). The provider below is held
to ADR-0012's definition, which this record does not restate, and `ring`
is one of the two C libraries ADR-0012 removes, `secp256k1-sys` being the
other. The owner's standing words were "pure rust everywhere, check the
tls providers first", with more work accepted where it serves code
quality and efficiency. The provider research those words asked for read
the candidates on 2026-10-26. Its findings that could not be checked
again against the repository, the locked crate sources or the reference
Go's source for this record are marked as the research's.

### What a provider does, and where the node uses one

rustls speaks the TLS protocol and does none of the cryptography itself.
A `CryptoProvider` supplies the record ciphers, the key exchanges, the key
loader that turns a private key into a signer, the signature checks that
certificate verification runs, and random numbers. rustls 0.23.46 is
itself written in Rust with no C, and forbids `unsafe`
(`rustls-0.23.46/src/lib.rs:332`); its provider in this node is `ring`
0.17.14, about 151k lines of C and assembly
(`docs/dependency-ledger.md:51`).

`dcroxide-node` uses the provider in three places:

1. **The RPC and websocket TLS listener.** `build_server_config`
   (`crates/dcroxide-node/src/rpcrun.rs:4405`) loads `rpc.key` through
   ring's key loader (`:4480`), and `RpcTlsConfigs` builds one rustls
   configuration for each cipher-suite order and TLS 1.3 key exchange
   Go's server can settle on, each from ring's provider with its suites
   and groups replaced (`src/rpctls.rs:287-303`; `rpc_cipher_suites`,
   `:179-211`; `rpc_kx_groups`, `:97-105`). A P-521 key and the P-521 key
   exchange already run beside the provider, on the pure-Rust `p521`
   through `dcroxide-tlscrypto` (its signer, `rpcrun.rs:4468-4478`; its
   `kx_group::SECP521R1`, `rpctls.rs:103`), since ring's ECDSA signs over
   P-256 and P-384 only and its key exchanges are X25519, P-256 and P-384
   (`rustls-0.23.46/src/crypto/ring/sign.rs:45-65`, `mod.rs:180-181`).
2. **The RPC client-certificate verifier**, `GoClientCertVerifier`
   (`rpcrun.rs:3516`), under `--authtype=clientcert`. Its replay of Go's
   chain search checks signatures with ring's verification algorithms
   (`:4035-4037`), and the handshake signature and webpki's path check go
   to a `WebPkiClientVerifier` made with `WebPkiClientVerifier::builder`
   (`:4045-4047`), which takes the process default provider
   (`rustls-0.23.46/src/webpki/client_verifier.rs:274-279`).
3. **Both clients of the HTTPS seeder.** Without a proxy, `UreqTransport`
   (`src/seeding.rs:25`) goes through `ureq` 3.4.2, which picks a
   provider when it first builds its configuration: the one its
   `TlsConfig` names, else the process default, else ring when its
   `_ring` feature is on, else a panic
   (`ureq-3.4.2/src/tls/rustls.rs:137-160`). Under `--proxy`,
   `ProxySeederTransport` (`seeding.rs:93`) runs rustls itself over a
   configuration built on ring's provider (`seeder_tls_config`,
   `:151-167`). Both check the seeder's chain with the provider's
   verification algorithms (`rustls-0.23.46/src/client/builder.rs:51-61`).

`rustls::crypto::ring` is named 46 times in seven files of `dcroxide-node`,
seven of those uses outside tests (`rpctls.rs:98`, `:180`, `:292`;
`rpcrun.rs:4035`, `:4421`, `:4480`; `seeding.rs:158`).

### How `ring` arrives

No workspace crate depends on the `ring` crate directly; the node
reaches it only through rustls's `crypto::ring` module. It arrives
through two feature switches. `dcroxide-node` turns on rustls's
`ring` feature (`crates/dcroxide-node/Cargo.toml:64-69`), which turns on
`rustls-webpki`'s as well (`rustls-0.23.46/Cargo.toml:88-91`). And the
node asks for `ureq = "3"` with its default features
(`crates/dcroxide-node/Cargo.toml:82`), whose `rustls` feature turns on
`_ring`, that is `rustls?/ring` (`ureq-3.4.2/Cargo.toml:63`, `:74-77`,
`:101-105`). Cargo unifies features across the build, so `ring` leaves
only when both switches change; either alone brings it back. `fuzz/`,
outside the workspace with a lock of its own, takes the node's whole tree
through `dcroxide-node` (`fuzz/Cargo.toml:21-24`) and locks `ring` too
(`fuzz/Cargo.lock:1392`).

### The process default

The node installs ring as rustls's process-wide default in one place, the
top of `build_server_config` (`rpcrun.rs:4421`), which runs only when an
RPC listener is built with TLS: under `--norpc` there is no listener, and
under `--notls` it serves plain HTTP (`src/bin/dcroxide.rs:1210-1215`).
The seeder runs unless `--noseeders` (`:1513`) and, without a proxy,
through `UreqTransport` (`:1545-1562`). A ureq with no provider of its
own and no process default falls back to ring through `_ring` today; once
`_ring` is gone, the same call panics with ureq's "No CryptoProvider for
Rustls" (`ureq-3.4.2/src/tls/rustls.rs:153-159`). Under `--norpc` or
`--notls` a replacement therefore reaches ureq only by being handed to
it. `WebPkiClientVerifier::builder` depends on the process default in the
same way, and rustls panics there when it finds none
(`rustls-0.23.46/src/crypto/mod.rs:243-257`).

### What a replacement has to do

From `rpctls.rs`, `rpcrun.rs` and `seeding.rs`, and from the choices Go's
server makes in the reference Go, 1.26.2 (ADR-0001's addendum of
2026-10-26 on the reference Go):

- **(a) Nine cipher suites, each addressable on its own**, so that both
  of Go's suite orders can be built (`rpctls.rs:179-211`): TLS 1.3's
  AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305, and TLS 1.2's
  ECDHE-ECDSA and ECDHE-RSA with each of the three.
- **(b) TLS 1.2** (rustls's `tls12` feature,
  `crates/dcroxide-node/Cargo.toml:67`).
- **(c) Key exchange:** X25519, P-256, P-384 and P-521, as now
  (`rpctls.rs:85-105`); and the three hybrids with ML-KEM,
  X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024, which
  Go 1.26.2 puts ahead of the classical groups
  (`crypto/tls/defaults.go:30-33`), in TLS 1.3 only (`common.go:158-165`),
  and which dcrd at the parity pin `3360ae4d` leaves on
  (`rpctls.rs:15-23`). The node offers none of the three today
  (`docs/PARITY.md:2953-2986`).
- **(d) Server keys:** P-256, the default, and P-521 under `--tlscurve`;
  P-384 and Ed25519, which `gencerts` writes
  (`crates/dcroxide-certgen/src/gentool.rs:12-15`); and RSA, when an
  operator supplies one, which dcrd accepts and ring loads today
  (`sign.rs:21-24`).
- **(e) Verification.** Today ring's set: ECDSA on P-256 and P-384 with
  SHA-256 or SHA-384, Ed25519, and RSA PKCS#1 v1.5 and PSS with keys of
  2048 to 8192 bits (`rustls-0.23.46/src/crypto/ring/mod.rs:107-123`). Go
  verifies more, among it P-521 keys, ECDSA with SHA-512, and RSA keys of
  1024 to 2047 bits and over 8192 (`PARITY.md:2818-2834`).
- **(f) RSA verification is mandatory.** The seeders' chains are checked
  with the same algorithms (use 3 above). The research found the
  certificates of `mainnet-seed-1.decred.org` and
  `testnet-seed-1.decred.org`
  (`crates/dcroxide-chaincfg/src/mainnet.rs:287`, `testnet.rs:317`)
  issued by a Let's Encrypt RSA-2048 intermediate whose default chain
  ends at an RSA root, in certificate transparency logs read on
  2026-10-26; this was not checked again for this record. A provider
  without RSA verification breaks HTTPS seeding.
- **(g) The rest of a provider:** a `&'static` set of verification
  algorithms, which `GoClientCertVerifier` holds (`rpcrun.rs:3522`), a key
  provider, and a source of random numbers.

Go's four TLS 1.2 CBC suites (Go 1.26.2's
`crypto/tls/cipher_suites.go:290-291`) are not on the list: no provider
can add them (Known limits, below).

### The providers that exist

The research found none that is pure Rust, mature and able to do (a) to
(g). These findings are the research's; none of these providers' sources
is in the local registry, and none was re-read for this record.

- **C, so ruled out by ADR-0012:** ring; aws-lc-rs, rustls's default
  provider (`rustls-0.23.46/Cargo.toml:70-76`), which the node's manifest
  already keeps out as a C and assembly library
  (`crates/dcroxide-node/Cargo.toml:59-63`); and the providers over
  SymCrypt, BoringSSL, OpenSSL, Mbed TLS, wolfCrypt, Windows CNG and
  Botan.
- **graviola** (with `rustls-graviola`): it needs no C compiler, but it
  embeds about 35,000 lines of assembly from s2n-bignum and mlkem-native
  in `asm!` blocks; it builds only for x86_64 and aarch64; it panics on
  first use on processors without the extensions it assumes (pre-Broadwell
  Intel, Atom-class chips, aarch64 without AES, PMULL or SHA2); and it has
  no P-521 and no P-256 or P-384 hybrid.
- **rustls-rustcrypto**, the RustCrypto project's own provider: one
  release, a 2024 alpha whose README says not to use it in production;
  master is unreleased, has open defects, and has no P-521 and no
  hybrids.
- **The rest** were days old or hobby-scale when read: `rustls-pure`
  (TLS 1.3 only and no RSA, so it fails (b) and (f)), providers that need
  the unreleased rustls 0.24, and a few crates published in the preceding
  fortnight with tens of downloads.

With any of them, the node would still own P-521 itself, as it does now.

### The client-certificate pre-check

Commit `185b9d2` replays Go's chain search before webpki's for an RPC
client (`go_build_chains`, `rpcrun.rs:3281`). The replay checks each
candidate's signature with `sig_algs`, ring's verification algorithms
(`:3270-3282`, `:3519-3522`, `:4035-4037`), and takes a candidate whose
signature Go verifies and ring cannot for a failed check. PARITY.md lists
those cases one by one (`PARITY.md:2818-2834`), so the list follows the
provider's verification set.

## Decision

### T1 — an in-tree provider on RustCrypto

dcroxide writes its own TLS crypto provider: a new workspace crate (the
approval's working name is `dcroxide-tlscrypto`) built from RustCrypto
libraries, most of them already in the lock (`p256`, `p384` and `p521`
0.14.0, `ecdsa` 0.17.0, `sha2` 0.11.0, `hmac` 0.13.0, `chacha20` 0.10.2,
with `curve25519-dalek` 5.0.0 beside them), with `aes-gcm`,
`chacha20poly1305` and `ml-kem` new. It is held to ADR-0012's definition
of pure Rust, and as a workspace crate it inherits `unsafe_code =
"forbid"` (`Cargo.toml:134-135`). It exports a `CryptoProvider` and every
suite and group as an item of its own, which (a) needs. The research
estimated it at 1.5k to 2.5k lines plus tests, from the size of
rustls-rustcrypto's source; nothing has been prototyped. Of the options
the research found, it is the one that covers all of (a) to (g).

`ring` stays the provider until the in-tree provider passes the Go
interop matrix (T10): every cipher suite, key exchange group, key type and
TLS version, plus client certificates. Then `ring` goes in one change,
which moves the RPC listener, the client-certificate verifier and both
seeder clients to the provider together and leaves nothing in the build
that selects `ring`. This record reads the matrix that gates that change
as covering what the change ships, today's feature level (below); the
hybrids and the wider client-certificate set, which come after it, are
each proven by interop with Go when they land.

### Order of work

The approved recommendations put the work in this order, after the
decision records:

1. ECDSA's move to `k256` and its soak (ADR-0012, and the later record
   that supersedes ADR-0006);
2. the provider at today's feature level, then the switch;
3. the three hybrids (T3) and the wider client-certificate set (T4);
4. the BLAKE3 port and the power-cut shim's rewrite (ADR-0012).

Today's feature level is (a) to (g) without the hybrids, as ring and the
node's own P-521 code provide it now, with RSA verified by the in-tree
code of T5 and with no RSA server key (T6).

### T3 — the three post-quantum hybrids

The provider adds X25519MLKEM768, SecP256r1MLKEM768 and
SecP384r1MLKEM1024 on RustCrypto's `ml-kem`, ordered as Go orders them
and proven by interop with Go. In Go 1.26.2 they come first, in that order
(`defaults.go:30-33`), only in TLS 1.3 (`common.go:158-165`), and the
server sorts a hybrid the client supports ahead of every other group,
even one the client sent a key share for
(`handshake_server_tls13.go:201-231`), so `go_tls13_group`
(`rpctls.rs:225`) takes that rule with them. rustls's own hybrid type is
private to its aws-lc-rs module
(`rustls-0.23.46/src/crypto/aws_lc_rs/pq/hybrid.rs:11`), so the provider
writes its own, completing on the client's share in one step
(`SupportedKxGroup::start_and_complete`, `src/crypto/mod.rs:388`).
rustls 0.23.46 names two of the three groups
(`src/msgs/enums.rs:256-257`); the third, SecP384r1MLKEM1024, code 0x11ed
(Go's 4589, `common.go:155`), would travel as `NamedGroup::Unknown`
(`src/msgs/macros.rs:36`, `:77`), and whether rustls negotiates a group
under an unknown code end to end was not checked. Two questions the
research left open are for the interop tests to settle: whether `ml-kem`
checks an encapsulation key as Go's `crypto/mlkem` does, and whether the
hybrid shares and secrets are laid out as Go lays them out.

### T4 — Go's client-certificate set

The provider verifies Go's set: P-521 keys, ECDSA with SHA-512, and RSA
keys from 1,024 bits, beyond ring's set in (e). That closes the
client-certificate refusals PARITY.md records for those cases
(`PARITY.md:2928-2939`): a P-521 client key; a chain whose issuer signs
with ecdsa-with-SHA512, a P-256 client certificate under a P-521 CA among
them; and an RSA client key below 2048 bits. Where the three cases leave
a bound open, the largest RSA key for one, this record reads "Go's set" as
deciding it. P-224 keys, which Go verifies (Go 1.26.2's
`crypto/x509/x509.go:539-540`), and ML-DSA keys, which the reference
Go's `crypto/x509` does not parse (it knows no ML-DSA, and an unknown key
algorithm leaves the key unset, `parser.go:1005-1018`), are not named in
the approval, and this record reads them as not added.

### T5 — RSA verification, in-tree

RSA signatures are checked by in-tree, verification-only code, about 300
lines by the research's estimate, tested against Google's Wycheproof
vectors. For today's feature level it covers PKCS#1 v1.5 and PSS, the
schemes ring verifies now (`ring/mod.rs:114-122`). Checking a signature
uses only the public key, so the code holds no secret. The `rsa` crate
was not taken: the line of it built on the RustCrypto generation in the
lock was a prerelease when the research read it, its stable 0.9 line is
built on the generation before (`digest` 0.10,
`rsa-0.9.10/Cargo.toml:108-109`, where the lock has 0.11.3,
`Cargo.lock:838-839`), and it carries RUSTSEC-2023-0071, the
timing advisory `gencerts` already cites (`gentool.rs:12-15`). That
advisory concerns private-key operations, which verification does not
run; this is the research's reading, and the advisory was not re-read for
this record. The choice is revisited when the `rsa` crate's current line
is stable.

### T6 — an RSA server key is refused

An RSA `rpc.key` is refused at startup with a clear message, and
PARITY.md records the divergence; neither is done yet. dcrd accepts such
a key and ring signs with one today. The only pure-Rust RSA signer is
the `rsa` crate, and its advisory is about the private-key operations a
signer runs, which is why `gencerts` already refuses RSA
(`gentool.rs:12-15`). This record reads the refusal as landing with the
switch, the change that takes away the only signer of an RSA key; until
then ring serves one as it does now. A certificate rotation loads the key
through the same function (`rpcrun.rs:2154`), and this record reads "at
startup" as naming where the daemon stops, not as limiting the check: a
rotated-in RSA key meets the same refusal.

### T7 — the seeder's HTTPS clients

For the switch, `ureq` stays, with the provider handed to it explicitly
through `TlsConfigBuilder::unversioned_rustls_crypto_provider`, reached
through `TlsConfig::builder()` (`ureq-3.4.2/src/tls/mod.rs:296-302`), so
that a run under `--norpc` or `--notls`, which installs no process
default, never reaches ureq's panic. ureq says that call is not guaranteed
for semver (`mod.rs:246-254`).
While the node relies on it, ureq is pinned to an exact version, where
the manifest asks for `"3"` today; this record takes the pin from the
research's condition on keeping ureq, since the approved text names only
the unstable API.

Afterwards one small in-tree client replaces both seeder clients. It
closes the redirect gap PARITY.md records on the proxy path, whose client
follows no redirects and decodes no chunked transfer encoding
(`PARITY.md:940`; `seeding.rs:86-92`), drops `ureq` and `ureq-proto`,
and ends the reliance on ureq's unstable provider API.

### T10 — assurance for the new cryptography

- **A dependency-ledger row for each new crypto crate:** `aes-gcm`,
  `chacha20poly1305`, `ml-kem`, and the provider crate itself.
- **Wycheproof vectors in CI.** This record reads them as covering each
  of the provider's primitives that Wycheproof has vectors for, RSA among
  them (T5).
- **The Go interop matrix**, through the oracle: every cipher suite, key
  exchange group, key type and TLS version, plus client certificates,
  against the reference Go. "Through the oracle" is the research's means;
  the approved text says "against Go". When this was accepted the oracle
  had no TLS command, its one X.509 command being `x509_verify_client`
  (`tools/oracle/main.go:1550`).
- **A constant-time check on the signing and key-exchange paths.** Its
  method is not set here.

### Known limits

- **Go's four TLS 1.2 CBC suites stay a recorded gap**
  (`PARITY.md:2988-2995`). rustls's TLS 1.2 key block has no place for a
  MAC key (`rustls-0.23.46/src/crypto/cipher.rs:110-134`), so no provider
  under rustls can offer them. Every client the Decred tools ship offers
  an AES-GCM suite (`PARITY.md:2994-2995`).
- **rustls 0.24 is unreleased.** The provider is written against 0.23,
  the line the node is on (0.23.46, `Cargo.lock:1527-1528`), and is ported
  to 0.24 when that is stable. The research read 0.24.0-dev.2 as
  reshaping `CryptoProvider`, separate TLS 1.2 and TLS 1.3 suite lists
  among the changes, and estimated a modest port; it also found that
  rustls's own RustCrypto example provider had been removed from its main
  branch, which leaves no upstream pure-Rust provider to follow for 0.24.
  The approved text does not name 0.24: the port follows from owning the
  provider (T1), and is recorded as that.

### Not decided here

- The seeder clients' trust in the compiled-in `webpki-roots` alone,
  where dcrd's client uses the platform's store (`PARITY.md:2997`), is a
  decision of its own.
- Which source the provider's random numbers come from, where ring draws
  its own today.
- The provider crate's final name, and the constant-time check's method.

## Consequences

- **C leaves the network surface** with the switch. ring's ~151k lines
  go (`dependency-ledger.md:51`), and with them `getrandom` 0.2 and
  `windows-sys` 0.52, which only ring pulls in, and `deny.toml`'s two
  skip entries for them (`deny.toml:42-48`). `fuzz/Cargo.lock` changes
  with the workspace's.
  The project owns the provider's glue, about 2k lines by estimate, the
  port to rustls 0.24, and keeping its suites, groups and order in step
  with the reference Go.
- **Hybrids for Go clients.** Once T3 lands, a Go client such as dcrctl
  or dcrwallet negotiates a hybrid with the port as with dcrd. The
  entries for the classical key exchange close (`PARITY.md:2953-2986`,
  `SECURITY.md:157-170`), and with them the exposure they describe: RPC
  sessions recorded on a non-local `--rpclisten` open to later
  decryption.
- **The pre-check moves with the provider.** At the switch the replay's
  `sig_algs` (`rpcrun.rs:4035-4037`) and the verifier over the whole pool
  take the provider's algorithms, and the comments that name ring
  (`:3270-3282`, `:3519-3522`) change with them. T4's wider set then
  changes which cases PARITY.md lists as ones Go verifies and the port
  cannot (`PARITY.md:2818-2834`): P-521 keys, ECDSA with SHA-512 and RSA
  keys of 1024 to 2047 bits leave that list, and what stays is outside
  the three named cases or outside the provider, such as a signature
  BIT STRING with unused bits.
- **The seeders are checked with the same set**
  (`rustls-0.23.46/src/client/builder.rs:51-61`), so T4 widens what their
  chains may use too; that this moves seeding nearer Go's client is an
  inference, not checked.
- **An operator with an RSA `rpc.key`**, which dcrd and the port accept
  today, has to replace it after the switch; `gencerts` writes none.
- **Tests change with the switch:** 39 of the 46 uses of ring's provider
  are in tests, and one asserts that ring has no P-521 verification
  (`crates/dcroxide-node/tests/rpclisten.rs:1023-1026`), a premise T4
  removes.
- **Binaries wait on it.** Meeting ADR-0012's rule, which takes `ring`
  out, is one of the four conditions the project owner set on 2026-10-26
  for publishing any binary (D7, [ADR-0014](0014-release-engineering.md)).
- **Speed is not measured.** In an old third-party benchmark of older
  crate versions, RustCrypto ran about 5 times behind ring on AES-256-GCM
  and 4 to 8 times behind on P-256; nothing was benchmarked here, and no
  benchmark covers the versions the provider will use. At RPC volumes the
  research put the cost at about 0.1 ms a handshake.
- **Audits, as the research found them:** RustCrypto's NIST curve crates
  and `ml-kem` say they were never independently audited; `aes-gcm` and
  `chacha20poly1305` had one review in 2020, of older versions;
  `curve25519-dalek` was audited in 2019. No published audit of ring was
  found either, though it carries BoringSSL's lineage and wide
  deployment. T10's items are what bound this.

## Alternatives

As the research read them on 2026-10-26:

- **graviola.** The fastest candidate, but it fails ADR-0012's
  definition, builds for two architectures only, panics on older
  processors with no public check beforehand, and lacks P-521 and the
  P-256 and P-384 hybrids, so the node would carry a second crypto stack
  for those.
- **rustls-rustcrypto from its git master.** The same crates as the
  in-tree provider, but unreleased code with open defects and without
  P-521 or the hybrids, which the node would have to patch on top of a
  project with fixes for some of those defects still in unmerged pull
  requests.
- **Keeping `ring` as a recorded exception.** No work, but C stays in the
  binary and the hybrids stay missing. It is the interim state only, as
  the Status records.
- **The `rsa` crate**, for verification (T5) or, behind an explicit
  opt-in, for RSA server keys (T6): declined for the reasons under T5 and
  T6.
- **`libcrux-ml-kem` for the hybrids.** Pre-0.1; it claims formal
  verification, and a third-party analysis of 2026-02 disputed parts of
  that claim. `ml-kem` comes from the same family as the rest of the
  provider.
- **Dropping `ureq` in the switch itself.** A larger switch; T7 keeps
  ureq through it and replaces both clients afterwards.
