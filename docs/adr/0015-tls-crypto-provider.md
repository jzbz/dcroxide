# ADR-0015 — TLS crypto provider: an in-tree provider on RustCrypto

- **Status:** Accepted 2026-10-26. Step 1 is under way:
  `dcroxide-tlscrypto` holds the nine cipher suites' record protection,
  the four key exchange groups, the signing keys and ring's fourteen
  verification algorithms, RSA among them verified in tree (T5), put
  together in its `default_provider`; the node takes only its P-521
  group and its P-521 signer, which `ring` lacks. `ring` stays the
  node's TLS provider for everything else until the in-tree provider
  passes the Go interop matrix: every cipher suite, key exchange group,
  key type and TLS version, plus client certificates, which is in the
  tree (addendum of 2026-10-30). Then `ring` goes in one change. The
  constant-time check T10 names is in the tree as well (addendum of
  2026-10-31).
- **Date:** 2026-10-26 (accepted), 2026-10-30 (addendum: the Go interop
  matrix), 2026-10-31 (addendum: the constant-time check)

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
   (`src/seeding.rs:78`) goes through `ureq` 3.4.2, which picks a
   provider when it first builds its configuration: the one its
   `TlsConfig` names, else the process default, else ring when its
   `_ring` feature is on, else a panic
   (`ureq-3.4.2/src/tls/rustls.rs:137-160`). Under `--proxy`,
   `ProxySeederTransport` (`seeding.rs:165`) runs rustls itself over a
   configuration built on ring's provider (`seeder_tls_config`,
   `:251-267`). Both check the seeder's chain with the provider's
   verification algorithms (`rustls-0.23.46/src/client/builder.rs:51-61`).

`rustls::crypto::ring` was named 46 times in seven files of
`dcroxide-node` when this was accepted, and is named 47 times in eight
since the matrix's addendum, whose `tests/tls_interop.rs` names it once,
in a regeneration the switch deletes. Seven of those uses are outside
tests (`rpctls.rs:98`, `:180`, `:292`; `rpcrun.rs:4035`, `:4421`,
`:4480`; `seeding.rs:72`).

### How `ring` arrives

No workspace crate depends on the `ring` crate directly; the node
reaches it only through rustls's `crypto::ring` module. It arrives
through two feature switches. `dcroxide-node` turns on rustls's
`ring` feature (`crates/dcroxide-node/Cargo.toml:64-69`), which turns on
`rustls-webpki`'s as well (`rustls-0.23.46/Cargo.toml:88-91`). And the
node asks for `ureq` with its default features, `"3"` when this was
accepted and `"=3.4.2"` since the matrix's addendum
(`crates/dcroxide-node/Cargo.toml:86`), whose `rustls` feature turns on
`_ring`, that is `rustls?/ring` (`ureq-3.4.2/Cargo.toml:63`, `:74-77`,
`:101-105`). Cargo unifies features across the build, so `ring` leaves
only when both switches change; either alone brings it back. `fuzz/`,
outside the workspace with a lock of its own, takes the node's whole tree
through `dcroxide-node` (`fuzz/Cargo.toml:21-24`) and locks `ring` too
(`fuzz/Cargo.lock:1414`).

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
`Cargo.lock:839-840`), and it carries RUSTSEC-2023-0071, the
timing advisory `gencerts` already cites (`gentool.rs:12-15`). That
advisory concerns private-key operations, which verification does not
run; this is the research's reading, and the advisory was not re-read for
this record. The choice is revisited when the `rsa` crate's current line
is stable.

### T6 — an RSA server key is refused

An RSA `rpc.key` is refused at startup with a clear message, and
PARITY.md records the divergence; neither is done yet. dcrd accepts such
a key. ring signs with one of 2048 to 4096 bits with an exponent of at
least 65537 today (`ring-0.17.14/src/rsa/keypair.rs:268-285`), and the
listener already refuses any other at startup, in ring's words for a key
none of its signers loads, a narrower divergence PARITY.md records since
the matrix's addendum; for those keys the switch changes only the
refusal's text. The only pure-Rust RSA signer is the `rsa` crate, and
its advisory is about the private-key operations a signer runs, which is
why `gencerts` already refuses RSA (`gentool.rs:12-15`). This record
reads the refusal as landing with the switch, the change that takes away
the only signer of an RSA key; until then ring serves the keys it loads
as it does now. A certificate rotation loads the key through the same
function (`rpcrun.rs:2154`), and this record reads "at startup" as
naming where the daemon stops, not as limiting the check: a rotated-in
RSA key meets the same refusal.

### T7 — the seeder's HTTPS clients

For the switch, `ureq` stays, with the provider handed to it explicitly
through `TlsConfigBuilder::unversioned_rustls_crypto_provider`, reached
through `TlsConfig::builder()` (`ureq-3.4.2/src/tls/mod.rs:296-302`), so
that a run under `--norpc` or `--notls`, which installs no process
default, never reaches ureq's panic. ureq says that call is not guaranteed
for semver (`mod.rs:246-254`).
While the node relies on it, ureq is pinned to an exact version, where
the manifest asked for `"3"` when this was accepted (the matrix's
addendum pins it); this record takes the pin from the research's
condition on keeping ureq, since the approved text names only the
unstable API.

Afterwards one small in-tree client replaces both seeder clients. It
closes the redirect gap PARITY.md records on the proxy path, whose client
follows no redirects and decodes no chunked transfer encoding
(`PARITY.md:940`; `seeding.rs:158-164`), drops `ureq` and `ureq-proto`,
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
  (`tools/oracle/main.go:1594`).
- **A constant-time check on the signing and key-exchange paths.** Its
  method is not set here.

### Known limits

- **Go's four TLS 1.2 CBC suites stay a recorded gap**
  (`PARITY.md:2988-2995`). rustls's TLS 1.2 key block has no place for a
  MAC key (`rustls-0.23.46/src/crypto/cipher.rs:110-134`), so no provider
  under rustls can offer them. Every client the Decred tools ship offers
  an AES-GCM suite (`PARITY.md:2994-2995`).
- **rustls 0.24 is unreleased.** The provider is written against 0.23,
  the line the node is on (0.23.46, `Cargo.lock:1528-1529`), and is ported
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
- **An operator with an RSA `rpc.key`** of 2048 to 4096 bits with an
  exponent of at least 65537, which dcrd and the port accept today, has
  to replace it after the switch; one outside those bounds, which dcrd
  serves, the port refuses already (T6). `gencerts` writes none.
- **Tests change with the switch:** 39 of the 46 uses of ring's provider
  were in tests when this was accepted, and 40 of the 47 are since the
  matrix's addendum; one asserts that ring has no P-521 verification
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

## Addendum, 2026-10-30 — the Go interop matrix

The matrix T10 names, the one the switch waits on, is in the tree. This
records what it holds and what each cell asserts. It records no result:
CI first runs it once the change that adds it is pushed, and the
switch's addendum cites those runs, with each system's times.

- **The oracle's TLS commands.** `tls_pki` makes certificates with Go's
  `x509.CreateCertificate`, each with the key, issuer, signature
  algorithm, basic constraints, extended key usages, names and validity
  asked for, generating EC and Ed25519 keys and taking RSA keys from the
  test-key fixture, never generating one. `tls_dial` makes one
  connection with Go's `crypto/tls` client, configured as asked, and one
  HTTP request over it. `tls_listen` starts a Go server on 127.0.0.1 that
  serves one connection in the background, and `tls_listen_result` gives
  what it saw, its peer's certificates, the chains Go verified them to
  and the first ClientHello among it. The answers come in a new `detail`
  field, the connections' with the version, cipher suite and key exchange
  by Go's names and whether there was a HelloRetryRequest. Go dials and
  listens on loopback alone, with one deadline over every accept,
  handshake, read and write. Each command refuses a field it does not
  name, since a misspelled one would leave Go's default in its place, the
  baseline the cells compare with; a TLS 1.3 suite name, which
  `crypto/tls` does not configure; and a client certificate without an
  HTTP request, since a TLS 1.3 server refuses one only after the
  client's handshake is done. The commands read `ConnectionState.CurveID`
  and `ConnectionState.HelloRetryRequest`, which Go 1.25 and 1.26 added,
  where the module's line stays `go 1.24.0` for the other commands'
  GODEBUG defaults, so they live in `tools/oracle/tls.go`, built by Go
  1.26 or later, and `tls_old.go` answers them with an error under an
  older Go. Their tests run each against the others, and every way a
  request can be refused. The interop tests start the oracle with
  `GODEBUG=tlssecpmlkem=1,tlssha1=0,x509sha256skid=1,cryptocustomrand=0`
  (`DCRD_TLS_GODEBUG`): dcrd's values at the parity pin for the four
  crypto, `crypto/tls` and `crypto/x509` settings among the eight where
  its `default=go1.26` differs from that line, so Go's default client and
  server are dcrd's, the three hybrids first. The oracle's own TLS tests
  use the same string, which a test holds equal.
- **The harness both matrices share,** `dcroxide-testutil`'s
  `tls_interop` module, on its new `oracle_or_skip_with_env`: the oracle
  under that GODEBUG, skipped, or failed under `DCROXIDE_REQUIRE_ORACLE`,
  where its Go is older than 1.26; certificates from `tls_pki`; Go's
  report of what a connection negotiated; and the client-certificate
  cells with each one's verdict today, so that T4 changes them in one
  place. A refusal is held to Go's words for it only when the oracle runs
  the reference Go, go1.26.2; under another Go only to its being a
  refusal, so that a newer toolchain still tests interop.
- **The provider's matrix,** `crates/dcroxide-tlscrypto/tests/go_interop.rs`:
  rustls configurations built from `default_provider` alone, cut to the
  suites, groups or signature schemes of a cell. Go's client against the
  provider's server, 155 handshakes: TLS 1.3's three suites, forced on
  the server, and TLS 1.2's three ECDHE-ECDSA suites, each by the four
  groups by the server keys P-256, P-384, P-521 and Ed25519; a
  HelloRetryRequest; client keys P-256, P-384, Ed25519 and RSA-2048, each
  a self-signed leaf and under a P-256, P-384, RSA-4096 (SHA256-RSA and
  SHA256-RSAPSS) and Ed25519 CA, in each version; and refused, a P-521
  client key, an issuer signing with ECDSA-SHA512, an RSA-1024 client
  key, ECDHE-RSA suites against an ECDSA key, a CBC suite and no group in
  common. The provider's client against Go's server, 181 handshakes:
  TLS 1.3's suites by the groups by the server keys P-256, P-384, Ed25519
  and RSA-2048, -3072 and -4096, and TLS 1.2's ECDSA and RSA suites by the
  groups by the keys of their kind; each RSA signature scheme alone in
  each version that has it; an RSA-4096 root over an RSA-2048
  intermediate over a P-256 leaf, the seeders' shape, under four
  signature algorithms, a P-384 root over a P-256 leaf and an Ed25519
  chain; refused, a P-521 server key, a P-521 root and RSA-1024 and
  RSA-8193 intermediates; and the provider's client certificates on
  P-256, P-384, P-521 and Ed25519 keys. A completed cell asserts that
  both ends report one version, suite, group and HelloRetryRequest, the
  cell's version and, where it names them, its suite, group and
  HelloRetryRequest, and an HTTP request answered over it; a refused
  cell, the refusing end's rustls error and Go's refusal. Each refused
  cell's rustls error was checked once against ring's, in a local run of
  the matrix with ring's provider put in for this one while ring is in
  the tree, which gave the same error in every refused cell it can run,
  all but those whose keys are P-521. The rustls end of a failed
  connection closes it only once its peer has, so that its alert is not
  lost to a reset. The refusals are today's feature level (the provider
  verifies no P-521 or SHA-512 ECDSA and no RSA key outside 2048 to 8192
  bits), and T4 turns the client-certificate ones into completed cells.
- **The node's matrix,** `crates/dcroxide-node/tests/tls_interop.rs`:
  production code alone, `start_rpc_listener` over `reloadable_tls_config`
  and both seeder transports, so the same file runs on ring's provider
  and on this one. Go's client against the RPC listener, 213 handshakes:
  server keys P-256 and P-521 from certgen, P-384 and Ed25519 from
  gencerts and RSA-2048 from the fixture, by fourteen client profiles
  (Go's default, TLS 1.2, each group alone in each version, each TLS 1.2
  suite of the key's kind alone, and a SecP384r1MLKEM1024 share with
  P-256 and no P-384), each a `getblockcount` answered 200 and compared
  with Go's server holding the same pair: one cut to the listener's
  classical groups agrees on every cell, and one on Go's default list on
  every cell but those of the two profiles where it takes a hybrid, which
  the test asserts as PARITY's classical key exchange entry records; and
  the fixture's RSA-1024, RSA-8192 and e = 3 keys, which ring's signer
  does not load, each refused by the listener at startup in ring's words
  and served by Go's server, as dcrd serves them, which PARITY's RSA
  `rpc.key` entry records. Under
  `--authtype=clientcert`, 108 handshakes: the shared client certificates
  through `GoClientCertVerifier` and Go's server alike, in each version;
  the 48 accepted cells accepted by both, and the three refused today
  refused by the listener in its handshake, each with the alert Go's
  client reports for it and no HTTP answer, where the reference Go's
  server accepts them, as PARITY's client-certificate entry records; the
  listener's count asserted, and under the reference Go, Go's server's.
  The seeder transports against Go's HTTPS server, 73 handshakes: P-256,
  P-384 and Ed25519 keys and the seeders' RSA chain, in each version,
  under each group alone, P-521 refused since the seeders offer ring's
  three, with the addresses read through `seed_addrs`; in each version,
  the daemon's own constructors, which trust `webpki-roots`, and the test
  constructors given a root that did not issue the chain, each refusing
  the chain as an unknown issuer; and for ureq, whose client dials a
  name where the proxy's needs a proxy to, a seeder named `localhost`.
  Each ClientHello Go's server saw equals
  `tests/data/seeder-client-hello.json`, recorded from a run on ring's
  provider to a seeder named by its address: suites, groups, signature
  schemes and versions in order and extensions as a set, since rustls
  orders them at random, with the server_name extension added for the
  seeder named `localhost`. So the daemon's constructors' provider
  hand-off is compared, though no local chain gets through it. Its
  regeneration holds what it records to ring's provider's lists, so the
  switch, which takes ring out, deletes it. In TLS 1.3 Go's server sees a
  seeder's refusal as the connection's end with no alert: rustls makes
  one write after a failed handshake, and both transports' connections
  write one buffer a call, so the middlebox-compatibility ChangeCipherSpec
  queued ahead of the alert goes and the alert does not. The RSA-2048
  `rpc.key` is served today; T6 refuses it at the switch, which flips
  that cell, `RSA_RPC_KEY_SERVED`, and no other, pins T6's refusal text
  in its branch, which also has Go's server serve the pair, puts the same
  text in place of ring's words for the three keys refused today
  (`RSA_KEY_REFUSAL`), and must reproduce the recorded ClientHello. Where
  the node refuses Go's end, off Linux a reset passes for the alert,
  since a system that throws away what it has received when a reset
  arrives would show Go the reset.
- **The seeders' provider hand-off.** Each seeder transport now makes its
  TLS client in one private constructor that takes its roots, `new`, the
  daemon's, passing `webpki-roots`, and `with_root_certs`, the matrix's,
  passing a test chain's root, so the matrix runs the hand-off the daemon
  runs; each kind of roots is turned into each client's form in one
  place, and a unit test holds each constructor to its roots alone and
  both to one provider's lists. Both hand rustls ring's provider
  explicitly from one function, `seeder_crypto_provider`: `UreqTransport`
  through T7's `unversioned_rustls_crypto_provider`, with ureq now pinned
  at `=3.4.2` as T7 asks while the node relies on that call,
  `ProxySeederTransport` through `ClientConfig::builder_with_provider`,
  as before. ureq's fallback (Context, item 3) chose ring's provider for
  `UreqTransport` already, so the daemon's seeders run as they did; the
  switch changes that one function.

Each matrix prints its handshakes and wall time to the test log, which
the switch's addendum reads from CI. The checks every cell rests on, a
completed cell held to what it negotiated, the listener held to both Go
servers and a ClientHello held to its description, have tests of their
own that run without the oracle. What gates the switch: both matrices
green in CI's `test` job on the four systems and in `test-wrapping`, the
provider's again on the portable backends of `tls-soft-backends`, and the
oracle's Go tests in `go-tools`.

## Addendum, 2026-10-31 — the constant-time check

The constant-time check T10 names is in the tree, by the method this
record left open and the provider's design recommended, which the project
owner approved with the design's other answers on 2026-10-26: a dudect
harness in the tree, in a CI workflow of its own. Its verdict departs
from the design's by a floor the project owner added on 2026-10-30
(below). This records what it holds, what each target compares and why
the floor is there. It records no run of the workflow: CI first runs it
once the change that adds it is pushed, and the switch's addendum cites
those runs.

- **The harness,** `crates/dcroxide-tlscrypto/src/ct_check.rs`, built only
  into the crate's unit tests: dudect's fixed-against-random test
  (Reparaz, Balasch and Verbauwhede, 2017), with no crate added and
  nothing to install. A target times one operation with
  `std::time::Instant` on inputs of several fixed classes and one random
  class, interleaved: each sample is of the random class with probability
  1/2, else of a fixed class chosen uniformly, the choice drawn from
  `dcroxide-testutil`'s `SplitMix64`, and Welch's t compares each fixed
  class with the random class. The fixed classes are corner cases of the
  secret, since a fixed value drawn at random gives a leak no more to key
  on than the random class does. A chunk of samples' inputs is built
  before any of them is timed, every class's the same way: from a buffer
  the random class's draw fills, a fixed class's bytes written over it, so
  that what building allocates, and the heap the inputs lie in, does not
  depend on the class. The timed region runs the operations, each on an
  input it borrows, and keeps their results; the inputs and results are
  dropped outside it, but for the exchange that `complete` consumes, as it
  does in the provider. A chunk holds at most 256 KiB of inputs, the heap
  they point to aside, so that an operation finds its input in a core's
  cache, as the provider finds the cipher or key it keeps. An operation
  quicker than 2 µs runs in a batch on inputs of one class, sized from the
  median of 33 operations timed one by one, the clock's own cost included,
  so that a sample takes about 2 µs. The first 1,000 samples, or the first
  tenth of the budget, warm up, set dudect's 100 crops (the samples
  quicker than the warm-up's quantile 1 - 0.5^(10(i + 1)/100)) and are
  thrown away. Each fixed class is compared with the random class
  uncropped and in each crop with 100 samples or more on each side. A
  class fails the target when a comparison's |t| is above 10 and the
  largest difference between the class's mean time and the random class's
  among those comparisons is 1 ns an operation or more; above 10 on
  smaller differences alone it is reported as under the floor, and above
  4.5 it is reported, and both pass; and a target with no comparison of
  that many samples fails too. A class's result is the comparison that
  decides it: for a class that fails, the one of the largest difference
  among those above 10, and otherwise its largest |t|. Each target's row
  gives the class that decides it: of the classes that fail, the one whose
  result has the largest |t|, or else the largest |t| of all. Beside t,
  which grows with the root of the samples, each result gives its effect
  size, the difference of the means in standard deviations, and the
  difference in nanoseconds an operation. The positive control, an
  early-exit comparison of 64 bytes, must fail by the same rule, or the
  run fails; that shows the clock and the measurement see a leak at all,
  not that a run could see a small one, which the effect sizes speak to.
  The crop quantiles are dudect's as recalled for this change; no copy of
  dudect's source was at hand to read them against. The harness's own
  tests drive it with a simulated clock and time nothing, so they run in
  every `cargo test`, beside tests that each fixed class is the extreme it
  is named for and reaches the code it is timed through.
- **The 1 ns floor** changes the verdict the provider's design gave (its
  section 11.2, approved with the method on 2026-10-26), which failed a
  target on |t| above 10 for any fixed class alone. The project owner
  chose it on 2026-10-30, after a run in which a difference far smaller
  than any instruction's cost failed a target. |t| grows with the root of
  the samples, and a quick operation's run at the nightly budget counts
  millions: timed on a 5-CPU x86_64 Linux container on a shared host,
  AES-256-GCM's seal on the portable backends, 586 ns an operation,
  failed one of two 60 s runs at |t| 13.28, each of its three fixed
  classes 0.06 to 0.07 ns an operation slower than the random class (|t|
  12.31 to 13.28, an effect of 0.011 standard deviations), and was
  reported at 8.20 in the other, 0.09 ns slower. A secret-dependent
  instruction path costs a few cycles an operation at least, about 1 ns at
  3 to 5 GHz. The floor is more than ten times that difference. An
  early-exit tag comparison planted in AES-128-GCM's open failed at |t|
  2,720 and 2,819, on 5.31 and 3.20 ns an operation in two runs'
  comparisons of the largest |t|, three times the floor or more. A smaller
  leak, about 4.8 ns a call planted in ECDSA P-256 signing by the key, was
  not found at 10 s or at 60 s: signing's spread, a standard deviation of
  about 3.6 µs, needs a difference of a few hundred nanoseconds for |t| to
  reach 10 in those budgets, a limit of the statistics and not of the
  floor. The floor is judged on the largest difference among a class's
  comparisons above |t| 10, not on the comparison of its largest |t|
  alone: a crop keeps the samples quicker than its threshold, so one that
  cuts into the slower class's times lowers its mean, and often its spread
  more, and the comparison of the largest |t| can show less of the
  difference than the class has, as with the planted tag comparison: 3.20
  ns in a crop at the warm-up's quantile 0.732 in one run, against 5.31 ns
  at 0.989 in the other. What the floor gives up is a class whose
  comparisons above |t| 10 all differ by less than 1 ns an operation, as a
  leak of fewer than about 3 to 5 cycles on a secret-dependent path would:
  the target passes, and its row in the job's summary is marked as
  reported under the floor.
- **The targets,** 27 `#[ignore]` tests. ECDSA signing on P-256, P-384
  and P-521, by the key, with the message and the hedge fixed so that RFC
  6979's nonce follows the key, and by the nonce, with the key fixed,
  through the test-only `sign_with_nonce`, each over twelve scalar
  classes, eleven on P-521, whose top 4-bit window holds its top bit
  alone: 1, 2, 0xff, 2^64 - 1, the top bit alone, n - 1, n - 2, n - 1
  with its bottom half zero and with its top half zero, eight set bits,
  n - 1 with eight of its bits cleared, and n - 1's top window alone. The
  key exchange's `complete`, with the peer's share fixed, and the step
  `start` takes after its draw, which computes the public key: on each
  NIST curve over the same classes, and on X25519 over all zeros and all
  ones, 2^254 and 2^255 - 8 once clamped, and the clamped scalars of low
  and high weight (eight bits set, eight cleared). Ed25519 signing by the
  expanded scalar, 2^254, 2^254 + 8, 2^255 - 8, low and high weight, and
  6L + 2 and 5L - 1, within the clamp, whose residues mod L, which the
  key's arithmetic uses, are 2 and L - 1; and by the nonce, 0, 1, L - 1,
  and low and high weight. Sealing a record with each of the three
  AEADs, by keys of all zeros, all ones and 0x55 and 0xaa in turn, with
  the cipher made ahead as the provider makes one for each traffic key;
  keying AES-128-GCM and AES-256-GCM, AES's key schedule and GHASH's
  key, by the same keys; and opening a record with a tag wrong in its
  first byte and in its last, against a tag wrong at random. HMAC-SHA256
  and HMAC-SHA384, keyed by all zeros, all ones and one bit set. The keys
  are made through `sign.rs`'s test-only module `timing` and the
  exchanges through `kx.rs`'s test-only `exchange_with`; neither is in
  the crate's public API or its build outside tests.
- **The workflow,** `.github/workflows/constant-time.yml`, on pushes to
  `master` and pull requests that touch `crates/dcroxide-tlscrypto/**`,
  `crates/dcroxide-testutil/**`, `crates/dcroxide-crypto/**` (a normal
  dependency of the crate, linked into the timed binary, whose features
  on `chacha20` merge with the AEAD's), `Cargo.lock`, the root
  `Cargo.toml`, `rust-toolchain.toml` or the workflow, nightly, and on
  dispatch: four jobs, `ubuntu-latest` and `ubuntu-24.04-arm` each with
  the backends the crates pick for the processor and with the portable
  ones that `tls-soft-backends`'s cfgs force, each running
  `cargo test -p dcroxide-tlscrypto --release --lib ct_check -- --ignored
  --test-threads=1 --nocapture`, every target for `DCROXIDE_CT_SECONDS`
  seconds, 10 on pushes and pull requests and 60 nightly and on dispatch,
  and putting each target's row in the job's summary.

It is statistical: it sees a difference large enough to show on a runner,
fails only on one of 1 ns an operation or more, and a pass is not a
proof. What is timed is each operation as the provider runs it, public
work included: an ECDSA signature's DER encoding branches on the
signature's leading bytes, which a fixed class repeats and the random
class varies. No target reaches what
`curve25519_dalek_backend` switches, verification's double-base
multiplication. The switch waits on this workflow green on the change
that adds it, as pushed, beside the matrices.
