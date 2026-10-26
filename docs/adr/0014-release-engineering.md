# ADR-0014 — D7: Release engineering

- **Status:** Accepted 2026-10-26 as policy (decision D7), approved by the
  project owner with the other recommendations of that day. Nothing it
  describes is built: no binary is published until the four conditions of
  part 2 hold; the release workflow, the reproduction script and the
  changes listed under Consequences are pending; and part 6 leaves two
  questions for the first release.
- **Date:** 2026-10-26

## Context

The project brief (§9) asks D7 to settle the MSRV, a platform tier list
("match dcrd: Linux/macOS/Windows first-class") and the approach to release
signing and reproducibility. Its Phase 15 asks for "reproducible builds,
signed artifacts matching Decred's binary-verification culture" (§6), and
M5's acceptance column ends in "reproducible signed release" (§11). Since
`2fd991b` (2026-08-07) the D7 entry in the ADR index has made this ADR a hard
gate before any binary is published, and has required it to decide the
pre-1.0 stale-binary question explicitly, in that entry's words "a
Cuprate-style expiry or a recorded refusal".

**What exists.** No tag and no release; `.github/workflows` holds only
`ci.yml`. Of the release engineering, only `[profile.dist]` and
`panic = "abort"` exist (the brief's status block, "Release engineering,
partial"). `dist` inherits `release` and sets `strip = "debuginfo"`, and is
"the profile release artifacts are cut from" (`Cargo.toml:93-112`). The
toolchain is pinned at 1.98.1 (`rust-toolchain.toml:17-19`), and the
workspace `rust-version` names the same release (`Cargo.toml:43-48`). That
has held since `d2bcb31` (2026-09-15), which also removed the `msrv` CI
job, since with the floor on the pinned release it repeated the lint
build. Before it the workspace kept an older floor, checked by that job:
1.85, then 1.88 from `5f5e8ea` (2026-07-08), with no `rust-toolchain.toml`,
then 1.94 under a 1.97.1 pin from `08ab843` (2026-08-05), whose message
records that the floor had drifted nine releases behind stable, "holding
the MSRV-aware resolver back across 226 locked dependencies". The pin takes
a point release rather than a `.0`, citing miscompilations in 1.97.0 and
1.98.0 (`rust-toolchain.toml:10-13`). Many Rust minors never get a `.1`,
so that rule as written can block a bump indefinitely.

**Where the evidence is.** CI runs `cargo test --workspace` on four
runners: `ubuntu-latest`, `ubuntu-24.04-arm`, `macos-latest` (taken to be
arm64, not checked here) and `windows-latest` (`ci.yml:65-92`). The
fault-injection tests in that run are Linux-only, so they run on the two
Linux legs (`:16-25`). Everything else runs on x86_64 Linux only: rustfmt
and clippy, the suites with overflow checks off as the release profile
computes (`:94-124`), the live dcrd interop test (`:126-180`), the no_std
check, docs, deny and fuzzing. No job builds the workspace's `release` or
`dist` profile on any target, so the configuration that ships (thin LTO,
`codegen-units = 1`, `panic = "abort"`) has never been compiled in CI.
Every timed sync ran on x86_64 machines (m1 to m3,
`docs/bench-ledger.md:28-30`), none on Windows or macOS
(`README.md:694-695`), and none on aarch64 of any OS. Ecosystem acceptance
has been run once, on x86_64 Linux, without Decrediton's IPC lifecycle or
config, IPC and service parity on Windows and macOS (the brief's status
block), so the exit criterion that Decrediton launches, supervises and
cleanly stops the daemon over IPC on all three OSes (brief §6, Phase 14) is
unmet, and with it M4's.

**Reproducibility has been claimed, not checked.**
`docs/operating.md`'s "Running it" said, until this change, that the pinned
toolchain makes artifacts "reproducible from the same source", and the D7
entry has called reproducible-artifact verification "attainable" from the pin
and `codegen-units = 1`. No record in the repository compares two builds. A
release-profile `dcroxide` built on 2026-10-24 on an x86_64 Linux development
machine, from a commit not recorded, was examined on 2026-10-26:

- its `.rodata` holds 255 absolute host paths, 214 under
  `$CARGO_HOME/registry/src` and 41 in the 1.98.1 toolchain's `rust-src`
  tree (`std`, `alloc` and `core`); none points into the checkout;
- it links `libc.so.6`, `libm.so.6` and `libgcc_s.so.1`, needs glibc symbol
  versions up to `GLIBC_2.39`, and carries a GNU build ID.

Inference: `strip = "debuginfo"` does not touch `.rodata`, so a `dist`
build keeps those paths, and since `rust-toolchain.toml` lists only rustfmt
and clippy (`:19`), a builder without `rust-src` embeds different ones.
Nothing in the tree sets `--remap-path-prefix`, and cargo 1.98.1 rejects
the `trim-paths` profile key as "not stabilized in this version of Cargo"
(checked 2026-10-26 against a throwaway manifest). The host C compiler is
an input too: through the `cc` crate (1.5.1 in `Cargo.lock`) it builds
`secp256k1-sys`, about 67k lines of C, and `ring`, about 151k lines of C
and assembly, and blake3's build script probes it
(`docs/dependency-ledger.md`, the rows for each).

**Stale binaries.** There is no expiry code, and dcrd has none to port.
The argument the D7 entry has carried since `2fd991b`: the threat model is
Decred's, not Monero's. A consensus-divergent node cannot sustain a
competing chain without ticket votes, so a stale pre-release isolates
itself rather than splitting the network, and the harm concentrates on its
own operator: a voting wallet or VSP behind a wedged node misses votes.

**Decisions of the same day that this one builds on.**
[ADR-0012](0012-pure-rust.md) adopts the pure-Rust rule for what ships and
what `cargo test` builds, to be enforced by `cargo-deny` bans on crates that
build C and by a CI build with no C compiler, which ADR-0012 reads as none
that a build script can reach; under it, D3 moves ECDSA from libsecp256k1 to
`k256` behind the differential-fuzz soak that ADR-0006 named as its gate
(ADR-0006's addendum of 2026-10-26), and
[ADR-0015](0015-tls-crypto-provider.md) replaces `ring` with an in-tree TLS
provider; and [ADR-0013](0013-upstream-tracking-release-tags.md) has the pin
follow dcrd's release tags once v2.2.0 is tagged. Together they supply three
conditions of the publication gate below. The rule's checks, the move to
`k256`, the provider and the soak are not built yet, and the pin is still on
dcrd master.

## Decision

### 1. The MSRV is the pinned toolchain

- The workspace `rust-version` (`Cargo.toml`) and the `channel` in
  `rust-toolchain.toml` name the same release and move in the same commit:
  every pin move is an MSRV bump. There is no older floor and no `msrv`
  job, so the MSRV-aware resolver chooses dependencies for the compiler the
  suites run on.
- The pin takes a point release. **Fallback:** a `.0` that never gets a
  point release becomes eligible once the next minor ships without a point
  release for it. If 1.99.0 has no 1.99.1 when 1.100.0 is released,
  1.99.0 is eligible from that day; 1.100.0 is not, until it has a `.1` or
  1.101.0 ships without one for it. Eligibility permits a move and never
  forces one. The approval called for a rule without naming its trigger;
  this condition is this record's reading.
- Not decided here: an older floor for library crates, which only
  publishing them to crates.io would call for. No crates.io release is
  recorded.

### 2. No binary before the gate; then x86_64 Linux alone

No binary is published, for any target and from any workflow, until all
four of these hold:

1. **The pure-Rust rule is met:** ADR-0012's rule holds and its two checks,
   the `cargo-deny` bans and the CI build without a C compiler, pass.
   Today four things break it: `secp256k1-sys`, which goes with D3's move of
   ECDSA to `k256`; `ring`, which goes once the in-tree TLS provider of
   ADR-0015 passes its interop matrix against Go; blake3's build-time
   compiler probe, which goes with an in-tree BLAKE3; and the C power-cut
   shim, which goes with its rewrite in Rust.
2. **The D3 soak has passed:** oracle-backed differential fuzzers for all
   three signature types, aimed at named input classes, have run to the
   floors ADR-0006's 2026-10-26 addendum records against the backends the
   node ships, and the ADR that supersedes ADR-0006 records the result.
3. **The pin is at a dcrd v2.2 release tag,** not a master commit. It is
   at master `3360ae4d` (2.2.0-pre) today.
4. **The reproduction prototype has passed** (part 4).

Until then the node is built from source. A release workflow can be built
and run through `workflow_dispatch` without publishing anything, and the
prototype needs one.

Once the gate is open, the tiers are:

| tier | targets | what it means |
|---|---|---|
| 1 | x86_64 Linux | published binary, CI, the signing and reproduction rules of parts 3 and 4 |
| 2 | `aarch64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc` | CI-tested, built from source, no binary |
| 3 | everything else (Intel macOS, Windows on arm64, the BSDs and 32-bit targets among them) | no claim |

The approval names aarch64 Linux, macOS and Windows, not the architectures
of the last two. This record reads them as the ones CI's runners test
today, `macos-latest` (taken to be arm64) and `windows-latest` (x86_64).
That reading leaves Intel macOS and Windows on arm64 in Tier 3, with no
path to promotion; whether they join Tier 2 is not decided here.

x86_64 Linux is Tier 1 because it is the only target with the full
evidence: the timed syncs, the live interop test, the overflow-off suites
and ecosystem acceptance, beside the fault-injection tests it shares with
aarch64 Linux. Whether its binary is `x86_64-unknown-linux-gnu` against an
older glibc or static `x86_64-unknown-linux-musl` is open (part 6). Its
`dist` build is first compiled by the release workflow and the prototype.

A Tier 2 target is promoted to Tier 1 on its own, in a dated addendum here,
once all of these hold for it:

- a CI job builds the `dist` profile, which inherits `release`, on that
  target and runs the overflow-off suites there;
- one mainnet sync has been timed on that architecture and OS and recorded
  in the bench ledger;
- for macOS and Windows, the M4 check that Decrediton launches, supervises
  and cleanly stops the daemon over IPC passes there.

A promoted target's binary falls under parts 3 and 4 like any other, so it
is published only once its off-GitHub rebuild matches. Inference: Apple-
and MSVC-built artifacts are harder to reproduce off GitHub than a Linux
one, so that rebuild may hold back those two promotions. Platform code
signing, Apple's or Windows', is not decided here.

### 3. Signing: the project owner's two signatures, and attestations

- **The tag.** A `v*` tag signed by the project owner with the SSH key that
  signs this repository's commits, made by hand and pushed by name. The
  release workflow builds from that tag and never creates one.
- **`SHA256SUMS`.** The workflow writes one `SHA256SUMS` covering every
  asset onto a draft release. That file is the one signed, never
  regenerated, and no asset of a release is ever replaced.
- **The signature over it.** After part 4's rebuild matches, the project
  owner signs `SHA256SUMS` by hand with an OpenPGP key, as a detached
  armoured signature uploaded beside it. Neither key ever enters CI, so a
  compromised workflow could publish an artifact but could not sign it.
  The draft is then verified as a stranger would verify it and published,
  marked as a pre-release, on the project owner's word.
- **Attestations.** The workflow also attests each artifact with GitHub's
  `actions/attest-build-provenance`, which ties it to the workflow run and
  the commit that built it and is verifiable with `gh attestation verify`.
  The job needs `id-token: write` and `attestations: write`. Attestations
  add to the signatures and the rebuild and replace neither.
- **Not decided here:** whether the release workflow uses only GitHub-owned
  actions, each pinned to a full commit SHA, and restores no cache, where
  `ci.yml` pins by tag and uses third-party actions (`ci.yml:44`, `:59`,
  `:214`, `:238`); and where the two fingerprints, the SSH key's for tags
  and the OpenPGP key's for `SHA256SUMS`, are published with the
  verification steps, `SECURITY.md` and the README being candidates.

### 4. Reproducibility: a double build in CI, and a rebuild off GitHub

Two checks, both required for every published artifact:

- **In CI.** The release workflow builds every artifact twice, in separate
  jobs with different checkout paths, and fails on any byte difference.
  That catches nondeterminism. It cannot catch a compromised workflow or
  runner, since both builds share GitHub's environment.
- **Off GitHub.** Every artifact is rebuilt off GitHub, on the project
  owner's side, from the signed tag, in the build environment the workflow
  uses, pinned by digest, and the project owner signs `SHA256SUMS` only if
  every rebuilt artifact matches its line. A mismatch means no signature.
  The signature then means that the artifacts were reproduced
  independently from the signed tag, not only that CI produced them.

What this needs, none of it done:

- **Path remapping.** `--remap-path-prefix`, through `RUSTFLAGS`, for the
  registry sources and the `rust-src` tree, or identical absolute paths
  and toolchain components in both environments, since `trim-paths` is
  not stable on 1.98.1.
- **A pinned build environment.** The linker and the C library, and until
  the pure-Rust rule is met the C compiler, come from an image pinned by
  digest. The pure-Rust rule takes the C compiler out of what has to be
  pinned for code: once the four breaches of ADR-0012 are gone no crate's
  C reaches the binary and no build script runs a C compiler for a target
  the project builds for. The linker driver and the C library stay inputs
  whatever the crates are, since rustc links through `cc` on Linux
  (ADR-0012) and the binary links glibc on a `-gnu` target.
- **Deterministic packaging:** a bare binary, or an archive with fixed
  times, owners and order.
- **A reproduction script** under `tools/`, and the runbook in the release
  workflow's header comment.

**The prototype that gates publication** (part 2, condition 4): two `dist`
builds of one commit, at different paths, one on a GitHub runner and one
off GitHub, byte for byte identical.

This supersedes the D7 entry's sentence that the pinned toolchain and
`codegen-units = 1` "already make reproducible-artifact verification
attainable". The pin is necessary and not sufficient: host paths, the C
toolchain, the linker and the C library are inputs too. Inference:
`codegen-units = 1` is there for speed (`Cargo.toml:52-53`) and is not
needed for deterministic output.

### 5. Stale binaries: no expiry

No binary carries an expiry date or a refusal to start after a date. The
reasons:

- **The threat model.** A stale binary on the far side of a rule change
  isolates itself rather than splitting the network, because a chain
  without ticket votes cannot be sustained. Its harm falls on its own
  operator. An expiry would wedge every voting wallet or VSP behind such a
  node on a known date, turning a conditional harm into a certain one.
- **The audience.** Those operators are the ones `SECURITY.md` tells not to
  point a wallet at this node at all (`:8-12`).
- **Parity.** dcrd has no expiry, so one would be a divergence.

The case the refusal leaves open, by inference: an agenda that only
tightens the rules leaves a stale node following the chain without
enforcing the new rule, rather than isolating it. The mainnet rule-change
interval is 8,064 blocks, about four weeks (`2016 * 4`,
`crates/dcroxide-chaincfg/src/mainnet.rs:162`; dcrd's
`chaincfg/mainnetparams.go:153`), which by inference leaves at least that
long between a vote passing and the rule activating for release notes to
reach operators.

Mitigations, each due with the first release:

- every release is marked as a pre-release on GitHub;
- only the latest release is supported; `SECURITY.md` says today that there
  are no supported versions (`:14-16`);
- release notes name the dcrd pin and the agendas the binary knows;
- `--version` shows the build's identity. Today it prints
  `dcroxide version 2.2.0-pre`
  (`crates/dcroxide-node/src/bin/dcroxide.rs:280`), and the commit is left
  out on purpose (`crates/dcroxide-node/src/version.rs:1-9`).

Not decided here: a warning once a binary reaches some age, which stops
nothing, and a log warning when the network's stake version passes the
newest deployment the binary knows. dcrd has neither, so each would be a
recorded divergence in PARITY.md.

### 6. Open for the first release

- **The Linux C library.** An older-glibc build image, whose glibc becomes
  the floor (the binary examined under Context needs `GLIBC_2.39`), or
  static musl, which matches dcrd's "static binary" (dcrd's `README.md:196`
  at `3360ae4d`). musl brings its own allocator, and the sync is sensitive
  to the allocator: `88c46c3` with jemalloc preloaded synced in 339.4 and
  341.4 s against controls of 391.1 and 395.8 s
  (`docs/bench-ledger.md:90`). An allocator crate would be a dependency
  addition, which needs an ADR (brief §8), and under the pure-Rust rule it
  could not be one built from C.
- **The release's version identity.** A tag such as `v0.1.0`, the
  workspace version (`Cargo.toml:40`), would not match what the binary
  prints, `2.2.0-pre`, or the `dcroxide:2.2.0(pre)` its user agent carries
  (`user_agent_version`, `crates/dcroxide-node/src/version.rs:55-58`, with
  the pre-release as its comment). dcrd's release branches set the build
  metadata to `release.local` so that source builds stay distinct from
  reproducible builds, which override the version through `-ldflags`
  (`internal/version/version.go:34-53` at `3360ae4d`). The choice is to be
  made together with the PARITY.md gap "`version` reports an empty
  `buildmetadata` on a live node", which turns on the same build metadata,
  and has to come out the same in both builds of part 4.

## Consequences

- Binaries depart from the brief's D7 recommendation, Linux, macOS and
  Windows first-class: one target first, others by promotion. CI keeps
  testing on all three OSes, so the brief's intent holds at the source
  level. dcrd provides binaries "for common operating systems and
  architectures" (dcrd's `README.md:115` at `3360ae4d`); this node, at
  first, for one.
- The first release workflow is small: one target, no Apple or Windows
  signing, and every published artifact under the off-GitHub rebuild.
  Inference: with no asset arriving late, the workflow can write
  `SHA256SUMS` itself.
- Until the gate opens everyone builds from source, and after it everyone
  off x86_64 Linux does, with the pinned toolchain. Inference: a
  distribution whose packaged rustc lags the pin cannot build the node
  with it.
- Each promotion needs a sync timed on that architecture and OS, and none
  has been timed on aarch64, Windows or macOS (`README.md:694-695`,
  `docs/bench-ledger.md:28-30`): it needs such a machine, or a CI runner
  with room for a mainnet data directory, a median of 27.93 GiB after the
  syncs of 2026-10-17 (`README.md:706-708`). Runner disk sizes were not
  checked.
- Each release costs an LTO build per target off GitHub and two signatures
  by hand, and checking both the tag and the binaries takes two keys.
- M5's "reproducible signed release" stays open until the first release
  made under this ADR.
- Pending, none of it written: the fallback rule in `rust-toolchain.toml`'s
  header; `docs/operating.md`'s `cargo build --release` (`:1870-1872`),
  where artifacts are cut from `dist`; `SECURITY.md`'s supported versions;
  the fingerprints and verification steps, wherever part 3's open question
  puts them; the brief's status block; `.github/workflows/release.yml`
  with its runbook; the reproduction script; and the PARITY.md
  `buildmetadata` entry, with part 6. The change that records this ADR
  stops `docs/operating.md` calling D7 open and claiming reproducibility.
