# ADR-0012 — Pure Rust everywhere

- **Status:** Accepted 2026-10-26. Four things break the rule on that
  date. `secp256k1-sys` goes with D3's move of ECDSA to `k256`, behind a
  differential soak and a speed measurement; `ring` goes once the in-tree
  TLS provider of ADR-0015 has passed its interop matrix against Go;
  blake3's build-time compiler probe goes with an in-tree BLAKE3; and the
  C power-cut shim goes with its rewrite as a Rust library. Neither of the
  two checks that enforce the rule is written yet.
- **Date:** 2026-10-26

## Context

The project owner's rule, in the owner's words, is "pure rust everywhere",
with the TLS providers to be checked first. The workspace already forbids
`unsafe` in its own crates, with one audited exception (the project
brief's principle 4, `docs/dcroxide-project-brief.md:530`), but that stops
at its dependencies, two of which compile C and assembly into the node
(`:775`). On 2026-10-26 the project owner approved three sets of
recommendations ("go with your recommendations"). The first settled the
rule's scope and its two exceptions, its enforcement and the move of ECDSA
to `k256`, and kept blake3. The second, ten answers numbered T1 to T10
that followed the TLS research, chose the TLS provider, defined what
"pure Rust" allows, and changed the first set's answer on blake3; where
the two differ, the second holds. The third answered twelve questions of
the plan for the `k256` port, and D3's own records carry it.

The research found no ready-made rustls crypto provider that is pure Rust,
mature and able to do everything the node's TLS does; `graviola`, which
needs no C compiler, does its cryptography in assembly.
[ADR-0015](0015-tls-crypto-provider.md) records the research and the
provider chosen.

**What drives a C compiler at `185b9d2`.** `cc` 1.5.1
(`Cargo.lock:153`), the crate through which build scripts drive a C
compiler, is a build dependency of exactly four crates in the lock, as
`cargo tree -i cc --target all` shows. The lock has no `cmake`,
`pkg-config`, `vcpkg` or `bindgen`, and no workspace crate has a build
script.

- **`secp256k1-sys` 0.14.1** (`Cargo.lock:1605`): ~67k lines of vendored
  libsecp256k1 C (`docs/dependency-ledger.md:43`), under `secp256k1`
  0.33.1, which `dcroxide-dcrec` takes as `libsecp256k1`
  (`crates/dcroxide-dcrec/Cargo.toml:33`). It runs ECDSA verification
  (`src/secp256k1/ecdsa.rs:176-198`), signing of a hash below the group
  order (`:374-386`) and the compact recovery behind the `verifymessage`
  RPC (`:336-363`), and it parses every secp256k1 key, Schnorr keys
  included (`src/secp256k1.rs:214`, `:232`, `:286`): the consensus path of
  signature types 0 and 2. `k256` 0.14.0 sits beside it (`Cargo.toml:38`)
  for EC-Schnorr-DCRv0 and for ECDSA signing of a hash at or above the
  order (`ecdsa.rs:388-437`).
- **`ring` 0.17.14** (`Cargo.lock:1483`): ~151k lines of C and assembly
  (`dependency-ledger.md:51`), the crypto provider of `rustls` 0.23.46.
  `dcroxide-node` selects rustls's `ring` feature
  (`crates/dcroxide-node/Cargo.toml:59-69`), `ureq` 3.4.2 selects it
  through its default `rustls` feature, and `rustls-webpki` 0.103.16
  depends on it (`Cargo.lock:1552-1560`). It runs the RPC and websocket
  TLS listener, the RPC client-certificate verifier
  (`rpcrun::GoClientCertVerifier`, which hands `rustls-webpki` ring's
  signature algorithms) and both TLS clients of the HTTPS seeder
  (`crates/dcroxide-node/src/seeding.rs`: `ureq` and
  `ProxySeederTransport`). P-521 signing and key exchange already run on
  the pure-Rust `p521` (`dependency-ledger.md:54`). The listener is off
  under `--norpc`; the seeder runs at startup unless `--noseeders` (`:51`).
  Two of `deny.toml`'s three skip entries exist only for it
  (`deny.toml:42-48`).
- **`blake3` 1.8.7**, built with `pure`
  (`crates/dcroxide-wire/Cargo.toml:25`), which compiles none of the
  crate's C or assembly (`dependency-ledger.md:46`). On x86 targets its
  build script still asks a C compiler, when it finds one, whether it
  accepts two AVX-512 flags (`build.rs:161-175`), and asks before it reads
  `pure` (`:343-344`).
- **`iana-time-zone-haiku` 0.1.2**, reached through `chrono`'s `clock`
  feature (`crates/dcroxide-node/Cargo.toml:28`) and `iana-time-zone`
  0.1.65, which depends on it only when the target OS is Haiku. There its
  build script compiles C++. The project builds for no Haiku target.

**The repository's one C file** is `tools/powerloss/shim.c`, the
`LD_PRELOAD` power-cut shim that ADR-0009's durability gate rests on. No
cargo build compiles it: two Linux-only tests compile it with `cc` when
they run and preload it into a child process
(`crates/dcroxide-testutil/tests/review_powerloss_shim.rs:156-162`,
`crates/dcroxide-node/tests/existsaddr_powerloss.rs:473-478`), and CI
makes a skip of either a failure (`.github/workflows/ci.yml:26-35`).

**Inline assembly in Rust crates.** Crates already in the node's build
carry `asm!`, which rustc assembles itself, with no C toolchain: the
system calls of `rustix` 1.1.5, which `dcroxide-node` takes on Unix
(`crates/dcroxide-node/Cargo.toml:106`) and whose build script picks its
Linux backend there (`build.rs:101-122`); the optimization barrier of
`zeroize` 1.9.0 (`src/barrier.rs:69`); the constant-time moves of `cmov`
0.5.4; and a few more, which the dependency ledger lists.

**A build without a C compiler.** A check on 2026-10-26, on an x86_64
Linux desktop, in throwaway crates outside the repository, used the pinned
1.98.1 toolchain and `cc` 1.5.1 with no C compiler on `PATH`. With nothing
more, rustc could not link even a build script ("linker `cc` not found").
Given its linker by absolute path, `secp256k1-sys` and `ring` failed in
their build scripts, while `blake3` 1.8.7 with `pure` built, with
warnings, and hashed `abc` to the vector that
`blake3_still_answers_the_known_vectors` holds
(`crates/dcroxide-wire/src/blockheader.rs:193-213`): the probe's error
becomes a `cargo::warning` and the build goes on (`build.rs:186-192`).
That rustc needs its linker given is a constraint the enforcement below
inherits.

ADR-0006 put ECDSA on libsecp "for verification performance"
(`0006-secp256k1-backend.md:25-26`), accepted two secp256k1 arithmetic
stacks (`:41-43`), and gated its ratification on a differential soak that
was never run (`:47-48`, and its addenda). The rule overrides the first,
ends the second, and keeps the third as a gate.

## Decision

### The rule

What ships, and what `cargo test` builds, is Rust. That covers, on each
target the project builds for, the library, binaries, tests, benches and
build scripts of every workspace crate with every dependency they pull
in, and anything a test compiles while it runs. For all of it (the second
set's T2):

1. **No C or C++** is compiled into it or linked with it, by a build
   script or by anything else.
2. **No cryptographic routine is written in assembly**, whether in an
   assembly file or in Rust's `asm!` or `global_asm!`.
3. **Tiny inline-assembly barriers and system calls are allowed**, each
   named in [dependency-ledger.md](../dependency-ledger.md), in its
   section "Inline assembly the pure-Rust rule allows".
4. **CPU intrinsics are allowed** (`core::arch`): they are Rust, which the
   compiler checks.
5. **Operating-system bindings are allowed** (the first set's 1b): crates
   that declare the platform's own interfaces and compile nothing, such
   as `libc`, `windows-sys`, `linux-raw-sys` and `core-foundation-sys`.

The approvals do not spell out five points, and this record reads them so:

- **The platform's own libraries** are not C "linked with it" under item
  1: those that Rust's standard library and the system linker bring in
  themselves. The first set's 1b allowed the binding crates, not these
  libraries by name. A release build of 2026-10-24 on x86_64 Linux needs
  `libc.so.6`, `libm.so.6` and `libgcc_s.so.1`, and no other shared
  library.
- **The targets the project builds for** are, on 2026-10-26, those of
  CI's test matrix, x86_64 and aarch64 Linux, macOS and Windows
  (`.github/workflows/ci.yml:92`), and the no-OS target of its no_std
  check (`:345-350`). [ADR-0014](0014-release-engineering.md) decides
  which of them get binaries.
- **"What `cargo test` builds"** includes anything a test compiles while
  it runs, which reaches the shim and the oracle, though cargo itself
  builds neither.
- **"Tiny"** means a site of a few instructions that implements no
  cryptographic algorithm: an optimization barrier, a system call, or a
  constant-time select or mask like `cmov`'s, which the second set itself
  counted among the tiny pieces it allowed. By the same measure it takes
  in a single instruction Rust has no stable intrinsic for (`num-bigint`'s
  `div`), empty `asm!` operands used as compiler barriers (`zmij`), the
  no-op marker `objc2` emits for the Objective-C runtime on Apple targets,
  and, until blake3 leaves, `constant_time_eq`'s constant-time comparisons
  and its switch of aarch64's data-independent-timing flag.
- **Assembly outside that allowance is not allowed**, an assembly file a
  C toolchain builds among it.

The ledger's section lists what the rule allows at `185b9d2` and what is
in the lock but compiled for none of those targets. Among the latter are
the compression functions `sha1` and `sha2` 0.11.0 write in assembly for
LoongArch, which the rule refuses.

### Exceptions: two tools that never ship

The first set named two exceptions, development-only tools that check the
port and never ship (1a). The second, answering the C in the test tooling,
said to keep libFuzzer "as the one named exception" (T9). This record
reads T9's "one" as counted among the C and C++ test tools that answer
was about, so that it leaves 1a's exception for the oracle standing, the
C that cgo links into the oracle included:

- **The oracle**, the Go program that runs dcrd's own code to answer the
  differential tests. Tests build it with `go build`
  (`crates/dcroxide-testutil/src/lib.rs:349-375`), and where a C compiler
  is present Go enables cgo and links C from its own runtime and resolver
  into it: an oracle the test suite built on an x86_64 Linux desktop
  records `CGO_ENABLED=1` and needs `libresolv.so.2`. This record reads
  the exception as covering, with the oracle, the Go generators under
  `tools/` that regenerate vector files from dcrd's own code (ADR-0001's
  addenda from 2026-10-02 on), and dcrd itself, which the interop job
  builds and runs (`.github/workflows/ci.yml:201-255`).
- **cargo-fuzz's libFuzzer**, which has no pure-Rust drop-in. `fuzz/` is
  outside the workspace (the root `Cargo.toml:39`) with its own lock, and
  `libfuzzer-sys` 0.4.13 (`fuzz/Cargo.lock:1109-1110`) compiles libFuzzer's
  C++ with `cc` under its default `link_libfuzzer` feature
  (`build.rs:24-38`, `:43-44`).

The fuzz crate takes no libsecp256k1 as a reference implementation
either: the third set answered that the rule already decides it.

### Tools in other languages

The rule as the second set defines it names C, C++ and assembly. This
record reads it as not reaching tools in other languages that never ship:
the Go tools `tools/pinbump` and `tools/dcrdstat`, which CI vets and tests
beside the oracle (`ci.yml:278-282`), and the Python instruments
`tools/dsample/dsample.py` and `tools/powerloss/replay.py`, the second run
by the two power-cut tests. They are neither exceptions nor breaches. The
shim beside `replay.py` is C, and the second set settles it (T9, below).

### What breaks the rule on 2026-10-26, and how each goes

**ECDSA moves to `k256`** (the first set's item 2, decision D3).
Verification, compact recovery, signing and the parsing of every
secp256k1 public and private key move from `secp256k1`/`secp256k1-sys` to
`k256`, which then carries all secp256k1 arithmetic. dcrd's acceptance
rules stay where ADR-0006 put them, in `dcroxide-dcrec` in front of the
backend. Two gates, which ADR-0006's 2026-10-26 addendum reads as both to
be met on the ported code before it merges:

1. **The differential soak** ADR-0006 asked for, re-specified: fuzzers
   that ask dcrd's own code, through the oracle, for the right answer, for
   all three signature types, aimed at four input classes (unusual key
   encodings, small-order Ed25519 keys, hashes at or above the group
   order, and key recovery) and run to the floors the project owner
   accepted, which ADR-0006's 2026-10-26 addendum records with the further
   classes the plan for the port named. Three pieces do not exist yet: no
   fuzz target calls the oracle, none can build torsion keys (both in
   ADR-0006's addenda), and the oracle has no recovery command
   (`tools/oracle/main.go`).
2. **A speed measurement** of ECDSA verification before and after the
   port, on fully validated blocks, since no script is checked before the
   assume-valid block (`docs/operating.md:805-806`), with `k256`'s
   `precomputed-tables` feature tried. By the reading recorded in dcrec's
   manifest (`crates/dcroxide-dcrec/Cargo.toml:20-27`), the tables serve
   only `mul_by_generator` and `mul_by_generator_vartime`, not the combined
   pass Schnorr verification uses, so they can help only an ECDSA path
   that calls one of those two (inference from that reading, not
   measured). Timed runs start on the project owner's word.

The port merges only if the slowdown is small or is optimized away. The
third set fixed when further speed work starts: if full validation is more
than 10% slower, or a default sync moves beyond one session's run-to-run
noise. ADR-0006's 2026-10-26 addendum reads the two together as the bar
the port has to clear to merge, with speed work first where it falls
outside, and a slowdown that work cannot close going back to the project
owner. Until the port merges, libsecp stays recorded here as a breach.
Once both gates pass, a new ADR, numbered when it is written, records the
port, the soak's volume and findings and the measurement, and supersedes
ADR-0006.

**TLS: `ring` goes with an in-tree provider** (T1). rustls takes its
cryptography from a provider, and both the node and `ureq` select ring's:
`dcroxide-node` turns on rustls's `ring` feature, and `ureq` 3.4.2's
default `rustls` feature turns on its `_ring` feature (`ureq`'s
`Cargo.toml:63`, `:74-77`, `:101-105`), so both selections have to go for
ring to leave. The provider is written in the tree, as a new crate built
from RustCrypto crates. `ring` stays until that provider passes a full
interop matrix against Go, every cipher suite, key exchange, key type and
TLS version, plus client certificates, and is then deleted in one change.
ADR-0015 records the choice and what goes with it.

**blake3: an in-tree BLAKE3** (T8, which replaces the first set's 1c). By the
rule's definition blake3's probe counts: on x86 targets its build script runs a
C compiler, when it finds one, on a check file for each AVX-512 flag (`cc`
1.5.1 compiles it with `-c`, `src/lib.rs:1670-1674`), and does so whether or
not `pure` is on. The first set had kept the crate, since under `pure` the
answer is not used and the crate builds with no compiler; the second replaced
that answer. BLAKE3 is to be ported into the tree for the one hash the node
takes from it, DCP0011's proof-of-work hash of a 180-byte header
(`crates/dcroxide-wire/src/blockheader.rs:171-173`), as ADR-0002 did for
BLAKE-256. The known-answer test is in place (`:193-213`: the empty input,
`abc` and a 180-byte input), and `pow_hash_differential` already compares the
hashes of 200 random 180-byte headers with dcrd's
(`crates/dcroxide-standalone/tests/oracle_differential.rs:563-581`). A 180-byte
input fits in one BLAKE3 chunk of 1,024 bytes (blake3 1.8.7, `src/lib.rs:166`).
The port departs from the brief's principle 3, which takes BLAKE3, with
secp256k1 arithmetic, SHA-2 and Ed25519 field math, from audited or widely used
crates and owns only Decred-specific constructions
(`docs/dcroxide-project-brief.md:529`); T8 decides it for BLAKE3.

**The power-cut shim: rewritten in Rust** (T9). `tools/powerloss/shim.c` is to
be rewritten as a small Rust library, which the two tests then build in its
place. The shim interposes C library calls in another process: it exports
`open`, `write`, `fsync` and their kin under their C names and reaches the C
library's own definitions through `dlsym(RTLD_NEXT, ...)`
(`tools/powerloss/shim.c:131-135`). In Rust both need `unsafe`, which the
workspace's `unsafe_code = "forbid"` (`Cargo.toml:134-135`) refuses: on the
pinned toolchain the lint refuses even the `#[unsafe(no_mangle)]` an exported
symbol needs (checked on 2026-10-26). Neither approval addresses that `unsafe`.
This record reads T9 as accepting the `unsafe` a shim cannot do without,
confined to the shim's own crate, for an instrument that never ships, and sees
two forms that leave the brief's principle 4 as it stands for the node's
crates: a crate outside the workspace, as `fuzz/` is, with its own manifest and
lock; or a workspace crate that denies rather than forbids `unsafe_code`,
listed beside `dcroxide-winsvc` as a second audited exception, each `unsafe`
block allowed on its own with a `SAFETY` comment, as ADR-0008's addendum of
2026-09-25 set out for that crate. Which form is the change's.

### Enforcement

Two checks, neither written yet (the first set's 1b):

- **cargo-deny bans.** `deny.toml`'s `[bans]` table holds
  `multiple-versions = "deny"` and three `[[bans.skip]]` entries
  (`deny.toml:23-52`). It gains a `deny` list refusing the crates that
  compile or link C. cargo-deny 0.20.2, the version read here (CI's action
  names none, `ci.yml:289`), matches a banned crate by its name and a
  version requirement, with no patterns (`src/lib.rs:482-484`), so the
  `-sys` crates that build C are refused through the means they build it
  with: `cc`; the other native build drivers, `cmake`, `pkg-config`,
  `vcpkg` and `bindgen`, none of them in the lock; and, once each has
  left, `ring` and `secp256k1-sys` by name. A ban lets a crate through
  when every direct dependent of it is one of the ban's wrappers
  (`src/bans/cfg.rs:9-12`, `src/bans.rs:608-649`). `ring`,
  `secp256k1-sys` and `blake3` are `cc`'s wrappers until each leaves, so
  the bans need not wait for the removals and stop a further crate that
  builds C from entering in the meantime. cargo-deny warns of a wrapper it
  does not meet (`src/bans/diags.rs:349-363`), so each wrapper goes with
  its crate, as the two skip entries for `ring` go with `ring`.
  Operating-system bindings compile nothing and are not listed. A ban
  that matches nothing is doing its job, unlike the unmatched allowances
  and skips the file's comments argue against (`deny.toml:12-15`,
  `:33-36`).

  `iana-time-zone-haiku` stays among `cc`'s wrappers after the other three
  have gone. `[graph]` names no targets (`deny.toml:1-2`), and with none
  cargo-deny applies no target filter (`src/cargo-deny/common.rs:279-288`;
  `krates` 0.21.2, `src/builder.rs:763`), so the bans read every target's
  crates, Haiku's among them, where `iana-time-zone` takes the crate (its
  `Cargo.toml:86-87`) and its build script compiles C++ (`build.rs:4-9`).
  This record's reading: the crate does not break the rule, since no
  target the project builds for compiles it, and it is listed as a
  lasting wrapper with that reason, so the C++ it carries stays in view in
  `deny.toml`. Naming targets in `[graph]` would hide it, and would also
  narrow the advisory and licence checks, which read the same graph. Were
  the project to build for Haiku, the crate would break the rule there.
- **A build with no C compiler.** The first set's 1b asked for a CI job
  that builds the whole node on a machine with no C compiler installed.
  The check in Context fixes two constraints on it. rustc links through
  `cc` on Linux, so this record reads the job as one that builds every
  workspace target (`cargo build --workspace --all-targets --locked`) with
  no C or C++ compiler that a build script can reach: the compiler is
  hidden from build scripts, not from the link step, and rustc is given
  its linker by absolute path. That reading misses a build script that
  runs the compiler by its absolute path. And blake3, while it remains,
  fails on its no-compiler warning when `BLAKE3_CI` is set
  (`build.rs:28-39`), so the job leaves it unset. The job catches what a
  list of names cannot: a build script that compiles C by any other route.
  It cannot see blake3's probe, which only warns when no compiler answers
  (Context); the `cc` ban sees that. The job's exact form is the change's.

The CI job cannot pass while `secp256k1-sys` or `ring` remains, so it
lands with the second of those removals. The rule is met when all four
breaches are gone and both checks run and pass.

Neither check sees inline assembly, nor a C file a test compiles while it
runs: the ledger's list of allowed `asm!` is kept by review, and the shim
leaves with its rewrite. A crate that compiles nothing and only links a
library, one already on the system or one it ships prebuilt, gets past
both checks too. cargo-deny's `[bans.build]` table can refuse a build
script that is not on a list and a prebuilt archive
(`allow-build-scripts`, `executables`, `include-archives`;
`src/bans/cfg.rs:267-290`); whether to add it is the change's.

### Order

The first set put the records first, then the `k256` port and its soak,
then TLS. The second set gave the order after the records: the `k256`
ECDSA port and its soak; the TLS provider at today's feature level, then
the switch; the post-quantum hybrids and the wider set of client
certificates (ADR-0015); and the BLAKE3 port and the shim rewrite. The
third set added that the oracle and differential tooling for the port,
which does not depend on the TLS answers, can start at once.

## Consequences

- **The C leaves the consensus path and the network surface**: about 67k
  lines under the signature checks and 151k under TLS
  (`dependency-ledger.md:43`, `:51`), with the FFI between them and the
  node. A source build compiles no C, though on Linux rustc still links
  through the system's `cc` driver.
- **One secp256k1 stack**, `k256`, where ADR-0006 accepted two. ECDSA
  verification moves from the most widely deployed implementation
  (`dependency-ledger.md:43`) to a crate the ledger records as accepted,
  not reviewed (`:44`); the soak is what bounds that risk. dcrec's `std`
  feature, which only selects libsecp's per-thread context
  (`crates/dcroxide-dcrec/Cargo.toml:13-18`, `:28`), loses its reason.
  Inference, not checked: `dcroxide-txscript`, which the no_std job leaves
  out because it fails on `secp256k1-sys` and nothing else
  (`ci.yml:330-334`), may then pass that check.
- **libsecp's speed lead is to be measured, not assumed away.** In the one
  profile in the repository that splits out fully validated blocks,
  secp256k1 took about 38% of user-space cycles on all threads and
  BLAKE-256 compression 48.4% (`docs/bench-ledger.md:2706-2707`), libsecp
  and `k256` not separated; the repository holds no ECDSA figure for
  `k256`. With no script checked before the assume-valid block, a default
  sync up to it should not move (inference); `--assumevalid=0` syncs and
  blocks at the tip carry the cost.
- **BLAKE3 becomes the project's own code.** DCP0011's proof-of-work hash
  is then held by the known-answer test and the oracle differential, as
  BLAKE-256 is, and owning it is the cost the first set's 1c argued
  against and the second set accepted. The brief's principle 3 still
  names BLAKE3 among the algorithms taken from outside crates
  (`docs/dcroxide-project-brief.md:529`) and is to be brought in line when
  the port lands. The port takes `blake3`, `arrayvec` 0.7.8 and
  `constant_time_eq` 0.4.2 out of the lock, since nothing else uses the
  last two.
- **`cc` stays in `Cargo.lock`.** The lock records every target's
  dependencies, so `iana-time-zone-haiku` keeps `cc`, with `shlex` and
  `find-msvc-tools`, after the other three removals, for as long as
  `chrono`'s `clock` feature takes `iana-time-zone`; the node uses it for
  the local offset of its log timestamps
  (`crates/dcroxide-node/src/logging.rs:157-158`). No build for a target
  the project builds for compiles it. `cc` would leave the lock only with
  a `chrono` setup that does without `iana-time-zone`, which nothing here
  decides.
- **Reproducible builds, for D7 (ADR-0014).** `rust-toolchain.toml` pins
  only Rust (`:17-19`), so today the C compiler that builds
  `secp256k1-sys` and `ring`, and answers blake3's probe, is an unpinned
  input to the build. With the four breaches gone, no crate's C reaches
  the binary and no build script runs a C compiler for a target the
  project builds for. The linker and the C runtime stay inputs, since
  rustc links through `cc` on Linux and the binary links `libc.so.6`,
  `libm.so.6` and `libgcc_s.so.1`: a reproducibility check still has to
  hold them fixed or compare across them, but it no longer pins a C
  compiler for crate code. Meeting this rule is also one of the four
  conditions the project owner set on 2026-10-26 for publishing any
  binary (D7).
- **Two duplicates go with `ring`.** Removing it takes `getrandom` 0.2.17,
  `windows-sys` 0.52.0, `windows-targets` 0.52.6 and the eight
  `windows_*` 0.52.6 import-library crates, which only it uses
  (`deny.toml:42-48`; `dependency-ledger.md:53`), and both skip entries
  with them.
- **The shim's rewrite meets C's variadic calls.** The shim interposes
  `open`, `open64` and `openat` (`tools/powerloss/shim.c:266`, `:276`,
  `:286`), which C declares variadic, and on the pinned 1.98.1 toolchain
  rustc refuses a C-variadic function definition as unstable (E0658,
  checked on 2026-10-26). Inference, not checked: the rewrite will declare
  them with fixed arguments, which the Linux calling conventions of x86_64
  and aarch64 pass in the same registers as the variadic ones.
- **The allowance holds for every crate.** A version bump or a new crate
  that brings `asm!` into a build for a target the project builds for
  needs its entry in the ledger's section first, and nothing mechanical
  checks that. Until the bans land, nothing mechanical stops a further
  crate that builds C from entering either; review does.
- **Fuzz builds keep libFuzzer's C++**, as excepted above.
- **Not drafted here:** the `deny.toml` bans and the CI job; and, as each
  breach goes, the dependency ledger's rows for it, the brief's figures
  on line 775, its principle 3, the no_std job's notes on
  `secp256k1-sys` (`ci.yml:323-341`), and the CI comment on dcrec's run
  without `std` (`ci.yml:104-108`).
