# ADR-0017 — D3: secp256k1 in pure Rust, as built

- **Status:** Accepted 2026-11-09. Supersedes
  [ADR-0006](0006-secp256k1-backend.md). It takes effect with the merge of
  the port's branch; until then master runs libsecp256k1 and ADR-0006
  describes it. The merge-bar run of
  [ADR-0016](0016-secp256k1-vartime-arithmetic.md) passed on 2026-11-10
  ("The speed measurement and the merge bar", below), and the port
  plan's criteria 8 and 9, the extra soak legs and the committed witness
  vectors, were met that day (addendum of 2026-11-10), so the merge waits
  only on the project owner's word.
- **Date:** 2026-11-09, 2026-11-10 (addendum: the extra soak legs, the
  merge-bar run and the witness vectors)

## Context

ADR-0006, proposed on 2026-07-03, put ECDSA (signature type 0) and every
secp256k1 key on the `secp256k1` bindings to libsecp256k1, EC-Schnorr-DCRv0
(type 2) on `k256`, and Ed25519 (type 1) on `curve25519-dalek`, with dcrd's
acceptance rules in dcroxide's own layer in front of each. Its ratification
waited on a differential soak against dcrd, and it was never ratified.

On 2026-10-26 the project owner decided D3 under
[ADR-0012](0012-pure-rust.md)'s rule, "pure rust everywhere": ECDSA and
every secp256k1 key move to `k256`, and Ed25519 stays on
`curve25519-dalek`, behind an oracle-backed differential soak of all three
signature types over named input classes, to floors the owner accepted,
and a speed measurement, with "only merge if the slowdown is small or
optimized away" as the condition. Speed work, stage 2, follows if full
validation is more than 10% slower than on libsecp256k1 or the default
sync moves beyond one session's run-to-run noise. ADR-0006's addenda of
that day read the two as the bar to merge, set out how the soak is run
and compared, and asked for a new record of the soak, the measurement and
the pin the gate soak ran against, to supersede ADR-0006. This is that
record. ADR-0006's and ADR-0012's text expected it to follow the
full-validation comparison and the merge; it is written before the
merge-bar run because it takes effect only with the merge, which waits
on that run.

The port is five commits on the branch of the pull request that carries
it, `83709d7` to `750c984`: verification on `k256` by dcrd's algorithm;
signing of every hash, with dcrd's `SignCompact` ported; the key types;
compact recovery, with the `secp256k1` dependency and `secp256k1-sys`
removed (`7bc3816`); and the text that names the backend. Then `43beedc`
added the `cargo-deny` bans and the CI job that builds with no C compiler.

The gates of 2026-11-07 passed the soak and failed the speed bar: full
validation took 1.497 times as long as on libsecp256k1, and the default
sync's 29.1 s difference was beyond base's 16.0 s spread. Stage 2 began.
Its first step, stage 2a (`d50fc1c`, recorded in ADR-0006's addendum of
2026-11-08 by `3c50313`), cut a verification from 1.963 to 1.582 times
libsecp256k1's and full validation to 1.300; the node-side tuning measured
the same day passed neither of its bars and was closed. Route c, in which
dcroxide owns its variable-time secp256k1 arithmetic, was approved and
built in five increments (ADR-0016).

## Decision

**dcrd's rules in front of the arithmetic.** `dcroxide-dcrec` keeps
dcrd's acceptance rules in its own code, where ADR-0006 put them: DER and
compact signature parsing, the public key formats with hybrid keys, the
r and s range checks, hashing to a scalar, the acceptance of any S in
[1, N-1], low-S serialization, the error kinds and their order, and the
verification step numbering (`VerifyStep`). Every one is differential-
tested against dcrd's own code through `tools/oracle`.

**Public data, variable time, on the owned crate.** The arithmetic of
operations on public values runs on `dcroxide-secp256k1-vartime`, ported
from libsecp256k1 (ADR-0016): ECDSA verification's scalars, its sum
u1·G + u2·Q and its x check; compact recovery's steps 4 to 10 and the
recovered key; EC-Schnorr-DCRv0 verification's R = s·G + e·Q and its
affine coordinates; and public keys, from the decompression of compressed
keys and the curve check of uncompressed and hybrid ones to their
coordinates, serialization and equality. dcrec names the crate in one
module, `src/secp256k1/backend.rs`.

**Secrets, constant time, on `k256`.** `k256` 0.14.0, with `arithmetic`
alone (`ecdsa`, `std` and `precomputed-tables` off), keeps what touches a
secret: private keys, and `PrivateKey::public_key`'s product d·G, which
enters the crate's point once, as a finished public value; ECDSA signing,
which picks the low S in constant time, and EC-Schnorr-DCRv0 signing, both
multiplying by the generator as `GENERATOR * k` through `lincomb` and
zeroing the copies of the key they make, as dcrd does; and dcrd's RFC6979
nonce, ported, its result taken as a `k256` scalar. Schnorr verification
also checks its challenge e < N with `k256`'s `Scalar::from_repr`, in the
function signing shares
(`crates/dcroxide-dcrec/src/secp256k1/schnorr.rs:181-187`); it reads a
public hash and no point.

**The fallback.** `k256`'s combined multiply, normalization,
decompression and recovery arithmetic stay live behind the seam. Should
the owned crate decline an input, which its proofs rule out, the seam
takes them, with a debug assertion. Builds with debug assertions also
compute `k256`'s answer for verification, recovery and Schnorr
verification on every call and stop on any difference; a decompression is
held to its own x and parity, and to `k256`'s where no point exists. A
`None` from the crate's
decompression or curve check is an answer, not a decline. ADR-0016 holds
the details.

**Ed25519** stays on `curve25519-dalek` 5 primitives with dcrd's 2017-agl
semantics in dcrec, as ADR-0006 decided.

**No C.** `secp256k1` and `secp256k1-sys` are out of every build on the
port's branch; the `cargo-deny` bans and the CI job with no C compiler
hold that (ADR-0012's addendum of 2026-11-06). The owned crate is
`ISC AND MIT`, with libsecp256k1's licence and copyright lines in its
`NOTICE` (ADR-0016).

## The soak and the pin

ADR-0006's addendum of 2026-10-26 asks this record to hold the soak and
the pin; [ADR-0014](0014-release-engineering.md)'s second condition asks
it to record the result.

- **The baseline**, on libsecp256k1 at master `0c4154d` (2026-11-06): the
  floors run, 427,002,940 cases and 547,005,573 requests, the sum of the
  approved floors, in 3,438.3 s; passed and eligible to gate; master seed
  `0x18e56cebf8f0edf0`; generator fingerprint `c21c897e`; the replay equal
  in all 82 classes; the model baseline and canaries C1-C18 caught. The
  oracle binary was built with go1.26.2, sha256
  `2fc78fc922ad014f13f4551a8e3838880d37cf9e35c397fdebc286c1bd5fcb53`.
- **The gate soaks**, each at that seed with that oracle binary, each with
  no disagreement and no oracle fault, every class digest equal to the
  baseline's, the replay equal and every canary caught: G3 on `43beedc`
  (2026-11-07), the `k256` port; stage 2a on `3c50313` (2026-11-08); RC1
  to RC4 on `8c672e9` and RC5 and RC6 on the tree of `b479c1c`
  (2026-11-09), each of the last two with a `soak-asserts` leg of 762,940
  cases. The last is the tree the port's dcrec and owned crate have at
  the time of this record.
- **The pin**: dcrd master `3360ae4d`. Every gate used the baseline's
  oracle binary, so the same dcrd code judged every run, and the pin rule
  of ADR-0006's second addendum of 2026-10-26 held at each. The soak's
  frozen files are unchanged since the baseline's commit, so no gate
  needed the model relaxation of ADR-0006's addendum of 2026-10-30.
- **Divergences found**: none. No gate soak disagreed with dcrd on any
  case. The nightly soak and the oracle-backed fuzz targets are regression
  evidence, not gate runs (ADR-0006's addendum of 2026-10-27).

## The speed measurement and the merge bar

On an x86_64 Linux desktop, against master in the same session each
time, `0c4154d` until the merge-bar run and `012192b` in it, which differs
only in TLS signing code (ADR-0016's addenda of 2026-11-09 and 2026-11-10
have the full tables, the bench ledger each run):

| | `k256` port | stage 2a | route c, RC4 | route c, RC6 |
|---|---|---|---|---|
| ECDSA verification, one thread | 1.963 | 1.582 | 1.036 | 1.031 |
| full validation, wall | 1.497 | 1.300 | 1.035 | 1.034 (merge-bar run) |
| default sync, head - base | +29.1 s | +22.65 s | -2.90 s | +1.8 s (merge-bar run) |

The bar, as ADR-0006's addendum of 2026-10-26 reads it and the project
owner's decision 4 of 2026-11-08 keeps it: a fresh G5 at the final branch
against master, with full validation at no more than 1.10 times base and
the default sync's mean difference within base's spread in that session.
**That run passed on 2026-11-10**, at `3a231c6`, whose shipped code is
RC6's: full validation 1.034 times base's, and the default sync 1.8 s
slower, inside base's spread of 11.4 s, with every full-validation run
ending on the same UTXO set. ADR-0016's addendum of that date has the
numbers. The first milestone after RC4 had measured 1.035 and -2.90 s.
By the bar the port merges on the project owner's word, and this record
takes effect with it.

## Switching back

ADR-0016's "Switching back" holds the checklist; in short:

1. **Before the merge, nothing.** Not merging is the switch back: master
   runs libsecp256k1, which the baseline soak shows giving dcrd's answers.
2. **After the merge, pure Rust first.** Production moves back to the live
   `k256` arm, or to stage 2a's loop by reverting RC4 to RC6 in forward
   commits,
   with no policy change and one gate soak.
3. **After the merge, the C library third.** A forward change puts a
   libsecp256k1 backend behind the seam in master's `0c4154d` shape, with
   dcrd's checks in front and EC-Schnorr-DCRv0 left in Rust, restores the
   dependency and both lockfiles' C crates, reverses the bans, the job with
   no C compiler and ADR-0012's rule for ECDSA, and passes one gate soak.
   Reversing "pure rust everywhere" is the project owner's decision.

No dormant `libsecp` feature is kept. The judge of a switch either way is
kept: the baseline at `0c4154d` with its seed, fingerprint, pin and
oracle binary, and an out-of-tree benchmark with libsecp256k1 in the same
process.

## What ADR-0006 keeps, and what it loses

ADR-0006 keeps its Context (three signature types, a verification-heavy
daemon, dcrd's acceptance as the compatibility surface); dcrd's rules in
dcroxide's own layer in front of the arithmetic; EC-Schnorr-DCRv0 ported
from dcrd with its vectors; Ed25519 on `curve25519-dalek` primitives with
the 2017-agl semantics; the requirement that every verification path be
differential-tested against dcrd; and its addenda as the procedure of the
soak, which stays in force: the second of 2026-10-26 on the freeze,
canaries, floors, error text and pin moves, that of 2026-10-27 on the fuzz
targets and the nightly soak, and that of 2026-10-30 on model fixes.

It loses the libsecp256k1 bindings and the way out it kept of moving
Schnorr onto them, and the present tense of its addenda: the first of
2026-10-26, where all secp256k1 arithmetic was to move to `k256`, now
narrowed by ADR-0016, and that of 2026-11-08, whose module (`ecmult.rs`),
its `once_cell` cell and ledger row and the race test of its first use
left the tree with RC5 (`0632b75`). Its consequence of two arithmetic
stacks holds again, both Rust: `k256` for secrets and the fallback, the
owned crate for public data. ADR-0006's text is not edited beyond its
status and date lines.

## Consequences

- No C runs under the signature checks on the port's branch, nor on
  master once it merges. ADR-0012's rule loses its `secp256k1-sys` breach
  then, and ADR-0014's first release condition the same part. Its second
  condition, the D3 soak, has passed its gate runs and the extra soak
  legs (addendum of 2026-11-10), recorded here, and counts for a release
  once the port merges.
- Two secp256k1 stacks, both Rust, where ADR-0012's Consequences expected
  one, `k256`. The owned crate is unaudited; the literal port, its tests
  and the soaks against dcrd bound that.
- Signing costs about 1.22 times libsecp256k1's, constant-time `k256`, off
  the sync path. Schnorr verification costs about 0.55 of what it did on
  `k256`, which base used too.
- The project brief's principle 3 lists ADR-0016's crate as an exception.
- The dependency ledger narrows `k256` to keys, signing, the nonce and the
  fallbacks, and gives the crate an owned row; fiat-crypto is a
  development dependency only.
- Before the merge: the merge-bar run and the port plan's criteria 8
  and 9 (the extra soak legs and the committed witness vectors), all met
  on 2026-11-10 (addendum of that date); what remains is the project
  owner's word.

## Not decided here

- Whether the soak harness is unfrozen once (ADR-0016: not needed).
- Pull requests to RustCrypto with any of this work, each the project
  owner's call.
- The sweep of other files derived from non-ISC sources.

## Addendum, 2026-11-10 — the extra soak legs, the merge-bar run and the witness vectors

**The extra soak legs**, the port plan's criterion 8. Three legs ran on
the x86_64 Linux desktop of the gate soaks, at `e0cdf66`, whose
signature code is that of the gate after RC6 with comments changed;
`3a231c6` after it changes six files, all tests, none built into the
soak binary. Each used the
baseline's master seed and oracle binary, at pin `3360ae4d` with
generator fingerprint `c21c897e`:

- **S**, the 16 Ed25519 classes at their floors, 94,000,307 cases, with
  `curve25519-dalek`'s serial backend (`--cfg
  curve25519_dalek_backend="serial"`); a probe of the binary found no
  vector entry point and the serial doubling running.
- **X**, the same classes and cases with dalek's AVX-512 IFMA backend,
  built as the leg's plan allows in place of its first design: AVX-512
  IFMA through `curve25519-dalek`'s `--cfg
  curve25519_dalek_backend="avx512"`, which compiles dalek's IFMA code
  and selects it at run time; the crate-wide target-feature build hits
  an LLVM crash compiling `k256` under rustc 1.99.1. The soak's record
  therefore names the backend `avx2`, as an AVX2 run's would. A debugger
  probe of the leg's own binary after the run settles it: on an honest
  Ed25519 case dalek's IFMA double-base multiplication
  (`spec_avx512ifma_avx512vl`) ran once and its AVX2 one (`spec_avx2`)
  never, and on a random case neither.
- **C**, all 82 classes at their floors, 427,002,940 cases and
  547,005,573 requests, in a release profile with overflow checks on in
  every crate of the soak binary, which holds 612 call sites that panic
  on overflow, in `k256`, the owned crate, `curve25519-dalek` and dcrec
  among others. No panic was logged. It took 1.016 times as long as the
  baseline soak and 1.037 times as long as the gate after RC6, in other
  sessions.

Each leg had no disagreement and no oracle fault, passed every check of
its plan, replayed equal, and caught its canaries: the model baseline
and C7, C8, C15 and C16 in S and X, and the model baseline and C1-C18 in
C. Every digest checkpoint of every leg equals the baseline's on
libsecp256k1; S and X, which run 16 of the 82 classes, are compared
with it as a subset, 16 classes equal and 66 absent. The soak's
criterion 4, that each reachable error kind is seen, holds vacuously
for S and X: no error kind it checks is reachable from the Ed25519
classes.

- **A**, arm64: the nightly soak job of CI, dispatched on `3a231c6` with
  the baseline's master seed, ran all 82 classes for its 2,100 s budget
  on a two-worker arm64 runner, every class reaching at least a
  hundredth of its floor: 40,632,764 cases, no disagreement and no
  oracle fault. Its replay equals the baseline's in all 82 classes, and
  its fixed-seed record equals an x86_64 one of `e0cdf66` in all 82,
  both compared as exploratory, since a budget run is not a gate. The
  same dispatch's x86_64 canary run, which caught the model baseline and
  C1-C18, stands in for the canaries on arm64. The leg's plan asked that
  the diff from `e0cdf66` to the dispatched commit over dcrec's sources,
  the owned crate, the soak, the oracle and `Cargo.lock` be empty. It
  holds one file, a `#[cfg(test)]` module of
  `dcroxide-secp256k1-vartime` with criterion 9's new test, which the
  soak binary does not compile; the generator's fingerprint and frozen
  sources are the baseline's in every record of both commits, and the
  lock record is the same in all of the port's. The plan's optional
  further comparison, against master's nightly arm64 record, was not
  run.

With these legs the D3 soak of ADR-0014's second condition is complete
on the port's branch.

**The merge-bar run** passed: full validation 1.034 times
libsecp256k1's, the default sync 1.8 s slower within base's spread of
11.4 s, and every full-validation run ending on the same UTXO set ("The
speed measurement and the merge bar", above, and ADR-0016's addendum of
this date).

**The witness vectors**, criterion 9: the soak's witness file and
dcrec's three branch files hold dcrd's verdicts for every constructed
class and every adversarial family of route c, the Straus loop's
doubling through an addition at each of its four call sites included
since `3a231c6` (ADR-0016's addendum of this date).

**What this corrects.** The status and date lines, the speed table's
last column and the paragraph under it, and the two Consequences that
named these as still to come.
