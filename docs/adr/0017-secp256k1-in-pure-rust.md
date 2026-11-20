# ADR-0017 — D3: secp256k1 in pure Rust, as built

- **Status:** Accepted 2026-11-09. Supersedes
  [ADR-0006](0006-secp256k1-backend.md). In effect since the port's
  branch merged to master at `28ad696` on 2026-11-10 (second addendum of
  that date); master no longer runs libsecp256k1. The merge-bar run of
  [ADR-0016](0016-secp256k1-vartime-arithmetic.md) passed on 2026-11-10
  ("The speed measurement and the merge bar", below), and the port
  plan's criteria 8 and 9, the extra soak legs and the committed witness
  vectors, were met that day (first addendum of 2026-11-10), before the
  merge.
- **Date:** 2026-11-09, 2026-11-10 (addendum: the extra soak legs, the
  merge-bar run and the witness vectors; second addendum: the merge),
  2026-11-18 (addendum: HD derivation's entry points), 2026-11-19
  (addendum: secret generator multiplication through `k256`'s basepoint
  table; second addendum: a timing test of the secrets; third addendum:
  a micro benchmark of the secrets, and what each claim rests on),
  2026-11-20 (addendum: EC-Schnorr-DCRv0's nonce negation selected, not
  branched on)

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
(`crates/dcroxide-dcrec/src/secp256k1/schnorr.rs:182-188`); it reads a
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

## Addendum, 2026-11-10 (second) — the merge

The port's pull request merged by fast-forward on 2026-11-10, moving
master from `012192b` to `28ad696`, the records commit of the merge-bar
run and criteria 8 and 9. From that commit this record is in effect and
ADR-0006 is superseded. On master `secp256k1` and `secp256k1-sys` are
out of every build and out of both lockfiles, and the `cargo-deny` bans
and the CI job with no C compiler of ADR-0012's addendum of 2026-11-06
hold them out of the workspace. So the `secp256k1-sys` breach of
ADR-0012's rule is gone from master, that part of ADR-0014's first
release condition is met there, and ADR-0014's second condition, the D3
soak, holds there. blake3's compiler probe and the C power-cut shim
still break ADR-0012's rule, and ADR-0014's third and fourth conditions
are unchanged.

**What this corrects.** The status and date lines. The Context's "it
takes effect only with the merge, which waits on that run" (`:36-38`)
and its "The port is five commits on the branch of the pull request
that carries it" (`:40-41`), which is on master now; "No C"'s "on the
port's branch" (`:104-105`), which now holds on master as well; the
sentence that ends "The speed measurement and the merge bar"
(`:162-163`); Switching back's first step (`:169-170`), which no longer
applies, so a switch back starts at the second; and the Consequences'
first item (`:211-216`), whose "once it merges" and "once the port
merges" are now past, and their last (`:227-230`). The first addendum
of this date keeps its words, its "complete on the port's branch"
(`:301-302`) included: that soak is the one master now has.

## Addendum, 2026-11-18 — HD derivation's entry points

dcrec gains the secp256k1 entry points of HD key derivation (dcrd's
`hdkeychain` v3.1.3), so that a port of that package outside dcrec
touches no `k256` type; [ADR-0016](0016-secp256k1-vartime-arithmetic.md)'s
addendum of this date records the split and the tests. They follow this
record's line between public data and secrets.

**What this corrects.**

- "Public data, variable time, on the owned crate" gains the HD public
  child's sum Il·G + Q (`add_public_tweak`), on public values only: its
  tweak is the Il of a non-hardened child of an extended public key, which
  that key already gives away, and its documentation forbids a secret
  tweak.
- "Secrets, constant time, on `k256`" gains the range check of a 32-byte
  scalar (`check_scalar`, dcrd's `overflow || IsZero`), the reduction
  modulo N of `PrivKeyFromBytes` (`ReducedPrivateKey::from_bytes`, a key
  that reduces to zero being its own variant, `ReducedPrivateKey::Zero`,
  which no signing function takes), the private child's sum
  `(Il + parent) mod N` (`add_private_tweak`), and the read-out of a
  private key's bytes (`PrivateKey::serialize`). The public key of a
  reduced key is `PrivateKey::public_key`'s product, unchanged. The
  `Zeroizing` values dcrec holds are wiped on drop; copies inside
  `k256` and stack copies the compiler leaves are not, as for the signers'
  key copies.
- "The fallback": `k256`'s combined multiply
  (`mul_by_generator_and_mul_add_vartime`) and one
  `batch_normalize_vartime` now also serve `add_public_tweak` should the
  owned crate decline, and builds with debug assertions compute `k256`'s
  answer for it on every call, as for verification, recovery and Schnorr
  verification, and stop on any difference. A fallback whose conversion of
  the key also fails, two faults, has no answer here, unlike verification's
  rejection, so `add_public_tweak` stops, as `PrivateKey::public_key`
  does.
- The Consequence on the dependency ledger: `k256` is narrowed to keys,
  signing, the nonce, the scalar arithmetic of HD derivation's private
  side and the fallbacks.

The rest of the Decision stands as written: dcrd's rules stay in dcrec in
front of both stacks, dcrec names the owned crate in one module, and no
signing function reaches it.

## Addendum, 2026-11-19 — secret generator multiplication through `k256`'s basepoint table

dcrec's secret generator multiplications now read `k256`'s precomputed
basepoint table. The wallet that consumes dcrec asked for it: signing
there took about 1.72 times Go's time, against a criterion of at most
1.15 times. The Decision's "Secrets, constant time, on `k256`" said
`precomputed-tables` and `std` were off and that both signers and
`PrivateKey::public_key` multiplied as `GENERATOR * k` through `lincomb`.
That held for this record's date. dcrec's manifest and the dependency
ledger's `k256` row gave the reason: nothing called `mul_by_generator`,
the only constant-time reader of the table, so the table bought nothing.

**What changes.**

- Every multiplication of the generator by a secret goes through one
  function, `mul_secret_by_generator` (`src/secp256k1.rs`): the public key
  dG of `PrivateKey::public_key` (and with it
  `ReducedPrivateKey::public_point` and the public key of an HD private
  child), ECDSA signing's kG (and so compact signing's), and
  EC-Schnorr-DCRv0 signing's R = kG. It calls `k256`'s `mul_by_generator`.
- dcrec gains one feature, `precomputed-tables`, on by default. It turns
  on `k256/precomputed-tables` and `primeorder/std`, which the table's
  one-time initialisation needs (`primeorder` 0.14.0
  `src/tables/basepoint.rs:5-19`: `std` or `critical-section`). `std` is
  chosen over `critical-section`. It uses `std::sync::LazyLock` and adds
  no package. `critical-section` adds `once_cell`, `critical-section` and
  `portable-atomic`, and needs an implementation linked into every
  binary, which on a host is `critical-section/std`. `k256/std` is not
  taken, since it also enables `getrandom`. The lock gains one edge,
  dcrec to `primeorder`, and no package.
- With the feature, `mul_by_generator` recodes the scalar, without
  branching, into 65 signed radix-16 digits. Each digit selects in
  constant time one entry of 33 tables of eight multiples (digit 64 from
  table 32, digits 2i and 2i+1 from table i). The 65 entries are summed
  into two accumulators by 64 additions, the odd-digit accumulator is
  doubled four times, and one final addition joins the two. Without it,
  `k256` computes `GENERATOR * k` through `lincomb`, the path every build
  took before. The no_std check builds dcrec without default features, so
  without the table and without `std`. Both paths add table entries
  chosen by `primeorder`'s `LookupTable::select`, the identity among them
  for a zero digit. The table walk therefore brings no kind of selection
  or addition that `lincomb` did not already make.
- The points are the same. `mul_secret_by_generator_matches_the_plain_multiply`
  holds the table against `lincomb` for 0, 1 to 64 and N - 1 to N - 64
  (those also against repeated addition), every 2^i and 2^i - 1, each
  byte value repeated, the low-S boundary and 4,096 random scalars. dcrd's
  vectors and the oracle differentials pass unchanged with the feature
  on, and CI runs dcrec's whole suite once more without it. ECDSA, compact
  and Schnorr signatures, and public keys, equal Go's byte for byte with
  and without the table in the microbenchmark's 8,192 cases.
- Measured on m3 (docs/bench-ledger.md, "Secret generator multiplication
  through k256's basepoint table (2026-11-19)"), the public key fell from
  37.8 µs to 19.7 µs, ECDSA signing from 42.8 µs to 24.7 µs and Schnorr
  signing from 38.9 µs to 21.0 µs. Against dcrd at the oracle's pin,
  signing went from 1.57 to 1.63 times Go's time to 0.85 to 0.95 times.
  Verification and recovery moved by under 0.6%. The table is built on
  the first call, which takes about 90 µs longer than one without it.
  Without the feature the change runs at the old speed.
- Verification, recovery, key parsing and HD derivation's public tweak sum
  are untouched. They run on the owned crate, with `k256`'s combined
  variable-time multiply as their fallback, and read no table.

**What is not done.** dcrec has no timing check of its own like
`dcroxide-tlscrypto`'s dudect targets (ADR-0015 T10), with the table or
without it. The constant-time claim rests on reading `k256` 0.14.0 and
`primeorder` 0.14.0. Neither path wipes the scalar's recoding or the
intermediate points it leaves on the stack, and neither did before.

The rest of the Decision stands. dcrd's rules stay in dcrec in front of
both stacks, and no signing function reaches the owned crate.

## Addendum, 2026-11-19 (second) — a timing test of the secrets

The first addendum of this date left dcrec without a timing check of its
own, with the table or without it. dcrec now has one:
`crates/dcroxide-dcrec/src/ct_check.rs`, dudect's fixed-against-random
t-test, run by `.github/workflows/constant-time.yml` in a job of its own.

**The harness.** `dcroxide-tlscrypto`'s (ADR-0015 T10) with that crate's
targets and its one known report left out, now
`crates/dcroxide-testutil/src/ct.rs`, with its own tests: classes
interleaved sample by sample, inputs built ahead the same way for every
class, operations under 2 µs batched, dudect's 100 crops besides the
uncropped test, and a class failing on |t| above 10 with a difference of
1 ns an operation or more. Every class, the random one included, now
draws an equal share of the samples, where `dcroxide-tlscrypto`'s copy
gives the random class half; "The class shares" below says why, and
what the earlier draw did. The trace line of each target also names the
processors its thread was allowed, from `/proc/self/status`, so a run
shows whether it was pinned. `dcroxide-tlscrypto` keeps its own copy for
now; it is not touched here. *(2026-11-20: no longer; its targets run on
this harness, with their known report as a parameter of the harness's
report, and its copy is gone: ADR-0015's addendum of 2026-11-20.)*

**The entry points.** Every public item of dcrec that computes on a
secret, and the one internal function they share, has a target: the
generator's multiplication by a secret scalar (`mul_secret_by_generator`,
k256's `mul_by_generator`), `PrivateKey::public_key` (and with it
`ReducedPrivateKey::public_point` and an HD private child's public key),
the range checks and read-out of `PrivateKey::from_bytes`,
`check_scalar` and `PrivateKey::serialize`, ECDSA signing by the key
(`ecdsa::sign`, whose signer `ecdsa::sign_compact` shares) and by the
nonce (`sign_with_nonce`, from kG to the low-S signature),
EC-Schnorr-DCRv0 signing by the key and by the nonce, the RFC 6979 nonce
by the key, `add_private_tweak` by Il and by the parent (the parent's
reduction modulo n included), and Ed25519's public key and signing by
the seed: 12 targets and a positive control. Verification, recovery,
parsing, serialization of public keys and `add_public_tweak` take public
values and are not timed. The module's documentation holds the table of
entry points and targets.

**The classes.** A scalar's: 1, 2, 0xff, 2^64 - 1, the top bit alone,
n - 1, n - 2, (n - 1)/2, n - 1 with its bottom or its top half zero,
eight bits set and eight cleared, n - 1 with every 4-bit window but the
top one zero, and a placebo. A scalar that reaches the generator's
multiplication adds five classes of the table walk's signed radix-16
recoding: every digit 1, every digit 7, every digit -8 (the largest
entry of every table, negated), the even digits zero (all 33 of the
selects for the walk's first accumulator give the identity, the one
that starts it and the 32 it adds) and the odd digits zero (the second
accumulator, which starts from the identity, adds it 32 times). Those
are the table path's shapes only. Without the table, `lincomb` first
splits the scalar by the GLV endomorphism into two halves of at most 128
bits, k = r1 + r2·λ modulo n, and recodes each half into 33 digits:
there 1, 2, 0xff, 2^64 - 1, n - 1 and n - 2 have r2 = 0 and an r1 of
mostly zero digits, the top bit alone has an r1 of 32 bits (28 of its
33 digits zero) beside a full-width r2, and the top window alone and the
five walk classes split into halves whose digits look like a random
scalar's. So the multiplication's targets also take five classes of the
split: λ, 2λ and (2^64 - 1)λ, whose r1 is 0 and r2 is 1, 2 and
2^64 - 1, and the two scalars whose halves are equal and every digit 7,
or every digit -8 below a top digit of 1 (31 digits each; halves of 32
digits of 7 are longer than the split gives, and it splits their scalar
otherwise). No other class has r1 = 0. These were added after the
review of this work, so the calibration and the 60 s measurement below
ran without them; the runs that had them follow the measurement. An HD
parent adds n, 0, n + 1 and 2^256 - 1; an Ed25519 seed has three fixed
seeds, since SHA-512 stands between it and the arithmetic. Signing by
the key draws a fresh hash for each sample for every class, so that a
fixed key does not also fix the nonce and the signature. The class
lists are tested in every `cargo test`, the walk's digits against a port
of `primeorder`'s recoding and the split's halves against a port of
k256's `glv::decompose_scalar`, which is held to k256's bound of 2^128
on 2,000 random scalars.

**The control** is k256's variable-time multiply, `mul_vartime` on the
generator, on the multiplication's classes. It must fail, and it has
failed in every run, but by a margin that follows the machine's load:
over the 10 s runs on the desktop below, its |t| ranged from about 50 to
about 2,700 (twelve runs of a review of this work, six for each build,
gave 52 to 2,734, six of them below 500; this work's own runs gave 495
to 1,837), and over four 60 s runs from 167 to 6,840: a larger budget
does not by itself give a larger |t|. That is still five times the
threshold of 10 at its lowest, but a control |t| near 50 marks a run
whose power was low, and the planted leaks below are what measure it.

**CI.** The new `dcrec` job runs on x86_64 and arm64, each with the
default `precomputed-tables` feature and with `--no-default-features`
(k256's `lincomb`), four jobs, each target's name in its row carrying the
path, `(table)` or `(no table)`. The budgets are the first job's: 10 s a
target on pushes and pull requests, about 2.5 minutes a job; 60 s
nightly, about 14. The run is pinned to the runner's last processor with
`taskset`. A dispatch picks a suite, `tlscrypto` or `dcrec` or both, and
a target needs one. The thresholds are the harness's, unchanged.

**The calibration.** Each leak below was planted in a scratch copy of
the tree, never in the repository, and timed by `generator_multiply`,
`public_key` and signing by the nonce, both ECDSA and Schnorr, pinned to
one processor of an x86_64 Linux desktop (a 16-core Zen 4 processor)
that other processes kept busy throughout, load averages 9 to 52 on 32
logical processors. Each difference is the deciding comparison's, in
nanoseconds an operation:

| planted leak | 10 s, table | 10 s, no table | 60 s, table | 60 s, no table |
|---|---|---|---|---|
| A: one point addition for each nonzero 4-bit window, as a walk that skips zero windows | 4 of 4 found, \|t\| 36 to 377 | 4 of 4, \|t\| 51 to 128 | - | - |
| E: ECDSA's nonce inverted by k256's `invert_vartime`, about 1 µs | found, \|t\| 108 | found, \|t\| 58 | - | - |
| B: one point addition unless the top window is zero, 350 to 440 ns | 0 of 4, all reported at \|t\| 6.8 to 9.4 | 3 of 4 | 3 of 4 | 0 of 4, all reported at \|t\| 6.8 to 9.6 |
| D: four scalar multiplications unless the top window is zero, 100 to 230 ns as measured | 3 of 4 | 3 of 4 | 4 of 4, \|t\| 18 to 27 | 3 of 4 |
| C: one scalar multiplication unless the top window is zero, 19 to 30 ns as measured | 1 of 4 (`generator_multiply`, \|t\| 24.6) | 2 of 4 | 1 of 4 | 2 of 4 |

("Found" is the harness's LEAK, which fails a target; "reported" is |t|
above 4.5, which passes.) Every leak was found by some target in some
run at the CI budget, A and E by every target that reaches them. The
table shows more than that: the power of a run on a shared machine
follows the load more than the budget. B, the larger of the
top-window leaks, was only reported in the first 10 s run, while the
operation's mean doubled under a load average of 52, and in the 60 s run
without the table; C, ten times smaller, was found by
`generator_multiply` at 10 s in a quieter hour and missed by it at 60 s.
The 60 s runs of B and C overlapped, in part, a workspace build and
test of this work's own checks. In the failing runs every class with a zero top window was
the one quicker, and in dudect's quickest crops the other classes showed
as slower instead, since the random class's quick samples are its
zero-top-window draws: both are the planted leak, not noise.

**The measurement.** Every target at the nightly budget, 60 s, pinned,
with the table and without it, on the same desktop:

| target | table: t, class | difference, ns/op | verdict | no table: t, class | difference, ns/op | verdict |
|---|---|---|---|---|---|---|
| `generator_multiply` | -3.64, 0xff | -43.26 of 16,349.4 | pass | -4.67, n - 1 | -213.64 of 35,021.9 | reported |
| `public_key` | +3.20, placebo | +14.51 of 19,723.9 | pass | -4.16, 1 | -338.75 of 46,643.8 | pass |
| `key_from_bytes` | -2.71, bottom half zero | -0.03 of 49.5 | pass | -4.60, 2^64 - 1 | -0.12 of 32.8 | reported |
| `ecdsa_signing_by_key` | -3.77, 2 | -172.22 of 26,288.5 | pass | -2.76, n - 1 | -154.92 of 47,773.6 | pass |
| `ecdsa_signing_by_nonce` | -3.63, top window alone | -1.16 of 22,275.4 | pass | -3.78, top half zero | -622.66 of 55,267.4 | pass |
| `schnorr_signing_by_key` | +3.50, 1 | +3.42 of 19,852.3 | pass | -2.74, (n - 1)/2 | -38.94 of 39,233.3 | pass |
| `schnorr_signing_by_nonce` | -3.53, 0xff | -613.88 of 28,837.0 | pass | -4.30, every digit 7 | -1024.35 of 49,201.8 | pass |
| `rfc6979_nonce_by_key` | +2.74, bottom half zero | +0.35 of 996.6 | pass | -3.03, (n - 1)/2 | -0.35 of 1,046.1 | pass |
| `hd_private_child_by_tweak` | -2.97, top half zero | -0.01 of 76.0 | pass | +2.55, top window alone | +0.00 of 70.9 | pass |
| `hd_private_child_by_parent` | -2.76, low weight | -0.03 of 77.7 | pass | -5.21, placebo | -0.11 of 78.0 | reported |
| `ed25519_public_key` | -2.32, 0x55 and 0xaa | -4.20 of 11,748.5 | pass | +2.45, all ones | +3.08 of 11,844.8 | pass |
| `ed25519_signing` | +2.46, 0x55 and 0xaa | +20.99 of 25,839.4 | pass | +2.16, all zeros | +17.72 of 25,307.9 | pass |
| `vartime_multiply_control` | -624.66, 2 | -33172.50 of 38,672.1 | control found | -167.25, 2 | -34126.37 of 39,639.2 | control found |

Each row gives the class that decides the target, its largest |t| over
the uncropped test and the 100 crops, and its difference from the random
class against the random class's mean, in nanoseconds an operation. The
targets took 1.1 to 4.6 million samples of the operations of 12 µs and
more, one to a sample, and 15 to 38 million of those of 1 µs and less,
in batches of 2 to 40, each fixed class a 1/38 to 1/6 share of them and
the random class half, as the harness then drew them. Every target
passed, in both builds: no class reached |t| 10 anywhere, the largest
|t| of any target was 5.21, and three targets were reported above 4.5,
one of them on the placebo, all three negative. They were not chance
maxima of symmetric noise: a small fixed class that drew fewer than its
share of the run's rare slow outliers leans negative against the large
random class, as "The class shares" below measures. Every target's
thread was pinned to one processor, as its trace
line shows. The load averages over the two runs were 20 to 43. The
control was found at |t| 625 and 167.

**With the split's classes.** After the five classes of the GLV split
were added, every target ran again on the same desktop, pinned, both
builds at once on two processors, at 10 s and then at 60 s, load
averages 11 to 35. Every target passed in all four runs. At 10 s the
largest |t| of a target was 5.29 (`generator_multiply` without the
table, 2^64 - 1, reported), and of a split class 4.54 (the same target,
both halves every digit 7, reported) and 3.79 with the table; the
control was found at |t| 1,837 and 1,114. At 60 s the largest |t| was
7.89, `generator_multiply` without the table on the class 2, reported:
a difference of -1,163 ns on a mean of 39,267 ns in the uncropped test,
which came from one of the six segments of the run, -7.89 there against
-2.92 to +0.85 in the others, in the minute of the run's highest load
average, 35, while crop 32 gave the class -0.12 (-5 ns). In the earlier
runs the class with the largest |t| on that target was another each
time (n - 1, 2^64 - 1). It was the machine's noise in the slow tail, not
a leak, and it took that sign and size because of the class shares: a
class of 1/48 of the samples that drew none or few of that minute's
slow outliers, against a random class of half of them that drew its
share ("The class shares" below). The split classes' largest |t| at 60 s was
4.29 (`generator_multiply` with the table, (2^64 - 1)λ) and 3.04
without it, where they mean something (ECDSA signing by the nonce, both
halves every digit -8). The control was found at |t| 6,840 and 5,603,
so at 60 s too its |t| spans more than a factor of 40 between runs.

**The class shares, and a false leak they caused.** Everything above
ran on the harness as it then drew its classes: half of the samples
random, and each fixed class an equal share of the other half, 1/48 each
for the multiplication's 24. The review of this work counted the rows
of every clean dcrec run of this work and of its first review: 288 rows,
189 of them negative, and of the 24 above 4.5, 23 negative, almost all
in the uncropped test or in crops 82 to 99. Symmetric noise gives 23 or
more of 24 of one sign with probability about 3·10^-6. The cause is the
shares together with Welch's t, which estimates each side's variance
from that side's samples alone. A run's slow tail is rare outliers that
fall on whichever sample they hit. A fixed class that gets none of the
few its share should bring has a lower mean than the random class and a
far smaller variance, and its t comes out near -√k for the k outliers
the random class got, k being 24 times a fixed class's expected count.
The crops do not remove them: the uncropped test counts, and the
thresholds of crops 98 and 99 are the warm-up's slowest times, which
keep them. A neighbour pinned to the timed processor showed what that
does. A data-independent Python loop that spins for 1 ms after each
sleep of an exponential interval of mean 42 ms, about 2.4% of the
processor, failed unchanged code: the review counted 4 false leaks in 25
runs of `generator_multiply`, `ecdsa_signing_by_nonce` and the table's
full suite, its verification 3 in 14, each negative, at |t| 10.1 to
11.2 on differences of 330 to 660 ns, in the uncropped test or crop 99,
while crop 32 gave the same class |t| under 3 and each segment about -4
to -5, the -√k a sixth of the run predicts. Without the neighbour, none
of ten such runs failed. The neighbour is artificial, but it stands for
anything that shares the pinned processor in bursts, as other work can
on a shared CI runner, where the job pins to the runner's last
processor and cannot keep other work off it.

The harness now gives every class, the random one included, a share of
1/(K + 1) with K fixed classes (`crates/dcroxide-testutil/src/ct.rs`;
`dcroxide-tlscrypto`'s own copy is unchanged and still draws half of its
samples random; *2026-11-20: that copy is gone, and its targets draw
equal shares on this harness, ADR-0015's addendum of that date*).
A class that misses its outliers then leans by about
-√k with k its own expected count, and t follows the difference of two
counts of the same expectation, about a standard normal. For a leak on
one class the shares cost no precision when the noise dominates: the
variance of the difference of the means is σ²(1/n_fixed + 1/n_random),
2(K + 1)σ²/N of N samples either way. They cost |t| only where the
random class's spread comes from the leak itself, a leak large enough
to be found far above 10 either way. A harness test,
`a_bursty_neighbour_does_not_fail_a_class`, simulates 60 fixed classes
alike with an outlier of 100 µs in one operation of 100, drawn whatever
the class: with the draw put back to half random it fails at t -12.3,
as -√150 predicts, and with equal shares it passes under three seeds.

On the same desktop, after the change, at load averages 1.4 to 19:

- With the same neighbour on the same processor, 16 runs of
  `generator_multiply` and `ecdsa_signing_by_nonce` with the table at
  10 s gave no leak, the largest |t| 4.80; the old harness's binary, run
  at the same time on another processor of the same cache domain with a
  neighbour of its own, gave 4 false leaks in its 16 (|t| 10.40 to 10.66,
  all negative, all crop 99) and two more rows at -7.02 and -9.99. The
  full suite with the neighbour, both builds at 10 s, passed, the
  largest |t| 5.39, the control found at |t| 171 and 183.
- Without a neighbour, the full suite at the CI budget, 10 s, and at
  the nightly's, 60 s, in both builds, passed: the largest |t| was 5.52
  at 10 s (`ed25519_signing` with the table, 0x55 and 0xaa, positive) and
  5.51 at 60 s (`schnorr_signing_by_nonce` with the table, class 2), the
  control found at |t| 612 and 806 at 10 s and 2,898 and 2,435 at 60 s.
  Over all 96 rows of the new runs, control left out, 55 were negative
  and 4 above 4.5 (3 of them negative), their tests spread over the
  crops rather than gathered in the slow tail.
- Plants 1 to 6, 9 and 10 of the review's calibration and the clean
  build, on the four targets at 10 s, each paired with the old harness
  run at the same time on a neighbouring processor: 22 of 56 found by
  each. By plant: an addition skipped for every zero digit, the table
  read by a variable-time select, r2's zero digits skipped and an extra
  addition when r1 is 0, 4 of 4 each by both; an extra doubling for an
  odd scalar 4 of 4 by the new harness and 3 of 4 by the old with the
  table, 2 of 4 by each without it; a field multiplication for an odd
  scalar, about 6 ns, 0 of 4 by the new harness and 1 of 4 by the old
  (|t| 12.65) with the table, 0 of 4 by each without it; a negation for a
  high scalar and a four-limb subtraction for an odd one were found by
  neither in either build, though reported above 4.5 in some runs of
  each; and no clean run of either failed. For the largest leaks the new |t| was lower, 313 to
  815 against 595 to 4,760 for the zero-digit walk, where the random
  class's spread is the leak's own. One run of each pairing: the power
  is the same within what one run can tell, not measured more finely.

The calibration table above is the old harness's and is left as it was
measured; the repeat in the last item is the new harness's.

**What this shows, and what it does not.** On one x86_64 processor, on
one day, no class of any target differed from the random class by the
harness's rule. Planted leaks of a microsecond or more (an addition
skipped for every zero window, a variable-time inversion, the control's
variable-time multiply) were found by every target that reaches them.
Leaks of 100 to 440 ns on one window were found by most targets in most
runs, and by none in two runs on a busy machine; leaks of 20 to 30 ns
were found by one or two targets of four in each run. A neighbour that
takes the pinned processor in bursts made the harness fail clean code
before every class had an equal share, and did not in the 18 runs after;
other shapes of noise, such as a neighbour that keeps the processor for
seconds at a time and so lands within one segment, were not tried. That is evidence,
not proof. It does not show the
absence of a smaller difference: at these operations' spreads, tens of
microseconds with the machine's noise, |t| 10 needs tens to hundreds of
nanoseconds, many cycles; a leak of a few cycles in a 15 µs
multiplication is below what a minute can see. It says nothing of arm64,
which CI runs and which was not run here, nor of other x86_64
processors, compilers or builds; nothing of cache timing seen from
another process or core, of power or electromagnetic leakage, or of a
remote attacker's view; and nothing of the wiping of secrets, which the
first addendum of this date already leaves open. The CI job has not run
yet: its first runs are its own evidence, and its budgets may need
revisiting once they have. A pass by this test does not make a
dependency update safe without its own run.

**Read while doing this.** `k256` 0.14.0's `mul_by_generator` begins with
`let table = *BASEPOINT_TABLE;` (`src/arithmetic/mul.rs:184`), which
copies the whole table, 33 tables of eight points, about 31 KB, to the
stack on every call. It is not a timing leak, since the copy does not
depend on the scalar, but it is work the walk does not need; whether it
costs measurable time is for the benchmark of this work's second stage.
EC-Schnorr-DCRv0 signing negates the nonce with a branch on R's y
parity (`src/secp256k1/schnorr.rs`, `if y[31] & 1 == 1`), as dcrd does.
The parity is not published, but it tells only whether the RFC 6979
nonce or its negation became the nonce that signs, whose point is
public, so it gives nothing about that nonce. Its cost is not below
what the test can see, as this addendum first said. In
`schnorr_signing_by_nonce` with the table, in a run at the CI budget
after the class shares were made equal, crop 32 split the 23 fixed
classes by the parity of their R alone: the 11 whose R has an even y
were quicker than the random class, by 0.74 to 1.46 ns an operation at
|t| 3.1 to 6.1, and the 12 whose R has an odd y slower, by 0.72 to
1.22 ns at |t| 3.0 to 5.2, about 2 ns, some ten cycles, between them
(the parities from a probe of each class's kG, not kept). The target's
row was -9.01 (top bit alone, an even R, crop 49, -3.06 ns), reported,
not failed. The other runs of the target lean the same way less
clearly (crop 32 at 60 s gave the even classes -0.9 to -1.5 ns, the
odd ones -0.5 to +0.8), and without the table more weakly still. It is
the negation's branch, which a fixed nonce takes the same way every
time and the random class half the time, and it is a timing dependence
on the nonce's point, not on the key: it tells only which of k and -k
the RFC 6979 nonce was, as above. A run with more samples, or a quieter
machine, can carry it past |t| 10 on a difference above the 1 ns floor
and fail the target. A constant-time conditional negation (k256's
`Scalar::conditional_select` on the parity, as ECDSA's low-S
normalization already does) would remove it; dcrec's code is unchanged
here.

The rest of the Decision stands. dcrec's code paths are unchanged:
`ecdsa::sign_with_nonce` and `schnorr::sign_with_nonce` are now visible
to the crate (`pub(crate)`) for the targets that time them, and nothing
else moved.

## Addendum, 2026-11-19 (third) — a micro benchmark of the secrets, and what each claim rests on

The first addendum of this date measured the table with a program outside
the tree. The same operations, the ones the second addendum's timing test
times, now have an in-tree micro benchmark against dcrd:
`dcroxide-bench dcrec` (`crates/dcroxide-bench/src/dcrec.rs`), with dcrd's
side in the oracle's `secp_bench` command (`tools/oracle/bench.go`).

**The benchmark.** Both sides take the same cases, 8,192 by default from
a fixed seed: a key, a hash, an HD tweak and parent, an Ed25519 seed. Each
times one pass of an operation over every case in its own process, dcrd's
in the oracle's, and both fold the outputs into a digest; a difference
stops the run, so each pass is a differential as well. A warm-up pass
builds both libraries' tables. The side that goes first alternates by
operation and by round, and a flag reverses it from process to process;
`taskset` on the benchmark pins the oracle with it, since the child
inherits the pin. The workspace build cannot link dcrec without its
default feature (Cargo unifies it into every `k256`), so the no-table
path is timed as its multiplication, k256's `GENERATOR * k`, beside the
table's. A unit test, `every_operation_matches_dcrd`, runs every
operation against the oracle in each `cargo test` that has one, which CI
requires.

**Measured on m3, 2026-11-19** (docs/bench-ledger.md, "dcrec's operations
on secrets against dcrd's, in tree (2026-11-19)"; three sessions of eight
processes, the third the record, on a machine other work kept busy),
each figure the median over 40 back-to-back pairs of Rust's time over
dcrd's: ECDSA signing 0.94, EC-Schnorr-DCRv0 signing 0.83, the public key
0.86, the generator multiplication through the table 0.98 and through
`lincomb` 2.12, the RFC 6979 nonce 0.67, the private key's range check
0.71, Ed25519's public key 0.16 and signing 0.80, and HD derivation's
private child sum 1.19, about 11 ns slower than dcrd's composition of the
same calls. The signing and public-key figures agree with the first
addendum's within 0.012. Every pass of every operation gave dcrd's
outputs, byte for byte. dcrd's generator multiplication is its
variable-time `ScalarBaseMultNonConst`; dcrec's is constant time, so the
comparison is of the two libraries as they are, not of like algorithms.

**Two costs the benchmark found.**

- `k256` 0.14.0's `mul_by_generator` copies its whole table to the stack
  on every call, `let table = *BASEPOINT_TABLE;` (`src/arithmetic/mul.rs:184`,
  and `:211` in the variable-time twin that dcrec never calls). In the
  release build that is a `memcpy` of 31,680 bytes, read from the
  binary's disassembly. A scratch copy of the tree with `k256` patched to
  borrow the table (`&*BASEPOINT_TABLE`) ran 0.39 to 0.48 µs faster per
  multiplication, in the public key and both signers alike, about 3% of the
  walk. It is not a leak: the copy is the same for every scalar. The
  change belongs upstream, not in a vendored `k256`.
- `edwards::sign` derives the public key from the seed again for every
  signature, where dcrd's key carries the one `PrivKeyFromSecret` made:
  25.1 µs against 12.9 µs through `sign_with_pub_key_bytes` with the key
  supplied. Holding the expanded key and its public key in `SecretKey`
  would halve it. Nothing here changes it.

**What each claim rests on.** Two kinds of evidence stand behind dcrec's
secrets, and they are not interchangeable.

Measured, on one x86_64 desktop (m3), on one day, with Rust 1.100.0 and
Go 1.27.3:

- that dcrec's keys, signatures, nonces, HD sums and Ed25519 keys and
  signatures equal dcrd's over the benchmark's cases, as over the
  differential suites' and the soaks' far larger ones;
- the speeds above, and the cost of the table copy;
- that the release build copies the table on every call (the
  disassembly of that one function, not of anything else);
- that no class of the timing test's 12 targets differed from random
  inputs by its rule, with the table or without it, in 60 s a target, and
  that leaks planted in a scratch copy, of a microsecond down to tens of
  nanoseconds, were found as the second addendum's calibration table
  records. That is statistical evidence on one processor, not proof of
  constant time.

Read in the sources, not measured, and not inspected in the compiled
code:

- that `primeorder` 0.14.0's recoding of a scalar into signed radix-16
  digits, which k256 calls, has no branch on the scalar: nibbles, then a
  carry by arithmetic shifts (`src/tables/radix16.rs:31-55`);
- that `primeorder` 0.14.0's `LookupTable::select` reads all eight
  entries of a table for every digit and keeps one by `subtle`'s
  conditional assignment, then negates by another
  (`src/tables/lookup.rs:43-65`), so that no memory address depends on
  the scalar. The timing test times an operation from inside its own
  process; it cannot see which cache lines a walk touches from another
  process or core. That the walk touches the same ones for every scalar
  rests on this reading alone;
- that k256's point addition is the complete formula of Renes, Costello
  and Batina without a branch on its inputs (`src/arithmetic/projective.rs`,
  its comments at `:97`, `:143`, `:190`), and that `lincomb`, the scalar
  range checks, the reduction modulo N and the addition modulo N are
  constant time;
- that the compiler keeps all of that branch-free. dcrd's module says it
  inspects its generated machine code for this; dcroxide has not
  inspected k256's, beyond the `memcpy` above;
- that EC-Schnorr-DCRv0's branch on R's y parity
  (`src/secp256k1/schnorr.rs`) leaks nothing about the nonce, as the
  second addendum argues.

A leak below the timing test's resolution, of a few cycles in a 15 µs
multiplication, is excluded by neither kind. arm64, which CI times and
nothing here measured, other x86_64 processors, other compilers, power
and electromagnetic leakage, and the wiping of secrets, which the first
addendum of this date leaves open, are outside both.

The rest of the Decision stands. No shipped code changes in this
addendum: `dcroxide-bench` gains dcrec, `k256` and `dcroxide-testutil` as
dependencies, packages the lock already held, and the oracle gains one
command.

## Addendum, 2026-11-20 — EC-Schnorr-DCRv0's nonce negation selected, not branched on

The second addendum of 2026-11-19 found that EC-Schnorr-DCRv0 signing's
time depended, by about 2 ns, on the parity of the nonce point's y, through
the branch that negates the nonce (`src/secp256k1/schnorr.rs`,
`if y[31] & 1 == 1 { k = -k; }`), and left the code unchanged. On
2026-11-20 the project owner decided to replace the branch with a
constant-time conditional negation, keeping the output byte-identical to
dcrd's.

**What dcrd does.** At the oracle's pin, `schnorrSign` (`schnorr/signature.go`
of `dcrec/secp256k1/v4` v4.4.2-0.20261106175134-46e9df48109a, lines 284-292)
converts R = kG to affine coordinates and branches:
`if R.Y.IsOdd() { k.Negate() }`. Its R comes from the variable-time
`ScalarBaseMultNonConst` anyway, so the branch adds nothing there that the
multiplication does not already do; dcrec's R is constant time (the first
addendum of 2026-11-19), and the branch was the one nonce-dependent step
left on that path.

**What changes.** Step 5 of `sign_with_nonce` now reads the parity as a
`subtle::Choice` (`Choice::from(y[31] & 1)`) and selects
`Scalar::conditional_select(&k, &-k, y_is_odd)`, as ECDSA's low-S
normalization already selects its negation of s. `subtle` is reached
through k256's re-export (`k256::elliptic_curve::subtle`), so no
dependency is added. The selected nonce is the one the branch chose, so
every signature is the same: dcrd's eleven signing vectors (eight RFC 6979
rows and three explicit nonces, five of the eleven with an odd R, so both
sides of the select are pinned), the oracle differentials and the frozen
vectors pass unchanged with and without `precomputed-tables`, and a new
test, `a_nonce_and_its_negation_sign_alike`, holds that k and -k give the
same signature for 256 random nonces of both parities. The rest of the
path is unchanged: the parity is read from the uncompressed encoding of R,
as before, and the identity check before it (`expect` on R's y) is a
check of the encoding's tag, which no nonce in [1, N - 1] takes.

**The measurement.** `schnorr_signing_by_nonce`, the dcrec timing target
of signing by the nonce, at 60 s a run, built in release as
`.github/workflows/constant-time.yml` builds it, the code before the change
(`6272357`) against the code after (a tree that also held a change to
Ed25519's key, which this target does not reach), with the table and
without it. Five rounds on an x86_64 Linux desktop (a 16-core Zen 4
processor, the same machine as the second addendum of 2026-11-19), each
round the four builds at once, each process pinned with `taskset` to its
own processor (the trace line of every run shows one), 1.2 to 3.1
million samples a run, one operation a sample, at load averages of 7.9
to 29.9 as the rounds started, other builds and tests sharing the
machine. Each cell gives the
target's row, its deciding |t| and class, and then the parity split: in
crop 32, the mean difference from the random class of the 12 classes whose
R has an odd y less that of the 11 whose R has an even y, in nanoseconds an
operation, and the split statistic z, the mean crop-32 t of the even
classes less that of the odd, over √(1/11 + 1/12). Without a dependence on
the parity z centres on zero; it is a summary, not a calibrated test,
since the classes' t values are not independent draws. (The parities are
those of a probe of each class's kG run for this measurement and not
kept: the even ones are 1, 2, the top bit alone, low and high weight, the
top window alone, every digit -8, the odd digits zero, λ, 2λ and both
halves every digit -8; the placebo has none.)

| round | before, table | after, table | before, no table | after, no table |
|---|---|---|---|---|
| 1 | 4.06 (2), +1.93 ns, z -2.20 | 2.71 (2^64 - 1), -0.10 ns, z +0.12 | 3.11 (low weight), -1.31 ns, z +0.56 | 3.07 (bottom half zero), -1.64 ns, z +0.53 |
| 2 | 3.61 (2), +5.70 ns, z -2.85 | 2.37 (placebo), +1.39 ns, z -1.07 | 2.64 (even digits zero), -3.08 ns, z +0.27 | 2.82 (placebo), +11.67 ns, z -1.04 |
| 3 | **6.31** (top window alone, reported), +2.51 ns, z -14.87 | 3.44 (both halves every digit -8), +0.10 ns, z -0.58 | 2.94 (bottom half zero), +2.20 ns, z -4.09 | 3.63 (n - 1), -0.25 ns, z +0.41 |
| 4 | 3.85 (both halves every digit 7), +3.67 ns, z -9.16 | 3.39 (every digit 1), -0.23 ns, z +0.56 | 3.17 (bottom half zero), +2.12 ns, z -1.92 | 3.34 (n - 1), +0.81 ns, z -0.75 |
| 5 | **9.46** (every digit 1, reported), +2.61 ns, z -31.22 | 4.39 (top bit alone), +0.04 ns, z -0.41 | 4.45 (every digit 7), +2.74 ns, z -10.23 | 2.72 (0xff), +0.26 ns, z -1.15 |

Every run passed by the harness's rule (no class above |t| 10 on 1 ns or
more). Before the change, with the table, two of five runs were reported
(|t| above 4.5), at 6.31 and 9.46, the second on a class with an odd R,
and in every run the odd classes were the slower, by 1.9 to 5.7 ns in crop
32, z from -2.2 to -31.2; without the table the rows stayed under 4.5 (the
largest 4.45), and the split leaned the same way in three runs of five,
z -1.92, -4.09 and -10.23, and the other way, weakly, in two (z +0.27 and
+0.56), as the second addendum saw it weaker there. After the change no run
was reported, the largest |t| 4.39 on an even class with the table and
3.63 without it, and z lay between -1.15 and +0.56 in all ten runs, the
odd classes' crop-32 difference within 1.7 ns of the even ones' in nine
of them (the tenth, 11.67 ns in round 2 without the table, the round that
started at the highest load average, has z -1.04: its classes' t values
did not split by parity). So the parity
dependence the second addendum found is gone from this target's view, in
both builds.

**What this does not show.** One machine, one day, five runs a build at
the nightly budget; arm64 was not timed. The rest of the dcrec suite was
not run again: no other target's code changed. The machine code of the
select was read on x86_64 only (below); arm64's was not inspected.
Nothing wipes the negated temporary, as nothing wiped the old one.

**The machine code.** `subtle` supplies only the trait, the `Choice` and
`Choice::from`'s `black_box::<u8>`; the select itself is k256 0.14.0's
`Scalar::conditional_select` (`src/arithmetic/scalar.rs:449-452`), which
forwards to crypto-bigint 0.7.10's `Uint` select (`src/uint/ct.rs:78-81`,
its `ct_select`), and through it to ctutils 0.4.8 and cmov 0.5.4, the
versions the lock file pins. The negation is crypto-bigint's. A release
build of dcrec's unit tests for x86_64 with Rust 1.100.0
(`cargo test -p dcroxide-dcrec --release --lib --no-run`, with and
without `--no-default-features`), disassembled with `objdump -d -l`, has
no branch on the parity in `sign_with_nonce`: `Choice::from` is a call to
`subtle::black_box::<u8>`, whose body is a byte stored to the stack and
loaded back; the negation is straight-line subtraction with borrow, its
zero check `sete`; and the select is four `test; cmovne`, one for each
64-bit limb, from cmov's x86 backend. With the table, the only
conditional jumps from the end of R's affine conversion to the select are
on the SEC1 tag byte of R's encoding, which is public. Without the table
the compiler moves the four `cmovne` past the challenge and its e < N
check, whose jump depends only on the public hash, and keeps the choice
on the stack until then; still no jump reads the parity. That holds for
that compiler, those versions and that target; a different compiler
release can compile it differently, and nothing in CI reads the machine
code.

The third addendum's last item read in the sources, that the branch
leaks nothing about the nonce, no longer applies: there is no branch. The
rest of the Decision stands.
