# ADR-0016 — D3 stage 2: variable-time secp256k1 arithmetic owned in tree

- **Status:** Accepted 2026-11-09, with the measured results through the
  shared gate of RC5 and RC6 (addendum of that date). The project owner
  approved the route on 2026-11-08 and started it the same day (Context,
  "The approval"); it is built on the port's branch in five increments,
  RC1 to RC6, with RC3 folded into RC4 and RC7 not needed. **The
  merge-bar run passed on 2026-11-10**: a fresh G5 against master put
  full validation at 1.034 times libsecp256k1's and the default sync
  1.8 s slower, inside base's spread of 11.4 s in that session, where the
  bar is no more than 1.10 times and within that spread (Decision, "The
  merge bar"). The port plan's criteria 8 and 9, the extra soak legs and
  the committed witness vectors, are met as well (addendum of
  2026-11-10). By the bar the port merges on the project owner's word.
  This record supersedes nothing:
  [ADR-0017](0017-secp256k1-in-pure-rust.md) records D3 as built and
  supersedes [ADR-0006](0006-secp256k1-backend.md). It serves
  [ADR-0012](0012-pure-rust.md)'s rule.
- **Date:** 2026-11-08 (proposed), 2026-11-09 (accepted; addendum: the
  measured results, the merge bar pending), 2026-11-10 (addendum: the
  merge-bar run passed; criteria 8 and 9 met)

## Context

### Where D3 stands

On 2026-10-26 the project owner decided that ECDSA and every secp256k1 key
move from the `secp256k1` bindings to `k256` under ADR-0012's rule
(ADR-0006's addendum of that date), behind an oracle-backed differential soak
and a speed measurement, with "only merge if the slowdown is small or
optimized away" as the condition. The third set of answers that day made the
condition concrete (ADR-0006's index entry): speed work, "stage 2", follows if
full validation is more than 10% slower than on libsecp256k1 or the default
sync moves beyond one session's run-to-run noise.

The port is built on the branch of the pull request that carries it, six
commits over master ending at `43beedc`, then stage 2a's two (below): ECDSA
verification and signing, every key and compact recovery run on `k256`
0.14.0 by dcrd's algorithms, and `secp256k1-sys` is out of the build, which
the `cc` and `secp256k1-sys` bans (`deny.toml:81-82`) and the job that
builds with no C compiler (`.github/workflows/ci.yml:384`) now hold. Master
(`0c4154d`) still runs libsecp256k1 for ECDSA and keys.

### The gates, 2026-11-07

All three were run on an x86_64 Linux desktop, base = master `0c4154d`
(libsecp256k1 as `secp256k1-sys` 0.14.1 vendors and builds it, generator
window 15), head = `43beedc`.

- **G3, the gate soak: passed.** 427,002,940 cases in 3,630 s at the baseline
  soak's master seed `0x18e56cebf8f0edf0`, with the baseline's oracle binary;
  no disagreement and no oracle fault; every class digest equal to the
  baseline soak's on libsecp256k1, generator fingerprint `c21c897e`, pin
  `3360ae4d`; the replay equal; the model baseline and canaries C1-C18 all
  caught (ADR-0006's second addendum of 2026-10-26 describes the procedure).
  The `k256` port gives dcrd's answers on every case the soak draws.
- **G4, the signature microbenchmark** (32,768 cases, order base, head, head,
  base; digests equal across the four processes), head over base in time per
  operation at 1 and 16 threads: ECDSA verification 1.96 and 2.00; checksig
  1.92 and 1.95; compressed key parse 1.65 and 1.34; uncompressed key parse
  0.75 and 0.95; compact recovery 1.87 and 1.62; signing 1.21 and 1.23;
  EC-Schnorr-DCRv0 verification 1.00 and 0.99 (both arms ran it on `k256`).
- **G5, sync comparison.** Full validation (`--assumevalid=0`, from a dcrd
  block server on the same machine, order B H H B B H): base 477.7 s mean,
  head 715.1 s, **1.497**; CPU 1.80. Default sync from a block server on the
  local network, four runs each: base 238.1 s with a spread of 16.0 s, head
  267.3 s, **1.122**. All six full-validation runs ended on the same UTXO set
  at block 1,116,035.

**Stage 2 is triggered on both conditions**: 1.497 > 1.10, and the default
sync's 29.1 s difference is beyond the 16.0 s spread.

### Where the time goes

A profile of each full-validation arm put secp256k1 at 76.7% of base's
cycles and 88.0% of head's, and the whole wall regression in verification on
the block-connect path: the pre-verifier, which checks scripts ahead of
connection, keeps up on base and falls behind on head (pre-verify coverage
90.8% against 62.2%). Base's top symbols were libsecp256k1's `gej_double`
(31.4%), `gej_add_ge_var` (20.7%), `fe_sqrt` (8.4%) and `gej_add_zinv_var`
(7.5%); head's were `k256`'s projective `add_assign` (39.5%) and
`double_in_place` (22.3%), its field square (6.6%), the wNAF combination
(4.6%), `sqrt` (4.5%) and `crypto-bigint`'s safegcd (about 7.7% in three
functions). Against libsecp256k1, `k256`'s variable-time verification pays
for:

- complete projective formulas (doubling 6M+2S, additions of 11-12M) where
  libsecp256k1 uses Jacobian formulas with explicit special cases (doubling
  3M+4S, a mixed addition 8M+3S), on a field whose per-multiplication cost
  is already close to libsecp256k1's (`k256`'s 5x52 field is a port of
  libsecp256k1's, `k256-0.14.0/src/arithmetic/field/field_5x52.rs:1-2`);
- wNAF tables for G and for the key built on every call, where
  libsecp256k1 reads static generator tables and builds the key's table on
  an isomorphic curve so that its additions are mixed;
- a field inversion to bring the result to affine before comparing x with
  r, which libsecp256k1 avoids by comparing r·Z^2 with X;
- `crypto-bigint`'s safegcd for the scalar inverse, 3.5 to 3.7 times the
  cost of libsecp256k1's variable-time `modinv64` per call;
- a square root whose chain calls a non-inlined square, about 1.65 times
  libsecp256k1's for a compressed key (attributed, not proven).

In the code the profile ran, the calls were in
`crates/dcroxide-dcrec/src/secp256k1/ecdsa.rs` (the scalar inverse `:266`,
the combined multiply `:278`, the normalization `:294`; in recovery `:520`,
`:531`, `:540` and `:554`; at `43beedc`), and in
`crates/dcroxide-dcrec/src/secp256k1/schnorr.rs:158` and `:166` and
`crates/dcroxide-dcrec/src/secp256k1.rs:291`, all at `43beedc`.

### Stage 2a

The first step of stage 2 stays on `k256`'s public API: static affine tables
of G and 2^128·G at window 12, and dcroxide's own Straus loop with the GLV
split on the key. A prototype of it was reviewed with an exhaustive check of
its 2,048 table entries and a direct differential against dcrd's Go
`ecdsa.Signature.Verify` at the pin (1,462,459 cases, every verification
step reached, no mismatch). The project owner approved its integration on
2026-11-08 (decision 1); it has landed on the port's branch (`d50fc1c`), and
its record is ADR-0006's addendum of that date (`3c50313`).

Measured on 2026-11-08, on the same desktop and in the shapes of the
2026-11-07 gates:

- **G4**: 1.582 times libsecp256k1 per ECDSA verification at one thread
  (head 1.958 the same day); the integrated loop within 0.9999-1.0013 of
  its prototype.
- **G5**: full validation 624.7 s against base's 480.6 s, **1.300**, where
  the profile's wall-time models predicted 1.33-1.35; the default sync
  22.65 s (9.5%) slower than base, beyond the session's spread (5.6 s for
  base, 10.1 s for stage 2a). An interim measurement, with two default-sync
  runs per arm, not the merge-bar run of RC8; at 1.30 against 1.10 the
  outcome does not depend on that.
- **A G3-style gate soak** of stage 2a: 427,002,940 cases, no disagreement,
  every class digest equal to the baseline soak's, the replay equal.

Stage 2a is a real gain and does not meet the bar on its own. The same
session measured the node-side tuning of decision 3 (fifteen pre-verification
helpers and a read-ahead depth of 64, against the defaults of ten and 16) on
the `k256` head: full validation 1.3 s slower and the default sync 1.3 s
faster, neither past the bar set for it before the runs, so the defaults
stay and the rest of the gap has to come from the cost of each verification.

### The prototype, measured

Before anything was staged, the whole route was built outside the tree as
the prototype P0: the field, safegcd, the scalar, the group formulas,
generated tables at windows 12, 14 and 15, the wNAF, the Straus loop, the x
check and decompression. Its correctness:

- 53 tests in the dev profile, in release and in release with debug
  assertions, with their digests equal across the three;
- 1,591,441 verification records (1,492,547 distinct) compared with dcrd's
  Go `ecdsa.Signature.Verify` at the pin, with no mismatch, and again on a
  corpus drawn with fresh seeds, 1,078,368 of whose records were new, with
  no mismatch;
- in the same process, on the same records, against the `k256` head, stage
  2a and `k256`'s constant-time `lincomb`, with no mismatch.

Its timing, on 2026-11-08, at one thread, in the same process as
libsecp256k1, over 32,768 cases, the minimum of three rounds in each of two
runs: ECDSA verification (low S) **1.024 and 1.027** times libsecp256k1 at
window 12 (the worst over the three verification groups and both
statistics, 1.030), 1.002-1.003 at window 14 and 0.998-0.999 at window 15;
checksig 1.024-1.025 at window 12; compressed key parse 1.016-1.017; at 16
threads with SMT, on the least noisy verification group, 1.103-1.105 at
window 12. That build forces inlining of `Fe::mul` and `Fe::sqr`, of the
group formulas the loop calls and of the loop body; with only the first two
forced, window 12 measured 1.075-1.076.

This is the prototype's in-process measurement. Its arms model the seam as
it is after RC6, with no conversion to `k256` types, which is
estimated to understate RC4's G4 by 0.2-0.5%; recovery and Schnorr
verification were not timed; and 1.024-1.027 is below the floor the design
predicted (1.03-1.04 at window 12), for a reason the data does not show.

### Why the gap cannot be closed elsewhere

- **Upstream `k256`.** As read on 2026-11-07, `k256` 0.14.0 (2026-07-08) is
  the latest release. Its variable-time combined multiply is recent work
  (RustCrypto/elliptic-curves #1745, #1810, #1812, #1816, #1819, mid-2026);
  #1745's notes record that static generator tables with mixed additions
  were tried there and regressed at its window and scalar size. No open
  issue or pull request proposes Jacobian or other incomplete formulas for
  the variable-time path, an effective-affine key table, static tables in
  the combined multiply, an inversion-free x check, or a variable-time
  inverse of libsecp256k1's class, and the maintainers have asked for
  improvements expressed through the generic `group` and `wnaf` crates,
  which costs speed. Reaching libsecp256k1 there means all six changes, over
  `k256`, `primeorder`, `wnaf` and `crypto-bigint`, on the maintainers'
  timeline (0.13 to 0.14 took over three years), with a patched fork
  meanwhile; and a pull request to another project is the project owner's
  call (the third set's answer 3).
- **Other pure-Rust crates.** Parity's `libsecp256k1` is unmaintained
  (RUSTSEC-2025-0161, whose maintainers recommend `k256`) and uses the older
  10x26 field; `ark-secp256k1` and `halo2curves` are generic Montgomery
  implementations aimed at zero-knowledge work; `secp256k1`,
  `secp256k1-zkp` and similar wrap C, which ADR-0012 rules out. None is
  known to beat `k256` on a single verification.
- **A port of dcrd's own secp256k1.** The consensus reference measured
  97.4 µs per verification in Go on the same desktop, 4.1 times
  libsecp256k1: it multiplies by G and by the key separately with no shared
  doublings, uses NAF of width 2, and runs its curve code on the 10x26
  `FieldVal` (`dcrec/secp256k1/v4` at the pin, `ecdsa/signature.go:256-258`,
  `curve.go:1102-1265`). Making it fast means changing its algorithms.
- **A mechanical translation of libsecp256k1** (c2rust) is all `unsafe`,
  which the workspace forbids (`Cargo.toml:146-147`).

### The approval

On 2026-11-08 the project owner answered five decisions put the day before,
in these words: "ok let's do 1-5 can we always switch back to just using the
c secp256k1 if it doesn't work out well?" Decision 2 approved this route:
dcroxide owns its variable-time secp256k1 arithmetic (verification, recovery,
Schnorr verification; `k256` kept for keys and signing), in measured
increments, each soaked against dcrd, under a new ADR. Decision 4 kept the
approved trigger as the merge bar: a fresh full-validation comparison within
1.10 of base and the default sync within one session's spread, a result
between 1.10 and 1.20 coming back for a decision. The question in the same
sentence, whether the C library stays a way back, is answered under
Decision, "Switching back".

The design's open questions went to the owner the same day, each with a
recommendation, and were answered "go with your recommendations". That
settled: the prototype first, built and timed in process against
libsecp256k1 before anything is staged, stopping above 1.20; a new crate,
`dcroxide-secp256k1-vartime`; the licence below (libsecp256k1's notice
carried, with dcrd's ISC code as the fallback); the window chosen from the
prototype; stage 2a's pattern of a fallible fast path that falls back to
`k256`, with the wNAF builder as the GLV guard, an iteration cap on the
inverse and no `expect` in the seam; no unfreeze of the soak harness for
the gates; RC1 and RC2 sharing a gate, RC5 and RC6 likewise, RC4 with one of
its own; a `soak-asserts` profile; an `internals` feature for the fuzz
target and the benchmark, re-exports only; this record's number for route
c, with ADR-0006's superseding record taking the next free number after the
merge; the libsecp256k1 judge and the out-of-tree libsecp256k1 benchmark
arm kept; debug assertions for the new fuzz target only if cargo-fuzz's
default leaves them off; and the other files derived from non-ISC sources
swept separately, later.

After the prototype's measurement the owner said: "ok, start route c".
The owner's standing words are "pure rust everywhere" and "i don't mind
more work we care about code quality and efficiency".

## Decision

### Scope: variable time, public data only

dcroxide owns the arithmetic of these operations, all of which run on public
values:

- ECDSA verification steps 2 to 10: e = H mod N, s^-1, u1 and u2,
  X = u1·G + u2·Q, the infinity test and the x comparison with r and r+N;
- compact recovery steps 4 to 10 and its affine output, the decompression of
  R included;
- EC-Schnorr-DCRv0 verification steps 7 to 10: R = s·G + e·Q, the infinity
  test, the affine conversion, the parity and the x comparison;
- decompression of a compressed key, the uncompressed key's curve check and
  key serialization, and with them the public key itself.

Keys made from secrets, ECDSA and Schnorr signing and the RFC 6979 nonce
stay on `k256`, constant time and unchanged. Ed25519 is untouched. dcrd's
decisions stay in dcrec, in front of the arithmetic, exactly as they are:
DER and compact parsing, the r and s range checks, hashing to a scalar,
accepting any S, the error kinds and their order, and the verification step
numbering (`VerifyStep`). The new code replaces arithmetic only.

### Layout

- **A new internal crate, `dcroxide-secp256k1-vartime`**: `no_std` outside
  its tests, no `alloc`, no runtime dependency, `publish = false`, under the
  workspace's lints (`unsafe_code = "forbid"`, `missing_docs = "deny"`,
  `arithmetic_side_effects`). Every item in it is variable time and says so;
  nothing in it takes a private key, a nonce or a zeroizing type. Its public
  API is at the operation level: a scalar mod N, an affine point that is
  always on the curve with normalized coordinates, an opaque Jacobian point
  with `is_infinity`, `x_equals_var` and `to_affine_var`, and
  `ecmult_var(a, na, ng)` returning ng·G + na·A. Field elements, group
  formulas, the inverse, the wNAF and the tables are private; an
  `internals` feature re-exports the field for the fuzz target and the
  benchmark, and adds no behaviour. dcrec is its one production user; the
  fuzz crate and `dcroxide-bench` may use it. A workspace test holds that,
  that no manifest renames it, that it takes no dependency and no `alloc`,
  that dcrec's signing functions reach neither it nor the seam below, and
  that `PrivateKey::public_key` reaches the seam only to convert its
  finished, public point.
  It joins CI's no_std check by name.
- **One seam in dcrec**, a private `backend` module, the only place dcrec
  names the crate. Its contract is in dcrec's own terms (bytes and dcrec's
  key type), and ECDSA's steps 6 to 10 are written once above it, in dcrd's
  order (`dcrec/secp256k1/v4` `ecdsa/signature.go:263-293`): infinity, x
  against r, r against P−N, x against r+N. dcrec's public key holds the
  seam's key type, the crate's affine point, so verification hands it to
  the multiply as it is and parsing, recovery and serialization stay on
  it; `k256` meets a public key only in the fallback arms, which convert
  it, and in `PrivateKey::public_key`, whose constant-time product enters
  the key type once.
- **`k256` stays behind the seam as live code**: its combined multiply and
  normalization, the code G3 soaked, are the fallback when the new crate
  declines an input (below) and the reference the differential tests compare
  against.
- **`dcroxide-sigdiff` does not depend on the crate.** Its models and
  canaries stay on `k256`, so the soak's reference stays independent of the
  code under test; its independence test gains the crate's name as one no
  file of its fingerprinted sources may use. That test is outside the
  fingerprint, which stays `c21c897e`.

### The arithmetic

Ported from libsecp256k1 (`secp256k1-sys` 0.14.1's vendored copy, the code
base ran), operation for operation and branch for branch, so that a reviewer
can read the two side by side and so that the formulas keep the evidence of
libsecp256k1's own proofs of them (`sage/prove_group_implementations.sage`):

- **Field**: the 5x52 representation with u64 limbs and u128 products on
  every target (`field_5x52_int128_impl.h`, `field_5x52_impl.h`,
  `field_impl.h`), with libsecp256k1's magnitude rules. In debug builds a
  wrapper tracks each value's magnitude and normalization and checks its
  limbs against them (libsecp256k1's `fe_impl_verify`); debug-only code
  reads and asserts and never changes a value, so every profile computes
  what release computes. Operators stay plain wherever no overflow is the
  invariant, under a per-function allow whose reason states the bound, and
  `wrapping_*` is used only where libsecp256k1 relies on wraparound
  ([ADR-0008](0008-clippy-lint-policy.md)'s rule).
- **Group**: Jacobian points with an explicit infinity flag; `gej_double`,
  `gej_add_ge_var`, `gej_add_zinv_var`, and `gej_add_var` for table
  generation; the key's table built on an isomorphic curve with one global
  Z; the inversion-free x check with the r+N case. Affine outputs are
  normalized before anything reads their parity or bytes, as dcrd does
  (`curve.go:183-184`, `:1342`), where libsecp256k1 defers it to
  serialization.
- **Scalar and inverse**: a 4x64 scalar mod N, libsecp256k1's variable-time
  safegcd (`modinv64_impl.h`) for the scalar and field inverses, with
  release caps on its outer loop (twice the proven 12 batches of 62
  divsteps) and on the passes of each batch's inner loop, so that a port
  bug declines instead of hanging a verifying thread; the GLV split
  (`scalar_split_lambda`), whose bound the wNAF builder enforces: after
  folding a negative half as libsecp256k1 does, it declines any half that
  does not fit 129 positions, where libsecp256k1 checks that only in its
  test builds.
- **Generator tables**: static, in a committed generated source file that
  also defines the window, produced by a generator kept under `cfg(test)`
  and checked by a regeneration test and, entry by entry, by `k256` point
  additions. No build script, no constant evaluation, no lazy
  initialization. Window 12, 128 KiB: the prototype measured 1.024-1.027 at
  12, within the rule's first band, so window 15 (1 MiB, libsecp256k1's
  own) is not taken; it stays a lever for RC7 only if the first milestone
  lands between 1.10 and 1.15.
- **Inlining**: the prototype's policy is the starting point, forced
  inlining of `Fe::mul` and `Fe::sqr` (libsecp256k1 forces both), of the
  group formulas the Straus loop calls and of the loop body; RC7 is the
  place to revisit it.
- **Square root**: libsecp256k1's addition chain; decompression normalizes
  the root before reading its parity and again after negating it, as dcrd's
  `DecompressY` does.

**Nothing on the consensus path may panic.** Release is `panic = "abort"`
(`Cargo.toml:82`). Where the new crate declines an input (a GLV half out of
range, the inverse's iteration caps) or a conversion or consistency check at
the seam fails, dcrec takes the `k256` path with a debug assertion, and the
unit tests call the crate's fallible forms directly and require them to
succeed, so a broken bound cannot hide behind the fallback. These cases are
unreachable by the proofs the ports carry; for them the fallback keeps the
node's answer equal to the soaked one if a proof or a port is wrong.
Decompression's `None`, no point with that x, is an answer rather than a
decline, so it takes no fallback in release; builds with debug assertions
hold every such `None` to `k256`'s. The curve check of an uncompressed or
hybrid key is the same: its `None` is the answer, with no fallback, and
builds with debug assertions hold it to `k256`'s. Should a fallback arm's
conversion of the key to `k256` fail as well, which takes two independent
faults, there is no answer to fall back to, and the seam rejects with a
debug assertion. `PrivateKey::public_key`, which serves signing and not the
consensus path, has no answer to fall back to either: it panics if the
crate's curve check refuses the point `k256` computed, rather than return a
wrong key.

### Increments

The prototype of the whole route was built and measured outside the tree
first (Context); the route landed as increments, each a commit the
project owner signs, stacked on the port's branch after stage 2a. Every
wired increment is soaked before the next, RC1 and RC2 together if the
owner prefers, and RC5 and RC6 likewise. Expected effects are estimates
from the profile and the probes; only the prototype's in-process ratio is
measured. Each increment ships only code that its production callers or
the crate's public API reach, with that code's tests, so an item whose
first caller comes later (the GLV split, the field inverse, the
generator tables) lands with that caller. RC3's group formulas, key
table and generator tables would have had no caller before RC4's
multiply; on 2026-11-08 the project owner folded RC3 into RC4 ("fold rc3
into rc4"), so they land in one commit with the verification that calls
them, under RC4's gate. RC5 moves compact recovery's steps 4 to 10 and
its affine output, and EC-Schnorr-DCRv0 verification's steps 7 to 10,
onto the crate; the field inverse and the affine conversion get their
first callers with them. Each call site has one seam entry and one
fallback on `k256` (for recovery its decompression, scalar arithmetic
and `invert_vartime` too; for both its combined multiply, the one stage
2a's loop fell back to), held to the crate's answer by builds with
debug assertions.
Stage 2a's loop, its `once_cell` cell and the test that raced its first
use left the tree with it. RC6 moves dcrec's public key onto the crate's
affine point: parsing, the curve check of uncompressed and hybrid keys
included, serialization and equality read it, verification hands it to
the multiply with no conversion, and a recovered key is the point the
crate computed. `k256` keeps private keys, signing and the nonce;
`PrivateKey::public_key` converts its constant-time product once, and the
fallback arms convert the key when they run.

| step | what | wired | expected effect |
|---|---|---|---|
| P0 | the whole route as a prototype outside the tree; correctness against `k256` and against dcrd's Go verification; timed in the same process against libsecp256k1, windows 12, 14 and 15 | no | done: 1.024-1.027 at window 12, go; window 12 |
| RC0 | this record, Proposed | no | |
| RC1 | the crate with the scalar and the safegcd; s^-1 and r^-1 through the seam | yes, may share RC2's gate | ~1.3 µs off each verification and recovery |
| RC2 | the field and the square root; compressed-key decompression and recovery's R through the seam | yes, may share RC1's gate | compressed key parse from 1.65 toward 1.0 times libsecp256k1, ~1.9 µs per checksig that parses |
| RC3 | folded into RC4 (2026-11-08) | | |
| RC4 | RC3's group formulas, key table and generated generator tables at window 12 with their tests; the wNAF and GLV split, the Straus loop, the x check; ECDSA verification on the new crate. The field inverse serves only the tests and the table generator until RC5's affine conversion calls it | yes, a gate of its own | from ~1.53 to a central ~1.10-1.15 times libsecp256k1 per verification by the design's model (floor ~1.03-1.04 at window 12); the prototype measured 1.024-1.027 |
| RC5 | recovery and Schnorr verification on the new crate; stage 2a's loop and its `once_cell` dependency removed | yes, may share RC6's gate | Schnorr below base's cost; little in a sync, where Schnorr is rare and recovery is RPC only |
| RC6 | dcrec's public key held as the crate's affine point; parse and serialization on it | yes, may share RC5's gate | ~0.5-1% of a verification |
| RC7 | tuning, only if the first milestone asks for it | if changed | inlining; window 15 only if the first milestone lands between 1.10 and 1.15 (~2.5-3% of a verification) |
| RC8 | records (2026-11-09), then the merge-bar run (2026-11-10, passed) | no | |

Pre-registered thresholds, on the prototype's in-process ratio and on
RC4's G4 (one thread, head over base): at most 1.08, go on; 1.08 to 1.15,
go on with window 15, RC6 and RC7 as the levers (the node-side tuning of
decision 3 was measured and closed, Context); 1.15 to 1.20, back to the
project owner before the next increment; above 1.20, stop and report with a
profile. The prototype landed in the first band. By the profile's wall-time
models, with key parsing at libsecp256k1's cost, a per-verification ratio
of 1.10-1.15 corresponds to full validation at about 1.07-1.11 and one of
1.03 to about 1.03-1.10: the bar is within reach, not assured, and the
1.10-1.20 band of decision 4 is a live outcome. At 16 threads the prototype
measured 1.103-1.105, and full validation verifies in parallel, so RC4's
G4 and the first milestone read both.

### Tests and soaks

- **In the crate**: exhaustive tests on libsecp256k1's small-order curves of
  the formulas and of the Straus loop itself, the loop written generically
  over the curve's parameters so that its order-199 instance runs every
  pair of scalars; a structured grid on the real curve whose four digit
  streams collide by construction, with per-call-site counters asserting
  that every doubling and infinity branch ran; dcrd's group and
  decompression vectors; differentials against `k256`, an independent
  reference in the test code and, for the field multiplication,
  fiat-crypto's machine-checked code, limb for limb; boundary lattices for
  the field and the scalar; a digest over fixed vectors run in the dev and
  release profiles and required equal.
- **Against dcrd**: the grid's inputs become ECDSA and recovery cases by
  choosing the signature that makes verification recompute them, and final
  points at the boundaries (X.x in [N, P), r just below P−N, tiny
  coordinates, x near p, valid Schnorr signatures with s = 0), and keys at
  the curve check's edges in every format, are built the same way; each is
  judged by dcrd's code through the oracle in dcrec's oracle tests. The
  ones that reach each branch are committed in data files of dcrec's own,
  each with a test that regenerates or checks it; the
  soak's witness file is generated by `sigsoak emit-corpus` and must equal
  its generators' output, so it takes no hand-added line. This is what
  holds the special cases to dcrd's answers rather than `k256`'s.
- **The gate soak for each wired increment**, on the project owner's go: the
  baseline soak's master seed and oracle binary, every class digest equal to
  the baseline's on libsecp256k1, the canaries caught, the replay equal, as
  G3. No file under the soak's fingerprint changes, so every gate compares
  against the existing baseline. A reduced-volume leg in a new
  `soak-asserts` profile (release code generation with debug assertions and
  overflow checks) runs the same paths with the magnitude checks on.
- **The pin rule** of ADR-0006's second addendum of 2026-10-26 holds: a gate
  runs at a later pin only if dcrd's `dcrec/secp256k1/v4` source is
  unchanged.
- **Milestones**: a full G5 after RC4, and the merge-bar G5 at RC8.

A dcrd arithmetic bug (in its scalar split, its NAF or its byte tables)
would make the new crate, `k256` and libsecp256k1 disagree with dcrd alike;
only the soak against dcrd's own code can see one.

### The merge bar

At RC8, on the project owner's go, in one session: a fresh G5 with base =
master (libsecp256k1) and head = the final branch, as on 2026-11-07. The
port merges on the owner's word when the full-validation wall mean is at
most 1.10 times base's and the default sync's mean difference is within
base's spread in that session. A result between 1.10 and 1.20 goes back to
the owner with the numbers; above 1.20 the options are accepting the
residual (re-deciding the first set's answer 2b), asking RustCrypto
upstream, or switching back. The port plan's criteria 8 and 9 (the extra
soak legs and the committed witness vectors) complete after the last
arithmetic change and before the merge. The run passed and both
criteria were met on 2026-11-10 (addendum of that date).

### Switching back

The C library stays a way back, and how cheap it is depends on the merge,
which is the decision point:

1. **Before the merge, nothing.** Master runs libsecp256k1, the baseline
   soak at `0c4154d` shows it giving dcrd's answers, and the port, stage 2a
   and every increment of this record stay on the unmerged branch. Not
   merging is the switch back.
2. **After the merge, pure Rust first.** The `k256` arm stays live behind
   the seam, so production can move back to it, or to stage 2a's loop by
   reverting RC4 to RC6 in forward commits, with no policy change and one
   gate soak.
3. **After the merge, the C library third.** A forward change that:
   - puts a libsecp256k1 backend behind the seam in the shape master has at
     `0c4154d`: S normalized to low S before verification, since
     libsecp256k1 rejects high S
     (`crates/dcroxide-dcrec/src/secp256k1/ecdsa.rs:183-197` at `0c4154d`),
     recovery through `RecoverableSignature` (`:358` at `0c4154d`), and key
     parsing after dcrd's checks (`crates/dcroxide-dcrec/src/secp256k1.rs:181-236`
     at `0c4154d`), the hybrid-parity check included, since libsecp256k1
     accepts hybrid keys;
   - leaves EC-Schnorr-DCRv0 in Rust, which libsecp256k1 does not implement;
   - judges the shipped path in the soak: `dcroxide-sigdiff` answers ECDSA
     through `verify_detailed` (`crates/dcroxide-sigdiff/src/ours.rs:284-301`),
     consensus calls `verify` (`crates/dcroxide-dcrec/src/secp256k1/ecdsa.rs:223-225`
     delegates today), and a libsecp256k1 backend answers only a verdict, so
     either both stay on one backend or the adapter, which is outside the
     fingerprint, compares `verify`;
   - restores the `secp256k1` dependency and both lockfiles' C crates, at
     whatever `secp256k1-sys` version then builds;
   - reverses policy: lifts the `secp256k1-sys` ban and lists it among
     `cc`'s wrappers (`deny.toml:81-82`), removes or narrows the job that
     builds with no C compiler (`.github/workflows/ci.yml:384`), amends
     ADR-0012's "No C or C++" (`0012-pure-rust.md:128-131`) for ECDSA, adds
     an addendum here, and changes back the dependency ledger, README,
     PARITY.md, SECURITY.md and dcrec's "compiles no C";
   - passes one gate soak, with the oracle vectors above, which judge any
     backend.

   About one to two days of code and records, plus the soak. The reversal
   of "pure rust everywhere" for ECDSA is the real cost, and the project
   owner's decision.

No dormant `libsecp` feature is kept: cargo-deny reads every feature
(`deny.toml:1-2`), so it would fail the bans or force them weakened; Cargo
locks optional dependencies, so both lockfiles would carry C crates; the job
that builds with no C compiler builds default features only, so the feature
would go untested; and a feature that swaps the consensus backend flips the
whole node when any crate in the graph turns it on. The way back is the seam,
git history and the list above. The judge of a switch in either direction is
kept: the baseline soak at `0c4154d`, seed `0x18e56cebf8f0edf0`, fingerprint
`c21c897e`, pin `3360ae4d`, and its oracle binary (go1.26.2, sha256
`2fc78fc922ad014f13f4551a8e3838880d37cf9e35c397fdebc286c1bd5fcb53`). Since
the in-tree benchmark cannot link libsecp256k1 once the bans hold on master,
an out-of-tree benchmark with libsecp256k1 in the same process stays the
speed reference after the merge.

### Licence of the ported code

libsecp256k1 is MIT. The crate carries a `NOTICE` holding libsecp256k1's
`COPYING` verbatim and the copyright line of each file it follows (Pieter
Wuille for the field, group and scalar files; Pieter Wuille, Andrew
Poelstra and Jonas Nick for `ecmult_impl.h`; Peter Dettman for
`modinv64_impl.h`; and Russell O'Connor with the three for
`ecmult_compute_table_impl.h`, which the table generator follows). The
`NOTICE` lists only the files present in the tree at each commit, and grows
with the increments. Each derived file says `SPDX-License-Identifier: ISC
AND MIT` and names its upstream file; the crate's manifest says `license =
"ISC AND MIT"` rather than inheriting the workspace's ISC (`Cargo.toml:52`);
the root `LICENSE` gains a paragraph pointing at the crate's notice, without
adding the libsecp256k1 authors to its ISC holders. Two cases are settled
on the conservative side:

- the generated table file is `ISC AND MIT` and carries
  `ecmult_compute_table_impl.h`'s copyright line, although its entries are
  facts about the curve, because its generator and its layout follow that
  file;
- test modules ported from libsecp256k1's `tests.c` (the inverse identities
  and their case tables, the scalar and field vectors) are `ISC AND MIT`
  with `tests.c`'s line ("2013, 2014, 2015 Pieter Wuille, Gregory
  Maxwell"), so Gregory Maxwell is among the `NOTICE`'s holders.

Code is ported from libsecp256k1 alone, not from `k256`, whose field
credits libsecp256k1 under its own licences. Release archives must carry
the notice; no release workflow exists yet
([ADR-0014](0014-release-engineering.md)'s "none of it is built yet"), so
the requirement is recorded here and lands with D7's third-party-notices
step (Consequences). If the project owner rules out MIT-derived code, the
fallback is dcrd's ISC code (its formulas, `splitK`, `DecompressY` and the
Z3-proven `FieldVal64`) with a safegcd written from the paper, at the cost
of the literal port. This record rules on its own crate only; whether other
files taken from non-ISC sources need notices is a separate question.

### Not decided here

- Whether the soak harness is unfrozen once, for soak volume on valid
  s = 0 and u2 = 1: not needed for the gates; if wanted, at most once,
  between gates only, with a new baseline on libsecp256k1 before the next
  gate.
- Pull requests to RustCrypto with any of this work, each the project
  owner's call.
- The sweep of other files derived from non-ISC sources, after route c.

The record that supersedes ADR-0006 is
[ADR-0017](0017-secp256k1-in-pure-rust.md), written with this record's
acceptance on the port's branch; it takes effect with the merge.

## Consequences

- **dcroxide owns curve arithmetic on the consensus path**: about 3.5k lines
  of production code and a similar amount of tests, beside
  `dcroxide-tlscrypto`'s precedent of owned cryptography (ADR-0015). The C
  it follows has changed little in years, so the cost is mostly review. The
  code is unaudited; the literal port of reviewed, proven formulas, the
  differential and exhaustive tests and the soaks against dcrd are what
  bound that, and no audit is planned. It is a further exception to the
  project brief's principle 3, which lists it.
- **Incomplete formulas come back**, and with them the attacker-reachable
  special cases complete formulas avoid: doubling through an addition, a sum
  at infinity, and the r+N comparison, the three branches the third set of
  2026-10-26 named. The tests above target each at every call site, and the
  oracle vectors hold them to dcrd's answers.
- **`k256` narrows** to keys from secrets, signing and the nonce, plus the
  fallback arm; the dependency ledger's row changes with it and gains an
  "owned" row for the crate. fiat-crypto, already locked, becomes a
  development dependency of the crate and a dependency of the fuzz crate,
  never part of a shipped build.
- **Binary size**: the static tables give back 128 KiB of the 1.14 MB of
  read-only data the `k256` port saved (about 1 MiB if RC7 ever moves to
  window 15); stage 2a's tables, which were built on the heap at first
  use, went with RC5.
- **The merge may not come.** If the merge-bar run lands above 1.10, the
  decision returns to the project owner with the numbers; the branch stays
  unmerged meanwhile and master keeps libsecp256k1. It landed at 1.034
  on 2026-11-10 (addendum of that date).
- **Speed is measured in the shapes of the 2026-11-07 gates**: the
  prototype in process, G4 after RC4 and after RC6, and the first G5
  milestone after RC4 (addendum of 2026-11-09); the expected effects in
  the Increments table are the model's. The merge-bar G5 ran on
  2026-11-10, on the project owner's go like every timed run (addendum
  of that date).
- **32-bit targets** compute correctly by u128 semantics but are untested;
  every CI target is 64-bit.
- **Notices**: the crate's NOTICE must reach release archives;
  [ADR-0014](0014-release-engineering.md) has no third-party-notices step
  yet, a gap that exists already for the MIT and Apache dependencies and is
  a follow-up of its own.

## Alternatives

- **Stage 2a alone**, or stage 2a with dcrd's Jacobian formulas on `k256`'s
  `hazmat` field: 1.58 and about 1.36-1.40 times libsecp256k1 per
  verification (the second measured on a probe only); full validation
  measured 1.300 for the first, and about 1.21-1.30 for the second by the
  models. Neither reaches the bar; stage 2a has landed as the first step.
- **Upstream `k256` changes**: the same work in someone else's project, on
  its maintainers' timeline and design preferences, with a fork meanwhile.
  Later, optional, and each pull request the owner's call.
- **fiat-crypto's Dettman multiplication as the field kernel**: proven for
  inputs of magnitude 1, while libsecp256k1's formulas feed it up to
  magnitude 8, where it rests on the same hand bounds as a port (a probe
  found its products limb-identical to a literal port at magnitudes 1 and
  8); it would add a crate to the shipped build and take inlining out of
  the project's hands. Kept as a test oracle.
- **dcrd's `FieldVal` or `FieldVal64`**: the first is slower by design; the
  second is ISC and proven but fully reduced, so libsecp256k1's formulas
  would need a new magnitude plan, and its speed in Rust is unknown. Kept as
  the fallback if MIT-derived code is ruled out.
- **Accepting the cost** (1.50 full validation, 1.12 default sync, or 1.30
  and 9.5% with stage 2a): reverses the condition the owner set on
  2026-10-26.
- **Staying on libsecp256k1**: reverses "pure rust everywhere" and ADR-0012;
  available as the way back above.

## Addendum, 2026-11-09 — accepted, with the measured results; the merge bar pending

**What landed.** Five commits on the port's branch, each signed by the
project owner: RC1 `8851e57`, the crate with the scalar and the safegcd,
taking s^-1 and r^-1; RC2 `e7c7a6e`, the field and the square root,
taking the decompression of compressed keys and of recovery's R; RC4
`8c672e9`, RC3's group formulas and tables with the wNAF, the GLV split,
the Straus loop and the x check, taking ECDSA verification; RC5
`0632b75`, compact recovery and EC-Schnorr-DCRv0 verification, with stage
2a's loop and its `once_cell` dependency removed; and RC6 `b479c1c`,
dcrec's public key held as the crate's affine point. RC7 was to run only
if the first milestone asked for it, and its window change only if that
milestone landed between 1.10 and 1.15; the first milestone (M1) landed
at 1.035, so RC7 was not needed and the window stays at 12.

**Why Accepted before the merge bar.** The route is decided, built and
soaked, and its speed is measured in every shape but the last; what the
merge-bar run decides is whether the port merges, not whether this is
the route. The repository accepts decisions with an open condition the
same way, saying so in the status line
([ADR-0013](0013-upstream-tracking-release-tags.md), accepted "to take
effect when dcrd tags v2.2.0"). If the run fails the bar, the outcomes
of "The merge bar" above apply and a further addendum records which was
taken.

**The gates as run.** The project owner deferred the gates while the
increments were built, so RC1, RC2 and RC4
were soaked together at `8c672e9`, and RC5 and RC6 together at the tree
of `b479c1c`, where the Increments allowed RC1 with RC2, RC5 with RC6 and
RC4 alone. Each gate soak used the baseline soak's master seed
`0x18e56cebf8f0edf0` and its oracle binary, ran 427,002,940 cases with
no disagreement, matched every one of the 82 class digests of the
baseline run on libsecp256k1, replayed equal and caught the model
baseline and canaries C1-C18, at pin `3360ae4d` with generator
fingerprint `c21c897e`; the pin rule held. Each had a `soak-asserts` leg
of 762,940 cases, 10^4 per class and six small classes at their full
size, with no disagreement and replay digests equal to the baseline's.
In the RC5 and RC6 leg a decline of the crate on verification, recovery,
Schnorr verification or decompression stops the run, and the owned
results of the first three are compared with `k256`'s on every call, so
its clean pass also shows that each such call took the owned path, and
those three agreed with `k256`.

**The measurements.** On an x86_64 Linux desktop, base = master
`0c4154d` (libsecp256k1) in the same session as each head. G4 figures
are head over base in time per operation, the least over processes and
rounds, at one thread unless noted; EC-Schnorr-DCRv0 verification runs
on `k256` in base, so its row compares with that. The bench ledger
holds each run ("The k256 port against libsecp256k1, one operation at a
time (2026-11-07)" through "Route c through RC6, one operation at a time
(2026-11-09, evening)").

| measurement | `43beedc` (`k256`) | stage 2a `3c50313` | RC4 `8c672e9` | RC6 `b479c1c` |
|---|---|---|---|---|
| ECDSA verification, G4 | 1.963 | 1.582 | 1.036 | 1.031 |
| checksig (key parse, DER parse, verification), G4 | 1.917 | 1.589 | 1.033 | 1.026 |
| compressed key parse, G4 | 1.648 | 1.617 | 1.011 | 0.993 |
| compact recovery, G4 | 1.867 | 1.544 | 1.397 | 1.029 |
| EC-Schnorr-DCRv0 verification, G4 | 0.996 | 0.795 | 0.796 | 0.549 |
| RFC6979 signing, G4 (`k256` in every head) | 1.214 | 1.216 | 1.215 | 1.216 |
| ECDSA verification, G4, 16 threads | 2.002 | 1.570 | 1.106-1.146 | 1.106-1.126 |
| full validation, G5, wall mean head/base | 1.497 | 1.300 | **1.035** (M1) | not run |
| default sync, G5, mean head - base | +29.1 s (base spread 16.0 s) | +22.65 s (5.6 s) | -2.90 s (9.5 s) | not run |
| gate soak against the libsecp256k1 baseline | equal (G3) | equal | equal | equal |

- The compressed key's parse reads 1.648 for `43beedc` and 1.617 for
  stage 2a, each from its own session; stage 2a did not change parsing,
  and in the RC4 session the two read the other way round, 1.617 and
  1.648.
- RC4's integrated verification came in at 1.034-1.036, 0.7 to 1.2
  points above the prototype's in-process 1.024-1.030, more than the
  0.2-0.5% the conversions at the seam were expected to cost. The cause
  is not attributed.
- RC6's expected gain of 0.5-1% on a verification is not seen: against
  RC4 in the same session the difference, -0.15% to -0.19%, is within
  the spread. RC6 is faster than RC4 on the compressed key's parse
  (-1.87%), recovery (-26.1%) and Schnorr verification (-30.9%). Recovery
  now costs what a verification does, relative to libsecp256k1, and
  Schnorr verification about as much as an ECDSA verification, 0.549 of
  base's `k256` Schnorr.
- The RC6 session read about 0.4 points more favourably than RC4's on
  byte-identical binaries; on RC4's conditions RC6's verification is
  about 1.035.
- The 16-thread figures are indicative only: identical code moved by
  15-20% between processes at 16 threads in the RC4 session.
- M1, three full-validation runs a side: all nine pairings 1.022-1.046,
  and every UTXO set equal at block 1,116,035, as in the earlier
  sessions. The default sync, four runs a side, differed by -2.90 s,
  inside base's 9.5 s spread. In that session the dcrd block server read
  its chain from disk in every full-validation run, 9.6-17.5 GB, where
  it read none before, so the walls are higher than on 2026-11-07 and
  2026-11-08 (base 489.47 s against 477.7 s and 480.57 s); if that cost
  both arms alike the ratio is about 1.036, and head against the
  2026-11-07 base gives 1.060.
- The node-side tuning of decision 3 was closed on 2026-11-08 (Context),
  so the merge-bar run runs both arms at the defaults.

**Against the rules.** RC4's G4 is in the first band of the
pre-registered thresholds (at most 1.08, go on), and M1 at 1.035 is at
most 1.10, which continues RC5 and RC6 as planned. Read informally
against the merge bar, M1 would pass both conditions. It is not the
merge-bar run: that is a fresh G5 at the final branch against master's
tip, recorded with base's commit, in one session, with three
full-validation runs a side in the order B H H B B H and four default
syncs a side.

**What remains before the merge.** The merge-bar run, on the project
owner's go, then a records commit with its numbers in this record and in
ADR-0017; and the port plan's criteria 8 and 9, the extra soak legs
(overflow checks, `curve25519-dalek`'s serial and AVX-512 backends,
arm64) and the committed witness vectors, after the last arithmetic
change. The soak harness's unfreeze is not needed.

**What this corrects.** The status line; the Consequences' "Speed is
measured once, in process", rewritten above, and their new sentence on
the brief's principle 3; the Increments' tense and their RC8 row; the
Scope's ECDSA steps, 2 to 10, since e = H mod N runs on the crate; the
licence section's tense and its list of upstream files, which has no
ECDSA file; and "Not decided here", whose bullet on ADR-0006's
superseding record is now a sentence naming ADR-0017. The Context's
account of where D3 stands is that of 2026-11-08 and keeps its words,
including "every key and compact recovery run on `k256`", which RC1 to
RC6 have since narrowed to keys from secrets, signing, the nonce and the
fallback arms. So does the approval's "ADR-0006's superseding record
taking the next free number after the merge": that is the approval as
given, and the sentence after "Not decided here" says how it was met.

## Addendum, 2026-11-10 — the merge-bar run passed; criteria 8 and 9 met

**The merge-bar run.** One session on the x86_64 Linux desktop of the
earlier milestones, on the project owner's go. Master's tip had moved
from `0c4154d` to `012192b`, which changes only TLS signing code and
ADR-0015, so base is `012192b` on libsecp256k1. Head is `3a231c6`, whose
shipped code is RC6's with that same TLS change, merged into the
branch; otherwise only comments and tests changed after RC6. Both
arms ran at the node's defaults, route e having closed. The bench
ledger has the runs ("Route c at the merge bar in syncs
(2026-11-10)").

| | base `012192b` | head `3a231c6` |
|---|---|---|
| full validation, B H H B B H | 486.9 s, 476.1 s, 477.9 s; mean 480.30 s, spread 10.8 s | 498.1 s, 496.2 s, 496.2 s; mean 496.83 s, spread 1.9 s |
| default sync from a LAN peer, B H H B H B B H | 234.5 s, 239.5 s, 228.1 s, 232.2 s; mean 233.575 s, spread 11.4 s | 235.8 s, 236.0 s, 235.6 s, 234.0 s; mean 235.35 s, spread 2.0 s |

Full validation took **1.034** times as long in head, 1.019 to 1.046
over the nine pairings, with 1.060 times the process CPU time. The
default sync took **1.8 s** longer in head, inside base's spread of
11.4 s. All six full-validation runs ended on one UTXO set at block
1,116,035 (serialized hash `eb7f88de…c30c`, 1,850,903 outputs), the set
of every full-validation run of the first milestone, of stage 2a and of
2026-11-07; since RC6 holds public keys on the crate's point, and the
UTXO set's compressed scripts go through key parsing and serialization,
that equality is the end-to-end check RC6 was to get here. Every default
sync reached the target's hash. No run was marked disturbed, none was
repeated, and every one exited cleanly.

Against the bar: 1.034 is at most 1.10, and the default sync's
difference is within base's spread. **The run passes.** By "The merge
bar" above, the port merges on the project owner's word.

- The first milestone, at RC4, measured 1.035 and -2.90 s. RC5 and RC6
  made no difference to full validation that three runs a side resolve.
- Base's first full-validation run was 9 to 11 s slower than its other
  two. The block server read 19.5 GB from its drive in that run and
  13.2 GB in head's first, and nothing in the four after; head's first
  was only 1.9 s slower than its others, so the reads do not explain the
  difference alone, and its cause is not established. Without that run
  the ratio is 1.042.
- A system package upgrade after the first milestone changed the
  kernel's dirty-page write-back limits from fixed sizes, 256 MiB and
  64 MiB, to ratios of memory, 10% and 3%. Both arms of this run ran
  under the new settings, so its ratio and difference stand, but any
  comparison across sessions crosses that change, which was not
  isolated: base's means are 9.17 s lower in full validation and 11.95 s
  lower in the default sync than at the first milestone.

**Criterion 8, the extra soak legs.** Overflow checks on,
`curve25519-dalek`'s serial and AVX-512 IFMA backends, and arm64 all
passed. [ADR-0017](0017-secp256k1-in-pure-rust.md)'s addendum of this
date records each leg with the soak, as ADR-0014's second condition
asks of it.

**Criterion 9, the committed witness vectors.** The soak's witness
file, `crates/dcroxide-dcrec/tests/data/sigdiff_witness_vectors.txt`
(`298e570`), and dcrec's three branch files,
`vartime_ecdsa_branches.txt` (RC4, `8c672e9`),
`vartime_recovery_schnorr_branches.txt` (RC5, `0632b75`) and
`vartime_pubkey_branches.txt` (RC6, `b479c1c`), hold dcrd's verdicts for
every constructed input class of the soak and every adversarial family
of "Against dcrd" above, checked without Go and regenerated through
the oracle in CI on every platform.
`3a231c6` added the one branch no committed line reached: the Straus
loop's doubling through an addition, at each of its four call sites, as
four grid cases in each of the ECDSA and recovery files, with a test in
the crate that each still doubles at its site. With it, "Against dcrd"
holds as written: the vectors that reach each branch are committed.

**What this corrects.** The status line; the Increments' RC8 row; the
sentence that ends "The merge bar"; and the Consequences on the merge
that may not come and on the merge-bar G5 still to come. The addendum
of 2026-11-09 keeps its words, its "not run" cells and its "What
remains before the merge" included: this addendum is what came of them.
