# ADR-0006 — D3: secp256k1 backend split

- **Status:** Proposed (draft for decision D3) — on 2026-10-26 the project
  owner decided that ECDSA and secp256k1 key handling move to `k256` under
  ADR-0012 and that Ed25519 stays on `curve25519-dalek`; a new ADR is to
  supersede this one after the port, its differential soak and its speed
  measurement; see the 2026-10-26 addendum
- **Date:** 2026-07-03 (proposed), 2026-07-26 (addendum: the split held),
  2026-10-26 (addendum: ECDSA and key handling to move to `k256`; a superseding
  ADR pending; second addendum: how the soak is run and compared), 2026-10-27
  (addendum: the oracle-backed fuzz targets and the nightly soak), 2026-10-30
  (addendum: a fix to the soak's model of dcrd between the soaks)

## Context

Decred uses three signature types: ECDSA-secp256k1 (type 0), Ed25519
(type 1), and EC-Schnorr-DCRv0 (type 2). EC-Schnorr-DCRv0 is Decred-specific
(BLAKE-256 challenge; not BIP340) and needs raw scalar/point operations no
packaged signing API exposes. The daemon is verification-heavy; signing
appears only in tooling/miner paths. dcrd's acceptance rules (lax DER
parsing quirks, canonicality decisions) are the compatibility surface, per
risk R4.

## Decision (proposed)

- **ECDSA (type 0):** `secp256k1` crate (libsecp256k1 bindings) for
  verification performance, with dcrd's exact DER-acceptance behavior
  implemented in our parsing layer *in front of* the backend (the backend
  only sees normalized signatures).
- **EC-Schnorr-DCRv0 (type 2):** implemented on **`k256`** (pure Rust)
  scalar/point arithmetic, ported from dcrd `dcrec/secp256k1/schnorr` with
  all vectors.
- **Ed25519 (type 1):** `curve25519-dalek` primitives with dcrd
  `dcrec/edwards` acceptance implemented explicitly in our layer (chosen
  over wrapping `ed25519-dalek`'s packaged verifier, whose semantics differ
  from the 2017-agl code dcrd delegates to — e.g. the S range check).
- All three verify paths differential-fuzzed against the oracle to high
  volume before the chain engine consumes them (Phase 1 exit criterion).

## Consequences

- Two secp256k1 arithmetic stacks in-tree (bindings + k256). Accepted: the
  alternative — hand-building Schnorr-DCRv0 on the bindings' internal API —
  couples us to non-public interfaces.
- If differential fuzz shows k256 verify throughput is a sync bottleneck,
  the Schnorr hot path can migrate to the bindings later without changing
  acceptance behavior (vectors pin it).
- Final ratification blocked on: Phase 1 differential-fuzz soak results for
  all three types.

## Addendum, 2026-07-26 — the split held

The three backends named above are the ones the finished port uses.
At the time of this addendum, `crates/dcroxide-dcrec/Cargo.toml` depended on
`secp256k1` 0.29 (imported under the alias `libsecp256k1`), `k256` 0.13 and
`curve25519-dalek` 4, with dcrd's acceptance rules implemented in front of
each rather than delegated to them. (2026-09-23: these have since moved to
`secp256k1` 0.33.1, `k256` 0.14.0 and `curve25519-dalek` 5.0.0 per
`Cargo.lock`, and [dependency-ledger.md](../dependency-ledger.md) tracks the
current versions. Schnorr verification now computes `s*G + e*Q` with k256
0.14's `MulByGeneratorVartime::mul_by_generator_and_mul_add_vartime`, one
variable-time GLV/wNAF pass where dcrd runs `ScalarBaseMultNonConst`,
`ScalarMultNonConst` and `AddNonConst`.) The escape hatch was never needed:
the Schnorr path still runs on `k256`.

The coverage the ratification gate asked for is only partly in place. All
three verify paths are compared against dcrd live: `oracle_differential.rs`,
`schnorr_differential.rs` and `edwards_differential.rs` under
`crates/dcroxide-dcrec/tests/` drive the oracle's `ecdsa_*`, `schnorr_*` and
`ed25519_*` commands over randomized keys, hashes, tampered scalars and
malformed encodings, comparing verdicts, produced signatures and — where dcrd
exposes them rather than returning a plain error — error kinds.
The four dcrec fuzz targets under `fuzz/fuzz_targets/` — `dcrec_parse_der`,
`dcrec_pubkey_parse`, `dcrec_schnorr`, `dcrec_ed25519` — are property fuzzers,
not differential ones: they call no oracle and assert only that parsing and
signing never panic and that signatures round-trip. So the differential
coverage is a fixed-iteration test battery and the fuzzing is single-sided;
the extended differential-*fuzz* soak the gate names has not been run (CI
gives each target 60 s, the nightly job 10 minutes). `dcrec_ed25519` signs
only with `SecretKey::from_seed` keys, which are torsion-free, so it cannot
reach the torsion divergence between agl's point negation and a
scalar-negation verify that `verify_raw` guards against: building
`a*B + T` keys and ground signatures needs `curve25519-dalek` and `sha2`,
which the fuzz crate does not depend on directly. That key class is covered in
`crates/dcroxide-dcrec/tests/edwards_differential.rs` instead, by a
fixed-seed pair of witnesses (k = 0 and k = 5 mod 8) checked against both
verification forms, oracle rows for all eight small-order points and their
`a*B + T` composites at every residue of k mod 8, and a randomized sweep
(`ed25519_random_torsion_keys_verify_as_agl_does`). Extending the fuzz target
waits on a decision to add those two dependencies to `fuzz/Cargo.toml`.
Ratifying D3 remains the project owner's call.

## Addendum, 2026-10-26 — ECDSA to move to `k256`; a superseding ADR pending

On 2026-10-26 the project owner decided D3, and the split this ADR proposed is
not to be ratified. Under [ADR-0012](0012-pure-rust.md)'s rule that what ships,
and what `cargo test` builds, is Rust, ECDSA (type 0) and secp256k1 key
handling are to move from the `secp256k1` bindings to `k256`, which already
carries EC-Schnorr-DCRv0 (type 2): key parsing, verification, signing and
compact recovery all go. Ed25519 (type 1) stays on `curve25519-dalek`, which is
Rust already. The bindings' `secp256k1-sys`, ~67k lines of vendored C
([dependency-ledger.md](../dependency-ledger.md)), is the one crate in
`dcroxide-dcrec`'s build that compiles C, the only crate under which
`cargo tree -p dcroxide-dcrec -i cc` finds `cc`, and it leaves with them.
`ring`, the TLS provider, compiles C as well; its replacement, a separate part
of the same rule, is [ADR-0015](0015-tls-crypto-provider.md)'s. Most of dcrd's
acceptance rules sit in dcroxide's own layer in front of the arithmetic, where
this ADR put them, and stay there. Two checks are libsecp256k1's today and are
to move to `k256` with the rest: that a parsed key is on the curve, or
decompresses, and that a compact signature's r and s are in range. The move is
meant to change no verdict, and the soak below is what has to show that.

The same day the project owner accepted the recommended answers to twelve
questions that a plan for the port, made by reading dcrd's code against
`k256`'s, had left open. Each is recorded below where it applies. Line numbers
in dcrd's code below are in its `dcrec/secp256k1` module at the parity pin,
`3360ae4d`, as the oracle pins it.

**What the tree holds today.** The decision is not built: the code is still the
split the 2026-07-26 addendum describes, with two facts that addendum did not
record.

- **`k256` already signs some ECDSA.** Since `9857639` (2026-09-24),
  `ecdsa::sign` hands a hash at or above the group order N to
  `sign_rfc6979_unreduced_hash`, a port of dcrd's `signRFC6979` on `k256`
  (`crates/dcroxide-dcrec/src/secp256k1/ecdsa.rs`), because libsecp256k1
  reduces the hash mod N before it derives its RFC6979 nonce and dcrd's
  `NonceRFC6979` takes the hash as it is. Below N, libsecp256k1 still signs.
  PARITY.md's `dcrec/secp256k1` row records this, and the text above does not.
  It is signing only, and changes nothing dcroxide accepts.
- **libsecp256k1 holds every secp256k1 key.** `PublicKey` and `PrivateKey`
  (`crates/dcroxide-dcrec/src/secp256k1.rs`) wrap the bindings' key types, and
  `PublicKey::parse` hands each key, Schnorr keys included, to
  `libsecp256k1::PublicKey::from_slice` once dcroxide's own format checks pass.
  Schnorr verification gets the point into `k256` by serializing it
  uncompressed and parsing it again (`as_k256_point`). Compact recovery,
  `recover_compact`, runs on libsecp256k1 too; its one caller is the
  `verifymessage` RPC (`crates/dcroxide-rpc/src/handlers.rs`), not a consensus
  path.

**The gate was not met, and its timing has lapsed.** This ADR wanted all three
verify paths differential-fuzzed to high volume "before the chain engine
consumes them". The chain engine has called all three since it was built, and
the soak was never run. What exists is what the 2026-07-26 addendum lists:
oracle batteries of fixed iteration counts, seeded afresh on each run unless
`DCROXIDE_TEST_SEED` is set, with no running total kept, and dcrec fuzz targets
that check dcroxide only against itself. Two syncs with `--assumevalid=0`, on
2026-10-19 and 2026-10-24, validated every block of mainnet's chain to
1,116,035 in full (README.md), so the builds synced accepted every signature in
that history; what dcroxide rejects rests on the batteries, as README.md says.
Two input classes the random batteries did not generate were found outside
them:

- torsion-carrying Ed25519 keys, a consensus divergence live from `5bf83a6`
  (2026-07-04) until `e57120d` (2026-08-19) and found by the 2026-08 security
  review. The fix's commit message calls the differential "blind to this by
  construction", since every key it drew was torsion-free; oracle rows for the
  class landed in `9b343c4` (2026-09-23);
- ECDSA signing of a hash at or above N, fixed in `9857639`: a valid signature
  that differed from dcrd's, which the header of
  `crates/dcroxide-dcrec/tests/review_ecdsa_sign_unreduced.rs` says the
  random-hash differential never saw, at odds of about 2^-128.

Inference: more runs over the same input shapes would have found neither;
naming the classes would have. The oracle has gaps the 2026-07-26 addendum did
not list: it has no command for compact signing or recovery, and its
`ecdsa_verify` takes 33-byte keys only (`tools/oracle/main.go`).

**What the port has to keep.** The reading behind the plan found three things
this ADR and its first addendum do not say.

- **Verification accepts any S.** dcrd's `Signature.Verify` refuses only an r
  or s of zero (`ecdsa/signature.go:229-231`), and `Signature::verify` reaches
  the same verdict by negating a high S before libsecp256k1 sees it. Refusing a
  high S in verification would not split the chain: `OP_CHECKSIG` and
  `OP_CHECKMULTISIG` refuse an S above half the group order before they verify
  (`check_signature_encoding`,
  `crates/dcroxide-txscript/src/consensus.rs:224-242`, called at
  `opcodes.rs:1567` and `:1769`). It would change what `Signature::verify`
  answers its other callers, dcrec's public API and `merge_multi_sig` in
  txscript's `sign.rs` (`:451-473`) among them. So dcrd's rule is kept, and the
  port does not verify with `k256`'s ECDSA verifier from `ecdsa` 0.17, which
  refuses a high S because `k256` sets `NORMALIZE_S` (`k256` 0.14.0
  `src/ecdsa.rs:104-106`, `ecdsa` 0.17.0 `src/hazmat.rs:142-144`); it follows
  dcrd's algorithm instead.
- **Three branches an attacker can reach in consensus.** A script can take its
  public key from the spending input's signature script, which the signature
  hash does not commit to: it commits to the script of the input being signed
  and to empty scripts for the others
  (`crates/dcroxide-txscript/src/sighash.rs:294-319`). A pay-to-script-hash
  redeem script that is only `OP_CHECKSIG` is one such script. Whoever spends
  such an output knows the hash before choosing the key, and can solve for a
  key that sends verification down a branch an honest signature reaches with
  negligible odds:
  - dcrd's r + N branch, which accepts a signature whose sum has the x
    coordinate r + N, below the field prime (`ecdsa/signature.go:281-293`). A
    verifier that compares that x with r as bytes, or skips the branch, refuses
    a block dcrd accepts, and the chain splits;
  - a sum at the point at infinity, which dcrd refuses (`:260-265`);
  - point doubling: dcrd's addition doubles when its two points are equal
    (`curve.go:229-234`, `:459-464`), in ECDSA's u1·G + u2·Q
    (`ecdsa/signature.go:254-258`) and in Schnorr's s·G + e·Q
    (`schnorr/signature.go:196-198`). `k256`'s complete formulas handle it
    today; addition formulas that are not complete, the kind speed work might
    bring in, would not.

  libsecp256k1 takes the r + N branch too, so these classes pin behaviour the
  port must keep. Syncing mainnet is no evidence for any of them. Each is to
  get a constructed input class in the soak, a witness vector that dcrd's code
  generates and that is committed so that it runs without Go, and a canary, a
  deliberately broken implementation that the class must catch.
- **Untrusted key bytes go only through dcroxide's own checks.** `k256`'s SEC1
  decoding refuses hybrid keys, which dcrd accepts, and accepts a 33-byte
  compact form tagged 0x05, which dcrd refuses, and its point decoder accepts
  the one-byte identity as well (`sec1` 0.8.1 `src/point.rs:527-535`; `k256`
  0.14.0 `src/arithmetic/affine.rs:328-336`). So no key bytes from a script or
  an RPC request reach `from_sec1_bytes`: the length, format byte, coordinate
  range and hybrid parity checks of `PublicKey::parse` run first, as they do
  today, and `k256` then checks the point, or decompresses it, from its
  coordinates, so that dcrd's error kinds do not collapse into one.

**The soak, re-specified.** The gate on the port is oracle-backed differential
fuzzing of all three signature types: fuzz targets that hand each input to
dcroxide and, through `tools/oracle`, to dcrd's own code, and compare verdicts,
the keys and signatures produced, and error kinds where dcrd exposes them.
libFuzzer and the Go oracle are test tooling that never ships, the two
exceptions ADR-0012 names. dcrd's code is the only reference: the fuzz crate
gets no libsecp256k1 of its own. The targets aim at named input classes, not at
volume alone:

- **Ed25519 torsion keys:** the eight small-order points and `a*B + T`
  composites, at every residue of k mod 8, through key parsing and
  verification. Building them in a fuzz target needs `curve25519-dalek` and
  `sha2` in `fuzz/Cargo.toml`, as the 2026-07-26 addendum says, so the soak
  takes the decision that addendum left waiting; `fuzz/Cargo.lock` already
  resolves both at the versions `dcroxide-dcrec` uses.
- **Hashes at or above N,** for ECDSA signing, verification and recovery, built
  rather than drawn, since a random digest lands there with odds of about
  2^-128.
- **Key encodings:** compressed, uncompressed and hybrid secp256k1 keys, valid
  and malformed (a coordinate at or above the field prime, a point off the
  curve, an x with no point on it, a hybrid prefix whose parity does not match
  y), through key parsing, the Schnorr key parse among it, and through ECDSA
  verification.
- **The three branches above:** the r + N branch, accepting and refusing, a sum
  at infinity and a doubled sum in ECDSA verification, a doubled sum in Schnorr
  verification, and the same cases in compact recovery, whose r, s and header
  byte a `verifymessage` caller supplies.
- **High-S** ECDSA signatures, which dcrd verifies and which
  `Signature::verify` today normalizes before libsecp256k1 sees them: a class
  for dcrec's API and the multisig merge, since scripts refuse them first.
- **Recovery codes:** compact recovery over every header byte, the eight valid
  ones from 27 to 34 and those outside them, with r and s at the edges of their
  range.

dcrd's fixed vectors that dcrec does not port yet are to join its tests, which
run without Go: the ECDSA `TestSignAndVerify`, `TestVerifyFailures`,
`TestSignAndRecoverCompact` and `TestRecoverCompactErrors`
(`ecdsa/signature_test.go`), and the Ed25519 `TestGolden` of dcrd's
`dcrec/edwards`. Its 784,207-byte fixture, `testdata/sign.input.gz`, a
selection of the test cases in the Ed25519 reference's `sign.input` as dcrd's
test says, is to be committed gzipped, as dcrd keeps it, with where it came
from recorded in the dependency ledger.

**Volume, baseline and order.** The project owner accepted these floors: 10^7
cases for each parse and verification class, 10^6 for each signing, recovery
and constructed class, and every case of a class that has finitely many, such
as the 256 header bytes of compact recovery; the gate soak runs for one to
three hours. The tooling lands first and runs against libsecp256k1, before any
commit of the port, as a baseline: a divergence there is a parity bug in
today's code, to be fixed before the port. The gate soak then runs on the
ported code. If the parity pin moves while D3 is under way, the gate soak runs
against the pin current when it runs, and records it. The baseline soak and the
gate soak each start only on the project owner's word. A result records the
inputs each target ran, by class where the target can count them, the commit,
the pin, the seeds or corpus, the canaries caught, and every divergence, each
of which is a stop-ship bug whose minimized input becomes a permanent
regression test (the project brief's §7, Layer 4). The existing batteries keep
running in CI.

The project owner's decision asks for the signature code to be checked against
dcrd's before it is trusted. This record reads that as the gate soak passing on
the ported code before the port merges.

**The speed measurement.** Signature checks are a large share of full
validation: in the one profile the bench ledger records over fully validated
blocks, secp256k1 took about 38% of the user-space cycles on all threads and
BLAKE-256 compression 48.4% (docs/bench-ledger.md, "Five changes on the
block-processing thread (2026-10-11)"). That profile is of `74168e8`, a build
from before BLAKE-256's rounds were written out (`5590b07`) and before
signatures were pre-verified ahead of the block thread (ADR-0005's second
addendum of 2026-10-17), and it does not separate libsecp256k1 from `k256`.
`k256`'s ECDSA speed has not been measured here. Two measurements are to be
made, each timed run on the project owner's word:

- a microbenchmark of the two verifiers, outside the workspace, which can run
  before the port and shows early whether stage 2 (below) will be needed.
  `k256`'s `precomputed-tables` feature, off since the Schnorr code reads no
  basepoint table (the dependency ledger's `k256` row), is tried there as one
  arm. Its table serves only `mul_by_generator` and `mul_by_generator_vartime`,
  not the combined pass (`mul_by_generator_and_mul_add_vartime`) that dcrd's
  algorithm calls for (`k256` 0.14.0 `src/arithmetic/mul.rs:180-232`,
  `:303-310`), so it is expected to buy verification nothing (inference).
  Without `std` or `critical-section` the table does not build (`primeorder`
  0.14.0 `src/tables/basepoint.rs:5-6`), and `dcroxide-dcrec`'s no_std check
  builds with neither. The feature stays off unless the arm shows a gain;
- syncs that validate in full, with `--assumevalid=0`, of the build before the
  port and the build with it, interleaved on one machine in one session, since
  the bench ledger reads seconds only against a baseline run in the same
  session; and default syncs of both builds, which check no script before the
  assume-valid block (docs/operating.md) and so show the change only after it.

**The bar.** The project owner set it in two parts on 2026-10-26: the port
merges only if the slowdown is small or optimized away, and speed work beyond
the port (stage 2) is done if full validation is more than 10% slower, or if
the default sync moves beyond the run-to-run noise of one session. This record
reads the two together as the bar the port has to clear to merge: syncs with
`--assumevalid=0` that take no more than 10% longer with the port than without
it, and default syncs that do not move beyond the run-to-run noise of the
session that measures them. A port outside the bar gets stage 2 first, and a
slowdown that stage 2 cannot bring inside the bar goes back to the project
owner, whose call it then is; that, too, is this record's reading. The
superseding ADR waits for the full-validation comparison.

**Stage 2.** The first route is static tables inside `dcroxide-dcrec`, built on
the public `wnaf` crate, which `k256` already brings into the build. An
estimate, not a measurement, puts what that wins back at about 10%: `k256`'s
field type is not public (`src/lib.rs:38`, `:58`), so its additions stay its
own complete projective ones. A change to `k256` itself would be a pull request
to another project, and is made only on the project owner's word. Either way,
the doubling and infinity witnesses above guard the result. A `k256`-only
signature benchmark is to be added to `dcroxide-bench` as well, and kept, to
catch later slowdowns. The escape hatch in the Consequences above, moving
Schnorr onto the bindings, closes with this decision.

**What is pending, and what gates the superseding ADR.** None of the work is in
the tree as of this addendum. In order:

1. The differential tooling, which depends on none of the TLS work and can
   start first: the oracle commands the soak lacks (verification taking a key
   in any of dcrd's formats, compact signing, and compact recovery returning
   dcrd's error kinds), the soak's targets and classes with their witness
   vectors and canaries, and dcrd's fixed vectors above, run against
   libsecp256k1 for the baseline soak.
2. The port, in five steps: verification on `k256`, by dcrd's algorithm;
   signing of every hash on `k256`; `PublicKey` and `PrivateKey` on `k256`,
   with the curve check and decompression that `PublicKey::parse` leaves to
   libsecp256k1 today; `recover_compact` on `k256`, with the `secp256k1`
   dependency, and `secp256k1-sys` with it, removed; and the text that names
   the backend. Within them:
   - dcrd's `SignCompact` (`ecdsa/signature.go:771-786`), about 40 lines,
     ported as a public function, so that the oracle can check the recovery
     code byte for byte;
   - `recover_compact` reporting dcrd's error kinds, checked in dcrd's order,
     as new variants of the `ecdsa::Error` that DER parsing returns, since
     dcrd's ECDSA package has one error type for both; four of
     `RecoverCompact`'s eight kinds are DER's already (`:858-990`);
   - the temporary copies of a private key that signing makes zeroed, as dcrd
     zeroes its own (`:700-713`), with `zeroize` as a direct dependency. It is
     pure Rust and already in `dcroxide-dcrec`'s build under `k256` and
     `curve25519-dalek`; its wipe barrier, an empty `asm!` (`zeroize` 1.9.0
     `src/barrier.rs:69`), is one of the inline-assembly barriers ADR-0012
     allows, each named in the dependency ledger;
   - the crate's `std` feature, which today selects only libsecp256k1's
     per-thread context and which no dependent names, removed, with the second
     `dcroxide-dcrec` test run in CI that exists for it, and the no_std job's
     notes on `secp256k1-sys` rewritten;
   - the `k256`-only benchmark in `dcroxide-bench`;
   - the crate docs and manifest, the dependency ledger, PARITY.md's `dcrec`
     rows, the brief's §8 "As built" paragraph and README.md's `dcroxide-dcrec`
     entry brought in line.
3. The gate soak on the ported code, to its floors, with every divergence it
   finds fixed; and the speed measurement, with stage 2 if the bar calls for
   it.

The port merges once the gate soak has passed on it and it is inside the bar
(this record's readings, above). A new ADR, which takes the next free number
when it is written, then records the soak, the measurement and the pin the gate
soak ran against, and supersedes this one, whose status then names it. Until
then this ADR and its addenda describe the code in the tree. The soak passing
is also one of the conditions the project owner set the same day for publishing
any binary (D7, [ADR-0014](0014-release-engineering.md)), and its sign-off
falls under the project brief's §7 gates as amended that day.

## Addendum, 2026-10-26 (second) — how the soak is run and compared

The soak's tool, `dcroxide-sigdiff` with its `sigsoak` binary, was designed the
same day, and the design left five questions on the wording of the plan the
project owner had approved. The owner accepted the recommended answer to each:

1. **What the freeze covers.** The plan held the soak's code frozen from the
   baseline soak on libsecp256k1 to the gate soak on `k256`, or the baseline
   run again. The freeze covers the modules that build inputs, model dcrd's
   answers and judge them, whose source a fingerprint built into `sigsoak`
   covers (`crates/dcroxide-sigdiff/src/fingerprint.rs`). `src/ours.rs`, the
   one module that calls `dcroxide-dcrec` and the one the port's steps edit,
   and the plumbing that runs and records cases may change between the two
   soaks. `sigsoak compare` refuses two runs whose fingerprints differ.
2. **What a canary may trip.** Each deliberately broken model, a canary, has a
   primary class, where it must be caught within 10^4 cases, and a footprint of
   classes it may also trip, declared in code; tripping a class outside its
   footprint fails the run. The plan's "in no other class" cannot hold for the
   canaries whose break necessarily shows in a neighbouring class.
3. **The floors over the window.** If the calibration minute shows the floors
   need more than the 1-3 hour window, the window stretches and the floors
   stay.
4. **Ed25519 error text.** A case where dcroxide's Ed25519 error text differs
   from dcrd's while the verdicts agree is a disagreement, and blocks the gate.
5. **A pin move between the soaks.** The gate soak may run at a later pin than
   the baseline only if the move leaves dcrd's `dcrec/secp256k1/v4` and
   `dcrec/edwards/v2` source unchanged; otherwise the baseline is run again at
   the new pin. `sigsoak compare` refuses runs at different pins unless told,
   with `--allow-pin-change`, that this rule allows it.

Three further points of the design, which change nothing approved, follow its
recommendations: recovery error kinds are compared from the port step that
makes `recover_compact` report them; `dcroxide-sigdiff` has no build script;
and the port's ECDSA verification reports which of dcrd's steps decided it, as
EC-Schnorr-DCRv0's `verify_detailed` does, so that the soak checks each
constructed case's branch against dcroxide's own answer.

The microbenchmark the plan names ran the same day, before any port (bench
ledger, "ECDSA verification on libsecp256k1 and on k256 (2026-10-26)"): one
ECDSA verification costs about twice as much on `k256` as on libsecp256k1.

## Addendum, 2026-10-27 — the oracle-backed fuzz targets and the nightly soak

The fuzz crate gains six signature targets, which read their inputs through the
soak's tool, `dcroxide-sigdiff` (`crates/dcroxide-sigdiff/src/fuzz.rs`). Five
of them, `dcrec_diff_ecdsa` (the ECDSA and DER classes), `dcrec_diff_recover`,
`dcrec_diff_pubkey`, `dcrec_diff_schnorr` and `dcrec_diff_ed25519`, take an
input's first byte as one of the soak's input classes, the next eight as the
case index and the rest as the class generator's entropy, so that the fuzzer
steers the constructions the soak draws from its seed; together they reach all
82 classes. Every request of the case is answered by `dcroxide-dcrec` and,
through one `tools/oracle` per fuzz process whose pin is checked before the
target fuzzes, by dcrd's own code, and the soak's own comparison holds the two
answers side by side. The intents a generator attaches to a case are first
rebased on the soak's models, since a stream the fuzzer chooses can make a
construction miss the branch it was built for while both sides agree; the four
torsion classes keep the Accept or Reject their generators compute from the
signature they built. Any failure the comparison reports, and an oracle that
fails on an input, ends the target with the case, every request and both
answers, and `sigsoak fuzz-replay` replays the input without libFuzzer. The
entry is plumbing in the soak's fingerprint lists: no soak run, digest or
witness passes through it, and the generator fingerprint did not move. The
targets run in CI's 60-second and ten-minute fuzz jobs, the nightly one also
reading inputs from `sigsoak fuzz-seeds` that regenerate each class's per-PR
cases. That is regression evidence on the code in the tree, not the soak that
gates the port.

The sixth, `dcrec_ed25519_model`, reads the Ed25519 classes' inputs the same
way and needs no oracle: it holds `dcroxide-dcrec`'s Ed25519 key parsing,
signature parsing and verification to the soak's Go-free model of dcrd's
parsing and of agl's verification, and requires every signature dcrec makes to
verify under the model. Its classes build what `dcrec_ed25519`, which signs
only with keys from a seed, cannot reach: the eight small-order points and
`a*B + T` keys at every residue of k mod 8, their non-canonical encodings, and
zero-S signatures with a small-order R. The model decodes points with the same
`curve25519-dalek` decompression as dcrec, so only `dcrec_diff_ed25519` holds
that decoding to dcrd, and the model's own parsing has unit-test evidence only.
`dcrec_ed25519` keeps its four properties, unchanged. The decision the
2026-07-26 addendum left waiting is taken through the `dcroxide-sigdiff` path
dependency rather than direct `curve25519-dalek` and `sha2` lines in
`fuzz/Cargo.toml`: both are still reached, through sigdiff, at the versions
`dcroxide-dcrec` uses, and `fuzz/Cargo.lock` gains only the two path crates,
`dcroxide-sigdiff` and `dcroxide-testutil`. The fuzz crate still takes no
libsecp256k1 reference: libsecp256k1 reaches it only through `dcroxide-dcrec`,
as the code under test, and the references are dcrd, through the oracle, and
the soak's models.

The soak itself also runs in CI each night, in three legs: x86_64 over every
class, x86_64 with `curve25519-dalek`'s portable serial backend over the Ed25519
classes, and arm64 over every class. Each leg runs `sigsoak run` for 35 minutes
from a fresh seed, which it prints, or from the seed a manual dispatch names.
The run fails on any disagreement with dcrd, any dcroxide panic, any intent a
case missed, any outcome mix out of its band, or any class short of a hundredth
of its floor, finite classes whole; `sigsoak run` gains `--min-scale` for that
last check, since a budget run did not judge the floors before. Each leg then
runs a fixed-seed record, 10^4 cases of each sampled class and the finite
classes whole under one master seed that never changes, which
`sigsoak compare --exploratory` holds to equal digests from one night to the
next; the nights before the port are the baseline, on libsecp256k1, that the
nights after it are compared with. The x86_64 leg also runs the canaries at the
soak's volume. Every night's records are kept for 90 days. None of these runs is
gate-eligible: they are regression evidence, and the soak that gates the port is
still the one run on the project owner's go.

## Addendum, 2026-10-30 — a fix to the soak's model of dcrd between the soaks

The design of the oracle-backed fuzz targets and the nightly soak, the
2026-10-27 addendum's subject, left one question to the project owner: what
follows when fuzzing finds a bug in the soak's Go-free model of dcrd
(`crates/dcroxide-sigdiff/src/model/`) after the baseline soak has run and
before the gate soak. A model file is frozen, so item 1 of the second 2026-10-26
addendum has the baseline run again. Of the three ways the design gave (run the
baseline again; leave the bug until after the gate soak; or compare the gate
soak, with the fix, with the original baseline), the owner chose the third on
2026-10-30, with the three conditions recommended with it:

1. **Model-only changes.** It applies only when every frozen file that differs
   between the baseline's commit and the gate soak's lies under `src/model/`.
   Any other frozen file that differs means the baseline is run again.
2. **An exact match.** The gate soak runs at the baseline's seeds and counts,
   and every class's digest equals the baseline's. A partial match does not
   count.
3. **A record.** The fix lands with the fuzz input that found it, shrunk to a
   small test, and the comparison's output, with its line naming the
   relaxation, is kept with the gate soak's record and noted in this ADR.

In a soak run the model's view of a case is consulted only by two of the
comparison's intent checks, those of the ECDSA branch and the EC-Schnorr-DCRv0
reason a case was built for, never by the checks of dcroxide's answer against
dcrd's (verdict, value, flag, error kind, text). The generators also build from
`src/model/`: the recovery classes derive their compact signatures' header
bytes, and some of their intents, from four constants of `src/model/ecdsa.rs`,
and some ECDSA verification classes' intents are steps of the branch type that
`src/model/mod.rs` defines. A change under `src/model/` can therefore alter a
case's request bytes or intents as well as the model's view. A digest leaf
covers a case's request bytes, dcrd's canonical answers and the case's status,
and the status includes every intent check: a change that alters any soak case's
requests or result changes its class's digest, and so equal digests leave a
second baseline nothing to find.

`sigsoak` gains what checks condition 1 from the two runs' records. Every
manifest a run or a canary run writes holds, beside the generator fingerprint,
each frozen file's own hash (`tool.frozen_sources`), and
`sigsoak compare --allow-model-change` accepts two runs whose fingerprints
differ only when both manifests hold the list and every frozen file that
differs, by hash or by being in one list only, lies under `src/model/`;
otherwise it fails, naming each file outside it or the run without a list. The
comparison's verdict line names the relaxation. Every other check stays, equal
final digests for every class among them, and the flag is refused beside
`--replay` and `--allow-subset`, which compare only part of a run.
`--allow-fingerprint-change`, which accepts any two fingerprints, is unchanged
and serves exploratory comparisons. The recommendation the owner accepted named
it for the comparison with the baseline; this record reads condition 1 as
checked by the narrower `--allow-model-change`, so of the two fingerprint flags
the gate soak's comparison with the baseline uses only that one, while
`--allow-pin-change` stays available under item 5 of the second 2026-10-26
addendum. `sigsoak compare` does not enforce the choice, but the kept output's
verdict line (condition 3) names the flag used. No baseline soak has been run,
so the baseline's record will hold the list.
