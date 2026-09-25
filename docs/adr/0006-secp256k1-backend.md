# ADR-0006 — D3: secp256k1 backend split

- **Status:** Proposed (draft for decision D3)
- **Date:** 2026-07-03 (proposed), 2026-07-26 (addendum: the split held)

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
