# ADR-0007 — D4: JSON emission strategy for RPC byte-parity

- **Status:** Proposed (draft for decision D4)
- **Date:** 2026-07-03

## Context

Compatibility surface C3 wants byte-compatible JSON-RPC responses. Go's
`encoding/json` differs from serde_json defaults in float formatting (Go uses
a shortest-round-trip algorithm with specific exponent thresholds; difficulty
and fee fields are floats), struct-order field emission, and `omitempty`
semantics. Real clients (dcrctl, dcrwallet, Decrediton) are the acceptance
arbiters (risk R3).

## Decision (proposed)

- Typed command/result structs (`dcrjson` equivalent) emitted through
  **serde with a custom serializer layer** that: (a) preserves dcrd's field
  order (serde emits in declaration order — declare in dcrd's order and lock
  with golden tests), (b) reproduces Go `omitempty` rules per field, and
  (c) formats floats via a Go-`strconv.AppendFloat('g')`-compatible
  formatter (vendored/ported, KAT-pinned against oracle-generated vectors —
  Go's shortest-float algorithm is well-specified and portable).
- Golden request/response captures from dcrd for every method (success +
  each documented error) are the regression suite: canonical JSON comparison
  always; raw-byte comparison wherever the golden bytes are deterministic.
- Any residual byte-level delta that cannot be reproduced must be proven
  irrelevant against all three real clients and documented in `QUIRKS.md`.

## Consequences

- A float-formatting module with its own oracle-generated KAT corpus joins
  the project (small, but consensus-adjacent for `getwork`/difficulty
  outputs — treat with vector rigor).
- Golden capture tooling becomes part of `tools/oracle` scope in Phase 13.
- Final ratification blocked on: a Phase 13 spike running the golden suite
  over the first ~10 methods.
