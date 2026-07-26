# ADR-0007 — D4: JSON emission strategy for RPC byte-parity

- **Status:** Proposed (draft for decision D4) — serde was not used and the
  captures took a different form; see the 2026-07-26 addendum
- **Date:** 2026-07-03 (proposed), 2026-07-26 (addendum: what shipped)

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

## Addendum, 2026-07-26 — no serde, and the captures came from inside dcrd

Both halves of the proposal were built, but neither in the shape described.

**The emission layer does not go through serde.** `dcroxide-dcrjson`,
`dcroxide-rpctypes` and `dcroxide-rpc` declare no serde dependency at all.
dcrd's `dcrjson` is reflection-driven — one registry of command types feeds
parameter parsing, marshalling, and the generated help text — so the port
carries a runtime type model (`GoType`/`GoValue`) and `gojson.rs`
reimplements Go `encoding/json` over it. That module covers the three
behaviours the ADR named (field order from `json` tags in declaration order,
per-field `omitempty`, and Go's shortest-round-trip float formatting with its
exponent-form cutoff and `e-0X` cleanup) plus two it had not identified:
HTML-unsafe escaping of `<`, `>` and `&`, and bytewise map-key sorting. The
float formatter is therefore part of `gojson.rs` rather than a module of its
own, and its corpus is not oracle-generated: it has a dedicated test file for
the non-finite and shortest-digit paths
(`crates/dcroxide-dcrjson/tests/gojson_nonfinite.rs`) on top of the float
values the frozen vectors below carry.

**The regression suite is not golden captures from a running dcrd, and
`tools/oracle` grew no JSON commands.** Instead an in-package dump test
running inside dcrd's own `dcrjson` and `internal/rpcserver` packages freezes
the marshalled request and response bytes, the exact error codes and
messages, the one-line usage text and the full generated help output; the
Rust suites rebuild the same inputs and compare byte for byte
(`crates/dcroxide-dcrjson/tests/dcrjson_vectors.rs`,
`crates/dcroxide-rpc/tests/rpchandlers*_vectors.rs`,
`rpchelp_vectors.rs`). Comparing dcrd's own marshalled bytes is the property
the ADR wanted; taking them from inside the package reaches handler paths and
error cases that driving a live daemon over HTTP cannot.

The captures carry one staleness. They were frozen inside dcrd at
`release-v2.1.5`, and the dcrd 2.2 rpcserver delta was absorbed by editing the
affected rows in place and adding native cases rather than by recapturing the
suite at the `452c1a6c` parity target, so those rows are pinned by the port's
reading of dcrd rather than by dcrd's own bytes.

The `QUIRKS.md` escape hatch has not been used: it carries no JSON-emission
entry. Ratifying D4 remains the project owner's call.
