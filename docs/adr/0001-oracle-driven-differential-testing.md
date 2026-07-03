# ADR-0001 — Oracle rig: Go shim over line-JSON, pinned to dcrd release-v2.1.5

- **Status:** Accepted
- **Date:** 2026-07-03

## Context

The project brief (§4, §7) makes dcrd the specification and requires
differential testing against it for every consensus-relevant module. We need a
mechanism for (a) regenerating test vectors from dcrd instead of trusting
inherited fixtures, and (b) live differential fuzzing/testing where dcroxide
and dcrd process identical inputs and results are compared.

Options considered: cgo/FFI linking of dcrd packages into the Rust test
binary (fragile, couples build systems), golden-file-only vectors (no live
differential capability), or a standalone Go subprocess speaking a simple
protocol (loose coupling, works on all three target OSes, trivially
extensible).

## Decision

`tools/oracle` is a standalone Go module producing one binary, `dcrd-oracle`,
that links real dcrd packages and serves requests over **stdin/stdout,
one JSON object per line** (`{"cmd": ..., ...}` → `{"result": ...}` or
`{"error": ...}`). New capabilities are added as new `cmd` values.

Every dcrd module dependency in `tools/oracle/go.mod` is pinned to the exact
version required by dcrd `release-v2.1.5`'s `go.mod` — the parity target.
Versions move only when the parity target moves.

Rust tests build the oracle on demand (`go build` into `target/oracle/`) and
spawn it. Locally, a missing Go toolchain skips differential tests with a
notice; in CI, `DCROXIDE_REQUIRE_ORACLE=1` turns a missing toolchain into a
failure so differential coverage can never silently disappear.

## Consequences

- Differential tests require a Go toolchain (CI installs one; developers
  without Go still get the full non-differential suite).
- Process-per-oracle with line-delimited JSON is slow relative to FFI, but
  hashing/validation throughput is dominated by pipe round-trips only for
  tiny inputs; acceptable for test volumes, and batching commands can be
  added later if needed.
- The full dcrd source tree is *not* vendored as a submodule yet; the Go
  module proxy provides pinned, checksummed sources. A submodule checkout for
  source-reading/test-porting convenience can be added when Phase 1 porting
  begins in earnest.
