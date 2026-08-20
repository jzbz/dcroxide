# ADR-0001 — Oracle rig: Go shim over line-JSON, pinned to dcrd release-v2.1.5

- **Status:** Accepted
- **Date:** 2026-07-03 (accepted), 2026-07-26 (addendum: the pin moved with
  the parity target)

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

## Addendum, 2026-07-26 — re-pinned to dcrd master `452c1a6c`

## Addendum, 2026-08-20 — the target moved again; the oracle pin did not

The parity target is now dcrd master `29f17894` (still 2.2.0-pre): `PARITY.md`
tracks against it, and `crates/dcroxide-testutil/src/lib.rs`'s
`DCRD_PARITY_COMMIT` refuses to run the interop harness against a daemon built
from any other commit. `tools/oracle/go.mod` did **not** move with it — every
module is still on its `452c1a6c` pseudo-version — so this is an exception to
the rule above rather than the rule working. The reason is recorded in
`PARITY.md`'s "Oracle pin" paragraph: nothing in the `452c1a6c..29f17894`
delta changes what any exporter emits, several vector sets are expensive to
reproduce, and one of them (mixpool) can only be regenerated with a clock
overlay. Move the module pins when a delta actually requires it, not on every
target bump. Every module dcrd replaces
with an in-tree directory whose source differs from its published release —
`stake`, `standalone`, `edwards`, `secp256k1`, `gcs`, `txscript`, `wire` — is
pinned to the pseudo-version at that commit, so the oracle links the code the
dcrd binary at `452c1a6c` links. The remaining pins (`chainhash`, `chaincfg`,
`blake256`, `dcrutil`, `uint256`, `base58`) are byte-identical to the in-tree
sources at that commit and stay on their release versions.

Nothing about the mechanism changed: one Go binary, line-delimited JSON on
stdin/stdout, built on demand into `target/oracle/`, with
`DCROXIDE_REQUIRE_ORACLE=1` set in CI so a missing toolchain fails instead of
skipping. The dcrd source tree is still not vendored as a submodule.
