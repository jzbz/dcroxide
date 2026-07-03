# ADR-0004 — D1: Storage backend & datadir-compatibility stance

- **Status:** Proposed (draft for decision D1)
- **Date:** 2026-07-03

## Context

dcrd stores blocks in flat `.fdb` files with goleveldb metadata (`ffldb`),
plus a dedicated UTXO backend and index databases. Compatibility surface C6
(reading an existing dcrd datadir in place) is declared a stretch goal by the
project brief; fresh sync plus a bulk importer is the accepted default.

## Decision (proposed)

- Implement dcrd's `database` interface semantics (buckets, transactional
  model) as a Rust trait; back it with **`redb`** (pure Rust, no C build
  dependency, crash-safe B-tree, single-file). Keep `rocksdb` as the fallback
  candidate if profiling in Phase 7/8 shows redb cannot sustain sync-time
  write load.
- Block storage: dcrd-style flat files behind the same abstraction (this is
  also what makes an `addblock`-compatible bulk importer/exporter cheap).
- C6 stance: fresh sync default; `addblock`-format import as the migration
  path; ffldb/goleveldb read-compat explicitly out of scope until a
  separately-scheduled stretch milestone.

## Consequences

- No C/C++ toolchain requirement keeps the build simple on all three OS
  tiers and keeps `cargo-vet`/audit scope smaller.
- Crash-consistency test rig (kill -9 during writes) is required regardless
  of backend (Phase 7 exit criterion).
- Final ratification blocked on: a Phase 7 write-load prototype (headers +
  UTXO batches at sync rates) measured against rocksdb on the same hardware.
