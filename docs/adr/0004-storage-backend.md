# ADR-0004 — D1: Storage backend & datadir-compatibility stance

- **Status:** Accepted (decision D1 ratified by the project owner)
- **Date:** 2026-07-03 (proposed), 2026-07-05 (accepted),
  2026-07-26 (write-load gate resolved — see the amendment below)

## Context

dcrd stores blocks in flat `.fdb` files with goleveldb metadata (`ffldb`),
plus a dedicated UTXO backend and index databases. Compatibility surface C6
(reading an existing dcrd datadir in place) is declared a stretch goal by the
project brief; fresh sync plus a bulk importer is the accepted default.

## Decision

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
- A Phase 7/8 write-load validation (headers + UTXO batches at sync rates)
  remains a gate before M2: if redb cannot sustain sync-time write load,
  the interface abstraction makes swapping in rocksdb a contained change
  and this ADR gets superseded rather than silently amended.

## Amendment, 2026-07-26 — write-load validation (gate resolved)

The Phase 7/8 write-load gate has been run at mainnet scale. redb sustains
sync-time write load: dcroxide syncs mainnet from genesis to tip with full
consensus validation, from a dcroxide source and from a dcrd source alike.
The gate therefore does not fire, rocksdb was not exercised, and the
Decision above stands as written — this section records the outcome and its
cost, and amends nothing that was decided.

### What was measured

One machine, loopback, fresh datadir per run, both nodes `--norpc`, mainnet
genesis to tip (~1,100,400 blocks). dcroxide 2.2.0-pre against dcrd
2.2.0-pre+452c1a6c3 (go1.26.5), each syncing from each. Storage figures are
read from the real 14.48 GiB `metadata.redb` that sync produced, not from a
synthetic write load.

### Throughput

| syncer / source | from dcroxide      | from dcrd          |
|---|---|---|
| dcroxide        | 2.47 h — 124 blk/s | 2.51 h — 122 blk/s |
| dcrd            | 1.11 h — 276 blk/s | 1.02 h — 299 blk/s |

The syncer decides the time and the source barely matters: swapping the
source moves the run 1.6–8.8%, swapping the syncer moves it 2.2x. dcroxide
is ~2.2x slower than dcrd at initial block download.

The cause is the storage engine's commit shape, not validation. dcroxide
spent 80.1% / 82.4% of wall time in progress stalls longer than 20 s; dcrd
stalled zero times in 754 windows. goleveldb's LSM commit is O(dirty), with
compaction deferred to background threads and off the write path. redb is a
copy-on-write B-tree doing no background work, so a commit rewrites every
page on the path to a new root and its cost tracks the size of the tree
rather than the size of the batch.

### Space

Chain on disk at tip: dcrd 24 GB, dcroxide 33 GB. Block bytes are consensus
data and are the same on both sides (18 GB of flat `.fdb` files here), so
the whole 9 GB difference is metadata. dcrd splits its metadata across a
snappy-compressing goleveldb under `blocks_ffldb/metadata`
and a second goleveldb at `utxodb` for the UTXO set; dcroxide keeps all of
it uncompressed in one `metadata.redb`.

That file is 14.48 GiB: 5.65 GiB stored, 0.69 b-tree metadata, 8.13
fragmented. Page fill 43.8%, tree height 6, 2,175,036 leaf nodes,
76,302,003 rows.
redb's `fragmented_bytes` is the unused tail *inside* each allocated page
(redb-2.6.3 `src/tree_store/btree.rs:963`) — a fill factor, not reclaimable
free space between pages.

Three mechanisms in redb 2.6.3 produce that fill, all confirmed in its
source: splits go to the byte midpoint with no append fast path
(`btree_base.rs:565-577`); merges happen only below 33% fill
(`btree_mutator.rs:610-618`); and the buddy allocator rounds every
allocation up to a power of two — `required_order` is
`ceil_log2(required_pages)`
(`tree_store/page_store/page_manager.rs:1058-1059`).

Neither available remedy recovers the fragmented 8.13 GiB.
`Database::compact()` ran 598.5 s to recover 0.12 GiB and a second pass
returns false — it relocates pages with `copy_from_slice` and never repacks
them. A full sorted copy-out
rebuild (76.3M rows in 228 s plus a 10.5 s commit) yields a 12.00 GiB file
at 53.0% fill, recovering 2.48 GiB, 17% of the file and not the 8.13 GiB
the fragmentation figure suggests. 53.0% is redb's best case for this data,
not a starting point that tuning improves on.

Payload by bucket, stored key+value bytes: `spendjournalv3` 2.46 GiB over
1.1M rows; `existsaddridx` 1.55 GiB over 66,477,608 rows (the values are
empty — the key is the datum); `gcsfilters` 0.41 GiB; `stakeblockundo`
0.39; `blockidxv3` 0.24; `ffldb-blockidx` 0.23; `ticketsinblock` 0.17;
`utxosetv3` 0.13.

### Verdict

redb stays. It is crash-safe, pure Rust, needs no C toolchain, and carries
the full mainnet chain; the gate asked whether it could sustain the load,
and it can. The price is ~2.2x dcrd's initial-block-download time and 9 GB
more on disk, all of it metadata. Both are properties of the engine, not
of how the port drives it, so no amount of work in the layers above
recovers them.

Four levers have been identified and **none is implemented or measured**:
sizing redb's read cache against the working set; decoupling flush cadence
from block connection so one commit amortizes over more work; compressing
values, which dcrd gets for free from goleveldb; and shipping a rebuild
tool for the 17% a copy-out recovers. Each is a hypothesis about where the
cost goes, and each is tracked as open work rather than promised.

The rocksdb fallback is resolved rather than retired: it was never
exercised, because the condition that would have triggered it — redb
failing to sustain the write load — did not occur. Revisiting it needs a
different trigger, one this validation cannot supply: sync time or metadata
size becoming a release blocker *after* the levers above have been measured
and found insufficient. That swap is also less contained than the original
clause implies. `dcroxide-database` exposes a concrete `Database` type over
redb, not a trait with two backends behind it, so a swap rewrites that
crate's internals; only its callers and the flat block files, which sit
outside the metadata store, are genuinely insulated. It would also trade
the C/C++ toolchain requirement back in, which the Consequences above
weighed and declined.
