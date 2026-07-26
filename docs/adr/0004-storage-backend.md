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

Both data directories were measured directly, at the same height.

| | dcrd | dcroxide |
|---|---:|---:|
| flat `.fdb` block files | 17.580 GiB | 17.579 GiB |
| chain metadata | 6.045 GiB | 14.483 GiB |
| UTXO set | 0.108 GiB | *(in the same file)* |
| **total** | **23.73 GiB** | **32.06 GiB** |

Block bytes are consensus data and match to within a mebibyte, so the whole
8.33 GiB difference is metadata. dcrd splits its across a goleveldb under
`blocks_ffldb/metadata` and a second goleveldb at `utxodb`; dcroxide keeps
all of it in one `metadata.redb`.

**Compression is not the explanation.** dcrd opens every chain leveldb with
`Compression: opt.NoCompression` — `database/ffldb/db.go:2095` and
`internal/blockchain/utxobackend.go:365`. Both sides store raw bytes, so the
gap is per-key structural overhead, not codec choice. (dcrd does leave
snappy on for one database, `<datadir>/feesdb`, which is half a megabyte.)

`metadata.redb` decomposes as follows, read from the real file.

| | GiB | share |
|---|---:|---:|
| payload (keys + values, 76,302,003 rows) | 5.65 | 39.0% |
| redb per-pair overhead and branch pages | 0.69 | 4.8% |
| intra-page slack | 3.44 | 23.7% |
| allocated but free pages | 4.69 | 32.4% |

The live B-tree is 9.79 GiB of that, giving a **page fill of 64.86%** — the
tree packs reasonably. The single largest component is instead the 4.69 GiB
of free pages: space the allocator holds and has not returned to the file.

Beware `DatabaseStats::fragmented_bytes`, which reports 8.13 GiB here and
looks like a fill figure but is not one. It sums the three trees' intra-page
slack *and* `count_free_pages() * page_size`
(redb-2.6.3 `src/transactions.rs:2298-2301`). Only the per-table
`TableStats::fragmented_bytes` (`btree.rs:963`) is intra-page slack. Reading
the database figure as a packing ratio understates the fill as 43.8% and
charges free pages against the B-tree.

Neither available remedy is what it appears to be. `Database::compact()` ran
598.5 s to recover 0.12 GiB and a second pass returns false — it relocates
pages with `copy_from_slice` and never repacks them. A full sorted copy-out
rebuild (76.3M rows in 228 s plus a 10.5 s commit) does yield a smaller
file, 12.00 GiB against 14.48, but **not by packing better**: it lands at
58.29% fill against the original's 64.86%, and its live tree is *larger*,
10.92 GiB against 9.79. The 2.48 GiB it saves is free pages, 4.69 GiB down
to 1.08. Sequential insertion splits the rightmost leaf at the byte midpoint
with no append fast path (`btree_base.rs:565-577`), so a rebuild trades
denser packing for a cleaner allocator. Two further mechanisms bound the
fill in either case: merges happen only below 33%
(`btree_mutator.rs:610-618`), and the buddy allocator rounds every
allocation to a power of two, `required_order = ceil_log2(required_pages)`
(`tree_store/page_store/page_manager.rs:1058-1059`).

Where the free pages come from is not established. One candidate is visible
in this crate: `Database::begin` takes a redb `begin_read()` for the whole
life of *every* ffldb transaction including read-only ones
(`crates/dcroxide-database/src/lib.rs:386`), and redb will not return a
freed page to the allocator past the oldest live read transaction
(`transaction_tracker.rs:253-261`). A read held across writes therefore pins
freed pages and the allocator grows the file instead of reusing them. That
is a hypothesis with a mechanism, not a measurement.

Payload by bucket, stored key+value bytes: `spendjournalv3` 2.46 GiB over
1,100,392 rows; `existsaddridx` 1.55 GiB over 66,495,032 rows (the values
are empty — the key is the datum); `gcsfilters` 0.41 GiB; `stakeblockundo`
0.39; `blockidxv3` 0.24; `ffldb-blockidx` 0.23; `ticketsinblock` 0.17;
`utxosetv3` 0.13. Attribution is near-exact: only 12 of 2,175,036 leaf pages
straddle two buckets, since the buckets are contiguous key ranges.

### Verdict

redb stays. It is crash-safe, pure Rust, needs no C toolchain, and carries
the full mainnet chain; the gate asked whether it could sustain the load,
and it can. The price is ~2.2x dcrd's initial-block-download time and
8.33 GiB more on disk, all of it metadata.

How much of that price is inherent to redb is *not* settled, and an earlier
draft of this section claimed it was. A copy-on-write B-tree costing more
per commit than an LSM is structural. But the largest single component of
the file is free pages, and the leading hypothesis for those points at how
this crate drives redb rather than at redb itself. Until that is measured,
the honest position is that some unknown fraction is recoverable in the
layers above.

Levers, **none implemented and none measured**:

- **Audit long-lived read transactions.** Targets the 4.69 GiB of free
  pages, the largest component, via the mechanism described above. Testable
  without an on-disk format change.
- **Size redb's read cache against the working set.** Targets flush time,
  not space. A probe on the real tree took a 500k-key insert loop from
  4.3-6.1 s to 1.3-1.5 s by raising the cache from the 1 GiB default to
  8 GiB; that is a microbenchmark, not a sync.
- **Decouple flush cadence from block connection**, so one commit amortizes
  over more work.
- **Shrink the two dominant buckets.** `spendjournalv3` (4.1 GiB of tree
  footprint, 2402 B mean row) and `existsaddridx` (3.1 GiB over 66.5M rows
  of a 25-byte key with an empty value) are 72% of the tree between them,
  and they waste space by different mechanisms — large-value round-up
  against fixed per-row overhead — so they need different treatments.

Value compression is deliberately *not* on that list. dcrd stores the same
data uncompressed and still fits it in 6.045 GiB, so compression would be a
divergence from the reference implementation adopted to paper over an
overhead dcrd does not pay. It stays available if the levers above fall
short.

A rebuild tool is not on the list either. A copy-out reclaims 2.48 GiB, but
by clearing free pages while packing *worse*, so it treats a symptom of the
first lever. Fix the free pages and the rebuild has little left to recover.

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
