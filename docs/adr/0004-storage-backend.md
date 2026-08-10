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

## Findings as of 2026-08-09 (read this first)

Six dated addenda follow the amendment below, and later ones supersede
earlier ones — including a retraction. This section states what is currently
believed and points at the evidence; nothing below it has been rewritten.

**The decomposition is validated.** Replaying the full chain with
`--addrindex` alone, matching the baseline datadir's composition, reproduces
it on every metric: live tree 9.82 GiB against 9.79, fill 0.6462 against
0.6486, free-page share 33.0% against 32.4%. The instrument
(`dcroxide-bench redbstat`) also reproduces the amendment's original table,
which a throwaway tool produced. Measurements can be scored against this.

| component | GiB | share | status |
|---|---:|---:|---|
| payload | 5.65 | 39.0% | the data itself |
| redb per-pair and branch overhead | 0.69 | 4.8% | inherent to the engine |
| **intra-page slack** | **3.44** | **23.7%** | **the target.** Fill sits at 0.62-0.65 across every run, tree size and index configuration, and converges on the real store's value when composition matches |
| allocated but free pages | 4.69 | 32.4% | attributable and reproducible for a given configuration, but *reused working space* the allocator draws down — not recoverable from any layer above the engine |

**Levers.** (a) *audit long-lived read transactions* — **closed**, measured
dead: three probe arms differed by 0.0008%, in the direction opposite to
pinning. (b) *size the read cache* and (c) *decouple flush cadence* —
**measured for space, and neither moves fill**: across a five-arm full-chain
sweep with an eightfold page cache and an eightfold flush cadence, fill
spanned 0.6450 to 0.6462, a spread of 0.0011. Lever (c) does raise free
pages as predicted (8.40 GiB against 6.17), which is a cost rather than a
gain. Their *throughput* claims remain unproven: that half of the sweep was
voided by a 1.64x drift between two runs of the identical baseline. (d)
*shrink the dominant buckets* — `existsaddridx` is capped near 0.75 GiB by
arithmetic and costs the contiguous ffldb keyspace to claim;
`spendjournalv3`'s page-size hypothesis is untested.

**So tuning above the engine has not moved the one property worth
optimising against** — with the exception of lever (d) on `spendjournalv3`,
which is untested and targets that property directly. The gate this ADR set
for revisiting the backend is therefore *not* satisfied;
[ADR-0009](0009-storage-shape.md) records what still has to be measured, and
withdraws a density comparison against dcrd that this file's figures do not
support (dcrd's payload was never measured, only its file sizes).

**Commit cost.** 9.4 us per dirty entry at the end of a full un-indexed
replay against 1.59 at the start — 9.4x over 66x of tree growth. Earlier text
quotes 4.9x from raw milliseconds; that figure is confounded by dirty-set
size and should not be used. Of the optional indexes, the transaction index
carries the write-path cost (23.27 us/entry with both) and the address index
essentially none (13.70, marginally under un-indexed).

**Two measurement traps, both hit here.** `DatabaseStats::fragmented_bytes`
is slack *plus* free pages, not a fill figure. And redb's `stats()` walk
scales with the tree — 5 ms early, 6.6 s at tip — so a timer spanning it
reports instrument overhead as commit cost; `FlushObservation` separates the
two.

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
(What that row means was worked out later: it is reused working space, not
retained garbage. See the findings section above.)

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
(`crates/dcroxide-database/src/lib.rs`, in `begin_seed` — the citation
here read `:386` until the 2026-08-07 addendum corrected it; that line is
now the closing brace of `db_type`), and redb will not return a
freed page to the allocator past the oldest live read transaction
(`transaction_tracker.rs:253-261`). A read held across writes therefore pins
freed pages and the allocator grows the file instead of reusing them. That
is a hypothesis with a mechanism, not a measurement. **Superseded:** it was
subsequently ruled out on the code and then killed by measurement — see the
2026-08-07 addenda.

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

Levers, **none implemented and none measured** at the time this was written
(one has since been closed by measurement and another made adjustable — the
findings section at the top of this file has their current state):

- **Audit long-lived read transactions.** Targets the 4.69 GiB of free
  pages, the largest component, via the mechanism described above. Testable
  without an on-disk format change. *Demoted 2026-08-07: the mechanism does
  not hold for the transaction that triggers its own flush, and the cache
  mutex prevents a new reader from straddling one. What is left is a bounded
  audit of cross-thread read-only transaction lifetimes. **Closed
  2026-08-07 by measurement** — see the second addendum: a reader held
  across every flush of a probe run moved free pages by 0.0008%.*
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

## Addendum, 2026-08-07 — the free-page hypothesis does not survive reading

The amendment above named the long-lived read transaction as the leading
candidate for the 4.69 GiB of allocated-but-free pages, with the honest
caveat that it was "a hypothesis with a mechanism, not a measurement." A
static audit of that mechanism, against redb 2.6.3 and this crate, says it
is the wrong candidate. Nothing here has been measured either; what has
changed is that the cheap explanation is now ruled out on the code, so the
measurement to run is a different one.

**The mechanism, followed through.** redb keys freed pages by the write
transaction that freed them and releases keys strictly below `free_until`,
which is `oldest_live_read.next()` when a read transaction is live and the
committing transaction's own id otherwise (`transactions.rs:1936-1940`,
`2129-2160`, `2200-2262`). The only steady-state writer to the metadata
store is `DbCache::flush`. It is reached from `Transaction::commit_internal`
(`transaction.rs:634-641`), where the committing transaction's read snapshot
sits at the last committed id `R` and the flush's own write lands at `R+1`.
`free_until` is therefore `R+1` whether or not that reader exists: the
transaction that triggers its own flush pins nothing.

The second path is closed by locking rather than arithmetic.
`Database::begin` takes the cache mutex and holds it across `begin_read()`
(`lib.rs:450-462`), and `commit_internal` takes that same mutex before
calling `cache.flush`. A read transaction therefore cannot come into
existence while a flush is running, so no *new* reader can straddle one.

What remains is a read-only ffldb transaction opened on another thread
before a flush and still alive after it. That is a real exposure and worth
bounding — but the sync that produced every figure in the amendment ran
`--norpc`, which removes the main source of concurrent readers. The
hypothesis is a poor fit for the measurement it was invented to explain.

**What the measurement should ask instead.** A one-generation lag is
structural: pages freed by flush `W` become reclaimable only at `W+1`, so
free pages are bounded below by the largest single flush's freed set, and
redb never returns space to the filesystem. 4.69 GiB may simply be a
high-water mark — in which case no lever in the layers above recovers it,
and the honest reading is that more of the 8.33 GiB is inherent than the
amendment supposed.

Two levers move on this. Lever (a) is demoted: it is now a bounded audit of
cross-thread read-only transaction lifetimes, not the leading explanation.
Lever (d)'s `existsaddridx` half is close to settled by arithmetic —
66,495,032 rows of a 25-byte key with an empty value cost 33 B/pair
including redb's two `u32` leaf offsets, which at the file's 64.86% fill is
3.15 GiB against the measured 3.1 GiB. The entire recoverable amount is the
8 B/pair of offsets, roughly 0.75 GiB, and claiming it means giving each
bucket its own table with a fixed-width key, which breaks the single
contiguous ffldb keyspace that `scan_prefix_keys` and the cursor merge
depend on. That may be the lever to decline.

**Sequencing.** The instrument comes first: the decomposition that produced
the amendment's table was a throwaway and is not in the tree, so no lever
can be scored before and after until it is rebuilt as a `dcroxide-bench`
subcommand emitting machine-readable output. Then a per-flush observer on
`DbCache::flush` (flush sequence, dirty entries, bytes, elapsed, allocated
and free pages) produces the curve whose *shape* distinguishes the
candidates: a monotone stair stepping by one flush's freed set is the
structural lag, a single ratchet that never recovers is a high-water mark
no lever fixes, growth tracking reader overlap revives lever (a), and
growth tracking row-size distribution points at allocator rounding.

Levers (b) and (c) are not worth booking until that curve exists. Cache
size and flush cadence interact with free pages in opposite directions —
fewer, larger commits amortize better while raising the per-generation
freed set that sets the high-water mark — so either measured alone yields a
number nobody can interpret. Neither is adjustable today in any case:
`DbCache::new` hardcodes its 100 MiB size and 300 s interval, and
`dcroxide-bench` has no page-cache flag, so every replay silently runs at
the 1 GiB default.

**Preserving the baseline.** Every figure in the amendment comes from one
datadir, and opening it is not read-only — redb can quick-repair on open,
and `Database::open` rolls the block files back when the metadata trails
them (`lib.rs:365-369`). It has been reflink-cloned to
`artifacts/dcroxide-bench/m1/baseline-2026-07-25/` (btrfs, 22 s, no
additional space); the clone is what probes open, and the original is not
to be touched.

## Addendum, 2026-08-07 (second) — the reader hypothesis is measured dead

The addendum above ruled out the long-lived read transaction by reading
redb's reclaim logic. `dcroxide-bench pinprobe` now tests it directly, and
the reading holds.

Three arms, each on its own reflink clone of the mainnet store: 400,000
scattered writes over 8 commits with an 8 MiB overlay ceiling, sampling the
full decomposition after every flush. The arms differ only in what is held
open — nothing, one read transaction for the whole run, or a reader
spanning exactly two flushes.

| flush | `none` | `all` | `two` |
|---|---:|---:|---:|
| 1 | 5,018,687,597 | 5,018,687,597 | 5,018,687,597 |
| 2 | 5,003,313,221 | 5,003,313,221 | 5,003,313,221 |
| 3 | 4,967,783,213 | 4,967,741,431 | 4,967,783,213 |

Free-page bytes. The first two flushes agree byte for byte across all three
arms. At the third, `none` and `two` are still identical and `all` differs
by 41,782 bytes — 0.0008% of 4.97 GiB, and *fewer* free pages with the
reader held, which is the opposite of what pinning would produce. A reader
held across every flush of the run changes nothing measurable. Lever (a) is
closed.

**What the run says instead.** Free pages fell 48.5 MiB while stored payload
grew 20,400,020 bytes, and `accounted_bytes` fell by 4.2 MB: the file did
not grow. redb absorbed 300,000 new rows out of the free pool rather than
extending the store. That is the behaviour of reusable working space, not
of retained garbage, and it is the strongest evidence yet for the
high-water-mark reading — with the consequence that **the largest single
component of the metadata gap is not recoverable from the layers above the
engine.**

What remains addressable is smaller than the 8.33 GiB headline: the 3.44 GiB
of intra-page slack at 64.86% fill, and `existsaddridx`, whose arithmetic
above caps the recoverable amount near 0.75 GiB at the cost of the
contiguous ffldb keyspace. A gap that is mostly inherent to a copy-on-write
B-tree argues for changing the storage shape rather than tuning it — which
is the conclusion Cuprate reached after three years on a generic key-value
layer, and the case for specialising by access shape beneath the
`database/v3` interface rather than for another round of levers.

**Scope of the claim.** This settles the reader question and nothing wider.
The workload is scattered inserts into a fresh bucket over three flushes; a
sync performs far more flushes and generates freed pages through updates and
deletes as well. Characterising free-page behaviour under sync load needs
the observer attached to a replay, which is now possible and was not before.

Sampling is not free and perturbs slightly: `stats()` walks every branch and
leaf page (~1m53s on this tree) and requires a write transaction, so each
flush here cost ~206 s and each measurement takes a fresh clone.

## Addendum, 2026-08-08 — free pages under sync churn are a sawtooth

The previous addendum closed lever (a) but scoped its claim narrowly: the
probe applied scattered inserts, where a sync also frees pages through
updates and deletes, over far more flushes. The observer has now been
attached to a replay — 250,000 mainnet blocks, 1,925,867 regular
transactions, full validation, the production 100 MiB overlay ceiling, with
the decomposition sampled on every one of the 17 flushes.

Free pages neither stair-step nor ratchet. They oscillate, by nearly the
size of the file:

| flush | free MiB | live MiB | free/alloc | fill |
|---:|---:|---:|---:|---:|
| 1 | 0.0 | 105.4 | 0.00 | 0.6222 |
| 4 | 24.9 | 317.5 | 0.05 | 0.6263 |
| 5 | 334.2 | 415.7 | 0.51 | 0.6311 |
| 7 | 49.5 | 595.5 | 0.05 | 0.6328 |
| 8 | 994.3 | 673.4 | **0.96** | 0.6335 |
| 12 | 657.0 | 953.3 | 0.48 | 0.6360 |
| 16 | 352.5 | 1190.7 | 0.21 | 0.6311 |

A commit frees a large batch — flush 8 held 945 MiB more than flush 7 — and
the following commits draw it back down, at about 80 MiB consumed per flush
against 65 MiB of live tree added, until the next spike. Across the run free
pages ranged from **0.0% to 96.2% of the allocated file**.

**What this costs the amendment's table.** The 4.69 GiB of free pages
recorded at mainnet tip is 32.4% of that file — squarely inside the range
this run sweeps through repeatedly. It is one sample of an oscillation, taken
wherever the sync happened to stop. Stopping a few commits earlier or later
would have recorded a materially different figure and therefore a different
decomposition. The free-page row is not a stable property of the store, and
the 8.33 GiB metadata gap should not be attributed against it as though it
were. That is a sharper statement than the previous addendum's "may simply be
a high-water mark," and it points the same way: nothing in the layers above
the engine recovers this, because there is no steady quantity there to
recover.

**What is stable is the fill.** Across the whole run it moved between 0.6169
and 0.6360 — a spread of 0.019 — while the live tree grew from 105 MiB to
1.19 GiB, and mainnet tip sits at 0.6486 on a tree eight times larger again.
Page fill is a structural constant of this B-tree near 63-65%, which makes
the roughly 35% of the live tree spent on intra-page slack — 3.44 GiB at
tip — the durable and genuinely attributable target. Any storage work should
be scored against slack and against commit cost, not against free pages.

**Commit cost, measured on one monotonic run.** Throughput fell from 745
blk/s over the first 50,000 blocks to 324 by block 200,000, and the full
mainnet sync on a far larger tree ran at 124. Flush duration rose with the
tree over the same run, 630 ms to 2,973 ms for comparable dirty sets. This is
the copy-on-write signature the amendment inferred from two separate syncs,
now visible within a single one.

Note also what a genesis slice cannot stand in for: this run averaged 445
blk/s where the real sync managed 124. Slices are informative about shape and
misleading about magnitude.

## Addendum, 2026-08-08 (second) — the same chain, replayed, ends with 4% free pages

The sawtooth above was measured on a 250,000-block slice. Repeating it over
the whole chain — 1,100,392 blocks, 7,935,579 regular transactions, 17.99 GiB
of block data, the production 100 MiB overlay, every one of the 122 flushes
sampled — settles the amplitude question and, incidentally, the attribution
question with it.

**Free pages, full scale.** They swing from 0.0 MiB to 3,983 MiB, which is
0% to 96.2% of the allocated file, and the run *ends* at 313 MiB — **4.0%**.
The datadir this project measured at tip, from a live sync of the same chain,
ended at 4.69 GiB — **32.4%**. Same consensus data, same engine, same overlay
ceiling; an eightfold difference in the figure the amendment's table lists as
a component of the metadata gap. Whatever else is true, that row is not a
property of the stored chain. It records where in the allocate-and-reuse cycle
a particular run happened to stop.

**Fill, full scale.** 0.6169 to 0.6360 across all 122 flushes — a spread of
0.019, which is the same spread the 250,000-block run produced while the tree
grew from 105 MiB to 6.81 GiB, a factor of 66. Page fill is the invariant
here. It is what a storage change should be scored against.

**Commit cost, and why the timing split mattered.** Flush cost rose 528 ms to
2,590 ms, a factor of 4.9, over that 66x growth — sublinear, which is what a
copy-on-write B-tree rewriting a root path of depth O(log n) should do. The
stats walk over the same span rose 5 ms to 6,568 ms, a factor of 1,302, and
by the end it was 2.5x the flush it was measuring. Had the observation not
separated them, the combined figure would have read 533 ms to 9,158 ms and
the honest-looking conclusion would have been a **17.2x** commit slowdown —
three and a half times the real one. Instrument overhead that scales with the
thing under study is not noise; it is a wrong answer waiting to be reported.

**What this run is not.** The replay drives `Chain::open`, which does not
build the optional indexes the daemon wires separately, so its live tree ends
at 6.81 GiB against the synced datadir's 9.79 — a gap close to
`existsaddridx`'s 3.1 GiB footprint. It measures the chain engine's own
metadata under real block churn, not a fully indexed node's store. The curve
shape, the fill invariant and the commit-cost growth all hold for what it
does cover; absolute totals should still be read from a real sync.

## Addendum, 2026-08-09 — the same run with the indexes built

`Chain::open` builds none of the optional indexes, so every replay above
measured a store smaller than a synced node's. `dcroxide-bench replay` can
now build them, and the full chain was replayed again with `--txindex` and
`--addrindex`: 1,100,392 blocks, 168 flushes, every one sampled.

**The fill invariant now matches a real datadir.** It ends at **0.6546**
against the synced tip's 0.6486 — within 0.006, where the un-indexed replay
sat 0.023 low at 0.6258. Fill is not merely stable across tree sizes; it
converges on the real store's value once the store has the real store's
composition. That is the strongest form of the claim these runs support:
packing is the property worth optimising against.

**Free pages give a third answer for the same chain.** They range 0.0 to
4,465 MiB across the run and end at 1,629 MiB — 10.6% of the file. The three
runs of this identical chain therefore end at **0.31, 1.59 and 4.69 GiB**, a
fifteenfold spread. No further argument about that row should be necessary.

**A correction to the previous addendum.** It reported flush cost rising
528 ms to 2,590 ms, "a factor of 4.9", and read that as sublinear growth.
The comparison was confounded: the final flush of that run carried 174,146
dirty entries against the first flush's 332,714, so raw milliseconds
*understated* the growth. Per dirty entry the un-indexed run rose 1.59 us to
14.87 us — **9.4x**, not 4.9x. Still sublinear against 66x of tree growth,
but less comfortably so, and the earlier figure should not be quoted.

**Indexes cost per entry, not just in bulk.** The indexed run rose 1.77 us to
23.27 us per dirty entry, 13.2x, ending 56% more expensive per entry than the
un-indexed run at the same height. The address index is in the write path and
its cost grows with the tree rather than sitting beside it.

**One thing this run overshoots.** It enabled both indexes, where the payload
listing in the amendment above names `existsaddridx` and no transaction-index
bucket — so the baseline datadir was synced with the address index and
without the transaction index. The replayed live tree is 11.56 GiB against
the synced 9.79. For a size-comparable run, use `--addrindex` alone; the fill
and per-entry figures above are not sensitive to the difference, the absolute
tree size obviously is.

## Addendum, 2026-08-09 (second) — retraction: free pages are attributable after all

Replaying the full chain with `--addrindex` alone — matching the payload
listing above, which names `existsaddridx` and no transaction-index bucket —
reproduces the synced datadir on every metric:

| | live tree | free pages | fill |
|---|---:|---:|---:|
| this replay | 9.82 GiB | 3.97 GiB (33.0%) | 0.6462 |
| synced datadir | 9.79 GiB | 4.69 GiB (32.4%) | 0.6486 |

Live tree within 0.3%, fill within 0.0024, free-page share within 0.6
percentage points.

**What this retracts.** The previous addendum argued that free pages are "not
a quantity", on the grounds that three runs of the identical chain ended at
0.31, 1.59 and 4.69 GiB — a fifteenfold spread — and concluded that the
amendment's free-page row should not be attributed against. That comparison
was invalid, and the invalidity was self-inflicted: those three runs had
*different index configurations*. Comparing them was apples to oranges. With
the configuration matched to the baseline, the figure reproduces. The 4.69 GiB
row is a real property of that datadir, not an artifact of where a sync
stopped.

**What survives.** Free pages remain the most volatile component and the one
most sensitive to *when* it is read. Within this run the share swings from 0%
to 94.6%, and across the final ten flushes alone it ranges 1.6% to 33.0% —
so the close agreement above is a matched *stopping point* as well as a
matched configuration, and a run halted a few flushes earlier would report a
much smaller figure. The pinprobe result also stands: the pool is reused
working space, so attributing it is not the same as being able to recover it.

Fill is stable in both senses, which is what makes it the better target: it
varies only with composition (0.6258 un-indexed, 0.6462 address index, 0.6546
both) and barely at all within a run.

**A second correction, on where index cost lands.** The previous addendum
attributed the rise in per-entry flush cost to the address index being "in
the write path". The three runs say otherwise:

| run | us per dirty entry, first -> last |
|---|---|
| un-indexed | 1.59 -> 14.87 (9.4x) |
| address index | 1.80 -> 13.70 (7.6x) |
| both indexes | 1.77 -> 23.27 (13.2x) |

The address index costs essentially nothing per entry — it ends marginally
cheaper than the un-indexed run, within run-to-run variation. The 70% rise
belongs to the **transaction index**. Anything scoring write-path cost should
treat those two separately rather than as "indexes".

## Addendum, 2026-08-09 (third) — levers (b) and (c): no effect on fill

Both remaining levers were measurable for the first time. Lever (b) needed
`--dbcache` to reach redb's page cache, and lever (c) needed `--utxocache`:
the metadata overlay ceiling does not govern flush cadence, because
connecting a block calls `maybe_flush_utxo_cache`, and that flush forces a
durable metadata commit whatever the overlay says. An earlier sweep moved
`--metacache` alone and produced *more* flushes at 800 MiB than at 100 MiB,
which is the signature of turning the wrong knob.

Five arms over the full chain, `--addrindex`, `--statsevery 0`, each
decomposed and then deleted so no arm ran on a fuller disk than the one
before it. The baseline configuration ran first **and last** as a drift
control.

**The throughput half is void.** The identical baseline measured 4,198 s at
the start and 6,865 s at the end — a 1.64x drift against lever effects of
0.88x to 1.12x. Nothing between the two baselines is comparable, and the
arms' timings should not be quoted. The control is what makes that statement
possible rather than a suspicion; without it these numbers would have read as
"the page cache costs 12% and cadence buys 12%", both inside the noise. Disk
stayed flat at 289 GB used and the machine was at 50 C afterwards, so the
cause is not disk fill; sustained load over ~6.5 hours is the likeliest
explanation and is not something this rig currently controls for.

**The space half is clean**, since it does not depend on wall time.

| arm | dbcache / metacache / utxocache | fill | live GiB | free GiB |
|---|---|---:|---:|---:|
| base-first | 1024 / 100 / 150 | 0.646166 | 9.823 | 6.17 |
| cache | 8192 / 100 / 150 | 0.646171 | 9.823 | 6.17 |
| cadence | 1024 / 800 / 1200 | 0.645363 | 9.835 | 8.40 |
| both | 8192 / 800 / 1200 | 0.645042 | 9.840 | 6.15 |
| base-last | 1024 / 100 / 150 | 0.646120 | 9.824 | 4.18 |

Three results survive the drift:

- **Neither lever moves fill.** The spread across all five arms is 0.0011.
  An eightfold page cache and an eightfold flush cadence change packing by
  nothing. Since intra-page slack is the component identified as the real
  target, **neither lever addresses it.**
- **Stored payload is bit-identical across all five arms** (6,069,302,981
  bytes). The replay is deterministic in what it stores, which is what
  licenses comparing the arms at all.
- **Lever (c) raises free pages, as this ADR predicted.** The cadence arm
  ends at 8.40 GiB against the baseline's 6.17 — larger commits amortize
  over more work while raising the per-generation freed set that sets the
  high-water mark. Note the baseline itself moved 6.17 to 4.18 between its
  two runs, so the sawtooth's phase sensitivity sits underneath this and the
  effect is a tendency rather than a constant.

**Where this leaves the levers.** (a) closed by measurement. (b) no effect on
fill; its throughput claim rests on a 500k-key microbenchmark that a full
replay has not reproduced and this rig cannot currently test. (c) no effect
on fill, a measured cost in free pages, and an unproven throughput benefit.
(d) `existsaddridx` capped near 0.75 GiB by arithmetic at the cost of the
contiguous keyspace; `spendjournalv3`'s page-size hypothesis untested.

Tuning above the engine has not moved the one property that is stable enough
to optimise against. That is not proof that a shape change would, but it
removes the cheaper alternative to trying one.

**What a valid throughput measurement would need**, if anyone wants one:
alternating arms rather than sequential blocks, several repetitions per
configuration, and a rig that either controls for sustained-load state or
measures it. A single pass of five hour-long arms cannot separate a 10%
effect from a 64% drift, and this attempt is the evidence.
