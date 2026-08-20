# ADR-0004 — D1: Storage backend & datadir-compatibility stance

- **Status:** Accepted (decision D1 ratified by the project owner).
  **Revisit gate satisfied and closed 2026-08-17: the engine stays redb.**
- **Date:** 2026-07-03 (proposed), 2026-07-05 (accepted),
  2026-07-26 (write-load gate resolved — see the amendment below),
  2026-08-17 (revisit concluded — [ADR-0009](0009-storage-shape.md))

> **The revisit this ADR set up has run its course.** Its gate — revisit only
> after all four levers are measured and found insufficient — was satisfied on
> 2026-08-12, and ADR-0009 then measured a candidate engine against every
> condition. The candidate won on size and on write shape and lost on crash
> safety (fjall #311: a corrupted journal record silently discards
> acknowledged commits, and the reopen succeeds). **redb stays.** The costs
> that motivated the revisit are not retracted — 1.29x dcrd at IBD, ~48% of
> block-sync wall time stalled on storage, 90–98% of it in the metadata commit
> — they are accepted.

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

## Findings as of 2026-08-13 (read this first)

Dated addenda follow the amendment below, and later ones supersede earlier
ones — including a retraction. This section states what is currently
believed and points at the evidence; nothing below it has been rewritten.

**The metadata store now runs redb 4.1.0** (addendum, 2026-08-13). The
on-disk format changed with it: redb 4 reads only format 3 and returns
`UpgradeRequired` for a 2.x file, mapped here to a typed error that names
redb 2.x — a data directory written before 2026-08-13 is refused rather
than misread, and has to be re-synced or re-imported; the chain data itself
is not damaged. Every decomposition figure below — payload, overhead,
slack, free pages, the 0.6486 fill — was measured on 2.6.3, and the packing
half of it holds: 4.1.0 reproduces the 2.6.3 tree to four decimals on a
250,000-block replay. Its 9.4% fewer bytes of file come entirely out of
free-page retention, which is the one row above that a 4.1.0 store reports
smaller.

**The engine is now measured against candidates, and redb loses on this
workload.** Handed the identical engine-level journal, fjall 3.1.8 holds
dcroxide's 76,301,856 rows in 5.80 GiB where redb 2.6.3 needs 16.00 — 1.026x
payload against 2.831x — with point reads 3.5x faster and a bulk load 22x
faster. A goleveldb control lands at 1.058x, confirming the target is a
property of the engine class rather than of dcrd's write schedule, and a
redb 2.6.3 control reproduces this file's own baseline to 0.008%. That does
not by itself decide anything: the crash-safety gate this ADR chose redb for
is *not* met by fjall today, on two open upstream issues that land on the
cross-bucket atomicity invariant. [ADR-0009](0009-storage-shape.md) records
the measurement, the gates, and the three conditions a migration would have
to clear. A free result alongside it: **redb 4.1.0 holds the same content in
14.50 GiB against 2.6.3's 16.00, and loads 21% faster.**

**The dcrd comparison is now measured on both sides, and it holds.** The
2026-08-11 addendum reports dcrd's payload at matched index composition,
against the same block bytes: the two implementations store the *same
payload*, fifteen buckets agreeing to the byte and the whole-store
difference 54 bytes on 6.06 GB. Two consequences run through everything
below. First, the density comparison ADR-0009 withdrew is reinstated — the
premise it was withdrawn on (that dcrd's domain encodings must be denser) is
measured false. Second, the remaining gap is the storage layer with no
domain-level component left in it: the same payload occupies 6.10 GiB under
goleveldb and 9.82 GiB in redb's live tree, 1.08x against 1.74x over each
store's own payload.

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
*shrink the dominant buckets* — **measured per bucket, and it is one bucket**:
`spendjournalv3` carries 1.536 GiB of slack, 44% of the store's, measured on
the per-table statistic. `existsaddridx` remains capped near 0.75 GiB and
costs the contiguous ffldb keyspace to claim. **The page-size remedy is
unreachable** — redb gates `set_page_size` behind `cfg(any(fuzzing, test))`.
**The re-keying remedy is closed by measurement** (2026-08-12 addendum): six
layouts were built at the bucket's real dimensions and today's is the
smallest; every split costs 0.18–0.38 GiB. What remains untested is a denser
row, which has no dcrd precedent to copy.

> **Correction, 2026-08-12.** This paragraph read "holds a 2402-byte mean row
> against a 4096-byte page, so it gets one row per page and pays 1.74 GiB of
> the 2.33 GiB predicted slack, about 75%. Every other bucket packs at 10
> rows per page or better." Those figures were *modelled*, not measured —
> `floor(page_size / mean_row)` — and the mean misdescribes the bucket: the
> median row is 1248 bytes and the bucket packs 1.55 rows per leaf node. The
> slack is real and close to the estimate (1.536 GiB measured against 1.74
> predicted), which is why the model was never questioned; the mechanism was
> wrong, and the remedy it implied does not work.

**Throughput, measured properly at last.** Twelve full-chain runs through
`dcroxide-bench sweep`, interleaved and repeated, every arm's range disjoint
from the baseline's: an 8 GiB page cache is **50% slower**, reversing lever
(b)'s microbenchmark premise; raising flush cadence gives **11% faster**; and
the cache penalty vanishes when cadence is raised, confirming the interaction
this ADR predicted.

**So tuning above the engine buys 12.7% against what was then a 2.2x gap** (the
2026-08-15 addendum re-measures it at 1.29x, which makes that 12.7% a larger
share of what is left) **and the only un-closed lever needs the port to
re-encode its own spend-journal rows.**
[ADR-0009](0009-storage-shape.md) records what remains. Its withdrawal of
the density comparison is superseded by the 2026-08-11 addendum, which
measures dcrd's payload rather than deriving it: the comparison is sound and
the figures below do support it. What that addendum removes instead is the
*precedent* for lever (d) — dcrd stores `spendjournalv3` at exactly the same
bytes, so a denser row is a divergence to invent, not a dcrd behaviour this
port is failing to copy.

**Commit cost.** 14.87 us per dirty entry at the end of a full un-indexed
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

> **Superseded by the 2026-08-15 addendum**, which re-measures the gap at
> 1.29x daemon-against-daemon. This table stands as measured; it is the
> ratio's currency that has lapsed, and part of it was this harness — both
> nodes syncing from each other on one machine.

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
here read `:386` until the 2026-08-07 addendum corrected it; that line now
holds `DEFAULT_DB_CACHE_BYTES`), and redb will not return a
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
8.33 GiB more on disk, all of it metadata. (Re-measured 2026-08-15: **1.29x
and 9.89 GiB** — see the addendum at the end of this file.)

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
store is `DbCache::run_flush`. It is reached from `Transaction::commit_internal`
(`transaction.rs:671`), where the committing transaction's read snapshot
sits at the last committed id `R` and the flush's own write lands at `R+1`.
`free_until` is therefore `R+1` whether or not that reader exists: the
transaction that triggers its own flush pins nothing.

The second path is closed by locking rather than arithmetic.
`Database::begin` takes the cache mutex and holds it across `begin_read()`
(`lib.rs:1143-1155`, in `begin_seed`). It no longer holds it across the flush:
since `d5aa17f` (2026-08-16) `flush_locked` takes the cache lock only to
`begin_flush` and `finish_flush`, releasing it across `DbCache::run_flush` and
redb's commit (`lib.rs:400-421`), so a *new* reader can now come into existence
while a flush is running. The in-flight layers stay published for the duration
instead, which preserves what a reader sees but not this argument.

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
them (`lib.rs:882-884`). It has been reflink-cloned to
`baseline-2026-07-25/` (btrfs, 22 s, no
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

## Addendum, 2026-08-10 — levers (b) and (c) measured for throughput; (b) is inverted

The earlier sweeps could not measure throughput: one turned the wrong knob,
the other was voided by a 1.64x drift. `dcroxide-bench sweep` fixes the
method — arms interleaved with the order rotated each repetition, a fresh
process and workdir per run, machine state recorded, a discarded warm-up, and
a summary that reports drift and range overlap before any median.

Twelve full-chain runs, four arms at three repetitions, `--addrindex`,
excluding the cold-start first run:

| arm | dbcache / metacache / utxocache | range (s) | vs baseline | |
|---|---|---|---:|---|
| baseline | 1024 / 100 / 150 | 3866-3888 | 1.00x | |
| **cache** | 8192 / 100 / 150 | 5125-6294 | **1.50x** | disjoint |
| **cadence** | 1024 / 800 / 1200 | 3424-3467 | **0.89x** | disjoint |
| both | 8192 / 800 / 1200 | 3459-3511 | 0.90x | disjoint |

Every arm's range is disjoint from the baseline's, which is a claim about
every observation rather than a comparison of medians against a noise floor.

**Lever (b) does not merely fail; it reverses.** Its entire basis was a
500,000-key insert microbenchmark in which raising the page cache from 1 GiB
to 8 GiB cut the loop from 4.3-6.1 s to 1.3-1.5 s. Over a full chain the same
change makes the replay **50% slower**. A plausible mechanism is in this
file's own `Options` documentation: redb splits `db_cache_bytes` 90/10 into
read cache and write buffer, so an eightfold figure mostly buys read cache a
sequential sync does not reuse, while the LRU accounting grows with it. The
microbenchmark measured a workload whose working set fits; a sync's does not.
**Lever (b) is closed, in the opposite direction to its premise.**

**Lever (c) is a real 11% gain** — the first lever to show a measured
throughput benefit, and modest against the 2.2x gap as it stood when this was
written. Against the 1.29x measured 2026-08-15 it is a materially larger
share of the remainder.

**They interact, as this ADR insisted they would.** The 50% cache penalty
disappears when cadence is raised: `both` matches `cadence`. Measuring either
alone would have produced a number that could not be interpreted, and the
instruction to measure them together was right.

**A method note.** The first run of the sweep took 6,440 s against 3,866-3,888
for the same configuration later — a 66% cold-start penalty that the
first-half/second-half drift check misreported as a trend. `sweep` now
discards a warm-up run by default and reports range overlap, which does not
confuse a single outlier with drift.

## Addendum, 2026-08-10 (second) — lever (d) measured: one bucket, and a blocked remedy

`dcroxide-bench redbstat --buckets` reports each bucket's rows, payload and
mean row size, with how many rows fit a page and the slack that implies. Run
against the store that reproduces the synced datadir:

| bucket | rows | payload MiB | mean row | rows/page (modelled) | predicted slack MiB (modelled) |
|---|---:|---:|---:|---:|---:|
| **spendjournalv3** | 1,100,392 | 2,520.8 | **2402 B** | **1** | **1,777.6** |
| `d` (existsaddridx) | 66,494,886 | 1,585.4 | 25 B | 124 | 509.4 |
| gcsfilters | 1,100,393 | 414.4 | 395 B | 10 | 15.4 |
| stakeblockundo | 1,100,393 | 402.7 | 384 B | 10 | 27.1 |
| blockidxv3 | 1,100,393 | 243.7 | 232 B | 17 | 9.1 |
| ffldb-blockidx | 1,100,393 | 239.3 | 228 B | 17 | 13.6 |
| utxosetv3 | 1,849,177 | 128.8 | 73 B | 50 | 15.7 |

> **Correction, 2026-08-12.** The last two columns are *modelled* —
> `floor(page_size / mean_row)` — and the model has since been deleted from
> `redbstat` (see the second 2026-08-12 addendum below). Measured,
> `spendjournalv3` carries **1.536 GiB** of slack against the 1,777.6 MiB
> predicted here, 13% high, and the mean the model divides by hides two
> populations: p50 1024 B, largest row 66,699 B. Read those two columns, and
> the two paragraphs after this table, as resting on that model.

Predicted slack across all buckets: **2.33 GiB**, against the 3.44 GiB
measured — the model accounts for two thirds of it, and its prediction for
`spendjournalv3`'s footprint (4,298 MiB) lands on the 4.1 GiB this ADR
measured independently. The mechanism this lever proposed is real and
located.

**It is one bucket.** `spendjournalv3` contributes 1.74 GiB of the predicted
2.33, about 75%. Its 2402-byte mean row is over half a 4096-byte page, so two
rows can never share one and roughly 1694 bytes of every page is slack. Every
other bucket packs at 10 rows per page or better and contributes little.

> **Correction, 2026-08-12.** Modelled, and the mechanism is wrong. redb
> splits a leaf whose serialized form exceeds a page *unless the leaf holds
> a single pair* (`btree_base.rs` `should_split`), so the threshold is per
> row rather than per mean: with a 36-byte key a value over about 4048 bytes
> can never share a leaf, and two rows share only when each is under about
> 2002. `spendjournalv3` is two populations — 83% of rows that already share
> leaves and 16.7% large enough to need their own page runs — so "two rows
> can never share one" is false for five sixths of them. The measured slack
> is 1.536 GiB, roughly 86% ordinary leaf under-fill and 14% allocator
> power-of-two rounding, neither of which a key layout reaches: the
> re-keying this mechanism implies was built and refuted (see the second
> 2026-08-12 addendum). "The mechanism this lever proposed is real and
> located", above, is wrong in the same way.

**The obvious remedy is unreachable.** Raising the page size to 8 KiB would
fit three of those rows. redb gates `Builder::set_page_size` behind
`#[cfg(any(fuzzing, test))]` (`db.rs:1176`) and exposes no feature that
enables it, so testing the page-size variant of this lever means forking the
dependency. That is a fact about redb, not a result about dcroxide, and it is
why the lever stayed untested for so long.

**What is reachable is a denser row.** Anything that brings a spend-journal
entry below about 2040 bytes fits two per page and recovers most of the
1.74 GiB. dcrd's own domain-level compressed amount and script encodings are
the precedent, and are the same mechanism [ADR-0009](0009-storage-shape.md)
identifies behind dcrd's smaller `utxodb`. That is a change to what the port
stores, not to how redb stores it, so it needs weighing against parity: the
spend journal is dcroxide's own serialization, but its *contents* are
consensus rewind data.

> **Correction, 2026-08-11.** The precedent named in that paragraph does not
> exist, and neither does the mechanism it attributes to `utxodb`. dcrd
> stores `spendjournalv3` at 1,100,392 rows and 2,643,223,854 bytes — the
> same rows and the same bytes as dcroxide, because dcroxide already uses
> dcrd's compressed amount and script encodings. There is no denser dcrd
> encoding to copy. dcrd's `utxodb` is not smaller in payload either
> (127,657,896 B against dcroxide's 135,054,499 for the same 1,849,177
> entries, the difference being a 4-byte bucket-id prefix); its *file* is
> smaller than its own payload because goleveldb elides shared key prefixes,
> which is an engine property, not an encoding. See the addendum below. The
> arithmetic in the paragraph stands — a row under ~2040 bytes still fits two
> per page and still recovers ~1.74 GiB — but it would be a divergence from
> dcrd rather than a convergence with it, which raises the parity cost the
> paragraph already flags.

**So the gate.** Lever (d) is now measured rather than assumed. Its upside is
bounded at roughly 1.74 GiB, concentrated in one bucket, reachable only by
re-encoding that bucket's rows and not by any storage-engine setting. Set
against the 3.44 GiB of slack and the 8.33 GiB total gap, it is a real but
partial remedy — and unlike levers (a), (b) and (c) it is not closed, only
costed.

## Addendum, 2026-08-11 — dcrd's payload, measured: the same bytes, a different engine

Every dcrd figure in this file until now was a *file size*. This addendum
measures dcrd's payload with `tools/dcrdstat`, which defines payload exactly
as `dcroxide-bench redbstat --buckets` does — every key/value pair,
`len(key) + len(value)`, attributed by ffldb's four-byte bucket id — so the
two sides report the same quantity rather than two analogous ones.

**Method, stated because composition is what this project has lost before.**
dcroxide exported `mainnet-full.corpus` from its own datadir in dcrd's
`addblock` bootstrap format; dcrd imported that exact file. Both sides
therefore ingested byte-identical blocks, with no network sync on either.
Index composition was **recorded**: exists-address index on, transaction
index off, on both sides. One trap is worth naming — `addblock` logs
"Exists address index is enabled" and then does not build it; the index
subscriber only catches up when the daemon runs, so the store was 4.09 GiB
with no `existsaddridx` bucket until `dcrd --norpc --nolisten
--connect=127.0.0.1:1` brought it to 5.98 GiB. A comparison drawn before
that step would have been the 2026-07 baseline's error over again. The
datadir is preserved and rowed in [bench-ledger.md](../bench-ledger.md).

**The result: the two implementations store the same payload.**

| | payload | on disk | over its own payload |
|---|---:|---:|---:|
| dcrd, goleveldb, two stores | 6,061,905,929 B (5.646 GiB) | 6.096 GiB | **1.081x** |
| dcroxide, redb, live B-tree | 6,069,302,583 B (5.652 GiB) | 9.823 GiB | **1.738x** |
| dcroxide, whole file, uncompacted | " | 16.002 GiB | 2.832x |
| dcroxide, whole file, compacted | " | 12.052 GiB | 2.132x |

(Payload here is bucket-attributed, the figure both tools report;
`stored_leaf_bytes` is 398 B larger because it also counts the `bidx`
bucket-index rows. The ratios move by 1e-7.)

> **Correction, 2026-08-12.** This table first quoted *consumed* bytes for
> the redb side — 14.505 GiB rather than 16.002 — on the reasoning that
> `metadata.redb` is sparse and `st_blocks` is therefore the honest figure.
> That is backwards. redb extends with a bare `set_len` and never punches a
> hole, so the sparse tail is only the part no page has been written into
> *yet*; it shrinks as the node runs and never grows back. `st_blocks` is a
> high-water mark of one run, not a footprint. Quote apparent length, or the
> live tree. The same correction applies to the compaction figures below.

Fifteen buckets agree **to the byte**, including `spendjournalv3`
(2,643,223,854 B over 1,100,392 rows on both sides) and `existsaddridx`
(1,662,372,150 B over 66,494,886). The whole-store difference is 7,396,654 B
against 7,396,708 B predicted from the 4-byte bucket-id prefix dcroxide adds
to each of 1,849,177 UTXO rows — a **54-byte residual on 6.06 GB**. The
per-bucket table is in the ledger.

Note what that measures: equal row counts and equal summed key+value
lengths, not a content diff. A sum cannot see offsetting differences. But
fifteen buckets agreeing simultaneously at byte resolution is not something
two different encodings produce, and a digest over each side's sorted stream
would settle it outright.

**Which figure to quote.** The live tree, 1.738x. It reproduces — 9.79 to
9.82 GiB across runs, 0.3% — where the whole-file figure does not: matched
composition has produced 14.00, 14.48 and 16.00 GiB apparent, with free
pages at 4.18, 4.69 and 6.17 GiB. Free pages are working space (see the
2026-08-09 retraction), so the live tree is also the honest structural term.
Two asymmetries belong in the same breath as any ratio:

- **goleveldb's 1.081x is not a pure packing figure.** Its sstable blocks
  store only each key's non-shared suffix relative to its predecessor, with
  compression explicitly off on both stores (`Compression: opt.NoCompression`
  in dcrd's `database/ffldb/db.go` and `internal/blockchain/utxobackend.go`).
  That is why `utxodb` holds 127,657,896 B of payload in a 119,405,557 B
  file — **0.935x its own payload**, which ADR-0009 called impossible. It is
  not impossible; it is prefix elision on sorted 34-byte outpoint keys that
  repeat a 32-byte txid. A file size can never bound a store's payload, and
  that single error is what sent the earlier comparison wrong.
- **The two stores were not written on the same schedule.** dcrd's
  66,494,886 address-index rows — 92% of all rows — were appended in one
  catch-up pass over an otherwise finished database, while dcroxide's were
  interleaved across 1.1M block commits. Insertion order is a first-order
  determinant of leaf fill and free-page retention in a copy-on-write
  B-tree, and largely erased by compaction in an LSM. So this bounds the
  gap as a storage-layer gap; it does not isolate the engine term from the
  write-schedule term. Doing that needs dcroxide replayed with a matched
  two-phase index build. **Measured 2026-08-12 (addendum below): it is
  second-order, worth 0.68% of the live tree, and it moves in dcroxide's
  favour.**

**What it settles.** ADR-0009's withdrawal of the density comparison is
reversed: dcrd's payload is measured, not derived, and the encodings are not
denser. The *domain-level* explanation for the disk gap is dead — there is
none left, because the payload underneath is the same. What remains is the
storage layer, and within it the two terms above.

**What it closes and does not close.** It closes lever (d)'s precedent, not
lever (d): re-encoding `spendjournalv3` still recovers ~1.74 GiB
arithmetically, but with no dcrd behaviour to copy it becomes a deliberate
divergence. A re-*keying* that splits the row while storing dcrd's exact
bytes is a third option this file has never considered and nobody has
tested.

**Compaction, since free pages are the largest remaining term.**
`redb::Database::compact` is never called in dcroxide. Measured twice now,
it disagrees with itself by 20x on the same chain: 0.12 GiB in 598.5 s on
the 2026-07 datadir, 3.950 GiB in 137.9 s on the replay store (16.002 GiB of
claimed length down to 12.052, the compacted file being dense). The
disagreement is the result — compaction relocates pages forward and
truncates, so the yield depends on where free pages sit rather than how many
there are. It never repacks: `fill_ratio` was 0.646166 before and after, to
the digit, and every bucket's payload was identical afterwards. Neither
figure is characteristic, and it is not an operator knob on this evidence.

**A measurement trap worth recording.** `metadata.redb` is sparse. The
replay store reads 17,182,003,200 B apparent but consumes 15,574,482,944 — a
1.497 GiB hole to EOF — while dcrd's 3,179 files round *up* to 4 KiB blocks,
consuming 6,552,084,480 against 6,545,168,267 apparent. Comparing apparent
sizes overstates redb's cost by about 10% and understates dcrd's. Use
`st_blocks`.

> **Correction, 2026-08-12.** The trap is real and the conclusion drawn from
> it was wrong. redb extends its file with a bare `set_len` and never calls
> `fallocate` or punches a hole, so the tail is unwritten rather than
> reserved: it only ever fills in. Six million scattered writes into a copy
> of one store left the length bit-identical while consumed rose 398 MiB.
> `st_blocks` therefore records how far a particular run got, not what the
> store costs, and an operator's `du` climbs toward `st_size` as the node
> runs. **Quote apparent length, or the live tree.** The 2026-08-12 addendum
> shows what the wrong choice buys: two stores of byte-identical length whose
> consumed figures differ by 717 MB, entirely in sparse tail, pointing the
> opposite way from every quantity the engine itself accounts for.

**A tool bug this exposed, now fixed.** Both instruments reported
`existsaddridx` as a bucket named `d`. `bidx-cbid` — the bucket-id counter —
shares the `bidx` prefix and parses as an index row: nine bytes with a
four-byte value, so the split reads `-cbi` as the parent and `d` as the
name, then binds it to the id the counter holds, which is the most recently
allocated bucket. It sorts after the real row (`-` is 0x2d against the root
parent's 0x00) and overwrote it. Every per-bucket table this project has
produced carried the wrong label for its second-largest bucket; no number
was affected. Fixed in both tools, with a test that fails without the fix.

## Addendum, 2026-08-12 — the write schedule is second-order, and two disk metrics disagree

The previous addendum's second caveat was that dcrd's index was appended in
one catch-up pass over a finished store while dcroxide's was interleaved
across 1.1M block commits, so the comparison bounded a storage-layer gap
without isolating the engine from the schedule. This measures it.

`dcroxide-bench indexcatchup` builds an index over a finished store through
the same `IndexSubscriber::catch_up` the daemon uses — a port of dcrd's
`CatchUp`. `replay` with no index flags followed by that reproduces dcrd's
schedule. Two arms, two reps, order alternated, identical composition.

| | live tree | fill | intra-page slack | over payload |
|---|---:|---:|---:|---:|
| twophase (dcrd's schedule) | 10,475,610,112 | 0.650482 | 3,661,410,507 | **1.726x** |
| interleave (the shipped path) | 10,547,240,960 | 0.646171 | 3,731,920,971 | **1.738x** |

Payload is byte-identical across arms and across scales, so catch-up builds
exactly the index the interleaved path builds. Both reps of each arm agree on
every storage figure to the byte — the replay is deterministic, which is
worth knowing on its own: variation seen earlier across "matched" runs came
from differing configuration, not from noise.

**The schedule is real, in the predicted direction, and second-order.**
Batch-building does pack better — fill +0.004, slack −1.9%, live tree
−0.68% — so the objection's mechanism was right. Its magnitude was not: the
effect closes about 1.8% of the excess of dcroxide's 1.738x over dcrd's
1.081x. The schedule-matched structural figure is **1.726x**; 1.738x remains
what the shipped path actually produces. The caveat can be struck for the
address index, and what remains is attributed to the storage layer by
elimination rather than identified.

**Bounded, not closed.** Only exists-address rows changed schedule —
`spendjournalv3`, the largest bucket and 1.74 GiB of the predicted slack, is
written per block in both arms. Neither arm was compacted, while dcrd was
measured after its compactor had quiesced. redb persists its allocator across
a clean close, so phase 2 writes into free pages phase 1 reserved, which is
not goleveldb's situation. And goleveldb's own schedule sensitivity — the
premise of the objection, that copy-on-write trees are sensitive where LSMs
are not — was never measured, so this is closed in one direction only.

**Two figures pointing opposite ways, and why one is not a measurement.**
Consumed bytes say interleaving *wins* by 4.6% (16,291,467,264 against
15,574,482,944). Both files have byte-identical length, 17,182,003,200 B, and
the whole 716,984,320 B difference is sparse tail — it matches the hole
difference exactly. It records how far into the final region each run had
written when it stopped. Free pages (6.233 against 6.169 GiB) are the same
non-finding restated: with the length fixed, `allocated + free` reconstructs
it to within ~30 KB, so free pages are the live-tree number with its sign
flipped, not an independent quantity. Free pages have moved 4x at 250k, 2.01x
across five matched cache/cadence arms with the live tree pinned, and 55%
between two ledger runs of the same arm. They are not a comparison metric,
and this file's earlier treatment of them as "the largest single component
and the least understood" should be read as a statement about the allocator,
not an invitation to compare stores by them.

**A void pilot, recorded because the trap generalises.** A 250,000-block
version of this experiment showed interleaving costing 32% more — the
opposite result. Its two arms landed on *consecutive rungs of redb's
file-growth ladder*: 2,156,408,832 B and 4,295,503,872 B. redb doubles the
trailing region while the file holds no full region and adds whole 4 GiB
regions above that, with page size and region size both un-settable outside
`cfg(test)`, so lengths quantise hard. One growth event decided every
file-level figure in the pilot. Its two unquantised figures, live tree and
fill, agree in sign with the full chain. Any storage comparison on a corpus
small enough to sit near a rung boundary is measuring the boundary.

**Timing, reported and not established.** Two-phase finished ahead in both
replicates — 61.0 and 56.5 minutes including 10.6 and 10.0 of catch-up,
against 68.9 and 68.8 — and the slowest two-phase beat the fastest
interleave by 7.8 minutes. But n=2, the order was blocked rather than
interleaved, the within-arm spread on two-phase is 8.0%, no drift was
measured, and catch-up's block reads may have come from a page cache phase 1
warmed. It was not run through `dcroxide-bench sweep`, which exists for this
comparison class and reports drift before arm effects. A hypothesis worth
re-measuring, not a result. It is also not reachable by default: the daemon
indexes inline during IBD, though an operator can approximate it by syncing
under `--noexistsaddrindex` and restarting without it, at the cost of a
startup stall with `existsaddress` unavailable.

**What this does not change.** It supplies the schedule-matched figure and
retires one caveat. It is not new evidence for a storage rework: both of
ADR-0009's remaining blockers — the candidate engine benchmark and lever
(d)'s untested re-keying — are untouched. And it says nothing about the 2.2x
IBD gap, which is a live-network measurement of a path this offline replay
does not exercise.

## Addendum, 2026-08-12 (second) — lever (d): the slack is real, the re-keying does not reach it

ADR-0009 kept one option alive under lever (d): re-key `spendjournalv3` so
each row is split across several keys, letting chunks from different blocks
share a page without changing a stored byte. It was the last remedy that did
not require inventing an encoding dcrd does not have. It has now been built
and measured, and it does not work.

**The instrument.** A standalone probe (redb 2.6.3 only, no dcroxide code)
reads the real value length of every `spendjournalv3` row out of a live
store, then builds fresh databases inserting each row as *k* keys whose
values partition the original. Identical pseudo-random key order and commit
cadence across arms — the write schedule moves fill on its own, as the
previous addendum establishes.

| arm | tree bytes | payload | slack | fill | vs today |
|---|---:|---:|---:|---:|---:|
| **k=1, today** | **4,349,997,056** | 2,643,223,854 | 1,649,264,978 | 0.6076 | — |
| k=2 | 4,622,987,264 | 2,687,202,978 | 1,851,670,202 | 0.5813 | +0.254 GiB |
| k=4 | 4,608,131,072 | 2,770,796,214 | 1,729,445,984 | 0.6013 | +0.240 GiB |
| split >4048 into 2002 | 4,724,146,176 | 2,666,495,856 | 1,975,077,422 | 0.5644 | +0.348 GiB |
| split >4048 into 1300 | 4,542,418,944 | 2,680,449,684 | 1,771,169,188 | 0.5901 | +0.179 GiB |
| split >2002 into 2002 | 4,757,565,440 | 2,672,015,696 | 2,000,235,630 | 0.5616 | +0.380 GiB |

**Today's layout is the smallest of the six.** Every re-keying raises *slack*
as well as payload, so it is not merely paying for the extra keys — it packs
worse too. The selective arms, which split only the rows that provably cannot
share a leaf, lose as well.

**The slack is real: 1.536 GiB**, 44% of the store's, and the model that
predicted 1.74 GiB was 13% high rather than fabricated. That is why it went
unchallenged for days.

**The mechanism, which the model had wrong.** redb splits a leaf when its
serialized form exceeds one page *unless the leaf holds a single pair*, which
is then given a power-of-two run of pages (`btree_base.rs` `should_split`).
So the threshold is per row, not per mean: with a 36-byte key a value over
about 4048 bytes can never share a leaf, and two rows share only when each is
under about 2002. `spendjournalv3` is therefore two populations — 83% of rows
that already share leaves, and 16.7% large enough to need their own page
runs — and chunking makes the first population worse to help the second.
Roughly 86% of the slack is ordinary B-tree leaf under-fill, an artifact of
splitting at the byte midpoint under random keys, and 14% is the allocator's
power-of-two rounding. Neither is addressable by a key layout.

**What this leaves of lever (d).** The page-size remedy is unreachable, the
re-keying remedy is refuted, and the denser-row remedy lost its dcrd
precedent in the 2026-08-11 addendum — dcrd stores this bucket byte for byte
as dcroxide does. So the 1.536 GiB is real, attributable, and reachable only
by inventing an encoding denser than the reference implementation's, or by a
different storage engine. **The lever is closed at this layer.** That is a
finding for ADR-0009's engine question, not against it.

### The measurement error, recorded because it is this file's own trap

The probe's first pass reported every arm within 0.045% of the baseline and
concluded that re-keying was neutral and the slack was a model artifact. Both
were wrong. It had called `WriteTransaction::stats()`, whose
`fragmented_bytes` adds `count_free_pages() * page_size`
(`redb transactions.rs:2298`) — so its headline column tracked a 6.44 GB
*file* containing 2.09 GB of free pages, inside which the tree and the free
pool moved in opposite directions and cancelled. The correct statistic is the
per-table `TableStats::fragmented_bytes`, which is exactly what this file's
findings header names as measurement trap number one, and what
`RawStats::live_tree_bytes` already computes.

Two further errors came from the same pass and are corrected here: redb's
`leaf_pages()` counts leaf *nodes*, not 4096-byte pages, so "708,672 leaf
pages for 1,100,392 rows" is 1.55 rows per node and not 0.64 pages per row;
and redb 2.6.3 has no overflow-page mechanism at all — the 1.42 GiB
discrepancy this file previously attributed to overflow pages is the
allocator's power-of-two rounding, which is the same mechanism lever (d)
turns on. Both doc comments in `dcroxide-database` are fixed.

### The model is deleted

`BucketStats::rows_per_page`, `predicted_pages` and `predicted_slack_bytes`
are removed. They were untested, had one consumer, and printed modelled
columns in the same table and typeface as measured ones with no provenance
marker. `redbstat --buckets` now reports the measured distribution instead —
mean, p50, p90, p99 and `largest_row_bytes`, the last of which was computed
all along and read by nothing. On the real store it prints mean 2402 against
a p50 of 1024 and a largest of 66699, which is the shape that would have
killed the mean-row reading on day one.

The rule this implies, and which the ledger now carries: a bench tool may not
print a modelled quantity beside measured ones without labelling it, and no
ADR may quote a modelled figure without a measured counterpart. redb reports
page counts per *table* and never per bucket, so a per-bucket page figure is
not something this project can measure — only model.

## Addendum, 2026-08-13 — redb 2.6.3 to 4.1.0

Taken on the strength of [ADR-0009](0009-storage-shape.md)'s candidate
engine benchmark, which measured the upgrade arm alongside the swap
candidates. It is a dependency bump, not the storage rework that ADR
discusses, and it should not be read as a step toward one.

**What it buys, measured on the identical engine-level journal.** The same
76,301,856 rows occupy 15,568,752,640 B under 4.1.0 against 17,182,003,200
under 2.6.3 — **9.4% less** — and the load ran 3,842 s against 4,884 s.

**What it does not buy, and this is the point.** Packing is untouched. A
250,000-block replay under 4.1.0 reproduces the 2.6.3 tree exactly: live
tree 1.355 GiB and fill 0.6373 on both, to four decimals. The gain is
entirely in free-page retention, which is the allocator, not the B-tree. So
this does nothing for the 1.738x structural figure that motivates ADR-0009,
and an engine that stores the same payload in 1.026x remains the open
question. Anyone reading this addendum as "the space problem is being
addressed incrementally" has read it wrong.

**The on-disk format changed, and old data directories are refused.** redb 4
reads only file format 3 and returns `UpgradeRequired` for a 2.x file, so it
cannot misread one. That is mapped to `ErrorKind::Invalid` with a message
that names redb 2.x, says to sync again, and says the chain is not damaged —
the two failures an operator can hit here need to look different from each
other. There is no in-place migration and ADR-0004's fresh-sync stance means
there does not need to be. A test writes a genuine 2.x store with the
previous major as a dev-dependency and asserts the refusal, so the behaviour
keeps being tested if either version moves.

**MSRV is unaffected:** redb 4.1.0 requires 1.89 against this workspace's
1.94 floor.

**Known issues in 4.1.0, since fixed upstream**, recorded so the upgrade is
not mistaken for a robustness improvement: #1331 and #1332 abort the process on malformed
on-disk structures (an unvalidated 5-bit page order, and a cyclic branch
pointer reached from ordinary reads), #1333 leaves a file permanently
unopenable when the repair path itself panics, and read paths do not verify
page checksums until a fix that is currently master-only. These concern
files that are already damaged or hostile; they are not regressions against
2.6.3, which shares the lineage. They are a reason to treat the upgrade as
routine maintenance rather than a hardening step, and a reason the
crash-safety question in ADR-0009 stays open.

## Addendum, 2026-08-15 — the IBD gap re-measured: 1.29x, not 2.2x

The 2026-07 amendment above put dcroxide at ~2.2x dcrd's initial block
download, and every downstream claim in this repo descends from it. Measured
again, daemon against daemon, the gap is **1.29x**.

Both daemons sync mainnet genesis to tip from **one shared dcrd server** on
loopback, sequentially, defaults intact. Index composition was verified in
both logs — exists-address index on, no transaction index, both sides — rather
than assumed, because assuming it is what cost the 2026-07 baseline its
conclusion.

| arm | blocks | wall | rate | mean cores | mean loadavg |
|---|---:|---:|---:|---:|---:|
| dcrd 2.2.0-pre+452c1a6c3 | 1,100,392 | 3,220.5 s | 341.7 blk/s | 1.50 | 2.45 |
| dcroxide `b6d0c63` | 1,100,392 | 4,153 s | 265.0 blk/s | 0.76 | 4.62 |

**Both sides improved**: dcroxide 124 → 265 blk/s (2.14x), dcrd 276 → 342
(1.24x). dcrd improving on the same hardware is the tell that part of the
original figure belonged to its harness — the 2026-07 campaign ran the two
nodes syncing *from each other*, contending for one machine. That inflated
both arms and the ratio between them.

**This is a bound, not a point estimate.** The arms ran ~12 h apart, under
load averages of 4.62 and 2.45, n=1 each, and the dcroxide binary predates
`c091b46` (one validation worker per core, 6.1% on the replay corpus). Every
one of those can only have cost dcroxide, so the true gap is 1.29x or better.
The [bench ledger](../bench-ledger.md) records the full caveat list and the
harness fault behind it.

**What it changes for this ADR.** The verdict's price — "~2.2x dcrd's
initial-block-download time and 8.33 GiB more on disk" — is now ~1.29x and
9.89 GiB (23.69 GiB against 33.58, apparent size, composition verified). And
the framing that the lever results were measured against: lever (c)'s 11% is
11% of a 1.29x gap, not of a 2.2x one, which makes above-the-engine tuning a
materially larger share of what is left to win than this ADR assumed.

**What it does not change.** It is not evidence about *where* the remaining
time goes. The commit-shape attribution rests on the same 2026-07 stall
statistic, which records that progress halted rather than what halted it, and
the 2026-08-14 profiling attempt failed. If anything the new run sharpens the
question rather than answering it: **dcroxide reaches 1.29x while using 0.76
cores against dcrd's 1.50**, so it is not compute-starved, it is waiting. A
load average of 4.62 at 0.76 cores is either another tenant on the box or
dcroxide's own threads in uninterruptible sleep on redb writes — the second
would be direct evidence for the storage attribution this ADR has never been
able to establish, and separating the two is the next measurement worth
making.

## Addendum, 2026-08-15 (second) — the commit-shape attribution, finally measured

This ADR has claimed since 2026-07 that the IBD gap is the storage engine's
commit shape rather than validation, on the strength of a progress-stall
statistic — which records that progress halted, not what halted it. Every
attempt to profile it failed, most recently on 2026-08-14. **The mechanism is
now measured, and the claim holds. The hypothesis was wrong about where the
cost lands, which is why the profilers kept missing it.**

Both daemons syncing mainnet from one shared dcrd server, back to back on a
quiet box, with per-thread scheduler states sampled at 10 Hz and the whole
system's task table walked at 1 Hz. Mean tasks during block sync — the load
average counts runnable *and* uninterruptible:

| arm | own R | own D | kernel threads | server | other userspace | loadavg |
|---|---:|---:|---:|---:|---:|---:|
| dcroxide | 0.77 | 0.38 | **1.64** | 0.08 | 1.72 | 5.54 |
| dcrd | 1.86 | 0.12 | **0.14** | 0.10 | 1.23 | 2.62 |

**The port's own threads are not the blocked ones** — 0.38 is far too few to
explain the gap. What separates the daemons is kernel-side storage work,
**1.64 against 0.14, 11.7x**, overwhelmingly `dmcrypt_write` (1,002 blocked
samples against 23). This is why profiling dcroxide's threads never found the
cost: most of it is not in the process.

**It is the write shape, not the write volume.** dcrd wrote **1.16x more
bytes at 1.74x the rate** (382.64 GiB against 331.29, 122.4 MiB/s against
70.4) and blocked **30x less per GiB** (0.1 dm-crypt-D samples per GiB against
3.0). The LSM has the *higher* write amplification of the two — 16.2x against
the B-tree's 10.5x — and still costs less, because compaction is sequential
and off the write path, while the copy-on-write B-tree writes fewer bytes
synchronously with one fsync per commit. dcroxide also reads **99x** more
during ingest (42.48 GiB against 0.43): the B-tree fetching pages to copy
them, a cost this ADR had not accounted for at all.

**The wait channels name it.** dcroxide's blocked threads park in
`folio_wait_bit_common` (page writeback), `handle_reserve_ticket` (btrfs
metadata reservation), `wait_for_commit` (transaction commit) and
`btrfs_btree_wait_writeback_range`. dcrd's park in `folio_wait_bit_common` and
`barrier_all_devices`.

So the sentence this ADR has carried — "goleveldb's LSM commit is O(dirty)
with background compaction, while redb is a copy-on-write B-tree with no
background work, so commit cost tracks the size of the tree" — is now
evidence rather than inference. **Read it with the correction that the cost is
largely paid outside the process**, in kernel writeback and dm-crypt.

**The share, from the same samples.** dcroxide is **fully stalled — zero
runnable threads — for 34.6% of block-sync wall time**, against dcrd's 0.9%,
and 99.4% of its blocked samples have nothing else runnable, so this is
critical-path wall time rather than an occupancy figure. It tracks tree growth
exactly as this ADR predicted: 1.3% below block 300,000, **50.9% above block
900,000**. Removing it moves dcroxide to 346.6 blk/s against dcrd's own
counterfactual 346.9.

> **Corrected 2026-08-16.** "The stall is the entire gap" and the ~1.5x prize
> drawn from it are withdrawn: the counterfactual removing only the commit
> stall projects 373.7 blk/s, *faster than dcrd*, which shows the model is too
> generous rather than the prize large. A flush is not pure blocking — median
> 26.9 s, occupying 59% of wall — and a background committer relocates its CPU
> half rather than removing it.
>
> **What survives, measured the same day by pairing the sampler with
> dcroxide's own flush observer:** the metadata commit is **90–98% of the
> fully-stalled time** on every weighting, and the stall is **48% of
> block-sync wall time** once the sampler's own starvation is corrected for
> (34.6% was a count-weighting artifact; both runs agree at 48–51% when
> weighted by represented time). During a flush the process is stalled 40.9%
> of the time at 0.55 cores; outside one, 3.2% at 1.38. So this ADR's
> commit-shape attribution is confirmed at the call site, not merely at the
> mechanism. Full figures and the method's two weaknesses in
> [bench-ledger.md](../bench-ledger.md).

**What it does not settle.** Whether the stall is *removable*. dcrd shows the
work can be overlapped with compute; it does not show redb can overlap it. Two
or more dcroxide threads block simultaneously in only 0.2% of samples, so its
storage path is serialized — which implicates the commit structure, a
synchronous fsync on the critical path, as much as the engine choice. It is
n=1 per arm, ambient was not matched between arms, and
thread-state counts are not strictly commensurable between a Rust
thread-per-operation process and a Go runtime — which is why the argument
rests on kernel-side and per-GiB figures rather than the own-thread
comparison. The filesystem is btrfs on LUKS; how much of the dm-crypt term
survives on a different stack is untested.

**Two cheap instruments are blind to this and should not be reached for.**
`/proc/stat`'s `procs_blocked` counts only tasks in `io_schedule()`: three
threads in a write+fsync loop measure D=2.93 in a task walk while
`procs_blocked` reads 1.54, *below the target's own count*. Delay accounting
fails identically — with `kernel.task_delayacct=1` confirmed live against
O_DIRECT reads, dcroxide's entire sync logged **zero** blkio ticks. btrfs
fsync blocking is uninterruptible and counted by the load average, but it is
not block-device wait. Only a task-state walk sees it.

Full figures, caveats and raw paths in [bench-ledger.md](../bench-ledger.md).
