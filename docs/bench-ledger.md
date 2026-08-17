# Benchmark ledger

Every performance number this repo relies on, keyed by machine, commit,
and corpus, so any two measurements can be compared — or ruled
incomparable — after the fact. Prose snapshots (README, ADRs) cite
these rows; this file is the record.

Rules: append rows, never rewrite them. A row names the machine (table
below), the dcroxide commit measured, the workload, and where the raw
run lives. Raw exports, logs, and profiles stay out of the tree, under
`/home/jz/zx/dev/artifacts/dcroxide-bench/<machine>/<commit>/` on the
machine that ran them. Record a row for every storage-rework milestone,
so the campaign against the IBD gap produces a curve, not before/after
anecdotes. That gap was 2.23x when the campaign opened in 2026-07 and
measured 1.29x on 2026-08-15; the curve is the point of this file.

## Machines

| id | CPU | cores/threads | RAM | disk |
|---|---|---|---|---|
| m1 | AMD Ryzen AI MAX+ 395 | 16/32 | 64 GB | WD PC SN5000S 1 TB NVMe |

Hardware was not recorded when the 2026-07 campaign ran; its rows are
attributed to m1 as the only bench host to date, with specs read on
2026-08-07.

## Sync throughput

Mainnet genesis to tip over loopback, one machine, fresh datadir per
run, both nodes `--norpc`.

| date | machine | dcroxide commit | vs dcrd | corpus | result | source |
|---|---|---|---|---|---|---|
| 2026-07 | m1 | unrecorded (2.2.0-pre, at the ADR-0004 amendment) | 2.2.0-pre+452c1a6c3 (go1.26.5) | mainnet, ~1,100,400 blocks | syncer dcroxide: 2.47 h — 124 blk/s (from dcroxide), 2.51 h — 122 blk/s (from dcrd); syncer dcrd: 1.11 h — 276 blk/s, 1.02 h — 299 blk/s | ADR-0004 amendment |
| 2026-08-15 | m1 | `b6d0c63` (fan-out fix `c091b46` **not** in the binary) | 2.2.0-pre+452c1a6c3 (go1.26.5) | mainnet, 1,100,392 blocks | Both daemons from one shared dcrd server, sequential, defaults, exists-address index verified on both: dcroxide 4,153 s — **265.0 blk/s** at 0.76 mean cores; dcrd 3,220.5 s — **341.7 blk/s** at 1.50. **1.29x**, not the 2.23x above. Arms ~12 h apart under unmatched loadavg (4.62 vs 2.45), n=1 — a bound, not a point estimate | this file, below |
| 2026-08-15 (second) | m1 | `8b27d20` (fan-out fix included) | 2.2.0-pre+452c1a6c3 (go1.26.5) | mainnet, 1,100,392 blocks | Same shared server, arms back to back on a quiet box, page cache pre-warmed before each: dcroxide 4,821.4 s — **228.2 blk/s**; dcrd 3,200.8 s — **343.8 blk/s**. Ratio **1.51x**. dcrd reproduced to 0.6% across the two 2026-08-15 runs; dcroxide fell 14% under higher ambient (a browser active in its arm only). Both runs carried more ambient in the dcroxide arm, so **1.29x above remains the tighter upper bound** — this row is the D-state run's throughput, not a supersession | this file, below |

## Storage at tip

| date | machine | dcroxide commit | corpus | result | source |
|---|---|---|---|---|---|
| 2026-07 | m1 | unrecorded (2.2.0-pre, at the ADR-0004 amendment) | mainnet tip | dcroxide 32.06 GiB total (17.579 GiB blocks + 14.483 GiB metadata.redb); dcrd 23.73 GiB (17.580 GiB blocks + 6.045 GiB metadata leveldb + 0.108 GiB utxodb) | ADR-0004 amendment |
| 2026-08-11 | m1 | `6cb2f56` | mainnet tip, both sides fed `mainnet-full.corpus` | **Matched composition, payload measured on both sides.** Metadata store, consumed bytes: dcrd 6.102 GiB (6,552,084,480) against dcroxide 14.505 GiB uncompacted (15,574,482,944) and 12.052 GiB compacted (12,940,464,128); dcroxide's live B-tree 9.823 GiB (10,547,314,688). Payload: dcrd 6,061,905,929 B, dcroxide 6,069,302,583 B. Over each store's *own* payload: dcrd 1.081x, dcroxide 1.738x on the live tree, 2.566x on the uncompacted file. | this file, below |
| 2026-08-15 | m1 | `b6d0c63` | mainnet tip, both daemons synced from one shared dcrd server, exists-address index on both, no transaction index | **Apparent size**, whole appdata: dcroxide 36,055,044,196 B (33.58 GiB) against dcrd 25,433,938,876 B (23.69 GiB) — 1.42x. Same pair as the 2026-08-15 sync row above; both daemons' own datadirs, not a replay. | this file, below |

> **The 2026-08-11 row's store sizes are CONSUMED BYTES, superseded by the
> apparent-size rule adopted 2026-08-12.** This file is append-only, so the
> row stands as written; read it with the trap recorded at the end of this
> file — redb extends with a bare `set_len` and never punches a hole, so
> consumed is a high-water mark of what one run happened to touch before it
> stopped. Read dcroxide's uncompacted store as **17,182,003,200 B apparent
> (16.00 GiB), 2.831x** over its own payload, not 14.505 GiB and 2.566x, and
> the drop to the compacted figure as the **3.950 GiB** the file's claim
> shrank by, not the 2.453 GiB the two consumed columns imply. The compacted
> file is dense, so 12.052 GiB and 2.132x stand; dcrd's files round *up* to
> 4 KiB blocks (1.001x), so its 1.081x is unaffected either way.
>
> **The live tree is the figure to quote** — 9.823 GiB, **1.738x** over
> payload, measured directly and untouched by any of this. Whole-file
> figures are the least reproducible quantity in this file: the same chain
> at the same composition has landed at 14.483 GiB apparent live-synced
> (the row above) and 16.00 GiB replayed. Both were taken on redb 2.6.3;
> 4.1.0 holds identical content in 9.4% less file, which is free-page
> retention and leaves packing unchanged.

## Storage decomposition

`dcroxide-bench redbstat`, one JSON object per run. Totals alone hide the
thing under study: a change that moves free pages without moving the file
size is invisible in the table above, and the two have different causes.

Reproduces ADR-0004's amendment, which was produced by a throwaway tool
that is not in the tree — that agreement is what licenses using this
instrument to score the levers.

| date | machine | dcroxide commit | corpus | payload | overhead | slack | free pages | fill |
|---|---|---|---|---|---|---|---|---|
| 2026-08-07 | m1 | `b49bf92`+ | mainnet tip (baseline-2026-07-25 clone) | 5.65 GiB | 0.69 GiB | 3.44 GiB | 4.69 GiB | 64.86% |

Live tree 9.79 GiB; `accounted_bytes` 15,551,077,894 against a file of
15,551,119,360, so 41,466 bytes of redb header and region metadata are
unexplained and everything else is. The walk takes about 1m53s on this
tree, which is why the per-flush observer samples rather than measuring
every commit.

Note that measuring perturbs: `stats()` exists only on a write
transaction, so each run allocates a little. Two runs against the same
clone moved `allocated_pages` by ~1,000 and free pages by ~2 MiB. Take
each measurement on a fresh clone.

## Preserved baselines

The datadir every figure above was read from, kept because opening a redb
database is not a read-only act (quick-repair on open, and `Database::open`
rolls the block files back when the metadata trails them). Probes open a
fresh reflink clone of the snapshot; neither the original nor the snapshot
is opened directly.

| date | machine | what | path | notes |
|---|---|---|---|---|
| 2026-08-07 | m1 | mainnet datadir behind the 2026-07 sync and storage rows | `artifacts/dcroxide-bench/m1/baseline-2026-07-25/blocks_ffldb/` | reflink clone of `artifacts/p2p-sync/data/mainnet/blocks_ffldb/`, written 2026-07-25; 31 GiB apparent, no additional space on btrfs, 22 s. `metadata.redb` is 15,551,119,360 B, the 14.483 GiB the ADR decomposes. |
| 2026-08-11 | m1 | **dcrd** datadir behind the matched-composition rows | `artifacts/dcroxide-bench/m1/dcrd-payload/data/mainnet/` | dcrd 2.2.0-pre at the parity commit `29f17894`. Built by `tools/addblock -i mainnet-full.corpus` (12m17s, 1,493 blk/s) and then `dcrd --appdata … --norpc --nolisten --connect=127.0.0.1:1` to drive index catch-up. **Composition recorded, which is the point of keeping it:** exists-address index ON, transaction index OFF — `addblock` defaults, no `--txindex`. Kept because ADR-0009 records that losing the 2026-07 baseline's composition cost this project a conclusion. |

## Replay throughput (dcroxide-bench)

Identical-corpus replays via `dcroxide-bench export` / `replay`
(crates/dcroxide-bench). No rows yet — the first storage-rework
milestone starts this table, measured against the corpus the 2026-07
campaign exported.

| date | machine | dcroxide commit | corpus | result | raw run |
|---|---|---|---|---|---|

## Free-page probes (`dcroxide-bench pinprobe`)

Three arms per experiment, each on its own reflink clone, differing only
in what is held open across the flushes.

| date | machine | dcroxide commit | workload | arms | result |
|---|---|---|---|---|---|
| 2026-08-07 | m1 | `6a2951b` | 400k scattered writes, 8 commits, 8 MiB overlay, mainnet clone | none / all / two | Free-page curves identical. Flushes 1-2 byte-for-byte across all arms; flush 3 differs by 41,782 B (0.0008%) between `all` and `none`, in the direction opposite to pinning. Free pages fell 48.5 MiB while payload grew 20.4 MiB and the file did not grow. ADR-0004 lever (a) closed. |

Each sampled flush costs about 206 s here, roughly half of it the
`stats()` tree walk, so a three-arm run is around an hour.

## Flush curves under replay (`dcroxide-bench replay --flushlog`)

Free-page behaviour under real sync churn — updates and deletes, not the
synthetic inserts pinprobe applies.

| date | machine | dcroxide commit | workload | flushes | result |
|---|---|---|---|---|---|
| 2026-08-08 | m1 | `52903af` | 250k mainnet blocks, 1,925,867 regular txs, 100 MiB overlay, `--statsevery 1` | 17 | Free pages are a sawtooth: 0.0 to 994.3 MiB within one run, 0.0% to 96.2% of the allocated file. Spikes are drawn down at ~80 MiB per flush against ~65 MiB of live tree added. Fill ratio is stable at 0.6169-0.6360 while the tree grows 105 MiB to 1.19 GiB. Throughput 745 to 324 blk/s across the run. |
| 2026-08-08 | m1 | `ff36811`+ | full mainnet: 1,100,392 blocks, 7,935,579 regular txs, 100 MiB overlay, `--statsevery 1` | 122 | Free pages 0.0 to 3,983 MiB (0% to 96.2% of file), **ending at 313 MiB / 4.0%** against the live-synced datadir's 4.69 GiB / 32.4%. Fill 0.6169-0.6360 across a 66x tree growth. Flush cost 528 to 2,590 ms (4.9x); stats walk 5 to 6,568 ms (1,302x) — unseparated these would read as a 17.2x commit slowdown. Replay live tree 6.81 GiB vs synced 9.79: `Chain::open` builds no optional indexes. Total 3,271 s at 336 blk/s. |
| 2026-08-09 | m1 | `7e74895` | full mainnet **with `--txindex --addrindex`**, 100 MiB overlay, `--statsevery 1` | 168 | Fill ends **0.6546** against the synced tip's 0.6486 (un-indexed 0.6258) — the invariant converges once composition matches. Free pages 0.0 to 4,465 MiB, ending 1,629 MiB / 10.6%; the same chain has now ended at 0.31, 1.59 and 4.69 GiB across three runs. Flush cost per dirty entry 1.77 to 23.27 us (13.2x) against un-indexed 1.59 to 14.87 us (9.4x). Live tree 11.56 GiB vs synced 9.79: both indexes enabled where the baseline had the address index only. |
| 2026-08-09 | m1 | `14a1907` | full mainnet **with `--addrindex` alone** (matches the baseline's composition), 100 MiB overlay, `--statsevery 1` | 130 | **Reproduces the synced datadir**: live 9.82 GiB vs 9.79, free 3.97 GiB / 33.0% vs 4.69 / 32.4%, fill 0.6462 vs 0.6486. Retracts the "free pages are not a quantity" reading — the earlier 0.31/1.59/4.69 spread compared runs with different index configurations. Per dirty entry 1.80 to 13.70 us (7.6x), marginally cheaper than un-indexed, so the write-path cost of "indexes" belongs to the transaction index, not the address index. Free share still swings 0% to 94.6% within the run and 1.6% to 33.0% across the last ten flushes. Total 4,767 s at 230.8 blk/s. |

Raw records: `artifacts/dcroxide-bench/m1/replay-flush-all.jsonl`; corpus
`mainnet-250k.corpus` (2.43 GB, exported from the 2026-07-25 baseline).

The run averaged 445 blk/s where the full mainnet sync managed 124, so
this slice is informative about curve shape and misleading about
magnitude. Raw records for the full run:
`artifacts/dcroxide-bench/m1/full-flush.jsonl`; corpus
`mainnet-full.corpus` (18.87 GB).

## Lever sweeps (`dcroxide-bench replay --dbcache/--metacache/--utxocache`)

ADR-0004's levers (b) read cache and (c) flush cadence. Lever (c) requires
`--utxocache` as well as `--metacache`: the overlay ceiling does not govern
cadence, since connecting a block flushes the UTXO cache and that forces a
durable metadata commit regardless.

| date | machine | dcroxide commit | design | outcome |
|---|---|---|---|---|
| 2026-08-09 | m1 | `a471db2` | 4 arms, `--metacache` only, no drift control | **Void.** The unchanged baseline measured 4,767 s and 6,780 s hours apart (total flush time 863 s vs 3,462 s) while the disk filled from 343G to 523G. Also measured the wrong knob: the 800 MiB arm produced *more* flushes (164) than the 100 MiB arm (128). |
| 2026-08-09 | m1 | `a471db2` | 5 arms with `--utxocache`, baseline first **and** last, each arm decomposed then deleted | **Throughput void, space clean.** Baselines 4,198 s vs 6,865 s — 1.64x drift against lever effects of 0.88x-1.12x, so no timing may be quoted. Space: fill 0.6450-0.6462 across all five arms (spread 0.0011) — neither lever moves packing; payload bit-identical at 6,069,302,981 bytes across arms; lever (c) raises free pages to 8.40 GiB against the baseline 6.17. |
| 2026-08-10 | m1 | `62f65f4` | `sweep`: 4 arms x 3 reps, full mainnet, `--addrindex`, interleaved + rotated, 1 warm-up discarded | **First defensible throughput result.** All arms disjoint from baseline (3866-3888 s): cache 8 GiB **5125-6294 s, 1.50x — 50% slower**; cadence 800/1200 **3424-3467 s, 0.89x**; both 3459-3511 s, 0.90x. Lever (b) reverses its microbenchmark premise; lever (c) gives 11%; the cache penalty vanishes when cadence is raised, confirming the interaction. Cold-start run 1 at 6,440 s prompted the warm-up discard. |
| 2026-08-11 | m1 | `49a53ef` | `sweep`: 5 arms x 3 reps, full mainnet, `--addrindex`, isolating the two operator-reachable knobs | **drift 1.00x.** `--utxocachemaxsize` alone carries the gain: utxo1200 **5490-6049 s, 0.88x — 12% faster**, utxo600 5608-6079 s, 0.93x, both **disjoint** from baseline 6332-6501 s. The page cache is correctly sized: db256 (1.01x) and db512 (1.00x) both **overlap** baseline, and 8192 was already 50% slower — so do not raise it, and nothing is gained by lowering it. |

Raw records: `artifacts/dcroxide-bench/m1/s2-*.jsonl` and `lever-sweep2.log`.

**Absolute seconds are not comparable across sweeps.** The identical
baseline configuration measured 3866-3888 s in the 2026-08-10 lever sweep
and 6332-6501 s in the 2026-08-11 operator sweep — 1.63x, same flags, same
corpus, same machine, one day apart, with comparable free disk at both
starts. Nothing inside a sweep can see that. It is why every arm is reported
relative to a baseline running in the same session, and why a row's seconds
should only ever be read against the other arms in its own row's run.

A valid throughput measurement needs alternating rather than sequential
arms, repetitions per configuration, and control for sustained-load state.
One pass of five hour-long arms cannot separate a 10% effect from a 64%
drift; the second sweep is the evidence for that, not a counterexample.
The third row above is that rig, built as `dcroxide-bench sweep`, and the
measurement it made possible. Raw records:
`artifacts/dcroxide-bench/m1/sweep-levers.jsonl`.

## Per-bucket decomposition (`dcroxide-bench redbstat --buckets`)

Scores ADR-0004's lever (d) per bucket: rows, payload, mean row size, rows
per page and the slack that implies. Read-only, so unlike `redbstat` alone
it does not perturb the store it measures.

| date | machine | dcroxide commit | store | result |
|---|---|---|---|---|
| 2026-08-10 | m1 | `98b0f37` | full `--addrindex` replay (reproduces the synced datadir) | `spendjournalv3` is **1 row/page** at a 2402 B mean row — 1,777.6 MiB of predicted slack, 75% of the 2.33 GiB predicted total, against 3.44 GiB measured. Its predicted footprint (4,298 MiB) matches ADR-0004's independently measured 4.1 GiB. Every other bucket packs at 10+ rows/page. redb gates `set_page_size` behind `cfg(any(fuzzing, test))`, so the page-size remedy needs a fork; a row under ~2040 B would fit two per page. |

> **The 2026-08-10 row's rows/page, predicted-footprint and predicted-slack
> cells are MODEL OUTPUT, refuted 2026-08-12.** This file is append-only, so
> the row stands as written; read it with the row below. The model divided
> the page size by the *mean* row. The bucket's median row is 1248 bytes, it
> packs 1.55 rows per leaf node rather than one, and its slack measures
> 1.536 GiB rather than 1.74. The estimate being close is why nobody checked
> it. The generating code has been deleted from `BucketStats`.
>
> **Rule adopted from it:** a bench tool may not print a modelled quantity
> beside measured ones without labelling it; no ADR may quote a modelled
> figure without a measured counterpart; every row here names its instrument.

| date | machine | dcroxide commit | store | result |
|---|---|---|---|---|
| 2026-08-12 | m1 | `23940c7` | standalone redb 2.6.3 probe at `spendjournalv3`'s real row lengths | **Measured, replacing the row above.** Tree 4,349,997,056 B over 2,643,223,854 B payload: slack **1,649,264,978 B (1.536 GiB)**, fill 0.6076, 708,672 leaf nodes for 1,100,392 rows = **1.55 rows/node**. Distribution: mean 2402, p50 1248, p99 13748, largest 66699 — 16.7% of rows exceed 4048 B and can never share a leaf. |

## Re-keying `spendjournalv3` (ADR-0004 lever (d), 2026-08-12)

Six layouts built at the bucket's real row lengths, same pseudo-random key
order and commit cadence, measured on `TableStats` (per-table
`fragmented_bytes` is intra-page slack; the database-wide figure is not).
Raw log: `artifacts/dcroxide-bench/m1/rekey2.log`.

| arm | tree bytes | payload | slack | fill | vs today |
|---|---:|---:|---:|---:|---:|
| **k=1, today** | **4,349,997,056** | 2,643,223,854 | 1,649,264,978 | 0.6076 | — |
| k=2 | 4,622,987,264 | 2,687,202,978 | 1,851,670,202 | 0.5813 | +0.254 GiB |
| k=4 | 4,608,131,072 | 2,770,796,214 | 1,729,445,984 | 0.6013 | +0.240 GiB |
| split >4048 into 2002 | 4,724,146,176 | 2,666,495,856 | 1,975,077,422 | 0.5644 | +0.348 GiB |
| split >4048 into 1300 | 4,542,418,944 | 2,680,449,684 | 1,771,169,188 | 0.5901 | +0.179 GiB |
| split >2002 into 2002 | 4,757,565,440 | 2,672,015,696 | 2,000,235,630 | 0.5616 | +0.380 GiB |

Today's layout is the smallest. Every split raises slack as well as payload,
so it packs worse rather than merely paying for extra keys.

**A voided first pass, recorded because it is this project's own documented
trap.** The probe initially read `WriteTransaction::stats()`, whose
`fragmented_bytes` includes `count_free_pages() * page_size`. Its headline
column therefore tracked a 6.44 GB file holding 2.09 GB of free pages, inside
which the tree and the free pool moved oppositely and cancelled: every arm
landed within 0.045% and the conclusion drawn was that re-keying was neutral
*and the slack was a model artifact*. Both were wrong. ADR-0004's findings
header names this exact trap as measurement trap number one.

## Payload, both implementations (2026-08-11)

`tools/dcrdstat` against dcrd and `dcroxide-bench redbstat --buckets`
against dcroxide, at matched index composition, both fed the identical
`mainnet-full.corpus`. The two tools define payload the same way — every
key/value pair, `len(key) + len(value)`, attributed by ffldb's four-byte
bucket-id prefix — so the columns are comparable rather than analogous.

Byte-exact, because the printed MiB columns round to 0.1 and the claim
here is one of *equality*:

| bucket | rows | dcrd bytes | dcroxide bytes | delta |
|---|---:|---:|---:|---:|
| `spendjournalv3` | 1,100,392 | 2,643,223,854 | 2,643,223,854 | 0 |
| `existsaddridx` | 66,494,886 | 1,662,372,150 | 1,662,372,150 | 0 |
| `gcsfilters` | 1,100,393 | 434,544,067 | 434,544,067 | 0 |
| `stakeblockundo` | 1,100,393 | 422,306,856 | 422,306,856 | 0 |
| `blockidxv3` | 1,100,393 | 255,544,549 | 255,544,549 | 0 |
| `ffldb-blockidx` | 1,100,393 | 250,889,604 | 250,889,604 | 0 |
| `ticketsinblock` | 1,100,393 | 186,711,336 | 186,711,336 | 0 |
| `hdrcmts` | 668,905 | 46,154,445 | 46,154,445 | 0 |
| `treasury` | 547,945 | 26,818,360 | 26,818,360 | 0 |
| `revokedtickets` | 97,514 | 3,998,074 | 3,998,074 | 0 |
| `livetickets` | 41,000 | 1,681,000 | 1,681,000 | 0 |
| `tspend` | 42 | 3,192 | 3,192 | 0 |
| `dbinfo` | 5 | 79 | 79 | 0 |
| `idxtips` | 2 | 75 | 75 | 0 |
| `stakedbinfo` | 1 | 23 | 23 | 0 |
| root (`<id 00000000>`) | 4 / 5 | 369 | 420 | **+51** |
| UTXO set | 1,849,182 / 1,849,177 | 127,657,896 | 135,054,499 | **+7,396,603** |
| **total** | | **6,061,905,929** | **6,069,302,583** | **+7,396,654** |

Fifteen buckets agree **to the byte**. Both exceptions are placement, not
content:

- The **root** difference is 51 B, which is `utxosetstate` — dcroxide keeps
  it in the metadata root (`chaindb.rs`, `UTXO_SET_STATE_KEY_NAME`) where
  dcrd keeps it in `utxodb`. 4 B bucket id + 12 B name + 32 B hash + a VLQ
  height is 51 B, so it is accounted exactly rather than approximately.
- The **UTXO set** difference is keying. dcrd's utxo keys are *not*
  unprefixed: every one carries a 2-byte key-set/version prefix
  (`utxoPrefixUtxoSet = {3,3}`), which dcroxide ports verbatim and then
  prepends ffldb's 4-byte bucket id on top. Net 4 B/row over 1,849,177 rows
  is 7,396,708 B predicted against 7,396,654 B observed for the whole
  store — a **54-byte residual on 6.06 GB**, 9 parts per billion, the
  remainder being the handful of housekeeping rows the two place
  differently. dcrd's five extra rows are its four `dbinfo` keys plus
  `utxosetstate`.

Two bytes of that four are pure redundancy on dcroxide's side — a key-set
discriminator inside a bucket that already discriminates key sets — worth
about 3.5 MiB with no parity cost. It is noted, not proposed.

**What this does and does not establish.** It measures equal row counts and
equal summed key+value lengths, not a content diff; a sum cannot see
offsetting differences. But twelve buckets agreeing simultaneously at byte
resolution, over stores built from the same block bytes, is not something
two different encodings produce. A digest over each side's sorted key/value
stream would convert it from overwhelming to proof, and both tools already
iterate every row.

## Write schedule (`dcroxide-bench indexcatchup`, 2026-08-12)

Closes the standing objection to the payload comparison above: dcrd's
66,494,886 exists-address rows were appended in one catch-up pass over a
finished database, where `replay --addrindex` interleaves them across 1.1M
block commits. Two arms at identical composition, order alternated
twophase / interleave / interleave / twophase, `mainnet-full.corpus`,
commit `73ac17e`, raw records in `artifacts/dcroxide-bench/m1/schedule-sweep.jsonl`.

| arm | live tree | fill | intra-page slack | leaf pages | branch pages | apparent |
|---|---:|---:|---:|---:|---:|---:|
| twophase (dcrd's schedule) | 10,475,610,112 | 0.650482 | 3,661,410,507 | 2,162,269 | 48,795 | 17,182,003,200 |
| interleave (shipped path) | 10,547,240,960 | 0.646171 | 3,731,920,971 | 2,184,891 | 43,722 | 17,182,003,200 |

Both reps of each arm are **byte-identical on every storage figure** — the
replay is deterministic — while wall times differ (two-phase replay 3,025.40
and 2,783.89 s; interleave 4,127.27 and 4,118.58). Payload is identical
across arms and scales, so catch-up builds exactly the index the interleaved
path builds.

**Result: the schedule is a second-order effect.** Building the index dcrd's
way makes dcroxide marginally *better* — live tree −0.68%, fill +0.004,
slack −1.9% — moving the structural multiple over payload from **1.738x to
1.726x**. Against goleveldb's 1.081x that closes about 1.8% of the excess.
The reviewer's mechanism is confirmed in sign (batch-building does pack
better) and refuted in magnitude (it was predicted first-order).

**Do not quote these two figures**, both of which point the other way:

- *Consumed bytes* (16,291,467,264 twophase against 15,574,482,944
  interleave, a 4.6% "win" for interleaving). Both files have **byte-identical
  length**; the entire 716,984,320 B difference is sparse tail, matching the
  hole difference exactly (890,535,936 against 1,607,520,256). It measures how
  far into the last region each run had written when it stopped.
- *Free pages* (6.233 against 6.169 GiB). With apparent length identical,
  free pages are the live-tree figure with the sign flipped —
  `allocated + free` reconstructs the file length to within ~30 KB in both
  arms — so it is not an independent measurement. Free pages have moved 4x at
  250k, 2.01x across five matched cache/cadence arms with the live tree
  pinned, and 55% between two ledger runs of the same arm; they are not a
  comparison metric.

**Bounded, not closed.** Only exists-address rows changed schedule —
`spendjournalv3`, the largest bucket, is written per block in both arms.
Neither arm was compacted, while dcrd was measured after its compactor had
quiesced. redb persists its allocator across a clean close, so phase 2 writes
into free pages phase 1 reserved, which is not goleveldb's situation. And
goleveldb's own schedule sensitivity — the premise of the objection — was
never measured, so the asymmetry is closed in one direction only.

**Timing, reported but not established:** two-phase finished ahead in both
replicates (61.0 and 56.5 min including 10.6 and 10.0 min of catch-up,
against 68.9 and 68.8). The ordering separates cleanly — the slowest
two-phase beat the fastest interleave by 7.8 min — but n=2, the order was
blocked rather than interleaved, the within-two-phase spread is 8.0%, no
drift was measured, and catch-up's block reads may have been served from a
page cache phase 1 warmed. It was not run through `sweep`, which exists for
exactly this comparison class. Treat as a hypothesis worth re-measuring.

### redb's file-growth ladder (why the 250k smoke result was void)

A 250,000-block pilot showed interleaving costing 32% more disk — the
opposite of the full-chain result — and it was an artifact worth recording,
because the same trap will catch the next small-corpus comparison.

redb grows in two regimes (`page_manager.rs` `grow()`): while the file holds
no full region it **doubles** the trailing region; above that it adds whole
4 GiB regions. `MAX_USABLE_REGION_SPACE` is 4 GiB and the page size is 4096,
both un-settable outside `cfg(test)`. File length is
`4096 + Σ (130 + 1,048,576) × 4096` per full region — a 1-page super header
plus a 130-page region header. So lengths land on a fixed ladder, verified
byte-exactly by a synthetic probe sharing nothing with dcroxide but the
engine:

- 250k two-phase: **2,156,408,832 B** (usable 257 × 2¹¹ pages)
- 250k interleave: **4,295,503,872 B** (clamped to one full region)
- full chain, both arms: **17,182,003,200 B** = exactly four full regions

The pilot's two arms sat on *consecutive rungs*, so its apparent, free-page
and consumed figures were decided by a single growth event rather than by the
schedule. What the crossing does show is directional — interleaving drove
peak allocator demand past 2.008 GiB where two-phase did not — and the two
unquantised figures, live tree and fill, agree in sign with the full chain at
both scales.

Note the ladder also bounds the full-chain comparison: equal apparent length
means both arms fell inside the same 4 GiB quantum, which pins the schedule's
effect on *file* size only to within one region.

## Script validation fan-out (2026-08-14)

`validate_items` spawned `runtime.NumCPU()*3` scoped OS threads per call,
copied from dcrd's goroutine count. A goroutine costs a couple of
microseconds; an OS thread costs tens. Measured on the 250k corpus with
`--addrindex`, arms alternated, two repetitions each, thread creation
sampled 120 s in:

| workers | wall | distinct TIDs / 10 s |
|---|---:|---:|
| `cores * 3` = 96 (baseline) | 458.5–460.2 s | 27,706–28,974 |
| **`cores` = 32 (adopted)** | **431.1–431.5 s** | 17,396–18,637 |
| `items / 32` capped at cores (rejected) | 488.4–490.3 s | 2,291–2,445 |

One worker per core is **6.1% faster** than the baseline on disjoint ranges,
with within-arm spread of 0.1–0.4%.

**The rejected arm is the instructive one.** Sizing workers by the batch cut
thread creation 12x — by far the biggest mechanical improvement of the three
— and ran **4.6% slower** on disjoint ranges, because a 100-item batch then
ran on three threads while 29 cores idled. The mechanism moved exactly as
intended and the outcome went the other way. Fan-out has to stay
proportional to the machine, not to the batch; the work-stealing loop is
what lets one worker per core suffice.

Two earlier churn figures in this file are superseded by these: a ">=276
threads/second" measurement taken early in the chain, where blocks are too
sparse to reach the 16-item parallel threshold, understated the steady-state
rate by roughly an order of magnitude.

## IBD profiling attempt (2026-08-14) — and why replay cannot proxy for it

ADR-0009 records the 2.2x IBD gap as attributed to commit shape "by a
progress-stall statistic — which records that progress halted, not what
halted it — and no profile exists." This attempted the profile. **It did not
identify the bottleneck, and the reason is the useful part.**

Two arms to mainnet tip, same binary (`b6d0c63`), same machine, sequential,
on an idle host; a first attempt was voided by ambient load and restarted.

| arm | wall | rate | in-window cores (800k–1.1M) |
|---|---:|---:|---:|
| `replay --addrindex` | 4,545 s | 242.1 blk/s | 2.86 |
| daemon syncing from a local dcrd | 5,568 s | 197.6 blk/s | 0.68 |

**These two arms are not comparable, and no flag makes them so.** The replay
validates every block. The daemon syncs headers first, finds mainnet's
assume-valid anchor, and skips connect validation for roughly 93% of the
chain. `--assumevalid` on the replay is accepted and does nothing below the
anchor: `is_assume_valid_ancestor` needs `assume_valid_node`, set only once
the chain has *seen* the anchor block, which a sequential replay reaches only
at the end. Measured directly — identical CPU with the flag set and unset,
2.86/2.89/2.68 cores against 2.66/2.86/2.65 over the same heights.

So every replay-versus-sync ratio here compares full validation against
almost none. **Withdrawn**: the 1.23x whole-chain and 1.62x in-window ratios
as measures of anything, "script validation is not the workload", the
57%-storage composition of the sync's hot thread, and "the documented 2.2x is
stale" (no dcrd arm was run).

**What survives, measured:**

- The daemon synced 1,100,392 blocks in **5,568 s (197.6 blk/s)** from a
  local dcrd on an idle host, exists-address index on.
- It runs at **0.68 cores** in the dense range on a 32-thread host. Not a
  ptrace artifact: the CPU-delta window excludes the sampling burst, and a
  ptrace-free run of the same arm measured 0.926 mean.
- The parallel validation pool spawns **≥276 OS threads per second** —
  `workers = cores × 3` (96 here) created and joined per `validate_items`
  call, gated at 16 items. A lower bound; 2 ms polling misses short-lived
  threads. Shared by both paths, so not the arm difference, but a real cost
  nobody had measured.

**A load-bearing ADR number is now in doubt.** ADR-0009 bounds what storage
can buy in IBD with "the matched `--addrindex` replay spent 863 s of 4,767 in
flushes", 18%, concluding at most 1.22x. That fraction comes from a run that
validates every block. The daemon skips most of that validation, so storage
is plausibly a *larger* share of daemon IBD than 18% — which would cut
against the ADR's own conclusion that a rework cannot be sold on IBD. Not
established: the sync-side composition figure that suggested it is one of the
withdrawals above.

**Two instrument failures, recorded so the next attempt skips them.** Leaf
sampling of the hottest thread is blind to the validation pool: `hot_tid`
ranks by a 1 s CPU delta and the pool's scoped threads live milliseconds, so
the persistent leader always wins. Sampling *all* threads inclusively fails
differently — 787 of 845 worker stacks came back at depth 0, caught
mid-creation or mid-teardown. 846 distinct TIDs appeared in 60 passes. To
profile the pool, sample it from inside the process rather than from outside.

**The experiment that would answer the question** is daemon against daemon —
dcroxide and dcrd both syncing from a common source, each doing its own real
work — which is what the 2026-07 campaign did and what the 2.2x came from.

## Daemon against daemon (2026-08-15) — the 2.2x is at most 1.29x

The experiment the previous section names as the one that would answer the
question. Both daemons sync mainnet genesis to tip from **one shared dcrd
server** on loopback, each doing its own real work, defaults intact
(`--norpc --nolisten --connect=127.0.0.1:19108 --nodnsseed`). Composition was
verified in both logs rather than assumed — exists-address index on, no
transaction index, on both sides — because losing that check is what cost the
2026-07 baseline its conclusion.

| arm | blocks | wall | rate | mean cores | mean loadavg |
|---|---:|---:|---:|---:|---:|
| dcrd 2.2.0-pre+452c1a6c3 | 1,100,392 | 3,220.5 s | **341.7 blk/s** | 1.50 | 2.45 |
| dcroxide `b6d0c63` | 1,100,392 | 4,153 s | **265.0 blk/s** | 0.76 | 4.62 |

**1.29x, against the 2.23x this repo has documented since 2026-07.** Both
sides moved: dcroxide 124 → 265 blk/s (2.14x), dcrd 276 → 342 (1.24x). That
dcrd improved too is the tell that part of the change is the harness — the
2026-07 campaign ran the two nodes syncing *from each other*, contending for
one machine, where these ran sequentially against a quiet server. That
inflated both arms then, and inflated the ratio between them.

**Read this as a bound, not a point estimate.** Four reasons, recorded so the
next run tightens them instead of rediscovering them:

- **The arms were neither simultaneous nor matched.** dcroxide ran
  03:32–04:41, dcrd 16:37–17:31, about 12 h apart. Same machine, same server
  binary, same corpus — not the same ambient conditions.
- **Mean loadavg differed, 4.62 against 2.45.** Whether that is ambient or
  self-inflicted is unresolved; see below. If ambient, it can only have slowed
  dcroxide, which makes 1.29x an upper bound on the gap.
- **n=1 per arm.** No repetition, so no dispersion estimate.
- **The dcroxide binary predates the fan-out fix.** Built 2026-08-13 20:14 at
  `b6d0c63`; `c091b46` (one validation worker per core, 6.1% on the replay
  corpus) is not in it. The current tree should be at or above 265 blk/s.

**Load average is confounded with the thing being measured.** Linux counts
uninterruptible-sleep tasks in loadavg, so a node blocked on disk shows high
load at low CPU with no other tenant on the box. dcroxide averaged 4.62 load
at 0.76 cores — roughly 3.9 tasks not explained by its own CPU. Two readings,
which this run does not separate: another workload was present (the confound
that voided the first attempt at this experiment), or dcroxide's own threads
were parked in D-state on redb writes. The second reading is precisely the
storage-bound signature the 2026-08-14 profiling attempt failed to capture, so
it is worth separating deliberately — sample per-process D-state counts
alongside CPU.

Within the dcroxide arm, load and height are collinear: every sample below
block 699k sits at load ≤3.0 and every sample above 688k above it. So this run
cannot attribute its own slowdown to either one. That is a design fault in the
harness, recorded as such, not a result.

**Storage at tip, same pair, apparent size** (the rule adopted 2026-08-12):

| | apparent bytes | GiB |
|---|---:|---:|
| dcroxide | 36,055,044,196 | 33.58 |
| dcrd | 25,433,938,876 | 23.69 |

1.42x, against 1.35x in the 2026-07 row whose composition was never recorded.
dcrd is flat across the year (23.73 → 23.69 GiB); dcroxide grew 32.06 → 33.58.
redb's apparent length is a high-water mark, so this figure is the honest
operator-facing number and an overstatement of live data at the same time.

**What this supersedes.** Every "~2.2x slower than dcrd at IBD" in this repo —
README, PARITY, SECURITY, the project brief, ADR-0004, ADR-0005, ADR-0009 —
descends from that single 2026-07 row. The row is not withdrawn; it was
measured. It is superseded as a description of the port's current standing.
The gap is 1.29x or better, and dcroxide reaches it at roughly half dcrd's
CPU — which relocates the open question from "how much compute is missing" to
"what is the node blocked on".

**Harness bug worth recording.** The first dcrd arm died 30 s in: its tip
detector matched `height [0-9]+`, which also matches the peer's advertised
`Syncing headers to block height 1100392 from peer`. The replacement pattern
then assumed dcrd's daemon log ends in a timestamp — that is `addblock`'s
format, not the daemon's. Both daemons write `…, height N, progress P%`, and
the original `daemon-vs.sh` pattern (`height [0-9]+, progress`) was correct for
both all along. dcrd's wall time above is therefore recovered from its own log
timestamps, process start to last block-progress line, not from the harness
clock.

Raw: `artifacts/dcroxide-bench/m1/daemon-vs/` — `rox.log`, `rox-cpu-VALID.txt`,
`dcrd2.log`, `dcrd-cpu.txt`, `server.log`, `server2.log`.

## Candidate engine benchmark (ADR-0009 prerequisite 4, 2026-08-13)

Every arm is handed the **identical journal**: what dcroxide's engine was
actually given, batch for batch, captured by `replay --writelog` and
replayed with one atomic durable commit per dcroxide flush. 102,686,859
write records in 130 batches, producing 76,301,856 rows and 6,069,302,955 B
of payload. Insertion order therefore cannot decide the result — a sorted
bulk load is an LSM's best case and a copy-on-write B-tree's worst, and
neither is what the engine sees.

Compression off everywhere (fjall built `default-features = false`, so LZ4
is absent rather than unconfigured; goleveldb with dcrd's own
`opt.NoCompression`). Sizes are **apparent**, and LSM arms are measured
after compaction quiesces — an engine measured mid-compaction is not
comparable to one that has settled.

| engine | settled | over payload | peak | load |
|---|---:|---:|---:|---:|
| **fjall 3.1.8** | 6,227,582,792 | **1.026x** | 1.519x | 219 s |
| goleveldb (dcrd's), *oracle* | 6,421,155,136 | **1.058x** | 1.130x | 485 s |
| redb 4.1.0 | 15,568,752,640 | 2.565x | 2.831x | 3,842 s |
| redb 2.6.3 (incumbent) | 17,182,003,200 | 2.831x | 2.831x | 4,884 s |

All four hold identical content: 76,301,856 rows, 6,069,302,955 payload
bytes, every arm.

**The rig reproduces a known answer.** The redb 2.6.3 control landed at live
tree 10,548,097,024 against the measured baseline's 10,547,240,960 (0.008%,
abort threshold 2%) and fill 0.6461 against 0.6462 (0.0001, threshold
0.005). That check was pre-registered: no candidate number may be quoted
from a rig that cannot reproduce a known answer.

**The oracle validates the target.** goleveldb, handed our journal, lands at
1.058x — inside the pre-registered 1.05–1.12x band. So dcrd's 1.081x is a
property of the engine class, not of dcrd's write schedule. Had it landed
outside, the pre-registration made the answer "stay on redb" regardless of
what any candidate did.

The first goleveldb run read 1.2465x and was **voided**: it measured the
store as closed, with L0 files outstanding, where dcrd's reference figure
was taken after its compactor had quiesced. The tell was `settled` exceeding
`peak`, which is impossible for a store that has settled.

### Reads (gate B: non-regression, threshold ≤1.5x redb)

| | 200k point reads | per read | full scan |
|---|---:|---:|---:|
| redb 2.6.3 | 20.85 s | 104.26 µs | 93.4 s |
| fjall 3.1.8 | 5.96 s | **29.80 µs** | **11.2 s** |

0.29x and 0.12x against a 1.5x ceiling. Both returned 200,000 hits with
identical value bytes. Caveat: not true-cold — dropping caches needs root,
so each arm was preceded by streaming the 18.9 GB block corpus through the
page cache, which is crude but symmetric. Part of fjall's advantage is that
a 5.8 GiB store survives caching better than a 16.0 GiB one, which
conflates engine speed with store size; store size is the finding, so the
gain is real even though the attribution is mixed.

### Crash safety (gate C: pass/fail, no trade against size)

`kill -9` on the process group mid-load, three times per engine at
different points. Each batch writes a marker key **inside its own atomic
unit**, so the store's claim about itself must match its contents exactly.

| control (redb 2.6.3) | claims | expected rows | missing | wrong | leaked | verdict |
|---|---:|---:|---:|---:|---:|---|
| kill @25s | batch 9 | 3,647,531 | 0 | 0 | 0 | PASS |
| kill @60s | batch 15 | 5,705,334 | 0 | 0 | 0 | PASS |
| kill @110s | batch 22 | 7,817,058 | 0 | 0 | 0 | PASS |

The first row is the one that shows the test works: 10 batches had been
committed but the store claims 9, so redb discarded an incomplete
transaction rather than half-applying it.

Both engines, re-run 2026-08-13 with a sampled verifier (below). Every arm
passes:

| engine | kill | claims | rows checked | missing | wrong | leaked |
|---|---|---:|---:|---:|---:|---:|
| redb 2.6.3 | 25 s | batch 14 | 517,918 | 0 | 0 | 0 |
| redb 2.6.3 | 60 s | batch 25 | 636,598 | 0 | 0 | 0 |
| redb 2.6.3 | 110 s | batch 38 | 1,121,670 | 0 | 0 | 0 |
| fjall 3.1.8 | 25 s | batch 19 | 500,254 | 0 | 0 | 0 |
| fjall 3.1.8 | 60 s | batch 104 | 1,467,647 | 0 | 0 | 0 |
| fjall 3.1.8 | 110 s | batch 129 | 1,844,689 | 0 | 0 | 0 |

fjall's write throughput shows here too: the 110 s kill caught it after all
130 batches, where redb had reached 38.

**The verifier is sampled, and the reason is worth recording.** The first
version reconstructed every expected row in a hash map: over an hour per
arm, ~5 GB resident, and it drove the host into swap. The property under
test is per-key, so a deterministic 1-in-64 sample keyed on an FNV hash of
the key answers it at the same confidence — validated by reproducing the
exhaustive verifier's verdict on the redb control in **3.5 s against 76
minutes**. Two things stay exhaustive because sampling is the wrong tool for
them: every row of the *boundary* batch, since a torn commit tears exactly
there, and every row the *next* batch would have written, since that is the
leaked-data direction a lost-data-only check misses. Both engines were
re-run rather than only fjall — comparing arms measured with different
instruments is the confound that has voided three measurements here.

One redb arm first reported FAIL and was **a harness bug, not an engine
result**: `DatabaseAlreadyOpen`, because the previous iteration's loader
still held the lock. Re-run with a wait-for-exit, it passes. Recorded
because a crash-test failure that turns out to be the rig is exactly the
kind of thing that gets quietly dropped.

None of this changes the gate-C verdict, which fails on the
open-upstream-issue condition that no `kill -9` can exercise.

**What this test does not cover.** `kill -9` is process death, not power
loss, and not a write failure. The arms commit with
`PersistMode::SyncData`, so the data reached the device — but fjall's
*default* is `PersistMode::Buffer`, which returns `Ok` with no fsync at all.
Adopting fjall would mean enforcing durability in the wrapper rather than
inheriting it, which inverts ADR-0004's durable-defaults rule.

**Two open upstream issues decide gate C, and no kill test reaches them.**
fjall #308 (open, filed against 3.1.8) has `WriteBatch::commit()` return
`Ok` for a batch that does not survive restart, when an earlier journal
*write failure* left an unterminated record and recovery truncates from it.
fjall #311 (open) has no strict recovery mode, so mid-journal corruption is
indistinguishable from a torn tail and presents as silent truncation. Both
land on the cross-bucket atomicity `process.rs:908-916` depends on, and
neither is reachable by killing a healthy process.

### The upgrade arm, taken

redb 4.1.0 was adopted on 2026-08-13 (`redb = "4"` in
`dcroxide-database`). It holds the identical content in 9.4% less space and
loaded 21% faster on this journal, and a 250,000-block replay reproduces the
2.6.3 tree exactly — live tree 1.355 GiB, fill 0.6373, both versions, to
four decimals — so the gain is free-page retention and not packing. The
1.738x structural figure is unchanged, which is why this is a dependency
bump rather than an answer to ADR-0009.

The on-disk format changed with it: 4.x reads only file format 3 and refuses
a 2.x directory with a typed error rather than misreading it. Data
directories written before that date must be re-synced.

### Excluded candidates, with the reason recorded

- **rocksdb** — the build fails on this machine even with g++ 16.2.1 and 32
  cores, because bindgen needs libclang. Adopting it means every build host
  on three OS tiers acquires an LLVM dependency, not merely a C++ compiler,
  which is more than ADR-0004's weighed decision priced.
- **LMDB / heed** — best measured case ~1.30–1.35x, below the adopt
  threshold before it starts; structural floor of 1.463x on `existsaddridx`
  even with a perfectly sorted `MDB_APPEND` load. No page checksums, on a
  node that ingests attacker-supplied blocks.
- **sled 0.34.7** — measured at 3.44x against redb's 2.07x on the same host:
  worse than the engine it would replace. No range scans inside a
  transaction (issue #1143, open since 2020), which dcroxide's cursors
  require. Last release 2021.

## Compaction (`redb::Database::compact`)

Never called in dcroxide; measured here because ADR-0004 named free pages
as the leading term and this is the only mechanism that returns them.

| date | machine | store | result |
|---|---|---|---|
| 2026-08-09 | m1 | 2026-07 mainnet datadir (14.483 GiB, 4.69 GiB free pages) | 598.5 s to recover **0.12 GiB**; a second pass returns `false` |
| 2026-08-11 | m1 | full `--addrindex` replay (14.505 GiB consumed, 6.17 GiB free pages) | 137.9 s to recover **2.453 GiB consumed** (3.950 GiB apparent). Free pages 6.17 → 2.22 GiB. `live_tree_bytes` and `fill_ratio` (0.646166) **unchanged to the digit**; every bucket's payload identical afterwards. |

The two disagree by 20x on the same chain at the same composition, and the
disagreement is the finding: `compact()` relocates pages toward the front
and truncates, so its yield depends on where free pages happen to sit, not
on how many there are. Neither figure is characteristic. It never repacks —
fill is untouched in both runs — which is consistent with ADR-0004's
reading of the mechanism.

**Measurement trap: `metadata.redb` is sparse** — and the obvious reading of
that is wrong, so read this before quoting a disk figure.

The replay store's apparent size is 17,182,003,200 B while it consumes
15,574,482,944 — a 1.497 GiB hole running to EOF. dcrd's side errs the other
way: its files round *up* to 4 KiB blocks, consuming 6,552,084,480 against
6,545,168,267 apparent, a dense 1.001x.

The trap is that **`st_blocks` is not the conservative choice here.** redb
extends its file with a bare `set_len` and never calls `fallocate` or punches
a hole, so the sparse tail is simply the region no page has been written into
*yet*. It only ever shrinks: writing scattered pages into a copy of the 250k
store left the length bit-identical while consumed rose 398 MiB. So
`st_blocks` is a high-water mark of what a particular run happened to touch
before it stopped, not a steady-state footprint, and an operator's `du` walks
toward `st_size` as the node keeps running.

**Quote apparent length (or the live tree) for redb; either is fine for
dcrd.** The corollary for the compaction rows above: the honest saving is the
**3.950 GiB** the file's claim shrank by, not the 2.453 GiB the filesystem
handed back that day — the uncompacted file would have gone on materialising
its tail. Two figures from the same run pointing opposite ways is the signal
that one of them is not a property of the store: see the write-schedule rows
below, where the entire consumed difference between two byte-identical-length
files is sparse tail.

## D-state decomposition (2026-08-15) — the commit-shape attribution, measured

The 2026-08-15 daemon-against-daemon row left one thing unresolved: dcroxide
averaged 4.62 load at 0.76 cores, and Linux counts uninterruptible tasks in
the load average, so that gap was either other tenants on the box or the port
blocking on its own storage. Only the second reading is evidence for the
commit-shape attribution ADR-0004 has carried since 2026-07 on a
progress-stall statistic. **This separates them, and the attribution survives
— by a mechanism the hypothesis had wrong.**

Both daemons syncing mainnet from one shared dcrd server, back to back on a
quiet box (load 0.55 at launch), server chain pre-read into page cache before
*each* arm, per-thread scheduler states sampled at 10 Hz and the whole task
table walked at 1 Hz. dcroxide built at `8b27d20`, so unlike the earlier row
the fan-out fix is included.

**Mean tasks during block sync** (load average counts R + D):

| arm | own R | own D | kernel threads | server | other userspace | loadavg |
|---|---:|---:|---:|---:|---:|---:|
| dcroxide | 0.77 | 0.38 | **1.64** | 0.08 | 1.72 | 5.54 |
| dcrd | 1.86 | 0.12 | **0.14** | 0.10 | 1.23 | 2.62 |

**The port's own threads are not the blocked ones.** At 0.38 they are far too
few to explain the gap. What separates the two daemons is kernel-side storage
work — 1.64 against 0.14, **11.7x** — overwhelmingly `dmcrypt_write` (1,002
blocked samples against 23). Bucketing kernel threads separately is what makes
this visible: charging them to "ambient", which is the obvious design, shows
dcroxide's own D at 0.38, concludes "not self-inflicted", and is wrong.

**It is the write shape, not the write volume:**

| | wrote | rate | datadir | write amp | read | dm-crypt D per GiB |
|---|---:|---:|---:|---:|---:|---:|
| dcroxide | 331.29 GiB | 70.4 MiB/s | 31.58 GiB | 10.5x | 42.48 GiB | **3.0** |
| dcrd | 382.64 GiB | 122.4 MiB/s | 23.69 GiB | 16.2x | 0.43 GiB | **0.1** |

dcrd writes **1.16x more bytes at 1.74x the rate and blocks 30x less per
GiB**. The LSM has the *higher* write amplification of the two and still costs
less, because compaction is sequential and off the write path; the
copy-on-write B-tree writes fewer bytes synchronously, one fsync per commit.
dcroxide also reads **99x** more during ingest (42.48 GiB against 0.43) — the
B-tree fetching pages in order to copy them.

**The wait channels name the mechanism.** dcroxide's blocked threads park in
`folio_wait_bit_common` (729 samples, page writeback), `handle_reserve_ticket`
(113, btrfs metadata reservation), `wait_for_commit` (101, transaction commit)
and `btrfs_btree_wait_writeback_range` (27). dcrd's park in
`folio_wait_bit_common` (159) and `barrier_all_devices` (95).

So ADR-0004's hypothesis — "goleveldb's LSM commit is O(dirty) with background
compaction, while redb is a copy-on-write B-tree with no background work, so
commit cost tracks the size of the tree" — is now measured rather than
inferred from a stall statistic. **The correction to it is that the cost lands
mostly outside the process**, in kernel writeback and dm-crypt, which is why
every profiler pointed at the port's own threads has failed to find it.

**Two instruments are blind to this workload, recorded so the next attempt
skips them.** `/proc/stat`'s `procs_blocked` counts only tasks in
`io_schedule()`: three threads in a write+fsync loop measured D=2.93 in a task
walk against `procs_blocked` = 1.54, *lower than the target's own count*, so
any "ambient = procs_blocked − target" residual goes negative. Delay
accounting fails the same way and for the same reason — with
`kernel.task_delayacct=1` confirmed live (O_DIRECT reads logged 4.44 s of
blkio delay in 6 s wall), dcroxide's whole sync logged **0.000** blkio ticks
per sample. btrfs fsync blocking is `TASK_UNINTERRUPTIBLE` and counted by the
load average, but it is not block-device wait, so both cheap counters report
nothing. Only a task-state walk sees it.

**Throughput, and why it does not supersede the 1.29x row.** This run measured
dcroxide 4,821 s (228.2 blk/s) against dcrd 3,201 s (343.8), a ratio of
**1.51x**. dcrd reproduced to 0.6% across the two runs (343.8 against 341.7)
while dcroxide fell 14% (265.0 to 228.2). The sampler is not the cause — it
cost 0.06% of the box. The cause is in the data: ambient load was higher in
every height band than the earlier run, with a browser active during the
dcroxide arm (`ThreadPoolForeg`, 740 blocked samples against 10 in the dcrd
arm). **Both runs carried more ambient during the dcroxide arm, so both ratios
are upper bounds and 1.29x remains the tighter one.** The row above stands.

**Caveats.** Thread-state counts are not strictly commensurable between a Rust
thread-per-operation process and a Go runtime that parks an M and may start
another, which is why the argument above rests on kernel-side and per-GiB
evidence rather than on the own-thread comparison. Ambient was not matched
between arms. n=1 per arm.

Raw: `artifacts/dcroxide-bench/m1/dstate/` — `rox.jsonl`, `dcrd.jsonl` (34,083
and 31,979 samples), `rox.log`, `dcrd.log`, `run.log`. Sampler and harness:
`artifacts/dcroxide-bench/m1/dsample.py`, `dstate.sh`.

### The wall-time share, from the same samples (2026-08-15)

The section above measured the mechanism but left the number ADR-0009 actually
needs — the *share* of sync wall time storage costs. It is in the same
samples. **It is 34.6%, and it accounts for essentially the whole gap to
dcrd.**

First, that the D state is storage and not something else: **97.8%** of
dcroxide's blocked-thread wait channels are storage symbols (`folio_wait_bit`,
`handle_reserve_ticket`, `wait_for_commit`, `btrfs_*`), the remainder being 15
samples of `exit_mm` and 5 of `__vm_munmap`. For dcrd it is 100%.

Second, and this is what makes it a wall-time figure rather than an occupancy
one: **when dcroxide blocks on storage, 99.4% of the time it has zero runnable
threads.** The process is not merely blocking a worker, it is stopped. Only
0.2% of samples have two or more threads blocked, so the storage path is
effectively serialized — one thread waits and nothing else proceeds. dcrd
blocks too, but keeps working through it (mean 1.465 runnable threads while
blocked) and is fully stalled for only 0.9% of its run.

| | ≥1 own thread blocked | fully stalled (nothing runnable) |
|---|---:|---:|
| dcroxide | 34.8% | **34.6%** |
| dcrd | 11.3% | **0.9%** |

**The stall tracks tree growth**, which is the copy-on-write prediction this
ADR set has carried since 2026-07, now with a curve rather than an assertion:

| height band | dcroxide stalled | dcrd stalled |
|---|---:|---:|
| 0–300,000 | 1.3% | 1.8% |
| 300,000–600,000 | 1.7% | 0.4% |
| 600,000–900,000 | 29.2% | 0.7% |
| 900,000–1,100,392 | **50.9%** | 1.0% |

By the last third of the chain dcroxide spends **half its wall time completely
stopped**. dcrd stays near 1% throughout.

**The counterfactual: the stall is the gap.** Removing dcroxide's 1,646 s of
stall puts it at **346.6 blk/s**; giving dcrd the same treatment puts it at
**346.9**. They converge within 0.1%. The observed ratio for this run is
1.506x and the stall alone predicts 1.52x, so outside of storage stalls the
two implementations process blocks at the same rate — which is what should be
expected, since both skip the same validation under the same assume-valid
anchor.

**It cross-checks against the other run of the same day.** At 265.0 blk/s
against that same ~346 ceiling, the earlier arm implies a ~23% stall share and
a 1.31x gap, against the 1.29x actually measured. Both runs are internally
consistent: in each, the gap equals the stall. **So the share is 23–35%
depending on I/O contention** — this run carried more ambient, which lengthens
storage waits and inflates the figure.

**This overturns the bound ADR-0009 reasons from.** That ADR concluded a
rework "cannot be sold on IBD" from the replay's 863 s of 4,767 in flushes,
18%, giving at most 1.22x. Both halves are wrong for a daemon: the replay
validates every block where the daemon skips ~93%, and the measured daemon
figure is 23–35% with a counterfactual of **~1.5x**.

**What the counterfactual does and does not license.** It assumes the stall is
removable. dcrd demonstrates the *work* can be overlapped with compute — it is
not evidence that redb can overlap it. The near-total absence of ≥2 blocked
threads says dcroxide's storage path is serialized, so this points at the
commit structure — a synchronous fsync on the critical path — as much as at
the engine. A faster engine that stayed synchronous would collect less of the
1.5x than an asynchronous or background-committed one, possibly much less.
That distinction is the difference between "swap the engine" and "restructure
the commit", and this measurement does not choose between them.

Derived from `rox.jsonl` / `dcrd.jsonl` in the run directory above; no new run.

### Correction, 2026-08-16 — the 34.6% is measured, its attribution is not

The section above ends "the stall is the entire gap" and derives a ~1.5x prize
from it. **The arithmetic stands and the attribution does not.** The
correction matters because the prize is what ADR-0009's engine decision now
rests on.

**What the instrument can and cannot see.** `dsample.py` records per-thread
scheduler state and the kernel wait channel (`wchan`). It records no user
stacks. So "storage-blocked" means *a thread is parked in an uninterruptible
wait on a btrfs symbol* — it does **not** mean *inside `DbCache::flush`*.
Every statement that the stall is the metadata commit is an inference from
that, not a measurement of it. This is the same species of error as the 18%
figure it replaced: a number measured on one thing and read as another.

**What the stall is actually shaped like.** Decomposing the 33,421 block-sync
samples into contiguous stalled episodes:

| | strict | ≤2-sample gap tolerated |
|---|---:|---:|
| episodes | 2,985 | 1,409 |
| median episode | 0.10 s | 0.30 s |
| longest | 10.0 s | 36.6 s |
| episodes ≥2 s | 329, holding **63%** of stall time | 305, holding **86%** |
| sub-2 s events | 2,656, holding 37% | 1,104, holding 14% |

The multi-second episodes carry most of the time and their *count* (305–329)
is the right order for a flush population, so the flush-shaped reading
survives for the bulk of it. But **14–37% of the stall sits in one to two
thousand sub-second events, roughly one per 400 blocks**, which is not a
flush cadence and which moving the commit off the critical path would not
touch.

**The one direct flush measurement available points lower.** dcroxide's own
flush observer over the full mainnet replay: 122 flushes totalling **260.9 s
of a 3,271 s run — 8.0% of wall**, longest single flush 4.86 s. A replay is
not a daemon (it validates every block where the daemon skips ~93% under
assume-valid), so 8.0% does not transfer any more than 18% did. But the
distance between 8% and 34.6% is unexplained, and it is exactly the quantity
Option A's value depends on.

> **Trap in that file:** `elapsed_ms` is flush *plus* the stats walk, and the
> stats walk totals 442.5 s against the flush's 260.9 s. Summing `elapsed_ms`
> gives 703.4 s and reads as a 21.5% flush share — nearly triple the truth.
> Use `flush_ms`. The ledger already records the same trap in the 2026-08-08
> row, where an unseparated stats walk read as a 17.2x commit slowdown.

**What is withdrawn:** "the stall is the entire gap", "outside storage stalls
the two implementations process blocks at the same rate", and the ~1.5x prize
as a figure Option A can be expected to collect. **What stands:** the 34.6%
fully-stalled measurement itself, the 11.7x kernel-side ratio, the 30x-per-GiB
blocking ratio, and the write-shape conclusion — none of which depend on
attributing the stall to a call site.

**The experiment that settles it is cheap and has not been run:** sync the
daemon with the flush observer enabled and compare summed `flush_ms` against
the sampled stall over the same window. dcroxide already has the instrument;
the D-state run simply did not turn it on. Until that exists, treat the share
of IBD that a background committer can recover as bounded above by 34.6% and
below by nothing.

## Flush-observer attribution (2026-08-16) — the stall IS the commit, and 34.6% was a weighting artifact

The correction above says the recoverable share is "bounded above by 34.6% and
below by nothing" and names the experiment that would fix that: a daemon sync
with dcroxide's own flush observer enabled. This is that run. **It attributes
the stall, and it also finds that both of the figures either side of the
argument were wrong.**

Same harness as the D-state run — one shared dcrd server, page cache
pre-warmed, quiet box (load 1.14 at launch) — with `DCROXIDE_DB_FLUSHLOG`
recording every metadata flush's end instant and duration, and the sampler now
stamping absolute time so the two can be aligned. Stats sampling deliberately
left off: redb's `stats()` cost 442.5 s against the flushes' own 260.9 s in the
replay, and would have swamped the quantity being measured.

**1,100,392 blocks in 4,741 s (232.1 blk/s), 130 flushes.** The D-state run
managed 228.2, so the two agree to 1.7%.

### The attribution, which is what the run was for

| gap treatment | stall, % of wall | **of that stall, inside a flush** | commit, % of wall |
|---|---:|---:|---:|
| count-weighted | 18.7% | **89.8%** | 16.8% |
| 0.2 s cap | 21.4% | **91.4%** | 19.6% |
| 1 s cap | 32.3% | **95.3%** | 30.8% |
| 2 s cap | 39.2% | **96.6%** | 37.9% |
| gaps fully attributed | 48.1% | **97.8%** | 47.0% |

**The size of the stall depends on weighting; the attribution does not.**
Between 90% and 98% of the time the node spends fully stalled falls inside a
metadata-flush window, on every treatment. Corroborated without any weighting
at all: during a flush window the process is fully stalled 40.9% of the time
and runs at 0.55 cores; outside one it is stalled 3.2% and runs at 1.38.

So **the 2026-08-15 attribution was substantially right and the 2026-08-16
correction over-withdrew it.** The sub-second events that correction worried
about are real and are 2–10% of the stall, not the third to a half it
suggested. That correction was written from a review summary that had not been
checked against the data; the same species of error it was correcting.

### 34.6% was a count-weighting artifact

The sampler is starved during exactly the periods it measures — median
interval 100 ms, but gaps to 9 s, and those gaps sit inside stalls. Counting
samples therefore under-weights the stalled time. Weighting each sample by the
interval it represents:

| run | count-weighted | gaps fully attributed |
|---|---:|---:|
| D-state (2026-08-15, browser active) | 34.6% | **51.1%** |
| flush observer (2026-08-16, quiet box) | 18.6% | **48.1%** |

**The two runs agree at 48–51%.** Count-weighted they read 34.6% and 18.6%,
and the apparent halving between them — which looked like ambient load — is
the instrument, not the node. Quote the time-weighted figure, and quote it as
a band: the gap-cap column is the honest uncertainty, not a number to pick
from.

### The counterfactual is too generous to quote

Removing only the commit stall projects **373.7 blk/s — faster than dcrd's
343.8.** A counterfactual that beats the reference implementation is evidence
the model is wrong, not that the prize is large. It assumes the stalled time
*vanishes*, when a flush is not pure blocking: median flush **26.9 s** (mean
24.4, max 79.5, 61 of 130 over 30 s), windows occupying 59.4% of wall, and the
process stalled for only part of that. The rest is CPU work building the
transaction, which a background committer **relocates rather than removes** —
it can overlap with validation on another core, but it still has to happen.

So: what a background committer can recover is the stalled fraction, 48% of
wall at the upper end, *minus* whatever cannot overlap. The honest statement is
that it is large and worth pursuing, and that no arithmetic here yields a
defensible multiplier.

### Two weaknesses in the method, recorded rather than buried

- **Attribution is by time overlap, not by stack.** A reader blocked on the
  cache mutex while a flush runs is counted as flush-attributed. That is the
  right accounting for "would moving the commit off the critical path help",
  and it is not a profile. A thread blocked on a block-file write *inside* a
  flush window is also counted to the flush.
- **The sampler's starvation is correlated with the signal**, which is why the
  stall figure moves 18.7% → 48.1% across gap treatments. The gap-cap column
  exists to expose that rather than hide it behind a point estimate. A sampler
  that could not be starved — sampling from inside the process, or a fixed
  wall-clock schedule that records its own misses — would close it.

Raw: `artifacts/dcroxide-bench/m1/flushobs/` — `rox.jsonl` (26,391 samples),
`flush.jsonl` (130 records), `rox.log`, `run.log`. Harness `flushobs.sh`,
sampler `dsample.py`.

## Background commit (2026-08-16) — implemented, measured, and NOT shipped

ADR-0009's remaining question was whether the metadata commit could be moved
off the block-connection thread to recover the 48% of wall time the node
spends fully stalled in it. **It was built, measured, and reverted: it is
9.5% slower, and the reason is structural rather than a bug in the
implementation.**

The design: a committer thread per flush, holding an `Arc<DbInner>` so the
database cannot be destroyed mid-commit; the previous commit joined before the
next begins, which gives backpressure (at most one in flight) and flush
ordering for free; `Database::flush`/`close` drain first and stay synchronous
to durability; a background failure latches fatal and is reported to the next
caller. It built clean, passed the full suite, and synced mainnet to tip
without error.

| | baseline (synchronous commit) | background commit |
|---|---:|---:|
| rate | **232.1 blk/s** | **210.0 blk/s** |
| wall | 4,741 s | 5,241 s |
| fully stalled | 48.1% | 53.7% |
| flushes | 130 | 132 |
| flush duty cycle | 68% of wall | 71% |
| mean ambient load | 6.83 | 8.57 |

**Why it cannot work, normalised so the load difference does not decide it.**
Stall per second of commit work: **0.708 s baseline against 0.757 s
backgrounded.** The background version hid *less* commit time than the
synchronous one, on a measure that divides out the differing flush totals.

The premise was that the process sits idle during a commit and could be doing
other work. That is only about 30% true: **flushes occupy 68–71% of block-sync
wall time in both runs.** Commits are nearly back-to-back, not punctual events
with gaps between them. redb permits exactly one writer and holds its write
lock across the fsync, so a second commit can never overlap the first — the
next flush trigger fires while the previous commit is still running, and the
connection thread then blocks at the *drain* instead of at the commit. Moving
where it waits does not reduce how long it waits, and the in-flight window
lets the overlay accumulate, so the following batch is larger.

**What this means for the engine question.** The 48% stall is real and it is
the metadata commit (90–98%, measured the same day). But it is not recoverable
by restructuring *when* the commit runs, because the commits are already
saturating the available time and cannot be parallelised against each other by
construction. **The remaining lever is the cost of a commit, not its
schedule** — which is the write-shape finding: dcroxide writes fewer bytes
than dcrd and blocks 30x more per GiB, because scattered copy-on-write
overwrites on btrfs are close to the worst case for that stack, where an LSM's
sequential compaction is close to the best.

So ADR-0009's question narrows to the engine and the write shape, and the
"restructure the commit" branch is closed by measurement rather than left
open. The ~1.5x that an earlier counterfactual attached to this is not
available from scheduling.

**What was kept.** The Phase 1 work this was built on top of — releasing the
cache lock across the commit, the `compact` barrier, and the split flush
accounting — is committed and stands on its own: it unblocks readers for the
26.9 s median flush, and it costs nothing. Only the handoff was reverted.

Raw: `artifacts/dcroxide-bench/m1/phase2/` against
`artifacts/dcroxide-bench/m1/flushobs/`, same harness, same server, same
machine, hours apart.

## Write shape: redb 4.1.0 against fjall 3.1.8 (2026-08-17)

The background-commit result closed rescheduling as a lever and left the
*cost* of a commit as the only one. This measures it, with the engine as the
only variable: both engines replay the **identical journal** dcroxide's
storage layer was handed — 130 batches, 102,686,859 write records, 6.07 GB of
payload, captured by `replay --writelog` — with one durable commit per batch.
fjall is forced to `PersistMode::SyncAll`, not its buffered default whose
`commit()` returns `Ok` having fsynced nothing.

**Run twice with the arm order reversed**, because the first run's read figure
turned out to follow the order rather than the engine.

| | fjall 3.1.8 | redb 4.1.0 | ratio |
|---|---:|---:|---:|
| mean write size | 18,681 / 18,451 B | **4,348 / 4,340 B** | **4.27x** |
| write syscalls | 765,076 / 761,500 | **7,371,980 / 7,371,980** | **9.7x** |
| bytes written | 14.29 / 14.05 GB | 32.05 / 31.99 GB | **2.26x** |
| wall | 91.4 / 89.1 s | 238.0 / 200.8 s | 2.3–2.6x |
| blocked fraction | 0.089 / 0.064 | 0.313 / 0.204 | 3.2–3.5x |

**redb's mean write is one 4 KiB page.** Copy-on-write updates scatter single
pages across a growing file; an LSM appends sequential segments. redb issues
**9.7x more write syscalls to move 2.26x more bytes**, and spends **3.2–3.5x**
more of its life blocked. Its syscall count and store size are *bit-identical*
across the two runs — the pattern is deterministic — and every write-shape
figure reproduces within 2%. Absolute blocking fell on the quieter second run
while the ratio held.

This is the engine-isolated form of what the daemon comparison found: dcroxide
writes *fewer* bytes than dcrd and blocks 30x more per GiB. Scattered
copy-on-write overwrites onto btrfs-over-dm-crypt are near the worst case for
that stack; sequential compaction is near the best.

### Two figures this harness cannot supply

**`read_bytes` is not usable, and an earlier reading of it here was wrong.**
The first run had fjall first and showed fjall reading 8.2 GB against redb's
7 MB; an 8-batch smoke with redb first showed the reverse. The quantity was
the 8.1 GB journal being faulted in by whichever arm ran first. With the
journal pre-read before *each* arm, **redb reads 163,840 bytes and fjall
reads 0**. So this benchmark does **not** demonstrate read amplification, and
the claim that it corroborated the daemon's 99x is **withdrawn**. That daemon
figure (42.5 GiB against dcrd's 0.43) rests on its own evidence; a plausible
reason it does not reproduce here is that the replay's working set stays
cache-resident where a full sync's does not. Third time in this campaign that
an arm-order page-cache effect produced a credible wrong number, which is why
the reversed order was run rather than a plain repeat.

**`store_bytes` is not usable either.** fjall's moved 32% between runs (1.36
against 0.92 GB), both far below its own 6.07 GB payload, because this harness
measures immediately after load without quiescing compaction — which the
2026-08-13 engine benchmark deliberately did. Its settled figure, **6.23 GB /
1.026x payload against redb's 2.831x**, remains the size answer.

### What it establishes, and what it does not

Established: the write-shape mechanism is real, engine-attributable, and
large — 4.27x on write size, 9.7x on syscalls, 3.2–3.5x on blocking.

Not established: any daemon throughput prediction. This is a replay, and a
replay is not a daemon — the distinction that invalidated the 18% figure
earlier in this campaign. It measures how the two engines respond to identical
input, which is what the engine decision needs, and it does not say what IBD
would do.

Raw: `artifacts/dcroxide-bench/m1/writeshape.jsonl` (fjall first) and
`writeshape2.jsonl` (redb first, journal pre-warmed). Harness
`writeshape.sh` / `writeshape2.sh`, arm binary
`artifacts/dcroxide-tools/engbench/src/bin/writeshape.rs`.

## fjall against the crash gate (2026-08-17)

ADR-0009 makes crash safety a condition on any engine change, and names the
property: `Chain::flush` writes block index rows, UTXO entries and **both**
state markers in one transaction, so a crash can never leave the markers
disagreeing with the rows they name. `crash.rs` enforces that for redb. This
asks it of fjall, which the size and write-shape measurements otherwise
favour.

**Batch atomicity under SIGKILL: 12 rounds, 12 consistent.** A writer commits
one paired generation per batch — 200 rows plus both markers, one
`PersistMode::SyncAll` commit — and is killed at a randomised point inside a
batch. Every reopen found the markers agreeing with each other, agreeing with
the rows they name, and nothing visible past them.

**The rig has teeth, checked the way this file requires.** A control mode
commits the rows and the markers in *separate* batches, so they are not atomic
with each other. That is **detected in 7 of 12 rounds**, with the diagnostic
naming the failure ("rows visible past the marker"). Without the control the
clean 12/12 would mean nothing.

**The durability trap is confirmed rather than assumed.** 400 commits under
each mode:

| | wall | bytes to device | write syscalls |
|---|---:|---:|---:|
| `PersistMode::Buffer` | 0.016 s | 7.3 MB | 1,200 |
| `PersistMode::SyncAll` | 0.170 s | 41.0 MB | 1,200 |

Identical syscall counts, **5.6x more bytes actually reaching the disk and
10.6x slower** — `Buffer`'s `commit()` really does return `Ok` having left the
data in page cache. Any port on fjall must set `SyncAll` explicitly, which is
the same requirement `begin_durable_write` encodes on the redb side and the
reason ADR-0009 lists an asserted-durability seam as a condition.

### What this does NOT establish, which is the part that matters

**It is a process kill, not power loss.** The page cache survives, so it
cannot detect a missing fsync — the same limitation the redb suite had before
the 2026-08-15 power-loss backend, and the reason that backend was built.
**fjall exposes no injectable IO layer** (neither does `lsm-tree` beneath it),
so the `PowerLossBackend` cannot be pointed at it; the general form needs a
syscall-level shim intercepting write/fsync with an undo log, which does not
exist. Until it does, fjall's behaviour under power loss is untested here.

Also unreached: fjall **#308** (a commit does not poison the keyspace when the
journal write fails — needs fault injection, not a kill) and the full form of
**#311** (no strict recovery). Both are ADR-0009's stated reasons for
caution and neither is addressed by this.

So the engine picture is: fjall wins on size (1.026x its own payload against
redb's 2.831x), wins on write shape (4.27x mean write, 9.7x fewer syscalls,
3.2–3.5x less blocking), and **clears batch atomicity under process kill**.
Its power-loss behaviour and two upstream durability issues remain open, and
they are the half a consensus node cannot compromise on.

Harness: `artifacts/dcroxide-tools/engbench/src/bin/fjallcrash.rs`
(`write`, `writesplit` control, `verify`, `sync`).

### Power loss, engine-independent (2026-08-17)

The entry above closes with the missing instrument named: the 2026-08-15
power-loss primitive is a `redb::StorageBackend`, fjall exposes no injectable
IO layer, and asking a candidate engine the durability question needed a
syscall-level shim that did not exist. **It exists now, and fjall passes.**

`artifacts/dcroxide-tools/powerloss/` — an `LD_PRELOAD` shim intercepting
`open`/`openat`, `write`, `pwrite`/`pwrite64`, `ftruncate`, `fsync` and
`fdatasync`, plus a replay tool. Every write to a file under
`$POWERLOSS_DIR` is preceded by a record of what it destroys (the overwritten
bytes and the file's prior length); a successful sync of that file clears its
pending records, because those bytes can no longer be taken by a power cut.
Kill the target, replay what remains in reverse, and the tree is exactly as of
its last successful sync. It works at the libc boundary, so it is
engine-independent — and unlike the redb backend it also covers the flat
block-file path.

**The instrument is validated, not assumed.** A victim writes `AAAA`, fsyncs,
then writes `BBBB` over it and `CCCC` past the end, and is killed. Before
replay the file reads `BBBBBBBB` at 128 bytes; after replay it reads
`AAAAAAAA` at 64 — the unsynced overwrite *and* the unsynced extension are
both undone, and only the synced state survives.

**fjall under real power loss: 10 rounds, 10 consistent.** Paired generations,
one `SyncAll` batch each, killed at randomised points, everything since the
last successful fsync discarded. Markers agree with each other, agree with the
rows they name, nothing visible past them.

**With teeth, twice over.** The shim demonstrably engages on fjall's files —
a 16.4 MB undo log for one ~1 s round, with regions restored and lengths
rewound on replay. And the control that commits rows and markers in *separate*
batches is **caught in 4 of 8 rounds** under power loss, naming the failure.

So fjall's durability half now has the same standing as its size and
write-shape halves: measured, with a validated instrument and a failing
control. What remains open on gate C is narrower than before and unchanged by
this: **#308** needs an injected write *failure* rather than a kill, and
**#311** needs mid-journal corruption. The shim is the right place to build
both — it already sits on the write path — and neither is done.
