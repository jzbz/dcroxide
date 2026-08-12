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
so the campaign against the 2.2x IBD gap produces a curve, not
before/after anecdotes.

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

## Storage at tip

| date | machine | dcroxide commit | corpus | result | source |
|---|---|---|---|---|---|
| 2026-07 | m1 | unrecorded (2.2.0-pre, at the ADR-0004 amendment) | mainnet tip | dcroxide 32.06 GiB total (17.579 GiB blocks + 14.483 GiB metadata.redb); dcrd 23.73 GiB (17.580 GiB blocks + 6.045 GiB metadata leveldb + 0.108 GiB utxodb) | ADR-0004 amendment |
| 2026-08-11 | m1 | `6cb2f56` | mainnet tip, both sides fed `mainnet-full.corpus` | **Matched composition, payload measured on both sides.** Metadata store, consumed bytes: dcrd 6.102 GiB (6,552,084,480) against dcroxide 14.505 GiB uncompacted (15,574,482,944) and 12.052 GiB compacted (12,940,464,128); dcroxide's live B-tree 9.823 GiB (10,547,314,688). Payload: dcrd 6,061,905,929 B, dcroxide 6,069,302,583 B. Over each store's *own* payload: dcrd 1.081x, dcroxide 1.738x on the live tree, 2.566x on the uncompacted file. | this file, below |

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
