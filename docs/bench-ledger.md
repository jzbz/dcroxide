# Benchmark ledger

Every performance number this repo relies on, keyed by machine, commit,
and corpus, so any two measurements can be compared — or ruled
incomparable — after the fact. Prose snapshots (README, ADRs) cite
these rows; this file is the record.

Rules: append rows, never rewrite them. A row names the machine (table
below), the dcroxide commit measured, the workload, and the raw export
it came from. Raw exports, logs, and profiles stay out of the tree and
are not retained: a `Raw:` line names the files a run produced so the
row can say what it rests on, not a location anyone can open. **The
figures in this file are the record.** Record a row for every
storage-rework milestone, so the campaign against the IBD gap produces
a curve, not before/after anecdotes. That gap was 2.23x when the
campaign opened in 2026-07 and measured 1.29x on 2026-08-15; the curve
is the point of this file. A separate comparison on 2026-10-09 and
2026-10-10, on m3 and against dcrd's latest release, had dcroxide
syncing 2.71x as fast as dcrd at the defaults, and 1.42x with the
exists-address index off in both (one run each). It is not a later
point on that curve:
the machine, the dcrd version and the harness all differ.

## Machines

| id | CPU | cores/threads | RAM | disk |
|---|---|---|---|---|
| m1 | AMD Ryzen AI MAX+ 395 | 16/32 | 64 GB | WD PC SN5000S 1 TB NVMe |
| m2 | x86_64, a container on a larger host | 4 CPUs for the node, one for the dcrd server and harness | not recorded | ZFS mirror of QLC NVMe drives (recordsize 128K, compression on) |
| m3 | AMD Ryzen 9 7950X3D | 16/32; 8 cores (16 threads) for the node, 4 others for the block server | 96 GB | Samsung 990 PRO 2 TB NVMe, btrfs (zstd compression on) over an encrypted mapping |

Hardware was not recorded when the 2026-07 campaign ran; its rows are
attributed to m1 as the only bench host to date, with specs read on
2026-08-07.

m3 was added on 2026-10-10. It is the development desktop that the
2026-10-09 end-state checks under "Exists-address index layout 3"
describe as not in this table.

## Sync throughput

Mainnet genesis to tip over loopback, one machine, fresh datadir per
run, both nodes `--norpc`.

These are loopback figures and do not describe operator IBD over a WAN.
There, dcrd's 16-block in-flight window (`internal/netsync/manager.go:32-38`,
`:1368`, ported exactly) is predicted to cap throughput near 9-16 blocks per
round trip once RTT exceeds about 9 x the per-block processing time: ~34 ms
for dcroxide at 3.8 ms/block (265 blk/s), ~26 ms for dcrd at 2.9 ms/block
(342 blk/s). No netem-delay arm (e.g. 50 and 100 ms added on the loopback
path) has been measured yet, so this crossover is unconfirmed.

> **Note (2026-10-11): measured, through a userspace relay and not
> netem.** At round trips of 20, 50 and 150 ms dcroxide ran at 12.2, 13.0
> and 13.6 blocks per round trip, and dcrd v2.1.6 at 12.6 at 50 ms, in
> fixed-time runs over the early chain on m3. See "Shared commits for
> UTXO-cache flushes, the filesystem's share and a delayed link" below.
>
> **Note (2026-10-12): the daemon's default window is no longer
> dcrd's.** Since `540b203` the daemon keeps up to 128 blocks and, past
> 16 of them, 3,145,728 bytes requested from its sync peer during the
> initial sync (`BUDGET_WINDOW_BLOCKS` and `MAX_BUDGET_WINDOW_BYTES`,
> `crates/dcroxide-netsync/src/manager.rs:49`, `:81`). dcrd's window is
> still in the port and is what `DCROXIDE_BLOCK_WINDOW=dcrd` selects,
> so the paragraph above and the note of 2026-10-11 describe dcrd and
> that setting. Through the same relay on m3, one run of 300 s an arm,
> one binary: 13.1 blocks per round trip under dcrd's rule and 102
> under the default at a 50 ms round trip, and 13.6 and 117 at 150 ms.
> See "Eleven changes, a background commit not kept and a pool gate"
> below.

| date | machine | dcroxide commit | vs dcrd | corpus | result | source |
|---|---|---|---|---|---|---|
| 2026-07 | m1 | unrecorded (2.2.0-pre, at the ADR-0004 amendment) | 2.2.0-pre+452c1a6c3 (go1.26.5) | mainnet, ~1,100,400 blocks | syncer dcroxide: 2.47 h — 124 blk/s (from dcroxide), 2.51 h — 122 blk/s (from dcrd); syncer dcrd: 1.11 h — 276 blk/s, 1.02 h — 299 blk/s | ADR-0004 amendment |
| 2026-08-15 | m1 | `b6d0c63` (fan-out fix `c091b46` **not** in the binary) | 2.2.0-pre+452c1a6c3 (go1.26.5) | mainnet, 1,100,392 blocks | Both daemons from one shared dcrd server, sequential, defaults, exists-address index verified on both: dcroxide 4,153 s — **265.0 blk/s** at 0.76 mean cores; dcrd 3,220.5 s — **341.7 blk/s** at 1.50. **1.29x**, not the 2.23x above. Arms ~12 h apart under unmatched loadavg (4.62 vs 2.45), n=1 — a bound, not a point estimate | this file, below |
| 2026-08-15 (second) | m1 | `8b27d20` (fan-out fix included) | 2.2.0-pre+452c1a6c3 (go1.26.5) | mainnet, 1,100,392 blocks | Same shared server, arms back to back on a quiet box, page cache pre-warmed before each: dcroxide 4,821.4 s — **228.2 blk/s**; dcrd 3,200.8 s — **343.8 blk/s**. Ratio **1.51x**. dcrd reproduced to 0.6% across the two 2026-08-15 runs; dcroxide fell 14% under higher ambient (a browser active in its arm only). Both runs carried more ambient in the dcroxide arm, so **1.29x above remains the tighter upper bound** — this row is the D-state run's throughput, not a supersession | this file, below |
| 2026-10-09 and 2026-10-10 | m3 | `c128a93` | release v2.1.6 (go1.25.4) | mainnet, genesis to 1,116,035 | Each daemon from a block server run by the other, four runs each on a quiet machine (three alternated, one from a later round), defaults apart from the flags that point the node at the server, exists-address index on in both; the syncing node's RPC is on for the harness's height polls, so not `--norpc`: dcroxide 1,058.6 s median (1,055.8–1,065.0) — **1,054.3 blk/s** at 1.71–1.72 mean cores; dcrd 2,863.9 s (2,848.8–2,894.8) — **389.7 blk/s** at 1.94–1.95. dcroxide **2.71x** as fast. One same-session run of each daemon from its own kind: 1,072.2 s and 2,872.8 s, so the source moved either by about 1% or less | this file, "Daemon against daemon, each from the other" |
| 2026-10-10 | m3 | `c128a93` | master `6f6cf21b` (2.2.0-pre, go1.26.2, release image flags) | mainnet, genesis to 1,116,035 | The parity commit, in the harness of the row above: dcrd from a dcroxide block server, two runs, 2,909.8 s and 2,869.8 s — **383.5 and 388.9 blk/s** at 1.90–1.92 mean cores, against v2.1.6's 2,848.8–2,894.8 s. dcroxide's median of 1,058.6 s is **2.73x** as fast as their mean. With `--noexistsaddrindex` in both, one run each: dcroxide 880.8 s — **1,267.0 blk/s**; dcrd v2.1.6 1,247.8 s — **894.4 blk/s**; **1.42x** | this file, "The parity commit, the index off, two levers and a full replay" |
| 2026-10-11 | m3 | `74168e8` and the five changes that follow it, added one at a time | not run in this session | mainnet, genesis to 1,116,035 | dcroxide from the dcrd v2.1.6 block server at the defaults, in the harness of the two rows above. `74168e8` itself: 1,058.3 s in one run, made after the first of the others, where the median two rows above is 1,058.6 s. One run per cumulative change: 1,015.3 s, 912.8 s, 893.7 s, 820.3 s and, with all five, 759.1 s and 756.2 s in two runs — **1,470.3 and 1,475.9 blk/s** at 1.93–1.94 mean cores. That is 28.3% and 28.5% under the same session's 1,058.3 s. Set against dcrd's 2,863.9 s of 2026-10-09 and 2026-10-10 it is 3.77x and 3.79x, across sessions | this file, "Five changes on the block-processing thread" |
| 2026-10-11, afternoon | m3 | `b4a5d2d` (shared commits for UTXO-cache flushes, overlay default 300 MiB), and `7d31abb` before it | release v2.1.6 (go1.25.4), one run | mainnet, genesis to 1,116,035 | dcroxide from the dcrd v2.1.6 block server at the defaults, in the same harness. `7d31abb` itself: 775.6 s in one run that afternoon. With the change: 725.9 s, 728.7 s and 729.4 s, median 728.7 s — **1,531.6 blk/s** at 2.0 mean cores, 6.0% under the 775.6 s, with 54 flushes where there were 133. With `--noexistsaddrindex`, one run: 610.2 s — **1,829.1 blk/s**. dcrd from the same block server, one run that evening: 2,883.9 s — **387.0 blk/s**, so the change's median is **3.96x** as fast in one session. Set against dcrd's 2,863.9 s and 1,247.8 s of 2026-10-09 and 2026-10-10 it is 3.93x and 2.04x, across sessions | this file, "Shared commits for UTXO-cache flushes, the filesystem's share and a delayed link" |
| 2026-10-12 | m3 | `a83f9a1`, `6271436`, `3a367e5` and `540b203`, one run each | not run in this session | mainnet, genesis to 1,116,035 | dcroxide from the dcrd v2.1.6 block server at the defaults, in the same harness. The binary of the row above again: 728.5 s in one run, where its three runs above have a median of 728.7 s. Then one run per state, each holding the changes before it: `a83f9a1` (the missed-ticket handle, the UTXO maps' key comparison, one write per block record, the writer-wait timer) 673.8 s — 1,656.2 blk/s; `6271436` (three changes to the exists-address index and the ticket buckets) 628.0 s — 1,777.2 blk/s; `3a367e5` (the SigHashAll prefix hash) 607.7 s — **1,836.6 blk/s** at 1.9 mean cores; `540b203` (the block download window) 612.4 s — **1,822.3 blk/s** at 1.9 mean cores. The last two are 16.6% and 15.9% under the same session's 728.5 s. Set against dcrd's 2,883.9 s of the evening of 2026-10-11 and its 2,863.9 s of 2026-10-09 and 2026-10-10, the 612.4 s is 4.71x and 4.68x, across sessions | this file, "Eleven changes, a background commit not kept and a pool gate" |
| 2026-10-12 | m3 | the read-ahead build before its review's fixes, which became `b4ceb1c` and also holds `5cf9e04`; neither commit was run as committed | not run in this session | mainnet, genesis to 1,116,035 | One binary in the same harness, two runs under each setting, alternated. With `DCROXIDE_READ_AHEAD=off`: 597.6 s and 599.0 s. At the defaults: 494.6 s and 490.8 s — **2,256.3 and 2,273.9 blk/s** at 2.26–2.28 mean cores, 103.0 s and 108.2 s less than with read-ahead off and 32.1% and 32.6% under the same session's 728.5 s for `b4a5d2d`. `b4ceb1c` differs from the binary's code in one condition of the reader's idle budget and one private function, and has not been run in a sync. Set against dcrd's 2,883.9 s and 2,863.9 s as in the row above, the 494.6 s and 490.8 s are 5.83x and 5.88x, and 5.79x and 5.84x, across sessions | this file, "Eleven changes, a background commit not kept and a pool gate" |
| 2026-10-13 | m3 | `4700cf1` (the code of `b4ceb1c` and one log line more) | release v2.1.6 (go1.25.4), one run | mainnet, genesis to 1,116,035 | dcroxide from the dcrd v2.1.6 block server at the defaults, in the same harness, in a session in which that server read 15.7–18.0 GB from the drive during every run, where it read none in the runs of 2026-10-11 and at most 1.5 GB in those of 2026-10-12, none in the read-ahead runs of the row above. Three runs: 513.4 s, 513.5 s and 504.2 s — **2,173.8, 2,173.3 and 2,213.3 blk/s** at 2.19–2.23 mean cores. The first two spent about 10 s longer in their flushes' commit phase, for a reason the records do not give; with the commit seconds taken out the three are 432.8–433.7 s. With `--noexistsaddrindex`, one run: 423.6 s — 2,634.6 blk/s. dcrd from the same block server, one run: 2,920.3 s — **382.2 blk/s** at 1.94 mean cores, so dcroxide is **5.69x to 5.79x** as fast over the three pairings with that one run. The 494.6 s and 490.8 s of the row above are another session and another build | this file, "Seven cumulative builds, the validation pool, a background commit and dcrd" |
| 2026-10-13 | m3 | seven builds on `4700cf1` that add, one group at a time, the changes of the seventeen commits from `d76e8ec` to `6376eeb`, in another order than the commits and each with a developer variable the tree does not have, left unset; none is the tree of a commit | release v2.1.6, the one run of the row above | mainnet, genesis to 1,116,035 | The same session and harness. The first build (`4700cf1` with the flush log's processor times and the variable): 505.6 s and 502.8 s, the speed of `4700cf1` within its spread. The last: 441.9 s and 442.2 s — **2,525.5 and 2,524.1 blk/s** at 2.39–2.40 mean cores, 62.2 s or 12.3% under the first by wall, 62.6 s with the commit seconds taken out and 63.6 s by the node's clock less its flush time, with two runs at each end. The five builds between ran once each. The tree these commits leave with `f60ae3a` has not been run in a sync | this file, "Seven cumulative builds, the validation pool, a background commit and dcrd" |
| 2026-10-13 | m3 | `4700cf1` with the persistent validation pool that `f60ae3a` carries on top of the other seventeen commits; the tree of `f60ae3a` has not been run | release v2.1.6, the one run of the first 2026-10-13 row | mainnet, genesis to 1,116,035 | The same session and harness. Two runs: 491.3 s and 493.4 s — **2,271.8 and 2,262.1 blk/s** at 2.19 mean cores. About 12 to 16 s, 2.4–3.2%, under the code without the pool, by the measure: 11.9 s by wall against its runs with an ordinary commit phase and those of the first cumulative build, 15.8 s with the commit seconds taken out. All of it falls after the assume-valid block | this file, "Seven cumulative builds, the validation pool, a background commit and dcrd" |
| 2026-10-16 | m3 | `8fc9160`, which holds `4700cf1`, the seventeen commits to the node's code after it, one that adds tests, a patch release of `rustls` and a fix to two tests | release v2.1.7, built from its tag as its release image builds it, one run; release v2.1.6, one run | mainnet, genesis to 1,116,035 | dcroxide from the dcrd block server of the rows above at the defaults, in the same harness, four rounds interleaved with the builds of the next row and `4700cf1`; the server read 17.9–18.6 GB from its drive in each run of the first round and 0–11 MB in every later dcroxide run. Four clean runs: 421.2 s, 429.3 s, 432.1 s and 434.0 s, median 430.7 s — **2,649.9 to 2,571.6 blk/s** at 2.34–2.40 mean cores; a fifth, of the first round, was disturbed and repeated. `4700cf1`, four runs: median 516.2 s (513.1–517.9 s), so the commits after it took 85.5 s, 16.6%, off it. With `--noexistsaddrindex`, one run: 351.3 s — 3,176.9 blk/s. dcrd v2.1.7, one run: 2,944.4 s — **379.0 blk/s** at 1.94 mean cores; v2.1.6, one run, 2,944.5 s. So dcroxide is **6.84x** as fast in one session, against one dcrd run that read 18.0 GB of server data from the drive where the four runs of `8fc9160` read none. Against dcrd's 2,883.9 s and 2,863.9 s of earlier sessions it is 6.70x and 6.65x | this file, "`8fc9160`, a background commit and dcrd v2.1.7" |
| 2026-10-16 | m3 | a background commit, as it was measured, on `4700cf1` with the changes of those seventeen commits, the validation pool among them, as they were measured on 2026-10-13, against the same build without it; neither is the tree of a commit, and `02b802c`, which carries the change, has not been run | the runs of the row above | mainnet, genesis to 1,116,035 | The same session and harness, four runs of each interleaved with the row above. With it: 388.3 s, 391.7 s, 388.8 s and 390.3 s — **2,849.2 to 2,874.3 blk/s** at 2.65–2.69 mean cores. Without it: 432.4 s, 428.9 s, 430.0 s and 427.5 s, at 2.35–2.38. Medians 389.55 s and 429.45 s: **39.9 s or 9.3% less**, less in every pairing, and 38.6 s or 9.0% on the runs whose block server read no more than 11 MB from its drive. Process CPU time 27 s or 2.6% higher, and peak resident memory to the tip about 256 MiB higher at the median | this file, "`8fc9160`, a background commit and dcrd v2.1.7" |
| 2026-10-17 | m3 | `88c46c3`, the head of master when the syncs ran: `8fc9160` and the commits after it, which port dcrd's changes since `6f6cf21b` and commit the metadata on a thread of its own (`02b802c`) | release v2.1.7, the binary of the 2026-10-16 rows, two runs, and one with `--noexistsaddrindex` | mainnet, genesis to 1,116,035 | dcroxide from the dcrd v2.1.6 block server of the rows above at the defaults, in the same harness, with transparent huge pages at `madvise` where 2026-10-16 ran at `always`; the server read nothing from its drive in any run. Four runs interleaved with dcrd's and with the row below: 397.8 s, 396.6 s, 395.9 s and 395.3 s, median 396.25 s — **2,816.5 blk/s** at 2.63–2.65 mean cores; two later controls took 391.1 s and 395.8 s. With `--noexistsaddrindex`, two runs: 343.9 s and 344.0 s — 3,245.2 and 3,244.3 blk/s. dcrd v2.1.7: 2,944.4 s and 2,926.4 s — **379.0 and 381.4 blk/s** at 1.90 and 1.92 mean cores; with the index off, one run, 1,317.2 s — 847.3 blk/s. So dcroxide is **7.43x and 7.39x** as fast at the defaults and 3.83x with the index off, in one session. Against dcrd v2.1.6's 2,863.9 s of 2026-10-09 and 2026-10-10, from a dcroxide block server, 2,883.9 s of 2026-10-11 and 2,920.3 s of 2026-10-13 it is 7.23x, 7.28x and 7.37x, across sessions. All 18 full syncs of the session, dcrd's included, ended with the same block files and the same UTXO set by `gettxoutsetinfo` | this file, "`88c46c3`, the background commit as committed, dcrd v2.1.7 and two preloaded allocators" |
| 2026-10-17 | m3 | `88c46c3` with `DCROXIDE_DB_SYNC_COMMIT=1`, every metadata commit on the committing thread, against its default, the background commit as `02b802c` committed it | the runs of the row above | mainnet, genesis to 1,116,035 | The same session and harness, two runs interleaved with the four default runs of the row above: 430.4 s and 428.0 s — 2,593.0 and 2,607.6 blk/s at 2.36–2.37 mean cores. The default's median is **32.95 s or 7.7% less** than theirs, 34.15 s and 31.75 s less than each, and less in every pairing, with 32.3 s and 33.7 s more process CPU time and 205.5 and 254.5 MiB more peak resident memory to the tip. Both arms ended with the same UTXO set and block files | this file, "`88c46c3`, the background commit as committed, dcrd v2.1.7 and two preloaded allocators" |
| 2026-10-17 | m3 | `88c46c3`'s binary with jemalloc 5.4.0 or gperftools 2.18.1's tcmalloc_minimal preloaded (`LD_PRELOAD`), a configuration the daemon does not ship | not run with these | mainnet, genesis to 1,116,035 | The same harness, in a second queue of two rounds, each a default control, then jemalloc, then tcmalloc_minimal. Controls: 391.1 s and 395.8 s. jemalloc: 339.4 s and 341.4 s — 3,288.3 and 3,269.0 blk/s. tcmalloc_minimal: 334.5 s and 334.3 s — **3,336.4 and 3,338.4 blk/s**. 13.2% to 15.5% under the control of their round, with 73.8 to 76.8 s less process CPU time and 653 to 1,146 MiB less peak resident memory to the tip | this file, "`88c46c3`, the background commit as committed, dcrd v2.1.7 and two preloaded allocators" |
| 2026-10-18 | m3 | `88c46c3` and eight builds on it that add ten changes to the node's code a rung at a time, states of a worktree; none is the tree of a commit | not run in this series | mainnet, genesis to 1,116,035 | From a live dcrd v2.1.7 node on another machine on the same LAN, about 0.3 ms away, at the defaults: a series of its own, not comparable with the loopback rows above. `88c46c3`, three runs: 407.9 s, 407.8 s and 407.0 s, mean 407.57 s — **2,738.3 blk/s** at 2.57–2.59 mean cores. With all ten changes (G), two runs: 319.7 s and 323.2 s, mean 321.45 s — **3,471.9 blk/s** at 2.77–2.78, 86.12 s or 21.1% less, with 158.5 s less node CPU time. Each of the eight steps, 4.30 to 18.70 s, is beyond the 95% interval of these runs, about ±3.5 s; the change of one of them, 5.15 s, was not kept | this file, "Rungs from a block server on the LAN, two changes held for their memory, and dcrd v2.1.7" |
| 2026-10-18 | m3 | G without the change not kept (G'), G' with a block's data sanity checks made on the thread that read it (H), and H with two more changes, held for their memory (I, J); states of a worktree, none the tree of a commit | release v2.1.7 (go1.25.4), the binary of the rows above, one run, and one with `--noexistsaddrindex` | mainnet, genesis to 1,116,035 | The same LAN server, that afternoon, at the defaults. G': 320.8 s, 314.6 s and 320.9 s, mean 318.77 s; H: 318.0 s and 312.9 s, mean 315.45 s — **3,537.9 blk/s** at 2.84–2.89 mean cores, 3.32 s less, which the session's ±6.5 s does not resolve. J, a build that includes the two held changes: 264.4 s, 267.4 s and 268.9 s, mean 266.90 s — 4,181.5 blk/s, with a peak resident memory of 6,222 to 7,241 MiB against 3,077 to 3,342 MiB for G' and H. dcrd v2.1.7: 2,991.4 s — 373.1 blk/s at 1.89, so J is 11.21x as fast, and 5.37x with the index off (247.3 s and 248.0 s against 1,330.3 s). H was not set against dcrd | this file, "Rungs from a block server on the LAN, two changes held for their memory, and dcrd v2.1.7" |
| 2026-10-19 | m3 | J, the binary of the row above, and K, J's code with the `dbcommit` thread kept for the life of the store rather than made for each flush; states of a worktree, K's code that of the three commits that follow the commit that records these syncs | the runs of the row below | mainnet, genesis to 1,116,035 | From the LAN server of the two rows above, at the defaults, in runs alternated J, K, J, K, J. J: 274.8 s, 271.8 s and 274.3 s, mean 273.63 s, at a peak resident memory of 6,730 to 6,933 MiB. K: 270.7 s and 271.5 s, mean 271.10 s — 4,116.7 blk/s at 3.31–3.33 mean cores, 2.53 s less, which the session's ±3.9 s does not resolve, at **2,456 and 2,470 MiB**. One run of J with `MALLOC_ARENA_MAX=8`: 284.2 s and 5,455 MiB. J's mean is 6.73 s over that of its three runs of 2026-10-18 | this file, "One commit thread for the life of the store, a sync that checks every script, and dcrd v2.1.7" |
| 2026-10-19 | m3 | K, the binary of the row above: the code of the three commits that follow the commit that records these syncs, as a state of a worktree | release v2.1.7 (go1.25.4), the binary of the rows above, two runs, and one with `--noexistsaddrindex` | mainnet, genesis to 1,116,035 | The same LAN server and session, at the defaults. K, four runs, two of them those of the row above: 270.7 s, 271.5 s, 272.7 s and 271.8 s, mean 271.68 s — **4,108.0 blk/s** at 3.28–3.33 mean cores, with a peak resident memory of 2,456 to 2,470 MiB. With `--noexistsaddrindex`, two runs: 250.8 s and 249.6 s — 4,449.9 and 4,471.3 blk/s. With `DCROXIDE_DB_SYNC_COMMIT=1`, two runs: 350.2 s and 350.6 s, so the default is 78.7 s or 22.5% less, and peaks lower. dcrd v2.1.7: 3,014.6 s and 3,033.4 s — **370.2 and 367.9 blk/s** at 1.88 mean cores; with the index off, one run, 1,336.3 s — 835.2 blk/s. So K is **11.13x** as fast at the defaults, 11.05x to 11.21x over the eight pairings, and 5.34x with the index off, in one session. One sync of K from the loopback server with `--assumevalid=0`, every block validated in full, ended with the UTXO set and the block files of every full sync from that server since 2026-10-17; its 583.4 s is not a timing, since the server read 19.2 GB from its drive | this file, "One commit thread for the life of the store, a sync that checks every script, and dcrd v2.1.7" |
| 2026-10-19, evening | m3 | `797a213`, the head of master when the syncs ran, and R1, `797a213` with four changes as a state of a worktree, R1's code that of the sixth commit after the commit that records these syncs but for tests and comments | not run in this session | mainnet, genesis to 1,116,035 | From the LAN server of the rows above, at the defaults, the two alternated. `797a213`: 273.1 s, 270.9 s, 273.2 s and 269.8 s, mean 271.75 s — **4,106.8 blk/s** at 3.30–3.35 mean cores, where K's four runs of that morning had a mean of 271.68 s. R1: 263.1 s, 266.3 s, 265.5 s and 264.9 s, mean 264.95 s — **4,212.2 blk/s** at 3.38–3.40, 6.80 s or 2.5% less, beyond the session's ±2.6 s, at a peak resident memory of 2,460 to 2,470 MiB against 2,465 to 2,500 MiB. One sync of R1 from the loopback server ended with the UTXO set and the block files of every full sync from that server since 2026-10-17 | this file, "Where `797a213`'s block thread waits, a deeper read-ahead and a rung of four changes" |
| 2026-10-19, evening | m3 | a diagnostic build of `797a213` that reads the read-ahead's depth, four frames in the code, and the index notification buffer, 128, from the environment, not for commit; the depth of sixteen is that of the seventh commit after the commit that records these syncs, which also holds R1's changes and was not run | not run in this session | mainnet, genesis to 1,116,035 | The same LAN server and session, at the defaults but for the setting, two runs of each, alternated. Depth 4: 273.3 s and 272.9 s. Depth 16: 263.4 s and 263.4 s, mean 263.40 s — 4,237.0 blk/s at 3.39–3.40 mean cores, 9.70 s or 3.6% less than depth 4, beyond the queue's ±4.8 s, with 66.2% and 65.5% of the inputs of the guessed shape pre-verified against 51.7% and 52.2%. Depth 32: 267.2 s and 263.5 s, 7.75 s less than depth 4. A buffer of 512 at depth 4: 273.3 s and 270.1 s, 1.40 s less, which is not resolved. In a later queue, depth 16 once more, 264.8 s, and depth 16 with `DCROXIDE_PREVERIFY=10`, at most ten helpers where the default is six: 258.1 s and 259.6 s, 5.02 s under the three runs at depth 16, for 29.83 s more node CPU time | this file, "Where `797a213`'s block thread waits, a deeper read-ahead and a rung of four changes" |

> **The headline 1.29x predates the fan-out fix, so it is conservative for
> master.** That figure was measured on `b6d0c63`; `c091b46` (one validation
> worker per core, 6.1% on the replay corpus) landed after it, along with
> `d5aa17f` (the cache lock released across the metadata commit, which
> unblocks readers and is not expected to move IBD). Every prose citation of
> 1.29x — README, PARITY, the project brief, ADR-0004, operating.md — is
> therefore an upper bound on the gap for current master in two independent
> ways: the ambient-load asymmetry recorded in the row itself, and this.
>
> **Re-measuring it needs repetitions, not another single run.** dcroxide
> measured 265.0 and 228.2 blk/s eleven hours apart (the two rows above), a
> 14% spread — wider than the effect being looked for. A single new arm would
> return a number indistinguishable from that variance. The form that would
> settle it is two arms, dcroxide-from-dcrd and dcrd-from-dcrd, three
> alternating repetitions each so drift cannot load onto one arm, in one
> session on a quiet box: about six hours, and the first figure this
> comparison has ever had with error bars. The four-combination shape of the
> 2026-07 row is not needed — its question, whether the *source* matters, was
> answered there (1.6–8.8%) and has not been in doubt since.
>
> Not scheduled: ADR-0009 closed on 2026-08-17, so this number informs no
> pending decision and is documentation accuracy. Worth running before a
> release, or after any change expected to move IBD.
>
> **Run on 2026-10-09 and 2026-10-10, in a different shape.** Alternating
> repetitions on a quiet machine, as asked for above, but on m3, against
> dcrd's latest release instead of 2.2.0-pre, and with each daemon
> syncing from the other: the 2026-10-09 and 2026-10-10 row above, and
> "Daemon against daemon, each from the other" below. It does not
> re-measure 1.29x on m1. The README no longer cites 1.29x: its
> Performance section reported this comparison instead, and later ones
> after it. From 2026-10-17 it reported only the comparison of that day,
> and the text it carried until then is in "README Performance text
> retired on 2026-10-17" below. Since 2026-10-19 it reports the syncs of
> that morning from a block server on the LAN, with those of 2026-10-17
> in one bullet; the text it replaced is in git history, and its figures
> in "`88c46c3`, the background commit as committed, dcrd v2.1.7 and
> two preloaded allocators" below.

**Open arm, unmeasured: the maturing-ticket ancestor read.** Every connect
past stake-enabled height lists the ticket purchases in the block
`ticket_maturity` below it (256 on mainnet) to add them to the live pool
(`maybe_fetch_new_tickets` in `process.rs`, dcrd `maybeFetchNewTickets`,
`stakenode.go:21-43`). The per-connect parent prune (dcrd `connectBlock`,
`chain.go:795-808`) now also evicts the parent's body and rows from the port's
recent-window mirrors once it sits more than 288 blocks below the best header,
which during initial sync is every block. So that ancestor is never resident,
and each connect pays a flat-file read, checksum and full `MsgBlock` decode of
it, plus, after treasury activation, a database view for
`calculate_treasury_balance`'s ancestor treasury row. dcrd pays the same
reads: its recent-block cache holds only 12 blocks (`recentBlockCacheSize`,
`chain.go:48`) and it fetches both treasury rows from the database
(`treasury.go:379`, `:387`), so this is a cost, not a parity gap. Two fixes
trade memory for it: exempt the ~257 bodies within `ticket_maturity + 1` of
the tip from the eviction, or record each block's ticket-purchase hashes when
its data is accepted (per node, or in a ring of `ticket_maturity + 1` entries)
so the read needs no body. The gain is an estimate, about 1-2% of the 3.8
ms/block above; nothing here has been measured. What decides it is a mainnet
sync, or a long simnet sync past stake-enabled height, with and without a
prototype of the hash ring, the arms alternated as in the overlay sweep below;
record the result here whether or not it ships.

> **Note (2026-10-11): taken, as the second of the two fixes, and measured
> on m3.** The chain records each block's ticket-purchase hashes when its
> data is accepted, in a list of the last `2 * ticket_maturity` blocks
> accepted (512 on mainnet; the half past `ticket_maturity` is room for
> side chain blocks), and `maybe_fetch_new_tickets` reads the block back
> only when the list has no entry for it. It was measured with one mainnet
> sync from genesis before and one after, not with alternated arms:
> 912.8 s without it and 893.7 s with it, 19.1 s or 2.1%, where five
> default runs of the earlier code spanned 9.2 s. The bytes the node read
> fell from 25.3 GB in 2.45 million calls to 6.1 GB in 1.33 million. The
> 19.2 GB between them is the chain's blocks, read once each. The run
> without it already had the faster block-file checksum, so the read cost
> less than it did when the estimate above was written, and that estimate
> was for m1. The treasury row's database view is unchanged. See "Five
> changes on the block-processing thread" below.

## Storage at tip

| date | machine | dcroxide commit | corpus | result | source |
|---|---|---|---|---|---|
| 2026-07 | m1 | unrecorded (2.2.0-pre, at the ADR-0004 amendment) | mainnet tip | dcroxide 32.06 GiB total (17.579 GiB blocks + 14.483 GiB metadata.redb); dcrd 23.73 GiB (17.580 GiB blocks + 6.045 GiB metadata leveldb + 0.108 GiB utxodb) | ADR-0004 amendment |
| 2026-08-11 | m1 | `6cb2f56` | mainnet tip, both sides fed `mainnet-full.corpus` | **Matched composition, payload measured on both sides.** Metadata store, consumed bytes: dcrd 6.102 GiB (6,552,084,480) against dcroxide 14.505 GiB uncompacted (15,574,482,944) and 12.052 GiB compacted (12,940,464,128); dcroxide's live B-tree 9.823 GiB (10,547,314,688). Payload: dcrd 6,061,905,929 B, dcroxide 6,069,302,583 B. Over each store's *own* payload: dcrd 1.081x, dcroxide 1.738x on the live tree, 2.566x on the uncompacted file. | this file, below |
| 2026-08-15 | m1 | `b6d0c63` | mainnet tip, both daemons synced from one shared dcrd server, exists-address index on both, no transaction index | **Apparent size**, whole appdata: dcroxide 36,055,044,196 B (33.58 GiB) against dcrd 25,433,938,876 B (23.69 GiB) — 1.42x. Same pair as the 2026-08-15 sync row above; both daemons' own datadirs, not a replay. | this file, below |
| 2026-10-09 and 2026-10-10 | m3 | `c128a93` | mainnet at block 1,116,035, each daemon synced from the other, exists-address index on both, no transaction index | **Apparent size**, whole appdata, medians of four runs: dcroxide 29,953,302,380 B (27.90 GiB; 17.884 GiB of block files + a 10.012 GiB metadata.redb) against dcrd v2.1.6 25,945,551,274 B (24.16 GiB) — 1.15x. The four runs span 2.6 MB for dcroxide and 27.7 MB for dcrd. | this file, "Daemon against daemon, each from the other" |
| 2026-10-17 | m3 | `88c46c3` | mainnet at block 1,116,035, each daemon synced from the dcrd v2.1.6 block server, exists-address index on in both, no transaction index | **Apparent size**, `du -sb` of the whole run directory after shutdown, logs included: dcroxide a median of 29,987,505,990.5 B over four runs (27.93 GiB; 29,941,263,220 to 30,007,106,445 B) against dcrd v2.1.7 25,937,696,188 and 25,963,945,368 B (24.16 and 24.18 GiB) — 1.16x and 1.15x. The block files are 19,202,596,910 B (17.884 GiB) in every run, so the rest is about 10.04 GiB under dcroxide and 6.27 and 6.30 GiB under dcrd; the size of `metadata.redb` alone was not recorded. With `--noexistsaddrindex`: 27,792,612,448 and 27,792,612,438 B (25.88 GiB) against 23,783,725,484 B (22.15 GiB), one run. | this file, "`88c46c3`, the background commit as committed, dcrd v2.1.7 and two preloaded allocators" |

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
database is not a read-only act (after an unclean stop redb runs a full
repair on open -- quick-repair is not enabled on flush commits, only on the
commit `Database::close` ends with -- and `Database::open` rolls the block
files back when the metadata trails them). Probes open a fresh reflink clone
of the snapshot; neither the original nor the snapshot is opened directly.

| date | machine | what | export | notes |
|---|---|---|---|---|
| 2026-08-07 | m1 | mainnet datadir behind the 2026-07 sync and storage rows | `baseline-2026-07-25/blocks_ffldb/` | reflink clone of `artifacts/p2p-sync/data/mainnet/blocks_ffldb/`, written 2026-07-25; 31 GiB apparent, no additional space on btrfs, 22 s. `metadata.redb` is 15,551,119,360 B, the 14.483 GiB the ADR decomposes. |
| 2026-08-11 | m1 | **dcrd** datadir behind the matched-composition rows | `dcrd-payload/data/mainnet/` | dcrd 2.2.0-pre at the parity commit `29f17894`. Built by `tools/addblock -i mainnet-full.corpus` (12m17s, 1,493 blk/s) and then `dcrd --appdata … --norpc --nolisten --connect=127.0.0.1:1` to drive index catch-up. **Composition recorded, which is the point of keeping it:** exists-address index ON, transaction index OFF — `addblock` defaults, no `--txindex`. Kept because ADR-0009 records that losing the 2026-07 baseline's composition cost this project a conclusion. |

## Replay throughput (dcroxide-bench)

Identical-corpus replays via `dcroxide-bench export` / `replay`
(crates/dcroxide-bench). No rows yet — the first storage-rework
milestone starts this table, measured against the corpus the 2026-07
campaign exported.

> **Note (2026-10-10): the table has its first row, and it is not that
> milestone's.** The replays of 2026-08 were recorded under their own
> sections below and never here. The row is a replay on m3 over a corpus
> exported the same day, so it has no earlier row to be set against.

| date | machine | dcroxide commit | corpus | result | raw run |
|---|---|---|---|---|---|
| 2026-10-10 | m3 | `337779d` | mainnet, blocks 1 to 1,116,035 (19,198,132,458 B), exported from a data directory synced the same day | `replay --addrindex` at the tool's default caches, pinned to 16 threads: 1,909.41 s — **584.5 blk/s**, every block validated in full, exit 0 at tip height 1,116,035, 11,875 MiB peak RSS | this file, "The parity commit, the index off, two levers and a full replay" |
| 2026-10-11 | m3 | `74168e8` and the five changes that follow it | the corpus of the row above | `replay --addrindex` at the tool's default caches, pinned to 16 threads: 1,746.67 s — **638.9 blk/s**, every block validated in full, exit 0 at tip height 1,116,035, 12,607 MiB peak RSS. Not a clean timing: compilers and test runs used the machine's other 16 threads during it, so it is not to be set against the row above as a measured gain | this file, "Five changes on the block-processing thread" |

## Free-page probes (`dcroxide-bench pinprobe`)

Three arms per experiment, each on its own reflink clone, differing only
in what is held open across the flushes.

| date | machine | dcroxide commit | workload | arms | result |
|---|---|---|---|---|---|
| 2026-08-07 | m1 | `6a2951b` | 400k scattered writes, 8 commits, 8 MiB overlay, mainnet clone | none / all / two | Free-page curves identical. Flushes 1-2 byte-for-byte across all arms; flush 3 differs by 41,782 B (0.0008%) between `all` and `none`, in the direction opposite to pinning. Free pages fell 48.5 MiB while payload grew 20.4 MiB and the file did not grow. ADR-0004 lever (a) closed. |

> **Correction (2026-09-23): the `two` arm was not measured.** This file is
> append-only, so the row stands as written. `pinprobe` dropped the `two`
> arm's reader after its second commit, not its second flush, and at these
> parameters no flush had run by then, so the reader spanned no flush and
> the arm was a second `none` control. The conclusion rests on `all` against
> `none`. `pinprobe` now counts flushes, releases the reader after flush 2
> and warns when fewer than two ran (`the_two_arm_reader_spans_two_flushes`).

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

Raw records: `replay-flush-all.jsonl`; corpus
`mainnet-250k.corpus` (2.43 GB, exported from the 2026-07-25 baseline).

The run averaged 445 blk/s where the full mainnet sync managed 124, so
this slice is informative about curve shape and misleading about
magnitude. Raw records for the full run:
`full-flush.jsonl`; corpus
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

Raw records: `s2-*.jsonl` and `lever-sweep2.log`.

> **Note (2026-09-23): the 2026-08-10 baseline rests on two runs.** The
> warm-up discard was taken from the baseline arm, because repetition 1
> always started there, so the baseline range 3866-3888 s comes from 2 runs
> against 3 for every other arm. The 2026-08-11 sweep ran the same schedule
> with a default of one warm-up; the row does not record whether it was
> overridden, so its baseline range 6332-6501 s may rest on 2 runs as well.
> `sweep` now runs warm-ups as extra runs before the first repetition
> (`sweep_schedule`), so every arm keeps all its repetitions.

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
`sweep-levers.jsonl`.

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
Raw log: `rekey2.log`.

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
offsetting differences. But fifteen buckets agreeing simultaneously at byte
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
commit `73ac17e`, raw records in `schedule-sweep.jsonl`.

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
— and ran **6.5% slower** on disjoint ranges, because a 100-item batch then
ran on three threads while 29 cores idled. The mechanism moved exactly as
intended and the outcome went the other way. Fan-out has to stay
proportional to the machine, not to the batch; the work-stealing loop is
what lets one worker per core suffice.

Two earlier churn figures in this file are superseded by these: a ">=276
threads/second" measurement taken early in the chain, where blocks are too
sparse to reach the 16-item parallel threshold, understated the steady-state
rate by roughly an order of magnitude.

**Open arm, unmeasured: a persistent pool.** All three arms above are
`std::thread::scope` workers, created and joined on every `validate_items`
call, so the adopted arm still creates 17,396–18,637 threads per 10 s. A
long-lived pool of `cores` workers, which ADR-0005 originally proposed, would
keep the full width without the per-call spawns, each batch reaching it
through the same shared index and first-failure slot. This arm has not been
measured; record it here whether or not it ships. `validate_items` carries
the same note.

> **Note (2026-10-12): gated by a replay benchmark, built outside the
> tree, and not measured in a sync.** A replay of every 20th fully
> validated block's script batches, in a benchmark outside the
> repository, put a persistent pool that takes batches of four or more
> items at 19.8 to 20.2 s saved over the validated part of a sync on
> m3, one that takes eight or more at 10.6 to 11.3 s and one that takes
> sixteen or more at 4.1 to 4.9 s, against these scoped workers. Those
> are estimates from a replay, at three settings of the work between
> batches. A pool was then built and reviewed in a scratch tree. It is
> not in the repository and no sync of it has been run, so this arm is
> still unmeasured in a sync, and `validate_items` still creates its
> workers on every call
> (`crates/dcroxide-blockchain/src/validate.rs:5280`). See "Eleven
> changes, a background commit not kept and a pool gate" below.
>
> **Note (2026-10-16): in the repository since `f60ae3a`, and measured
> in a sync on 2026-10-13.** A connected block's script trees of four
> items or more (`MIN_POOLED_ITEMS`,
> `crates/dcroxide-blockchain/src/scriptpool.rs:129`) are checked on
> helper threads that live as long as the process, at most one fewer
> than the logical CPUs it may run on, with the calling thread checking
> too. `validate_items`
> (`crates/dcroxide-blockchain/src/validate.rs:5505`) still creates its
> workers on every call for a batch of 16 items or more, where it is
> still used: a connected block's tree whose previous scripts exceed
> 1 MiB, the template check, the public `check_block_scripts` and a
> single transaction's inputs after its first. On m3 a build of
> `4700cf1` with the pool synced in 491.3 s and 493.4 s, about 12 to
> 16 s under the same code without it, depending on the measure, and all
> of it after the assume-valid block. The tree of `f60ae3a`, with the
> pool and the seventeen other commits of 2026-10-16, has not been run
> in a sync. See "Seven cumulative builds, the validation pool, a
> background commit and dcrd" below.

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

Raw: `daemon-vs/` — `rox.log`, `rox-cpu-VALID.txt`,
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
indistinguishable from a torn tail and presents as silent truncation. Both land on the cross-bucket atomicity `Chain::flush`'s single-transaction commit (`process.rs`) depends on, and
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
`folio_wait_bit_common` (729 samples, page I/O wait: a read waiting on
PG_locked or writeback waiting on PG_writeback, which wchan cannot
distinguish), `handle_reserve_ticket` (113, btrfs metadata reservation),
`wait_for_commit` (101, transaction commit) and
`btrfs_btree_wait_writeback_range` (27). dcrd's park in
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

Raw: `dstate/` — `rox.jsonl`, `dcrd.jsonl` (34,083
and 31,979 samples), `rox.log`, `dcrd.log`, `run.log`. Sampler and harness:
[`tools/dsample/dsample.py`](../tools/dsample/dsample.py); harness
`dstate.sh`.

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
24.4, max 79.5, 61 of 130 over 30 s), windows occupying 68% of wall, and the
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

Raw: `flushobs/` — `rox.jsonl` (26,391 samples),
`flush.jsonl` (130 records), `rox.log`, `run.log`. Harness `flushobs.sh`,
sampler [`tools/dsample/dsample.py`](../tools/dsample/dsample.py).

## Background commit (2026-08-16) — implemented, measured, and NOT shipped

ADR-0009's remaining question was whether the metadata commit could be moved
off the block-connection thread to recover the 48% of wall time the node
spends fully stalled in it. **It was built, measured, and reverted: it is
9.5% slower, and the reason is structural rather than a bug in the
implementation.**

> **Note (2026-10-12): built again in another form, on m3, and it
> gained.** With the storage engine's commit on a second thread for
> the flushes a commit trips, a default sync took 579.6 s against
> 607.9 s on the code of `3a367e5` and 468.0 s against 498.5 s on a
> build with read-ahead: 28.3 s and 30.5 s less, one run against one
> run each, for 981 and 748 MiB more peak resident memory. In those
> two control runs the flushes were 17.6% and 21.7% of the wall time,
> where they are 68–71% in the runs below. That experiment is not in
> the repository either: it was built as far as the measurement and no
> further. So what follows is the record of this design on m1 in
> 2026-08, and "cannot work" and "closed by measurement" below are
> statements about it. See "Eleven changes, a background commit not
> kept and a pool gate" below.
>
> **Note (2026-10-13): built a third time, on `231997b`, and it gained
> again.** With the engine's commit on its second thread holding a read
> snapshot of the store while it runs, a default sync on m3 took
> 465.7 s and 460.5 s against its control arm's 501.1 s and 500.5 s,
> 35.4 s and 40.0 s less, in two pairs of one binary, with no memory
> cost detected at a resolution of about 300 MiB. That form is not in
> the repository either. See "Seven cumulative builds, the validation
> pool, a background commit and dcrd" below.
>
> **Note (2026-10-16): kept, in the form of 2026-10-13.** On m3, on a
> build of `4700cf1` with the cumulative builds' changes and the pool,
> it took 389.55 s against 429.45 s for that build without it, four runs
> each, 9.3% less, where the flushes are well under half of the wall
> time. It is `02b802c`, on by default in the daemon, with
> `DCROXIDE_DB_SYNC_COMMIT=1` putting every commit back on the
> committing thread. It was not run on m1 or on slower storage. See
> "`8fc9160`, a background commit and dcrd v2.1.7" below.

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

Raw: `phase2/` against
`flushobs/`, same harness, same server, same
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

Raw: `writeshape.jsonl` (fjall first) and
`writeshape2.jsonl` (redb first, journal pre-warmed). Harness
`writeshape.sh` / `writeshape2.sh`, arm binary
`engbench/src/bin/writeshape.rs`.

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

Harness: `engbench/src/bin/fjallcrash.rs`
(`write`, `writesplit` control, `verify`, `sync`).

### Power loss, engine-independent (2026-08-17)

The entry above closes with the missing instrument named: the 2026-08-15
power-loss primitive is a `redb::StorageBackend`, fjall exposes no injectable
IO layer, and asking a candidate engine the durability question needed a
syscall-level shim that did not exist. **It exists now, and fjall passes.**

[`tools/powerloss/`](../tools/powerloss/) — an `LD_PRELOAD` shim intercepting
`open`/`open64`/`openat`, `write`, `writev`, `pwrite`/`pwrite64`, the `pwritev`
family, `ftruncate`/`ftruncate64`, `fallocate`/`fallocate64`, `fsync` and
`fdatasync`, plus a replay tool. (Until 2026-09-23 it intercepted only
`open`/`openat`, `write`, `pwrite`/`pwrite64`, `ftruncate`, `fsync` and
`fdatasync`; every round in this ledger ran on that version. See the note at
the end of the next entry.) Every write to a file under
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

### dcroxide's own block files under power loss (2026-08-17)

The shim's reason for existing beyond fjall: the 2026-08-15 primitive is a
`redb::StorageBackend`, so it reaches the metadata store and **not** the flat
`.fdb` block files. Those are the other half of the invariant `DbCache::flush`
maintains — block files are fsynced *before* the metadata commit, so metadata
can never name bytes a crash could take. The suite tested that half only under
`drop`, which cannot lose an unsynced append.

The daemon syncing mainnet from a local dcrd, `LD_PRELOAD`ed, killed with
SIGKILL deep in block sync, undo log replayed, then reopened:

| round | killed at height | `.fdb` written | reopened at | undo applied |
|---|---:|---:|---:|---|
| 1 | 81,465 | 735 MB | 93,518 | 7,168 lengths rewound |
| 2 | 177,707 | 1.69 GB | 177,707 | 9,392 |
| 3 | 162,496 | 1.52 GB | 162,496 | 4,928 |

**Three rounds, three clean reopens, zero corruption** — and not vacuously:
each round had thousands of unsynced appends actually undone, against 0.7–1.7
GB of block data on disk. `reconcileDB` recovered every time, and the metadata
never claimed more block data than survived, which is the failure the ordering
exists to prevent and the one `ErrCorruption` would have reported.

**A first attempt at this was vacuous and is worth recording.** Killing at
38–60 s landed inside headers sync, before any block file is written: every
round reported "killed at height 0" with a 16 KB undo log touching one file,
and passed while testing nothing. Headers sync takes ~56 s on this host, so
the kill window has to start past it. The tell was the undo log's size, not
the pass/fail result — which is the general lesson: a crash test that passes
without the instrument having anything to undo has not run.

**Corrected 2026-08-17, with per-path counts added to the replay tool.**
The inference above — that the undos were `.fdb` appends because they were
length rewinds — was **wrong**, and the truth is a better result. A round
killed at height 130,165 with 1.14 GB of block files reports:

    71,679 regions (304 MB) restored, 1 file touched
        .../blocks_ffldb/metadata.redb

**Only the metadata store had anything to undo.** Not because the shim misses
block files — it records 299,196, 214,228 and 20,820 writes across the three
`.fdb` files, with their syncs — but because by kill time every one of those
writes was already covered by an fsync.

**That is the files-before-metadata ordering working, and it is why a random
kill lands where it does.** `DbCache::flush` syncs the block files first,
clearing their pending records, and only then runs the metadata commit — which
the 2026-08-16 measurement puts at 68–71% of block-sync wall time. So a kill
at an arbitrary instant almost always falls *inside* the metadata commit, with
the block bytes already durable and the metadata naming them still in flight.
Power loss then rewinds the metadata behind the files, `reconcileDB` truncates
the orphaned block data on reopen, and the node continues — the designed
recovery path, exercised end to end.

So the earlier rounds tested something real, just not the thing they were
described as testing: they demonstrate that the ordering keeps block bytes
durable ahead of the metadata that names them, which is the invariant's whole
purpose. The per-path counts are what made the difference between inferring
that and knowing it.

**What these rounds did and did not show (2026-09-23).** The shim they ran
on had gaps. It did not interpose `ftruncate64`, the symbol Rust's
`File::set_len` calls, so neither redb's file growth nor `reconcileDB`'s
truncation of block files was ever recorded. It did not interpose `writev`,
`pwritev` or `fallocate` either. It silently dropped any overwrite of 64 KiB
or more (a record within 12 bytes of that size overran its buffer
instead), so a large redb page write was never undone. It put zeros back
where a shrink had cut bytes off. And it never recorded a file as created,
because it checked for the file after the `O_CREAT` open, so a never-synced
new `.fdb` survived replay empty instead of vanishing. All five are fixed,
and `dcroxide-testutil`'s `review_powerloss_shim` pins them end to end
(`writev` through `write_vectored`; the `pwritev` family and `fallocate` have
no case there). The shim still does not model directory durability (a
missing parent-directory fsync after a create, unlink or rename; unlink and
rename are not interposed at all), torn or reordered persistence within a
file's unsynced writes, or writes through descriptors it never saw opened.
So "three clean reopens, zero corruption" means the reopen raised no
`ErrCorruption` against a tree the instrument had partly rewound. It did not
compare the recovered UTXO set or the index tips against a reference node,
and no round killed the node during a reorg or disconnect, the shutdown
flush, the catch-up replay or an index drop. The rounds, and the fjall rounds above, need
re-running with the fixed shim before they support more than that.

### fjall #308 and #311, exercised (2026-08-17)

The two upstream issues ADR-0009 names as gate C's remaining blockers, both
previously unreachable: #308 needs a journal write to *fail* rather than a
process to die, and #311 needs mid-journal corruption. The shim's new fault
injection (`POWERLOSS_FAIL_MATCH` / `_AFTER` / `_COUNT`) supplies the first;
the second needs no shim.

**#308 — does not reproduce against 3.1.8.** The issue describes `commit()`
failing to poison the database on a journal write failure, with a later batch
committing after the unterminated record and returning `Ok`. Reproducing it
needs a **transient** fault: a permanent one only shows every later commit
erroring, which is correct behaviour rather than the bug. With 1 or 3 journal
writes failed and writes then resuming, fjall returned `Err` for **all 250
subsequent commits** — it poisoned — and every acknowledged generation
survived the reopen. Three variations (fail 1 after 150, fail 3 after 150,
fail 1 after 250), same result each time.

**#311 — reproduces, and it is the serious one.** 400 generations committed
with `SyncAll`, each acknowledged `Ok`. Corrupting **64 bytes inside the
journal's written extent**, then reopening:

| corruption point | acknowledged | survived | lost |
|---|---:|---:|---:|
| 30% of written extent | 400 | 120 | **280** |
| 70% of written extent | 400 | 280 | **120** |

**The reopen succeeds.** No error, no warning, no indication anything is
missing. Recovery truncates from the first bad record and the store comes up
presenting a consistent view of a chain state that has silently rolled back by
hundreds of generations. That is precisely the shape a consensus node cannot
tolerate: not a crash, which a supervisor handles, but committed state
disappearing behind a healthy-looking startup.

**Note the file layout trap.** fjall preallocates the journal to 64 MiB, so
corrupting at "30% of the file" lands in unwritten space and changes nothing —
a first attempt did exactly that and read as a clean pass. The written extent
was 686,800 B of the 67,108,864 B file. A corruption test that does not
locate the written region tests nothing, which is the same class of vacuous
pass as the crash rounds that never wrote a block file.

**Where this leaves gate C.** One of the two blockers is not reproducible and
the other is, in the most damaging form available. fjall wins on size, on
write shape, and survives power loss — and a single corrupted record in its
journal silently discards every commit after it. Whether that is
disqualifying is a judgement about operational context (a node that
re-syncs from peers can recover from silent truncation if it *notices*),
and it is the project owner's call, not a measurement. What is no longer
true is that gate C is blocked for want of an instrument.

### Would `reconcileDB` notice a #311 truncation? No — and the state can be torn (2026-08-17)

The entry above leaves #311's severity as a judgement about whether a
re-syncing node would notice a silent rollback. It would not, and the rollback
is worse than a rollback.

**`reconcileDB` takes the silent branch.** Its comparison is block-file cursor
against block-file contents (`lib.rs:869-885`):

```
if stored > scanned { return Err(Corruption) }        // metadata AHEAD  — loud
if stored < scanned { block_store.rollback_to(...) }  // metadata BEHIND — silent
```

A journal truncation rolls the metadata *backward*, so it lands on the second
branch: the block files are quietly truncated back to what the metadata knows
and the node starts. That is the correct handling of an unclean shutdown, and
it is indistinguishable from one. Nothing at database open compares the state
markers against the rows they name.

**And the rollback is not necessarily a clean prefix.** Corrupting 64 bytes at
five points inside the journal's written extent, with rows and both markers
committed in one batch:

| corruption point | result |
|---|---|
| 25% | **TORN** — 100 rows visible past the marker |
| 40% | **TORN** |
| 55% | **TORN** |
| 70% | clean prefix |
| 85% | clean prefix |

**Three of five leave rows the marker does not account for** — the desync
`Chain::flush` pairs its writes to forbid. The batch *was* atomic when it
committed; recovery breaks it afterwards.

**The mechanism is cross-keyspace flushing.** Rows and markers live in
separate fjall keyspaces, each with its own memtable and flush schedule.
Truncating the journal drops records, but whatever already reached an SSTable
survives — so if the rows keyspace had flushed generation G+1 and the markers
keyspace had not, the rows persist while the marker naming them does not.

**Why this is consensus-relevant and not merely wasteful.** UTXO rows past the
recorded state are not lost data, they are phantom spendable outputs. The
paired markers exist precisely so that cannot happen, `crash.rs` asserts it in
both directions, and **the daemon's startup path does not check it** —
`reconcileDB` validates the block-file cursor and nothing else.

**The open experiment, which could change the verdict.** The tearing looked
cross-keyspace, and dcroxide keeps its entire ffldb keyspace in **one** redb
table, so a fjall port using a single keyspace would have one memtable and one
flush schedule and truncation should then be a clean prefix.

> **Run 2026-08-17: refuted.** Same corruption offsets, rows and markers in
> ONE keyspace, everything else identical:
>
> | | clean prefix | torn |
> |---|---:|---:|
> | two keyspaces | 2 | 3 |
> | one keyspace | 2 | 3 |
>
> Identical, and at the identical offsets — 25/40/55% tear, 70/85% do not. A
> single-keyspace layout does **not** fix #311, so the mitigation this
> paragraph proposed does not exist and #311 stands on its own terms.
>
> **The mechanism is not established, and the obvious one is contradicted.**
> Rows and markers in one batch share a memtable and a flush, which predicts a
> clean prefix; the result says otherwise. The failure is offset-dependent
> rather than layout-dependent, so something about how a repeatedly-overwritten
> key (the marker is the same key every generation, unlike the per-generation
> rows) survives flush and compaction is involved. Recorded as unexplained
> rather than guessed at.

**A second one worth running regardless of engine:** a startup check that the
state markers agree with the rows they name, which `crash.rs` already
implements and the daemon does not. It would catch this class of damage
whatever produced it, and it is cheap against a store that already reads both
markers at open.

> **Added 2026-08-17**, in the narrower form the live data allows. The
> catch-up path already refuses a marker naming a block absent from the index;
> it now also refuses one whose **height disagrees with the index's** for that
> same hash — the signature of two durability domains rolled back by different
> amounts. The row-counting form `crash.rs` uses has nothing to compare
> against here, since a live utxo set records no expected row count. Costs one
> field comparison on a node the catch-up already loads, and
> `a_utxo_state_height_disagreeing_with_the_index_stops_the_node` fails when
> the comparison is disabled.

## Overlay flush cadence: +12.7% on IBD (2026-08-17)

`DCROXIDE_DB_OVERLAY` was exposed on 2026-08-16 as an untuned instrument: a
durable commit is forced by *either* the UTXO cache filling or the metadata
overlay filling, and only the first had ever been measured
(`--utxocachemaxsize`, 12% at 8x its default). This asks whether the second
trigger has comparable headroom. **It does.**

Four full mainnet syncs from one shared dcrd server, **alternating A B A B**,
same binary throughout, page cache pre-warmed before each arm:

| arm | overlay | rate | flushes |
|---|---|---:|---:|
| a1 | default (100 MiB) | 256.1 blk/s | 129 |
| b1 | **800 MiB** | **288.4** | 119 |
| a2 | default | 272.7 | 130 |
| b2 | **800 MiB** | **307.5** | 119 |

**+12.7%** (264.4 → 297.9 mean), and it clears this file's own bar for a
defensible result three ways:

- **Ranges are disjoint.** A spans [256.1, 272.7], B spans [288.4, 307.5].
- **Both adjacent pairs agree to 0.2 points**: a1→b1 is 12.6%, a2→b2 is 12.8%.
- **The mechanism is confirmed, not assumed.** Flush count drops 130 → 119,
  8.1% fewer. The knob engaged. An arm pair with identical flush counts would
  have meant the throughput numbers were measuring noise, which is the vacuous
  result this file has recorded three times in two days.

### The alternation was load-bearing

**Both arms drifted upward by ~6.5% across the run** — A from 256.1 to 272.7,
B from 288.4 to 307.5 — almost certainly page cache warming across successive
syncs on the same server. Run as A A B B, that drift would have inflated B by
roughly half the claimed effect. Because the arms alternate, it cancels within
each adjacent pair, which is why both pairs land on the same figure. Two
earlier sweeps in this campaign were voided by exactly this confound; this is
the first one where the design caught it in the act.

### Two things this does not say

**The absolutes are not comparable across sessions.** The default arm runs
264 blk/s here where 2026-08-16 measured 228–232 at the same setting — a
quieter box and a warmer cache, not a code change. Only the within-session A/B
is valid. Reading these absolutes against another day's is the error that
produced the 265-against-232 confusion in the first place.

**Whether it composes with `--utxocachemaxsize` is untested.** Both levers
measure ~12% and both act on the same durable commit through independent
triggers. They may stack toward ~25%, or both may be approaching the same
ceiling and together give ~12%. One more A/B answers it, and it is the obvious
next experiment on this thread.

> **Note (2026-09-23): the overlay is now counted as dcrd counts it.** Every
> arm above ran with entries counted at key and value bytes only, which put
> the figure 2-4x under the memory held for the small rows that dominate
> this store. Each entry now also counts dcrd's 72-byte `nodeFieldsSize`
> (`NODE_FIELDS_SIZE` in `dbcache.rs`), so both the default and the 800 MiB
> setting now flush a smaller overlay than the one measured here. The +12.7%
> and the 130 → 119 flush counts describe the old accounting; re-measure
> before quoting them for current master.

## Height-first per-block keys (2026-10-07 and 2026-10-08)

The arm [ADR-0010](adr/0010-height-first-block-keys.md) shipped: the seven
buckets that gain a row per block keyed by big-endian height first, chain
database version 15. Machine m2, the node on four cores syncing mainnet over
loopback from a dcrd `6f6cf21b` block server that holds a frozen chain to
1,116,035 (`--connect` to it, `--nolisten`, `--noseeders`, RPC on loopback
for the harness's height polls, `DCROXIDE_DB_FLUSHLOG` set, defaults
otherwise, so the exists-address index is on). Base is
`5559002`; the arm is `5559002` with the re-keying, the change this section
lands with. Each arm's tail runs start from its own snapshot at about
916,000, taken by the arm itself, since the two layouts cannot open each
other's directories. Tail runs of both arms were interleaved over about 22
hours with other arms between them.

| arm | runs | blk/s (median, range) | node bytes written, median | CPU time, median |
|---|---:|---|---:|---:|
| base, tail 916,041 → 1,116,035 | 5 | **78.1** (72.1–81.6) | 151.6 GB | 1,673 s |
| re-keyed, tail ~916,050 → 1,116,035 | 4 | **98.5** (95.3–108.1) | 136.6 GB | 1,546 s |
| base, genesis → 916,261 | 1 | **193.0** (4,747.8 s) | 274.2 GB | 2,147 s |
| re-keyed, genesis → 916,042 | 1 | **336.6** (2,721.6 s) | 235.0 GB | 1,767 s |
| dcrd `6f6cf21b`, genesis → 916,233 | 1 | **472.4** (1,939.5 s) | 238.7 GB | 3,005 s |

**+26% on the tail and 1.74x from genesis.** Every re-keyed tail run is faster
than every base run, and the gap is well outside this storage's noise: five-run
base calibrations on it spread 15–20% in blk/s (a standard deviation of about
7%), while bytes written varied by at most 3% from run to run and CPU time by
at most about 2% (5% in one calibration taken while other virtual machines
shared the node's cores), which is why the campaign judged arms by repeated,
interleaved runs and by bytes rather than by any one run. The node wrote 10%
fewer bytes on the tail, several times that byte jitter, and 14% fewer from
genesis, and it used 8% and 18% less CPU time. The data directory did not grow: 24.98 GB against
24.96 at about 916,000, and 33.22–33.33 GB against base's 33.26 at the tip
(one base run measured 33.50). That answers a prediction made before the
runs, that appending at each bucket's right edge would leave half-full leaves
(redb splits a full leaf at its midpoint) and cost some size; at this scale
it does not show.

Read the genesis rows as n=1 each. Read every absolute against this machine
only: its storage treats this write pattern very differently from m1's, and
dcrd syncs 2.45x as fast as base here from genesis where m1 measured 1.29x in
2026-08. Only the within-session comparison is valid.

Raw: the campaign's `runs.jsonl` rows labelled `flush-base`, `flush-base
noisy`, `flush-rekey` and `genesis`, with per-run samples (height, core
clocks, load, pressure) and per-flush logs (`DCROXIDE_DB_FLUSHLOG`). The fifth
base tail run carries the `noisy` flag because the host's load average was
1.98, over the harness's 1.5 quiet threshold, when its 15-minute wait for a
quiet host ran out. It is kept: its 76.45 blk/s falls inside the other four
runs' range, and the base median and range are the same with or without it.

## Exists-address index layout 3 (2026-10-09)

The arm [ADR-0011](adr/0011-exists-address-layout-3-and-the-flush-participant.md)
shipped. The exists-address index is stored in the port's own layout,
index version 3, and its rows are written by a flush participant inside
the metadata flush. Machine m2, set up as for the height-first runs
above: the node on four cores, syncing mainnet over loopback from the
same dcrd `6f6cf21b` block server and frozen chain, with
`DCROXIDE_DB_FLUSHLOG` set and defaults otherwise. The three arms:
- **Base** is `6c11a38`, with the height-first keys and the index on in
  dcrd's layout (index version 2).
- **Layout 3** is `6c11a38` with the change this section lands with.
- **The floor** is base with `--noexistsaddrindex`.

Base and the floor start each run from the re-keyed arm's snapshot
(chain tip 916,046). The floor leaves that snapshot's old index idle.
Layout 3 starts from a snapshot derived from a block clone of that one
(below), so its chain state is the same. All runs end at 1,116,035.
Measuring starts at about 916,050 (916,224 in one run), and the rate
counts only the blocks measured. There were fifteen runs in the order
base, layout 3, layout 3, base, floor, repeated three times. Each
followed a 600 s idle, and the round took about 7.3 hours.

| arm | runs | blk/s (median, range) | node bytes written, median | CPU time, median | flushes | flush time per run, median |
|---|---:|---|---:|---:|---:|---:|
| base, index in dcrd's layout | 6 | **94.0** (87.1–108.0) | 137.4 GB | 1,566 s | 58–59 | 1,416 s |
| layout 3 | 6 | **482.1** (461.8–497.5) | 15.5 GB | 649 s | 31 | 77.8 s |
| index off (the floor) | 3 | **501.1** (497.2–503.1) | 12.6 GB | 594 s | 31 | 105.5 s |

**5.1x on the tail with the index on, and level with the floor within
the noise.** Every layout-3 run was more than four times as fast as every
base run (461.8 blk/s against at most 108.0). Against base, layout 3
wrote 8.9x fewer bytes, used 2.4x less CPU time and made about half the
flushes. Against the floor, its median is 3.8% lower, inside the spread
described below, so wall time does not separate the two; the counts do.
The index added 2.9 GB of writes (+23%), 55 s of CPU time (+9%) and no
flush.
- **Participant work over the 31 flushes:** 484,420 rows put (1.96 GB;
  9,021–31,136 in a flush) and 302,190 rows read for merges. It
  journaled 16,676,749 keys and made 852 merges, 218 of them base
  rewrites.
- **Commit writes:** the flushes' commit phases wrote 10.03 GB against
  the floor's 7.99 GB.
- **Memtable:** 2.38–3.99 million keys when each flush began, so at most
  84 MB of keys.

These counters were identical in all six runs. The data directory at
the tip was 29.05 GB, against base's 32.84–33.33 GB. The floor's
29.81 GB still holds the old index its snapshot had at 916,046, so it is
not an index-free size. Shutdown took 2.6–3.3 s, against the floor's
1.5–1.7 s and base's 1.0–22.1 s.

**Against the plan's criteria** (ADR-0011):

| criterion | threshold | layout 3 | result |
|---|---|---|---|
| speed | a median of at least 180 blk/s and twice base's (188.1) | 482.1 | pass |
| bytes written | at most 10 GB over the floor's | 2.9 GB over | pass |
| flush count | within 2 of the floor's | equal, 31 | pass |
| index digest at 916,046 | equal to base's | equal (below) | pass |
| fallback: median | ~180 blk/s or above | 482.1 | not tripped |
| fallback: flush time | at most 1.15x the floor's total | 0.74x (77.8 s against 105.5 s of flush time per tail, medians; per-flush median 2.34 s against 3.08 s, 0.76x) | not tripped |

Two criteria were **not judged** by the method the plan set for them:
- **Read syscalls** were to be counted outside the flush windows, which
  this harness does not separate. Over whole runs, layout 3 made
  1,051,325 against the floor's 456,877 (base: 41.8–42.6 million). The
  excess includes the merges' reads inside the flushes and the journal
  load at start.
- **Peak memory** was to be compared at a small fixed cache, or with the
  cache's occupancy subtracted. At the default 1 GiB cache, layout 3
  peaked at 2,749–2,773 MiB, against the floor's 2,423–2,424 and base's
  2,504–2,506.

**The flush-time margin is not explained.** Layout 3's flushes wrote
more than the floor's and took less time. The floor's commit phases read
14.7–20.4 GB from storage, and layout 3's 1.8–3.6 GB. Base's, on the
floor's own snapshot with the index on, read under 0.1 GB. Why the
floor's read so much has not been established. So the fallback test
passes as specified, but this is not evidence that the index makes a
flush cheaper. On a desktop, before the implementation review's fixes,
index-on flushes took 52% longer (ADR-0011).

**Layout 3's snapshot: the refusal, the drop, the rebuild and the digest
at 916,046.** This snapshot was derived on m2 from a block clone of
base's snapshot, with layout 3's binary on four cores:
1. Started with the index on, the binary refused the old index with the
   version message and exit status 1, after 16 s.
2. `dcroxide-bench existsaddr-digest` read the old index as 49,318,296
   keys, BLAKE-256
   `7d117ab8c54f5605d084912e823a47563255dedca533917409703ef355e50bfd`.
3. `--noexistsaddrindex --dropexistsaddrindex` removed its 49,318,296
   rows in 68 s.
4. Started again with the index on and no reachable peer, the node
   rebuilt the index from genesis to 916,046 in **157 s**. It made 34
   flushes, wrote 3.12 GB, used 151.8 s of CPU time and peaked at
   1,727 MiB resident, then exited cleanly.
5. The rebuilt index's key count and BLAKE-256 equal the old one's.

A first attempt at this step halted in the harness, which could not read
the exited process's I/O counters in the container. The harness was
fixed and the step run again on a fresh clone.

**The end-state checks: the digest at the tip, and a SIGKILL.** These
ran on a development desktop that is not in the machine table, with the
same three binaries. They are deterministic checks, and the timings
below are observations, not measurements. The source was a version-15
snapshot at 916,546 with a layout-2 index, and a dcrd block server
running on a clone of the same frozen chain.
- **The snapshot route, twice.** Layout 3's snapshot route ran twice on
  the desktop, with the same outcome both times. The old index was
  refused. Before the drop and after the rebuild, the index held
  49,362,108 keys, BLAKE-256
  `2c6cb264eef73aa51a73be7eacd536bcbef644f7378fd34cf5b0182a2e507903`.
  The rebuild took 34 flushes.
- **The digest at 1,116,035.** Base, on a clone of the snapshot, and
  layout 3, on the derived one, each synced to 1,116,035. Each was
  stopped once `existsaddress` answered at that tip. Each holds
  67,960,843 keys, BLAKE-256
  `8b676bdb992c7f5ca0590fd32bbce298816b96a114a34263564cf1af7d2d7b18`.
- **The SIGKILL.** A third layout-3 node was killed with SIGKILL just
  after `getblockcount` returned 1,000,009. Its last flush had ended
  2.1 s before. On restart:
  - The metadata store logged its unclean-shutdown repair, which took
    22.6 s.
  - The chain state came back at 998,896, with dcrd's hash for that
    height.
  - The index caught up from 998,895 to 998,896 and no further. Every
    block above that came from the chain's own re-sync.
  - The index's startup, from its "enabled" line to its "Catching up"
    line, took 0.33 s. That includes the journal load, which logs no
    line of its own
    (`crates/dcroxide-indexers/src/existsaddrindex.rs:457`).
  - About 2.1 million keys were reloaded. That count is derived from
    the first flush's counters: 2,686,176 memtable keys, counted before
    any merge (`crates/dcroxide-indexers/src/existsaddr/store.rs:214`),
    less 589,181 journaled.

  The node then synced to 1,116,035 and reached the digest above. A
  later clean restart left the digest unchanged.
- **Lookups through it.**
  - At 998,896, the node was held there with no peer. All 323 addresses
    of blocks 998,894–998,896 answered `true`. Of 186,624 addresses
    sampled from blocks 998,897–1,030,000, 97,619 answered `true` and
    89,005 answered `false`. Whether each `true` address had appeared
    at or below 998,896 was not checked.
  - During the re-sync, 125 `existsaddresses` calls each asked for
    addresses of the blocks around the chain tip read just before the
    call. None answered `false` for an address of a block at or below
    that tip. 62 returned "exists address index: index not synced"
    after the 3 s wait of the readiness gate the port keeps from dcrd.
    None came at once: the index never lagged six or more blocks.
  - At 1,116,035, 22,010 addresses were checked: one from each block
    that had an address answering `false` at 998,896. All of them, and
    all 653 addresses of eight named blocks, answered `true`, with the
    same bitsets as dcrd's `existsaddresses`.

**How to read the noise.** On this storage, wall time moves a lot from
run to run, and by how much depends on the arm:
- Base's six runs span 87.1–108.0 blk/s, 22% of the median. The round's
  report-only spread gate for base failed, as five-run base calibrations
  here did at 15–20%.
- Layout 3's six runs span 461.8–497.5 blk/s (7%).
- The floor's three runs span 497.2–503.1 blk/s (1%).

The counts barely move:
- Every layout-3 run wrote 15,493 MB in 3,245,973–3,245,974 write
  calls, with the same flush-log counters.
- Every floor run wrote 12,576 MB.
- Base's bytes varied over 135.6–138.7 GB (2.3%). It made 58 flushes in
  one run and 59 in the other five.
- CPU time varied by 0.2% for layout 3, 0.3% for the floor and 1.1% for
  base.

So the effect against base is far outside the noise: 5.1x in wall time,
8.9x in bytes and 2.4x in CPU time. The 3.8% wall-time gap to the floor
is inside it, and the index's cost against the floor is the bytes and
CPU figures above.

Six runs carry the `noisy` flag: three of base, two of layout 3 and one
of the floor. Each time, the host's load average (1.53–5.79) was over
the harness's 1.5 quiet threshold when its 15-minute wait for a quiet
host ran out. They are kept. Without them the medians are 89.5, 484.7
and 500.1 blk/s, and no conclusion changes.

**dcrd, for context only.** dcrd `6f6cf21b` ran the same tail on m2 at
146.3–148.4 blk/s (median 147.6 over three runs, one flagged noisy) on
2026-10-07, two days earlier, with other arms between its runs. It was
not run in this round. Setting layout 3's tail against it is a
cross-session comparison, which this file does not accept as a ratio.

Raw: the campaign's `runs.jsonl` rows labelled `mm-master`, `mm-exv3`
and `mm-floor` and their `noisy` variants, with per-run samples and
per-flush logs (`DCROXIDE_DB_FLUSHLOG`). The snapshot step's record is
in `snapshots.jsonl`, with its phase logs and rebuild flush log. The
dcrd rows are labelled `dcrd-ab`. For the end-state checks: the node and
dcrd logs, the `existsaddr-digest` outputs, and the RPC query logs of
that check's harness.

## Daemon against daemon, each from the other (2026-10-09 and 2026-10-10)

The repetition that the note under the 2026-08-15 rows of "Sync
throughput" asked for, in a
different shape: on machine m3, against dcrd's latest release, and with
each daemon syncing from the other. dcroxide `c128a93` (the height-first
keys and exists-address layout 3; `cargo build --release` under rustc
1.98.1) against dcrd `release-v2.1.6` (commit `39e9b9f9`), built with
go1.25.4 and the flags of its release image (`CGO_ENABLED=0`,
`-trimpath`, `-tags safe,netgo,timetzdata`, `-ldflags "-s -w"`). Each
syncs mainnet from genesis to 1,116,035 over loopback from a block
server:

- **dcrd as the source** is dcrd v2.1.6 serving a frozen chain to
  1,116,035 that a 2.2.0-pre build wrote. v2.1.6 opens it unchanged
  (chain database 14).
- **dcroxide as the source** is the data directory run r1 left, served
  by the same dcroxide binary.

The server runs isolated: `--connect` to a dead loopback address,
`--noseeders`, `--norpc`, listening on loopback. It is restarted for
each run, after its data has been read once into the page cache, and
the run starts 15 s after it listens.

The syncing node runs with `--connect` to the server, `--nolisten`,
`--noseeders` and RPC on loopback without TLS for the harness's
once-a-second `getblockcount` poll, and defaults otherwise. So the
exists-address index is on in both, and both carry the same assume-valid
block (`458d6a8e…`, height 1,026,597): up to it they skip connect
validation, script checks included, and they validate the 89,438
blocks after it in full.
`DCROXIDE_DB_FLUSHLOG` is set for dcroxide. The syncing node is pinned to
eight cores and their SMT siblings (16 threads, the half of the CPU with
the larger L3; both runtimes size their pools from the affinity mask),
the server to four others and the harness to four more.

The clock runs from spawning the syncing process to the first poll that
sees 1,116,035. Node CPU time (`/proc/<pid>/stat`), `wchar` and the
write-call count (`/proc/<pid>/io`) and peak RSS (`VmHWM`) are read at
that poll, before SIGINT. The data directory is `du -sb` of the whole
appdata after exit.

Every run waits for a quiet machine: no compiler or build process, load
under 2, and the machine and the node's cores each under 5% busy,
checked twice a minute apart. All but the first run of a queue start
(r1, c1, q1) also follow a `sync` and a 300 s idle. r1 began 102 s
after the second of two 20,000-block smoke runs ended, q1 about four
minutes after c2, and c1 five hours after r6 ended and 2.4 hours after
a first start of c1 that was stopped by hand 20 s in and is not
counted. The harness
marks a run disturbed, and repeats it, if it sees a build process,
other userland above 3% of the machine's 32 threads, or more than 2 GB
read from the volume by anything but the node and the server. No run
was marked.

Twelve runs in three rounds:

- **r1 to r6** alternate the two cross directions over about 3.8 hours.
- **c1 and c2** are one same-source run of each daemon, five hours later.
- **q1 to q4** follow at once, back to back over about 2.5 hours: each
  daemon from its own kind and then from the other.

| run | started | syncer | source | wall | blk/s | node CPU time (user + sys) | written | write calls | peak RSS | data directory | other userland |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| r1 | 10-09 17:33 | dcroxide | dcrd | 1,055.8 s | 1,057.0 | 1,820.9 s (1,698.2 + 122.7) | 51.6 GB | 11,953,169 | 2,129 MiB | 29,953,066,923 B | 0.18% |
| r2 | 10-09 17:57 | dcrd | dcroxide | 2,854.9 s | 390.9 | 5,569.4 s (4,522.8 + 1,046.6) | 286.1 GB | 61,603,639 | 1,849 MiB | 25,946,723,606 B | 0.15% |
| r3 | 10-09 18:51 | dcroxide | dcrd | 1,065.0 s | 1,047.9 | 1,821.6 s (1,695.2 + 126.4) | 51.4 GB | 11,916,014 | 2,140 MiB | 29,952,657,393 B | 0.15% |
| r4 | 10-09 19:16 | dcrd | dcroxide | 2,848.8 s | 391.8 | 5,542.8 s (4,503.4 + 1,039.4) | 280.6 GB | 60,666,375 | 1,851 MiB | 25,930,224,360 B | 0.13% |
| r5 | 10-09 20:10 | dcroxide | dcrd | 1,056.1 s | 1,056.8 | 1,807.0 s (1,685.8 + 121.2) | 51.4 GB | 11,920,701 | 2,146 MiB | 29,955,270,442 B | 0.16% |
| r6 | 10-09 20:34 | dcrd | dcroxide | 2,872.8 s | 388.5 | 5,563.7 s (4,510.1 + 1,053.6) | 286.4 GB | 61,445,588 | 1,851 MiB | 25,957,887,733 B | 0.13% |
| c1 | 10-10 02:21 | dcroxide | dcroxide | 1,087.9 s | 1,025.9 | 1,842.1 s (1,711.9 + 130.2) | 51.4 GB | 11,919,108 | 2,144 MiB | 29,950,384,728 B | 0.97% |
| c2 | 10-10 02:46 | dcrd | dcrd | 2,947.3 s | 378.7 | 5,660.4 s (4,559.3 + 1,101.1) | 282.5 GB | 60,877,979 | 1,851 MiB | 25,946,378,981 B | 0.97% |
| q1 | 10-10 03:40 | dcroxide | dcroxide | 1,072.2 s | 1,040.9 | 1,826.4 s (1,700.4 + 126.0) | 51.5 GB | 11,944,390 | 2,142 MiB | 29,949,851,699 B | 0.28% |
| q2 | 10-10 04:04 | dcroxide | dcrd | 1,061.1 s | 1,051.8 | 1,822.3 s (1,696.0 + 126.3) | 51.5 GB | 11,923,514 | 2,137 MiB | 29,953,537,836 B | 0.15% |
| q3 | 10-10 04:29 | dcrd | dcrd | 2,872.8 s | 388.5 | 5,589.1 s (4,517.1 + 1,072.0) | 286.6 GB | 61,637,006 | 1,852 MiB | 25,941,613,526 B | 0.13% |
| q4 | 10-10 05:23 | dcrd | dcroxide | 2,894.8 s | 385.5 | 5,653.8 s (4,549.6 + 1,104.2) | 293.7 GB | 63,367,492 | 1,848 MiB | 25,944,378,941 B | 0.12% |

"Other userland" is the CPU time of every process but the node, the
server and the harness, as a share of the machine's 32 threads.

**dcroxide synced 2.71x as fast as dcrd v2.1.6.** Over the four
cross-source runs of each (r1, r3, r5, q2 and r2, r4, r6, q4) the medians
are 1,058.6 s (17.6 minutes, 1,054.3 blk/s) against 2,863.9 s (47.7
minutes, 389.7 blk/s). All twelve runs exited 0 on the server's tip,
`8752fdc9…`.

**CPU.** The dcroxide process used 0.33x dcrd's CPU time, a median of
1,821.3 s against 5,566.6 s. That is the node process alone. Busy time
on the machine beyond the node, the server and other userland was
287.5–306.0 s in dcroxide's four runs and 85.9–97.1 s in dcrd's. The
harness did not break it down: it is kernel threads and interrupt
handling, not held to the node's cores, and the busiest threads it
listed were dm-crypt and btrfs write workers. With it counted the ratio
is 0.37x.

**Bytes.** dcroxide passed 0.18x the bytes to write calls, 51.4 GB
against 286.3 GB (the node's `wchar`). At the volume the medians were
81.0 GB written against 322.9 GB, 0.25x. That counter sits below the
filesystem, so it takes file data after zstd compression, the
filesystem's own writes and everything else written to the machine's
system volume. It is 25–32 GB above the node's own dirtied bytes for
dcroxide and about 22 GB above for dcrd, and it is specific to this
filesystem.

**The noise is far below the effect.** The four cross-source wall times
span 0.9% of their median for dcroxide and 1.6% for dcrd. Node CPU time
spans 0.8% and 2.0%, and bytes passed to write calls 0.3% and 4.6%. In
those eight runs other userland was 0.12–0.18% of the machine, no build
process was seen in any run, and the volume read at most 158 MB that
neither process asked for. The server used 152–169 s of CPU in every
run, about 14% of one core while dcroxide synced and under 6% while
dcrd did. One signal the harness recorded and did not gate on:
system-wide I/O pressure (`some`, avg10) averaged 48–53% through r2 to
r6 and read 80–95% at each one's first sample, before the node had done
any work, against under 1% in dcroxide's other runs and 5–6% in dcrd's.
Its source was not identified. The measured volume's counters show
nothing extra in those runs (at most 158 MB read that neither process
asked for), and wall times do not follow it.

**The source moves the result by about 1% or less.** The q round, one
run of each pairing:

| syncer | from dcroxide | from dcrd | from dcroxide / from dcrd |
|---|---:|---:|---:|
| dcroxide | 1,072.2 s (q1) | 1,061.1 s (q2) | 1.010 |
| dcrd | 2,894.8 s (q4) | 2,872.8 s (q3) | 1.008 |

Both daemons synced about 1% faster from the dcrd server. For dcrd that
is inside the cross-source runs' own spread (0.8% against 1.6%). For
dcroxide it is just outside it (1.0% against 0.9%): q1's 1,072.2 s is
above all four cross-source runs, and q1 was the least quiet run of the
round, 0.28% other userland against 0.12–0.15% in the other three, and
the one that began without the 300 s idle. Swapping the syncer moves
the result 2.7x. The 2026-07 row found the source moving a run by
1.6–8.8% against 2.2x for the syncer, though there each daemon was the
faster from its own kind.

**c1 and c2 are kept, and they are not quiet runs.** They took 1,087.9 s
and 2,947.3 s, 2.8% and 2.9% over the cross-source medians, and 1.5% and
2.6% over the same pairings in the q round. Other userland was 0.97% of
the machine in both, against 0.12–0.28% in the other ten runs: a
compositor, a browser, chat clients and a system monitor among the
largest, about a third of one thread in all.
c1's block server also read 3,142 MB from the volume during the run,
against at most 181 MB in the other eleven, so c2 is the cleaner of the
two. The harness's 3% threshold did not flag either. They suggest that
a machine this lightly used can still cost a sync 1.5–3% (one run of
each, each the slowest of its syncer's six), and they are the reason
the q round was run. They do not enter the cross-source medians,
spreads or ratios above.

**The lead grows along the chain, and most where full validation
begins.** Seconds to reach each height, the median of each direction's
four cross-source runs, interpolated between samples taken every 10 s:

| height | dcroxide | dcrd | dcrd / dcroxide |
|---:|---:|---:|---:|
| 100,000 | 54.3 | 72.7 | 1.34x |
| 250,000 | 136.0 | 202.3 | 1.49x |
| 500,000 | 286.0 | 478.6 | 1.67x |
| 750,000 | 537.4 | 1,055.7 | 1.96x |
| 900,000 | 703.2 | 1,526.2 | 2.17x |
| 1,000,000 | 829.9 | 1,899.8 | 2.29x |
| 1,026,597 | 864.6 | 2,003.5 | 2.32x |
| 1,116,035 | 1,058.6 | 2,863.9 | 2.71x |

The step is at the assume-valid block. Over 1,000,000 to 1,026,597 the
medians were 761 blk/s (739–783) for dcroxide and 254 (250–263) for
dcrd. Over the 89,438 fully validated blocks after it they were 461.0
(458.4–463.5) and 104.0 (103.0–104.5), 4.4x apart, and those blocks took
18% of dcroxide's wall time and 30% of dcrd's. The node's 16 threads
were 31–33% busy there for dcroxide, about five threads, and 16% for
dcrd, under three, against 6–7% and 10% just before it. Windows that
straddle that block mix the two regimes: after 1,000,000 the medians
were 506.8 and 120.4 blk/s. Over m2's window, 916,000 to the tip,
dcroxide ran at 593.0 blk/s (584.7–599.2) on m3 and dcrd v2.1.6 at 156.5
(154.0–157.3). On m2 the layout-3 tail ran at a median of 482.1 blk/s on
four cores and slower storage, and dcrd `6f6cf21b` at 147.6 two days
before. That is another machine and other sessions, so none of these
pairs is a ratio.

**Flushes.** dcroxide made 134 metadata flushes in every run: 133
during the timed sync and one at shutdown, after the clock stopped. In
the four cross-source runs the 133 took 159.8–170.5 s in all, 15.1–16.1%
of wall time. The median flush took 1.30–1.37 s and the longest
2.44–2.97 s. Of the flush time, the redb commit was 101.7–112.7 s, the
insert loop 35.7–36.0 s, the block-file sync 3.1–3.4 s and the
exists-address participant 18.5–19.1 s. On m1 on 2026-08-16 the same
sync made 130 flushes with a median of 26.9 s, and flush windows
occupied 68% of wall time.

**Memory and shutdown.** Peak resident memory was 2,129–2,146 MiB for
dcroxide and 1,848–1,852 MiB for dcrd over all twelve runs. SIGINT at the
target took 1.0–1.3 s for dcroxide, most of it that last flush, and
0.2 s for dcrd.

**Storage at 1,116,035** (apparent bytes, whole appdata, medians of the
four cross-source runs). dcroxide 29,953,302,380 B (27.90 GiB). r1's
directory holds 19,202,596,910 B of block files (17.884 GiB) and a
10,750,377,984 B `metadata.redb` (10.012 GiB). dcrd v2.1.6
25,945,551,274 B (24.16 GiB), so dcroxide's is **1.15x** dcrd's. The dcrd
run directories were deleted before their split was read. The dcrd
server's block files total the same 19,202,596,910 B: 35 of the 36
files are byte-identical to r1's, and the other holds the same blocks
in a different order over an 8.6 MB span. That leaves about 6.28 GiB for
v2.1.6's metadata leveldb, `utxodb` and logs. The 2026-08-15 pair on m1
was 33.58 against 23.69 GiB, 1.42x, at 1,100,392.

**The WAN arithmetic, with these rates.** The preamble of "Sync
throughput" predicts that the in-flight window caps a sync once the
round trip passes about nine blocks' processing time. Here a block took
dcroxide 0.949 ms averaged over the chain and 2.17 ms after the
assume-valid block, and dcrd 2.566 ms and 9.62 ms, which puts that
round trip near 8.5 and 19.5 ms for dcroxide and 23.1 and 86.6 ms for
dcrd. Bandwidth is a second bound: 19.2 GB of blocks in 1,058.6 s is a
mean of 145 Mbit/s. Still a prediction: no delayed-link arm has been
run.

**What this does not establish.**

- Nothing about dcrd `6f6cf21b`, the parity target. dcrd here is the
  release, and the pin was not run on m3.
- Nothing about m1. This does not re-measure the 1.29x row, and it is
  not a later point on that row's curve: the machine, the dcrd version
  and the harness all differ.
- Not where the difference comes from. dcrd spent 1,039–1,104 s of its
  CPU time in the kernel against dcroxide's 121–126 s. It passed 5.6x
  the bytes to write calls, and in each of its six runs it read
  12.6–12.9 TB through 418–421 million read calls, nearly all of it from
  the page cache (at most 64 MB came from storage), against dcroxide's
  25.2–25.3 GB over 2.4–2.5 million. Neither daemon was profiled, and
  neither was run with `--noexistsaddrindex`, so the index's share of
  dcrd's time is not known.
- Nothing about a busy machine, fewer cores or slower storage. m3's
  volume is btrfs with zstd compression on an encrypted mapping that
  passes no discards, so the drive is never told that a deleted run's
  blocks are free. The directions alternated, so both were exposed to
  any drift from that. dcrd's four cross-source times rise 1.4% from
  first to last and dcroxide's 0.5%, the second inside those runs' own
  0.9% spread; four runs cannot tell either from noise, and both are
  small against 2.7x.

Raw: the comparison's `runs.jsonl` rows labelled `r1` to `r6`, `c1`,
`c2` and `q1` to `q4`, with per-run samples (height, load, the busy
share of the node's cores and of the machine, pressure, drive
temperature), dcroxide's per-flush logs (`DCROXIDE_DB_FLUSHLOG`), both
daemons' logs, and `smoke.jsonl` for the two 20,000-block runs that
checked the harness.

## The parity commit, the index off, two levers and a full replay (2026-10-10)

The section above left four things unmeasured on m3: dcrd at the parity
commit, either daemon with the exists-address index off, the tuning
levers under the current layouts, and a replay that validates every
block. All four were run later on 2026-10-10, between 16:24 and 20:54,
in the same harness with the same pinning, clock and quiet gate, each
sync from genesis to 1,116,035 over loopback from a block server run by
the other daemon. One thing in the harness changed: a run is now marked
disturbed above 0.5% other userland, not 3%, after c1 and c2 above. No
run was marked.

The binaries:

- **dcroxide** is the `c128a93` binary of the section above.
- **dcrd v2.1.6** is the release binary of the section above.
- **dcrd `6f6cf21b`** (2.2.0-pre, the parity target) is built from that
  commit with the flags of its own release image: go1.26.2,
  `CGO_ENABLED=0`, `-trimpath`, `-tags safe,netgo,timetzdata`,
  `-ldflags "-s -w"`.
- **dcroxide-bench** is a `cargo build --release` at `337779d` under
  rustc 1.98.1. The crates it links are unchanged since `c128a93`.

Nine steps in this order, each after a `sync` and a 300 s idle but the
first: p0, the corpus export, par1, the replay, off-dcroxide, off-dcrd,
overlay800, utxo1200, par2. p0 began about two minutes after the last of
three 20,000-block smoke runs. Its data directory became the dcroxide
block server and the source of the corpus.

| run | started | syncer | source | settings | wall | blk/s | node CPU time (user + sys) | written | peak RSS | data directory | other userland |
|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| p0 | 16:24 | dcroxide | dcrd | defaults | 1,060.4 s | 1,052.4 | 1,828.6 s (1,697.0 + 131.6) | 51.5 GB | 2,148 MiB | 29,953,533,805 B | 0.23% |
| par1 | 16:55 | dcrd `6f6cf21b` | dcroxide | defaults | 2,909.8 s | 383.5 | 5,542.0 s (4,445.3 + 1,096.7) | 292.6 GB | 1,846 MiB | 25,942,870,133 B | 0.17% |
| off-dcroxide | 18:28 | dcroxide | dcrd | `--noexistsaddrindex` | 880.8 s | 1,267.0 | 1,656.5 s (1,547.5 + 109.0) | 43.8 GB | 1,996 MiB | 27,792,596,806 B | 0.18% |
| off-dcrd | 18:50 | dcrd v2.1.6 | dcroxide | `--noexistsaddrindex` | 1,247.8 s | 894.4 | 2,629.2 s (2,433.4 + 195.8) | 102.8 GB | 1,849 MiB | 23,826,540,900 B | 0.15% |
| overlay800 | 19:17 | dcroxide | dcrd | `DCROXIDE_DB_OVERLAY=800` | 1,068.3 s | 1,044.7 | 1,816.5 s (1,685.8 + 130.7) | 51.6 GB | 2,146 MiB | 29,975,827,864 B | 0.17% |
| utxo1200 | 19:42 | dcroxide | dcrd | `--utxocachemaxsize=1200` | 1,019.5 s | 1,094.7 | 1,808.6 s (1,720.0 + 88.6) | 34.2 GB | 3,857 MiB | 29,988,844,341 B | 0.17% |
| par2 | 20:06 | dcrd `6f6cf21b` | dcroxide | defaults | 2,869.8 s | 388.9 | 5,505.2 s (4,432.5 + 1,072.7) | 293.9 GB | 1,851 MiB | 25,954,873,271 B | 0.15% |

All seven syncs exited 0 on the server's tip, `8752fdc9…`. p0 is the
session's check against the section above: 1,060.4 s, inside the
1,055.8–1,065.0 s of the four runs there.

One condition differs from the section above. In par1, off-dcrd and par2
the dcroxide server read 19.5, 19.1 and 18.7 GB from the volume during
the run, about the whole of its 19.2 GB of block files, where in the
four dcrd runs above it read at most 12 MB. Its data was read through
once before each run as before, and that read took 11.4–11.6 s against
2.1–6.8 s before those four, so the page cache was not holding it
between runs either. Why was not established: memory was not sampled.
One thing is known to have differed in this session: the 19 GB corpus
was written to the same volume and read back from it by the replay. The
server's data was the directory of the session's first run in both, r1's
above and p0's here. The reads were issued by the server process, which
is pinned to its own four cores, at a mean of 7 to 15 MB/s; the kernel's
part of them (decryption, checksums) is not pinned and was not broken
down. Whether they cost the syncing dcrd anything was not measured. If
they did, they count against dcrd in those three runs. The dcrd server
read at most 2 MB in the four dcroxide runs. The syncing nodes read a
little more of their own files from the volume as well: 83–88 MB in the
three dcrd runs against at most 1 MB in the four above, and 208 MB in
overlay800 against 0–45 MB in the five default runs, all of which ended
before the corpus was written; off-dcroxide read 25 MB and utxo1200 56
MB.

**The parity commit syncs like the release.** dcrd `6f6cf21b` took
2,909.8 s and 2,869.8 s, three hours apart, against 2,848.8–2,894.8 s
for v2.1.6 above. One run is inside that range and one 0.5% over its
slowest. Their mean, 2,889.8 s, is 0.9% over the release's median, and
dcroxide's 1,058.6 s is 2.73x as fast. Node CPU time was 5,542.0 s and
5,505.2 s against the release's median of 5,566.6 s, and 292.6 GB and
293.9 GB went to write calls against 286.3 GB. So the comparison above
holds against the commit this port tracks.

**Most of the gap is the exists-address index.** One run of each daemon
with `--noexistsaddrindex`, set against the medians above with it on:

| | index on | index off | the index costs |
|---|---:|---:|---:|
| dcroxide | 1,058.6 s | 880.8 s | 177.8 s, 16.8% of its sync |
| dcrd v2.1.6 | 2,863.9 s | 1,247.8 s | 1,616.1 s, 56.4% of its sync |
| dcrd / dcroxide | 2.71x | 1.42x | |

Of the 1,805.3 s between the two daemons at their defaults, 1,438.3 s
(80%) is the difference in what the index costs each, and 367.0 s
remains with it off. What remains is a net: dcrd is 89.6 s ahead at
the assume-valid block and dcroxide gains 456.6 s after it:

| | to block 1,026,597 | the 89,438 blocks after it |
|---|---:|---:|
| dcroxide, index on | 864.6 s | 194.0 s (461.0 blk/s) |
| dcroxide, index off | 708.1 s | 172.7 s (517.9 blk/s) |
| dcrd v2.1.6, index on | 2,003.5 s | 860.4 s (104.0 blk/s) |
| dcrd v2.1.6, index off | 618.5 s | 629.3 s (142.1 blk/s) |

With the index off dcrd is the faster daemon up to the assume-valid
block, by 1.14x, and dcroxide the faster over the fully validated blocks
after it, by 3.6x. The index-on figures are medians of four runs,
interpolated between 10 s samples as above; the index-off figures are
one run each. After that block the node's 16 threads were 35% busy for
dcroxide with the index off and 16% for dcrd, about 5.6 threads and 2.5,
against 31–33% and 16% with it on.

The counters move with it:

| | node CPU time | passed to write calls | read calls | flushes | peak RSS | data directory |
|---|---:|---:|---:|---:|---:|---:|
| dcroxide, index on | 1,821.3 s | 51.4 GB | 25.2–25.3 GB in 2.4–2.5 million | 133 in 159.8–170.5 s | 2,129–2,146 MiB | 27.90 GiB |
| dcroxide, index off | 1,656.5 s | 43.8 GB | 20.1 GB in 1.3 million | 133 in 115.5 s | 1,996 MiB | 25.88 GiB |
| dcrd v2.1.6, index on | 5,566.6 s | 286.3 GB | 12.6–12.9 TB in 418–421 million | | 1,848–1,852 MiB | 24.16 GiB |
| dcrd v2.1.6, index off | 2,629.2 s | 102.8 GB | 528.4 GB in 39.3 million | | 1,849 MiB | 22.19 GiB |

The index-on rows are the medians and ranges of the section above, and
the index-off rows one run each. The index is about 2 GiB on disk in
either daemon: 2.01 GiB for
dcroxide's layout and 1.97 GiB for dcrd's. With it off, the metadata
beyond the 17.884 GiB of block files is 8.00 GiB under dcroxide and
4.31 GiB under dcrd. dcrd's 12.6–12.9 TB of reads through read calls,
recorded above, are the index's: without it dcrd read 528.4 GB.

The index's part of dcroxide's flush time is larger here than on m2's
tail. The 133 flushes took 115.5 s with the index off against
159.8–170.5 s with it on above and 164.3 s in p0: 1.38–1.48x. Of the
44.3–55.0 s between them, the participant's `contribute` call is
18.5–19.1 s and the rest is in the commit phase, 76.8 s against
101.7–112.7 s. The insert loop (35.7 s against 35.7–36.0 s) and the
block-file sync (3.0 s against 3.1–3.4 s) do not move. "Exists-address
index layout 3" above set the fallback's flush-time test at 1.15x the
floor's and measured 0.74x on m2's tail. That test was not run again:
this is another machine, a whole chain and one index-off run. More than
two thirds of the 177.8 s the index costs here is outside the flushes
and is not attributed.

> **Note (2026-10-12): a wait that is likely part of it has since
> been timed, on later code.** The indexes moved to a thread of their
> own on 2026-10-11, and a timer added on 2026-10-12 (`a83f9a1`) totals
> the waits for the database's writer. In one default sync of that code
> the threads other than the index thread waited 74.9 s of 673.8 s for
> the writer, at least 62.0 s of it not behind a flush the index thread
> ran. The timer does not record who held the writer; the index
> thread's per-block transactions are the likely holder. With the
> index's per-block work done before its thread takes the writer
> (`6271436` and the two commits before it) the wait was 30.7 s and the
> sync 628.0 s. What the index costs a sync on that code was not
> measured: no run with `--noexistsaddrindex` was made on 2026-10-12.
> See "Eleven changes, a background commit not kept and a pool gate"
> below.

For scale, on m2's 200,000-block tail the same layout ran 3.8% slower
with the index on than off (482.1 against 501.1 blk/s), a gap that
section called inside its noise. From genesis on m3 the index is 16.8%
of the sync, 177.8 s against a spread of 9.2 s over five default runs.

**Two levers, re-measured.** One sync each on dcroxide, set against the
four-run median of 1,058.6 s above and against the range of five default
runs, those four and p0:

| setting | wall | against the four-run median of 1,058.6 s | flushes | passed to write calls | written at the volume | peak RSS | SIGINT at the target |
|---|---:|---:|---:|---:|---:|---:|---:|
| defaults | 1,055.8–1,065.0 s | | 133 in 159.8–170.5 s | 51.4–51.6 GB | 75.9–83.7 GB | 2,129–2,148 MiB | 1.0–1.3 s |
| `--utxocachemaxsize=1200` | 1,019.5 s | 3.7% faster | 92 in 82.3 s | 34.2 GB | 41.8 GB | 3,857 MiB | 2.8 s |
| `DCROXIDE_DB_OVERLAY=800` | 1,068.3 s | 0.9% slower | 121 in 182.3 s | 51.6 GB | 99.8 GB | 2,146 MiB | 1.3 s |

The larger UTXO cache still helps, by 3.7% in this sync where "Lever
sweeps" above measured 12% over full-validation replays on m1 in
2026-08. It makes 41 fewer flushes, halves the time in them and passes a
third fewer bytes to write calls, for 1.7 GiB more resident memory. The
larger overlay did not help here: its run is slower than each of those
five, with 12 fewer flushes that took longer in all and about a quarter
more bytes written at the volume. "Overlay flush cadence: +12.7% on IBD"
above measured 12.7% for it over syncs on m1 in 2026-08, under the entry
accounting that changed on 2026-09-23. Both are one run, and the 3 s by
which the overlay run exceeds the slowest of the five is inside what one
run can show.

**A full replay.** `dcroxide-bench export` wrote the main chain of p0's
data directory, blocks 1 to 1,116,035, to a 19,198,132,458 B corpus, and
`dcroxide-bench replay --addrindex` drove it into a fresh chain on the
node's 16 threads. A replay cannot use assume-valid (see "IBD profiling
attempt" above), so every block is validated in full:

| date | machine | commit | corpus | result |
|---|---|---|---|---|
| 2026-10-10 | m3 | `337779d` | mainnet, blocks 1 to 1,116,035, 8,034,100 regular transactions | **1,909.41 s, 584.5 blk/s**, exit 0 at tip height 1,116,035. Exists-address index on; the tool's default caches (100 MiB overlay ceiling, 1,024 MiB page cache, default UTXO cache). 4.4 of the 16 threads busy on average, 11,875 MiB peak RSS, 51.1 GB passed to write calls, 90.8 GB written at the volume, work directory 29,943,271,470 B (27.89 GiB) |

It is the first full replay on record since 2026-08 and the first over
the height-first keys, layout 3 and the parity pin at `6f6cf21b`. Its
50,000-block intervals fell from 1,393.1 blk/s over the first to
410.3–464.5 over the last five. The 1,909.41 s is the tool's own figure
for the replay; the harness, which polls every 10 s, saw the process
gone 1,921.2 s after starting it, and the corpus was read from storage.
It is a replay and not a sync, so its time is not to be set against the
daemons' above. Its peak resident memory, read from `VmHWM` by the tool,
is 5.5x the syncing daemon's 2,148 MiB; what holds it was not examined.

**What this does not establish.**

- Nothing about m1, and nothing about fewer cores, slower storage or a
  delayed link: this is the same machine over loopback.
- The index-off and lever figures are one run each. The default runs
  they are set against span 0.9% for dcroxide and 1.6% for dcrd.
- Not what the two regimes consist of. Neither daemon was profiled: why
  dcrd is the faster up to the assume-valid block with the index off,
  and dcroxide 3.6x the faster after it, is not known.
- Not that the index's cost to dcrd is inherent to its layout. dcrd was
  run at its defaults for every other setting. It exposes no setting
  for the metadata cache its index goes through (100 MiB, compiled in),
  and a build with a larger one was not tried.
- The replay shows the chain engine accepts every block of this chain
  under full validation. It does not test that it rejects what dcrd
  rejects.

Raw: the comparison's `runs.jsonl` rows labelled `p0`, `par1`, `par2`,
`off-dcroxide`, `off-dcrd`, `overlay800` and `utxo1200`, with per-run
samples, dcroxide's per-flush logs and both daemons' logs as above;
`replays.jsonl` and the replay's own output; and `smoke2.jsonl` for the
three 20,000-block runs that checked the new variants.

## Five changes on the block-processing thread (2026-10-11)

"The parity commit, the index off, two levers and a full replay" above
left the two regimes of a sync unexplained and neither daemon profiled.
On 2026-10-11 five changes were made to what a reading of the code
showed on the one thread that carries a sync up to the assume-valid
block, and the code before them was profiled on m3. The five were
chosen, and the first three built, before the profile was taken; what it
shows is under "The profile" below.

Each was measured with one default sync, and the last with two, in the
harness of the two sections above: mainnet from genesis to 1,116,035 over loopback from the
dcrd v2.1.6 block server, the same pinning, clock and quiet gate, and a
300 s idle before every run but pf-base, s-AGBC and s-base, each the
first of the batch it was queued in. The steps are cumulative, so each
run is set against the one before it. Three runs were added at the end
of the session, after a review of this section: the `74168e8` binary
without the profiler (s-base), the fourth change as committed
(s-AGBC-2), and the last binary a second time (s-final-2).

The changes, in the order measured, all on base `74168e8` (the commits
that carry them follow it):

1. **The block-file checksum.** The CRC-32C over a block record used the
   `crc` crate's one-table form, a byte a step. It now uses the same
   crate's sixteen-table form. The values are identical.
2. **The BLAKE-256 rounds.** The compression function looped over the
   permutation table. Its fourteen rounds are now written out with each
   row a constant. A microbenchmark (one thread, `sum256` over a fixed
   buffer, three passes, thin LTO and one codegen unit as the node is
   built; the program is not in the tree) measured 343.0–343.3 MB/s
   before and 559.6–560.2 after on 16 KiB inputs, 263.7–263.9 and
   428.4–428.7 on 250-byte inputs, and 168.0–168.1 and 267.2–267.5 on
   64-byte inputs.
3. **The ticket-purchase list.** During initial sync, every connect
   past stake-enabled height read the block `ticket_maturity` below it
   back from the block files to list its ticket purchases, that block's
   body having already left the recent window (the open arm under "Sync
   throughput"). The chain now keeps that list for the last
   `2 * ticket_maturity` blocks accepted.
4. **One hash per transaction.** A block's transactions were serialized
   and hashed four times between `Chain::process_block` and the node's
   connected-block handling. For a block connected by the call that
   delivered its data, as the blocks of a sync are, they are hashed once
   and the hashes handed down. PARITY.md lists what is still hashed
   again.
5. **The index thread.** The optional indexes were updated on the
   block-processing thread. The daemon now queues each block's
   notification for one index thread, as dcrd does.

| run | started | changes in the binary | wall | blk/s | node CPU time (user + sys) | bytes read, in calls | peak RSS | to block 1,026,597 | after it | flush time | other userland |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| pf-base | 03:51 | none (profiled) | 1,110.9 s | 1,004.7 | 2,075.0 s (1,654.8 + 420.2) | 25.3 GB in 2.44 million | 2,142 MiB | 880.0 s | 230.9 s | 133 in 169.3 s | 0.46% |
| s-base | 08:39 | none | 1,058.3 s | 1,054.5 | 1,820.9 s (1,695.3 + 125.6) | 25.2 GB in 2.44 million | 2,147 MiB | 866.0 s | 192.3 s | 133 in 163.2 s | 0.06% |
| s-A | 04:16 | the checksum table | 1,015.3 s | 1,099.2 | 1,769.0 s (1,642.0 + 127.0) | 25.3 GB in 2.44 million | 2,146 MiB | 824.9 s | 190.4 s | 133 in 172.5 s | 0.10% |
| s-AG | 04:39 | + the BLAKE-256 rounds | 912.8 s | 1,222.7 | 1,550.4 s (1,424.9 + 125.5) | 25.3 GB in 2.45 million | 2,140 MiB | 740.8 s | 172.0 s | 133 in 172.9 s | 0.07% |
| s-AGB | 05:01 | + the ticket-purchase list | 893.7 s | 1,248.8 | 1,529.3 s (1,404.4 + 124.9) | 6.1 GB in 1.33 million | 2,145 MiB | 724.0 s | 169.7 s | 133 in 175.9 s | 0.07% |
| s-AGBC | 06:41 | + one hash per transaction, as first built | 836.6 s | 1,334.0 | 1,471.7 s (1,347.7 + 124.0) | 6.1 GB in 1.34 million | 2,139 MiB | 673.2 s | 163.4 s | 133 in 173.2 s | 0.06% |
| s-AGBC-2 | 09:03 | the same four, as committed | 820.3 s | 1,360.5 | 1,462.8 s (1,341.3 + 121.5) | 6.1 GB in 1.34 million | 2,146 MiB | 659.6 s | 160.7 s | 133 in 162.1 s | 0.07% |
| s-final | 07:01 | + the index thread | 759.1 s | 1,470.3 | 1,465.5 s (1,340.7 + 124.8) | 6.1 GB in 1.32 million | 2,621 MiB | 604.1 s | 155.0 s | 133 in 167.9 s | 0.06% |
| s-final-2 | 09:24 | the same binary again | 756.2 s | 1,475.9 | 1,468.1 s (1,343.6 + 124.5) | 6.1 GB in 1.33 million | 2,624 MiB | 603.0 s | 153.2 s | 133 in 163.2 s | 0.07% |

Every run exited 0 on the server's tip, `8752fdc9…`, and none was marked
disturbed. pf-base is the `74168e8` binary under two `perf record`
recorders and is not a timing: the node's system time was 420.2 s where
the other runs have 121.5–127.0 s. The bytes-read column is `rchar` and
`syscr`; the bytes passed to write calls were 51.5–51.6 GB in every run.
The time to block 1,026,597 is interpolated between the two samples
either side of it, as in the two sections above: the samples are about
10 s apart, timed to the whole second, with heights from a once-a-second
poll. "After it" is the wall time less that. Neither column is good to
the 0.1 s shown.

**The sync went from 1,058.3 s to 759.1 s and 756.2 s, 28.3% and 28.5%
less, in one session.** By step:

| change | this run | the one before | gain |
|---|---:|---:|---:|
| the checksum table | 1,015.3 s | 1,058.3 s (s-base) | 43.0 s |
| the BLAKE-256 rounds | 912.8 s | 1,015.3 s | 102.5 s |
| the ticket-purchase list | 893.7 s | 912.8 s | 19.1 s |
| one hash per transaction | 820.3 s (s-AGBC-2) | 893.7 s | 73.4 s |
| the index thread | 759.1 s and 756.2 s | 820.3 s | 61.2 s and 64.1 s |

Each gain is one run against one run, the last two runs against one, all
in one session. Four things bear on how far one run can be trusted
here. s-base, the code before the changes run without the profiler, took
1,058.3 s, where the four runs of 2026-10-09 and 2026-10-10 that the
sections above rest on have a median of 1,058.6 s and five default runs
spanned 9.2 s. The two runs of the last binary are 2.9 s apart. And the
fourth change was run in two forms. s-AGBC is that change as first
built, 836.6 s. Review then made the ticket-purchase list take the
hashes already computed, where it had hashed each block's purchases
again, and added an assertion to the connected-block handling. s-AGBC-2
is a build of the fourth commit's tree, which has both: 820.3 s. The
16.3 s between the two forms is one run against one run. Of it, node CPU
time accounts for 8.9 s (1,471.7 s and 1,462.8 s), and the summed flush
time differs by 11.1 s (173.2 s and 162.1 s). Last, the three runs added
at the end have the three lowest flush sums of the eight, 162.1–163.2 s
against 167.9–175.9 s in the five before them, so the fourth step's
73.4 s, which sets a run of the last batch against one four hours
earlier, may carry some of that difference. The last binary also has a
floor of one on the index queue's depth, which a sync does not reach.

s-AGBC-2 was built from the tree of the fourth commit. Every other
binary was built from the working tree as its change was finished,
before the commits that carry the changes were made. s-A and s-AG
predate the review of the first two changes, which added tests and
comments, moved the `crc` requirement to 3.4 and bound the BLAKE-256
round's permutation row by reference instead of by value. The
microbenchmark's program was built before that review too. None of it
changed the code the runs measure: disassembled, the compression
function is the same 2,327 instructions in the s-AG binary, built
before, and in the s-AGB, s-AGBC and s-final binaries, built after, and
the lock file already held `crc` 3.4.0. What changed after the s-final
binary is tests, comments and a counter compiled only into the
blockchain crate's unit tests.

Up to the assume-valid block the sync took 604.1 s and 603.0 s where
s-base took 866.0 s, and the fully validated blocks after it 155.0 s and
153.2 s against 192.3 s. Node CPU time fell from 1,820.9 s to 1,465.5 s
and 1,468.1 s. The index thread moved work and did not remove it: CPU
time is the same without it (1,462.8 s in s-AGBC-2), and up to the
assume-valid block an average of 1.15 and 1.17 of the node's 16 threads
were busy where s-AGBC-2 had 1.06. The ticket-purchase list shows in the
read counters: 25.3 GB in 2.45 million calls before it, 6.1 GB in 1.33
million after, the difference being one read of every block file record.
The 133 flushes are unchanged in number and took 162.1–175.9 s in the
eight timed runs, which in the two runs of the last binary is 22% of the
sync.

Peak resident memory rose with the index thread, from 2,139–2,147 MiB in
the seven runs without it to 2,621 and 2,624 MiB. What holds it was not
examined.

**The profile.** pf-base recorded user-space cycles at 499 Hz
(`perf_event_paranoid` is 2, so kernel time is not in it). From the
start of the recording up to the assume-valid block: BLAKE-256
compression 27.1%, `memcmp` 14.6%, the allocator 13.5%, reading a block
back 3.8%, the block-store commit 3.8%, `memcpy` 3.2%, and nothing else
above 2%. Those were recomputed from the recording during review. The
saved aggregate leaves out the first 11 s and the allocator's `realloc`
and `calloc`, and gives 14.7% for `memcmp` and 13.2% for the allocator.
Over the fully validated blocks, on all threads: BLAKE-256
compression 48.4%, secp256k1 about 38%. A second recorder took DWARF
call chains at 49 Hz, and they almost never reached the node's own code:
up to the assume-valid block, 5,523 of the 5,551 `memcmp` samples carry
no caller frame. Why the chains end there was not established. It is not
a lack of unwind tables, which the profiled binary has. So the callers
of `memcmp` and the allocator were not established.

**A full replay.** `dcroxide-bench replay --addrindex`, built from the
sources of the s-final binary, drove the corpus of 2026-10-10 (blocks 1
to 1,116,035, 19,198,132,458 B) into a fresh chain on the node's 16
threads. A replay cannot use assume-valid, so every block is validated
in full:

| date | machine | commit | corpus | result |
|---|---|---|---|---|
| 2026-10-11 | m3 | `74168e8` and the five changes | mainnet, blocks 1 to 1,116,035, 8,034,100 regular transactions | **1,746.67 s, 638.9 blk/s**, exit 0 at tip height 1,116,035. Exists-address index on; the tool's default caches (100 MiB overlay ceiling, 1,024 MiB page cache, default UTXO cache). 4.4 of the 16 threads busy on average, 12,607 MiB peak RSS, 51.1 GB passed to write calls, work directory 29,986,390,062 B (27.93 GiB) |

It is the check that the five changes accept the whole chain with
nothing skipped: every script ran over the rewritten BLAKE-256 rounds,
and every block went through `Chain::process_block`, so through the
handed-down hashes and the ticket-purchase list. It does not exercise
the index thread, because a replay calls the index subscriber inline, on
the thread that connects the blocks. It is not a clean timing. Compilers
and test runs used the machine's other 16 threads during it, and the
harness saw one in about a third of its 10-second samples. So the
1,746.67 s is not to be set against the 1,909.41 s of 2026-10-10 as a
measured gain, and the bytes written at the volume, which include
theirs, are left out. Its 50,000-block intervals fell from 1,541.4 blk/s
over the first to 412.6–509.5 over the last five.

**What this does not establish.**

- Nothing about m1 or m2, fewer cores, slower storage or a delayed
  link. dcrd was not run in this session: set against its 2,863.9 s
  above, 759.1 s and 756.2 s are 3.77x and 3.79x, across sessions.
- Each step is one run against one run, and the last is two runs
  against one. The order of the steps matters to their sizes:
  the checksum table and the ticket-purchase list both remove checksum
  work, and with the faster hash already in, the fourth step is expected
  to be smaller than it would have measured first; no other order was
  run.
- Not where the rest goes. The profile names `memcmp` and the allocator
  without their callers, and the flushes, 22% of the sync now, were not
  touched.
- Not the index thread's cost to the block thread. Both commit under the
  database's writer, and how long each waits for the other was not
  measured.
- Not a sync with `--noexistsaddrindex` or `--assumevalid=0`, and no
  repeat of the tuning levers, on this code.

> **Note (2026-10-12), on the index thread's cost to the block
> thread:** measured from `a83f9a1` on, which times every wait for the
> database's writer. In one default sync of that code the threads
> other than the index thread waited 74.9 s for the writer in 401,906
> waits, and the index thread 0.02 s in 295. With the three commits
> that follow it, which end at `6271436`, the two waited 30.7 s and
> 30.4 s. See "Eleven changes, a background commit not kept and a pool
> gate" below.

Raw: the comparison's `runs.jsonl` rows labelled `pf-base`, `s-base`,
`s-A`, `s-AG`, `s-AGB`, `s-AGBC`, `s-AGBC-2`, `s-final` and `s-final-2`,
with per-run samples, flush logs and node logs as above; the `perf record` data of pf-base and its
flat reports; the microbenchmark's two outputs; `replays.jsonl` and the
replay's own output; and `smoke3.jsonl` for the short runs, which
checked the binaries of pf-base, s-AG, s-AGBC and s-final and two builds
that were not measured: an earlier one of the third step and an earlier
one with all five changes. The binaries of s-A, s-AGB and s-AGBC-2 had
no short run.

## Shared commits for UTXO-cache flushes, the filesystem's share and a delayed link (2026-10-11, afternoon)

"Five changes on the block-processing thread" above left the flushes
alone, at 22% of a sync. In the runs on record about 120 of the 133 are not
the overlay's own: each is the durable commit that ended a UTXO-cache
flush the cache's size limit had tripped, as dcrd makes its block
database durable before every UTXO-cache flush (`flushBlockDB`,
`utxocache.go:708-716`). On the afternoon of 2026-10-11, in a second
session on m3 in the same harness, a prototype that lets those flushes'
rows wait for the next commit was measured, the change was then made
properly and the code with it was measured. Two other things were
measured in that session: the same sync on a data directory without
copy-on-write, and syncs through a delayed link.

**The deciding runs.** The prototype is `7d31abb` with one condition
changed: a UTXO-cache flush forced a durable commit only when it was
forced itself or when the cache was under its size limit, so that the
120 s interval had tripped it. It was run with the overlay ceiling
raised through `DCROXIDE_DB_OVERLAY`: at the default 100 MiB the
overlay's own trigger, at 70 MB retained, would fire about as often as
the UTXO-cache flushes had (9.16 GB went through the overlay in a sync),
so little would be shared. That was not run. One default sync each, with
the 300 s idle before each but the first of the two batches (f-head and
f-proto-200):

| run | started | code | overlay ceiling | data directory | wall | flushes | flush time | outside the flushes | node CPU time (user + sys) | passed to write calls | written at the volume | peak RSS | other userland |
|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| f-head | 14:26 | `7d31abb` | 100 MiB (default) | as created | 775.6 s | 133 | 177.8 s | 597.8 s | 1,481.8 s (1,350.1 + 131.7) | 51.4 GB | 91.6 GB | 2,635 MiB | 0.14% |
| f-proto | 14:46 | prototype | 300 MiB | as created | 724.6 s | 52 | 104.8 s | 619.8 s | 1,462.3 s (1,364.7 + 97.6) | 39.1 GB | 53.4 GB | 3,284 MiB | 0.07% |
| f-proto-200 | 15:40 | prototype | 200 MiB | as created | 736.9 s | 63 | 115.3 s | 621.6 s | 1,466.7 s (1,368.2 + 98.5) | 40.7 GB | 59.4 GB | 3,271 MiB | 0.07% |
| f-head-nocow | 15:23 | `7d31abb` | 100 MiB (default) | no copy-on-write | 736.8 s | 133 | 144.0 s | 592.8 s | 1,435.8 s (1,341.7 + 94.1) | 51.4 GB | 52.3 GB | 2,621 MiB | 0.07% |
| f-proto-nocow | 15:05 | prototype | 300 MiB | no copy-on-write | 707.3 s | 52 | 86.7 s | 620.6 s | 1,450.5 s (1,365.5 + 85.0) | 39.2 GB | 40.4 GB | 3,098 MiB | 0.07% |

Every run exited 0 on the server's tip and none was marked disturbed.

- **On the data directory as created the prototype took 724.6 s where
  `7d31abb` took 775.6 s, 51.0 s or 6.6% less.** The flushes fell from
  133 to 52 and their time from 177.8 s to 104.8 s, 73.0 s. The time
  outside the flushes rose by 22.0 s, of which 14.6 s is user CPU time;
  what the node spends it on was not established.
- **Without copy-on-write it took 707.3 s where `7d31abb` took 736.8 s,
  29.5 s or 4.0% less.** The same 52 flushes took 86.7 s against 144.0 s,
  and the time outside them rose by 27.8 s.
- **It passed 39.1 GB to write calls where `7d31abb` passed 51.4 GB**,
  24% less, and 53.4 GB reached the volume against 91.6 GB.
- **Peak resident memory rose by 649 MiB, to 3,284 MiB**, and by 636 MiB
  with a 200 MiB ceiling, so the ceiling is not what holds it. What does
  was not established.
- **A 200 MiB ceiling kept 76% of the gain**: 736.9 s, 38.7 s under
  `7d31abb`, with 63 flushes, and the same peak memory as 300 MiB. So
  the default was set at 300 MiB.

Each of those is one run against one run. f-head is the code of the
morning's s-final and s-final-2 (759.1 s and 756.2 s) in another build
of the same sources, and took 775.6 s: 2.2% and 2.6% more, with 177.8 s
of flush time against 167.9 s and 163.2 s. So the afternoon's runs are
set against f-head and not against the morning's.

**The filesystem's share.** m3's data volume is btrfs with zstd
compression over an encrypted mapping. f-head-nocow and f-proto-nocow
ran in a data directory created with the no-copy-on-write attribute
(`chattr +C`), which turns off copy-on-write, checksums and compression
for the files made in it. `7d31abb` took 736.8 s there against 775.6 s,
38.8 s or 5.0% less: its 133 flushes took 144.0 s against 177.8 s, the
node's system time fell from 131.7 s to 94.1 s, and the volume took 52.3
GB against 91.6 GB for the same 51.4 GB passed to write calls. So about
a fifth of the flush time on m3, 33.7 s of 177.8 s, is this volume's
copy-on-write and compression, and the rest is not. That is one run
against one run, and it measures this stack: what ext4 or xfs would do
with the same writes was not measured.

**The change as made (`b4a5d2d`).** A UTXO-cache flush now ends in a
durable commit when it is forced (every connect once the chain is
current, the latch to current, every disconnect, `gettxoutsetinfo`,
shutdown) or when 120 s of processing have passed since the last one
that did. A flush that only the cache's size limit tripped writes its
rows and the set state in one transaction and returns, and they become
durable with the next durable commit, whichever trigger makes it. The
overlay's default ceiling is 300 MiB where it was dcrd's 100. It differs
from the prototype in the 120 s rule, which the prototype did not have,
and in tests. Three default syncs and one with `--noexistsaddrindex`,
each after the 300 s idle but the first:

| run | started | code | overlay ceiling | data directory | wall | flushes | flush time | outside the flushes | node CPU time (user + sys) | passed to write calls | written at the volume | peak RSS | other userland |
|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| g-1 | 17:23 | final | 300 MiB (default) | as created | 725.9 s | 54 | 107.4 s | 618.5 s | 1,462.1 s (1,364.4 + 97.7) | 39.7 GB | 52.7 GB | 3,090 MiB | 0.07% |
| g-2 | 17:42 | final | 300 MiB (default) | as created | 728.7 s | 54 | 108.9 s | 619.8 s | 1,461.7 s (1,364.5 + 97.2) | 39.7 GB | 53.1 GB | 3,285 MiB | 0.07% |
| g-3 | 18:18 | final | 300 MiB (default) | as created | 729.4 s | 54 | 109.7 s | 619.7 s | 1,458.1 s (1,363.0 + 95.1) | 39.8 GB | 53.1 GB | 3,238 MiB | 0.07% |
| g-off | 18:01 | final, `--noexistsaddrindex` | 300 MiB (default) | as created | 610.2 s | 41 | 63.6 s | 546.6 s | 1,273.2 s (1,196.7 + 76.5) | 32.7 GB | 38.1 GB | 2,138 MiB | 0.08% |

Every run exited 0 on the server's tip and none was marked disturbed.

- **At the defaults the final code took 725.9 s, 728.7 s and 729.4 s, a
  median of 728.7 s, where `7d31abb` took 775.6 s in f-head: 46.9 s or
  6.0% less.** That is three runs against one in one afternoon. The
  three span 3.5 s.
- **It made 54 flushes, two more than the prototype's 52**, taking
  107.4–109.7 s, 15% of the sync where f-head's 133 took 23%. The median
  flush is about 1.85 s against 1.44 s and the longest 3.2–3.4 s against
  2.8 s.
- **The overlay's ceiling trips few of them when the index is on.** In
  g-1, 11 of the 54 flushes began with more than 200 MiB retained, the
  overlay's own trigger at a 300 MiB ceiling, all of them within 141 s
  of the first flush. Five more fall about 122 s apart, 113 s, 235 s,
  357 s, 479 s and 601 s after the first, four of them clearly smaller
  than their neighbours, and are presumably the 120 s rule's. The
  exists-address index's participant asks for the other 38, which
  journaled 1.1–1.25 million keys each with 100–190 MiB in the overlay.
  With the index off (g-off) 36 of 41 flushes began over 200 MiB, and
  the other five are about 122 s apart.
- **Peak resident memory was 3,090, 3,285 and 3,238 MiB against f-head's
  2,635 MiB**, and 2,138 MiB with the index off. `7d31abb` was not run
  with the index off (`c128a93` peaked at 1,996 MiB without it on
  2026-10-10), so what the change costs without the index was not
  measured; nearly all of the 450–650 MiB appears to come with the
  index. The index's memtable peaked at 4.50 million keys against 3.99
  million in f-head, which does not account for it, and what holds it
  was not established.
- **The node passed 39.7–39.8 GB to write calls against 51.4 GB**, and
  redb's commits wrote 20.5–20.6 GB against 30.6 GB. Three to five of
  the 54 commits in each run wrote more than 512 MiB, the engine's
  write buffer, where none of f-head's 133 did (two of s-final's 133
  did that morning).
- **With the index off the sync took 610.2 s**, 118.5 s less than the
  median with it on: the index is 16% of a default sync, where it was
  17% at `c128a93` (880.8 s on 2026-10-10 against the 1,058.6 s median
  of 2026-10-09 and 2026-10-10).
- **Against dcrd.** One run of dcrd v2.1.6 at the end of the session
  (g-dcrd, started 18:49, from the same dcrd block server, exit 0 on its
  tip, not disturbed) took 2,883.9 s, inside the 2,848.8–2,894.8 s of
  its four runs of 2026-10-09 and 2026-10-10. Against it the final
  code's median of 728.7 s is 3.96x, in one session: three runs against
  one. Set against dcrd's 2,863.9 s median of the earlier runs it is
  3.93x, across sessions, and with the index off 610.2 s against dcrd's
  1,247.8 s of 2026-10-10 is 2.04x, across sessions. Up to the
  assume-valid block the final code's
  runs took 573.3–576.8 s and the blocks after it 152.6–152.7 s, about
  586 blk/s.

The binary of these four runs was built from the working tree after
the last review change, which is the code as committed but for the
wording of one comment.

**A delayed link.** Every sync figure in this ledger is over loopback.
Both daemons download through dcrd's window, 16 blocks in flight and a
refill once fewer than 10 remain, and the model under "Sync throughput"
has predicted since 2026-08 that a round trip longer than a few blocks'
processing time makes that window set the pace, with no run to check
it. On 2026-10-11 the syncing node was connected to a relay on the same
machine that holds every chunk for a fixed time in each direction, and
the relay to the dcrd block server: a pure delay, with no loss and no
bandwidth limit. Each run was stopped after a fixed time and the height
at each 10 s sample kept, so these are rates under a known round trip
and not sync times. The dcroxide runs used `7d31abb`.

> **Note (2026-10-12):** "both daemons download through dcrd's
> window" is true of the runs below, of `7d31abb` and dcrd v2.1.6.
> Since `540b203` the daemon's default window is up to 128 blocks and,
> past 16 of them, 3,145,728 bytes, and dcrd's rule is what
> `DCROXIDE_BLOCK_WINDOW=dcrd` selects. Through this relay on
> 2026-10-12 the default window moved 102 blocks per round trip at
> 50 ms and 117 at 150 ms, where dcrd's rule in the same binary moved
> 13.1 and 13.6, one run of 300 s each. See "Eleven changes, a
> background commit not kept and a pool gate" below.

| run | started | syncer | one-way delay | round trip | run length | height reached | first block after | rate once blocks flow | blocks per round trip | node CPU time |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| dl-dcroxide-50 | 16:00 | dcroxide-head | 25 ms | 50 ms | 600 s | 144,821 | 51 s | 260 blk/s over blocks 4,851–143,004 | 13.0 | 84 s |
| dl-dcrd-50 | 16:10 | dcrd | 25 ms | 50 ms | 600 s | 140,175 | 50 s | 252 blk/s over blocks 3,901–140,175 | 12.6 | 169 s |
| dl-dcroxide-150 | 16:21 | dcroxide-head | 75 ms | 150 ms | 540 s | 40,172 | 100 s | 91 blk/s over blocks 1,078–39,347 | 13.6 | 30 s |
| dl-dcroxide-20 | 16:30 | dcroxide-head | 10 ms | 20 ms | 420 s | 237,870 | 31 s | 609 blk/s over blocks 10,083–237,663 | 12.2 | 115 s |
| dl-dcroxide-0 | 16:38 | dcroxide-head | 0 ms | 0 ms | 150 s | 378,239 | 20 s | 2,575 blk/s over blocks 70,501–370,444 | n/a | 159 s |

- **At a 50 ms round trip dcroxide ran at 260 blk/s and dcrd v2.1.6 at
  252 blk/s**, 13.0 and 12.6 blocks per round trip. Over loopback the
  final code passed the same blocks at about 3,200 blk/s that afternoon
  (g-1) and dcrd at about 1,500 on 2026-10-09 (r2), so over that stretch
  a lead of about 2.1x, taken across sessions, becomes 1.03x.
- **The rate follows the round trip.** At 150 ms dcroxide ran at
  91 blk/s and at 20 ms at 609 blk/s: 13.6 and 12.2 blocks per round
  trip. The model's figure was 9–16.
- **The relay is not the limit.** With no delay dcroxide ran through it
  at 2,575 blk/s over blocks 70,501–370,444, which the final code passes
  over loopback at about 2,950 blk/s.
- **The header sync is delay-bound too.** The first block arrived
  between 40 and 51 s into the 50 ms runs and between 90 and 100 s into
  the 150 ms run (the samples are 10 s apart), where it takes between 10
  and 20 s over loopback: the headers come 2,000 to a round trip.
- **What it implies, not measured.** At 13 blocks per round trip this
  chain's 1,116,035 blocks need about 86,000 round trips: 72 minutes at
  50 ms and 3.6 hours at 150 ms, for either daemon wherever it can
  process faster than that. dcroxide can everywhere on this chain at
  50 ms, since its slowest stretch, after the assume-valid block, runs
  at about 586 blk/s. No delayed run went past block 237,870, and the
  blocks there are small.

> **Note (2026-10-12):** the implication above, "for either daemon
> wherever it can process faster than that", holds for dcrd's window:
> for dcrd, and for dcroxide under `DCROXIDE_BLOCK_WINDOW=dcrd`. What
> a whole sync takes over a delayed link with the default window has
> not been measured. The relay runs of 2026-10-12 lasted 300 s and
> reached block 532,079 at 50 ms and block 158,440 at 150 ms.

These runs were not on a quiet machine: other work went on on it
throughout, and a build was running at the end of the 20 ms and 0 ms
runs, which is the one time the harness looks. It was held to other
cores than the node's eight threads, the server's four and the relay's
two. The node used 84 s of CPU time in
the 600 s at 50 ms, so it was idle most of the time and the rates above
are the link's.

**What this does not establish.**

- The ratio to dcrd in one session rests on one dcrd run, taken from a
  dcrd block server where dcrd's published runs took their blocks from
  a dcroxide one. With the index off dcrd was not run again.
- Not what holds the extra memory, nor the 20 s or so more outside the
  flushes (618.5–619.8 s against 597.8 s).
- Not the final code on a data directory without copy-on-write, and
  nothing on ext4, xfs or ZFS.
- Not what an unclean stop now costs in time: the replay it leaves was
  tested for correctness (a sweep of unclean stops at sampled commits
  reopens to the right UTXO set) and not timed.
- Not the final code at a 100 MiB or 200 MiB ceiling, and not the cost
  of the forced commit every 120 s against a rule that counted the
  overlay's own commits: the five flushes about 122 s apart, and two
  more flushes in all than the prototype's, are the signs of it.
- Nothing about a real link: the relay adds delay only, to one peer on
  the same machine.
- Not `--assumevalid=0`, the tuning levers, m1 or m2 on this code.

> **Note (2026-10-12):** the final code has since been run on a data
> directory without copy-on-write: 714.1 s against 728.5 s for the
> same binary on the directory as created, 14.4 s or 2.0% less, one
> run each on 2026-10-12. Five starts of 300 s against the public main
> network were made that day too, of the code of `540b203`; they are
> not a sync over a real link. See "Eleven changes, a background
> commit not kept and a pool gate" below.

Raw: the comparison's `runs.jsonl` rows labelled `f-head`, `f-proto`,
`f-proto-200`, `f-proto-nocow`, `f-head-nocow`, `g-1`, `g-2`, `g-3`,
`g-off` and `g-dcrd`, with per-run samples, flush logs and node logs as
above;
`delay.jsonl` for the delayed runs, with the relay's source and the
script that drove them; the prototype's patch; and `smoke4.jsonl` and
`delay-smoke.jsonl` for the short runs that checked the prototype, the
no-copy-on-write option and the relay.

## Eleven changes, a background commit not kept and a pool gate (2026-10-12)

"Shared commits for UTXO-cache flushes, the filesystem's share and a
delayed link" above left a default sync at a median of 728.7 s, and
earlier sections left three things open: what the index thread costs
the thread that connects blocks, the download window that sets the pace
over a delayed link, and the persistent validation pool. On 2026-10-12
eleven changes were made and measured on m3 in five builds, each
holding the ones before it, and three things that are not in the
repository were measured, gated or designed: a background commit, a
persistent validation pool and the coalescing of the storage engine's
page writes. dcrd was not run.

The syncs are in the harness of the sections above: mainnet from
genesis to 1,116,035 over loopback from the dcrd v2.1.6 block server,
at the defaults but for the setting a row names, with the same pinning,
clock and quiet gate, and a 300 s idle before every run but h-nocow and
h-rabg-sync-1, each the first of the batch it was queued in. The relay
runs and the pool gate were steps of the same queue, between the syncs.
The starts against the public network were made before it, on a machine
that was not quiet.

The changes, in the order made and measured. The commits were made
afterwards, one per change, on `b212a0a`:

1. **The small batch**, four commits measured together. The best
   state keeps the tip's missed tickets as a handle on the stake node's
   treap, where every connect listed the whole set, as dcrd does
   (`chain.go:658`, `:857`), for a list only the mining template reads
   (`7f99184`). The keys of the UTXO view and the UTXO cache are
   compared as four big-endian words in a comparison written into the
   search, where the tuple's derived comparison went through `memcmp`,
   and a view is committed to the cache in one pass (`a65d647`). A
   block record is written with one positioned write, where it was a
   seek and then four writes, one for each field as in dcrd's
   `writeBlock` (`blockio.go:466-489`) (`7c6ec9a`). And a caller that
   finds the database's writer held is timed until it holds it, with
   the totals in the flush log (`a83f9a1`).
2. **The index batch**, three commits measured together. The
   exists-address index does a queued block's extraction, hashing,
   filtering and sorting before its thread takes the writer, where it
   did them holding it (`1d5d8a9`). Its 21-byte keys are compared
   inline (`4535d1e`). A best-node write looks each ticket bucket up
   once, where it looked one up for every ticket (`6271436`).
3. **The SigHashAll prefix hash** (`3a367e5`). At block connect the
   prefix hash of a `SigHashAll` signature hash is taken from the
   transaction hashes the chain has already computed, a path dcrd
   carries and ships switched off (`optimizeSigVerification`,
   `opcode.go:27-32`).
4. **The download window** (`540b203`). During the initial sync the
   daemon keeps up to 128 blocks and, past 16 of them, 3,145,728 bytes
   requested from its sync peer, where dcrd keeps 16
   (`internal/netsync/manager.go:32-38`). `DCROXIDE_BLOCK_WINDOW=dcrd`
   selects dcrd's rule.
5. **The block hand-off** (`5cf9e04`). A block a peer delivers reaches
   the chain in the allocation it was decoded into, without the copy
   the chain made when it accepted the block's data.
6. **Read-ahead** (`b4ceb1c`). On the sync peer's connection a
   `peer-reader` thread reads up to four frames ahead of the thread
   that connects blocks, and there checks each frame's checksum,
   decodes it and hashes a block's transactions. dcrd has no such
   thread. `DCROXIDE_READ_AHEAD=off` reads every connection as dcrd
   does.

PARITY.md states all six.

| run | started | code | setting | wall | to block 1,026,597 | after it | node CPU time (user + sys) | peak RSS | flushes | flush time | passed to write calls | write calls |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| h-nocow | 06:54 | `b4a5d2d` | data directory without copy-on-write | 714.1 s | 562.8 s | 151.3 s | 1,442.9 s (1,356.1 + 86.8) | 3,246 MiB | 55 | 97.1 s | 40.1 GB | 9.25 million |
| h-base | 07:12 | `b4a5d2d` | defaults | 728.5 s | 574.6 s | 153.9 s | 1,458.3 s (1,361.0 + 97.3) | 3,278 MiB | 54 | 107.4 s | 39.7 GB | 9.15 million |
| h-small | 07:31 | `a83f9a1` | defaults | 673.8 s | 524.6 s | 149.2 s | 1,400.9 s (1,308.3 + 92.6) | 3,299 MiB | 56 | 111.4 s | 40.0 GB | 5.86 million |
| h-index | 07:49 | `6271436` | defaults | 628.0 s | 487.7 s | 140.3 s | 1,393.8 s (1,298.6 + 95.2) | 3,224 MiB | 56 | 107.9 s | 40.0 GB | 5.87 million |
| h-sighash | 08:06 | `3a367e5` | defaults | 607.7 s | 486.1 s | 121.6 s | 1,152.2 s (1,058.0 + 94.2) | 3,234 MiB | 54 | 105.7 s | 39.6 GB | 5.78 million |
| h-window | 08:23 | `540b203` | defaults | 612.4 s | 489.3 s | 123.1 s | 1,160.0 s (1,065.8 + 94.2) | 3,204 MiB | 56 | 105.7 s | 40.3 GB | 5.94 million |
| h-ra-off-1 | 09:09 | read-ahead build | `DCROXIDE_READ_AHEAD=off` | 597.6 s | 472.7 s | 124.9 s | 1,141.6 s (1,045.2 + 96.4) | 3,273 MiB | 55 | 108.1 s | 40.3 GB | 5.95 million |
| h-ra-on-1 | 09:25 | read-ahead build | defaults | 494.6 s | 386.3 s | 108.3 s | 1,118.7 s (1,028.3 + 90.4) | 2,967 MiB | 55 | 105.3 s | 39.8 GB | 5.83 million |
| h-bg-sync-1 | 09:40 | background commit on `3a367e5` | `DCROXIDE_DB_SYNC_COMMIT=1` | 607.9 s | 484.3 s | 123.6 s | 1,149.6 s (1,054.5 + 95.1) | 3,207 MiB | 55 | 107.2 s | 39.9 GB | 5.84 million |
| h-bg-on-1 | 09:57 | background commit on `3a367e5` | commits in the background | 579.6 s | 458.1 s | 121.5 s | 1,181.9 s (1,078.1 + 103.8) | 4,188 MiB | 54 | 112.6 s | 41.5 GB | 6.16 million |
| h-ra-off-2 | 10:25 | read-ahead build | `DCROXIDE_READ_AHEAD=off` | 599.0 s | 473.0 s | 126.0 s | 1,139.3 s (1,042.5 + 96.8) | 3,256 MiB | 55 | 110.1 s | 40.3 GB | 5.93 million |
| h-ra-on-2 | 10:42 | read-ahead build | defaults | 490.8 s | 381.1 s | 109.7 s | 1,118.2 s (1,027.6 + 90.6) | 2,921 MiB | 55 | 104.3 s | 39.9 GB | 5.84 million |
| h-rabg-sync-1 | 10:54 | background commit on the read-ahead build | `DCROXIDE_DB_SYNC_COMMIT=1` | 498.5 s | 389.0 s | 109.5 s | 1,124.7 s (1,030.8 + 93.9) | 3,025 MiB | 55 | 107.9 s | 39.7 GB | 5.80 million |
| h-rabg-on-1 | 11:09 | background commit on the read-ahead build | commits in the background | 468.0 s | 362.7 s | 105.3 s | 1,154.3 s (1,053.9 + 100.4) | 3,773 MiB | 54 | 113.1 s | 41.4 GB | 6.13 million |

Every run exited 0 on the server's tip, `8752fdc9…`, and none was
marked disturbed. The harness's other-userland share is 0.21–0.22% in
every run, where the afternoon before had 0.07% and a run is marked at
0.5%: one desktop process, by its name a resource monitor left open,
used 14–21 s of the 33–49 s of other userland CPU time a run (15–17 s
the afternoon before), and the rest of the rise is not attributed. The time to block 1,026,597 is
interpolated between two samples about 10 s apart, as in the sections
above, and "after it" is the wall time less that. The flush columns
count the flushes of the sync and leave out the one the close makes at
shutdown, as the tables of 2026-10-11 do. The last two columns are
`wchar` and `syscw`. From `7c6ec9a` on a block record is one write call
where it was four, so the write-call counts from h-small down are not to
be set against the two above them. h-window, the read-ahead build and
the background-commit build made on it have the download window, and the
background-commit build on `3a367e5` does not. No run logged a narrowed
or widened window or a stalled peer.

h-nocow and h-base ran the binary of g-1 to g-3 above, which that
section describes. The four binaries after them were built from
working trees before the commits were made. Applied to `b212a0a`, the
patches saved of those trees at the time give the trees of `a83f9a1`
and `6271436` exactly, the tree of `3a367e5` but for PARITY.md, and
the tree of `540b203` but for five documents. The read-ahead build and
the two background-commit builds are described under their own
headings below.

**A default sync went from 728.5 s to 612.4 s on the code of
`540b203`, 15.9% less, and to 494.6 s and 490.8 s on the read-ahead
build, 32.1% and 32.6% less, in one session.** By step:

| step | this run | the one before | gain |
|---|---:|---:|---:|
| the small batch | 673.8 s | 728.5 s (h-base) | 54.7 s, 7.5% |
| the index batch | 628.0 s | 673.8 s | 45.8 s, 6.8% |
| the SigHashAll prefix hash | 607.7 s | 628.0 s | 20.3 s, 3.2% |
| the download window | 612.4 s | 607.7 s | 4.7 s more, 0.8% |
| the block hand-off, in the read-ahead build with read-ahead off | 597.6 s and 599.0 s | 612.4 s | 14.8 s and 13.4 s |
| read-ahead | 494.6 s and 490.8 s | 597.6 s and 599.0 s, the same binary | 103.0 s and 108.2 s, 17.2% and 18.1% |

Each gain is one run against one run, in the order the changes were
made. No step but the last was run twice, and no other order was run.

**The session's base, and the filesystem's share of it.** h-base is the
binary of the afternoon before, run again: 728.5 s, where its three
runs there took 725.9 s, 728.7 s and 729.4 s. h-nocow is the same
binary in a data directory made with the no-copy-on-write attribute,
which the section above listed as not run on that code: 714.1 s, 14.4 s
or 2.0% less. Its 55 flushes took 97.1 s against 54 in 107.4 s, the
node's system time was 86.8 s against 97.3 s, and the volume took
41.6 GB against 53.2 GB for the 40.1 GB and 39.7 GB passed to write
calls. On `7d31abb`, with 133 flushes, the same comparison came to
38.8 s or 5.0% on 2026-10-11. Both are one run against one run, and
h-nocow was the first run of its batch, with no idle before it.

**The small batch.** With the four the sync took 673.8 s against
728.5 s, 54.7 s or 7.5% less: 524.6 s against 574.6 s up to the
assume-valid block and 149.2 s against 153.9 s after it. The node's
user CPU time fell from 1,361.0 s to 1,308.3 s. It made 5.86 million
write calls where h-base made 9.15 million, 3.29 million fewer, for
40.0 GB and 39.7 GB passed to them; three fewer calls for each of the
1,116,035 block records would be 3.35 million. The four were not
measured apart, so the 54.7 s is not divided among them. The profile
of 2026-10-11 put `memcmp` at 14.6% of the cycles up to the
assume-valid block without its callers. The second commit replaces
the key comparison of the two UTXO maps, which went through `memcmp`;
no profile was taken on 2026-10-12, so what part of the 14.6% those
searches were is not established.

**The waits for the writer.** Every writable transaction, flush and
close takes the database's writer, and since the index thread of
2026-10-11 two threads take it for every block. From `a83f9a1` a
caller that finds it held is timed until it holds it (`acquire_writer`,
`crates/dcroxide-database/src/lib.rs:263`); one that finds it free
reads no clock and is not counted. The waits are totalled for the
thread named `index` and for all other threads together, and each
flush-log line carries the totals since the database was opened and
the name of the thread that ran the flush. The totals below are those
of each run's last line, which the close writes at shutdown. The flush
counts are of the sync, as in the table above. `peer-outbound` is the
thread that connects blocks in these runs.

| run | other threads: waits | waited | index thread: waits | waited | flushes run by `peer-outbound` | by `index` |
|---|---:|---:|---:|---:|---:|---:|
| h-small | 401,906 | 74.9 s | 295 | 0.02 s | 48 in 98.5 s | 8 in 12.9 s |
| h-index | 166,810 | 30.7 s | 97,538 | 30.4 s | 43 in 85.1 s | 13 in 22.8 s |
| h-sighash | 167,161 | 30.3 s | 99,862 | 39.0 s | 42 in 83.0 s | 12 in 22.6 s |
| h-window | 165,394 | 23.2 s | 98,041 | 51.0 s | 46 in 90.0 s | 10 in 15.8 s |
| h-ra-off-1 | 160,617 | 33.4 s | 115,449 | 44.3 s | 40 in 82.5 s | 15 in 25.6 s |
| h-ra-on-1 | 197,790 | 31.2 s | 305,825 | 53.1 s | 43 in 83.1 s | 12 in 22.2 s |
| h-bg-sync-1 | 165,886 | 35.0 s | 97,045 | 32.7 s | 40 in 80.3 s | 15 in 26.9 s |
| h-bg-on-1 | 174,103 | 16.4 s | 104,567 | 22.0 s | 4 in 6.6 s | none; 50 on `dbcommit` |
| h-ra-off-2 | 159,734 | 29.0 s | 112,774 | 38.9 s | 42 in 88.6 s | 13 in 21.4 s |
| h-ra-on-2 | 198,074 | 20.1 s | 304,294 | 73.3 s | 49 in 92.7 s | 6 in 11.7 s |
| h-rabg-sync-1 | 196,631 | 19.8 s | 306,257 | 71.9 s | 48 in 96.5 s | 7 in 11.4 s |
| h-rabg-on-1 | 202,815 | 15.9 s | 312,474 | 51.9 s | 3 in 4.4 s | none; 51 on `dbcommit` |

- **In the tree of `a83f9a1` the threads other than the index thread
  waited 74.9 s of a 673.8 s sync for the writer**, in 401,906 waits,
  and the index thread 295 times for 0.02 s in all. The index thread
  took the writer first and did a block's index work holding it. At
  most 12.9 s of the 74.9 s can have been spent behind the eight
  flushes the index thread ran. The other 62.0 s or more was not
  behind an index-thread flush. The timer does not record who held the
  writer, and a flush-log line names only the thread that ran a flush.
  In these single-peer syncs the index thread is the only thread known
  to take the writer for every block besides the one that connects
  them, so its per-block transactions are the likely holder, which the
  fall to 30.7 s with the index batch is consistent with. The two
  totals are the nearest measure there is of what "Five changes on the
  block-processing thread" above listed as not measured, how long the
  two threads wait for each other.
- **With the index batch it was 30.7 s**, in 166,810 waits: 44.3 s
  less, where the sync took 45.8 s less and the node's CPU time moved
  by 7.1 s (1,393.8 s against 1,400.9 s). The index thread, which now
  does a block's work before it asks for the writer, found it held
  97,538 times and waited 30.4 s, where it had hardly waited at all.
- **Less the flushes the index thread ran, what is left is 7.5–9.1 s
  a sync.** A flush holds the writer for about 1.8 s at the median,
  whichever thread's commit trips it. In the nine later runs that
  commit on the committing thread the index thread ran 6 to 15 of the
  54 to 56 flushes, in 11.4–26.9 s, and the other threads waited
  19.8–35.0 s; less the index thread's flush time that is 7.5–9.1 s in
  every one of them, against 62.0 s in h-small. The total moves with
  where the flushes fall. The two runs of one binary with read-ahead
  on differ by 11.1 s in the other threads' wait and by 10.5 s in the
  index thread's flush time. So a difference in this total between two
  runs is not by itself a difference between their builds.
- **With read-ahead on the index thread waits more than two and a
  half times as often**: 305,825 and 304,294 waits, for 53.1 s and
  73.3 s, against 115,449 and 112,774, for 44.3 s and 38.9 s, in the
  same binary with it off. The index thread's waiting holds the block
  thread up only when its queue of 128 notifications is full, which
  the read-ahead build counts in its shutdown line: 3.2 s and 3.3 s in
  those two runs. Earlier builds, and a run with read-ahead off, have
  no such count.

The totals do not say what the index costs a sync on this code: no run
with `--noexistsaddrindex` was made on 2026-10-12. The last is g-off,
on `b4a5d2d`: 610.2 s against a median of 728.7 s. `other` is every
thread not named `index`, so it bounds the block thread's wait from
above and does not single it out. A wait that has not ended when a
line is written is not in that line, and nothing a thread does while
it holds the writer is in any of them.

> **Note (2026-10-16):** on the code of `4700cf1`, which holds all
> eleven, one run with `--noexistsaddrindex` took 423.6 s on
> 2026-10-13, 80.6 to 89.9 s under each of three default runs of it
> that session. Less the flushes the index thread ran, the other
> threads' wait for the writer was 8.1 to 9.5 s in the eleven runs of
> that session whose code lacked `64359e7` and `85a5dc8` and that
> committed on the flushing thread with no other setting changed, and
> 1.6 to 1.7 s in the five runs of builds with them. See "Seven
> cumulative builds, the validation pool, a background commit and dcrd"
> below.

**The index batch.** 628.0 s against 673.8 s, 45.8 s or 6.8% less:
487.7 s against 524.6 s up to the assume-valid block and 140.3 s
against 149.2 s after it. The node's CPU time is 7.1 s lower and the
other threads' wait for the writer 44.3 s lower, as above. The three
were not measured apart.

**The SigHashAll prefix hash.** 607.7 s against 628.0 s, 20.3 s or 3.2%
less. Scripts run only after the assume-valid block, and that is where
it shows: 486.1 s against 487.7 s up to it, and 121.6 s against 140.3 s
for the 89,438 blocks after it, 735 blk/s against 638. The node's user
CPU time fell from 1,298.6 s to 1,058.0 s, 240.6 s: after the
assume-valid block an average of 4.7 of the node's 16 threads were
busy where h-index had 5.7.

**The download window.** Over loopback one default sync with it took
612.4 s against 607.7 s for the code before it, 4.7 s or 0.8% more,
with 7.8 s more user CPU time. That is one run against one run and
does not settle whether the window costs anything over loopback: later
that day two runs of one binary differed by 1.4 s, and two of the same
binary under its other setting by 3.8 s.

Through the relay of 2026-10-11, which holds every chunk for a fixed
time in each direction and does not limit bandwidth, the binary of
h-window ran for 300 s from the start of the process under dcrd's rule
(`DCROXIDE_BLOCK_WINDOW=dcrd`) and at its default, at two round trips,
one run an arm, as one step of the quiet queue:

| run | started | window | one-way delay | round trip | run length | height reached | first block after | rate once blocks flow | blocks per round trip | node CPU time |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| dl2-dcrdrule-50 | 08:40 | dcrd's rule | 25 ms | 50 ms | 300.9 s | 68,031 | 50.4 s | 262 blk/s over blocks 4,921–65,908 | 13.1 | 38 s |
| dl2-budget-50 | 08:46 | default | 25 ms | 50 ms | 300.9 s | 532,079 | 50.5 s | 2,043 blk/s over blocks 41,560–530,087 | 102.2 | 217 s |
| dl2-dcrdrule-150 | 08:51 | dcrd's rule | 75 ms | 150 ms | 300.9 s | 18,445 | 101.1 s | 91 blk/s over blocks 1,204–17,608 | 13.6 | 20 s |
| dl2-budget-150 | 08:57 | default | 75 ms | 150 ms | 300.5 s | 158,440 | 100.2 s | 779 blk/s over blocks 9,956–151,894 | 116.9 | 71 s |

- **Under dcrd's rule the binary repeats 2026-10-11**: 13.1 and 13.6
  blocks per round trip at 50 and 150 ms, where `7d31abb` moved 13.0
  and 13.6.
- **The default window moved 102 and 117 blocks per round trip.** It
  reached block 532,079 where dcrd's rule reached 68,031, and block
  158,440 where dcrd's rule reached 18,445: 7.8 and 8.6 times the
  height, at 7.8 and 8.6 times the rate once blocks flow.
- **What set the pace at 50 ms was not established.** Over loopback
  the same binary passed blocks 41,560–530,087 at 3,138 blk/s
  (h-window) and blocks 9,956–151,894 at 3,719 blk/s, so through the
  relay it ran at 65% of that pace at 50 ms and 21% at 150 ms. The
  node used 217 s of CPU time in the 301 s at 50 ms. A relay run gives
  the node four cores where a sync gives it eight, and with no delay
  the relay passed 2,575 blk/s on 2026-10-11, of `7d31abb` and with a
  build running at the time. Which of the window, the relay and the
  node was the limit at 50 ms is not known.
- **No arm logged a narrowed or widened window or a stalled peer.**
  The first block arrived about 50 s and 100 s in, as on 2026-10-11:
  the window does not touch the header sync.

Against the public main network, five outbound-only starts of 300 s,
each on a fresh data directory, between 06:05 and 06:32 with builds
running on the machine. Under dcrd's rule the node was at block 24,455
and at block 41,191 when stopped, 180.7 s and 220.3 s after its first
block arrived: 135 and 187 blk/s. Under the default window it was at
188,469 and at 93,095 after 215.7 s and 161.8 s, 874 and 575 blk/s,
and a third start under the default fetched no block in its 300 s.
None logged a narrowed window or a stalled peer. The peers and links
were whatever the network offered each start, so these show the window
working against real peers and are not figures to set against another
day's. PARITY.md, *Block download window*, has the rule, these runs
and the costs read from the code.

**The block hand-off** was not measured alone. The next binary holds
it together with the read-ahead code, and with read-ahead switched off
it took 597.6 s and 599.0 s where h-window took 612.4 s, 14.8 s and
13.4 s less. That is the hand-off and whatever else the read-ahead
build changes with its reader thread off, not divided.

**Read-ahead.** One binary, two runs with `DCROXIDE_READ_AHEAD=off`
and two at the default, alternated, with the background-commit pair
and the pool gate between the two pairs:

| | read-ahead off | read-ahead on | less |
|---|---:|---:|---:|
| first pair, wall | 597.6 s | 494.6 s | 103.0 s, 17.2% |
| second pair, wall | 599.0 s | 490.8 s | 108.2 s, 18.1% |
| to block 1,026,597 | 472.7 s and 473.0 s | 386.3 s and 381.1 s | |
| after it | 124.9 s and 126.0 s | 108.3 s and 109.7 s | |
| node CPU time | 1,141.6 s and 1,139.3 s | 1,118.7 s and 1,118.2 s | 22.9 s and 21.1 s |
| peak RSS | 3,273 and 3,256 MiB | 2,967 and 2,921 MiB | 306 and 335 MiB |

The node's own line at shutdown (`shutdown_line`,
`crates/dcroxide-node/src/readahead.rs:892`) in the two runs with
read-ahead on:

| | h-ra-on-1 | h-ra-on-2 |
|---|---:|---:|
| blocks the reader thread read | 1,116,034 (19,215,875,473 B) | 1,116,034 (19,215,875,473 B) |
| checksum and decode, done off the block thread | 45.829 s | 45.886 s |
| hashing, done off the block thread | 47.209 s | 47.246 s |
| the reader waited for the block thread | 382.350 s | 378.719 s |
| the block thread waited for the reader | 0.271 s | 0.273 s |
| most items queued | 4 | 4 |
| index queue full | 3.191 s | 3.265 s |

- **The sync took 103.0 s and 108.2 s less, and the work the line
  times is 93.0 s and 93.1 s.** The socket reads moved to the reader
  thread too and are not timed. What else is in the 10.0 s and 15.1 s
  between them was not established.
- **The block thread still sets the pace over loopback.** It waited
  0.27 s for the reader in a whole sync, and the reader waited 382 s
  and 379 s for it, 77% of the run, with the queue at its bound of
  four.
- **The reader thread read all but the first block**: it is started
  once the connection has had a block handled.
- **Node CPU time and peak resident memory are both lower with it
  on**, by 22.9 s and 21.1 s and by 306 and 335 MiB. Neither was
  explained.

> **Note (2026-10-16): the reader thread does more since, and its
> line says more.** From `a589c4a` the reader thread also lays out each
> block's block-file record in the bytes it received, and from
> `44cf801` it builds the block's two merkle trees, whose time is in
> the hashing figure; from `54e8cad` the header hash it took is handed
> down the processing call. The line gains a tail with the records
> laid out and those written as laid out (`shutdown_line`,
> `crates/dcroxide-node/src/readahead.rs:979`). In the syncs of
> 2026-10-13, another session, the three runs of `4700cf1` had 47.2 to
> 47.5 s of hashing, the reader waiting 391.9 to 401.7 s for the block
> thread and the block thread 0.26 to 0.28 s for the reader. The two
> runs of a build with the record and the trees had 52.536 s and
> 52.562 s of hashing, 1,116,034 records laid out in 7.128 s and
> 7.165 s and all of them written as laid out, the reader waiting
> 321.9 s and 321.8 s and the block thread 1.04 s and 1.01 s. See
> "Seven cumulative builds, the validation pool, a background commit
> and dcrd" below.

These four runs are of the build before the review's fixes, which is
not the code of any commit. Rebuilt from the patch saved with the
binary, its tree differs from `b4ceb1c` in production code in two
places. One is a condition in `Shared::waiting_since`
(`crates/dcroxide-node/src/readahead.rs:387`): before it, a frame the
reader began behind a block that was still queued took over the wait
for that block and could time out early. The other is a private
`hash_block` in `crates/dcroxide-blockchain/src/blockhashes.rs:308`,
which the merkle-leaf pass now goes through so that unit-test builds
can count its calls. The rest is tests, comments and documents.
`b4ceb1c` itself has not been run in a sync.

> **Note (2026-10-13): run since, as `4700cf1`.** `4700cf1` is the
> code of `b4ceb1c` with one log line more. Three default syncs of it
> on 2026-10-13 took 513.4 s, 513.5 s and 504.2 s, the first two with
> about 10 s more in their flushes' commit phase, and 432.8 s, 433.5 s
> and 433.7 s with the commit seconds taken out. In that session the
> block server read 15.7 to 18.0 GB from the drive during every run,
> where it read none in the runs above; no effect of that on
> dcroxide's times is shown, but the two sessions' times are of two
> sessions and two builds, and the difference between them is not a
> measure of the review's fixes. See "Seven cumulative builds, the
> validation pool, a background commit and dcrd" below.

**A background commit, measured and not kept.** "Background commit
(2026-08-16)" above built one on m1, measured it 9.5% slower and
closed the question. One was built again on 2026-10-12, in another
form and in a scratch tree outside the repository, as far as the stage
that makes it measurable. By the experiment's own account: for a flush
that a commit's own check trips, the committing thread captures the
cache, syncs the block files and puts the overlay's and the index's
rows into the storage engine's write transaction; the engine's commit
then runs on a second thread, `dbcommit`, one at a time; and an
explicit flush and the close still commit on the calling thread.
`DCROXIDE_DB_SYNC_COMMIT=1` puts every commit back on the committing
thread and is the control arm. It is a variable of the experiment's
build; no build of the repository reads it. Two pairs, one binary each:
the experiment on the code of `3a367e5`, and on the read-ahead build.
No patch was kept of the tree either binary was built from. That the
first holds the changes through `3a367e5` and not the download window
is read from the binary, which holds a string of the SigHashAll change
that the builds before it lack and none of the window's, and from its
control arm's user CPU time: 1,054.5 s, where h-sighash used 1,058.0 s
and h-index 1,298.6 s.

| run | commits run on | wall | peak RSS | written at the volume | the engine's commits wrote | flushes committed on `dbcommit` | time the threads that trip flushes spent in them |
|---|---|---:|---:|---:|---:|---:|---:|
| h-bg-sync-1 | the committing thread | 607.9 s | 3,207 MiB | 53.3 GB | 20.7 GB | 0 of 55 | 107.2 s |
| h-bg-on-1 | `dbcommit` | 579.6 s | 4,188 MiB | 59.9 GB | 23.3 GB | 50 of 54 | 50.7 s |
| h-rabg-sync-1 | the committing thread | 498.5 s | 3,025 MiB | 53.3 GB | 20.6 GB | 0 of 55 | 107.9 s |
| h-rabg-on-1 | `dbcommit` | 468.0 s | 3,773 MiB | 58.2 GB | 24.8 GB | 51 of 54 | 48.9 s |

- **It gained 28.3 s or 4.7% on `3a367e5` and 30.5 s or 6.1% on the
  read-ahead build**, one run against one run each. Nearly all of it
  is before the assume-valid block: 26.2 s and 26.3 s of it.
- **The control arms, against the code each was built on.**
  h-bg-sync-1 took 607.9 s where h-sighash took 607.7 s.
  h-rabg-sync-1 took 498.5 s where the read-ahead build took 494.6 s
  and 490.8 s, 3.9 s and 7.7 s more. It is the one run of the four
  with no idle before it, and the difference was not examined.
- **The threads whose commits trip flushes spent 50.7 s and 48.9 s in
  them**, the wait for the commit before included, where the control
  arms' flushes took 107.2 s and 107.9 s. About half of the 57 s and
  59 s between them came out as wall time.
- **It cost 981 and 748 MiB of peak resident memory**, 32.3 s and
  29.6 s more node CPU time, and more writing: the engine's commits
  wrote 23.3 GB and 24.8 GB against 20.7 GB and 20.6 GB, 13 and 16 of
  them over 512 MiB against 4 and 2, and 1.7 GB more went to write
  calls in each pair. What holds the memory and why more is written
  were not established.
- **The flushes are a smaller part of the wall time than in
  2026-08.** On m1 they filled 68–71% of it and one commit followed
  another. In these two control arms they are 17.6% and 21.7%.

It is not in the repository. The stage after the measurement was not
built: the sweeps of unclean stops with a commit in the background,
the rest of its tests and its mutation tests. The memory was not
explained. And two decisions were not taken: whether it would be the
default, and how ADR-0009's rule for a durable write that fails would
read when the failure reaches the next write, flush or close and not
the commit that tripped the flush.

> **Note (2026-10-13): built a third time, on `231997b`, and measured
> in two pairs and one more run.** In that build the engine's commit on
> `dbcommit` holds a read snapshot of the store while it runs, and
> `DCROXIDE_DB_BARE_COMMIT=1` runs it without one, as the form above
> did. With the snapshot a default sync took 465.7 s and 460.5 s
> against its control arm's 501.1 s and 500.5 s, 35.4 s and 40.0 s
> less, 31 to 34 s of it before the assume-valid block; in both pairs
> the arm with the snapshot ran first. No memory cost was detected, at
> a resolution of about 300 MiB: its peak was 119 MiB above its
> control in one pair and 288 MiB below it in the other. Without the
> snapshot, in one run, it took 471.1 s and peaked at 3,321 MiB,
> against 2,996 and 3,341 MiB for the two control runs, and wrote
> 3,269 to 3,340 MiB more than either control before its commits. That
> form is not in the repository either, and it was not built on
> `4700cf1`. See "Seven cumulative builds, the validation pool, a
> background commit and dcrd" below.
>
> **Note (2026-10-16): built in full and kept.** The stage after the
> measurement was built in the form of 2026-10-13: the sweeps of unclean
> stops with commits on their own thread, the rest of the tests and the
> mutation tests. The project owner made it the daemon's default and
> accepted ADR-0009's reworded rule. On a build of `4700cf1` with the
> cumulative builds' changes and the pool it took 389.55 s against
> 429.45 s, four runs each. It is `02b802c`. See "`8fc9160`, a
> background commit and dcrd v2.1.7" below.

**A persistent validation pool: the gate.** "Script validation fan-out
(2026-08-14)" above has asked for this arm to be measured. On
2026-10-12 it was put through a replay benchmark that is not in the
repository, and what follows is that benchmark's result and not a
sync's. The benchmark replays every 20th of the 89,438 blocks after
the assume-valid block, 4,472 of them, as the two script batches a
block makes, the stake tree's and the regular tree's, with the item
counts of the chain's blocks: 456,672 items. The items are signed
pay-to-pubkey-hash inputs made for the benchmark and checked through
the script engine with a warm signature cache. The benchmark links
the script engine of `b212a0a` with the SigHashAll change, the same
five crates as `3a367e5` (`dcroxide-txscript`, `-wire`, `-chainhash`,
`-dcrec` and `-crypto`), and none of the node's block-connect code,
for which it has stand-ins of its own. A fixed amount of hashing stands
in for the rest of a block's work: 0.2 ms after the stake batch and
0.45, 0.65 or 0.9 ms after the regular one. Five arms, three cycles a
setting, on the node's 16 threads, as a step of the quiet queue:

- **A**, today's rule: a batch under 16 items on the calling thread,
  a larger one on scoped threads made for the call
  (`MIN_PARALLEL_ITEMS`,
  `crates/dcroxide-blockchain/src/validate.rs:5232`).
- **B**, the same with fewer threads made: none once every item is
  claimed, and the caller works too.
- **C4, C8 and C16**, a pool of 15 threads that outlive the call, for
  batches of at least 4, 8 and 16 items.

| gap after the regular batch | A, the whole replay | B saves | C4 saves | C8 saves | C16 saves |
|---|---:|---:|---:|---:|---:|
| 0.45 ms | 5.747 s | 1.4 s | 19.8 s | 11.3 s | 4.9 s |
| 0.65 ms | 6.695 s | 1.5 s | 20.2 s | 11.3 s | 4.5 s |
| 0.9 ms | 7.857 s | 1.0 s | 19.8 s | 10.6 s | 4.1 s |

A saving is A's replay time less the arm's, times 20 for the blocks
left out, at the median of the three cycles. So it is an estimate of
seconds saved over the validated part of a sync, made from a replay.
The gate's rule was to go ahead at 9 s or more at every gap setting,
and the pool for batches of four or more met it at all three. What
C4 does and C16 does not is hand batches of 4 to 15 items to the pool,
which today's rule checks on the calling thread: 3,454 of the 4,472
stake batches replayed are of that size, and 744 of the regular ones.
No batch failed in any cycle. The serial cost of an item measured
28.3 µs, just outside the 19–28 µs the benchmark took as its sanity
range.

The pool was then built with that threshold and reviewed, in a scratch
tree outside the repository. It is not in the repository, and no sync
of it has been run, so no part of the saving above has been seen in a
sync.

> **Note (2026-10-16): in the repository since `f60ae3a`, and run in
> two syncs on 2026-10-13.** The pool takes a connected block's trees
> of four items or more, as gated. It differs from the build this
> paragraph describes in two rules: a batch it runs names its failing
> input of lowest index, and in an unwinding build a check's panic on a
> helper is raised again on the calling thread with its message. Arm
> A's threshold of 16 (`MIN_PARALLEL_ITEMS`, now
> `crates/dcroxide-blockchain/src/validate.rs:5510`) still decides
> whether scoped workers are made for every batch the pool does not
> take. Two syncs of a build of `4700cf1` with the pool took 491.3 s
> and 493.4 s, about 12 to 16 s under the same code without it, all of
> it after the assume-valid block: 13 to 15 s by the node's clock
> there, and 17 to 18 s with the flush time taken out, where the replay
> above estimated 19.8 to 20.2 s. The tree of `f60ae3a` has not been
> run in a sync. See "Seven cumulative builds, the validation pool, a
> background commit and dcrd" below.

**Coalescing the storage engine's page writes: designed, not built.**
A storage backend that holds a commit's page writes and issues
adjacent ones as one write before the sync was designed and reviewed
on paper. Nothing was built and nothing measured. The design's
estimate for a default sync on m3 is about no gain, between 9 s lost
and 10 s gained, for 0.4–0.6 GiB more resident memory, and its
recommendation is not to build it. Its main reason is read from the
runs of 2026-10-11 with and without copy-on-write: over matched
flushes the copy-on-write premium grows through a sync at an unchanged
size of write call, so the design takes it to be unlikely to be a cost
per call that fewer, larger calls would remove; what the premium is
paid for was not identified. That is an estimate from those records.

**What was not measured.**

- dcrd, on 2026-10-12. Its last runs are 2,883.9 s in one run on the
  evening of 2026-10-11 and a median of 2,863.9 s over four runs of
  2026-10-09 and 2026-10-10, on the same machine and harness. Set
  against them, across sessions, the 612.4 s of `540b203` is 4.71x and
  4.68x, and the 494.6 s and 490.8 s of the read-ahead build are 5.83x
  and 5.88x, and 5.79x and 5.84x.
- The code of `b4ceb1c` as committed, in any sync.
- `5cf9e04` alone, and the changes within the small batch and within
  the index batch one at a time.
- Any of the eleven with `--noexistsaddrindex`, so not what the index
  costs a sync now; with `--assumevalid=0` or the tuning levers; on
  another filesystem, on m1 or m2, or on fewer cores than the eight
  the node had. Only the code of `b4a5d2d` ran without copy-on-write.
- A whole sync over a delayed or a real link, with either window or
  with read-ahead; a link held to a set rate; a narrowing or a
  widening of the window in a run of the daemon.
- A replay that validates every block. The syncs run scripts over the
  89,438 blocks after the assume-valid block, so in these runs the
  SigHashAll path ran over those blocks and not over the ones before
  them.
- A profile of any of this code.
- The validation pool in a sync, and the background commit in more
  than the two pairs above.

> **Note (2026-10-13): five of these were run on 2026-10-13**, in
> another session: dcrd v2.1.6 once, 2,920.3 s; the code of `b4ceb1c`,
> as `4700cf1`, three times; the eleven with `--noexistsaddrindex`, as
> `4700cf1`, once, 423.6 s; the validation pool in two syncs of a build
> of `4700cf1`; and a background commit in another form, on `231997b`,
> in two pairs and one more run. The overlay's ceiling was raised in
> one run, together with a developer variable the tree does not have,
> in a build that is not a commit's. No profile was taken. See "Seven
> cumulative builds, the validation pool, a background commit and dcrd"
> below.

Raw: the comparison's `runs.jsonl` rows labelled `h-nocow`, `h-base`,
`h-small`, `h-index`, `h-sighash`, `h-window`, `h-ra-off-1`,
`h-ra-on-1`, `h-bg-sync-1`, `h-bg-on-1`, `h-ra-off-2`, `h-ra-on-2`,
`h-rabg-sync-1` and `h-rabg-on-1`, with per-run samples, flush logs
and node logs as above; `delay.jsonl` rows `dl2-dcrdrule-50`,
`dl2-budget-50`, `dl2-dcrdrule-150` and `dl2-budget-150`, and
`mainnet.jsonl`, with the scripts that drove them; `pool-gate.jsonl`
with the replay benchmark's source; the patches of the measured trees
and of the two experiments; and the designs of the pool, the
background commit and the coalesced writes.

## Seven cumulative builds, the validation pool, a background commit and dcrd (2026-10-13)

"Eleven changes, a background commit not kept and a pool gate" above
left a default sync at 494.6 s and 490.8 s for a build that is not the
code of any commit, dcrd unrun that day, the index's cost on that code
unmeasured and the persistent validation pool measured only in a
replay. On 2026-10-13, between 05:20 and 13:03, 27 syncs were run on
m3:

- three of `4700cf1`, the commit then pushed, which is the code of
  `b4ceb1c` with one log line more;
- nine of seven builds on `4700cf1` that add, one group at a time, the
  changes the seventeen commits from `d76e8ec` to `6376eeb` later
  carried;
- two of a build of `4700cf1` with the persistent validation pool,
  which `f60ae3a` later carried;
- five of a background commit built on `231997b`, which is not in the
  repository;
- five of settings that are not the tree's, and one with a deeper
  allocator thread cache;
- one of `4700cf1` with the exists-address index off;
- one of dcrd v2.1.6.

The commits were made on 2026-10-16, after the runs. The tree they
leave, `f60ae3a`, has not been run in a sync.

The syncs are in the harness of the sections above: mainnet from
genesis to 1,116,035 over loopback from the dcrd v2.1.6 block server,
at the defaults but for the setting a row names, with the same pinning,
clock and quiet gate, the flush log on in every dcroxide run, and a
`sync` and a 300 s idle before every run but n-head-1 and n-pool-1.
Those two were the first of the two batches the queue was started
with, at 05:19 and 08:00: n-head-1 began 87 s after three smoke syncs
of 150,000 blocks, and n-pool-1 about three minutes after n-head-2
ended. Every run exited 0 on the server's tip, `8752fdc9…`, none failed
and none was marked disturbed; other userland was 0.03% to 0.15% of
the machine.

The runs are read on three measures, because wall time moved by up to
10 s between runs of one binary this session (below):

- **Wall** is the harness's clock, from starting the node to the first
  once-a-second `getblockcount` poll that sees 1,116,035. That poll
  comes 0.02 to 1.00 s after the node logs the block, so a difference
  under a second is not measured.
- **Less commit** is wall less the commit phases of the flushes made
  inside the clock. Every dcroxide flush log ends with one flush the
  close makes at shutdown. It starts 0.07 to 0.27 s after the node logs
  that its server is shutting down, which the harness causes only after
  it has stopped the clock, and no flush inside the clock ends after
  the node logs the tip. Its commit, 1.16 to 3.33 s, is in no figure
  here.
- **Flush-free** is the node's own clock, from its first log line to
  the line that shows 1,116,035, less the time of the flushes inside
  it.

The time to block 1,026,597, the assume-valid block, is interpolated
from the node log's lines for blocks processed, with the flushes'
stalls taken out and the block rate either side weighed in. It is good
to about 1 s, and uncertain by a flush's length where the block falls
beside one, which it does once: in n-head-1 a flush ran from 394.7 s to
397.5 s, and if the block came after it the time after it is 115.3 s.
"After it" is the node's clock less that time, so the two columns add
to the node's clock and not to wall. Peak RSS is `VmHWM` read after the
clock stops and before the harness signals the node, so before the
closing flush, which raised the mark by 120 to 545 MiB in the five runs
whose flush log records it. Node CPU time is the process's. The start
times are taken from each run's id; the `started` field of
`runs.jsonl` is 9 to 11 s late in all 27 records.

| run | started | build | setting | wall | commit, inside the clock | less commit | flush-free | to block 1,026,597 | after it | node CPU time (user + sys) | peak RSS |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| n-head-1 | 05:20 | `4700cf1` | defaults | 513.4 s | 80.6 s | 432.8 s | 388.9 s | 395.2 s | 117.7 s | 1,126.4 s (1,030.1 + 96.3) | 3,021 MiB |
| n-L0-1 | 05:36 | L0 | defaults | 505.6 s | 73.0 s | 432.7 s | 388.9 s | 392.8 s | 112.1 s | 1,125.0 s (1,029.0 + 96.0) | 2,895 MiB |
| n-L1-A | 05:51 | L1 | defaults | 481.4 s | 72.4 s | 409.1 s | 365.5 s | 372.1 s | 109.2 s | 1,095.4 s (1,002.7 + 92.7) | 2,721 MiB |
| n-L2-R3 | 06:06 | L2 | defaults | 481.7 s | 81.0 s | 400.7 s | 356.4 s | 370.2 s | 111.0 s | 1,084.9 s (992.1 + 92.8) | 2,760 MiB |
| n-L3-R4 | 06:21 | L3 | defaults | 466.7 s | 72.9 s | 393.8 s | 349.9 s | 356.9 s | 109.0 s | 1,075.2 s (978.5 + 96.7) | 3,047 MiB |
| n-L4-R5 | 06:36 | L4 | defaults | 458.1 s | 71.2 s | 386.9 s | 342.4 s | 349.9 s | 107.5 s | 1,064.5 s (970.0 + 94.5) | 3,303 MiB |
| n-L5-R6 | 06:51 | L5 | defaults | 446.5 s | 70.4 s | 376.1 s | 333.1 s | 340.6 s | 105.9 s | 1,058.7 s (965.6 + 93.1) | 3,166 MiB |
| n-L6-B-1 | 07:05 | L6 | defaults | 441.9 s | 73.2 s | 368.7 s | 324.6 s | 335.2 s | 105.8 s | 1,057.4 s (963.4 + 94.0) | 3,188 MiB |
| n-L6-B-2 | 07:20 | L6 | defaults | 442.2 s | 72.9 s | 369.3 s | 325.0 s | 334.0 s | 107.2 s | 1,059.4 s (965.3 + 94.1) | 3,089 MiB |
| n-L0-2 | 07:34 | L0 | defaults | 502.8 s | 72.2 s | 430.6 s | 387.9 s | 390.0 s | 112.7 s | 1,123.8 s (1,028.2 + 95.6) | 3,021 MiB |
| n-head-2 | 07:49 | `4700cf1` | defaults | 513.5 s | 80.0 s | 433.5 s | 390.6 s | 398.4 s | 115.1 s | 1,123.9 s (1,029.5 + 94.4) | 3,128 MiB |
| n-pool-1 | 08:02 | the pool on `4700cf1` | defaults | 491.3 s | 74.1 s | 417.2 s | 373.5 s | 391.2 s | 99.4 s | 1,074.4 s (1,008.1 + 66.3) | 2,998 MiB |
| n-pool-2 | 08:17 | the pool on `4700cf1` | defaults | 493.4 s | 75.4 s | 418.0 s | 374.1 s | 392.8 s | 99.9 s | 1,079.4 s (1,011.0 + 68.4) | 2,908 MiB |
| n-K-umax3M-1 | 08:32 | L0 | `DCROXIDE_EXISTSADDR_U_MAX=3000000` | 502.4 s | 69.3 s | 433.1 s | 390.9 s | 385.8 s | 116.4 s | 1,122.3 s (1,031.8 + 90.5) | 3,061 MiB |
| n-K-umax3M-2 | 08:47 | L0 | `DCROXIDE_EXISTSADDR_U_MAX=3000000` | 508.3 s | 69.9 s | 438.4 s | 396.4 s | 392.5 s | 115.4 s | 1,129.5 s (1,038.5 + 91.0) | 3,281 MiB |
| n-M1-tcache | 09:03 | `4700cf1` | a deeper glibc thread cache (`GLIBC_TUNABLES`, below) | 2,005.2 s | 80.5 s | 1,924.7 s | 1,326.9 s | 1,706.4 s | 298.3 s | 3,021.8 s (2,917.8 + 104.0) | 4,794 MiB |
| n-bg-test-1 | 09:43 | background commit on `231997b` | defaults (commits in the background, with the snapshot) | 465.7 s | 75.6 s | 390.1 s | 346.6 s | 357.4 s | 107.5 s | 1,150.1 s (1,049.2 + 100.9) | 3,115 MiB |
| n-bg-control-1 | 09:58 | background commit on `231997b` | `DCROXIDE_DB_SYNC_COMMIT=1` | 501.1 s | 71.2 s | 430.0 s | 387.0 s | 388.3 s | 112.2 s | 1,121.8 s (1,026.7 + 95.1) | 2,996 MiB |
| n-bg-bare | 10:14 | background commit on `231997b` | `DCROXIDE_DB_BARE_COMMIT=1` | 471.1 s | 76.1 s | 395.0 s | 349.3 s | 359.9 s | 110.2 s | 1,152.2 s (1,052.7 + 99.5) | 3,321 MiB |
| n-M2-memtable4M | 10:28 | L0 | `DCROXIDE_EXISTSADDR_MEMTABLE_KEYS=4000000` | 502.7 s | 66.4 s | 436.3 s | 395.2 s | 388.4 s | 113.8 s | 1,135.7 s (1,042.7 + 93.0) | 3,264 MiB |
| n-M2-memtable4M-umax3M | 10:44 | L0 | `DCROXIDE_EXISTSADDR_MEMTABLE_KEYS=4000000` and `DCROXIDE_EXISTSADDR_U_MAX=3000000` | 495.8 s | 59.4 s | 436.4 s | 398.0 s | 384.3 s | 111.1 s | 1,134.3 s (1,045.5 + 88.8) | 3,581 MiB |
| n-M5-overlay450-umax4.5M | 10:59 | L0 | `DCROXIDE_DB_OVERLAY=450` and `DCROXIDE_EXISTSADDR_U_MAX=4500000` | 503.2 s | 57.6 s | 445.6 s | 403.1 s | 389.8 s | 112.8 s | 1,140.8 s (1,049.3 + 91.5) | 3,411 MiB |
| n-head-noindex | 11:15 | `4700cf1` | `--noexistsaddrindex` | 423.6 s | 38.2 s | 385.4 s | 358.4 s | 321.9 s | 101.2 s | 947.3 s (872.6 + 74.7) | 2,149 MiB |
| n-head-3 | 11:28 | `4700cf1` | defaults | 504.2 s | 70.5 s | 433.7 s | 390.6 s | 392.4 s | 111.2 s | 1,124.5 s (1,030.5 + 94.0) | 2,832 MiB |
| n-dcrd | 11:44 | dcrd v2.1.6 | defaults | 2,920.3 s | — | — | — | — | — | 5,679.8 s (4,542.1 + 1,137.7) | 1,852 MiB |
| n-bg-test-2 | 12:39 | background commit on `231997b` | defaults (commits in the background, with the snapshot) | 460.5 s | 69.9 s | 390.6 s | 348.0 s | 355.8 s | 104.7 s | 1,151.3 s (1,050.9 + 100.4) | 3,053 MiB |
| n-bg-control-2 | 12:54 | background commit on `231997b` | `DCROXIDE_DB_SYNC_COMMIT=1` | 500.5 s | 68.1 s | 432.4 s | 389.8 s | 389.5 s | 110.7 s | 1,123.9 s (1,029.6 + 94.3) | 3,341 MiB |

The builds L0 to L6 are described below, and they ran in the
table's order. Of the 27, only the five runs of `4700cf1` and dcrd's
are of the code of a commit.

**The block files are the same in all 27, dcrd's included.** After
shutdown the harness takes one SHA-256 over the block files' names and
bytes and records its first 64 bits. They were `33b7ac837a45c74f` in
every run, over 36 files and 19,202,596,910 B: in the runs of builds
that lay a block's record out on the reader thread (L5 and L6), in
those that do not and in dcrd's. That is the equality of a 64-bit
prefix of one hash, not a byte-for-byte comparison, and the metadata
store is not compared: only the tip and the data directory's size are
recorded.

**This session is not those of 2026-10-11 and 2026-10-12.** The block
server read 15.7 to 18.0 GB from the drive during every run, where it
read none in the runs of 2026-10-11 and none in those of 2026-10-12 but
the first two, h-nocow and h-base, which read 1,489 MB and 269 MB. The
block thread waited at most 1.04 s in all for the reader in any dcroxide
run, so no effect on dcroxide's times is shown. Still, this session's
times are not to be set beside those of the sections above without that
label. In particular `4700cf1` ran 504.2 to 513.5 s here, and the
494.6 s and 490.8 s of 2026-10-12 are another session and another build,
the read-ahead build before its review's fixes. One percent of a default
sync is 5.0 to 5.1 s in this session.

**The pushed commit, and why wall is not enough.** `4700cf1` took
513.4 s, 513.5 s and 504.2 s. The first two spent 80.6 s and 80.0 s in
the commit phases of their flushes inside the clock and the third
70.5 s. With those seconds taken out the three are 432.8 s, 433.5 s and
433.7 s, and flush-free 388.9 s, 390.6 s and 390.6 s.

- **Four runs had a commit phase near 80 s**: those two, n-L2-R3 and
  n-M1-tcache. The other default-setting runs that commit on the
  flushing thread took 68.1 to 75.4 s.
- **The extra was waiting.** `4700cf1`'s binary logs no processor time
  per phase. In n-L2-R3, of a build that does, the commit phases spent
  44.7 s on a processor, inside the 44.5 to 47.1 s of the other eight
  runs of the cumulative builds, and 36.1 s asleep against their 25.3
  to 27.7 s.
- **What it goes with.** Over the 16 default-setting runs that commit
  on the flushing thread, the commit seconds follow the bytes written
  at the drive (r = 0.88: 60.2 to 60.9 GB in the three slow runs, 55.3
  to 60.1 GB in the rest) and the mean I/O pressure in the samples
  (r = 0.86), and not the node's own `write_bytes` (r = 0.24). The
  records do not say what wrote the extra bytes, nor which way the
  relation runs. Two slow runs of three for `4700cf1`, against one of
  thirteen for the other default-setting builds, neither shows nor
  rules out something of that binary's own.

So each change below is read on wall and on the two commit-free
measures. On those two, runs of one binary at one setting differ by
0.4 to 2.8 s, and by 5.3 s and 5.5 s in the one pair at a raised flush
request.

**How sure a step is.** Pooling the spread of the runs repeated with
one binary at the defaults, two or three runs each, on the assumption
that they share one variance: at 95%, a difference between two single
runs is good to about ±3.5 s less commit and ±3.7 s flush-free, or
±5.7 s and ±5.9 s with the pair at the raised flush request counted
in, and to about ±11 s by wall. With two runs on one side the interval
is 0.87 times that; with two on each side it is ±2.5 to ±4.2 s on the
commit-free measures and ±7.9 s by wall.

**L0 runs at the speed of `4700cf1`.** L0 is `4700cf1` with the
processor time per flush phase in the flush log (`d76e8ec`) and the
developer variable described below, unset: 505.6 s and 502.8 s, 7.8 to
10.7 s under the two slow-commit runs of `4700cf1` by wall and within
1.4 s of the third. Less commit it took 432.7 s and 430.6 s and
flush-free 388.9 s and 387.9 s, 1.6 to 1.8 s under `4700cf1` on those
two, which repeats do not resolve.

**dcrd, one run.** dcrd v2.1.6, the binary of the sections above, from
the same block server: 2,920.3 s, with 5,679.8 s of CPU time
(4,542.1 + 1,137.7) and a peak of 1,852 MiB. Against the three runs of
`4700cf1` in this session that is 5.69x (against 513.4 s and 513.5 s)
to 5.79x (against 504.2 s), and 5.72x against their mean. It is one
dcrd run, so that is a range over three pairings with it and not a
spread of the ratio. Seven runs of this binary between 2026-10-09 and
2026-10-11, some from a dcroxide block server, took 2,848.8 to
2,947.3 s; 2,920.3 s is the second slowest of the eight. Neither figure
holds dcroxide's closing flush, which comes after the clock: shutdown
took 2.3 s, 2.4 s and 4.0 s in the three runs of `4700cf1` and 0.2 s
for dcrd.

**The index off.** One run of `4700cf1` with `--noexistsaddrindex`:
423.6 s, 80.6 to 89.9 s under each of its three default runs, with
385.4 s less commit and 358.4 s flush-free. It made 40 flushes inside
the clock against 54 to 56, and peaked at 2,149 MiB against 2,832 to
3,128 MiB. dcrd was not run with the index off in this session.

**Seven cumulative builds.** Each adds one change or group of changes
to the build before it, in the order below, which is not the order of
the commits that carry them: the bucket index, second here, is the
last code commit of the series but the pool's. Every build also holds
`DCROXIDE_EXISTSADDR_U_MAX`, a developer variable for the number of
keys not yet journaled at which the exists-address index asks for a
flush. It was unset in all nine runs, so the index asked at 1,500,000
keys, the figure the tree fixes. The tree does not have the variable:
it was left out of the series. So none of the builds is the tree of a
commit, and the last holds the changes of the seventeen commits from
`d76e8ec` to `6376eeb` and the variable. L0 and L6 ran twice, L0 before
and after the others, and L1 to L5 once each.

| build | adds | carried by | runs |
|---|---|---|---:|
| L0 | to `4700cf1`, the flushing thread's processor time per phase in the flush log, and the variable | `d76e8ec`; the variable by none | 2 |
| L1 | seven changes to header acceptance and the block thread: the rejected-transaction filter reset without a pass over data already zero, the node remembered beside each agenda's activation anchor, the early exit of the majority-version walk, one hash per accepted header, the treasury predicates refusing without building an error, with the spent outputs counted once, the copies, second store lookup and input set taken off an arriving block's path, and nothing sent to the rebroadcast thread while it tracks nothing | `8bec107`, `e6bc950`, `be14253`, `b2cacc3`, `0985600` and `674782a`, `3bd5e64`, `d82d86c` | 1 |
| L2 | nested bucket lookups answered from a copy of the bucket index in memory | `6376eeb` | 1 |
| L3 | the exists-address index's insert without a second search of unchanged partitions, and the overlay layers a flush retired freed after the writer is released | `64359e7`, `85a5dc8` | 1 |
| L4 | the ticket treap's path borrowed, its keys compared inline and one descent | `9330b4b` | 1 |
| L5 | the block-file record laid out on the reader thread from the bytes received | `a589c4a` | 1 |
| L6 | a block's two merkle trees built on the reader thread, and its header hash taken once and handed down the processing call | `44cf801`, `54e8cad`, and the count test `4878589` | 2 |

What each step gained, on each measure, with how far the commit-free
figures are good (95%):

| step | runs | by wall | less commit | flush-free | block thread's CPU time outside its flushes | share of L0's 504.2 s, commit-free | good to, commit-free |
|---|---|---:|---:|---:|---:|---:|---:|
| L0 to L1 | two against one | 22.8 s | 22.6 s | 22.9 s | 23.3 s | 4.5% | ±3.0 to ±5.1 s |
| L1 to L2 | one against one | not resolved: 481.4 s and 481.7 s | 8.3 s | 9.1 s | 8.4 s | 1.6–1.8% | ±3.5 to ±5.9 s |
| L2 to L3 | one against one | 15.0 s, L2's slow commit phase in it | 7.0 s | 6.5 s | 1.4 s | 1.3–1.4% | ±3.5 to ±5.9 s |
| L3 to L4 | one against one | 8.6 s | 6.9 s | 7.5 s | 7.7 s | 1.4–1.5% | ±3.5 to ±5.9 s |
| L4 to L5 | one against one | 11.6 s | 10.8 s | 9.3 s | 9.2 s | 1.8–2.1% | ±3.5 to ±5.9 s |
| L5 to L6 | one against two | 4.5 s | 7.1 s | 8.3 s | 8.3 s | 1.4–1.6% | ±3.0 to ±5.1 s |
| L0 to L6 | two against two | 62.2 s | 62.6 s | 63.6 s | | 12.3% by wall | ±2.5 to ±4.2 s |

The CPU column is user and system time. By wall a step between two
single runs is good to about ±11 s, ±9.7 s with two runs on one side.

- **As one batch the seven builds gained 62 to 64 s on every
  measure, 12.3% of L0 by wall**, with two runs at each end: good to
  ±8 s by wall and ±2.5 to ±4.2 s on the commit-free measures, so
  beyond doubt. By the node's clock 56.8 s of it falls before the
  assume-valid block and 5.9 s after it.
- **Step by step each is a single run's best estimate.** By that
  estimate every step is above 1% of a sync on both commit-free
  measures (1.3% to 4.5%). Beyond the uncertainty of single runs only
  the first is, and the block-file record on the tighter interval.
- **Like for like against `4700cf1`**, L6 is 62.2 s or 12.3% under
  n-head-3 by wall, and 64.4 s under the mean of `4700cf1`'s three runs
  with the commit seconds taken out. Against `4700cf1`'s median run,
  513.4 s, it is 71.4 s, but that run is one of the two with a slow
  commit phase and both runs of L6 had ordinary ones.

What the records show beyond the times, step by step:

- **L1.** The initial headers sync took 12.5 s and 12.7 s in L0's two
  runs, the second of them after all the others, and 7.2 to 7.5 s in all
  seven runs of L1 to L6: about 5 s of the gain, before any block is
  connected. The rest was not divided among the seven changes.
- **L2.** By wall the two runs are the same, a difference under the
  harness's resolution, because L2's commit phases took 8.6 s longer,
  8.4 s of it asleep: 36.1 s asleep against 27.7 s, with 44.7 s on a
  processor against 44.5 s. Outside the flushes the block thread's CPU
  time fell 8.4 s and the index thread's 2.8 s.
- **L3.** The 15.0 s by wall holds L2's slow commit phase. What holds
  beyond one run is the wait the two changes act on. The flush log's
  total of the waits for the writer by the threads other than the index
  thread, which bounds the block thread's from above (see "Eleven
  changes, a background commit not kept and a pool gate"), less the
  flushes the index thread ran, was 8.1 to 9.5 s in the eleven runs of
  code without them that committed on the flushing thread with no other
  setting changed (`4700cf1`'s three, L0's two, L1, L2, the pool's two
  and the background commit's two control runs) and 1.6 to 1.7 s in all
  five runs with them, about 6.4 s less. The time the index's queue was
  full rose from 3.1–3.2 s to 4.0–4.1 s. The block thread's user time
  fell 8.2 s, but mostly because seven flushes ran on the index thread
  instead (43 on the block thread, where L2 ran 50); outside its flushes
  its CPU time fell 1.0 to 1.4 s. The index thread's CPU time outside
  its flushes fell from 119.0 s to 107.9 s, and was 106.6 to 107.1 s in
  the four later runs. How much is each of the two changes was not
  measured.
- **L4.** Neither run had a slow commit phase. The block thread's CPU
  time outside its flushes fell 7.7 to 8.2 s.
- **L5.** The node's line at shutdown reported records laid out for
  1,116,034 blocks in 7.078 s and 1,116,034 written as laid out, and
  the same counts in 7.128 s and 7.165 s in the two runs of L6. The
  reader thread's user time rose 7.0 s, from 94.4 s to 101.5 s, as the
  block thread's CPU time outside its flushes fell 9.2 s, and the block
  thread waited 0.82 s in all for the reader where it had waited
  0.54 s.
- **L6.** The node's hashing figure rose from 47.369 s to 52.536 s and
  52.562 s, the reader's user time from 101.5 s to 106.6 s, and the
  block thread's wait for the reader to 1.04 s and 1.01 s; the block
  thread's CPU time outside its flushes fell 8.3 s. By wall the step
  is 4.5 s against the one run of L5, whose 54 flushes inside the clock
  took 113.4 s against 55 in 116.2 s and 116.4 s in L6's: the step
  nearest the bar by wall, and above it on the commit-free measures.

**The last two steps move CPU time rather than remove it.** The
block-file record and the merkle trees put about 7 s and 5 s of CPU
time on the reader thread. That pays while the reader has time to
spare, and here it waited 321.8 s and 321.9 s for the block thread in
L6's runs, fed by a server on the same machine.

**Memory and CPU.** Peak RSS before the closing flush was 2,895 and
3,021 MiB for L0, 2,721 for L1, 2,760 for L2, 3,047 for L3, 3,303 for
L4, 3,166 for L5, and 3,188 and 3,089 MiB for L6. Runs of one binary
differed by up to 345 MiB this session. L1 and L2 are the two lowest
default-setting runs of the session, and from L3 on the runs lie
inside the 2,832 to 3,341 MiB of `4700cf1`'s runs and the background
commit's control runs; which step, if any, moves memory is not decided
by one run each. The process's user time fell from 1,029.0 s and
1,028.2 s at L0 to 963.4 s and 965.3 s at L6.

**The validation pool, on `4700cf1` alone.** One build: `4700cf1` with
a persistent pool for a connected block's script trees of four items
or more, the change `f60ae3a` later carried on top of the seventeen
commits above. Two runs, 491.3 s and 493.4 s. It was not run with any
change of the cumulative builds.

- **About 12 to 16 s, 2.4% to 3.2% of a sync of 504 s, by the
  measure.** By wall 11.9 s against the mean of the runs of that code
  with an ordinary commit phase, n-head-3 and the two of L0 (504.2 s).
  Less commit 15.8 s, 417.2 s and 418.0 s against 432.8 to 433.7 s,
  and 14.9 to 16.6 s over the pairings. Flush-free 16.3 s. Against
  n-head-1 and n-head-2 alone it is 20 to 22 s by wall, and 18.0 s
  against the mean of `4700cf1`'s three runs, which holds the slow
  commit phases of those two and is not the pool's doing.
- **All of it falls after the assume-valid block**, before which no
  script is checked and the pool does not exist. From that block to
  the tip the two runs took 99.4 s and 99.9 s by the node's clock,
  against 110.7 to 117.7 s in seven runs of code without the pool
  (`4700cf1`'s three, L0's two and the background commit's two control
  runs): 13 to 15 s less, and 17 to 18 s with the flush time taken out.
  The replay gate of 2026-10-12 had estimated 19.8 to 20.2 s over the
  validated part of a sync for a pool at this threshold. Before the
  block the pool's runs were about 2 s slower outside the flushes than
  the mean of those seven, at or just past their top, which two runs
  do not resolve.
- **CPU.** The process's system time was 66.3 s and 68.4 s, against
  94.0 to 96.3 s for `4700cf1`, and its user time 1,008.1 s and
  1,011.0 s against 1,029.5 to 1,030.5 s. Both runs ended with 15
  threads named `scriptval-N`, one fewer than the 16 logical CPUs the
  node was pinned to, each with 27.2 to 27.4 s of user time.
  Per-thread figures do not compare between the pool and the rest
  without care: in `4700cf1`'s runs the script checks' scoped threads
  had exited before the harness's last read, so 442 to 444 s of user
  time and 22 to 23 s of system time are listed under no thread
  there.
- **Memory.** Peak RSS 2,998 and 2,908 MiB, inside the 2,832 to
  3,128 MiB of `4700cf1`'s three runs.

**A background commit, in a third form, not kept.** Built on
`231997b`, one commit behind `4700cf1` and so the code of `b4ceb1c`
without its log line, in a scratch tree outside the repository. For a
flush that a commit's own check trips, the storage engine's commit runs
on a second thread, `dbcommit`, as in the form of 2026-10-12 above, and
here it holds a read snapshot of the store while it runs. One binary,
three arms: nothing set, with the snapshot; `DCROXIDE_DB_SYNC_COMMIT=1`,
every commit on the committing thread, the control arm; and
`DCROXIDE_DB_BARE_COMMIT=1`, in the background without the snapshot, as
in the form of 2026-10-12. Both variables are the experiment's, and no
build of the repository reads them. Two pairs, each with the snapshot
arm before its control (09:43 and 09:58, 12:39 and 12:54), not
alternated, and one run without the snapshot.

> **Note (2026-10-16): one of the two is now the daemon's.** Since
> `02b802c` the daemon commits a flush that a commit trips on `dbcommit`
> by default, holding the snapshot, and reads `DCROXIDE_DB_SYNC_COMMIT`,
> which puts every commit back on the committing thread.
> `DCROXIDE_DB_BARE_COMMIT` is read by no build of the repository. See
> "`8fc9160`, a background commit and dcrd v2.1.7" below.

- **With the snapshot it took 465.7 s and 460.5 s, against its control
  arm's 501.1 s and 500.5 s**: 35.4 s and 40.0 s less, 7.1% and 8.0% of
  its own control. That is against its control, on `231997b`, and not
  against `4700cf1`. The control's commit phases were at the fast end
  (71.2 s and 68.1 s): by wall it ran 3 to 13 s under `4700cf1`'s runs,
  and less commit 430.0 s and 432.4 s against 432.8 to 433.7 s.
- **31 to 34 s of the gain came before the assume-valid block** (30.9 s
  and 33.8 s) and 4.7 s and 6.1 s after it, by the node's clock. The
  threads that trip flushes spent 46.7 s and 47.0 s in them inside the
  clock against the control's 113.5 s and 110.5 s. Of those 64 to
  67 s, 35 to 40 s reached the wall: the time outside the flushes rose
  by 25.7 s and 21.1 s before the block and 5.6 s and 3.5 s after it.
- **Without the snapshot, one run: 471.1 s**, 30.0 s and 29.4 s under
  the two controls and 5.4 to 10.6 s over the runs with it. What marks
  that arm is the writing before the commits: 3,587 MiB, against 247
  and 318 MiB in the controls and 133 and 89 MiB with the snapshot, and
  1.26 million read calls against 1.02 to 1.06 million.
- **Process CPU time was about 28 s higher with the snapshot**, about
  22 s of it user and 5 to 6 s system. Each background commit runs on a
  new `dbcommit` thread that exits, so its CPU is in no per-thread
  figure.
- **No memory cost was detected, at a resolution of about 300 MiB.**
  Peak RSS before the closing flush was 119 MiB above the control in
  the first pair and 288 MiB below it in the second, and −226 and
  +57 MiB paired the other way. The run without the snapshot peaked
  325 MiB above the first control and 20 MiB below the second. Runs of
  one binary differed by 62 to 345 MiB this session, so a difference of
  two single runs is good to about ±440 MiB, and of two pairs' means to
  about ±310 MiB. The last reading each flush log has, after the
  closing commit and not the mark at exit, is 3,266 and 3,299 MiB with
  the snapshot, 3,536 and 3,461 MiB for the controls and 3,886 MiB
  without the snapshot.

On 2026-10-12 the form without the snapshot had peaked 981 and 748 MiB
above its control runs, one pair each on other code. This form is not
in the repository either. It was not built on `4700cf1`, and it was
not run with the cumulative builds' changes or the pool.

> **Note (2026-10-16): this form is the one kept.** On the build of
> `4700cf1` with the cumulative builds' changes and the pool it took
> 389.55 s against 429.45 s for that build without it, four runs each,
> 9.3% less, with 27 s more process CPU time and about 256 MiB more peak
> resident memory to the tip at the median. Ported onto the later
> commits, without `DCROXIDE_DB_BARE_COMMIT`, it is `02b802c`, on by
> default in the daemon. See "`8fc9160`, a background commit and dcrd
> v2.1.7" below.

**Settings, on L0.** Five runs of the L0 binary, against its two
default runs (mean 504.2 s). The flush request is the developer
variable above, which the tree does not have. The memtable target
(`DCROXIDE_EXISTSADDR_MEMTABLE_KEYS`, 2,000,000 keys by default) and the
overlay's ceiling (`DCROXIDE_DB_OVERLAY`, 300 MiB by default) are the
tree's variables, here at values that are not its defaults.

| runs | setting | wall | flushes inside the clock | their time | flush-free | block thread's CPU time outside its flushes | peak RSS |
|---|---|---:|---:|---:|---:|---:|---:|
| n-L0-1, n-L0-2 | defaults | 505.6 s, 502.8 s | 54, 54 | 116.1 s, 114.8 s | 388.9 s, 387.9 s | 345.0 s, 344.2 s | 2,895, 3,021 MiB |
| n-K-umax3M-1, n-K-umax3M-2 | `DCROXIDE_EXISTSADDR_U_MAX=3000000` | 502.4 s, 508.3 s | 42, 41 | 111.3 s, 111.6 s | 390.9 s, 396.4 s | 345.2 s, 351.2 s | 3,061, 3,281 MiB |
| n-M2-memtable4M | `DCROXIDE_EXISTSADDR_MEMTABLE_KEYS=4000000` | 502.7 s | 55 | 107.0 s | 395.2 s | 350.9 s | 3,264 MiB |
| n-M2-memtable4M-umax3M | both of those | 495.8 s | 41 | 97.3 s | 398.0 s | 350.4 s | 3,581 MiB |
| n-M5-overlay450-umax4.5M | `DCROXIDE_DB_OVERLAY=450` and `DCROXIDE_EXISTSADDR_U_MAX=4500000` | 503.2 s | 28 | 99.5 s | 403.1 s | 356.9 s | 3,411 MiB |

- **Three settings show no gain**: the larger flush request, the larger
  memtable target, and the larger overlay together with a flush
  request of 4,500,000. In every setting the flushes took less time,
  by 4.0, 8.4, 18.1 and 15.9 s in the order of the table, and the time
  outside them rose, by 2.5 to 8.0, 6.8, 9.6 and 14.7 s.
- **The two index settings together took 495.8 s in one run**, 7.0 s
  and 9.8 s (1.4% to 1.9%) under the two runs of L0, with 560 to
  690 MiB more at peak than L0 and 240 MiB above the highest peak of
  any default-setting run of the session, 3,341 MiB. One run against a
  pair is good to about ±10 s by wall, so a gain is neither shown nor
  excluded.
- They draw on the same commit seconds as the background commit, and
  were run on L0 alone.

**A deeper allocator thread cache.** One run of `4700cf1` with glibc's
per-thread cache raised two ways at once through `GLIBC_TUNABLES`,
`glibc.malloc.tcache_count=4096` and `glibc.malloc.tcache_max=131072`:
2,005.2 s, 3.91 to 3.98 times `4700cf1`'s default runs, with 2,917.8 s
of user and 104.0 s of system time and a peak of 4,794 MiB. The block
thread used 1,775.1 s of user time, the 63 flushes inside the clock
took 677.8 s, and the assume-valid block came at 1,706 s. Both tunables
were changed in the one run, so the records cannot say which did it,
and no run with the count alone was made. The tree sets no allocator
tunable.

**What was not measured.**

- The tree as committed, `f60ae3a`, in any sync, and any build that
  holds two or more of the cumulative builds' changes, the pool and the
  background commit. The three gains rest on three baselines, L0,
  `4700cf1` and the background commit's own control, and the
  cumulative builds and the background commit both gain before the
  assume-valid block, so their sum is not a prediction. With the later
  changes the pool fans out trees of 4 to 15 items beside a reader
  thread that `a589c4a` and `44cf801` gave more work, and its threshold
  has not been tried with them.
- Second runs of L1 to L5. The queue held n-L1-A-2 and n-L2-R3-2, the
  repeats of L1 and L2, and n-M6-utxo600, a run with a UTXO cache
  setting of 600; all three were skipped for the session's deadline.
  One more run of each of L1 to L5 would make each step good to about
  ±2.5 to ±4 s on the commit-free measures.
- The background commit on `4700cf1` or later code, and its memory to
  better than about 300 MiB.
- The settings on anything but L0, and a second run of the two index
  settings together.
- Either thread-cache tunable alone.
- A second dcrd run, and dcrd with the index off, in this session.
- The metadata store's end state in any run, and the memory high-water
  mark at exit.
- A sync from peers over a real link. Every run took its blocks from a
  server on the same machine, and the block-file record and the merkle
  trees moved work onto a reader thread that had time to spare here.
- A profile of any of this code, or a run on m1, m2, another filesystem
  or fewer cores.

> **Note (2026-10-16): two of these were run.** `8fc9160`, which holds
> the seventeen commits and the pool as committed, took a median of
> 430.7 s over four runs, and the background commit, on a build of
> `4700cf1` with the cumulative builds' changes and the pool, 389.55 s
> against 429.45 s for that build without it, four runs each, its peak
> to the tip about 256 MiB higher at the median. The background commit
> on the code as committed, `02b802c`, has not been run. See "`8fc9160`,
> a background commit and dcrd v2.1.7" below.

Raw: the comparison's `runs.jsonl` rows labelled `n-head-1`,
`n-L0-1`, `n-L1-A`, `n-L2-R3`, `n-L3-R4`, `n-L4-R5`, `n-L5-R6`,
`n-L6-B-1`, `n-L6-B-2`, `n-L0-2`, `n-head-2`, `n-pool-1`, `n-pool-2`,
`n-K-umax3M-1`, `n-K-umax3M-2`, `n-M1-tcache`, `n-bg-test-1`,
`n-bg-control-1`, `n-bg-bare`, `n-M2-memtable4M`,
`n-M2-memtable4M-umax3M`, `n-M5-overlay450-umax4.5M`,
`n-head-noindex`, `n-head-3`, `n-dcrd`, `n-bg-test-2` and
`n-bg-control-2`, with per-run samples, flush logs and node logs as
above; the queue's log; the scripts that reconciled the figures from
those records, with the tables they wrote; and the patches of the
measured trees and of the background-commit experiment.

## `8fc9160`, a background commit and dcrd v2.1.7 (2026-10-16)

"Seven cumulative builds, the validation pool, a background commit and
dcrd" above left the commits after `4700cf1` up to `f60ae3a` unrun as
committed, the cumulative builds' changes and the validation pool never
run together, the background commit measured only on `231997b`, and dcrd
at v2.1.6. On 2026-10-16, between 07:59 and 14:00, 20 syncs were run on
m3:

- six of `8fc9160`, the head of master when the syncs ran, which holds
  `4700cf1`, the seventeen commits to the node's code after it, one that
  adds tests, a patch release of `rustls` and a fix to two tests: five
  at the defaults, one of which was disturbed and repeated, and one with
  the exists-address index off;
- four of `4700cf1`;
- four of the pool build: `4700cf1` with the changes of sixteen of the
  seventeen as the last cumulative build (L6) above had them, and the
  validation pool, the seventeenth, as it was measured beside them. Its
  code does what `8fc9160` does but for comments, tests, a developer
  variable for the exists-address index's flush request that is left
  unset, and the patch release;
- four of the background-commit build: the pool build with the
  background commit as it was then, in the form of 2026-10-13 above with
  the snapshot, which `02b802c` carries after its port onto the commits
  that followed `8fc9160`;
- one of dcrd v2.1.7, built from its release tag as its release image
  builds it, and one of dcrd v2.1.6.

The syncs are in the harness of the sections above, from the same block
server, at the defaults but for what a row names, with the flush log on
in every dcroxide run. The node had the eight cores and their siblings
it had before, and the block server four others. Four rounds of the four
dcroxide builds, each round in another order (`8fc9160`, `4700cf1`,
pool, background; background, pool, `4700cf1`, `8fc9160`; `4700cf1`,
`8fc9160`, background, pool; pool, background, `8fc9160`, `4700cf1`),
with dcrd v2.1.7 after the first round, the index-off run after the
second and dcrd v2.1.6 after the third. Every run exited 0 on the
server's tip, and the block files hashed to `33b7ac837a45c74f` over 36
files and 19,202,596,910 B in all 20, dcrd's included. As above, that is
the equality of a 64-bit prefix of one hash, and the metadata store is
not compared.

| run | started | build | setting | wall | peak RSS | block server read from its drive |
|---|---|---|---|---:|---:|---:|
| o16-head-1 | 07:59 | `8fc9160` | defaults (disturbed, below) | 431.5 s | 3,264 MiB | 18,583 MB |
| o16-base-1 | 08:14 | `4700cf1` | defaults | 517.9 s | 2,865 MiB | 17,936 MB |
| o16-pool-1 | 08:29 | pool | defaults | 432.4 s | 3,272 MiB | 17,930 MB |
| o16-bg-1 | 08:43 | background commit | defaults | 388.3 s | 3,432 MiB | 17,930 MB |
| o16-dcrd-217 | 08:57 | dcrd v2.1.7 | defaults | 2,944.4 s | 1,848 MiB | 17,951 MB |
| o16-bg-2 | 09:53 | background commit | defaults | 391.7 s | 3,538 MiB | 11 MB |
| o16-pool-2 | 10:06 | pool | defaults | 428.9 s | 3,282 MiB | 0 MB |
| o16-base-2 | 10:20 | `4700cf1` | defaults | 516.2 s | 2,926 MiB | 0 MB |
| o16-head-2 | 10:36 | `8fc9160` | defaults | 421.2 s | 2,952 MiB | 0 MB |
| o16-head-noindex | 10:50 | `8fc9160` | `--noexistsaddrindex` | 351.3 s | 2,162 MiB | 0 MB |
| o16-base-3 | 11:02 | `4700cf1` | defaults | 516.2 s | 3,263 MiB | 0 MB |
| o16-head-3 | 11:18 | `8fc9160` | defaults | 429.3 s | 3,262 MiB | 0 MB |
| o16-bg-3 | 11:32 | background commit | defaults | 388.8 s | 3,617 MiB | 0 MB |
| o16-pool-3 | 11:45 | pool | defaults | 430.0 s | 3,016 MiB | 0 MB |
| o16-dcrd-216 | 12:00 | dcrd v2.1.6 | defaults | 2,944.5 s | 1,852 MiB | 12,001 MB |
| o16-pool-4 | 12:55 | pool | defaults | 427.5 s | 3,291 MiB | 0 MB |
| o16-bg-4 | 13:09 | background commit | defaults | 390.3 s | 3,529 MiB | 0 MB |
| o16-head-4 | 13:23 | `8fc9160` | defaults | 432.1 s | 3,339 MiB | 0 MB |
| o16-base-4 | 13:37 | `4700cf1` | defaults | 513.1 s | 3,233 MiB | 0 MB |
| o16-head-1-again2 | 13:52 | `8fc9160` | defaults | 434.0 s | 3,208 MiB | 0 MB |

Wall is the harness's clock, as above. Peak RSS is `VmHWM` read after
the clock stops and before the harness signals the node, so before the
closing flush. The figures below are the medians of the four clean runs
of each build.

**`8fc9160` against `4700cf1`: 430.7 s against 516.2 s, 85.5 s or 16.6%
less.** `4700cf1` took 513.1 to 517.9 s, and `8fc9160` 421.2 to 434.0 s.
The spread of `8fc9160`'s four, 12.8 s, follows its flush time run by
run, 118.5 s in the fastest and 128.8 s in the slowest; less the flush
time inside the clock its runs are about 306 to 309 s.

**`8fc9160` against dcrd v2.1.7: 6.84x in this session, 2,944.4 s
against 430.7 s.** Three caveats go with it. It rests on one dcrd run.
That run's block server read 18.0 GB of its data from the drive, where
none of the four clean runs of `8fc9160` read any. And the day's two
dcrd runs are the slowest clean dcrd runs on record, which suggests, and
does not prove, that the uncached server cost dcrd 1 to 3%. Against
dcrd's runs of earlier sessions, 2,883.9 s on 2026-10-11 and the
2,863.9 s median of 2026-10-09 and 2026-10-10, the ratio is 6.70x and
6.65x, across sessions.

> **Note (2026-10-17): the uncached server is not borne out as the
> cause.** The same v2.1.7 binary took 2,944.4 s and 2,926.4 s on
> 2026-10-17 with a block server that read nothing from its drive, and
> passed 299.9 GB and 302.3 GB to write calls, so the "about 7% more"
> below did not recur either. Why dcrd ran slower on 2026-10-16 and
> 2026-10-17 than on 2026-10-09 to 2026-10-11 is not known. See
> "`88c46c3`, the background commit as committed, dcrd v2.1.7 and two
> preloaded allocators" below.

**The index off: 351.3 s**, one run of `8fc9160` with
`--noexistsaddrindex`, peaking at 2,162 MiB.

**dcrd v2.1.7 and v2.1.6 took the same time**, 2,944.4 s and 2,944.5 s
in one run each, their progress within 0.3% of each other throughout.
v2.1.7 passed about 7% more bytes to write calls. Equality finer than
about 2% is not established by one run each.

**The pool build and `8fc9160` are the same within the noise**: 429.45 s
against 430.7 s, and 428.9 s against 430.7 s on the runs whose server
read nothing from its drive.

**The background commit: 389.55 s against 429.45 s, 39.9 s or 9.3%
less**, against its own build without it.

- It was faster in every pairing: its slowest run took 391.7 s and the
  pool build's fastest 427.5 s. On the runs whose server read no more
  than 11 MB from its drive it was 38.6 s or 9.0% less.
- It took about 75 s of flush work off the threads that sync. Their
  flushes took about 48 s (47.8 to 49.1 s) against 118 to 129 s without
  it. But the wall fell only 40 s: the rest of the sync ran about 35 s
  slower beside the commit, for a cause not measured.
- Process CPU time was 27 s higher, 2.6%, so the gain depends on spare
  cores.
- Peak resident memory to the tip was about 256 MiB higher: medians of
  3,533 against 3,277 MiB. Its true peak is in the shutdown flush, 3.84
  to 4.14 GiB by its flush log; the pool build's peak there is not
  recorded.

**The flushes.** A run's flushes took 118.5 to 128.8 s in all, the
medians by build 124.0 to 126.5 s. Without the background commit the
block thread carried 84.5 to 113.6 s of that and the index thread the
rest. The totals include the shutdown flush, 1.6 to 3.3 s, after the
tip.

**The disturbed run.** o16-head-1, 431.5 s, had 119.8 s of other
userland, 0.87% of the machine, where every other dcroxide run had 22 to
53 s; the record attributes almost none of it. It is left out of every
figure above, and was repeated as o16-head-1-again2. A system monitor
took about 10 to 16 s of each run's other userland.

**The block server's cache.** In the first round the server's data did
not stay cached: each run of that round read 17.9 to 18.6 GB from the
drive. The machine's samples show the kernel's background reclaim
evicting about 13 GiB of freshly warmed page cache within seconds while
39 to 49 GB was free and the free blocks of huge-page size had run out.
Transparent huge pages are `always` there and proactive compaction is
off, so reclaim for huge pages is the likely cause; it is not
demonstrated. From o16-bg-2 on every dcroxide run read 0 to 11 MB from
the server, for reasons not known, and the dcrd v2.1.6 run still read
12.0 GB. The session of 2026-10-13 was uncached throughout. The pool
build, `4700cf1` and the background-commit build each have one uncached
run, of the first round, which differs from their cached medians by
+3.5 s, +1.7 s and −2.0 s; `8fc9160` has no clean uncached run.

**What was not measured.**

- The tree that carries the background commit, `02b802c`, or any tree
  after `8fc9160`: the commits that port dcrd's changes since
  `6f6cf21b`, and the background commit as ported onto them, have not
  been run in a sync.
- The store's end state with the background commit against its control
  (the exists-address index's digest and the UTXO statistics at the
  tip).
- Slower storage: only m3's NVMe drive under btrfs was measured. The
  form of 2026-08-16 lost 9.5% on m1, where commits ran back to back
  (`DCROXIDE_DB_SYNC_COMMIT=1` is the way back).
- Windows and macOS.
- Two proposals of the background-commit work, neither built: a read
  snapshot for the flushes `Database::flush` and the close make, which
  still commit with no reader open, and a committer thread kept for the
  life of the process, should allocator arenas turn out to hold the
  extra memory. Its memory is not settled.

> **Note (2026-10-17): the tree was run.** `88c46c3`, which holds
> `02b802c` and the commits after `8fc9160`, took a median of 396.25 s
> over four default syncs, and 430.4 s and 428.0 s with
> `DCROXIDE_DB_SYNC_COMMIT=1`: the background commit as committed is
> 32.95 s or 7.7% less by the medians. Both arms ended with the same
> UTXO set by `gettxoutsetinfo` and the same block files, dcrd's too;
> the exists-address index's digest was still not compared. The flush
> after the tip is now the one the harness's `gettxoutsetinfo` call
> makes, and the close's takes 0.01 s, so the peak after the clock is no
> longer the shutdown flush's. See "`88c46c3`, the background commit
> as committed, dcrd v2.1.7 and two preloaded allocators" below.

> **Note (2026-10-18): with more of each flush on `dbcommit`, capping
> the arenas took nearly all the extra memory away.** In syncs from a
> block server on the LAN, a build that also makes a flush's row inserts
> and the exists-address index's contribution on `dbcommit` peaked at
> 6,835 and 7,200 MiB of resident memory, and one with a second change
> besides at 6,222 to 7,241 MiB, against 3,077 to 3,342 MiB without
> them; with `MALLOC_ARENA_MAX=2` one run of the second peaked at
> 3,423 MiB and took 41.9 s longer. So the extra is memory glibc's
> arenas hold, as inferred from the cap's effect: nothing records an
> arena's bytes in use. Both changes are held. The background commit's
> own extra memory above, about 256 MiB, was not taken apart, and a
> committer thread kept for the life of the process was not built. See
> "Rungs from a block server on the LAN, two changes held for their
> memory, and dcrd v2.1.7" below.

> **Note (2026-10-19): the committer thread was built, and the memory
> came down.** A build that adds to the one with the two held changes
> one `dbcommit` thread, started by the first flush handed over and kept
> until the store's close, peaked at 2,456 to 2,470 MiB of resident
> memory in four default syncs from the LAN server, against 6,730 to
> 6,933 MiB without it in three runs of the same session, and was no
> slower. Those four runs also peaked 489 to 508 MiB below the same
> build's two runs with `DCROXIDE_DB_SYNC_COMMIT=1`, where in this
> section's runs the background commit peaked about 256 MiB above its
> build without it; that is other code in another series. The build's
> code is that of the three commits that follow the commit that records
> those syncs. See "One commit thread for the life of the store, a sync
> that checks every script, and dcrd v2.1.7" below.

Raw: the comparison's `runs.jsonl` rows labelled `o16-head-1`,
`o16-base-1`, `o16-pool-1`, `o16-bg-1`, `o16-dcrd-217`, `o16-bg-2`,
`o16-pool-2`, `o16-base-2`, `o16-head-2`, `o16-head-noindex`,
`o16-base-3`, `o16-head-3`, `o16-bg-3`, `o16-pool-3`, `o16-dcrd-216`,
`o16-pool-4`, `o16-bg-4`, `o16-head-4`, `o16-base-4` and
`o16-head-1-again2`, with per-run samples, flush logs and node logs; the
queue's steps and log; the machine's memory samples of the first round;
and the patches of the two builds that are not the tree of a commit.

## `88c46c3`, the background commit as committed, dcrd v2.1.7 and two preloaded allocators (2026-10-17)

"`8fc9160`, a background commit and dcrd v2.1.7" above left the code
after `8fc9160` unrun, the background commit measured only on a build
that is not the code of a commit, the store's end state not compared
between its arms, dcrd v2.1.7 run once, against a block server that read
its data from the drive, and the index off run once. On 2026-10-17,
between 05:22 and 11:03, 20 syncs were run on m3, in two queues:

- two smoke syncs, of `88c46c3` and of dcrd v2.1.7, each stopped at the
  first height poll past block 60,000;
- six of `88c46c3`, the head of master when the syncs ran, at the
  defaults: four in the first queue and two in the second, as controls
  for the allocator runs below;
- two of `88c46c3` with `DCROXIDE_DB_SYNC_COMMIT=1`, which puts every
  metadata commit back on the committing thread;
- two of `88c46c3` with the exists-address index off;
- two of dcrd v2.1.7 at the defaults and one with the index off, the
  binary of o16-dcrd-217 above, which logs its version as
  `2.1.7+release.local (Go version go1.25.4 linux/amd64)`;
- one of a build of `88c46c3` with frame pointers, under two `perf`
  recorders: a profile, not a clean timing;
- two of `88c46c3`'s binary with the system's jemalloc 5.4.0 preloaded
  (`LD_PRELOAD`), and two with tcmalloc_minimal of gperftools 2.18.1:
  measurements for this file, of a configuration the daemon does not
  ship.

`88c46c3` holds `02b802c`, which commits the metadata on a thread of
its own, and after it only documents, so these are the first syncs of
the code as it stands, and the first of the commits after `8fc9160`
that port dcrd's changes since `6f6cf21b`.

The syncs are in the harness of the sections above, from the same dcrd
v2.1.6 block server, at the defaults but for what a row names, with the
flush log on in every dcroxide run. The node had the eight cores and
their siblings it had before, the block server four others, and the
profiled run's recorders four more. The server's data, 26.0 GB, was
read into the page cache before every run, in 29.1 s before the first
smoke sync and in 1.2 to 1.4 s after it, and the server read nothing
from its drive in any of the 18 full syncs. Every measured run followed
a `sync`, a 300 s idle and the quiet gate, except t17-head-5, the first
of the second queue, which started about two and a half minutes after
the profiled run's record was written, with no idle before it.
Transparent huge pages were `madvise` throughout. The setting is in no
run record: the system journal shows it written at 05:21, before the
first run and after a reboot at 00:39 had put it back to the kernel's
default, `always`; the value written is not logged, and the setting
read `madvise` after the queues. On 2026-10-16 it was `always` (above),
and the sessions before that did not record it.

Every full sync exited 0 on the server's tip, `8752fdc9…`, none stalled
and none was marked disturbed; other userland was 0.04% to 0.06% of the
machine. From this session the harness also calls `gettxoutsetinfo`
once the clock has stopped, before it signals the node. In all 18 full
syncs, dcrd's three and the profiled run's included, it reported the
same UTXO set at block 1,116,035: 760,741 transactions, 1,850,903
outputs, a total amount of 1,672,716,060,550,750 atoms and the
serialized hash `eb7f88de7b69f98676ce78072c0f90cc2667b875df0b26637dffcf9da5b3c30c`.
The block files hashed to `33b7ac837a45c74f` over 36 files and
19,202,596,910 B in all 18. The exists-address index and the rest of
the metadata store were not compared. The two smoke syncs also exited
0, at other heights and tips, `88c46c3` at block 65,035 after 15.1 s
and dcrd at block 61,278 after 48.1 s, with sets and block files of
their own and other userland at 0.24% and 0.27%.

Wall is the harness's clock, from starting the node to the first
once-a-second `getblockcount` poll that sees 1,116,035. The rate is
1,116,035 blocks over wall; the `blk_per_s` field of `runs.jsonl`,
computed from the unrounded clock, differs from it by up to 0.4 blk/s.
Node CPU time is the process's, user plus system, and leaves out the
kernel threads that encrypt and write its bytes back. "Written" is the
bytes the node passed to write calls, in MB of 10^6, not what reached
the drive. Peak RSS is `VmHWM` read when the clock stops, before the
`gettxoutsetinfo` call. The data directory is `du -sb` of the run's
directory after shutdown, logs included. The time to block 1,026,597,
the assume-valid block, is interpolated between the 10 s samples, the
last height taken at wall. The start times are taken from each run's
id; the `started` field is 8 to 9 s late in the records of all 18 full
syncs.

| run | started | build | setting | wall | rate | to block 1,026,597 | after it | node CPU time (user + sys) | written | peak RSS | data directory |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| t17-smoke-head | 05:22 | `88c46c3` | smoke, to block 65,035 | 15.1 s | | | | 20.3 s (18.0 + 2.3) | 1,053 MB | 1,494 MiB | 1.54 GB |
| t17-smoke-dcrd | 05:29 | dcrd v2.1.7 | smoke, to block 61,278 | 48.1 s | | | | 69.7 s (63.5 + 6.2) | 2,276 MB | 1,441 MiB | 0.89 GB |
| t17-head-1 | 05:36 | `88c46c3` | defaults | 397.8 s | 2,805.5 blk/s | 316.7 s | 81.1 s | 1,044.8 s (976.0 + 68.8) | 39,687 MB | 3,484 MiB | 30.00 GB |
| t17-sync-1 | 05:49 | `88c46c3` | `DCROXIDE_DB_SYNC_COMMIT=1` | 430.4 s | 2,593.0 blk/s | 344.3 s | 86.1 s | 1,014.3 s (951.8 + 62.5) | 39,610 MB | 3,291 MiB | 30.00 GB |
| t17-head-2 | 06:03 | `88c46c3` | defaults | 396.6 s | 2,814.0 blk/s | 314.0 s | 82.6 s | 1,047.1 s (976.9 + 70.2) | 39,808 MB | 3,509 MiB | 29.98 GB |
| t17-dcrd-1 | 06:17 | dcrd v2.1.7 | defaults | 2,944.4 s | 379.0 blk/s | 2,077.4 s | 867.0 s | 5,608.1 s (4,557.6 + 1,050.5) | 299,866 MB | 1,837 MiB | 25.94 GB |
| t17-head-3 | 07:13 | `88c46c3` | defaults | 395.9 s | 2,819.0 blk/s | 313.8 s | 82.1 s | 1,046.1 s (976.4 + 69.7) | 39,672 MB | 3,464 MiB | 30.01 GB |
| t17-sync-2 | 07:26 | `88c46c3` | `DCROXIDE_DB_SYNC_COMMIT=1` | 428.0 s | 2,607.6 blk/s | 343.6 s | 84.4 s | 1,012.9 s (950.8 + 62.1) | 39,758 MB | 3,242 MiB | 29.96 GB |
| t17-head-4 | 07:40 | `88c46c3` | defaults | 395.3 s | 2,823.3 blk/s | 315.3 s | 80.0 s | 1,048.3 s (977.2 + 71.1) | 39,785 MB | 3,710 MiB | 29.94 GB |
| t17-head-noindex-1 | 07:54 | `88c46c3` | `--noexistsaddrindex` | 343.9 s | 3,245.2 blk/s | 271.0 s | 72.9 s | 871.8 s (822.4 + 49.4) | 32,162 MB | 2,202 MiB | 27.79 GB |
| t17-dcrd-noindex | 08:06 | dcrd v2.1.7 | `--noexistsaddrindex` | 1,317.2 s | 847.3 blk/s | 680.8 s | 636.4 s | 2,757.7 s (2,533.2 + 224.5) | 129,941 MB | 1,838 MiB | 23.78 GB |
| t17-dcrd-2 | 08:35 | dcrd v2.1.7 | defaults | 2,926.4 s | 381.4 blk/s | 2,057.1 s | 869.3 s | 5,614.0 s (4,547.6 + 1,066.4) | 302,264 MB | 1,835 MiB | 25.96 GB |
| t17-head-noindex-2 | 09:30 | `88c46c3` | `--noexistsaddrindex` | 344.0 s | 3,244.3 blk/s | 272.2 s | 71.8 s | 870.4 s (822.4 + 48.0) | 32,128 MB | 2,203 MiB | 27.79 GB |
| t17-head-profile | 09:43 | `88c46c3` with frame pointers | defaults, under `perf` (not a clean timing) | 403.2 s | 2,767.9 blk/s | 321.5 s | 81.7 s | 1,069.4 s (990.9 + 78.5) | 39,604 MB | 3,213 MiB | 29.95 GB |
| t17-head-5 | 09:53 | `88c46c3` | defaults (control) | 391.1 s | 2,853.6 blk/s | 311.8 s | 79.3 s | 1,043.4 s (973.6 + 69.8) | 39,386 MB | 3,537 MiB | 29.95 GB |
| t17-jemalloc-1 | 10:06 | `88c46c3` | jemalloc preloaded | 339.4 s | 3,288.3 blk/s | 267.0 s | 72.4 s | 968.6 s (902.3 + 66.3) | 39,514 MB | 2,884 MiB | 29.95 GB |
| t17-tcmalloc-1 | 10:18 | `88c46c3` | tcmalloc_minimal preloaded | 334.5 s | 3,336.4 blk/s | 262.5 s | 72.0 s | 966.6 s (904.0 + 62.6) | 39,637 MB | 2,541 MiB | 29.98 GB |
| t17-head-6 | 10:31 | `88c46c3` | defaults (control) | 395.8 s | 2,819.7 blk/s | 314.9 s | 80.9 s | 1,042.0 s (973.4 + 68.6) | 39,823 MB | 3,679 MiB | 30.01 GB |
| t17-jemalloc-2 | 10:44 | `88c46c3` | jemalloc preloaded | 341.4 s | 3,269.0 blk/s | 267.7 s | 73.7 s | 968.2 s (902.8 + 65.4) | 39,737 MB | 2,931 MiB | 30.03 GB |
| t17-tcmalloc-2 | 10:57 | `88c46c3` | tcmalloc_minimal preloaded | 334.3 s | 3,338.4 blk/s | 263.0 s | 71.3 s | 965.4 s (904.1 + 61.3) | 39,588 MB | 2,533 MiB | 29.98 GB |

The figures below are the medians of t17-head-1 to t17-head-4 unless a
run is named, and two-run figures are given as both values.

**`88c46c3` at the defaults: 396.25 s, 6.6 minutes**, over 395.3 to
397.8 s, a spread of 2.5 s or 0.6%; 2,816.5 blk/s at 2.63 to 2.65 mean
cores. Node CPU time 1,046.6 s (976.65 + 69.95), written 39,736 MB, peak
RSS 3,496.5 MiB (3,464 to 3,710), data directory 29.99 GB. The two
controls of the second queue took 391.1 s and 395.8 s, so the six
default runs span 391.1 to 397.8 s with a median of 395.85 s. t17-head-5
is the fastest, 4.2 s under the fastest of the four; it is also the one
run that followed no idle.

**Against dcrd v2.1.7: 7.43x and 7.39x in one session**, 2,944.4 s and
2,926.4 s against 396.25 s; 7.41x against their median of 2,935.4 s,
and 7.36x to 7.45x over the eight pairings. dcrd used 5.36x the node CPU
time (5,608.1 s and 5,614.0 s), passed 7.55x and 7.61x the bytes to
write calls and peaked at 1,837 and 1,835 MiB, so dcroxide's peak to the
tip is 1.90x and 1.91x dcrd's; dcrd logs a soft memory limit of
1.80 GiB.

- **The uncached server of 2026-10-16 is not what slowed dcrd.**
  t17-dcrd-1 took 2,944.4 s, the time of o16-dcrd-217, the same binary,
  whose block server read 18.0 GB from its drive; this session's read
  none. The suggestion above that the uncached server cost dcrd 1 to 3%
  is not borne out.
- **dcrd was slower on 2026-10-16 and 2026-10-17 than before.** The
  two runs here and the two of 2026-10-16 (v2.1.7 and v2.1.6) took
  2,926.4 to 2,944.5 s, where v2.1.6, in quiet runs, took a median of
  2,863.9 s on 2026-10-09 and 2026-10-10, from a dcroxide block server,
  2,872.8 s (q3) from the dcrd server in the same session, 2,883.9 s on
  2026-10-11 and 2,920.3 s on 2026-10-13, both from the dcrd server;
  c2 of 2026-10-10, from the dcrd server on a machine that was not
  quiet, took 2,947.3 s. Neither the version, the server's cache nor
  the kind of block server separates the slow runs from the others,
  and the huge-page setting of the sessions before 2026-10-16 was not
  recorded, so the cause is not known. Against the figures of
  2026-10-09 to 2026-10-11 dcroxide's median is 7.23x and 7.28x, and
  against that of 2026-10-13 7.37x, across sessions.
- **v2.1.7's bytes.** It passed 299.9 GB and 302.3 GB to write calls,
  against 318.8 GB in o16-dcrd-217 and 298.5 GB for v2.1.6 in
  o16-dcrd-216: the "about 7% more" of 2026-10-16 did not recur.

**The index off: 343.9 s and 344.0 s against dcrd's 1,317.2 s, 3.83x**,
on one dcrd run. dcroxide used 871.8 s and 870.4 s of CPU time (dcrd
3.16x and 3.17x that), passed 32,162 and 32,128 MB to write calls (dcrd
4.04x), and peaked at 2,202 and 2,203 MiB against 1,838 MiB. The index
costs dcroxide 52.3 s, 13.2% of its default sync, and dcrd 1,627.2 s and
1,609.2 s, 55.3% and 55.0% of each run against the one index-off run. Of
the gap between the two at the defaults, 2,548.15 s and 2,530.15 s, the
difference in what the index costs is 61.8% and 61.5%. With it off
dcroxide reached the assume-valid block in 271.6 s and dcrd in 680.8 s,
2.51x, and ran the blocks after it in 72.3 s against 636.4 s, 8.8x. This
dcrd run is 5.6% slower than v2.1.6's 1,247.8 s of 2026-10-10, which
synced from a dcroxide block server that read 19.1 GB from its drive,
and passed 129.9 GB to write calls against 102.8 GB; against that run
dcroxide's index-off median is 3.63x, across sessions.

**Time to each height**, interpolated between the samples:

| block | `88c46c3`, median of four | each run | dcrd v2.1.7 | `88c46c3`, index off | dcrd, index off | `88c46c3`, `DCROXIDE_DB_SYNC_COMMIT=1` |
|---:|---:|---|---|---:|---:|---|
| 250,000 | 50.8 s | 50.8, 50.7, 49.8, 50.8 s | 211.1 s, 212.7 s | 48.1 s | 132.0 s | 54.0 s, 54.1 s |
| 500,000 | 105.1 s | 106.1, 104.7, 103.7, 105.6 s | 507.7 s, 512.1 s | 96.5 s | 263.9 s | 112.9 s, 113.3 s |
| 750,000 | 195.5 s | 196.4, 195.8, 194.3, 195.1 s | 1,101.4 s, 1,111.5 s | 171.3 s | 450.0 s | 212.5 s, 211.5 s |
| 1,000,000 | 301.0 s | 303.8, 300.6, 299.2, 301.3 s | 1,966.6 s, 1,946.6 s | 260.3 s | 655.6 s | 329.8 s, 328.6 s |
| 1,026,597 | 314.6 s | 316.7, 314.0, 313.8, 315.3 s | 2,077.4 s, 2,057.1 s | 271.6 s | 680.8 s | 344.3 s, 343.6 s |
| 1,116,035 | 396.25 s | 397.8, 396.6, 395.9, 395.3 s | 2,944.4 s, 2,926.4 s | 343.95 s | 1,317.2 s | 430.4 s, 428.0 s |

The index-off columns of `88c46c3` are the medians of two runs.
dcrd's time against dcroxide's grows from 4.16x and 4.19x at block
250,000 to 6.60x and 6.54x at the assume-valid block. To that block
dcroxide averaged 3,263 blk/s and dcrd 494.2 and 499.0. The 89,438
blocks after it took dcroxide 81.6 s, 1,096 blk/s (1,082.7 to
1,117.9 blk/s by run), and dcrd 867.0 s and 869.3 s, 103.2 and
102.9 blk/s: 10.62x and 10.65x. The samples' times are whole seconds
and the height is polled once a second, so each interpolated time is
good to a second or two.

**The background commit as committed: 396.25 s against 429.2 s, 32.95 s
or 7.7% less** than the median of the two runs with
`DCROXIDE_DB_SYNC_COMMIT=1` (430.4 s and 428.0 s), and 34.15 s and
31.75 s less than each; measured against the default, the variable's
runs are 8.3% slower. Every default run was faster than both: the
slowest took 397.8 s.

- **CPU and memory.** The default used 32.3 s and 33.7 s more process
  CPU time, 3.2% and 3.3%, and peaked 205.5 and 254.5 MiB higher to the
  tip (3,291 and 3,242 MiB with the variable). By the flush logs, whose
  marks take in the `gettxoutsetinfo` call after the clock, the two arms
  peak alike: 3,764 to 4,052 MiB at the default against 3,890 and
  3,739 MiB.
- **The flushes.** At the default the threads that sync were held in
  flushes, foreground work and waits for a commit still running, for
  46.9 to 48.6 s, a median of 47.1 s or 11.9% of the wall; with the
  variable for 103.6 s and 100.8 s, 24.1% and 23.5%, of which the block
  thread had 80.5 s and 89.4 s and the index thread 23.1 s and 11.3 s.
  So 55.1 s left those threads while the wall fell 32.95 s: wall less
  that time is a median of 348.5 s at the default against 327.0 s, and
  the rest of the sync ran about 21.5 s slower beside the commit, for a
  cause not measured.
- **The end state.** Both arms ended with the UTXO set and block files
  above, dcrd's. The exists-address index's digest and the rest of the
  metadata store were not compared.
- **Against 2026-10-16.** That session's 39.9 s, 9.3%, was of a build
  that is not the code of a commit, with transparent huge pages
  `always` and a server that read from its drive in the first round,
  against a control of its own; the difference between the two figures
  is not to be read as an effect of the code.

**The flushes at the defaults.** Counting the flushes that ended at or
before the node logged the tip, the four runs made 54, 55, 54 and 54: 51
or 52 with the commit in the background and three foreground ones on the
block thread, 4.4 to 5.5 s together. Some flush was under way for 109.2
to 111.8 s, a median of 110.2 s or 27.8% of the wall; the flushes never
overlapped, so that is also their sum. Their commit phases took 65.7 to
67.8 s, 62.2 to 64.7 s of it in the background. With the index off: 39
flushes, 61.4 s and 60.9 s (17.8% and 17.7%), holding the threads that
sync for 29.2 s and 29.0 s (8.5% and 8.4%). After the clock every flush
log has two more: the one the `gettxoutsetinfo` call makes, explicit and
in the foreground, 1.7 to 2.7 s, starting 0.1 to 1.0 s after the tip,
and the close's, 0.01 s. That call took 2.8 to 4.0 s for dcroxide and
1.3 to 1.4 s for dcrd, and shutdown 0.1 to 0.2 s for both.

**Memory after the clock.** The note of 2026-10-16 above that the true
peak is in the shutdown flush does not carry over: the close's flush now
takes 0.01 s, and the flush after the tip is the harness's. By the
flush logs' high-water marks, which take in that call, the defaults
peaked at 3,892, 3,869, 3,764 and 4,052 MiB, the controls at 4,181 and
3,963 MiB and the index-off runs at 2,636 and 2,670 MiB. The flush that
call makes reached 3,710 to 3,999 MiB at the defaults by its own
records, so the last 15 to 54 MiB came after it, in the rest of the call
or in shutdown before the close. That is not part of a sync. dcrd's
peak after the clock is not recorded.

**The read-ahead.** In the four default runs the block thread waited
0.84 to 0.86 s in all for the reader, and the reader 275.4 to 278.0 s
for the block thread. `DCROXIDE_READ_AHEAD=off` was not run.

**Two allocators, preloaded.** In the second queue, two rounds of a
default control, then jemalloc, then tcmalloc_minimal, each preloaded
from the distribution's package at its default options; the order was
the same in both rounds. No build of the repository links either, and
nothing here is a figure for the daemon as it ships.

| | runs | wall | to block 1,026,597 | after it | node CPU time | peak RSS | after the clock |
|---|---|---|---|---|---|---|---|
| control | t17-head-5, t17-head-6 | 391.1 s, 395.8 s | 311.8 s, 314.9 s | 79.3 s, 80.9 s | 1,043.4 s, 1,042.0 s | 3,537, 3,679 MiB | 4,181, 3,963 MiB |
| jemalloc | t17-jemalloc-1, -2 | 339.4 s, 341.4 s | 267.0 s, 267.7 s | 72.4 s, 73.7 s | 968.6 s, 968.2 s | 2,884, 2,931 MiB | 2,910, 2,950 MiB |
| tcmalloc_minimal | t17-tcmalloc-1, -2 | 334.5 s, 334.3 s | 262.5 s, 263.0 s | 72.0 s, 71.3 s | 966.6 s, 965.4 s | 2,541, 2,533 MiB | 2,631, 2,624 MiB |

- **13.2% to 15.5% less wall than the control of the same round**:
  jemalloc 51.7 s and 54.4 s, tcmalloc_minimal 56.6 s and 61.5 s.
  Against the controls' median of 393.45 s, jemalloc's median is
  53.05 s or 13.5% less and tcmalloc_minimal's 59.05 s or 15.0% less.
  Every preload run was faster than every control: the slowest took
  341.4 s, the fastest control 391.1 s.
- **Most of it falls before the assume-valid block**, 44.8 to 51.9 s
  of it against the control of the round, and 6.9 to 9.6 s after it.
  The flushes held the threads that sync for 43.7 to 44.3 s against
  46.1 s and 47.0 s, so little of it is in the flushes.
- **CPU and memory.** 73.8 to 76.8 s less process CPU time than the
  control of the round, at 2.84 to 2.89 mean cores against 2.63 and
  2.67; 653 and 748 MiB less peak RSS to the tip for jemalloc and 996
  and 1,146 MiB less for tcmalloc_minimal, and 1,013 to 1,550 MiB less
  after the clock.
- **The end state** was the same as every other run's.
- **Not tried**: an allocator linked into the binary, mimalloc, glibc's
  own tunables, the order of the arms alternated, and the huge-page
  setting at `always`.

**The profiled run.** t17-head-profile ran a build of `88c46c3` with
frame pointers, not the binary of the runs above, under two `perf`
recorders on four cores of their own: a flat one at 499 Hz, 523,025
samples, and a call-graph one at 199 Hz unwinding by frame pointer,
209,884 samples, both of user space only. It took 403.2 s, 6.95 s or
1.8% over the default median, which is not a timing of either build.
What the profile shows is not set out here.

**What was not measured.**

- The exists-address index's digest and the rest of the metadata store,
  in any run.
- A second dcrd run with the index off.
- `DCROXIDE_READ_AHEAD=off`, so the read-ahead's gain as committed; any
  link with a round trip, so the download window in a whole sync.
- The flush log's own cost: it was on in every dcroxide run.
- Storage other than m3's NVMe drive under btrfs; Windows and macOS.
- dcrd's peak memory after the clock, and the kernel threads' CPU time
  for either daemon.
- The huge-page setting in any run record.
- dcrd's time taken apart.

> **Note (2026-10-18): whole syncs over a link with a short round
> trip.** `88c46c3` and builds on it were synced through the default
> download window, with the read-ahead on, from a dcrd v2.1.7 node on
> another machine on the same LAN, about 0.3 ms away; a link with a
> longer round trip, and `DCROXIDE_READ_AHEAD=off`, were still not run.
> See "Rungs from a block server on the LAN, two changes held for their
> memory, and dcrd v2.1.7" below.

Raw: the comparison's `runs.jsonl` rows labelled `t17-head-1`,
`t17-sync-1`, `t17-head-2`, `t17-dcrd-1`, `t17-head-3`, `t17-sync-2`,
`t17-head-4`, `t17-head-noindex-1`, `t17-dcrd-noindex`, `t17-dcrd-2`,
`t17-head-noindex-2`, `t17-head-5`, `t17-jemalloc-1`, `t17-tcmalloc-1`,
`t17-head-6`, `t17-jemalloc-2` and `t17-tcmalloc-2`; the smoke rows
`t17-smoke-head` and `t17-smoke-dcrd`, and the profiled run's
`t17-head-profile`, each in a results file of its own; per-run samples,
flush logs and node logs; the profiled run's two recordings; the
queues' steps and log; and the working summary written at the end of
the first queue.

## README Performance text retired on 2026-10-17

Until 2026-10-17 the README's Performance section held the text below,
as it stood at `88c46c3`. That day the section was rewritten around the
syncs of "`88c46c3`, the background commit as committed, dcrd v2.1.7
and two preloaded allocators" above, and the text it carried before is
kept here so that nothing in it is lost. It is verbatim but for its
link targets, rewritten to resolve from this directory. "This page",
"this section", "above" and "below" in it are the README and the
section itself, and its present tense is that of `88c46c3` before the
syncs of 2026-10-17: the code after `8fc9160` has since been run in
syncs, and the section above supersedes its headline figures.

The latest comparison, with four runs of dcroxide, a run with the
exists-address index off and dcrd in the same session, is of dcroxide
`8fc9160` on 2026-10-16: a median of 7.2 minutes against dcrd v2.1.7's
49.1, 6.84x in one session, with the caveats set out with it. It comes
first, and with it the background commit, measured that day on a build
that is not the code of a commit. The commits after `8fc9160`, which
port dcrd's changes since `6f6cf21b` and carry the background commit
(`02b802c`), have not been run in a sync. The steps of 2026-10-12 and
the complete comparison of `b4a5d2d` on 2026-10-11 follow as they were
set out then: eleven commits that change the node's code followed
`b4a5d2d`, their steps were measured on 2026-10-12 in one or two syncs
each, dcrd was not run that day, and the last step was measured in a
build that is not the code as committed. A session of the same kind was
run on 2026-10-13 with `4700cf1`, beside builds that held the changes of
the seventeen commits after it in parts; the [bench
ledger](bench-ledger.md) has it, and this page sets out no figure
from it. From *The last complete comparison* on, every table, and every
measurement of dcroxide not dated 2026-10-12 or 2026-10-16, is of
`b4a5d2d` or of the code before it. Every sync time on this page is from
one machine, over loopback, into a fresh data directory.

**`8fc9160` against dcrd v2.1.7, on 2026-10-16.** `8fc9160`, the head of
master when the syncs ran, holds `4700cf1`, the seventeen commits to the
node's code after it, one that adds tests, a patch release of `rustls`
and a fix to two tests. Four clean syncs of mainnet from genesis to
block 1,116,035, from the dcrd block server and in the harness of the
comparisons below, interleaved with runs of `4700cf1` and of two builds
described below, took 421.2 s, 429.3 s, 432.1 s and 434.0 s: a median of
**430.7 s, 7.2 minutes**. A fifth, disturbed by other work on the
machine, was repeated. `4700cf1` took a median of 516.2 s in the same
session, so the commits after it took 85.5 s, 16.6%, off it. dcrd v2.1.7
took 2,944.4 s, 49.1 minutes, in one run, so dcroxide was **6.84x as
fast in one session**. Three things temper that figure. It rests on one
dcrd run. That run's block server read 18.0 GB of its data from the
drive, where none of the four runs of `8fc9160` read any. And the day's
two dcrd runs (v2.1.6 took 2,944.5 s) are the slowest clean dcrd runs on
record, which suggests, and does not prove, that the uncached server
cost dcrd 1 to 3%. Against dcrd's runs of earlier sessions, 2,883.9 s
and 2,863.9 s, the ratio is 6.70x and 6.65x. With `--noexistsaddrindex`,
`8fc9160` took 351.3 s in one run.

**The background commit, kept.** Since `02b802c` the daemon makes the
storage engine's commit of most metadata flushes on a thread of its own
([PARITY.md](PARITY.md), *Where a cache flush's commit runs*). It was
measured on 2026-10-16 as part of a build that is not the code of any
commit: `4700cf1` with the changes of the seventeen commits, the
validation pool among them, as they were measured on 2026-10-13, whose
code does what `8fc9160` does but for comments, a developer variable
left unset and the `rustls` patch release, and which took 429.45 s
without the background commit, the same as `8fc9160` within the noise.
With it, in four runs interleaved with four without, a sync took 388.3
to 391.7 s, a median of **389.55 s: 39.9 s or 9.3% less**, and less in
every pairing (38.6 s or 9.0% on the runs whose block server read no
more than 11 MB from its drive). About 75 s of flush work left the
threads that sync, whose flushes took about 48 s against 118 to 129 s,
but the wall fell 40 s: the rest of the sync ran about 35 s slower
beside the commit, for a cause not measured. It costs 27 s more process
CPU time, 2.6%, so the gain depends on spare cores, and about 256 MiB
more peak resident memory up to the tip (medians 3,533 against
3,277 MiB); its true peak is in the shutdown flush, 3.84 to 4.14 GiB by
its flush log, and the control's there is not recorded. Only m3's
storage was measured. The form of 2026-08-16 lost 9.5% on m1, where
commits ran back to back, and `DCROXIDE_DB_SYNC_COMMIT=1` puts every
commit back on the committing thread
([docs/operating.md](operating.md)). The commit as ported has not
been run in a sync, and the store's end state was not compared between
the two arms.

**Eleven commits to the node's code since `b4a5d2d`, measured a step at
a time on 2026-10-12.** Each run was a sync of mainnet from genesis to
block 1,116,035 from a dcrd v2.1.6 server, at the defaults but for the
one setting named below, on a quiet machine, with the machine, the
harness and the pinning of the comparison further down. Each ended on
the server's tip, and the harness marked none as disturbed. One run of
the code of each commit that was run:

| dcroxide | what it adds to the row above | wall time, one run | node CPU time |
|---|---|---:|---:|
| `b4a5d2d` | (the code of the complete comparison) | 12.1 min (728.5 s) | 1,458 s |
| `a83f9a1` | four small changes | 11.2 min (673.8 s) | 1,401 s |
| `6271436` | three on the exists-address index and the ticket database | 10.5 min (628.0 s) | 1,394 s |
| `3a367e5` | the `SigHashAll` prefix hash taken from the block's transaction hashes | 10.1 min (607.7 s) | 1,152 s |
| `540b203` | the block download window | 10.2 min (612.4 s) | 1,160 s |

The first three steps are 54.7 s (7.5%), 45.8 s (6.8%) and 20.3 s
(3.2%) less than the run before them. The window's run is 4.7 s (0.8%)
more than the one before it, and one run each does not settle whether
the window costs anything over loopback; what it is for is a link with
a round trip, under *What these figures do not say*. Every step is one
run against one run. For scale, the three runs of `b4a5d2d` on
2026-10-11 spanned 3.5 s.

The last two commits were measured in one binary, run four times in
the order off, on, off, on, with other runs between the two pairs.
With `DCROXIDE_READ_AHEAD=off`, which leaves the block hand-off of
`5cf9e04` and reads every connection as dcrd does, a sync took 597.6 s
and 599.0 s. With the read-ahead of `b4ceb1c` on, which is the default,
it took 494.6 s and 490.8 s, 8.2 minutes: 103.0 s and 108.2 s less,
17.2% and 18.1%. **That binary is the build made before the review of
the read-ahead and its fixes. Those four runs are of no commit.**
`b4ceb1c` as committed was run in syncs on 2026-10-13, inside `4700cf1`
and only with the read-ahead on (the [bench
ledger](bench-ledger.md) has those runs), so its gain as committed
has not been measured. The hand-off was not measured alone: the 14.8 s
and 13.4 s between the window's run and the two with the read-ahead off
are not attributed.

What the eleven are, in the order they were made:

- **Four small changes, measured together: 673.8 s against 728.5 s.**
  - `7f99184` — the best state holds its missed tickets as a handle on
    the tip stake node's treap, where every connect walked that whole
    treap to fill a list that only the mining template reads.
  - `a65d647` — the keys of the UTXO view and of the UTXO cache are
    compared inline, where each key a search visited cost a call to the
    C library's `memcmp`, and a view is committed to the cache in one
    pass.
  - `7c6ec9a` — a block record is written with one positioned write,
    where it took a seek and four writes; dcrd makes the four
    (`database/ffldb/blockio.go:466-489`). The node made 5.86 million
    write calls in the sync with it and 9.15 million in the one before.
  - `a83f9a1` — the waits for the database's writer are timed and
    reported in the flush log. It is a measurement and changes no
    behaviour: in that sync the threads other than the index thread
    waited 74.9 s for the writer.
- **Three on the exists-address index and the ticket database, measured
  together: 628.0 s against 673.8 s**, with those threads' wait for the
  writer at 30.7 s.
  - `1d5d8a9` — the index computes a connected block's keys before it
    takes the database's writer (the address extraction, the partition
    hashes, a first filter against its memtable, the sort), where it
    computed them inside its write transaction, as dcrd does
    (`internal/blockchain/indexers/existsaddrindex.go:383-444`).
  - `4535d1e` — the index's 21-byte keys are compared inline, as the
    UTXO maps' keys are.
  - `6271436` — a best-node write of the ticket database looks each
    ticket bucket up once, where it looked one up for every ticket, as
    dcrd does (`blockchain/stake/internal/ticketdb/chainio.go:609`,
    `:625`).
- **`3a367e5`, a step past dcrd: 607.7 s against 628.0 s.** While a
  block is connected, a `SigHashAll` signature hash takes its prefix
  hash from the block's transaction hashes, which are already computed,
  where dcrd serializes and hashes the transaction's prefix again for
  every signature. dcrd carries the shortcut in its source and ships it
  switched off, with a warning that it has not been vetted
  (`txscript/opcode.go:27-32`); [PARITY.md](PARITY.md) records it under
  the accepted departures, with its tests. The 89,438 blocks validated
  in full took 121.6 s against 140.3 s, and the node's user CPU time
  was 1,058.0 s against 1,298.6 s.
- **`540b203`, the block download window: 612.4 s against 607.7 s over
  loopback.** During the initial sync the node keeps up to 128 blocks
  requested from its sync peer, within a byte budget, where dcrd keeps
  16 ([PARITY.md](PARITY.md), *Block download window*). Its
  measurements over a delayed link are below.
- **`5cf9e04`, not measured alone.** A block a peer delivers is handed
  to the chain as the allocation its message was decoded into, where
  the chain copied it once as it accepted it; dcrd copies nothing there
  (`internal/blockchain/process.go:571`).
- **`b4ceb1c`, the read-ahead: 494.6 s and 490.8 s against 597.6 s and
  599.0 s, in the build before its review's fixes.** During the initial
  sync a thread of its own reads the sync peer's connection up to four
  messages ahead of the thread that connects blocks, checks each
  checksum, decodes and, for a block, hashes its transactions. dcrd has
  no such thread and holds further reads back on purpose
  (`server.go:1365-1369`). Two of the eighteen later commits to the
  node's code give that thread more to do for each block: since
  `a589c4a` it lays the block out as its block-file record from the
  bytes it arrived in, and since `44cf801` it builds the block's two
  merkle trees. [PARITY.md](PARITY.md), *Reading ahead of the block
  handler*, has the rule and what a peer can see of it, and
  [SECURITY.md](../SECURITY.md) what it gives a hostile sync peer.

**dcrd was not run on 2026-10-12, so there is no ratio for the code run
that day from one session.** dcrd's last run before it, on the evening
of 2026-10-11 on the same machine and in the same harness, took
2,883.9 s. Set against it across sessions, the 612.4 s of `540b203`,
the last commit whose code was run that day, is 4.71x, and the two runs
with the read-ahead on are 5.83x and 5.88x, of a build that is not the
committed code. Neither is a figure of the kind the 3.96x below is.
dcrd was run once more on 2026-10-13, in the session of `4700cf1`
above, and that run is in the ledger.

Not measured on 2026-10-12, for any of the eleven: a sync with the
exists-address index off, so what the index cost that code, and how
much of the lead it was, was not known that day (`4700cf1` was run once
with the index off on 2026-10-13, and dcrd was not); a second run of
any step but the last; the four changes of the first batch and the
three of the second one at a time; any other machine or filesystem;
and a whole sync over a delayed or a real link, where the round trip
and not the thread that connects blocks may set the pace. The tables of
the index's cost and of the time to each height below are of `b4a5d2d`
and were not redone. The
[bench ledger](bench-ledger.md) has every run of the day, with
what else was measured then and is not in the repository.

**The last complete comparison set out here is of `b4a5d2d`, on
2026-10-11**, until that of `8fc9160`
above. It synced mainnet from genesis to block 1,116,035 in a
median of 12.1 minutes over three runs that day. dcrd release v2.1.6
(go1.25.4) took 48.1 minutes in one run that evening, so
dcroxide was **3.96x as fast** in one session. dcrd's median over four
runs on 2026-10-09 and 2026-10-10, on the same machine and in the same
harness, is 47.7 minutes, and the tables below use it: against it the
figure is 3.93x, across sessions. When the two were first measured
together, at dcroxide `c128a93`, it was 17.6 minutes against 47.7,
**2.71x**. Much of the lead is the exists-address index,
which both daemons build by default: with it off dcroxide took 10.2
minutes in one run on 2026-10-11 and dcrd 20.8 on 2026-10-10, 2.04x
across sessions. In the tables below the syncing daemon took its
blocks from a server run by the other daemon; dcrd's one run of the
evening of 2026-10-11 took them from a dcrd server.

| syncer | source | runs | wall time, median (range) | mean rate | node CPU time | written by the node |
|---|---|---|---|---|---|---|
| dcroxide `b4a5d2d` | dcrd | three, 2026-10-11 | **12.1 min** (728.7 s; 725.9–729.4 s) | 1,532 blk/s | 1,462 s | 39.7 GB |
| dcroxide `c128a93` | dcrd | four, 2026-10-09 and 2026-10-10 | 17.6 min (1,058.6 s; 1,055.8–1,065.0 s) | 1,054 blk/s | 1,821 s | 51.4 GB |
| dcrd v2.1.6 | dcroxide | four, 2026-10-09 and 2026-10-10 | **47.7 min** (2,863.9 s; 2,848.8–2,894.8 s) | 390 blk/s | 5,567 s | 286.3 GB |

Each figure is the median of its runs. The rate is 1,116,035 blocks over
the wall time. CPU time is the node process's own, user plus system.
"Written" is the bytes the process passed to write calls, in GB of 10^9
bytes, not what reached the drive. So at `b4a5d2d` dcroxide took about
a quarter of dcrd's node CPU time and passed about a seventh of its
bytes to write calls. The three runs of `b4a5d2d` span 0.5% of their
median, and every sync timed on this page ended on the server's tip.
Interop holds in both directions: dcrd accepts
`/dcrwire:1.0.0/dcroxide:2.2.0(pre)/` and dcroxide accepts
`/dcrwire:1.0.0/dcrd:2.1.6/`.

**Six changes since `c128a93` account for the difference.** Five are on
the block-processing path: a wider table for the block-file checksum,
the BLAKE-256 rounds written out, the tickets each block purchased kept
in memory for the block that matures them, a block's transaction hashes
computed once as it is processed where four steps each computed them,
and the indexes on a thread of their own. On the morning of 2026-10-11
the code before them took 1,058.3 s in one run, where the median above
is 1,058.6 s, and one sync as each was added took 1,015.3 s, 912.8 s,
893.7 s, 820.3 s and, with all five, 759.1 s and 756.2 s. The sixth
changes when the node commits: during the initial sync a UTXO cache
flush that the cache's size limit trips no longer forces the metadata
store to disk, so several share one commit. That afternoon the code
before it took 775.6 s in one run, and the figures above are the code
with it. It trades a longer replay after a crash during the initial
sync, and more memory, for the time;
[docs/operating.md](operating.md) has the trade and the [bench
ledger](bench-ledger.md) every step.

**The commit dcroxide then tracked syncs like the release.** dcrd
master `6f6cf21b` (2.2.0-pre), then the parity target, built under
go1.26.2 with the flags of its release image, took 2,909.8 s and
2,869.8 s from a dcroxide server in two runs on 2026-10-10. One is
inside the release's range above and the other 0.5% over its slowest
run.

**Much of the lead is the exists-address index.** One run of each daemon
with `--noexistsaddrindex`, dcroxide's on 2026-10-11 and dcrd's on
2026-10-10, set against the medians above:

| | index on | index off | the index costs |
|---|---:|---:|---:|
| dcroxide `b4a5d2d` | 12.1 min (728.7 s) | 10.2 min (610.2 s) | 16% of its sync |
| dcrd v2.1.6 | 47.7 min (2,863.9 s) | 20.8 min (1,247.8 s) | 56% of its sync |
| dcrd / dcroxide | 3.93x | 2.04x | |

Of the 36 minutes between the two at their defaults, 70% is the
difference in what the index costs each. With it off dcroxide reached
the assume-valid block in 7.9 minutes, where dcrd took 10.3, and ran the
fully validated blocks after it in 2.3 minutes against 10.5. At
`c128a93` dcrd was the first to that block, 10.3 minutes against 11.8.

**The syncer decides the time, not the source.** At `c128a93` each
daemon was also run from a server of its own kind, back to back with a
cross-source run: dcroxide took 1,072.2 s from a dcroxide server against
1,061.1 s from dcrd's, and dcrd 2,872.8 s from a dcrd server against
2,894.8 s from dcroxide's. That is one run of each, and the source moved
either by about 1% or less, the size of the run-to-run spread. An
earlier pair of same-source runs, taken with more activity on the
machine, is in the ledger with the rest. Every sync of dcroxide on
2026-10-11 and 2026-10-12, and every run through the relay, took its
blocks from the dcrd server.

Both daemons ran at their defaults, apart from the flags that point them
at the block server and open RPC for the height poll, and
`--noexistsaddrindex` in the index-off pair. So the exists-address index
is on in every other run, and both carry the same assume-valid block,
1,026,597: up to it they skip connect validation, script checks
included, and they validate the 89,438 blocks after it in full. The
syncing node was pinned to eight cores (16 threads) of a 16-core desktop
with one NVMe drive, m3 in the [bench ledger](bench-ledger.md), and
the serving node to four others, with its data read into the page cache
before each run. The clock runs from the syncing process's start to the
first once-a-second `getblockcount` poll that reports the target height.
In three of dcrd's runs of 2026-10-10, the two of `6f6cf21b` and the one
with the index off, the page cache did not keep the dcroxide server's
block files and it read them from the drive as it served them. Whether
that cost dcrd anything was not measured.

The lead grows along the chain, and most where full validation begins.
Time to reach each height, the median of each daemon's runs above,
interpolated between samples taken every 10 s:

| block | dcroxide `b4a5d2d` | dcrd v2.1.6 |
|---:|---:|---:|
| 250,000 | 1.5 min | 3.4 min |
| 500,000 | 3.2 min | 8.0 min |
| 750,000 | 6.0 min | 17.6 min |
| 1,000,000 | 9.2 min | 31.7 min |
| 1,026,597 (assume-valid) | 9.6 min | 33.4 min |
| 1,116,035 | 12.1 min | 47.7 min |

Up to the assume-valid block dcroxide led 3.5x with the index on. Over
the 89,438 blocks after it dcroxide ran at about 586 blk/s against
dcrd's 104, 5.6x. dcroxide's metadata flushes took 15% of its wall time,
and its peak resident memory was 3.16 GiB against dcrd's 1.81 GiB.
Those are of `b4a5d2d`. In the nine syncs of 2026-10-12 described at
the top of this section the flushes took 104.3–111.4 s whichever code
ran, so their share grew as the rest shrank: 21.3% of each of the two
runs with the read-ahead on.

What these figures do not say:

- **Where the rest of the difference comes from.** dcrd was not
  profiled, and dcroxide only on 2026-10-11, in one sync of the code
  before the six changes above (user-space time only). What dcrd's time
  goes on has not been taken apart.
- **It is loopback, and what a delayed link costs depends on the
  download window.** dcrd requests blocks through a window of 16 in
  flight, refilled once fewer than 10 remain. So did dcroxide through
  the runs of 2026-10-11, and so it does when started with
  `DCROXIDE_BLOCK_WINDOW=dcrd`. Through a relay that delays every
  chunk, at a 50 ms round trip dcroxide synced the early chain at
  260 blk/s and dcrd at 252, about 13 blocks per round trip each, where
  over loopback they pass those blocks at about 3,200 and 1,500 blk/s.
  Those are fixed-time runs of 2026-10-11 with dcroxide `7d31abb`, on a
  machine that was not quiet. At 13 blocks per round trip this chain
  would take about 72 minutes at 50 ms for a daemon that processes
  faster than that throughout, as dcroxide does over loopback; dcrd runs
  the blocks after the assume-valid block at about 104 blk/s, so by the
  same arithmetic it would take at least about 80. Both are worked out
  for dcrd's window and were not run.
  By default dcroxide now uses a window of its own, measured only in
  short runs. It keeps up to 128 blocks requested from its sync peer,
  and beyond the first 16 no more than 3,145,728 bytes of them by the
  sizes in their headers, and it halves both limits, down to dcrd's 16
  blocks, each time a sync peer leaves with more than 16 requested
  ([PARITY.md](PARITY.md), *Block download window*). On 2026-10-12, on
  m3, one binary was run through the same relay for 300 s per arm,
  header sync included, on a quiet machine with the node on four cores,
  once with `DCROXIDE_BLOCK_WINDOW=dcrd` and once at the default: at a
  50 ms round trip it reached block 68,031 under dcrd's rule and block
  532,079 under the default, and at 150 ms blocks 18,445 and 158,440.
  No arm logged a narrowed or widened window or a stalled peer. The
  relay delays and does not limit bandwidth. The same day five
  outbound-only starts of 300 s were made against the public main
  network, on a machine that was not quiet and with the peers and links
  the network offered: under dcrd's rule the node reached block 24,455
  180.7 s after its first block arrived and block 41,191 after 220.3 s,
  and under the default block 188,469 after 215.7 s and block 93,095
  after 161.8 s. A third start under the default fetched no block, its
  header sync being about 68% done when the 300 s ended. None logged a
  narrowing, a stalled peer or a ban. Over loopback, on a quiet
  machine, one sync to block 1,116,035 took 612.4 s with the window and
  607.7 s with the code before it (`3a367e5`), one run each that day:
  0.8% more, and one run each does not settle whether the window costs
  anything over loopback. Both are in the table of 2026-10-12 at the
  top of this section. Not measured: a whole sync over a delayed or a
  real link, and the two cases in which the wider window can cost sync
  peers. No sync was run over a link held to a set rate or with a
  reader made to stop for 20 s or more: the public-network starts ran
  over whatever links their peers had, at rates that were not recorded,
  and the longest flush of the loopback sync took 3.5 s. A real link
  adds loss and a bandwidth limit that the relay does not;
  [docs/operating.md](operating.md) has the budget and the setting
  that puts dcrd's window back.
- **The read-ahead's gain was measured over loopback only, and not as
  committed.** dcrd reads one message from a connection, handles it
  and only then reads the next (`inHandler`,
  `peer/peer.go:1535-1598`). During the initial sync dcroxide now
  reads its sync peer's connection up to four messages ahead of the
  thread that connects blocks, on a thread of its own, and reads as
  dcrd does when started with `DCROXIDE_READ_AHEAD=off`
  ([PARITY.md](PARITY.md), *Reading ahead of the block handler*). The
  494.6 s and 490.8 s at the top of this section, against 597.6 s and
  599.0 s with it off, are of 2026-10-12 on m3, on a quiet machine
  with the node on eight cores, and of the build made before the
  review of the read-ahead and its fixes. The node's own line at
  shutdown put the checksum and decode work that left the block thread
  at 45.8 s and 45.9 s and the hashing at 47.2 s in both runs, 93 s of
  the 103.0 s and 108.2 s gained; the socket reads moved too and are
  not timed, and what the rest is was not established. The reader
  thread was parked on a full queue for 382.4 s and 378.7 s of those
  runs, and the block thread waited on an empty one for 0.27 s: over
  loopback the next block was nearly always there, which a link with a
  round trip need not give. Peak resident memory was 2,967 and
  2,921 MiB with it on against 3,273 and 3,256 MiB with it off, which
  is not explained. Not measured: the gain of the code as committed,
  which was run on 2026-10-13 only inside `4700cf1` and only with the
  read-ahead on, nor of the reader's added work since (`a589c4a`,
  `44cf801`), which has been run only in builds that are not the code
  as it stands; a sync with it over a delayed or a real link, where the
  round trip and not the thread that connects blocks may set the pace
  and reading ahead may gain nothing; a node on fewer than eight cores;
  and its gain with `--noexistsaddrindex`, under which it was run once,
  in `4700cf1` on 2026-10-13. It costs one more thread and one more
  descriptor on that connection and the memory of up to four decoded
  messages held there, each with the frame it was read in, which was
  not measured. By estimates from the sizes of the structures, since
  `a589c4a` those are about 220 kB for four main network blocks of mean
  size, and at worst, from a hostile sync peer, the connection holds
  about 62 MB, with about 1.3 MB more for a moment while one frame is
  compared with its block's serialization, or up to about 1.4 MB while
  one block's merkle trees are built, against about 12.5 MB without the
  read-ahead ([SECURITY.md](../SECURITY.md), *Known gaps*).
  [docs/operating.md](operating.md) has the setting and how to
  read the shutdown line.
- **It is one machine with fast storage.** On m2 in the ledger, a
  container on a ZFS
  mirror of QLC drives with the node on four cores, dcroxide with the
  same storage layout ran the 200,000 blocks after 916,000 at a median
  of 482 blk/s, where m3 ran them at about 593, both before the changes
  of 2026-10-11. No sync from genesis has been measured on m2 with that
  layout, and the eleven commits of 2026-10-12 have been run on m3
  only. One run that day, of `b4a5d2d`, was on a data directory
  without copy-on-write: 714.1 s, against 728.5 s on the directory as
  created. None of the eleven was run that way.

At block 1,116,035 the data directory is 27.90 GiB under dcroxide and
24.16 GiB under dcrd, 1.15x. Block files make up 17.88 GiB of each. The
rest is metadata: one 10.01 GiB `metadata.redb`, against about 6.28 GiB left
for dcrd's two leveldb stores. The exists-address index is about 2.0 GiB
of either: with it off the directories were 25.88 and 22.19 GiB. Neither
side compresses. A 2026-08-11
measurement found the two implementations storing the same payload for
the same chain, so the difference then was redb's page layout and not
extra data. The exists-address index has since moved to a layout of its
own ([ADR-0011](adr/0011-exists-address-layout-3-and-the-flush-participant.md)),
and that payload comparison has not been repeated.
[PARITY.md](PARITY.md) records the divergence from dcrd's two-database
layout.

Earlier measurements are kept in the
[bench ledger](bench-ledger.md), which records every figure per
machine, commit and corpus, with the storage analysis behind them in
[ADR-0004](adr/0004-storage-backend.md) and
[ADR-0009](adr/0009-storage-shape.md). The 2026-07 and 2026-08
figures there were taken against dcrd 2.2.0-pre on m1, before the
height-first block keys
([ADR-0010](adr/0010-height-first-block-keys.md)) and the
exists-address layout, so they are not earlier points on the same curve
as the headline figures above. The 2026-10 rows on m2 measure those two
changes, on slower storage and four cores.

## Rungs from a block server on the LAN, two changes held for their memory, and dcrd v2.1.7 (2026-10-17 and 2026-10-18)

"`88c46c3`, the background commit as committed, dcrd v2.1.7 and two
preloaded allocators" above ran `88c46c3`. Ten changes to the node's
code were then made on `fdd7a83`, whose code is `88c46c3`'s, one after
another as states of a worktree, with nothing committed, and a release
binary was built at each rung of that stack so that a sync could price
each change against the build below it. By the evening of 2026-10-17 the
loopback block server's data no longer stayed in the page cache: in both
runs of the sampler below the server read 19.2 GB from its drive after
the queue's warm-up, where in the runs of that morning it had read none.
So the rungs were run from a block server on another machine. Between
20:51 on 2026-10-17 and 18:51 on 2026-10-18, 47 syncs were run on m3, 44
of them set out here, in four queues and two runs outside any queue:

- two of `88c46c3` from the loopback dcrd v2.1.6 block server, at the
  defaults and with `DCROXIDE_DB_SYNC_COMMIT=1`, under a sampler of
  where the block and index threads wait, on the evening of 2026-10-17
  ("Where the block thread waits beside a background commit", below);
- 21 from the LAN server between 02:53 and 07:12 on 2026-10-18
  (labelled l17-*): three of `88c46c3` as controls, two of each of
  eight builds, A1 to G, that add the ten changes a rung at a time, and
  two of a prototype of one of the changes, with it on and off;
- one of G from the loopback server at 07:15, for its end state
  (v18-G-loopback);
- 18 between 14:15 and 18:39: two of J from the loopback server for its
  end state, at the defaults and with `DCROXIDE_DB_SYNC_COMMIT=1`
  (v18-J-*); then from the LAN server three of G', which is G without
  one of its ten changes, and two each of H, I and J, each of which adds
  a change to the build below it (s18-*); then dcrd v2.1.7 at the
  defaults and with the exists-address index off, one run each, J once
  more at the defaults, and J with the index off and with
  `DCROXIDE_DB_SYNC_COMMIT=1`, two runs each (f18-*);
- two of J with an allocator setting each, at 18:40 and 18:46, outside
  any queue (diag-*).

The evening's queue also ran a replay benchmark of the signature
pre-verification, a smoke sync and one sync of the prototype from the
loopback server, whose pair was stopped unfinished; a smoke sync from
the LAN server, to block 63,504, ran outside any queue before the l17
queue. None of these, three syncs and a replay, is set out here.

**The builds.** Every dcroxide build but the prototype is a release
build, at the workspace's release profile with nothing else set, of
the stack's state at its rung. A1 to E were built on 2026-10-17 one
after another, F and G after them, and G', H, I and J on 2026-10-18 in
a second stack, G' by taking F's change back out of G, checked to
leave G's code less exactly that change. In the first stack the same
build at `fdd7a83` reproduced the control's code and data byte for
byte, every loaded section equal, with only the build id and the debug
information, which names the checkout's path, differing; in the second
a build at G reproduced G's code and data the same way. So a build and
the build it is set against differ by the changes between them alone.

| build | adds to the build above it | runs |
|---|---|---|
| `88c46c3` | the control: the binary of the section above | 3 |
| A1 | the overlay's newest layer folded into the one below once no reader holds that one | 2 |
| A2 | overlay keys compared through their first sixteen bytes, held inline | 2 |
| B | GCS filter bits written a word at a time, and a block's signature operations counted on the thread that read it | 2 |
| C | the ticket treaps of a dropped stake node handed to its child | 2 |
| D | a Bloom filter in front of each exists-address memtable partition | 2 |
| E | short UTXO scripts held in place rather than on the heap, and a block's input fetch queue sized once | 2 |
| F | a connected block's ticket rows deleted without being read first: measured, and not kept | 2 |
| G | the signatures of blocks read ahead pre-verified on the script pool | 2, and v18-G-loopback |
| G' | G without F's change | 3 |
| H | a block's data sanity checks made on the thread that read it | 2 |
| I | a flush's row inserts and the exists-address index's contribution made on `dbcommit`: held | 2 |
| J | a durable commit that carries a UTXO cache flush counted toward the periodic flush's 120 s, and that flush's commit handed over: held | 3, and the runs below |
| prototype | `88c46c3`'s code with G's pre-verification, which `DCROXIDE_PREVERIFY=off` turns off, and counters of what it did | 2 |

None of the builds is the tree of a commit: the changes were states of
a worktree when they ran. F's change was measured here and not kept.
The changes of builds I and J are held, after the memory finding
below.

> **Note (2026-10-19): kept, with a third change.** A build of J's code
> with the `dbcommit` thread kept for the life of the store, K, peaked
> at 2,456 to 2,470 MiB in four default syncs from the same LAN server
> and was no slower than J in the same session. The two held changes and
> that one are the three commits that follow the commit that records
> those syncs, the kept thread first. See "One commit thread for the
> life of the store, a sync that checks every script, and dcrd v2.1.7"
> below.

**The LAN server.** The block server was a live mainnet node on
another machine on the same LAN, dcrd v2.1.7 by its user agent
(`/dcrwire:1.0.0/dcrd:2.1.7/`), about 0.3 ms away (0.1 to 0.65 ms; no
run record holds the round trip). It was a node in service, following
the network: the starting height it gave each run went from 1,124,621
to 1,124,661 over the morning's runs and from 1,124,766 to 1,124,830
over the afternoon's. Its load, its cache, its configuration and its
link's speed are in no record, and nothing on m3 started, warmed or
stopped it; its processor time and reads, which the harness counts for
a loopback server, are not counted. The node under test had the eight
cores and their siblings it had before; the four that held the
loopback server ran no server in the LAN runs.

**The harness, for a server on another machine.** `sync_run.py` and
`queue.py` gained a source on another machine for these runs. The
clock is the harness's, as above, from starting the node to the first
once-a-second `getblockcount` poll that sees 1,116,035 or more. A live
server's chain does not end there, so the node goes on: at that poll it
was 13 to 1,864 blocks past the block, up to about 1.3 s of blocks at
the rate after the assume-valid block, where from a loopback server the
poll comes up to a second after the node reaches the server's tip. The
harness then asks the node for its block at 1,116,035 and checks it
against the frozen chain's, `8752fdc9…`, the block every loopback run
ended on, and halts the queue on a mismatch; every LAN run had that
block. That says the node followed the frozen chain to that height,
and nothing of what it stored. Because the node is still connecting
blocks after the clock, the harness does not record, for these runs,
the UTXO set, the block files' hash, the shutdown or the data
directory's size: they would describe wherever the node had got to.
CPU time, the per-thread counters and peak RSS (`VmHWM`) are read when
the clock stops, as before, while the node is still syncing. The
node's line at shutdown runs on to the shutdown, so the figures taken
from it below count 1,116,181 to 1,118,066 blocks, not 1,116,035; those
taken from the flush log are of the flushes that ended inside the
clock. The harness also records the bytes received on the interface
the server is reached through, every 10 s, and the peer's user agent
and starting height.

Every LAN run exited 0, none stalled, and none was marked disturbed.
Other userland was 0.04% to 0.06% of the machine in the morning, 0.25%
in its first run, and 0.14% to 0.15% in the afternoon. Every run of a
queue but its first followed a `sync`, a 300 s idle and the quiet gate;
the first of each queue (s17-m1-head, l17-pv-on-1, v18-G-loopback and
v18-J-loopback) followed the gate alone, and the two runs outside any
queue none of them. Transparent huge pages were `madvise` throughout:
the system journal shows no write to the setting after the one of
2026-10-17 at 05:21 and no restart, and it read `madvise` after the
last run. The flush log was on in every dcroxide run.

The time to block 1,026,597, the assume-valid block, is interpolated
between the 10 s samples, the last height taken at wall, and is good to
a second or two; "after it" is wall less that time. The rate is
1,116,035 blocks over wall. Node CPU time is the process's, user plus
system. The block, index and reader threads' figures are each thread's
time on a processor by the scheduler's count (`peer-outbound`, `index`
and `peer-reader`). The start times are taken from each run's id.

**This is a series of its own.** Neither the server, nor the link, nor
the node's receive path is that of the loopback rows above, and no
figure here is to be set beside a loopback figure without that label.
`88c46c3` took 407.0 to 407.9 s here, against 391.1 to 397.8 s in its
six default runs from the loopback server on 2026-10-17, and dcrd
v2.1.7 2,991.4 s, against 2,926.4 s and 2,944.4 s; why both were slower
from the LAN server is not taken apart. The morning's runs and the
afternoon's are two sessions as well: their controls spread 0.9 s and
6.3 s.

**The morning: ten changes, a rung at a time (l17).** The runs went
in the order of the table: the prototype's pair, then a control, A1 to
G, a second control, G back to A1, and a third control. So each
build's two runs bracket the middle control, and a drift linear in
time loads alike on every build's mean.

| run | started | build | setting | wall | rate | to block 1,026,597 | after it | node CPU time (user + sys) | block thread | index thread | reader thread | peak RSS | received, highest 10 s |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| l17-pv-on-1 | 02:53 | prototype | defaults | 397.3 s | 2,809.0 blk/s | 326.2 s | 71.1 s | 1,010.5 s (936.0 + 74.5) | 322.1 s | 128.1 s | 118.5 s | 3,437 MiB | 66.7 MB/s |
| l17-pv-off-1 | 03:06 | prototype | `DCROXIDE_PREVERIFY=off` | 404.7 s | 2,757.7 blk/s | 322.5 s | 82.2 s | 1,055.5 s (982.5 + 73.0) | 339.8 s | 125.2 s | 116.8 s | 3,489 MiB | 66.0 MB/s |
| l17-H-1 | 03:19 | `88c46c3` | defaults | 407.9 s | 2,736.1 blk/s | 324.6 s | 83.3 s | 1,050.0 s (976.9 + 73.1) | 340.4 s | 124.0 s | 116.6 s | 3,452 MiB | 65.6 MB/s |
| l17-A1-1 | 03:33 | A1 | defaults | 390.7 s | 2,856.5 blk/s | 308.9 s | 81.8 s | 1,039.3 s (965.5 + 73.8) | 322.1 s | 126.9 s | 117.2 s | 3,422 MiB | 70.5 MB/s |
| l17-A2-1 | 03:46 | A2 | defaults | 386.1 s | 2,890.5 blk/s | 304.7 s | 81.4 s | 1,030.0 s (956.6 + 73.4) | 312.3 s | 130.2 s | 116.5 s | 3,592 MiB | 70.6 MB/s |
| l17-B-1 | 03:59 | B | defaults | 379.1 s | 2,943.9 blk/s | 297.0 s | 82.1 s | 1,022.2 s (948.4 + 73.8) | 304.1 s | 128.0 s | 121.0 s | 3,594 MiB | 76.0 MB/s |
| l17-C-1 | 04:12 | C | defaults | 359.8 s | 3,101.8 blk/s | 282.2 s | 77.6 s | 1,011.0 s (938.0 + 73.0) | 285.7 s | 133.1 s | 121.3 s | 3,484 MiB | 78.7 MB/s |
| l17-D-1 | 04:24 | D | defaults | 353.9 s | 3,153.5 blk/s | 278.6 s | 75.3 s | 958.8 s (884.3 + 74.5) | 293.9 s | 71.5 s | 121.2 s | 3,365 MiB | 75.7 MB/s |
| l17-E-1 | 04:36 | E | defaults | 332.8 s | 3,353.5 blk/s | 257.9 s | 74.9 s | 934.7 s (861.3 + 73.4) | 271.1 s | 72.4 s | 121.7 s | 3,325 MiB | 85.6 MB/s |
| l17-F-1 | 04:48 | F | defaults | 329.5 s | 3,387.1 blk/s | 255.4 s | 74.1 s | 935.2 s (862.1 + 73.1) | 268.1 s | 72.4 s | 121.0 s | 3,239 MiB | 86.7 MB/s |
| l17-G-1 | 05:00 | G | defaults | 319.7 s | 3,490.9 blk/s | 256.3 s | 63.4 s | 890.3 s (817.9 + 72.4) | 253.3 s | 73.0 s | 122.3 s | 3,170 MiB | 83.7 MB/s |
| l17-H-2 | 05:12 | `88c46c3` | defaults | 407.8 s | 2,736.7 blk/s | 325.2 s | 82.6 s | 1,055.7 s (981.5 + 74.2) | 340.5 s | 126.8 s | 116.0 s | 3,546 MiB | 66.0 MB/s |
| l17-G-2 | 05:26 | G | defaults | 323.2 s | 3,453.1 blk/s | 258.2 s | 65.0 s | 894.8 s (822.0 + 72.8) | 254.9 s | 72.8 s | 122.7 s | 3,156 MiB | 82.2 MB/s |
| l17-F-2 | 05:38 | F | defaults | 329.3 s | 3,389.1 blk/s | 258.0 s | 71.3 s | 931.2 s (858.3 + 72.9) | 268.0 s | 71.3 s | 120.9 s | 3,230 MiB | 85.6 MB/s |
| l17-E-2 | 05:50 | E | defaults | 336.3 s | 3,318.6 blk/s | 260.6 s | 75.7 s | 933.9 s (859.5 + 74.4) | 270.9 s | 71.4 s | 120.4 s | 3,211 MiB | 86.8 MB/s |
| l17-D-2 | 06:02 | D | defaults | 352.6 s | 3,165.2 blk/s | 274.6 s | 78.0 s | 953.2 s (880.8 + 72.4) | 292.7 s | 72.4 s | 120.6 s | 3,166 MiB | 81.8 MB/s |
| l17-C-2 | 06:14 | C | defaults | 362.1 s | 3,082.1 blk/s | 282.6 s | 79.5 s | 1,008.5 s (935.2 + 73.3) | 285.9 s | 132.5 s | 120.6 s | 3,573 MiB | 78.0 MB/s |
| l17-B-2 | 06:27 | B | defaults | 375.6 s | 2,971.3 blk/s | 295.5 s | 80.1 s | 1,022.6 s (949.0 + 73.6) | 305.8 s | 126.7 s | 119.9 s | 3,693 MiB | 75.1 MB/s |
| l17-A2-2 | 06:39 | A2 | defaults | 385.1 s | 2,898.0 blk/s | 303.0 s | 82.1 s | 1,028.6 s (953.1 + 75.5) | 315.3 s | 125.4 s | 116.6 s | 3,397 MiB | 72.1 MB/s |
| l17-A1-2 | 06:52 | A1 | defaults | 389.1 s | 2,868.2 blk/s | 308.6 s | 80.5 s | 1,032.0 s (957.7 + 74.3) | 321.1 s | 126.0 s | 116.8 s | 3,657 MiB | 75.9 MB/s |
| l17-H-3 | 07:05 | `88c46c3` | defaults | 407.0 s | 2,742.1 blk/s | 323.9 s | 83.1 s | 1,047.4 s (975.5 + 71.9) | 339.0 s | 122.2 s | 116.1 s | 3,414 MiB | 66.1 MB/s |

The records label the controls l17-H-*: they are runs of `88c46c3`,
not of the build H of the afternoon.

What each rung gained, by the means of its runs against those of the
build below it:

| step | adds | wall | of `88c46c3`'s mean | before block 1,026,597 | after it | block thread | index thread | reader thread | node CPU time |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `88c46c3` to A1 | the overlay fold | −17.67 s | 4.3% | −15.82 s | −1.85 s | −18.4 s | +2.1 s | +0.8 s | −15.4 s |
| A1 to A2 | the inline key heads | −4.30 s | 1.1% | −4.90 s | +0.60 s | −7.8 s | +1.4 s | −0.4 s | −6.4 s |
| A2 to B | the GCS writer and the reader's signature-operation counts | −8.25 s | 2.0% | −7.60 s | −0.65 s | −8.9 s | −0.5 s | +3.9 s | −6.9 s |
| B to C | the treaps handed to the child | −16.40 s | 4.0% | −13.85 s | −2.55 s | −19.2 s | +5.5 s | +0.5 s | −12.7 s |
| C to D | the Bloom filter | −7.70 s | 1.9% | −5.80 s | −1.90 s | +7.5 s | −60.9 s | −0.1 s | −53.8 s |
| D to E | the inline scripts and the fetch queue | −18.70 s | 4.6% | −17.35 s | −1.35 s | −22.3 s | 0.0 s | +0.2 s | −21.7 s |
| E to F | the ticket rows deleted unread, not kept | −5.15 s | 1.3% | −2.55 s | −2.60 s | −2.9 s | 0.0 s | −0.1 s | −1.1 s |
| F to G | the signature pre-verification | −7.95 s | 2.0% | +0.55 s | −8.50 s | −13.9 s | +1.1 s | +1.5 s | −40.7 s |
| `88c46c3` to G | all ten | −86.12 s | 21.1% | −67.32 s | −18.80 s | −85.9 s | −51.4 s | +6.3 s | −158.5 s |

The means are 407.57 s for `88c46c3`, then 389.90, 385.60, 377.35,
360.95, 353.25, 334.55, 329.40 and 321.45 s for A1 to G.

**`88c46c3` against G: 407.57 s against 321.45 s, 86.12 s or 21.1%
less**, over three controls of 407.0 to 407.9 s and two runs of G,
319.7 s and 323.2 s, with 158.5 s less node CPU time, 1,051.0 s against
892.6 s. Both runs of every build were faster than both of the build
below it.

**How sure a step is.** Pooling the spread of the controls and of each
build's pair, on the assumption that they share one variance (10
degrees of freedom, a standard deviation of 1.55 s): at 95% a step
between two pairs is good to about ±3.5 s, and one from the three
controls to ±3.2 s. Every step is beyond that, the smallest, A2's
4.30 s, included. Each step is its change's effect on top of the
changes below it, in this order, and not its effect alone.

What the records show beyond the times, rung by rung:

- **A1, the overlay fold.** The flush log's count of overlay layers at
  each capture averaged 3.76 to 3.91 in the controls, up to 7, and
  1.00 in both runs of A1, and at each retirement 6.40 to 6.93, up to
  13, against 1.94; from A2 on the two averaged 1.00 to 1.04 and 1.94
  to 2.00. Each run of A1 made 53 flushes inside the clock against 54
  and 55 in the controls, and its median flush carried about 584,000
  and 591,000 entries against 607,000 to 630,000. The block thread's
  time fell 18.4 s, and 15.82 s of the wall's 17.67 s came before the
  assume-valid block.
- **A2, the inline key heads.** The block thread's time fell 7.8 s.
  Peak RSS was 3,592 and 3,397 MiB against A1's 3,422 and 3,657 MiB:
  what the overlay's entries now hold more does not show at the peak,
  which A1's two runs alone put 235 MiB apart.
- **B, the GCS writer and the reader's signature-operation counts,**
  which were not run apart. The block thread's time fell 8.9 s and the
  reader thread's rose 3.9 s. The hashing figure of the node's line at
  shutdown, which times the reader's making of each hashed block and
  from B on includes the two counts, rose from 52.52 to 52.94 s in the
  runs of `88c46c3`, A1 and A2 to 56.70 and 57.00 s.
- **C, the treaps handed to the child.** The block thread's time fell
  19.2 s, and 13.85 s of the wall's 16.40 s came before the
  assume-valid block. The index thread's time rose 5.5 s.
- **D, the Bloom filter.** The index thread's time fell from 133.1 and
  132.5 s to 71.5 and 72.4 s, 60.9 s or 46%, and the node's CPU time
  53.8 s. The time the index's queue was full, by the node's line at
  shutdown, was 3.45 and 3.48 s against 3.69 and 3.80 s in C's runs;
  in every run of the morning it was 3.20 to 3.80 s, the controls'
  3.20 to 3.30 s among them. The block thread's time rose 7.5 s, which
  the records do not explain.
- **E, the inline scripts and the fetch queue,** which were not run
  apart. The block thread's time fell 22.3 s, and 17.35 s of the
  wall's 18.70 s came before the assume-valid block. Peak RSS was 3,325
  and 3,211 MiB against D's 3,365 and 3,166 MiB.
- **F, the ticket rows deleted unread.** 5.15 s, 2.55 s and 2.60 s of
  it either side of the assume-valid block, and 2.9 s of the block
  thread's time. The change was not kept.
- **G, the pre-verification.** All of it after the assume-valid block,
  8.50 s, with 0.55 s more before it, where no script is checked. The
  block thread's time fell 13.9 s, that of the script pool's 15
  threads 29.0 s (418.7 to 389.7 s in all), and the node's CPU time
  40.7 s.
- **The read-ahead.** The block thread waited for the reader 0.82 to
  0.88 s in all in the controls and 2.64 and 2.65 s in G's runs, and
  the reader for the block thread 283.9 to 286.3 s and 190.0 and
  193.0 s. The highest 10 s receive rate rose with the builds' speed,
  from 65.6 to 66.1 MB/s in the controls to 82.2 to 86.8 MB/s for E to
  G.
- **Memory.** Peak RSS was 3,414 to 3,546 MiB in the controls and
  3,170 and 3,156 MiB for G, about 300 MiB less by the means; a
  build's two runs differed by up to 235 MiB, so no one step's memory
  is resolved.

**The prototype pair.** One build of `88c46c3`'s code with the
pre-verification and counters of what it did, run first at the
defaults, with it on, and then with `DCROXIDE_PREVERIFY=off`: 397.3 s
against 404.7 s, 7.4 s less, beside G's step of 7.95 s. After the
assume-valid block it took 71.1 s against 82.2 s, 11.1 s less; before
it 326.2 s against 322.5 s, 3.7 s more, where the pre-verifier does
nothing, which shows how far one pair can stray. The block thread's
time fell 17.7 s, the script pool's threads' 34.2 s and the node's CPU
time 45.0 s. With it off, the build ran within 3.2 s of the controls by
wall and 0.8 s by the block thread's time. In the run with it on, the
node's line at shutdown, which counts to the shutdown, reported 90,379
blocks with 9,250,453 inputs to guess for, on at most 6 helpers;
5,615,646 inputs checked ahead of the block thread and 5,615,550 of
them verified; and 19,972 blocks cut short by the block thread or the
shutdown. The connect checks' lookups of the signature cache hit
5,601,349 times and missed 3,662,510, 60.5% hits. In each run 11 of the
inputs the connect checks ran spent a pay-to-pubkey-hash output with
the guessed shape, two pushes, a signature and then a public key, and
were signed with another hash type than SigHashAll. The prototype's
code is not G's.

**The end state (v18).** Three syncs from the loopback dcrd v2.1.6
server, to compare the end state, which the LAN runs do not record: G
at 07:15 (v18-G-loopback), and J at the defaults and with
`DCROXIDE_DB_SYNC_COMMIT=1` at 14:15 and 14:28 (v18-J-loopback and
v18-J-sync-loopback). Each ended on the server's tip, `8752fdc9…`, and
in each `gettxoutsetinfo` reported the UTXO set of every full sync of
2026-10-17: 760,741 transactions, 1,850,903 outputs, a total amount of
1,672,716,060,550,750 atoms and the serialized hash
`eb7f88de7b69f98676ce78072c0f90cc2667b875df0b26637dffcf9da5b3c30c`.
The block files hashed to `33b7ac837a45c74f` over 36 files and
19,202,596,910 B in all three. The exists-address index and the rest
of the metadata store were not compared. G holds all of H's changes
but the data sanity checks, and F's besides; J holds all of H's and
the two held ones; neither G' nor H was checked this way. The server
read 17.8 to 19.2 GB from its drive in each despite the warm-up, so
their walls, 350.0 s, 309.0 s and 393.8 s, are not timings. Peak RSS
was 3,268, 6,931 and 2,886 MiB.

**The afternoon: G', H and the two held changes (s18), J against dcrd
(f18), and two diagnostics.** The rungs went G', H, I, J, G', J, I, H,
G', so each build's two runs bracket the middle run of G'. A third run
of J, f18-J-3, came later, among the runs set against dcrd.

| run | started | build | setting | wall | rate | to block 1,026,597 | after it | node CPU time (user + sys) | block thread | index thread | reader thread | peak RSS | received, highest 10 s |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| s18-G-1 | 14:41 | G' | defaults | 320.8 s | 3,478.9 blk/s | 255.4 s | 65.4 s | 895.1 s (822.3 + 72.8) | 255.1 s | 72.8 s | 122.4 s | 3,342 MiB | 88.0 MB/s |
| s18-H-1 | 14:53 | H | defaults | 318.0 s | 3,509.5 blk/s | 250.6 s | 67.4 s | 901.8 s (829.5 + 72.3) | 248.7 s | 75.5 s | 128.1 s | 3,338 MiB | 86.9 MB/s |
| s18-I-1 | 15:05 | I | defaults | 274.7 s | 4,062.7 blk/s | 210.5 s | 64.2 s | 900.4 s (825.3 + 75.1) | 211.6 s | 71.0 s | 128.2 s | 7,200 MiB | 102.9 MB/s |
| s18-J-1 | 15:16 | J | defaults | 264.4 s | 4,221.0 blk/s | 204.8 s | 59.6 s | 907.2 s (831.4 + 75.8) | 211.8 s | 70.9 s | 128.3 s | 7,241 MiB | 101.4 MB/s |
| s18-G-2 | 15:27 | G' | defaults | 314.6 s | 3,547.5 blk/s | 250.7 s | 63.9 s | 898.8 s (825.2 + 73.6) | 254.4 s | 73.3 s | 122.9 s | 3,219 MiB | 87.4 MB/s |
| s18-J-2 | 15:38 | J | defaults | 267.4 s | 4,173.7 blk/s | 209.0 s | 58.4 s | 907.8 s (829.0 + 78.8) | 210.4 s | 70.8 s | 128.4 s | 6,695 MiB | 103.5 MB/s |
| s18-I-2 | 15:49 | I | defaults | 273.3 s | 4,083.6 blk/s | 210.1 s | 63.2 s | 898.3 s (823.6 + 74.7) | 212.8 s | 70.8 s | 127.7 s | 6,835 MiB | 103.2 MB/s |
| s18-H-2 | 16:00 | H | defaults | 312.9 s | 3,566.7 blk/s | 248.5 s | 64.4 s | 904.8 s (831.0 + 73.8) | 250.8 s | 74.7 s | 127.6 s | 3,195 MiB | 87.4 MB/s |
| s18-G-3 | 16:12 | G' | defaults | 320.9 s | 3,477.8 blk/s | 252.4 s | 68.5 s | 897.6 s (824.5 + 73.1) | 255.5 s | 71.9 s | 122.5 s | 3,077 MiB | 90.3 MB/s |
| f18-dcrd-1 | 16:24 | dcrd v2.1.7 | defaults | 2,991.4 s | 373.1 blk/s | 2,119.8 s | 871.6 s | 5,666.6 s (4,551.8 + 1,114.8) | — | — | — | 1,835 MiB | 15.4 MB/s |
| f18-J-noindex-1 | 17:20 | J | `--noexistsaddrindex` | 247.3 s | 4,512.9 blk/s | 193.2 s | 54.1 s | 790.6 s (736.1 + 54.5) | 211.1 s | — | 126.4 s | 6,111 MiB | 110.8 MB/s |
| f18-J-sync-1 | 17:30 | J | `DCROXIDE_DB_SYNC_COMMIT=1` | 356.2 s | 3,133.2 blk/s | 287.1 s | 69.1 s | 877.1 s (808.9 + 68.2) | 286.7 s | 71.5 s | 126.4 s | 2,966 MiB | 79.5 MB/s |
| f18-J-3 | 17:43 | J | defaults | 268.9 s | 4,150.4 blk/s | 210.6 s | 58.3 s | 910.4 s (830.7 + 79.7) | 212.0 s | 72.1 s | 130.7 s | 6,222 MiB | 101.6 MB/s |
| f18-dcrd-noindex | 17:54 | dcrd v2.1.7 | `--noexistsaddrindex` | 1,330.3 s | 838.9 blk/s | 690.6 s | 639.7 s | 2,786.8 s (2,542.5 + 244.3) | — | — | — | 1,836 MiB | 38.1 MB/s |
| f18-J-noindex-2 | 18:22 | J | `--noexistsaddrindex` | 248.0 s | 4,500.1 blk/s | 194.2 s | 53.8 s | 790.7 s (735.6 + 55.1) | 209.6 s | — | 126.5 s | 5,498 MiB | 113.6 MB/s |
| f18-J-sync-2 | 18:33 | J | `DCROXIDE_DB_SYNC_COMMIT=1` | 358.0 s | 3,117.4 blk/s | 285.0 s | 73.0 s | 882.6 s (811.7 + 70.9) | 291.2 s | 71.5 s | 127.1 s | 2,888 MiB | 87.0 MB/s |
| diag-J-arena2 | 18:40 | J | `MALLOC_ARENA_MAX=2` | 308.8 s | 3,614.1 blk/s | 244.6 s | 64.2 s | 969.5 s (876.4 + 93.1) | 233.7 s | 90.6 s | 153.7 s | 3,423 MiB | 85.1 MB/s |
| diag-J-mmap128k | 18:46 | J | `MALLOC_MMAP_THRESHOLD_=131072` | 266.7 s | 4,184.6 blk/s | 207.7 s | 59.0 s | 907.0 s (827.1 + 79.9) | 209.3 s | 71.2 s | 128.8 s | 7,199 MiB | 102.4 MB/s |

The records label the runs of G' s18-G-*. dcrd is the v2.1.7 binary of
the sections above, `2.1.7+release.local (Go version go1.25.4
linux/amd64)`.

| step | adds | wall | of the mean of G' | before block 1,026,597 | after it | block thread | index thread | reader thread | node CPU time |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| G' to H | the data sanity checks on the reader | −3.32 s | 1.0% | −3.28 s | −0.03 s | −5.3 s | +2.4 s | +5.2 s | +6.1 s |
| H to I | a flush's inserts and the index's contribution on `dbcommit`, held | −41.45 s | 13.0% | −39.25 s | −2.20 s | −37.6 s | −4.2 s | +0.2 s | −4.0 s |
| I to J | durable commits counted toward the periodic flush's 120 s, held | −7.10 s | 2.2% | −2.17 s | −4.93 s | −0.8 s | +0.4 s | +1.1 s | +9.1 s |
| G' to J | the three | −51.87 s | 16.3% | −44.70 s | −7.17 s | −43.6 s | −1.4 s | +6.5 s | +11.3 s |

The means are 318.77 s for G', 315.45 s for H, 274.00 s for I and
266.90 s for J, the last over its three default runs.

**How sure a step is, here.** Pooled as above over this session's
runs (6 degrees of freedom, a standard deviation of 2.90 s, nearly
twice the morning's): at 95% a step between two runs and three is good
to about ±6.5 s, and one between two pairs to ±7.1 s. H's 3.32 s is not
resolved. Build I's 41.45 s is. J's 7.10 s is at the edge, and its third
run was made later and outside the bracket; on its two bracketed runs
alone it is 8.10 s against ±7.1 s.

- **H, the data sanity checks on the reader.** The block thread's time
  fell 5.3 s and the reader thread's rose 5.2 s; the hashing figure of
  the node's line at shutdown, which from H on includes the checks,
  rose from 57.96 to 57.98 s in the runs of G' to 63.03 and 63.06 s.
  By wall 3.32 s, not resolved: 3.28 s of it before the assume-valid
  block and none after it. Peak RSS was 3,338 and 3,195 MiB against
  3,077 to 3,342 MiB for G'.
- **G' against G.** G' ran 318.77 s here and G 321.45 s in the
  morning: another session, with controls that spread seven times as
  wide, so F's change is not measured again by the two.
- **I and J, held.** With build I the flushes' foreground time (the
  flush log's `fg_ms`), 45.3 to 47.0 s in the runs of G' and H, fell to
  5.5 and 6.4 s, the block thread's time 37.6 s, and the wall 41.45 s,
  39.25 s of it before the assume-valid block. With J the foreground
  time fell to 2.6 to 3.2 s, and the wall 7.10 s, 4.93 s of it after
  the assume-valid block. Node CPU time did not fall: 897.2 s for G' and
  908.5 s for J by the means. Their memory is below.
- **The read-ahead and the link.** The block thread waited for the
  reader 2.59 to 2.64 s in all in the runs of G' and 3.37 to 3.80 s
  in those of H, I and J, and at most 3.98 s in any run of the session.
  The highest 10 s receive rate was 86.9 to 90.3 MB/s for G' and H,
  101.4 to 103.5 MB/s for I and J, and 110.8 and 113.6 MB/s for J with
  the index off. The link's speed is in no record; a gigabit link
  carries about 117 MB/s, so the fastest runs may have neared it in
  their fastest 10 s, which the records cannot settle.

**J against dcrd v2.1.7 (f18).** J is a build that includes the two
held changes, so none of these figures is one for code in the
repository, and nothing here sets H against dcrd. J's three default
runs, 264.4 s, 267.4 s and 268.9 s, a mean of 266.9 s, against dcrd's
one run of 2,991.4 s: 11.21x, 11.12x to 11.31x over the three
pairings. To the assume-valid block J took 208.1 s against 2,119.8 s,
10.2x, and the 89,438 blocks after it 58.8 s against 871.6 s, 14.8x.
With the index off, 247.3 s and 248.0 s against 1,330.3 s, 5.37x
(5.38x and 5.36x). The index costs J 19.25 s, 7.2% of its default
mean, and dcrd 1,661.1 s, 55.5% of its run. dcrd used 5,666.6 s of CPU
time, 6.2x J's mean of 908.5 s, and peaked at 1,835 MiB; J peaked at
6,222 to 7,241 MiB, 3.4x to 3.9x that, and H at 3,195 and 3,338 MiB,
1.7x and 1.8x. A fourth default run of J and a second dcrd run were
skipped for the queue's deadline, so the ratio rests on one dcrd run.

**The background commit with the held changes.** J with
`DCROXIDE_DB_SYNC_COMMIT=1`, every commit on the committing thread:
356.2 s and 358.0 s, a mean of 357.1 s, so J at the defaults took
90.2 s or 25.3% less, at a peak RSS of 6,222 to 7,241 MiB against 2,966
and 2,888 MiB. The flushes' foreground time was 112.3 s and 111.6 s
with the variable. On 2026-10-17, without the held changes and from
the loopback server, the background commit as committed was 32.95 s or
7.7% less than the variable's runs; that is other code in another
series.

**Memory: the held changes double the peak.** By the harness's peak
RSS to the clock, the highest 10 s sample before the assume-valid
block, and the bytes the thread arenas' mappings span at the last
flush capture inside the clock (the flush log's `arena_bytes` and
`arena_maps`, which count those mappings in use or freed and kept
alike):

| build | setting | runs | peak RSS | highest sample before block 1,026,597 | thread arenas at the last capture |
|---|---|---|---:|---:|---:|
| G' | defaults | 3 | 3,077 to 3,342 MiB | 2,931 to 2,957 MiB | 2.73 to 2.85 GiB in 57 or 58 mappings |
| H | defaults | 2 | 3,195 and 3,338 MiB | 2,942 and 3,137 MiB | 2.85 and 2.96 GiB in 59 |
| I | defaults | 2 | 6,835 and 7,200 MiB | 5,022 and 5,047 MiB | 6.03 and 6.60 GiB in 101 and 104 |
| J | defaults | 3, and v18-J-loopback | 6,222 to 7,241 MiB, and 6,931 MiB | 4,408 to 5,065 MiB | 5.47 to 6.71 GiB in 91 to 105 |
| J | `--noexistsaddrindex` | 2 | 5,498 and 6,111 MiB | 4,158 and 4,778 MiB | 4.60 and 5.19 GiB in 78 and 83 |
| J | `DCROXIDE_DB_SYNC_COMMIT=1` | 2, and v18-J-sync-loopback | 2,888 and 2,966 MiB, and 2,886 MiB | 2,837 to 2,917 MiB | 2.28 to 2.41 GiB in 53 to 57 |
| J | `MALLOC_ARENA_MAX=2` | 1 | 3,423 MiB | 3,346 MiB | 1.81 GiB in 21 |
| J | `MALLOC_MMAP_THRESHOLD_=131072` | 1 | 7,199 MiB | 4,812 MiB | 6.53 GiB in 103 |

The loopback runs' peaks are those of the end-state checks above.

- **The shape.** In G' and H resident memory climbed to about 2.9 to
  3.1 GiB by the assume-valid block and rose 0.1 to 0.4 GiB more after
  it. In builds I and J it rose and fell from flush to flush before
  that block, reaching 4.3 to 4.9 GiB, and rose 1.2 to 2.2 GiB after
  it, once the script pool's 15 threads start. The samples are 10 s
  apart, so they understate each peak between them.
- **With two arenas (`MALLOC_ARENA_MAX=2`) one run of J peaked at
  3,423 MiB**, 85 MiB above H's higher run, and took 308.8 s, 41.9 s
  more than J's mean, with 969.5 s of CPU time against 907.2 to
  910.4 s; the reader thread's time rose to 153.7 s from 128.3 to
  130.7 s, and the node line's checksum-and-decode figure to 65.1 s
  from 47.7 to 48.2 s. So J's data at its peak is about H's, and the
  rest is memory glibc's arenas hold. That is inferred from the cap's
  effect and not read: nothing records an arena's bytes in use.
- **With the mmap threshold fixed at 128 KiB
  (`MALLOC_MMAP_THRESHOLD_=131072`) one run peaked at 7,199 MiB in
  266.7 s**, as J does at the defaults: allocations of 128 KiB or more,
  which that setting maps and unmaps on their own, are not where the
  memory is held.
- **What it goes with.** Build I moves a flush's row inserts and the
  index's contribution onto `dbcommit`, a thread made for each flush
  that ends with it, so that work allocates from whichever arena glibc
  gives the new thread, and a chunk goes back to the arena it came from
  whichever thread frees it. That is the likely mechanism, and it is not
  demonstrated. With `DCROXIDE_DB_SYNC_COMMIT=1`, which keeps every
  commit on the committing thread, J peaked below every run of G'.
- **Not tried:** one committer thread kept for the life of the
  process, less allocation on the commit path, other arena counts, and
  a second run of either diagnostic. Both diagnostics ran straight from
  the harness after the queue, without its idle and quiet gate, with
  other userland at 0.16% and 0.18%.

> **Note (2026-10-19): one commit thread for the life of the store, and
> eight arenas.** K, J's code with the `dbcommit` thread started by the
> first flush handed over and kept until the close, peaked at 2,456 and
> 2,470 MiB in two default runs alternated with three of J, which peaked
> at 6,730 to 6,933 MiB, and took 271.10 s against 273.63 s by the
> means, a difference that session does not resolve. Its thread arenas
> spanned 1.98 and 1.99 GiB at the last capture, against J's 6.01 to
> 6.18 GiB. One run of J with `MALLOC_ARENA_MAX=8` peaked at 5,455 MiB
> and took 284.2 s, 10.6 s more than J's mean there. That fits the
> mechanism above without demonstrating it: which arena each thread used
> is still in no record. See "One commit thread for the life of the
> store, a sync that checks every script, and dcrd v2.1.7" below.

**Where the block thread waits beside a background commit (the
evening of 2026-10-17).** Two syncs of `88c46c3` from the loopback
dcrd v2.1.6 server, s17-m1-head at the defaults at 20:51 and
s17-m1-sync with `DCROXIDE_DB_SYNC_COMMIT=1` at 21:06, under a sampler
that read, 200 times a second, the scheduler state of the block thread
and the index thread and, for a thread not running, the kernel
function it waited in, and noted whether a `dbcommit` thread existed at
that instant. They took 426.0 s and 468.1 s, but the server read
19.2 GB from its drive in both, so neither wall is a timing beside the
runs of 2026-10-17 above. The block thread's CPU time at the defaults,
339.5 s, is that of the default runs there (337.1 to 339.9 s), and its
time off a processor 86.5 s against 53.6 to 60.0 s. The shape is the
finding. The block thread of s17-m1-head:

| block thread | no `dbcommit` thread (330.7 s) | a `dbcommit` thread (95.1 s) |
|---|---:|---:|
| running or runnable | 293.3 s (88.7%) | 50.9 s (53.6%) |
| uninterruptible, a page under writeback or locked (`folio_wait_bit_common`) | 6.7 s | 20.9 s |
| uninterruptible, a write's space reservation (`reserve_bytes`) | 0.3 s | 9.1 s |
| uninterruptible, the ordered extents over a range written (`btrfs_start_ordered_extent_nowriteback`) | 10.1 s | 8.1 s |
| uninterruptible, elsewhere | 1.0 s | 0.4 s |
| asleep on a futex | 15.5 s | 5.0 s |
| asleep elsewhere | 3.9 s | 0.7 s |

- **The commits.** A `dbcommit` thread existed in 22.3% of the
  samples; by the flush log the 52 background commits inside the clock
  spent 83.7 s in their commit phases, 41.5 s of it off a processor,
  and wrote 19.56 GiB to the metadata file, a median of 360 MB and
  1.52 s each. The thread also retires what its flush captured, which
  that phase leaves out.
- **The waits are the filesystem's.** The block thread was
  uninterruptible for 56.4 s in all, 38.4 s of it while a commit was
  under way, nearly all of it in btrfs's buffered-write paths; m3's
  btrfs compresses and sits on an encrypted mapping. Its waits on a
  futex, the node's own locks among them, were 5.0 s of the 95.1 s.
- **Which file is by elimination.** The sampler could not read which
  system call a wait was in: the kernel's ptrace restriction forbids
  it. The flushes' own block-file syncs took 3.2 s, 2.7 s of it off a
  processor, and their row inserts 29.2 s, 0.2 s of it off a processor,
  and the node logged 84 lines. What is left is the block thread's write
  of each block's record into the current block file, which writes
  again the last page the record before it wrote. That is inferred,
  not observed.
- **With `DCROXIDE_DB_SYNC_COMMIT=1`** the block thread made 38 of the
  flushes inside the clock and committed them itself, 63.0 s of commit
  phases with 33.7 s off a processor, and the index thread 17, 29.3 s.
  The block thread was uninterruptible for 49.6 s
  (`folio_wait_bit_common` 20.7 s, the ordered extents 10.6 s,
  `reserve_bytes` 7.9 s, `btrfs_btree_wait_writeback_range` 4.7 s,
  `wait_for_commit` 3.1 s, elsewhere 2.6 s) and asleep on a futex for
  51.8 s.
- **Not measured:** the same with a block server whose data stays
  cached, since its reads from the drive may have added to these waits;
  the system call of each wait; any remedy.

> **Note (2026-10-19, evening): sampled again, from a server on another
> machine.** Under the same sampler, changed for a commit thread kept
> for the life of the store, the block thread of `797a213` was
> uninterruptible for 35.8 s of a default sync from the LAN server,
> 25.4 s of it while a commit was under way, nearly all of it in the
> same three btrfs functions. The system call of each wait is still not
> sampled, and no remedy was measured. See "Where `797a213`'s block
> thread waits, a deeper read-ahead and a rung of four changes" below.

**What was not measured.**

- The tree of any commit: every build here was a state of a worktree.
- G' and H, the builds with neither F's change nor the held ones,
  against dcrd; `88c46c3` against dcrd from the LAN server; the end
  state of G' or H.
- The metadata store beyond the UTXO set and the block files, in the
  three loopback checks; any end state, the shutdown and the memory
  after the clock, in the LAN runs.
- Each change on its own: B's two changes and E's two were not run
  apart, and each step is a change on top of those below it in this
  order.
- A fourth default run of J and a second dcrd run, skipped for the
  deadline; a second dcrd run with the index off.
- The LAN server's load, cache and configuration, the link's speed,
  and the round trip, in any run record; a link with a longer round
  trip.
- `DCROXIDE_READ_AHEAD=off`, and the flush log's own cost: it was on in
  every dcroxide run.
- G' and H with `DCROXIDE_DB_SYNC_COMMIT=1`, a remedy for the held
  changes' memory, and the diagnostics' repeats.
- Storage other than m3's NVMe drive under btrfs; Windows and macOS.

> **Note (2026-10-19): a remedy for the held changes' memory was
> measured**: J's code with one `dbcommit` thread kept for the life of
> the store. One other arena count, eight, was run on J once; neither
> diagnostic above was run again. See "One commit thread for the life of
> the store, a sync that checks every script, and dcrd v2.1.7" below.

Raw: the comparison's `runs-lan.jsonl` rows labelled `l17-H-1`,
`l17-A1-1`, `l17-A2-1`, `l17-B-1`, `l17-C-1`, `l17-D-1`, `l17-E-1`,
`l17-F-1`, `l17-G-1`, `l17-H-2`, `l17-G-2`, `l17-F-2`, `l17-E-2`,
`l17-D-2`, `l17-C-2`, `l17-B-2`, `l17-A2-2`, `l17-A1-2`, `l17-H-3`,
`s18-G-1`, `s18-H-1`, `s18-I-1`, `s18-J-1`, `s18-G-2`, `s18-J-2`,
`s18-I-2`, `s18-H-2`, `s18-G-3`, `f18-dcrd-1`, `f18-J-noindex-1`,
`f18-J-sync-1`, `f18-J-3`, `f18-dcrd-noindex`, `f18-J-noindex-2` and
`f18-J-sync-2`; `pv-pair-lan.jsonl`'s `l17-pv-on-1` and `l17-pv-off-1`;
`verify.jsonl`'s `v18-G-loopback`, `v18-J-loopback` and
`v18-J-sync-loopback`; `diag-mem.jsonl`'s `diag-J-arena2` and
`diag-J-mmap128k`; `runs.jsonl`'s `s17-m1-head` and `s17-m1-sync`, with
their wait-channel counts; per-run samples, flush logs and node logs;
the queues' steps and logs; the harness's change for a server on
another machine; and the two stacks' code states and build notes.

## One commit thread for the life of the store, a sync that checks every script, and dcrd v2.1.7 (2026-10-19)

"Rungs from a block server on the LAN, two changes held for their
memory, and dcrd v2.1.7" above held back the changes of builds I and J:
with a flush's row inserts and the exists-address index's contribution
made on `dbcommit`, a thread made for each flush, J peaked at 6,222 to
7,241 MiB of resident memory against 3,077 to 3,342 MiB for G' and H,
and one run with two allocator arenas took nearly all of the extra away
at a cost of 41.9 s. One more change was then made on J's code, as a
state of a worktree with nothing committed: the `dbcommit` thread is
started by the first flush handed to it and kept, asleep between
flushes, until the store's close or the drop of its last handle. Its
build is K. Between 02:51 and 07:57 on 2026-10-19, 18 syncs were run on
m3, in two queues and none outside them:

- one of K from the loopback dcrd v2.1.6 block server at the defaults,
  for its end state (v19-K-loopback);
- six from the LAN server of the section above, J, K, J, K and J at the
  defaults and then K with the exists-address index off (k19-*);
- one of J with `MALLOC_ARENA_MAX=8` (diag-J-arena8);
- one of K from the loopback server with `--assumevalid=0`, for its end
  state with every block validated in full (v19-K-fullval-loopback);
- in the second queue, from the LAN server, two more of K at the
  defaults, one with the index off and two with
  `DCROXIDE_DB_SYNC_COMMIT=1`, two of dcrd v2.1.7 at the defaults and
  one with the index off (f19-*), and one of a build of K with frame
  pointers under two `perf` recorders, a profile and not a clean timing
  (p19-K-profile).

**The builds.** J is the binary of build J above, unchanged: the
records' `binary_sha` is the same. K is a release build, at the
workspace's release profile with nothing else set, of J's code and the
one change, a state of a worktree on `fdd7a83` as the rungs above were.
A second build of K's code, from a fresh export of `fdd7a83` with the
changes applied as patches, had the same code and data, every loaded
section with contents equal, with only the build id, the debug
information, which names the source directory, and the suffixes ThinLTO
gives local symbols differing.

K's code is that of the three commits that follow the commit that adds
this section. They make its three changes in another order: the kept
thread first, then build I's change, then build J's, so that no commit
writes a flush's rows on a thread made for each flush. The third
commit's code differs from K's only by a doc comment in
`crates/dcroxide-blockchain/src/utxoview.rs` and a test's local name in
`crates/dcroxide-database/src/dbcache.rs`, the changes of `a752421` and
`a7f80b9`, which K's state predates and a release build does not
contain. The trees of the first two were neither built as release
binaries nor synced, so the kept thread before the rows move onto it is
not measured, nor build I's change on top of it.

**The session.** The syncs are in the harness of the section above. The
LAN server was the same live node, dcrd v2.1.7 by its user agent,
following the network: the starting height it gave each run went from
1,124,927 to 1,124,981; at the poll that stopped the clock the node was
4 to 1,818 blocks past block 1,116,035, and its block at that height was
the frozen chain's in every LAN run. Before each loopback run the
server's data, 26.0 GB, was read into the page cache, in 30.6 s and
28.3 s, and the server still read 19.2 GB from its drive in each, as in
the end-state checks above, so the two loopback walls are not timings.
Every run exited 0, none stalled, and none was marked disturbed; other
userland was 0.04% to 0.05% of the machine in the LAN runs and 0.10% and
0.05% in the loopback ones. Every run of a queue but its first followed
a `sync`, a 300 s idle and the quiet gate; the first of each,
v19-K-loopback and f19-K-3, followed the gate alone, f19-K-3 about two
and a half minutes after the first queue's last run ended. Unlike the
two diagnostics above, diag-J-arena8 ran inside a queue, after its idle
and gate. Transparent huge pages were `madvise` throughout: the system
journal shows no write to the setting after the one of 2026-10-17 at
05:21 and no restart, and it read `madvise` after the last run. The
flush log was on in every dcroxide run, and every figure is defined as
in the section above.

**This session and the last.** The LAN runs are of the series of the
section above, not comparable with the loopback rows. J's three runs
took 271.8 to 274.8 s, a mean of 273.63 s, where its three of 2026-10-18
took 264.4 to 268.9 s, a mean of 266.90 s, and dcrd v2.1.7 took
3,014.6 s and 3,033.4 s here against 2,991.4 s there. Both were slower
in this session, for a cause not taken apart, so a figure set against
one of 2026-10-18 carries a difference of that order. Across the two
sessions, K's mean at the defaults, 271.68 s, is 135.9 s or 33.3% under
the 407.57 s of `88c46c3`'s three controls of the morning of 2026-10-18.

| run | started | build | setting | wall | rate | to block 1,026,597 | after it | node CPU time (user + sys) | block thread | index thread | reader thread | `dbcommit` thread | peak RSS | received, highest 10 s |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| k19-J-1 | 03:02 | J | defaults | 274.8 s | 4,061.3 blk/s | 215.0 s | 59.8 s | 902.0 s (828.0 + 74.0) | 212.2 s | 70.7 s | 128.2 s | — | 6,730 MiB | 97.7 MB/s |
| k19-K-1 | 03:14 | K | defaults | 270.7 s | 4,122.8 blk/s | 212.8 s | 57.9 s | 896.2 s (825.3 + 70.9) | 211.7 s | 70.5 s | 128.4 s | 91.4 s | 2,456 MiB | 100.9 MB/s |
| k19-J-2 | 03:24 | J | defaults | 271.8 s | 4,106.1 blk/s | 212.6 s | 59.2 s | 901.4 s (826.9 + 74.5) | 211.7 s | 70.8 s | 128.2 s | — | 6,933 MiB | 98.0 MB/s |
| k19-K-2 | 03:36 | K | defaults | 271.5 s | 4,110.6 blk/s | 211.2 s | 60.3 s | 902.9 s (833.0 + 69.9) | 211.2 s | 70.8 s | 128.3 s | 91.2 s | 2,470 MiB | 103.6 MB/s |
| k19-J-3 | 03:46 | J | defaults | 274.3 s | 4,068.7 blk/s | 213.3 s | 61.0 s | 908.5 s (834.0 + 74.5) | 212.2 s | 71.9 s | 130.1 s | — | 6,786 MiB | 98.8 MB/s |
| k19-K-noindex-1 | 03:58 | K | `--noexistsaddrindex` | 250.8 s | 4,449.9 blk/s | 196.6 s | 54.2 s | 794.0 s (741.2 + 52.8) | 211.8 s | — | 127.2 s | 58.2 s | 2,269 MiB | 112.5 MB/s |
| diag-J-arena8 | 04:08 | J | `MALLOC_ARENA_MAX=8` | 284.2 s | 3,926.9 blk/s | 222.0 s | 62.2 s | 909.3 s (832.3 + 77.0) | 214.9 s | 77.3 s | 128.1 s | — | 5,455 MiB | 97.0 MB/s |
| f19-K-3 | 04:33 | K | defaults | 272.7 s | 4,092.5 blk/s | 212.6 s | 60.1 s | 894.2 s (824.2 + 70.0) | 211.0 s | 70.4 s | 128.1 s | 90.5 s | 2,457 MiB | 99.6 MB/s |
| f19-dcrd-1 | 04:44 | dcrd v2.1.7 | defaults | 3,014.6 s | 370.2 blk/s | 2,141.5 s | 873.1 s | 5,665.5 s (4,542.7 + 1,122.8) | — | — | — | — | 1,836 MiB | 15.4 MB/s |
| f19-K-sync-1 | 05:41 | K | `DCROXIDE_DB_SYNC_COMMIT=1` | 350.2 s | 3,186.9 blk/s | 282.6 s | 67.6 s | 877.8 s (809.0 + 68.8) | 285.6 s | 71.9 s | 126.9 s | — | 2,959 MiB | 86.8 MB/s |
| f19-K-4 | 05:53 | K | defaults | 271.8 s | 4,106.1 blk/s | 212.4 s | 59.4 s | 893.7 s (823.8 + 69.9) | 210.6 s | 70.5 s | 128.4 s | 90.7 s | 2,460 MiB | 97.3 MB/s |
| f19-dcrd-noindex | 06:04 | dcrd v2.1.7 | `--noexistsaddrindex` | 1,336.3 s | 835.2 blk/s | 697.6 s | 638.7 s | 2,779.9 s (2,540.0 + 239.9) | — | — | — | — | 1,836 MiB | 37.3 MB/s |
| f19-K-noindex-2 | 06:32 | K | `--noexistsaddrindex` | 249.6 s | 4,471.3 blk/s | 196.2 s | 53.4 s | 785.8 s (732.8 + 53.0) | 210.1 s | — | 126.7 s | 58.1 s | 2,270 MiB | 109.5 MB/s |
| f19-K-sync-2 | 06:43 | K | `DCROXIDE_DB_SYNC_COMMIT=1` | 350.6 s | 3,183.2 blk/s | 284.1 s | 66.5 s | 874.6 s (807.7 + 66.9) | 281.6 s | 74.5 s | 126.6 s | — | 2,964 MiB | 85.8 MB/s |
| p19-K-profile | 06:55 | K with frame pointers | defaults, under `perf` (not a clean timing) | 276.1 s | 4,042.1 blk/s | 216.5 s | 59.6 s | 927.5 s (845.2 + 82.3) | 216.7 s | 73.6 s | 135.0 s | 95.3 s | 2,464 MiB | 98.7 MB/s |
| f19-dcrd-2 | 07:06 | dcrd v2.1.7 | defaults | 3,033.4 s | 367.9 blk/s | 2,154.6 s | 878.8 s | 5,699.8 s (4,561.0 + 1,138.8) | — | — | — | — | 1,836 MiB | 15.0 MB/s |

The `dbcommit` column is the thread K keeps, by the same count as the
other threads. J's runs list none, the thread of each flush having ended
when the counters were read, and none is started with
`DCROXIDE_DB_SYNC_COMMIT=1`. dcrd is the v2.1.7 binary of the sections
above.

**J against K (k19).** The runs alternated J, K, J, K, J, so that each
run of K sits between two of J. **K peaked at 2,456 and 2,470 MiB
against J's 6,730 to 6,933 MiB, 4,353 MiB or 63.9% less by the means,
and took 270.7 s and 271.5 s, a mean of 271.10 s, against 274.8 s,
271.8 s and 274.3 s, a mean of 273.63 s**: 2.53 s less. Pooled over
those five runs as above (3 degrees of freedom, a standard deviation of
1.35 s), a step between two runs and three is good to about ±3.9 s, so
the 2.53 s is not resolved; with K's two later runs as well, 1.96 s less
against ±2.4 s (5 degrees of freedom), it is not either. K was no slower
than J.

- **Everything else was J's.** Each default run of either from the LAN
  server made 52 flushes inside the clock, all of them handed over, with
  2.5 to 2.8 s of foreground time; in all seven the block thread's time
  was 210.6 to 212.2 s, the index thread's 70.4 to 71.9 s and the reader
  thread's 128.1 to 130.1 s. Node CPU time was 893.7 to 902.9 s for K
  and 901.4 to 908.5 s for J.
- **The commit thread.** In every default run of K from the LAN server
  the per-thread counters list one `dbcommit` thread, on a processor for
  90.5 to 91.4 s, and for 58.2 s and 58.1 s with the index off.
- **The shape.** By the 10 s samples K climbed to 2,392 to 2,421 MiB by
  the assume-valid block, and its peak was 49 to 64 MiB above that; J
  reached 4,399 to 5,047 MiB by that block, and its peak was 1,739 to
  2,534 MiB above it. At the last flush capture inside the clock the
  thread arenas' mappings spanned 1.97 to 1.99 GiB in 55 or 56 mappings
  for K, and 6.01 to 6.18 GiB in 94 to 102 for J.
- **Below the builds without the held changes.** K peaked lower than G'
  and H did on 2026-10-18, 3,077 to 3,342 MiB; those hold neither held
  change, and made a `dbcommit` thread for each flush's commit and what
  follows it. That is another session, and the difference is not taken
  apart. With `DCROXIDE_DB_SYNC_COMMIT=1`, which starts no commit
  thread, K peaked at 2,959 and 2,964 MiB, above its default runs; J's
  runs with it on 2026-10-18 peaked at 2,966 and 2,888 MiB.
- **With eight arenas (`MALLOC_ARENA_MAX=8`) one run of J peaked at
  5,455 MiB** and took 284.2 s, 10.6 s more than J's mean, with 909.3 s
  of CPU time; its index thread's time was 77.3 s and its block thread's
  214.9 s. At the last capture its thread arenas spanned 4.27 GiB in 55
  mappings, and its highest sample before the assume-valid block,
  5,148 MiB, was above any run of J's. On 2026-10-18 two arenas brought
  J's peak to 3,423 MiB for 41.9 s.
- **What it shows.** K's result fits the mechanism inferred above, a
  thread made for each flush allocating from whichever arena glibc gives
  it and leaving what earlier flushes freed in theirs, and does not
  demonstrate it: which arena each thread used is still in no record.
  The memory after the clock, which the commit thread's arena may keep,
  is not recorded for the LAN runs.

**K against dcrd v2.1.7 (f19).** K's code is that of the commits that
follow, so these figures, unlike J's above, are for code the repository
holds from the third of them on. K's four default runs, 270.7 s,
271.5 s, 272.7 s and 271.8 s, a mean of 271.68 s, against dcrd's two
runs, 3,014.6 s and 3,033.4 s, a mean of 3,024.0 s: **11.13x**, 11.05x
to 11.21x over the eight pairings. To the assume-valid block K took
212.25 s against 2,148.05 s, 10.1x, and the 89,438 blocks after it
59.43 s against 875.95 s, 14.7x. With the index off, 250.8 s and 249.6 s
against one dcrd run of 1,336.3 s, 5.34x (5.33x and 5.35x). The index
costs K 21.5 s, 7.9% of its default mean, and dcrd 1,687.7 s, 55.8% of
its mean. dcrd used 5,665.5 s and 5,699.8 s of CPU time, 6.3x K's mean
of 896.75 s, and peaked at 1,836 MiB; K peaked at 2,456 to 2,470 MiB,
1.34x to 1.35x that. J's 11.21x of 2026-10-18 rests on one dcrd run of
another session.

**The background commit with K.** K with `DCROXIDE_DB_SYNC_COMMIT=1`,
every commit on the committing thread: 350.2 s and 350.6 s, a mean of
350.40 s, so K at the defaults took 78.7 s or 22.5% less, and peaked
lower, at 2,456 to 2,470 MiB against 2,959 and 2,964 MiB. With the
variable the flushes' foreground time was 106.1 s and 106.5 s, and the
block thread's time 285.6 s and 281.6 s against 210.6 to 211.7 s at the
defaults. On 2026-10-18 J at the defaults was 90.2 s or 25.3% less than
its own runs with the variable, and on 2026-10-17 `88c46c3` from the
loopback server 32.95 s or 7.7% less than its own: other code, and other
sessions.

**The end state, and every block validated in full (v19).** Two syncs of
K from the loopback dcrd v2.1.6 server, for the end state that the LAN
runs do not record: at the defaults at 02:51 and with `--assumevalid=0`
at 04:20, the node logging that assume-valid was disabled. Each ended on
the server's tip, `8752fdc9…`, and in each `gettxoutsetinfo` reported
the UTXO set of every full sync from the loopback server since
2026-10-17: 760,741 transactions, 1,850,903 outputs, a total amount of
1,672,716,060,550,750 atoms and the serialized hash
`eb7f88de7b69f98676ce78072c0f90cc2667b875df0b26637dffcf9da5b3c30c`. The
block files hashed to `33b7ac837a45c74f` over 36 files and
19,202,596,910 B in both. The exists-address index and the rest of the
metadata store were not compared.

| run | started | build | setting | wall | to block 1,026,597 | after it | node CPU time (user + sys) | mean cores | block thread | script pool, 15 threads | `dbcommit` thread | peak RSS |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| v19-K-loopback | 02:51 | K | defaults | 275.0 s | 211.9 s | 63.1 s | 898.1 s (829.6 + 68.5) | 3.27 | 214.0 s | 391.6 s | 94.2 s | 2,462 MiB |
| v19-K-fullval-loopback | 04:20 | K | `--assumevalid=0` | 583.4 s | 519.8 s | 63.6 s | 4,399.8 s (4,283.3 + 116.5) | 7.54 | 400.1 s | 3,661.2 s | 102.4 s | 2,373 MiB |

The sync with `--assumevalid=0` is the first this ledger records. At the
defaults the blocks up to the assume-valid block skip the costlier
checks, their scripts among them; here every block was validated in
full, and the chain was accepted into the same state. Its 583.4 s is not
a timing, since the server read 19.2 GB from its drive, but beside the
default run made under the same condition it took 307.9 s more to the
assume-valid block and 0.5 s more after it, with 4,399.8 s of CPU time
against 898.1 s, 3,661.2 s of it on the script pool's 15 threads, at
7.54 mean cores. Its peak, 2,373 MiB, was below the default run's
2,462 MiB.

**The profiled run.** p19-K-profile ran a build of K's code with frame
pointers (`-C force-frame-pointers=yes`), not K's binary, under two
`perf` recorders on four cores of their own: a flat one at 499 Hz,
446,721 samples, and a call-graph one at 199 Hz unwinding by frame
pointer, 179,015 samples, both of user space only. It took 276.1 s,
4.45 s or 1.6% over the median of K's four default runs, which is not a
timing of either build. Its analysis is not done, and what the profile
shows is not set out here.

**What was not measured.**

- The trees of the first two of the three commits that follow: the kept
  thread without the two held changes, and with build I's change but not
  build J's. So what the kept thread does before the rows move onto it,
  and each of the three changes on its own, are not measured.
- Any end state in the LAN runs; K's end state with the index off or
  with `DCROXIDE_DB_SYNC_COMMIT=1`; the exists-address index and the
  rest of the metadata store in the two loopback checks.
- A timing of the sync with `--assumevalid=0`, from a server whose data
  stays cached, a second run of it, and dcrd with `--assumevalid=0`.
- A second dcrd run with the index off.
- The memory after the clock, which the commit thread's arena may keep;
  a second run of the arena diagnostic, and other arena counts.
- A sync whose sync peer changes: the thread that connects the sync
  peer's blocks ends with its connection, and every run here took its
  blocks from one peer.
- The LAN server's load, cache and configuration, the link's speed, and
  the round trip, in any run record; a link with a longer round trip.
- `DCROXIDE_READ_AHEAD=off`, and the flush log's own cost: it was on in
  every dcroxide run.
- What the profile shows.
- Storage other than m3's NVMe drive under btrfs; Windows and macOS.

Raw: the comparison's `runs-lan.jsonl` rows labelled `k19-J-1`,
`k19-K-1`, `k19-J-2`, `k19-K-2`, `k19-J-3`, `k19-K-noindex-1`,
`f19-K-3`, `f19-dcrd-1`, `f19-K-sync-1`, `f19-K-4`, `f19-dcrd-noindex`,
`f19-K-noindex-2`, `f19-K-sync-2` and `f19-dcrd-2`; `diag-mem.jsonl`'s
`diag-J-arena8`; `verify.jsonl`'s `v19-K-loopback` and
`v19-K-fullval-loopback`; `perf-k19.jsonl`'s `p19-K-profile`, with its
two recordings; per-run samples, flush logs and node logs; the queues'
steps and logs; and the code state and build notes of K and of its build
with frame pointers.

## Where `797a213`'s block thread waits, a deeper read-ahead and a rung of four changes (2026-10-19, evening)

"One commit thread for the life of the store, a sync that checks every
script, and dcrd v2.1.7" above ran K. The three commits that follow that
section make its changes, and `797a213`, the head of master when the
syncs below ran, holds them. The syncs below put three questions to that
code: where its block thread now waits; whether the read-ahead gains
from a deeper queue, the index thread from a longer queue of
notifications, and the pre-verification from more helpers; and what four
more changes gain, as one rung on top of it. Between 16:30 and 20:17 on
2026-10-19, 22 syncs were run on m3, in three queues and none outside
them, all but one from the LAN server of the two sections above:

- two of `797a213` under a sampler of where its threads wait, at the
  defaults and with the exists-address index off (m1k-*);
- eight of a diagnostic build of `797a213` that reads the read-ahead's
  depth and the index notification buffer from the environment, two at
  each of four settings (ra4-*, ra16-*, ra32-* and ra4b512-*);
- in the second queue, four of `797a213` and four of R1, `797a213` with
  four changes, alternated (r1s-*), and then one of R1 from the loopback
  dcrd v2.1.6 block server, for its end state (v20-R1-loopback);
- in the third, two of the diagnostic build at depth 16 with
  `DCROXIDE_PREVERIFY=10`, either side of a third run at depth 16 alone
  (ra16pv10-* and ra16-3).

In the run labels H stands for `797a213`, not for build H above.

**The builds.** `797a213` is a release build of that commit's tree, at
the workspace's release profile with nothing else set, made in a
worktree at the commit with nothing changed. Every loaded section of it
is equal to that of K's binary, whose code differs from the commit's
only by a doc comment and a test's local name, which a release build
does not contain. The diagnostic build is `797a213` with two environment
variables of its own, read once at startup, which are in no commit and
not meant for one: `DCROXIDE_DIAG_READ_AHEAD_DEPTH`, the most frames the
reading thread keeps ahead of the thread that processes blocks, four in
the code, and `DCROXIDE_DIAG_INDEX_NTFN_BUFFER`, how many index
notifications queue for the index thread before the thread that connects
blocks waits, 128 in the code, as dcrd's `bufferSize`. Everything the
code derives from the depth follows the variable: the reading thread's
bound, its queue's capacity, and the pre-verifier's bound, the largest
block message times one more than the depth, 6,553,600 B at four,
22,282,240 B at 16 and 43,253,760 B at 32. Unset, the build runs at four
and 128 with an atomic load where the code reads a constant, and logs
one line more at startup, so its runs at depth 4, and not `797a213`'s,
are the control of its other settings. R1 is a release build of
`797a213` with four changes, made one after another as states of a
worktree:

- a block's transactions are classified once, as the block is processed,
  for every step that reads their types, where five steps of its connect
  classified each one again;
- a block filter's list of entries is allocated once, at a bound worked
  out from the block, where it started at dcrd's hint and grew by
  doubling;
- a handed-over flush's block-file sync runs on `dbcommit`, before the
  flush's rows, where the capturing thread ran it, holding the
  database's writer, before the hand-off;
- a block filter's previous scripts are read from the spend journal the
  block's connect built, where each was looked up in the UTXO view.

Each of the three was built a second time, from a fresh export of
`797a213` with its changes, if any, applied as patches, and had every
loaded section equal to the first, with only the build id, the debug
information, which names the source directory, and the suffixes ThinLTO
gives local symbols differing.

The seven commits that follow the commit that adds this section hold
R1's changes and the depth: two that change only tests and comments,
then R1's four changes in R1's order, one a commit, then one that sets
the read-ahead's depth to sixteen frames in the code. R1's code is that
of the sixth, but for tests and comments, which a release build does not
contain. The seventh sets in the code, at the same places, what the
diagnostic build set at depth 16 through its variable, without the
variables or the line they log; it does so on top of R1's changes, and
the depth of sixteen with R1's changes was neither built nor synced. No
tree of the seven was built as a release binary or synced, and R1's four
changes were measured together, not one at a time.

**The session.** The syncs are in the harness of the sections above. The
LAN server was the same live node, dcrd v2.1.7 by its user agent,
following the network: the starting height it gave each run went from
1,125,081 to 1,125,126; at the poll that stopped the clock the node was
186 to 1,735 blocks past block 1,116,035, and its block at that height
was the frozen chain's in every LAN run. Every run exited 0, none
stalled, and none was marked disturbed; other userland was 0.05% to
0.06% of the machine. Every run of a queue but its first followed a
`sync`, a 300 s idle and the quiet gate; the first of each, m1k-H-1,
r1s-H-1 and ra16pv10-1, followed the gate alone, the last two 142 s and
149 s after the queue before them ended. Before the loopback run the
server's data, 26.0 GB, was read into the page cache in 29.1 s, and the
server still read 19.2 GB from its drive, as in the end-state checks
above, so that run's wall is not a timing. Transparent huge pages were
`madvise` throughout: the system journal shows no write to the setting
after the one of 2026-10-17 at 05:21 and no restart, and it read
`madvise` after the last run. The flush log was on in every run, and
every figure is defined as in the sections above; the read-ahead's and
the pre-verifier's lines at shutdown count to the shutdown, past the
clock.

**This session and the morning's.** `797a213`'s four runs of the second
queue took 269.8 to 273.2 s, a mean of 271.75 s, where K's four default
runs of the morning, with the same loaded code, took a mean of 271.68 s.

| run | started | build | setting | wall | rate | to block 1,026,597 | after it | node CPU time (user + sys) | block thread | index thread | reader thread | `dbcommit` thread | peak RSS | received, highest 10 s |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| m1k-H-1 | 16:30 | `797a213` | defaults, under the wait sampler | 271.0 s | 4,118.2 blk/s | 213.3 s | 57.7 s | 908.1 s (831.4 + 76.7) | 210.1 s | 71.3 s | 128.5 s | 97.0 s | 2,473 MiB | 98.9 MB/s |
| m1k-H-noindex-1 | 16:41 | `797a213` | `--noexistsaddrindex`, under the wait sampler | 254.8 s | 4,380.0 blk/s | 199.9 s | 54.9 s | 795.3 s (740.8 + 54.5) | 211.0 s | — | 127.5 s | 59.9 s | 2,271 MiB | 108.0 MB/s |
| ra4-1 | 16:51 | diagnostic | depth 4 | 273.3 s | 4,083.6 blk/s | 213.6 s | 59.7 s | 907.3 s (831.1 + 76.2) | 211.3 s | 70.8 s | 128.4 s | 96.5 s | 2,451 MiB | 98.0 MB/s |
| ra16-1 | 17:02 | diagnostic | depth 16 | 263.4 s | 4,237.0 blk/s | 209.5 s | 53.9 s | 893.9 s (820.2 + 73.7) | 207.9 s | 71.5 s | 129.2 s | 95.6 s | 2,471 MiB | 97.9 MB/s |
| ra32-1 | 17:13 | diagnostic | depth 32 | 267.2 s | 4,176.8 blk/s | 211.9 s | 55.3 s | 891.6 s (817.1 + 74.5) | 207.6 s | 71.7 s | 129.0 s | 96.4 s | 2,481 MiB | 97.7 MB/s |
| ra4b512-1 | 17:24 | diagnostic | depth 4, buffer 512 | 273.3 s | 4,083.6 blk/s | 213.7 s | 59.6 s | 908.7 s (833.3 + 75.4) | 211.9 s | 70.9 s | 129.4 s | 96.2 s | 2,486 MiB | 100.3 MB/s |
| ra32-2 | 17:35 | diagnostic | depth 32 | 263.5 s | 4,235.4 blk/s | 210.4 s | 53.1 s | 891.0 s (816.0 + 75.0) | 206.9 s | 71.6 s | 129.0 s | 96.8 s | 2,467 MiB | 102.1 MB/s |
| ra16-2 | 17:46 | diagnostic | depth 16 | 263.4 s | 4,237.0 blk/s | 209.0 s | 54.4 s | 894.7 s (820.7 + 74.0) | 207.6 s | 71.5 s | 129.6 s | 95.2 s | 2,466 MiB | 100.5 MB/s |
| ra4-2 | 17:57 | diagnostic | depth 4 | 272.9 s | 4,089.5 blk/s | 213.3 s | 59.6 s | 909.6 s (832.4 + 77.2) | 211.8 s | 71.1 s | 128.8 s | 97.6 s | 2,460 MiB | 95.4 MB/s |
| ra4b512-2 | 18:08 | diagnostic | depth 4, buffer 512 | 270.1 s | 4,131.9 blk/s | 211.4 s | 58.7 s | 900.8 s (826.6 + 74.2) | 211.1 s | 70.9 s | 128.8 s | 94.9 s | 2,493 MiB | 96.3 MB/s |
| r1s-H-1 | 18:15 | `797a213` | defaults | 273.1 s | 4,086.5 blk/s | 211.1 s | 62.0 s | 905.8 s (831.1 + 74.7) | 210.3 s | 71.1 s | 128.3 s | 95.5 s | 2,471 MiB | 98.3 MB/s |
| r1s-R1-1 | 18:26 | R1 | defaults | 263.1 s | 4,241.9 blk/s | 206.2 s | 56.9 s | 895.9 s (823.6 + 72.3) | 205.2 s | 70.9 s | 128.1 s | 94.6 s | 2,463 MiB | 103.0 MB/s |
| r1s-H-2 | 18:37 | `797a213` | defaults | 270.9 s | 4,119.7 blk/s | 212.6 s | 58.3 s | 899.0 s (824.1 + 74.9) | 209.2 s | 70.9 s | 127.9 s | 96.2 s | 2,465 MiB | 99.4 MB/s |
| r1s-R1-2 | 18:48 | R1 | defaults | 266.3 s | 4,190.9 blk/s | 210.5 s | 55.8 s | 899.9 s (822.2 + 77.7) | 205.9 s | 70.7 s | 128.0 s | 99.2 s | 2,467 MiB | 100.6 MB/s |
| r1s-R1-3 | 18:59 | R1 | defaults | 265.5 s | 4,203.5 blk/s | 209.2 s | 56.3 s | 901.0 s (824.3 + 76.7) | 206.6 s | 71.2 s | 128.1 s | 98.2 s | 2,470 MiB | 101.7 MB/s |
| r1s-H-3 | 19:10 | `797a213` | defaults | 273.2 s | 4,085.0 blk/s | 211.6 s | 61.6 s | 900.8 s (827.5 + 73.3) | 210.9 s | 71.2 s | 128.6 s | 93.7 s | 2,473 MiB | 101.5 MB/s |
| r1s-R1-4 | 19:21 | R1 | defaults | 264.9 s | 4,213.0 blk/s | 205.3 s | 59.6 s | 899.2 s (823.8 + 75.4) | 205.6 s | 70.7 s | 128.5 s | 96.9 s | 2,460 MiB | 101.1 MB/s |
| r1s-H-4 | 19:31 | `797a213` | defaults | 269.8 s | 4,136.5 blk/s | 212.4 s | 57.4 s | 903.6 s (827.4 + 76.2) | 210.7 s | 71.2 s | 128.4 s | 96.4 s | 2,500 MiB | 97.9 MB/s |
| ra16pv10-1 | 19:51 | diagnostic | depth 16, `DCROXIDE_PREVERIFY=10` | 258.1 s | 4,324.0 blk/s | 210.5 s | 47.6 s | 924.6 s (852.0 + 72.6) | 204.5 s | 72.3 s | 131.8 s | 95.0 s | 2,460 MiB | 99.4 MB/s |
| ra16-3 | 20:02 | diagnostic | depth 16 | 264.8 s | 4,214.6 blk/s | 210.1 s | 54.7 s | 895.4 s (821.5 + 73.9) | 207.8 s | 71.1 s | 129.4 s | 95.4 s | 2,469 MiB | 100.5 MB/s |
| ra16pv10-2 | 20:12 | diagnostic | depth 16, `DCROXIDE_PREVERIFY=10` | 259.6 s | 4,299.1 blk/s | 210.9 s | 48.7 s | 924.4 s (851.4 + 73.0) | 202.7 s | 72.2 s | 131.6 s | 96.2 s | 2,470 MiB | 98.8 MB/s |

The `dbcommit` column is the thread kept for the life of the store, by
the same count as the other threads.

**Where the block thread waits (m1k).** m1k-H-1 at the defaults at 16:30
and m1k-H-noindex-1 with the index off at 16:41 ran under the sampler of
"Where the block thread waits beside a background commit" above, at
200 Hz, on four cores of its own, changed for a commit thread that lives
as long as the store. It reads, as before, the scheduler state of the
block thread and the index thread and, for a thread not running, the
kernel function it waits in, and now reads them for the `dbcommit`
thread too. It counts a commit as under way when that thread is anything
but asleep on a futex (`futex_wait`), where it waits for the next flush,
and no longer when a `dbcommit` thread exists, which since `0ffe161` it
does from the first flush handed over to the close. A commit's own waits
for a lock look the same as that idle wait and count as no commit. Since
`c94cd26` the thread also writes each flush's rows and the index's
contribution, so a commit under way now spans those as well as the
commit and the retirement. By the flush log the 52 flushes inside the
clock of m1k-H-1, every one handed over, spent 115.0 s on that thread
from the hand-off to the retirement; the sampler counted a commit under
way for 123.0 s, 45.4% of its 270.7 s, a difference not taken apart. The
sampler used 6.6 s and 4.9 s of processor time, and the two walls,
271.0 s and 254.8 s, are not set beside the other runs as timings.

| block thread | m1k-H-1, no commit under way (147.7 s) | m1k-H-1, a commit under way (123.0 s) | m1k-H-noindex-1, no commit under way (181.8 s) | m1k-H-noindex-1, a commit under way (72.8 s) |
|---|---:|---:|---:|---:|
| running or runnable | 124.4 s (84.2%) | 90.9 s (73.9%) | 159.3 s (87.6%) | 58.7 s (80.6%) |
| uninterruptible, a page under writeback or locked (`folio_wait_bit_common`) | 4.4 s | 8.9 s | 4.4 s | 3.3 s |
| uninterruptible, a write's space reservation (`reserve_bytes`) | 0.0 s | 11.9 s | 0.0 s | 5.4 s |
| uninterruptible, the ordered extents over a range written (`btrfs_start_ordered_extent_nowriteback`) | 5.8 s | 4.1 s | 8.5 s | 3.0 s |
| uninterruptible, elsewhere | 0.2 s | 0.5 s | 0.3 s | 0.3 s |
| asleep on a futex | 10.1 s | 5.2 s | 6.7 s | 1.5 s |
| asleep elsewhere | 2.8 s | 1.6 s | 2.6 s | 0.7 s |

- **The waits are the filesystem's, as on 2026-10-17.** At the defaults
  the block thread was uninterruptible for 35.8 s, 25.4 s of it while a
  commit was under way, nearly all of it in the same three functions of
  btrfs's buffered-write paths, and `reserve_bytes` only while a commit
  was under way. It was asleep on a futex for 15.3 s, and on a processor
  for 210.1 s by its counters. On 2026-10-17, from the loopback server
  reading its drive, the block thread of `88c46c3` was uninterruptible
  for 56.4 s, 38.4 s of it while a commit was under way by that
  sampler's test.
- **With the index off** a commit was under way for 72.8 s of 254.6 s,
  and the block thread was uninterruptible for 25.1 s, 11.9 s of it
  then, against 35.8 s with the index on, and asleep on a futex for
  8.2 s, against 15.3 s.
- **The commit thread.** While a commit was under way at the defaults,
  `dbcommit` was running or runnable for 98.6 s and uninterruptible for
  23.9 s: in `reserve_bytes` 13.9 s, `btrfs_btree_wait_writeback_range`
  3.8 s, `wait_for_commit` 2.7 s, `folio_wait_bit_common` 2.3 s and
  elsewhere 1.3 s. Its counters give it 97.0 s on a processor.
- **Which file is by elimination, again.** The sampler still cannot read
  which system call a wait is in. In `797a213` the flushes' row inserts
  and commits run on `dbcommit`; their block-file syncs, 2.7 s in all
  with 2.3 s of it off a processor, run on whichever thread captured the
  flush, the block thread or the index thread; the index thread was
  uninterruptible for 0.2 s in all; and the node logged 55 lines inside
  the clock. What is left on the block thread is its write of each
  block's record into the current block file, as on 2026-10-17. That is
  inferred, not observed. R1 moves the syncs to `dbcommit` (below); no
  change to the writes themselves was built or measured.

**The read-ahead's depth and the index buffer (ra).** The first queue
ran the diagnostic build at depth 4, 16 and 32, and at depth 4 with a
buffer of 512 notifications, two runs each, in the order 4, 16, 32,
buffer 512, 32, 16, 4, buffer 512. Pooled over those eight runs
(4 degrees of freedom, a standard deviation of 1.74 s), a step between
two runs and two is good to about ±4.8 s. The lines the node logs at
shutdown:

| run | setting | most frames queued | block thread waited for the reader | reader waited for the block thread | index queue full | inputs checked ahead | blocks cut short | helpers |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| ra4-1 | depth 4 | 4 | 3.60 s | 137.8 s | 3.69 s | 4,813,117 of 9,316,214 (51.7%) | 23,255 of 91,074 (25.5%) | 6 |
| ra16-1 | depth 16 | 16 | 0.45 s | 126.8 s | 3.76 s | 6,134,021 of 9,267,088 (66.2%) | 19,453 of 90,556 (21.5%) | 6 |
| ra32-1 | depth 32 | 32 | 0.30 s | 129.9 s | 3.79 s | 6,234,158 of 9,219,821 (67.6%) | 18,458 of 90,067 (20.5%) | 6 |
| ra4b512-1 | depth 4, buffer 512 | 4 | 3.72 s | 136.7 s | 2.24 s | 4,821,544 of 9,313,338 (51.8%) | 23,313 of 91,046 (25.6%) | 6 |
| ra32-2 | depth 32 | 32 | 0.32 s | 127.0 s | 3.79 s | 6,174,640 of 9,203,081 (67.1%) | 18,688 of 89,909 (20.8%) | 6 |
| ra16-2 | depth 16 | 16 | 0.51 s | 125.1 s | 3.74 s | 6,078,200 of 9,278,226 (65.5%) | 19,771 of 90,676 (21.8%) | 6 |
| ra4-2 | depth 4 | 4 | 3.62 s | 137.1 s | 3.73 s | 4,865,057 of 9,313,338 (52.2%) | 23,073 of 91,046 (25.3%) | 6 |
| ra4b512-2 | depth 4, buffer 512 | 4 | 3.64 s | 134.1 s | 2.29 s | 4,747,419 of 9,182,711 (51.7%) | 22,900 of 89,700 (25.5%) | 6 |
| ra16pv10-1 | depth 16, `DCROXIDE_PREVERIFY=10` | 16 | 0.46 s | 119.0 s | 3.73 s | 8,310,053 of 9,209,970 (90.2%) | 6,097 of 89,966 (6.8%) | 10 |
| ra16-3 | depth 16 | 16 | 0.46 s | 127.9 s | 3.69 s | 6,167,540 of 9,313,603 (66.2%) | 19,519 of 91,047 (21.4%) | 6 |
| ra16pv10-2 | depth 16, `DCROXIDE_PREVERIFY=10` | 16 | 0.48 s | 120.4 s | 3.71 s | 8,233,201 of 9,222,517 (89.3%) | 6,837 of 90,095 (7.6%) | 10 |

- **Depth 16: 263.4 s and 263.4 s against 273.3 s and 272.9 s at
  depth 4, 9.70 s or 3.6% less**, 4.2 s of it before the assume-valid
  block and 5.5 s after. ra16-3, a third run at depth 16 in the third
  queue, took 264.8 s. The block thread waited for the reader 0.45 s and
  0.51 s in all, against 3.60 s and 3.62 s, and the pre-verifier checked
  66.2% and 65.5% of the inputs it guessed for ahead of the block
  thread, against 51.7% and 52.2%. The block thread's time on a
  processor fell 3.78 s by the means, that of the script pool's 15
  threads 10.00 s, and node CPU time 14.15 s.
- **Depth 32: 267.2 s and 263.5 s, 7.75 s less than depth 4 and 1.95 s
  more than depth 16**, which the ±4.8 s does not resolve, with 67.6%
  and 67.1% of the inputs checked ahead and 0.30 s and 0.32 s of waiting
  for the reader. Each setting queued at most its depth, by the
  read-ahead's line.
- **The buffer at 512, at depth 4: 273.3 s and 270.1 s, 1.40 s less than
  depth 4**, which is not resolved. The index queue was full for 2.24 s
  and 2.29 s in all, against 3.69 s and 3.73 s.
- **Memory.** Peak RSS, read when the clock stopped, was 2,451 and
  2,460 MiB at depth 4, 2,466 to 2,471 MiB at depth 16, 2,481 and
  2,467 MiB at depth 32 and 2,486 and 2,493 MiB with the buffer at 512.
  No run filled the queue with the largest blocks, so what the depth's
  bound costs in memory is not measured.

**More helpers at depth 16 (ra16pv10).** At depth 16 the pre-verifier
still checked only about two thirds of its inputs ahead, so the third
queue ran depth 16 with `DCROXIDE_PREVERIFY=10`, at most ten helpers
where the default on the node's eight cores is six, two fewer than the
cores. **258.1 s and 259.6 s, a mean of 258.85 s, against 263.87 s for
the three runs at depth 16 alone, 5.02 s less**: pooled over those five
runs (3 degrees of freedom, a standard deviation of 0.90 s), about
±2.6 s, though two of the five ran in the first queue; against ra16-3
alone, which the two bracket, 5.95 s less. They took 6.2 s less after
the assume-valid block and 1.2 s more before it. The pre-verifier
checked 90.2% and 89.3% of its inputs ahead, against 65.5% to 66.2%, and
6.8% and 7.6% of its blocks were cut short by the block thread or the
shutdown, against 21.4% to 21.8%; node CPU time rose 29.83 s by the
means and the script pool's threads' time 30.64 s, at 3.58 and
3.56 mean cores. Which hardware threads the ten helpers ran on is not
recorded.

**R1 against `797a213` (r1s).** The runs alternated `797a213`, R1,
`797a213`, R1, R1, `797a213`, R1, `797a213`. **R1 took 263.1 s, 266.3 s,
265.5 s and 264.9 s, a mean of 264.95 s, against 273.1 s, 270.9 s,
273.2 s and 269.8 s, a mean of 271.75 s: 6.80 s or 2.5% less**, beyond
the session's 95% interval for a step between four runs and four, about
±2.6 s (6 degrees of freedom, a standard deviation of 1.53 s), and less
in each of the 16 pairings, by 3.5 to 10.1 s. 4.1 s of it came before
the assume-valid block and 2.7 s after.

- **The threads.** The block thread was on a processor for 205.2 to
  206.6 s against 209.2 to 210.9 s, 4.45 s less by the means, and node
  CPU time was 895.9 to 901.0 s against 899.0 to 905.8 s. `dbcommit`,
  which now also syncs the block files, was on a processor for 94.6 to
  99.2 s against 93.7 to 96.4 s, the index thread for 70.7 to 71.2 s
  against 70.9 to 71.2 s, and the reader for 128.0 to 128.5 s against
  127.9 to 128.6 s.
- **The flushes.** Each run made 52 flushes inside the clock, every one
  handed over. Their foreground time was 0.016 to 0.030 s in a run of
  R1, against 2.38 to 2.69 s for `797a213`, and R1's block-file syncs,
  timed on `dbcommit`, took 2.59 to 2.98 s in a run.
- **The rest.** The block thread waited for the reader 3.91 to 4.02 s in
  all, against 3.61 to 3.66 s; the pre-verifier checked 50.9% to 51.2%
  of its inputs ahead, against 51.4% to 51.8%; and peak RSS was 2,460 to
  2,470 MiB, against 2,465 to 2,500 MiB.

**R1's end state (v20).** One sync of R1 from the loopback dcrd v2.1.6
server at the defaults at 19:43, for the end state that the LAN runs do
not record. It ended on the server's tip, `8752fdc9…`, and
`gettxoutsetinfo` reported the UTXO set of every full sync from the
loopback server since 2026-10-17: 760,741 transactions, 1,850,903
outputs, a total amount of 1,672,716,060,550,750 atoms and the
serialized hash
`eb7f88de7b69f98676ce78072c0f90cc2667b875df0b26637dffcf9da5b3c30c`. The
block files hashed to `33b7ac837a45c74f` over 36 files and
19,202,596,910 B. The exists-address index and the rest of the metadata
store, the block filters R1 builds another way among them, were not
compared. Its wall, 274.5 s, is not a timing; it peaked at 2,481 MiB.

**What was not measured.**

- The trees of the seven commits that follow, and each of R1's four
  changes on its own.
- R1's changes with the depth at sixteen, which the seventh of those
  commits holds: the depth was run only in the diagnostic build, on
  `797a213`'s code, so whether its gain adds to R1's is not known. Ten
  helpers at any depth but 16, or with R1's changes.
- Depths other than 4, 16 and 32, a bound of the read-ahead in bytes,
  buffers other than 128 and 512 notifications, and helper counts other
  than six and ten.
- The memory at the depth's bound, with the queue full of the largest
  blocks, and how many of the entries pre-verified into the signature
  cache were evicted before their block was connected.
- The system call of each wait the sampler saw; the sampler on R1 or the
  diagnostic build; any change to the block-file writes.
- Any end state in the LAN runs; the exists-address index, the block
  filters and the rest of the metadata store in R1's loopback check.
- The memory after the clock.
- A sync whose sync peer changes; the LAN server's load, cache and
  configuration, the link's speed, and the round trip, in any run
  record; a link with a longer round trip.
- `DCROXIDE_READ_AHEAD=off`, the flush log's own cost, on in every run,
  and the sampler's.
- Storage other than m3's NVMe drive under btrfs; Windows and macOS.

Raw: `wchan-k.jsonl`'s `m1k-H-1` and `m1k-H-noindex-1`, with their
wait-channel counts; `arms.jsonl`'s `ra4-1`, `ra16-1`, `ra32-1`,
`ra4b512-1`, `ra32-2`, `ra16-2`, `ra4-2`, `ra4b512-2`, `ra16pv10-1`,
`ra16-3` and `ra16pv10-2`; the comparison's `runs-lan.jsonl` rows
labelled `r1s-H-1`, `r1s-R1-1`, `r1s-H-2`, `r1s-R1-2`, `r1s-R1-3`,
`r1s-H-3`, `r1s-R1-4` and `r1s-H-4`; `verify.jsonl`'s `v20-R1-loopback`;
per-run samples, flush logs and node logs; the queues' steps and logs;
the sampler and its change; and the code states and build notes of the
three builds.
