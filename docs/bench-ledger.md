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
> Performance section reports this comparison instead.

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
