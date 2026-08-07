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

## Preserved baselines

The datadir every figure above was read from, kept because opening a redb
database is not a read-only act (quick-repair on open, and `Database::open`
rolls the block files back when the metadata trails them). Probes open a
fresh reflink clone of the snapshot; neither the original nor the snapshot
is opened directly.

| date | machine | what | path | notes |
|---|---|---|---|---|
| 2026-08-07 | m1 | mainnet datadir behind the 2026-07 sync and storage rows | `artifacts/dcroxide-bench/m1/baseline-2026-07-25/blocks_ffldb/` | reflink clone of `artifacts/p2p-sync/data/mainnet/blocks_ffldb/`, written 2026-07-25; 31 GiB apparent, no additional space on btrfs, 22 s. `metadata.redb` is 15,551,119,360 B, the 14.483 GiB the ADR decomposes. |

## Replay throughput (dcroxide-bench)

Identical-corpus replays via `dcroxide-bench export` / `replay`
(crates/dcroxide-bench). No rows yet — the first storage-rework
milestone starts this table, measured against the corpus the 2026-07
campaign exported.

| date | machine | dcroxide commit | corpus | result | raw run |
|---|---|---|---|---|---|
