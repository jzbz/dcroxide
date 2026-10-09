# Operating dcroxide

Read [SECURITY.md](../SECURITY.md) first. **This node is pre-alpha: do
not expose it to the internet and do not use it with funds.** Use
[dcrd](https://github.com/decred/dcrd) for anything that matters. What
follows is for people running it deliberately anyway — on a private
network, against testnet or simnet, or to reproduce a measurement.

The operator-facing requirements are collected here because two of them
are traps: the node **must** run under a supervisor, and it **cannot**
adopt a dcrd data directory.

## A supervisor is required, not recommended

Release builds set `panic = "abort"`. A panic terminates the process
instead of unwinding, so **any reachable panic is an outage until
something restarts the node**. This is deliberate — Rust mutexes poison
on panic where Go's do not, so a panic that unwound would leave the
daemon wedged behind poisoned locks while the RPC layer kept answering
canned errors and looking healthy. Aborting is loud instead of silent,
and loud is what a consensus daemon wants. The full reasoning is in
`[profile.release]` in the workspace `Cargo.toml`, and a test fails if
the setting is dropped.

The consequence is an operational requirement: run it under something
that restarts it. A systemd unit needs at least

```ini
Restart=on-failure
RestartSec=5s
```

Anything equivalent works — a supervisor, a container restart policy,
runit. A node run by hand from a shell will simply stop on the first
panic.

A storage failure now stops the node rather than being retried. If a
durable write to the metadata store fails — a full disk, an I/O error — the
store refuses every later write, so the node makes no further progress until
it is restarted. Reads keep working, so RPC still answers. This trades
availability for integrity deliberately: the alternative is retrying a write
whose failure may have left the store in a state that a restart silently
rolls back, which is worse for a consensus daemon than stopping. Two things
follow for an operator. A node that has stopped making progress with
`ErrFatal` in its log has a storage problem, not a network one. And **a
non-zero exit with `Unable to flush the block database` in the log means
the shutdown flush failed.** The on-disk chain state is the last flush that
completed: an older, consistent state that the next start replays forward
from, so no chain data is lost. What failed is the storage, so investigate
it before restarting rather than restarting into the same fault. (The
`Flushing the block database to disk...` line is gone; dcrd logs nothing at
INF there. The shutdown now reads `Server shutting down`, `Server shutdown
complete`, `Gracefully shutting down the block database...`, `Shutdown
complete`.)

Pair it with a memory limit. A websocket client that subscribes and then
stops reading grows node memory without bound; the notification queues
are unbounded exactly as dcrd's are, so nothing is dropped or reordered
and the whole cost is paid in memory. That is not reachable without RPC
credentials, but a `MemoryMax=` (or the container equivalent) plus the
restart policy above bounds the damage from a subscriber you do not
control.

After an unclean stop (abort, SIGKILL, OOM kill, power loss), the next start
repairs the metadata store before the chain loads. It logs this under BCDB
as "Detected unclean shutdown of the metadata store - Repairing..." followed
by "Metadata store repair N% complete" lines. The repair reads the whole
metadata file up to three times, so on a mainnet-sized store expect a
noticeably slower start (not yet measured). A clean shutdown does not need
it: the node closes its database at exit.

The chain then replays the blocks the UTXO set had not yet flushed. As in
dcrd, that replay runs between the CHAN lines "UTXO cache initializing (max
size: N MiB)..." and "UTXO cache initialization completed", at the
configured `--utxocachemaxsize`. A start that sits between those two lines
is catching up, not hung.

The enabled indexes then catch up to the chain tip, as in dcrd, between the
INDX lines "Catching up from height X to Y" and "Caught up to height Y",
with an "Indexed N blocks in the last ..." line every ten seconds, so a
long catch-up shows its progress. `--droptxindex` and
`--dropexistsaddrindex` log "Dropping all <index> entries.  This might take
a while...", then "Deleted N keys (M total) from <index>" after each batch
of up to 2,000,000 deletions, then "Dropped <index>". When the index is not
there they log "Not dropping <index> because it does not exist" instead.
For the exists-address index those counts are rows of its own layout
(below), modelled at 0.4-0.5 million on mainnet, not the tens of
millions of addresses they hold, so a full drop is one batch.

## Fresh sync only — a dcrd data directory will not work

dcroxide does not read dcrd's on-disk format. There is no migration from
an existing dcrd data directory, and pointing it at one is not a
supported configuration. It is refused rather than adopted. A block
directory (`blocks_ffldb`, dcrd's name) that holds dcrd's `metadata/` store
stops the node at startup with "database already exists at the provided
path: <block directory>/metadata is a dcrd metadata store, and dcroxide
cannot use a dcrd data directory -- give it a data directory of its own
(see docs/operating.md)", pointing here, before any of dcrd's block files
are touched. Block files left with no metadata store at all are rolled back
on the first start, as dcrd itself would: every file after the first is
deleted and the first is truncated. Syncing from genesis is the accepted
default (ADR-0004's C6 stance); `addblock`-format import is the bulk path
when you already have the blocks.

The same holds when dcroxide's own on-disk format changes. There is no
in-place upgrade. An old directory is *refused*, not misread — the node
stops with a message naming the format it found and telling you to sync
again, and it says the chain is not damaged, because "this predates the
upgrade" and "your disk is failing" want opposite reactions from you.

No release has shipped, so no released directory is in that position, but
one written by a development build from before 2026-10-08 is: the chain
database moved from version 14 to version 15, which keys the per-block
rows by height ([ADR-0010](adr/0010-height-first-block-keys.md)). Started
on such a directory, the node exits with status 1 and leaves every row of
the database as it found it (opening and closing the database file can
still rewrite the file itself), and logs (here for mainnet on Linux, with
the home directory shortened to `~`):

```text
[ERR] DCRD: Unable to start server: the blockchain database in '~/.dcroxide/data/mainnet/blocks_ffldb' is version 14, which an older dcroxide wrote, and this version of the software reads only version 15 -- there is no in-place upgrade, and the chain is not damaged: delete '~/.dcroxide/data/mainnet/blocks_ffldb' and start again to build a new one from genesis (see docs/operating.md)
```

`addblock` stops the same way, with `[ERR] MAIN: Failed create block
importer:` in front of the same text. To recover:

1. Stop everything using that directory: the node, its supervisor's
   restart loop, and any `addblock` run.
2. Delete the directory the message names, and only that one. It is the
   block database, `blocks_ffldb` under the network's data directory
   (`--datadir` plus the network name; see the identity table below), and
   it holds the chain and the transaction and exists-address indexes.
   Everything else keeps working and should stay: `dcroxide.conf`,
   `rpc.cert` and `rpc.key` in the home directory, and the other networks'
   directories beside this one.
3. Start the node again. It creates a new database and syncs from genesis,
   rebuilding the indexes you have enabled, so budget the time an initial
   sync takes (below). If you already have the blocks in `addblock`'s
   bootstrap format, importing them with `addblock` is the faster path.

The other direction is refused too. A build from before the change,
started on a directory a current build wrote, stops with "the current
blockchain database is no longer compatible with this version of the
software (15 > 14)". Run a current build on it, or give the old build a
directory of its own. Every start that opens the chain logs its version
under CHAN, "Blockchain database version info: chain: 15, ...", where
dcrd prints "chain: 14": the one place the number shows, and the
difference is expected.

Budget for it: in every sync from genesis measured so far, initial block
download ran slower than dcrd's, by a factor that depends heavily on the
storage underneath. On machine m1 in
[bench-ledger.md](bench-ledger.md), with a single NVMe drive, it ran
about **1.29x slower than dcrd** — roughly 1.15 hours against dcrd's 0.9
for mainnet from genesis — and the chain cost more on disk, 33.58 GiB
against dcrd's 23.69 GiB at the same tip. Both were measured 2026-08-15
under redb 4.1.0, before the 2026-10-08 height-first keys, with both
daemons syncing from one shared dcrd server and the index composition
verified on each side. They replace 2026-07 figures of 2.2x and 32.06 GiB
against 23.73, taken under redb 2.6.3 with the two nodes syncing from
each other on one machine — a setup that inflated both arms.

On slower storage the gap is wider. On m2, a ZFS mirror of QLC NVMe
drives, dcrd synced from genesis to block 916,000 **2.45x** as fast as
dcroxide did before the height-first keys and **1.40x** as fast as it
does with them (one run each; bench-ledger.md, "Height-first per-block
keys"). The keys left the data directory's size unchanged there, and
they have not been measured on m1. The exists-address index's own
layout (2026-10-09, below) then took the 200,000-block tail after block
916,000 on m2 from a median of 94 to 482 blocks/s with the index on.
dcrd ran that tail there at 146-148 blocks/s, but on 2026-10-07, in
another session, so read the two together as context, not as a ratio.
No sync from genesis, on either machine, has been measured with the new
layout, so every from-genesis figure here predates it.

Treat 1.29x as a rough figure for fast local storage rather than a
precise ratio, and not as a bound: on m1 the two arms ran about 12 hours
apart under different background load, once each, and m2 measured gaps
well above it. What is not in doubt is the direction — the port has
roughly halved its distance to dcrd on m1 since 2026-07 — and that it
does the work at less CPU than dcrd: 0.76 cores against 1.50 on m1. If
your host is busy with other work, or its storage is slower than m1's,
expect the sync to stretch more than dcrd's would.
All of these come from syncing over loopback from a local dcrd server,
and none has been measured over the internet. There, both daemons request
blocks the same way: through dcrd's window of at most 16 blocks in flight,
refilled once fewer than 10 remain, from the sync peer only. By that window
arithmetic (a prediction, not a measurement), once the round trip to the
sync peer exceeds about nine blocks' processing time, roughly 34 ms for
dcroxide and 26 ms for dcrd on m1, the sync should wait on the network
at about 9-16 blocks per round trip, and the gap between the two should
narrow toward 1x as latency grows. Budget from your link's
latency as well as from these figures; the missing WAN measurement is
recorded in [bench-ledger.md](bench-ledger.md).
See [ADR-0004](adr/0004-storage-backend.md).

The two have different explanations, and only one of them is settled. The
**disk** difference is the storage engine and nothing else: as of
2026-08-11 both nodes have been measured to store the same payload for the
same chain at the same index composition — fifteen buckets equal to the
byte — so the extra space is how redb lays those bytes out, not extra data
dcroxide keeps. (The 2026-10-08 key change adds four bytes to the keys of
five per-block buckets, at most about 22 MB at the tip.) Block files match
to within a mebibyte. The **time**
difference is commit shape, and as of 2026-08-15 that is measured rather
than attributed: the node is fully stalled on storage — nothing runnable at
all — for **48% of block-sync wall time**, against dcrd's 0.9%. A
2026-08-16 run with the flush observer enabled puts **90–98% of that inside
a metadata-flush window**, so it is the metadata flush specifically rather
than storage in general. The flush window holds three phases: the
block-file fsync, the insert loop, which reads leaves redb has not cached,
and the redb commit. The flush log records each phase's time and the bytes
the flushing thread read in it, which separates read waits from writeback
waits. No mainnet run has been recorded with that split yet, so which phase
stalls is still open. (An earlier figure of 34.6% for the same runs was
count-weighted; the sampler is starved during the stalls it measures, and
weighting by represented time raises it to 48–51%.) How much of it is
*recoverable* was settled on 2026-08-16: moving the metadata commit off
the block-connection thread was built, measured at 9.5% slower (232.1 to
210.0 blk/s, with the stalled share rising from 48.1% to 53.7%), and
reverted. The stall is real and it is the flush, but it is not
recoverable by rescheduling *when* the commit runs — the remaining lever
is what a flush costs. The earlier 18% figure came from a replay, which
validates every block where a syncing daemon skips ~93% under assume-valid,
so it understated the daemon's share.

## The exists-address index: turn it off if no wallet needs it

The exists-address index is on by default, as in dcrd. In dcrd's layout
it was the largest single cost of an initial sync; in the port's own
layout, below, it costs far less. It is a set of every address ever
seen in a block or the mempool, and it serves exactly two RPCs,
`existsaddress` and `existsaddresses`. Wallets that sync over RPC use them
for address discovery, for example to find which addresses a wallet
restored from its seed has used. SPV wallets do not: they work from the
compact block filters.

If no wallet syncs against this node over RPC, start it with
`--noexistsaddrindex`. In dcrd's layout the saving was large: on m2 in
[bench-ledger.md](bench-ledger.md), with the index off, the node synced
the 200,000 blocks from 916,000 to 1,116,035 **3.4x faster**, a median of
262 blocks/s across two runs against 78, writing 21.8 GB instead of
151.6 GB. That was measured before the 2026-10-08 height-first keys. In
the current layout it is much smaller (below): on the same tail, with
those keys, the node ran at a median of 482 blocks/s with the index on
and 501 with it off, and wrote 15.5 GB against 12.6 GB. With the index
off, both RPCs fail with "exists address index disabled", as dcrd's do.

### How the index is stored, and what it costs

dcrd stores one row per address. On redb that made every new address
dirty its own page of a 66-million-row table, which is the cost the 3.4x
above measured. The index is now stored in its own layout (index version
3, [ADR-0011](adr/0011-exists-address-layout-3-and-the-flush-participant.md)):
the addresses of recent blocks in memory, and the rest in sorted runs of
4 KiB chunks, written inside the metadata flushes that already carry the
chain's rows, with a journal so a restart can rebuild the memory. It gives
dcrd's answers with two exceptions, both in
[PARITY.md](../PARITY.md): a storage read error answers "Could not query
address: ..." instead of "never seen", and an address seen only in the
mempool no longer answers "never seen" while its block is being indexed.
On m2 ([bench-ledger.md](bench-ledger.md), "Exists-address index layout
3"; six runs with the index on in each layout and three with it off,
interleaved, all with the height-first keys), the same 200,000-block
tail synced at a median of 482 blocks/s with the index on, against 94 in
dcrd's layout and 501 with the index off. The last gap is within that
storage's run-to-run noise. What the index measurably adds is in the
counts, which barely move from run to run. It wrote 15.5 GB against
12.6 GB with the index off (and 137.4 GB in dcrd's layout), and used 9%
more CPU time. It made the same 31 metadata flushes, where dcrd's layout
made 58-59.

- **Memory**: the index's in-memory set holds up to about 3 million
  addresses (about 63 MB) after each flush while syncing, and up to about
  4 million (84 MB) just before one; a catch-up from genesis peaked at
  4.5 million (95 MB). It also takes in, at each block, every address the
  mempool has seen since the last block, so a very large mempool adds to
  that. The index's pages also fill the metadata page cache
  (`DCROXIDE_DB_CACHE`, below) up to its configured size. On m2's tail,
  at the default 1 GiB cache, the node's peak resident memory was about
  350 MiB above the index-off run's (2,773 against 2,424 MiB). On a
  development desktop it was about 380 MB above at that cache, and about
  140 MB above with a 256 MiB cache.
- **Starting**: the node reads the journal back into memory before the
  index catches up, modelled at 1-3 s on mainnet, holding one copy of the
  addresses it reads back, and the journal's pages in the page cache.
  The read logs no line of its own. On a development desktop, a restart
  after a kill near block 1,000,000 reloaded about 2.1 million addresses,
  and the index's startup, from "Exists address index is enabled" to its
  "Catching up" line, took 0.33 s. A damaged meta or journal row stops
  startup with an error naming the remedy below; the index never opens
  empty.
- **A damaged run row is found later.** Startup does not read the runs,
  so the first lookup or flush that reads the row finds it. A lookup
  answers "Could not query address: ..." with the remedy, and lookups of
  other addresses still answer. The first flush that merges the row's
  part of the index fails and stops the metadata store taking writes, so
  the node commits no further blocks; that flush's error, and every
  write refused after it, name the exists address index and the remedy.
  Stop the node and apply the remedy below.
- **Lookups**: an address not seen recently reads up to two 4 KiB pages
  where it read one, so a large `existsaddresses` costs about twice the
  I/O.

**A data directory whose index was built before this layout is refused**,
when the index is on, with:

```text
[ERR] DCRD: Unable to start the indexes: exists address index: on-disk version 2 is not supported by this build; run once with --noexistsaddrindex --dropexistsaddrindex, then restart to rebuild it from genesis
```

Nothing is changed. Start once with `--noexistsaddrindex
--dropexistsaddrindex`, which drops the old index and exits, then start
normally: the index is rebuilt from genesis during startup, between the
"Catching up" and "Caught up" lines, before the node serves. Or run with
`--noexistsaddrindex` and leave the old rows idle.

**Do not run a build from before this layout with the index on over an
index built in it.** The older build has no check for it: it neither
refuses the index nor reads it. While it runs it answers "never seen" for
every address the new layout holds, and it adds rows of its own layout
and moves the index tip past their blocks. The next start of this build
finds those rows and refuses, with the same remedy, rather than open
without them. Before going back to an older build, drop the index with
`--noexistsaddrindex --dropexistsaddrindex`, or run the older build with
`--noexistsaddrindex`.

The choice is not permanent, but changing it costs time:

- **Turning it off on a node that already has it** leaves the index's data
  on disk. To delete it, start once with `--noexistsaddrindex
  --dropexistsaddrindex`: the node drops the index and exits, with the
  "Dropping all ..." and "Dropped ..." lines described earlier in this
  guide. `--dropexistsaddrindex` on its own is refused, as in dcrd. Then
  run with `--noexistsaddrindex`.
- **Turning it back on later** catches the index up from where it
  stopped, or builds it from genesis if it was dropped. The node catches
  the index up to the chain tip during startup, before it serves, with the
  "Catching up from height X to Y" progress lines described earlier. On
  m2 a rebuild from genesis to block 916,046, with no blocks arriving,
  took 157 s on four cores, wrote 3.1 GB and peaked at about 1.7 GiB
  resident.

## Storage tuning: two knobs help, one hurts, one is untested

Four settings change how the metadata store behaves. Three are measured and
one is not; the numbers are in [bench-ledger.md](bench-ledger.md) and the
reasoning in [ADR-0004](adr/0004-storage-backend.md).

The two that help are the two flush triggers, and they are worth understanding
together: a durable metadata commit is forced when **either** the UTXO cache
fills or the metadata overlay fills. Each ceiling governs one of them, raising
either reduces how often the node commits, and each measured ~12% on its own.

**`--utxocachemaxsize` (default 150 MiB) is one of the two.**
Connecting a block flushes the UTXO cache when it fills, and that flush
forces a durable metadata commit — so the ceiling governs how often the node
commits. Raising it on its own measured **12% faster** over a full chain at
1200 MiB, and 7% at 600 MiB, across three repetitions each with ranges that
do not overlap the baseline's. dcrd has the same flag and the same 150 MiB
default; the ceiling here is 32 GiB.

One caveat before you turn it up: a larger cache means more work redone
after an unclean stop. Nothing is corrupted — the flush ordering holds —
but more of the recent window has to be replayed, so pair a large value with
the supervisor above rather than treating it as free.

**`DCROXIDE_DB_CACHE` is the one to leave alone.** It sets redb's page cache
in MiB, defaulting to 1024. Raising it to 8192 made a full-chain replay
**50% slower** — 5125-6294 s against the same 3866-3888 s baseline, again
with non-overlapping ranges. That is the opposite of what the setting
suggests, and the opposite of what a 500,000-key microbenchmark predicted
when the knob was added. There is no fixed split to reason from: redb 4.3.0
keeps a single cache figure and partitions it on demand, holding the write
buffer at or below half of it, best effort, and letting the read cache grow
into all of it. The advice rests on the full-chain measurement, not on a
mechanism.

Lowering it does not help either: 256 MiB and 512 MiB both measured
indistinguishable from the 1024 MiB default, with ranges overlapping it.
The default is the right value — the only thing that matters is not raising
it, so leave the variable unset.

**`DCROXIDE_DB_OVERLAY` and `DCROXIDE_DB_FLUSH_SECS` reach the other flush
trigger.** Connecting a block forces a durable commit when *either* the UTXO
cache fills or the metadata overlay does — and until now only the first was
reachable. The overlay has its own ceiling, 100 MiB, and its own interval,
300 seconds; both were fixed at compile time, so half the cadence lever could
not be pulled. `DCROXIDE_DB_OVERLAY` sets the ceiling in MiB and
`DCROXIDE_DB_FLUSH_SECS` the interval in seconds. The ceiling counts each
overlay entry as dcrd does, at 72 bytes plus its key and value, so the
configured MiB tracks the overlay's resident memory to within allocator
overhead. Before 2026-09-23 entries were counted at key and value bytes
only, which let the overlay hold 2–4× the configured figure. The 12.7%
measurement for `DCROXIDE_DB_OVERLAY=800` below was taken under that older
accounting, so the same setting now flushes a smaller overlay. Re-measure
before relying on the figure or on the 130→119 flush count. Unset, both
keep the compiled defaults, so an untouched node behaves exactly as before.

**`DCROXIDE_DB_OVERLAY=800` measured 12.7% faster**, which makes it the
second knob worth raising. Four alternating full-mainnet syncs, 256.1 and
272.7 blk/s at the default against 288.4 and 307.5 at 800 MiB — ranges
disjoint, and both adjacent pairs agreeing to 0.2 points. The mechanism is
visible in the flush count, which drops 130 to 119.

Why it works: the node is *fully stalled* — nothing runnable at all — for
**48% of block-sync wall time**, and **90–98% of that is inside a
metadata-flush window**. Flushes are large, a median of 26.9 s and a longest
of 79.5 s. Cadence decides how many there are, and a durable commit is forced
by *either* the UTXO cache filling or the overlay filling. Raising one ceiling
leaves the other still firing, which is why both knobs matter.

Whether the two **compose** is untested. `--utxocachemaxsize` measures 12% and
this measures 12.7%, on independent triggers of the same commit; they may
stack toward ~25% or may both be nearing one ceiling. Raising both is
reasonable and unmeasured.

`DCROXIDE_DB_FLUSH_SECS` (the time trigger, default 300) remains untuned — no
value has been measured, and on a syncing node the size trigger fires long
before the interval does.

Pair any raised value with the supervisor above: as with the UTXO cache, a
larger overlay means more of the recent window replays after an unclean stop.

**Neither page-cache knob changes how densely the store packs.** Page fill sits at
0.62-0.65 regardless of either setting, so neither shrinks the data
directory. They are throughput settings. The size gap against dcrd is
settled in cause — the engine's page layout, not extra data dcroxide keeps
— and nothing above the engine reaches it: all four of ADR-0004's levers
have now been measured and closed. The engine choice itself was the last
thing open and is now settled: [ADR-0009](adr/0009-storage-shape.md)
closed on 2026-08-17 with redb staying. The candidate won on density and
on write shape and lost on crash safety, so the disk and commit costs
above are accepted rather than retracted.

## Identity: paths, files, and environment

dcroxide uses its own identity throughout. Nothing falls back to a
`dcrd` path or a `DCRD_*` variable — if you are migrating a
configuration, every name changes.

| | dcroxide | dcrd |
|---|---|---|
| application home directory (Linux) | `~/.dcroxide` | `~/.dcrd` |
| application home directory (macOS) | `~/Library/Application Support/Dcroxide` | `…/Dcrd` |
| application home directory (Windows) | `%LOCALAPPDATA%\Dcroxide` | `…\Dcrd` |
| configuration file | `dcroxide.conf` | `dcrd.conf` |
| home directory override | `--appdata`, `DCROXIDE_APPDATA` | `DCRD_APPDATA` |
| data directory override | `--datadir` | `--datadir` |
| extra TLS DNS names | `DCROXIDE_ALT_DNSNAMES` | `DCRD_ALT_DNSNAMES` |
| metadata page cache | `DCROXIDE_DB_CACHE` (MiB, default 1024) | — |
| metadata overlay flush size | `DCROXIDE_DB_OVERLAY` (MiB, default 100) | — |
| metadata overlay flush interval | `DCROXIDE_DB_FLUSH_SECS` (s, default 300) | — |
| metadata flush log (JSONL path) | `DCROXIDE_DB_FLUSHLOG` (unset = off) | — |
| exists-address memtable target (developer-only) | `DCROXIDE_EXISTSADDR_MEMTABLE_KEYS` (keys, default 2,000,000) | — |

The chain itself lives under the home directory, not at it: `--datadir`
defaults to `<home>/data` with the network appended, so on Linux the
blocks are in `~/.dcroxide/data/mainnet` while `dcroxide.conf`,
`rpc.cert` and `rpc.key` sit in `~/.dcroxide` itself.

Those seven are the only `DCROXIDE_*` variables read; only the first
two have dcrd counterparts, since the page cache, the overlay and the
flush log are properties of redb, which dcrd does not use, and the
memtable is a property of this port's exists-address layout. Of the four
storage variables, `DCROXIDE_DB_CACHE` is the one to leave unset, the
next two are untuned instruments — see the storage tuning above — and
`DCROXIDE_DB_FLUSHLOG` is diagnostic: it appends one JSON object per
metadata flush (sequence, end instant, duration, entries, bytes), which
is how the 90–98% attribution above was measured, and now also, for each of
the flush's three phases (block-file sync, insert loop, commit), its time
and, on Linux, the bytes the flushing thread read from storage and the bytes
it dirtied in that phase. `write_bytes` counts pages when they are dirtied,
not when they are written back, so writeback time shows in a phase's `ms`
and not in its `write_bytes`, and the block-file sync always reads about 0
there. Each line's `participant` is what the exists-address index wrote
inside that flush -- its rows, reads, journaled keys, merges, base
rewrites and memtable size, with its own time and I/O as a fourth phase --
or `null` when it had nothing to write. Leave it unset in normal operation;
it writes a line inside each flush. `DCROXIDE_EXISTSADDR_MEMTABLE_KEYS` is
for measurements only: it sets how many keys the exists-address index
holds in memory before its flushes merge them into its sorted runs (the
hard bound is one and a half times it), trading the index's memory, 21
bytes a key, against the pages its flushes write. It never changes an
answer; leave it unset. A malformed or zero value in any of the tuning variables warns and
falls back to the default rather than refusing to start, since they are
hints. Everything else is a command-line flag or a `dcroxide.conf` entry,
and the flag set is a verbatim port of dcrd's — same names, same semantics,
and the same help text apart from the two environment annotations, which
name `DCROXIDE_APPDATA` and `DCROXIDE_ALT_DNSNAMES` where dcrd's name
`DCRD_APPDATA` and `DCRD_ALT_DNSNAMES`.

There is no log file yet. `--logdir` (default `<home>/logs`), `--logsize`
and `--nofilelogging` are parsed and validated as dcrd's are, but the
rotating log file is not wired: standard output is the only sink, so
capture it — journald under systemd, or a redirect or service wrapper
elsewhere. Under the Windows service control manager the process has no
standard handles and every write is discarded, so a daemon run as a
service keeps no log at all until the log file is wired.

The daemon generates `rpc.cert` and `rpc.key` in the application home
directory — alongside `dcroxide.conf`, not under `data/` — on first
start, and only when *both* are absent: one present with the other
missing is an error naming the missing half rather than a regeneration
over the key that is still there. The modes are dcrd's, the certificate
`0644` and the key `0600`. Back up or replace
them the way you would dcrd's; a client that pinned dcrd's certificate
needs the new one. As in dcrd, replacing them is live: when an RPC
connection arrives, `rpc.cert`, `rpc.key` and (under
`--authtype=clientcert`) the `--clientcafile` bundle are checked for a
change of size or modification time, at most once every five seconds and
first five seconds after startup, and a changed set is re-read for that
connection and every later one. Connections already open keep the
configuration they were accepted under. A set that fails to load — a key
that does not match its certificate, a file caught half-written, a
deleted one — leaves the working configuration in place with a warning,
logged once per distinct error, and the repaired files are picked up on
a later check. Replacing the certificate and key together reloads twice,
logging `Reloaded modified RPC certificates` both times, because the
check stops at the first changed file and notices the key only on the
check after; dcrd does the same, and it is harmless. Editing
`clients.pem` is the whole revocation mechanism, since neither dcrd nor
this daemon consults a CRL or OCSP: removing a client's certificate, or
the authority that issued it, refuses every connection it makes from
the first check that loads the edited bundle, normally within five
seconds of the edit, while a websocket it already holds open stays
connected until it closes. The edited bundle must still
load, though: one left with no usable certificate is a failed reload
like any other, and the old bundle stays in force. `SIGHUP` is not
needed and will not help: it stops the daemon, exactly as it does in
dcrd.

The `--clientcafile` bundle is read the way dcrd's Go code reads it:
malformed PEM blocks, blocks with headers, other block types and
certificates that do not parse are skipped, and only a file with no
usable certificate is refused. A client may present a certificate that
is itself in the bundle, which is the simplest setup: run `gencerts
client.cert client.key` and append `client.cert` to `clients.pem`. Such a
certificate authenticates on its own validity and extended key usage;
any other must chain to a bundle certificate that dcrd would accept at
the top of the chain: within its validity window, with no critical
extension Go does not handle, an extended key usage that allows client
authentication, and a path length constraint the chain's intermediates
stay within. The client certificate shapes the daemon still refuses
where dcrd accepts them are listed in [PARITY.md](../PARITY.md).

Default ports are dcrd's, unchanged: mainnet 9108 (P2P) and 9109 (RPC).

## Running it

Build from source. Binaries are not published, and the release process —
signing, platform tiers, reproducibility — is an open decision (D7 in
[the ADR index](adr/README.md)); it is a hard gate before anything ships
as a binary.

```bash
cargo build --release
```

The release profile is deliberate: one codegen unit, thin LTO, line
tables kept for profiling, and the `panic = "abort"` discussed above.
The toolchain is pinned in `rust-toolchain.toml` so artifacts are
reproducible from the same source.

Start it against simnet or testnet rather than mainnet while evaluating:

```bash
./target/release/dcroxide --testnet --appdata=/path/outside/the/repo
```

`--norpc` disables the RPC and websocket surfaces entirely, which is the
right default if you only want a syncing node — it removes the entire
authenticated surface from the process.

## Status of what you are running

Per-package parity status is in [PARITY.md](../PARITY.md), which also
records every deliberate divergence from dcrd and the known remaining
gaps. Bug-for-bug reproductions of dcrd behavior — the ones that look
like defects and are not — are catalogued in [QUIRKS.md](../QUIRKS.md).

There is no per-RPC-method status ledger yet. It is planned alongside
the ecosystem-acceptance work (the `dcrdtest` harness, a `dcrctl`
sweep, dcrwallet integration), none of which has been run; the project
brief tracks that as unmet.
