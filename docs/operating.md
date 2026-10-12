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

Since 2026-10-11 that replay is the usual outcome of an unclean stop
during the initial sync, and there is more to do again. While the chain
is catching up, a UTXO cache flush that the cache's size limit trips no
longer forces the metadata store to disk. Its rows reach disk with the
store's next commit, and the chain forces one of its own about every
two minutes while blocks are connecting. If blocks stop arriving
nothing commits, and what is waiting stays in memory until the next
block or a clean shutdown: the loss is bounded in work, not in time. So
a kill or a power cut in that phase loses about two minutes of
processing at most, where it lost one fill of the UTXO cache, and the
node downloads and connects those blocks again.
Nothing is corrupted: what is on disk is always a state the chain was
in. Once the chain is current every block is flushed to disk as it
connects, as before, and a clean shutdown loses nothing in either phase.
The storage section below has what the change bought and what it costs
in memory.

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

Budget for it: on the one machine where a sync from genesis has been
measured with the current layout, it took less time than dcrd v2.1.6
did, and more disk. The current figure is a median of **12.1 minutes**
over three runs on 2026-10-11; the comparison with dcrd was made on
2026-10-09 and 2026-10-10, when dcroxide took 17.6, and it comes first. On machine m3 in
[bench-ledger.md](bench-ledger.md), a 16-core desktop with one NVMe
drive and the node held to eight of its cores, mainnet from genesis to
block 1,116,035 took a median of **17.6 minutes**, against **47.7
minutes** for dcrd v2.1.6 on the same cores. Those are four runs of each
on 2026-10-09 and 2026-10-10, each set of four spanning at most 1.6% of
its median, with each daemon syncing over loopback from the other. Both
ran at their defaults apart from the flags that point them at the
server, so the exists-address index was on. Which daemon served the
blocks moved either figure by about 1% or less. dcrd at the commit this
port tracks, `6f6cf21b`, took 47.8 and 48.5 minutes in two runs later on
2026-10-10, so the release stands for it. With `--noexistsaddrindex`
dcroxide's sync took **14.7 minutes** and dcrd v2.1.6's 20.8 (one run
each, in that later session; see the index's section below). In that
session's three dcrd runs the dcroxide block server read its block
files from the drive as it served them, which it did not in the
runs above; whether that slowed dcrd was not measured. At the defaults
the chain cost more on
disk: 27.90 GiB against dcrd's 24.16 GiB at that block.

Five changes to block processing on 2026-10-11 shortened dcroxide's
sync. Two runs of the same sync with all five, at the defaults, took
**12.6 and 12.7 minutes** (756.2 s and 759.1 s) and ended on the same
block, where the code before them took 17.6 minutes (1,058.3 s) in one
run the same day. Their peak resident memory was 2.56 GiB, where the
runs above peaked at about 2.1. A sixth change that afternoon, to when
the node commits during a sync (the paragraph on unclean stops above,
and the storage section below), took the sync to a median of **12.1
minutes** (728.7 s) over three runs, with a peak of 3.0–3.2 GiB, where
the code before it took 12.9 minutes (775.6 s) in one run that
afternoon and peaked at 2.6 GiB. With `--noexistsaddrindex` that code took 10.2 minutes (610.2 s)
in one run and peaked at 2.1 GiB. dcrd v2.1.6 took 48.1 minutes
(2,883.9 s) in one run that evening, 3.96x the 12.1 in one session;
3.93x and 2.04x against its 47.7 and 20.8 minutes above are figures
across sessions.
The ledger's section "Five changes on the block-processing thread" has
each step.

The rate falls as the chain grows, and falls again where full
validation begins: by default both daemons skip connect validation,
script checks included, up to the built-in assume-valid block,
1,026,597. On m3 the node reached block 500,000 in
4.8 minutes, block 1,000,000 in 13.8 and the assume-valid block in 14.4.
The 89,438 blocks after it took another 3.2 minutes, about 461 blocks/s
on about five of the node's 16 threads, against 1,054 over the whole
chain. (The three runs of 2026-10-11 with all six changes reached the
assume-valid block in 9.6 minutes and took 2.5 for the blocks after it,
about 586 blocks/s.) New blocks are past that point too, so a chain
longer than the one measured should add time at about 586 blocks/s on a
machine like m3 (three runs on 2026-10-11; the four earlier runs,
before that day's changes, gave a median of about 461), until a release
moves the assume-valid block. With `--assumevalid=0`
every block is validated in full and none of these figures apply.

On a smaller or slower machine, budget more. On m2, a ZFS mirror of QLC
NVMe drives with the node on four cores, the 200,000 blocks after
916,000 synced at a median of 482 blocks/s with the index on
(2026-10-09, below), where m3 ran the same blocks at about 593. m2 has
both fewer cores and slower storage, so that difference is not storage
alone, and no sync from genesis has been measured on m2 with the
current layout. dcrd ran that tail on m2 at 146-148 blocks/s, but on
2026-10-07, in another session, so read the two together as context,
not as a ratio. The m3 figures were taken on a quiet machine. One run
of each daemon there with a desktop in light use, about a third of one
thread, came out slower than a quiet run of the same pairing, dcroxide
by 1.5% and dcrd by 2.6%. That is one run each, but if your host is
busy with other work, expect the sync to stretch.

All of these come from syncing over loopback from a local server, and
no whole sync has been measured over the internet. There, dcrd requests
blocks through a window of at most 16 blocks in flight, refilled once
fewer than 10 remain, from the sync peer only. dcroxide did the same
through the runs of 2026-10-11 and does when started with
`DCROXIDE_BLOCK_WINDOW=dcrd`; its default is now a wider window of its
own, in the next paragraph. By the arithmetic of dcrd's window, once
the round trip to the sync peer exceeds about nine blocks' processing
time, the sync should wait on the network
at about 9-16 blocks per round trip. That was measured on 2026-10-11
through a relay on the same machine that delays every chunk: over the
early chain dcroxide synced at 12.2, 13.0 and 13.6 blocks per round
trip at round trips of 20, 50 and 150 ms (609, 260 and 91 blocks/s),
and dcrd v2.1.6 at 12.6 at 50 ms (252 blocks/s), where over loopback
they pass those blocks at about 3,200 and 1,500 blocks/s. The header
sync is paced the same way: the first blocks arrived between 41 and
51 s into a run at 50 ms and between 91 and 101 s in at 150 ms (samples
every 10 s). At 13 blocks per round trip the whole
chain would take dcroxide about 72 minutes at 50 ms and either daemon
3.6 hours at 150 ms; at 50 ms dcrd would take at least about 80
minutes, since it runs the blocks after the assume-valid block at about
104 blocks/s over loopback. These are worked out for dcrd's window and
were not run, and
assume one peer, no loss and no bandwidth limit. The rest of this paragraph is the same
arithmetic applied to the rates measured at `c128a93`, and is not a
measurement. On m3 a block took dcroxide 0.95 ms averaged over the chain and
2.2 ms after the assume-valid block, and dcrd 2.6 ms and 9.6 ms. So
under dcrd's window the
network should pace dcroxide's average block once the round trip passes
about 9 ms and dcrd's past about 23 ms, and the cheap early blocks
sooner. Only past about 87 ms would it also pace dcrd through the fully
validated blocks after the assume-valid block, where about 20 ms
already paces dcroxide, so with both daemons on that window the lead
over dcrd should narrow toward 1x
as latency grows toward that. Bandwidth binds too: the
measured 17.6 minutes carried 19.2 GB of blocks, a mean of 145 Mbit/s,
and the 12.1 minutes of 2026-10-11 a mean of 211 Mbit/s.
Budget from your link's latency and bandwidth as well as from these
figures; the delayed-link runs of 2026-10-11 are in
[bench-ledger.md](bench-ledger.md), and no whole sync over the internet
has been measured.

By default dcroxide now requests blocks through a window of its own
([PARITY.md](../PARITY.md), *Block download window*): up to 128 blocks
requested from the sync peer and, beyond the first 16, no more than
3,145,728 bytes of them by the sizes in their headers. It was measured
on m3 on 2026-10-12 in short runs only, one binary and one run per arm.
Through the same relay for 300 s from the start of the process, on a
quiet machine with the node on four cores, the node reached block
68,031 with `DCROXIDE_BLOCK_WINDOW=dcrd` and block 532,079 at the
default at a 50 ms round trip, and blocks 18,445 and 158,440 at 150 ms.
No arm logged a narrowed or widened window or a stalled peer. The relay
delays and does not limit bandwidth. In five outbound-only starts of
300 s against the public main network, on a machine that was not quiet
and with the peers and links the network offered, the node under dcrd's
rule reached block 24,455 180.7 s after its first block arrived and
block 41,191 after 220.3 s, and under the default block 188,469 after
215.7 s and block 93,095 after 161.8 s; a third start under the default
fetched no block, its header sync being about 68% done when the 300 s
ended. None logged a narrowing, a stalled peer or a ban. Over loopback,
on a quiet machine, one sync to block 1,116,035 took 612.4 s with the
window and 607.7 s with the code before it (`3a367e5`), one run each,
0.8% more, and one run each does not settle whether the window costs
anything over loopback; both are of later code than the 12.1 minutes
above. No whole sync has been run through
the default window over a delayed or a real link, so there is no sync
time to budget from for it, and the 72 minutes and 3.6 hours above are
not its figures.

The wider window can cost a node its sync peer where dcrd's would not,
in two cases. Neither has been measured; both are read from the code. A
requested block has to be read within 30 to 45 s of being asked for, so
a path that carries less than about 70 to 105 kB/s, which is 0.56 to
0.84 Mbit/s (the sync peer's uplink counts as much as your own link),
or a host that processes fewer than three or four blocks a second, has
its sync peer dropped as stalled while the peer is still delivering.
And a peer that bounds its writes (dcrd since its commit `62fd529a`,
and this port) hangs up on a node that does not read its socket for
more than about 20 s, through a long flush for one, while more of the
window is unsent than the socket buffers hold; neither end logs a stall
then. The node is not told why a peer left. Each time its sync peer
leaves with more than 16 blocks requested from it, for whatever reason,
it halves the window, 128 to 64 to 32 to dcrd's 16, and logs the first
of these lines under `SYNC`. Once one sync peer has since delivered
enough blocks (2,048 after the first narrowing, 4,096 once two are
counted, and so on) it undoes one halving and logs the second. dcrd
logs neither.

```text
Block download window narrowed to at most N blocks in flight: the sync peer left with M requested
Block download window widened to at most N blocks in flight after K blocks from the sync peer
```

The width in force is kept in memory only. A narrowed window is widened
only by blocks its sync peer delivers, and once the node has caught up
those are only the new blocks that peer is the first to announce. On
the main network, at 288 blocks a day, the 2,048 that undo the first
halving of the default window are at least 7.1 days of them, so a node
that has caught up keeps the width its sync ended with for a week or
more. A restart puts it back at the full width.

Set `DCROXIDE_BLOCK_WINDOW=dcrd` and restart the node if its log shows
any of these during a sync: the narrowed line again and again; `Peer P
appears to be stalled or misbehaving` lines for sync peers that were
still delivering blocks; or the sync peer leaving around a long pause
in the node's own progress, a long flush for one, with no stalled line
before the narrowed one. The runs above logged no narrowed line and no
stalled peer. With that setting the node requests blocks by dcrd's rule
exactly, never narrows or widens the window, and logs `Block download
window set to dcrd's 16 blocks in flight by DCROXIDE_BLOCK_WINDOW` at
startup.

The disk difference is all in the metadata store. Block files make up
17.88 GiB of each data directory at block 1,116,035, and the rest is
one 10.01 GiB redb file against about 6.28 GiB left for dcrd's two
leveldb stores. As of 2026-08-11 both nodes had been measured to store
the same payload for the same chain at the same index composition,
fifteen buckets equal to the byte, so the extra space then was how redb
lays those bytes out, not extra data dcroxide keeps. Two changes since
have not been through that comparison: the 2026-10-08 keys add four
bytes to the keys of five per-block buckets, at most about 22 MB at the
tip, and the exists-address index now has a layout of its own (below).
See [ADR-0004](adr/0004-storage-backend.md).

The earlier gap, when dcrd was the faster, was taken apart thread by
thread. This one has been taken apart only as far as the exists-address
index. One run of each daemon with the index off, on 2026-10-10, puts
80% of the 30 minutes between them down to the index: it is 56% of
dcrd's sync and 17% of dcroxide's. With it off dcrd took 20.8 minutes
to dcroxide's 14.7, and was the first to the assume-valid block, in
10.3 minutes against 11.8. dcroxide made that up over the fully
validated blocks after it, 2.9 minutes against 10.5. dcrd was not
profiled, and dcroxide only on 2026-10-11, in one sync with the index on
and before the five changes above (user-space time only; the ledger's
"Five changes on the block-processing thread" has it), so why dcrd was
ahead up to the assume-valid block with the index off at `c128a93`, and
dcroxide after it, has not been taken apart; on 2026-10-11, in one run
with the index off, dcroxide reached that block in 7.9 minutes, against
dcrd's 10.3 of 2026-10-10. What the runs of 2026-10-09 and
2026-10-10 record besides is that at the defaults
the node process used a third of dcrd's CPU time (1,821 s
against 5,567 s) and passed under a fifth of the bytes to write calls
(51.4 GB against 286.3 GB). Its metadata flushes, 133 per sync with a
median of about 1.3 s and a longest of 3.0 s, took 15–16% of the wall
time. In the two runs of 2026-10-11 with all five changes the same 133
flushes took 167.9 s and 163.2 s, 22% of each: the flush time did not
grow, the sync got shorter. With the sixth change a sync made 54
flushes taking 107–110 s, 15% of it. This guide used to describe a node fully stalled on storage for
48% of block-sync wall time, with a median flush of 26.9 s, and a sync
1.29x slower than dcrd's. Those were measured in 2026-08 on m1 in
[bench-ledger.md](bench-ledger.md), another machine, against dcrd
2.2.0-pre, before the height-first keys and the index's own layout.
They have not been re-measured there, and no run of the current layout,
m2's tail or m3 from genesis, looks like them. The analysis is in
[ADR-0009](adr/0009-storage-shape.md).

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
and 501 with it off, and wrote 15.5 GB against 12.6 GB. From genesis on
m3 it showed more: one sync with the index off took 14.7 minutes
against 17.6 with it on, and left a data directory 2.0 GiB smaller
(10.2 minutes against 12.1 on 2026-10-11, after that day's changes).
With the index off, both RPCs fail with "exists address index
disabled", as dcrd's do. With it on, the index is updated on a thread of
its own and can trail the chain by a little more than 128 blocks while
the node syncs. While it is more than five blocks behind the tip both
RPCs answer at once that the index is not synced; within five blocks
they wait for it to catch up, and answer that only if it still has not
after about three seconds, as dcrd's do. A node stopped during a sync
indexes the blocks it had not reached when it next starts, and logs
that catch-up.

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

From genesis the cost is larger and outside the noise. On m3 on
2026-10-10 ("The parity commit, the index off, two levers and a full
replay" in the ledger), one sync to block 1,116,035 with the index off
took 880.8 s, against 1,055.8–1,065.0 s over five with it on (the
budget's four and one more that day): the index is 17% of a default sync
there. With the index on the node used 10% more CPU time (1,821 against
1,657 s) and passed 51.4 GB to write calls against 43.8 GB. It made the
same 133 metadata flushes, which took 160–171 s in all against 116 s.
Its peak resident memory was about 140 MiB higher (2,129–2,148 against
1,996 MiB), and its data directory 2.01 GiB larger (27.90 against 25.88
GiB). dcrd v2.1.6 on the same machine took 1,247.8 s in one run with its
index off against a median of 2,863.9 s with it on, so the index is 56%
of its sync, for 1.97 GiB on disk. On 2026-10-11, after that day's six
changes, one sync with the index off took 610.2 s against a median of
728.7 s over three with it on: 16% of a default sync, 15% more CPU time
(1,462 against 1,273 s), 54 flushes taking 107–110 s against 41 taking
63.6 s, 39.7 GB passed to write calls against 32.7 GB, and 2.00 GiB
more on disk (27.89 against 25.88 GiB).

- **Memory**: the index's in-memory set holds up to about 3 million
  addresses (about 63 MB) after each flush while syncing, and up to about
  4 million (84 MB) just before one; a catch-up from genesis peaked at
  4.5 million (95 MB). It also takes in, at each block, every address the
  mempool has seen since the last block, so a very large mempool adds to
  that. The index's pages also fill the metadata page cache
  (`DCROXIDE_DB_CACHE`, below) up to its configured size. On m2's tail,
  at the default 1 GiB cache, the node's peak resident memory was about
  350 MiB above the index-off run's (2,773 against 2,424 MiB). On a
  development desktop it was about 380 MB above at that cache over a
  similar tail, and about 140 MB above with a 256 MiB cache. From
  genesis on m3 it was about 140 MiB above at the default cache
  (above). That was on 2026-10-10, before the index thread. With the
  thread, two default syncs on 2026-10-11 peaked at 2,621 and 2,624
  MiB, where the seven that day without it peaked at 2,139–2,147 MiB.
  Since the change to commits that afternoon, three default syncs
  peaked at 3,090–3,285 MiB and one with the index off at 2,138 MiB, so
  the index now adds about 0.9–1.1 GiB (952–1,147 MiB) to the peak of
  an initial sync.
  What in it holds that memory has not been found.
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

## Storage tuning: four knobs, and what each has measured

Four settings change how the metadata store behaves. Three are measured and
one is not; the numbers are in [bench-ledger.md](bench-ledger.md) and the
reasoning in [ADR-0004](adr/0004-storage-backend.md).

**Since 2026-10-11 a sync commits less often, and the overlay's default
ceiling is 300 MiB.** Until then every UTXO cache flush forced a durable
commit, about 120 of the 133 in a sync, and the overlay's own ceiling of
100 MiB hardly mattered. Now a flush the size limit trips shares the
next commit (the paragraph on unclean stops near the top has what that
risks). That commit comes when the overlay holds two thirds of its
ceiling or, with the exists-address index on, when the index has taken
about 1.5 million new keys since its last flush, which is what trips
most of them after the first few minutes of a sync; about one in ten is
the two-minute rule's. On m3 that day the code before the change
took 775.6 s with 133 flushes in one sync, a prototype of the change
took 724.6 s with 52 flushes at 300 MiB and 736.9 s with 63 at 200 MiB,
and the change as made took a median of 728.7 s over three syncs, with
54 flushes. It costs memory: peak resident memory was 3.0–3.2 GiB in
those three runs against 2.6 GiB before, and 2.1 GiB with the
exists-address index off, where the index-off sync of `c128a93` peaked
at 1.9 GiB. So nearly all of the extra appears to come with the index,
though the code before the change was not run with the index off; what
in it holds the memory has not been found. `DCROXIDE_DB_OVERLAY=100` should
put the overlay's part of the cadence back to about one commit per UTXO
cache flush, and restores the old ceiling in the header sync, where the
larger one should also mean fewer commits; neither was run on the new
code. A catch-up of the exists-address index is paced by the index
itself and does not change. The paragraphs below
describe measurements made before this change, and where they say a
UTXO cache flush forces a commit, that was so then.

The measurements quoted in the paragraphs below were taken on m1 in
2026-08, before the height-first keys and the exists-address index's
own layout. The two knobs that helped then, by about 12% each, were
tried again on m3 on 2026-10-10 with the current layout: one sync from
genesis each, where five default syncs from the same server, the four
of the budget above and one more that day, took 1,055.8–1,065.0 s.

- `--utxocachemaxsize=1200` took 1,019.5 s, 3.7% under the 1,058.6 s
  median of the four default syncs in the budget above. It made 92
  flushes where the default makes 133, and its peak resident memory was
  3.77 GiB against 2.09.
- `DCROXIDE_DB_OVERLAY=800` took 1,068.3 s, slower than each of those
  five, with 121 flushes.

So in one sync on m3 the larger UTXO cache gained 3.7%, where replays
with full validation on m1 measured 12%, and the larger overlay gained
nothing, where four alternating syncs on m1 measured 12.7%. That is one
run of each on one machine: enough to say the 12% figures do not carry
over to a default sync on it, not to rank the settings on another. The
UTXO cache and the overlay both
work by making flushes rarer, and flushes have less to give now.
On m2 the index's layout cut the flush time of a 200,000-block tail
from 1,416 s over 58-59 flushes to 78 s over 31. On m3 on 2026-10-09
and 2026-10-10 the median flush was about 1.3 s and flushes were 15–16%
of a sync's wall time (22% in the two runs of 2026-10-11 with all five
changes, where the flush time was the same and the sync shorter, and
15% with the sixth, which makes 54 flushes), where
on m1 on 2026-08-16 the median was 26.9 s and flush windows
occupied 68% of it. m3 is another machine as well as another layout, so
that pair is not a before and after.

The two that helped on m1 are the two flush triggers, and they are worth
understanding
together: a durable metadata commit was forced when **either** the UTXO cache
filled or the metadata overlay filled. Each ceiling governed one of them,
raising either reduced how often the node committed, and each measured ~12%
on its own there. `DCROXIDE_DB_CACHE`'s effect on sync time has not been measured
again since, and `DCROXIDE_DB_FLUSH_SECS` never has been.

**`--utxocachemaxsize` (default 150 MiB) is one of the two.**
Until 2026-10-11, connecting a block flushed the UTXO cache when it
filled, and that flush forced a durable metadata commit — so the ceiling
governed how often the node committed. Raising it on its own measured **12% faster** over a full-chain
replay on m1 at
1200 MiB, and 7% at 600 MiB, across three repetitions each with ranges that
do not overlap the baseline's. dcrd has the same flag and the same 150 MiB
default; the ceiling here is 32 GiB.

One caveat before you turn it up: a larger cache means more work redone
after an unclean stop. Nothing is corrupted — the flush ordering holds —
but more of the recent window has to be replayed, so pair a large value with
the supervisor above rather than treating it as free.

**`DCROXIDE_DB_CACHE` is the one to leave alone.** It sets redb's page cache
in MiB, defaulting to 1024. Raising it to 8192 made a full-chain replay
**50% slower** — 5125-6294 s against a 3866-3888 s baseline, in an earlier
sweep on m1, again with non-overlapping ranges. That is the opposite of
what the setting
suggests, and the opposite of what two microbenchmarks of 2026-07
predicted: the 500,000-key insert loop that was the premise of ADR-0004's
lever (b), and the 2,000,000-write grid reported when the knob was added,
which the source comments still carry, marked superseded. There is no
fixed split to reason from: redb 4.3.0
keeps a single cache figure and partitions it on demand, holding the write
buffer at or below half of it, best effort, and letting the read cache grow
into all of it. The advice rests on the full-chain measurement, not on a
mechanism.

Lowering it does not help either: 256 MiB and 512 MiB both measured
indistinguishable from the 1024 MiB default, with ranges overlapping it.
The default is the right value — the only thing that matters is not raising
it, so leave the variable unset.

**`DCROXIDE_DB_OVERLAY` and `DCROXIDE_DB_FLUSH_SECS` reach the other flush
trigger.** When they were added, connecting a block forced a durable commit
when *either* the UTXO cache filled or the metadata overlay did, and only the
first was reachable. The overlay has its own ceiling, 300 MiB since
2026-10-11 and 100 MiB before, and its own interval, 300 seconds; both were
fixed at compile time, so half the cadence lever could not be pulled. `DCROXIDE_DB_OVERLAY` sets the ceiling in MiB and
`DCROXIDE_DB_FLUSH_SECS` the interval in seconds. The ceiling counts each
overlay entry as dcrd does, at 72 bytes plus its key and value, so the
configured MiB tracks the overlay's resident memory to within allocator
overhead. Before 2026-09-23 entries were counted at key and value bytes
only, which let the overlay hold 2–4× the configured figure. The 12.7%
measurement for `DCROXIDE_DB_OVERLAY=800` below was taken under that older
accounting, so the same setting now flushes a smaller overlay. The one
re-measurement since, on m3 (above), found no gain. Unset, both
keep the compiled defaults.

**`DCROXIDE_DB_OVERLAY=800` measured 12.7% faster** on m1 in 2026-08,
which made it the
second knob worth raising then. Four alternating full-mainnet syncs, 256.1 and
272.7 blk/s at the default against 288.4 and 307.5 at 800 MiB — ranges
disjoint, and both adjacent pairs agreeing to 0.2 points. The mechanism is
visible in the flush count, which drops 130 to 119.

Why it worked: when this was measured the node was *fully stalled* —
nothing runnable at all — for **48% of block-sync wall time**, and **90–98%
of that was inside a metadata-flush window**. Flushes were large, a median of
26.9 s and a longest of 79.5 s. Cadence decides how many there are, and a
durable commit is forced by *either* the UTXO cache filling or the overlay
filling. Raising one ceiling leaves the other still firing, which is why both
knobs mattered.

Whether the two **compose** has not been measured in a sync. Over replays
on m1 in 2026-08, with both raised (overlay 800 MiB, UTXO cache 1200 MiB),
the gain was 11%, about what the UTXO cache alone measured there. On m3
with the current layout they measured 3.7% and nothing, one run each;
raising both was not run there.

`DCROXIDE_DB_FLUSH_SECS` (the time trigger, default 300) remains untuned — no
value has been measured, and on a syncing node the size trigger fires long
before the interval does.

Pair any raised value with the supervisor above: as with the UTXO cache, a
larger overlay means more of the recent window replays after an unclean stop.

**Neither page-cache knob changes how densely the store packs.** Page fill sits at
0.62-0.65 regardless of either setting, so neither shrinks the data
directory. They are throughput settings. The size gap against dcrd was
settled in cause on 2026-08-11 — the engine's page layout, not extra data
dcroxide kept — and none of ADR-0004's four levers reached it: all four
were measured and closed. The exists-address index's own layout has
narrowed it since: on m2 it took the data directory at the tip from
30.58-31.04 GiB to 27.05 GiB. Across machines, heights and dcrd
versions, so not a before and after, the pair against dcrd was 33.58
against 23.69 GiB on m1 in 2026-08 and 27.90 against 24.16 GiB on m3 in
2026-10. The payload comparison has not been repeated for the current
layout. The engine choice itself was the
last thing open and is now settled: [ADR-0009](adr/0009-storage-shape.md)
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
| metadata overlay flush size | `DCROXIDE_DB_OVERLAY` (MiB, default 300) | — |
| metadata overlay flush interval | `DCROXIDE_DB_FLUSH_SECS` (s, default 300) | — |
| metadata flush log (JSONL path) | `DCROXIDE_DB_FLUSHLOG` (unset = off) | — |
| exists-address memtable target (developer-only) | `DCROXIDE_EXISTSADDR_MEMTABLE_KEYS` (keys, default 2,000,000) | — |
| block download window | `DCROXIDE_BLOCK_WINDOW` (`dcrd`, or a whole number of blocks from 16 to 505; default this port's own window, at most 128 blocks and 3,145,728 bytes) | — |

The chain itself lives under the home directory, not at it: `--datadir`
defaults to `<home>/data` with the network appended, so on Linux the
blocks are in `~/.dcroxide/data/mainnet` while `dcroxide.conf`,
`rpc.cert` and `rpc.key` sit in `~/.dcroxide` itself.

Those eight are the only `DCROXIDE_*` variables read; only the first
two have dcrd counterparts, since the page cache, the overlay and the
flush log are properties of redb, which dcrd does not use, the
memtable is a property of this port's exists-address layout, and the
download window is this port's own rule for requesting blocks
([PARITY.md](../PARITY.md), *Block download window*). Of the four
storage variables, `DCROXIDE_DB_CACHE` is the one to leave unset, the
next two are untuned instruments — see the storage tuning above — and
`DCROXIDE_DB_FLUSHLOG` is diagnostic: it appends one JSON object per
metadata flush (sequence, end instant, duration, entries, bytes), which
is how the 90–98% attribution above was measured, and also, for each of
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
answer; leave it unset. `DCROXIDE_BLOCK_WINDOW` is read once at startup
and is the way back to dcrd's download window; the sync budget above
says when to use it. `dcrd`, in any letter case, selects dcrd's window
exactly. A whole number from 16 to 505 keeps the default's byte budget
and sets the most blocks it requests, for measurement; 16 is not dcrd's
rule. A set value is logged at startup, as `Block download window set
to dcrd's 16 blocks in flight by DCROXIDE_BLOCK_WINDOW` or `Block
download window set to at most N blocks in flight by
DCROXIDE_BLOCK_WINDOW`, where N is the full width and never a narrowed
one, and any other value as the warning `DCROXIDE_BLOCK_WINDOW=V is
neither dcrd nor a whole number of blocks from 16 to 505; using the
default`. Unset, the default applies and nothing is logged.
A malformed or zero value in any of the tuning variables warns and
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
