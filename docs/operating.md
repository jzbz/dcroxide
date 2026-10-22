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
store refuses every write from the moment it has recorded the failure,
so the node makes no further progress until it is restarted. Reads of
what is still in memory keep working, so RPC still answers what they
cover; from the failed write on, a read that needs a page of the
metadata file that is not cached fails. Most of a sync's commits to the
metadata store sync their block files, write their rows and commit on a
thread of their own (`dbcommit`; the flush log below), so such a
failure, in the block files' sync, the rows, the exists-address index's
or the commit, is logged under BCDB as
`Background commit of the metadata write cache failed: ...` when it
happens, and the refusal, with the same cause, comes at the next write,
flush or close. In a sync
the node often stops sooner, and harder: the next block with an input
that is not in the UTXO cache reads the UTXO set, that read fails, and
the process aborts with a panic that reads `corrupt utxo backend entry`
or `utxo backend read` and names `Previous I/O error occurred`, just
before or just after that BCDB line. Despite its wording it is the same
storage failure, not damage to the store, and an unclean stop like any
other. This trades
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
store's next commit, and the chain asks for one of its own about every
two minutes while blocks are connecting, counted from the last of its
flushes a commit has made durable; since 2026-10-19 the daemon makes
that commit on a thread of its own while blocks go on connecting, and
the flush counts once it has landed. If blocks stop arriving
nothing commits, and what is waiting stays in memory until the next
block or a clean shutdown: the loss is bounded in work, not in time. So
a kill or a power cut in that phase loses about two minutes of
processing at most, where it lost one fill of the UTXO cache, and the
node downloads and connects those blocks again. With the commit on a
thread of its own it can also lose what was committed while the commit
under way ran, which nothing had acknowledged as durable either.
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
difference is expected. The eleven commits of 2026-10-12 (`7f99184` to
`b4ceb1c`) change no on-disk format and no database version, and nor do
the eighteen commits to the node's code after them (below). That is
read from the code: no run on record opened a directory written before
them with a build made after them.

Budget for it: on the one machine where a sync from genesis has been
measured with the current layout, it took less time than dcrd did, and
more disk. Each figure below is of the code named with it. A build of
the code of `797a213` took a mean of 271.68 s over four runs at the
defaults on 2026-10-19, **4.5 minutes**, against 3,014.6 s and
3,033.4 s, 50.2 and 50.6 minutes, for dcrd v2.1.7 in two runs of the
same session, both syncing from a block server on another machine on the
same LAN, and peaked at 2,456 to 2,470 MiB when the clock stopped (the
paragraph on 2026-10-19 below has the rest, and why those figures are
not to be set beside the loopback ones that follow). `88c46c3` took a
median of 396.25 s over four runs at the defaults on 2026-10-17, **6.6
minutes**, against 2,944.4 s and 2,926.4 s, 49.1 and 48.8 minutes, for
dcrd v2.1.7 in two runs of the same session, from a block server on the
same machine, and peaked at 3,464 to 3,710 MiB up to the tip (the
paragraph on 2026-10-17 below has the rest). `8fc9160` took a median of
430.7 s over four runs at the defaults on 2026-10-16, **7.2 minutes**,
against 2,944.4 s, 49.1 minutes, for dcrd v2.1.7 in one run of the same
session (the paragraph on 2026-10-16 has what to make of that ratio).
`4700cf1` took 504.2 s, 513.4 s and 513.5 s at the defaults on
2026-10-13, **8.4 to 8.6 minutes**, in a session not to be set beside
the earlier ones without its label (the paragraph on 2026-10-13 says
why).
On 2026-10-12 two runs of a build of `b4ceb1c` made before the
last fixes to it took **8.2 minutes** each, and `540b203` took 10.2
minutes in one run; a median of **12.1 minutes** over three runs on
2026-10-11 is the figure before those with more than two runs behind it
(the paragraph on 2026-10-12 below has the steps). The comparison with
dcrd was made on 2026-10-09 and 2026-10-10, when dcroxide took 17.6,
and it comes first. On machine
m3 in [bench-ledger.md](bench-ledger.md), a 16-core desktop with one NVMe
drive and the node held to eight of its cores, mainnet from genesis to
block 1,116,035 took a median of **17.6 minutes**, against **47.7
minutes** for dcrd v2.1.6 on the same cores. Those are four runs of each
on 2026-10-09 and 2026-10-10, each set of four spanning at most 1.6% of
its median, with each daemon syncing over loopback from the other. Both
ran at their defaults apart from the flags that point them at the
server, so the exists-address index was on. Which daemon served the
blocks moved either figure by about 1% or less. dcrd at the commit this
port then tracked, `6f6cf21b`, took 47.8 and 48.5 minutes in two runs
later on 2026-10-10, so the release stands for it. With
`--noexistsaddrindex` dcroxide's sync took **14.7 minutes** and dcrd
v2.1.6's 20.8 (one run each, in that later session; see the index's
section below). In that session's three dcrd runs the dcroxide block
server read its block files from the drive as it served them, which it
did not in the runs above; whether that slowed dcrd was not measured.
At the defaults the chain cost more on disk: 27.90 GiB against dcrd's
24.16 GiB at that block.

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

Eleven more commits to the node's code followed on 2026-10-12, and the
sync is shorter again. They were measured on m3 as they accumulated, in
the same harness on a quiet machine, one sync at the defaults for each
step unless said, and each figure is of the code named with it. The code
of the 12.1 minutes, `b4a5d2d`, took 728.5 s that morning. With four
changes through `a83f9a1` (two to block processing, one to how a block
record is written, and a wait timer in the flush log) the sync took
673.8 s. With three more through `6271436`, two to the exists-address
index's work for each block and one to the ticket database's, it took
628.0 s. With a block's `SigHashAll` signature hashes built on the
transaction hashes its connect has already computed (`3a367e5`) it took
607.7 s, and with the block download window below (`540b203`) 612.4 s,
**10.2 minutes**, which was the last figure for a commit as committed
until those of `4700cf1` on 2026-10-13 (below). The two commits after
it hand a peer's block to the chain without copying it (`5cf9e04`) and
read the sync peer's connection ahead
(`b4ceb1c`, below). They were measured only together, and only in a
build made before a review's fixes to the second: two syncs took
**8.2 minutes** each (494.6 s and 490.8 s) with the read-ahead, and two
took 597.6 s and 599.0 s with `DCROXIDE_READ_AHEAD=off`, which still had
the hand-off. So for the code of `b4ceb1c` those runs of an earlier
build were all there was that day: the committed code was run in syncs
on 2026-10-13, inside `4700cf1` and only with the read-ahead on
(below), and the hand-off was not measured alone. Peak resident memory
was 3.1–3.2 GiB (3,204–3,299 MiB) in the seven runs without the
read-ahead and 2.9 GiB (2,967 and 2,921 MiB) in the two with it, which
is not explained. The node's CPU time, user and system, went from
1,458 s to 1,119 s and 1,118 s, most of the fall coming with the
signature hash (1,394 s in the run before it, 1,152 s with it). dcrd was
not run that day. Set against the 48.1 minutes of its one run on the
evening of 2026-10-11 the two 8.2-minute runs are 5.83x and 5.88x as
fast, and against its 47.7-minute median above 5.79x and 5.84x: ratios
across sessions, and of a build that is not the committed code. None of
the eleven changes has been run on another machine or filesystem, or in
a whole sync over a delayed link or a real one with a longer round trip
than a LAN's, and with `--noexistsaddrindex` only once, inside
`4700cf1` on 2026-10-13 (below).
The ledger's section "Eleven changes, a background commit not kept and a
pool gate" has each step.

Eighteen more commits to the node's code followed, and one that adds
tests only. `4700cf1` adds an error line dcrd logs (the end of this
guide). The seventeen after it, all of 2026-10-16, change how the node
does its work: on the path of an arriving block, in the flush log, in
the exists-address index's commit hook, in the database's flushes and
its lookups of nested buckets, in the ticket treap, in the rebroadcast
thread, on the reading thread (below), and in where a connected block's
scripts are checked (below). On 2026-10-13, on m3, in the same harness,
with no run marked as disturbed, `4700cf1` took 504.2 s, 513.4 s and
513.5 s at the defaults. Two of those three runs spent about 10 s longer
in their flushes' commit phase than the third, 80.6 s and 80.0 s against
70.5 s, and the records do not say why; with those seconds taken out the
three agree to within a second. In that session the block server read
15.7 to 18.0 GB from its drive in every run, where it had read none in
the runs of 2026-10-11 and at most 1.5 GB in those of 2026-10-12, so its
times are not a later point on the same curve as theirs. The seventeen
were not run as committed. Sixteen of them were run as a series of
builds on `4700cf1`, each adding one change or group of changes to the
build before, and every build of it also held a developer variable that
is not in the tree. The first build, `4700cf1` with the flush log's
processor times and that variable, ran at the speed of `4700cf1`
(505.6 s and 502.8 s); the last, with the other fifteen, took 441.9 s
and 442.2 s: 62 to 64 s, 12.3%, off a sync of about 504 s, with two runs
at each end, where the steps between are single runs. The seventeenth,
the script checks below, was run on `4700cf1` alone, twice: 491.3 s and
493.4 s, about 12 to 16 s less than the code it was added to, depending
on the measure, all of it after the assume-valid block. No build holding
both was run, so the two are not to be added, and the code as it stands
was not run in that session. dcrd was run once in it. The ledger's
section "Seven cumulative builds, the validation pool, a background
commit and dcrd" has every run, what each step is good to, and what was
not measured.

On 2026-10-16, on m3, in the same harness, `8fc9160`, which holds
`4700cf1` and the seventeen commits after it, took 421.2 s, 429.3 s,
432.1 s and 434.0 s at the defaults in four clean runs, a median of
**7.2 minutes** (430.7 s); a fifth, disturbed, was repeated. In the same
session `4700cf1` took a median of 516.2 s, so the seventeen took
85.5 s, 16.6%, off it, and dcrd v2.1.7 took 2,944.4 s, 49.1 minutes, in
one run: 6.84x in one session. That ratio rests on one dcrd run, whose
block server read 18.0 GB of its data from the drive where none of the
four runs of `8fc9160` read any, and the day's two dcrd runs (v2.1.6
took 2,944.5 s) are the slowest clean dcrd runs on record, which
suggests, and does not prove, a cost of 1 to 3% to dcrd; against dcrd's
runs of earlier sessions it is 6.70x and 6.65x. With
`--noexistsaddrindex` `8fc9160` took 351.3 s in one run. Its peak
resident memory was 2,952 to 3,339 MiB with the index on and 2,162 MiB
with it off. The same session measured the background commit (the
storage section below) on a build that is not the code of a commit, and
the code after `8fc9160`, which ports dcrd's changes since `6f6cf21b`
and carries the background commit, was not run in a sync that day. The
ledger's section "`8fc9160`, a background commit and dcrd v2.1.7" has
every run.

On 2026-10-17, on m3, in the same harness, `88c46c3`, then the code as
it stands, took 397.8 s, 396.6 s, 395.9 s and 395.3 s at the defaults, a
median of **6.6 minutes** (396.25 s), and two later runs 391.1 s and
395.8 s. dcrd v2.1.7 took 2,944.4 s and 2,926.4 s, so dcroxide was 7.43x
and 7.39x as fast in one session. dcrd ran slower on 2026-10-16 and
2026-10-17 than in the quiet runs of 2026-10-09 to 2026-10-13, where
v2.1.6 took 2,848.8 to 2,920.3 s, some of them from a dcroxide block
server, in sessions whose huge-page setting was not recorded; why is not
established. The block server read nothing from its drive in any run,
and transparent huge pages were `madvise` where they had been `always`
on 2026-10-16, so this session is not a later point on the same curve as
that one. With `--noexistsaddrindex` `88c46c3` took 343.9 s and 344.0 s,
and dcrd 1,317.2 s in one run, 3.83x. `88c46c3`'s peak resident memory
to the tip was 3,464 to 3,710 MiB with the index on and 2,202 and
2,203 MiB with it off; through the harness's `gettxoutsetinfo` call
after the tip, which flushes, and the shutdown, its high-water mark
reached 3,764 to 4,052 MiB with the index on. Every full sync, dcrd's
included, ended with the same UTXO set and block files. The ledger's
section "`88c46c3`, the background commit as committed, dcrd v2.1.7 and
two preloaded allocators" has every run.

On 2026-10-19, on m3, a build of the code of `797a213`, the ledger's K,
was run from a block server on another machine on the same LAN, a live
dcrd v2.1.7 node about 0.3 ms away that went on following the network,
in a series of its own, not to be set beside the loopback figures above:
from that server on 2026-10-18 `88c46c3` took 407.0 to 407.9 s, against
391.1 to 397.8 s from the loopback one the day before. The build was
made from a worktree before its code was committed, and its code differs
from that of `797a213` only by a doc comment and a test's local name. It
took 270.7 s, 271.5 s, 272.7 s and 271.8 s at the defaults, a mean of
**4.5 minutes** (271.68 s), and dcrd v2.1.7 took 3,014.6 s and
3,033.4 s, so dcroxide was 11.13x as fast in one session by the means,
11.05x to 11.21x over the eight pairings. dcrd ran slower than from the
same server on 2026-10-18, where it took 2,991.4 s, for a cause not
taken apart. With `--noexistsaddrindex` the build took 250.8 s and
249.6 s, and dcrd 1,336.3 s in one run, 5.34x. The build's peak resident
memory, read when the clock stopped with the node still syncing, was
2,456 to 2,470 MiB with the index on and 2,269 and 2,270 MiB with it
off, against dcrd's 1,836 MiB; nothing after the clock is recorded for
these runs. Since the node goes on syncing from a live server, they
record no end state either: in each the node's block at 1,116,035 was
the one every loopback sync ends on, and two syncs of the build from the
loopback server, at the defaults and with `--assumevalid=0` (below),
ended with the UTXO set and block files of every full sync from that
server since 2026-10-17. The ledger's section "One commit thread for the
life of the store, a sync that checks every script, and dcrd v2.1.7" has
every run.

The rate falls as the chain grows, and falls again where full
validation begins: by default both daemons skip connect validation,
script checks included, up to the built-in assume-valid block,
1,026,597. On m3 the node reached block 500,000 in
4.8 minutes, block 1,000,000 in 13.8 and the assume-valid block in 14.4.
The 89,438 blocks after it took another 3.2 minutes, about 461 blocks/s
on about five of the node's 16 threads, against 1,054 over the whole
chain. (The three runs of 2026-10-11 with all six changes reached the
assume-valid block in 9.6 minutes and took 2.5 for the blocks after it,
about 586 blocks/s. On 2026-10-12 the one run of `540b203` reached it
in 8.2 minutes and took 2.1 for the blocks after it, about 727
blocks/s, and the two runs with the read-ahead, of the build before its
review's fixes, reached it in 6.4 minutes and took 1.8, about 826 and
815 blocks/s. On 2026-10-17 the four runs of `88c46c3` reached it in a
median of 5.2 minutes and took 1.4 for the blocks after it, about
1,096 blocks/s. On 2026-10-19 the four runs of a build of the code of
`797a213`, from the LAN server, reached it in a mean of 3.5 minutes and
took 1.0 for the blocks after it, about 1,505 blocks/s.) New blocks are
past that point too, so a chain longer than the one measured should add
time, on a machine like m3, at the rate of the code that is run: about
1,505 blocks/s by the four runs of the code of `797a213` on 2026-10-19,
about 1,096 by the four runs of `88c46c3` on 2026-10-17, about 586 by
the three runs of 2026-10-11, about 727 by the one run of `540b203`, and
about 820 by the two runs of the read-ahead build, which is not the
committed code (the four runs before 2026-10-11's changes gave a median
of about 461), until a release moves the assume-valid block. With
`--assumevalid=0` every block is validated in full and none of these
figures apply. One sync of the build of 2026-10-19 with it, from the
loopback server, which read its data from its drive, took 583.4 s, which
is not a timing: beside a default sync made under the same condition it
took 307.9 s more to the assume-valid block and 0.5 s more after it,
with 4,399.8 s of processor time against 898.1 s, 3,661.2 s of it on its
15 script-checking threads, and it ended with the UTXO set and block
files of the default syncs from that server.

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
the 12.1 minutes of 2026-10-11 a mean of 211 Mbit/s, and the two
8.2-minute runs of 2026-10-12 a mean of 311 and 313 Mbit/s.
Budget from your link's latency and bandwidth as well as from these
figures; the delayed-link runs of 2026-10-11 are in
[bench-ledger.md](bench-ledger.md), and no whole sync over the internet
has been measured.

By default dcroxide now requests blocks through a window of its own
([PARITY.md](PARITY.md), *Block download window*): up to 128 blocks
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
the default window over a delayed link, or over a real one with a
longer round trip than a LAN's: the only whole syncs over a real link,
on 2026-10-18 and 2026-10-19, took their blocks from a node on another
machine on the same LAN ([bench-ledger.md](bench-ledger.md), "Rungs from
a block server on the LAN, two changes held for their memory, and dcrd
v2.1.7" and "One commit thread for the life of the store, a sync that
checks every script, and dcrd v2.1.7"). So there is no sync time to
budget from for a longer round trip, and the 72 minutes and 3.6 hours
above are not its figures.

The wider window can cost a node its sync peer where dcrd's would not,
in two cases. Neither has been measured; both are read from the code. A
requested block has to reach the thread that processes blocks within
30 to 45 s of being asked for (one read off the socket ahead of that
thread, as below, does not count until its turn comes), so
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

During the initial sync dcroxide also reads its sync peer's connection
ahead of the thread that processes the blocks, which dcrd does not do
([PARITY.md](PARITY.md), *Reading ahead of the block handler*). Once
that peer has delivered a first block, a thread of its own reads the
connection, checks each message's checksum and decodes it, and for a
block hashes its transactions, builds its two merkle trees, counts its
signature operations, makes the checks of the block's data that need no
chain state, and lays the bytes it arrived in out as its block-file
record, after comparing them with the block's own serialization. It
keeps at most sixteen messages ahead of the thread that processes
blocks, which still handles every message in the order it arrived, and
stores a block that comes with its record as that record, without
serializing it again. It changes nothing about which blocks or messages
are accepted, which peers are dropped or banned, or what is logged about
them, beyond lines of its own (below, and two more at the debug level in
PARITY.md): it moves work, and the one verdict it reaches, on a block's
data, is acted on only where the thread that processes blocks would have
reached it, with the same result. PARITY.md names the tests that hold it
to that and what they leave uncovered. One pair of counters shows it:
`getnettotals` counts a message's bytes when it is read and
`getpeerinfo`'s `bytesrecv` for that peer when it is handled, so the
total can lead the peer's count by up to sixteen messages.
It costs one more thread and one more descriptor on that one
connection, kept until the connection ends, and the memory of up to
sixteen decoded messages, each kept with the frame it was read in. By an
estimate from the sizes of the structures, not a measurement, those
sixteen are about 880 kB for main network blocks of mean size, under
1 MiB. At worst, from a hostile sync peer sending the largest blocks
made of the smallest transactions, the connection holds about 211 MB
with the block being handled and every frame counted: the frames, at
most 22,282,716 bytes, which is a bound (sixteen queued and the one
being handled, each at most the largest block message and 28 bytes), and
the blocks decoded from them, about 189 MB, which is the estimate. About
1.3 MB more is held for a moment while one frame is compared with its
block's serialization, or up to about 1.4 MB while one block's merkle
trees are built, against about 12.5 MB for one such block without the
read-ahead. The signature pre-verification (below) holds those same
blocks, not copies: its bound, 22,282,240 bytes of serialized blocks,
the sixteen messages and one more of the largest size, is counted in the
blocks above, and its own list of the inputs it guesses for, 12 bytes
for each, comes to at most about 2.8 MB at that bound, an input taking
at least 94 bytes of a block, in an allocation grown by doubling that
stays under about 5.7 MB. With four messages, the bound before sixteen,
the estimates were about 220 kB and about 62 MB. The read-ahead
was measured on m3 on 2026-10-12, on a quiet machine
with the node held to eight of the machine's cores, with one binary:
two default syncs to block 1,116,035 over loopback took 494.6 s and
490.8 s with it, and two with `DCROXIDE_READ_AHEAD=off` took 597.6 s
and 599.0 s, so 17.2% and 18.1% less, with peak resident memory of
2,967 and 2,921 MiB against 3,273 and 3,256 MiB, which is not
explained. Those four runs are of the build made before a review's
fixes to it, so none of these is a figure to budget from, and all are
of later code than the 12.1 minutes above. The read-ahead as `b4ceb1c`
committed it was run on 2026-10-13, inside `4700cf1` and only on
(above), so what it gains as committed has not been measured; the
reading thread's added work, the record and the merkle trees, has been
measured apart only in builds that are not the code as it stands (the
count of signature operations it also makes has been run in syncs only
beside another change, its scan of each block above the floor for inputs
to hand to the pre-verifier only on top of a change that was not kept,
and the checks of a block's data in one step that did not resolve them,
below), where it moved about 7 s and 5 s of processor time from the
thread that processes blocks to the reading thread rather than removing
it, which paid there because the reading thread, fed by a server on the
same machine, waited over 320 s for the other; in `88c46c3`, on
2026-10-17, it waited 275 to 278 s for the other in each default run. No
sync has been run with it over a delayed link, or over a real one with a
longer round trip than a LAN's (the syncs of 2026-10-18 and 2026-10-19
from a node on another machine on the same LAN had it on), where the
round trip and not the thread that processes blocks may set the pace and
it may gain nothing, nor on fewer cores, nor on macOS or Windows, where
none of its tests has been run either. With `--assumevalid=0` it was on
in one sync, on 2026-10-19 from a block server on the same machine
([bench-ledger.md](bench-ledger.md), "One commit thread for the life of
the store, a sync that checks every script, and dcrd v2.1.7"), and with
`--noexistsaddrindex` in one of `4700cf1` on 2026-10-13, two of
`88c46c3` on 2026-10-17 and five from that LAN node on 2026-10-18 and
2026-10-19, none of them against a run with it off.

Whether reading ahead ever costs anything has not been measured: the
loopback runs above are all there is. Set `DCROXIDE_READ_AHEAD=off` (or
`0`) and restart the node to have every connection read one message at
a time by its own thread alone, as dcrd reads: to rule the read-ahead
out when a sync peer's connection misbehaves, to hold the sync peer's
connection to one decoded message at a time when that peer is not
trusted, or to compare the two. The node then logs `Read-ahead of
blocks disabled by DCROXIDE_READ_AHEAD` at startup. With it on, the one
line of its own that a node logs at the default level between its
startup and its shutdown is a warning under `PEER`, `Unable to start a
read-ahead thread for peer P: E -- reading on the input thread`, when
the operating system refuses the thread: that connection goes on being
read by its own thread, as it was until then. A node that read ahead
also logs one line under `SRVR` as it shuts down, just before `Server
shutdown complete`, or before the pre-verification's line (below) when
there is one:

```text
Read-ahead: N blocks (B bytes) on C connections; checksum and decode X s and hashing Y s done off the block thread; the reader waited G s for the block thread; the block thread waited W s for the reader; at most Q items queued; index queue full for I s; block-file records laid out for R blocks in Z s, K written as laid out
```

N blocks of B bytes were read by the reading threads of C connections;
the first block of a connection is not among them, since the thread
that processes blocks read that one itself. X and Y are the time the
reading threads spent on checksums and decoding and on hashing, which
the thread that processes blocks no longer spends; the socket reads
moved too and are not timed. Since `44cf801` Y also covers building each
block's two merkle trees, and it now also covers counting each block's
signature operations twice and checking its data, so it is not to be
compared with a Y from earlier code. G is how long the reading threads
stood still with sixteen messages waiting: when it is most of the sync,
the thread that processes blocks set the pace and the reading kept up. W
is how long the thread that processes blocks waited for a block with
none ready. By the counter's definition, and not seen in a run, a large
W means the peer, the link or the reading itself was the slower side,
and reading ahead had less to give. Q is the most messages that waited
at once, and is never more than sixteen (four in builds before the bound
was raised). I is how long handing blocks to the
index thread waited for room in its queue, which is time the indexes
set the pace; it is counted whether or not anything is read ahead, and
printed in this line only. R is the blocks the reading threads handed
over laid out as their block-file records, and Z the time they spent
laying them out: serializing each block, comparing the bytes it arrived
in with that serialization, taking the record's checksum and hashing
the header once more, the serialization and the checksum being work
the thread that processes blocks does for every block that comes
without a record. R below N means bytes that were dropped for not
matching the serialization, which is not expected. K is the records
the block database wrote as they were handed to it, counted over the
life of the database: below R by the blocks the chain did not store,
and 0 beside an R above 0 when the database laid every record out
again, as it does for a record laid out for another network. The line
ended with I before `a589c4a`. In the two runs above with it on, of
the build of 2026-10-12, the line reported 1,116,034 blocks and
19,215,875,473 bytes on one connection
(printed as `1116034 blocks (19215875473 bytes) on 1 connections`),
with X at 45.829 s and 45.886 s, Y at 47.209 s and 47.246 s, G at
382.350 s and 378.719 s, W at 0.271 s and 0.273 s, Q at 4 and I at
3.191 s and 3.265 s. X and Y together are 93.0 s and 93.1 s, less than
the 103.0 s and 108.2 s the syncs gained, and what the rest is was not
established. In the three runs of 2026-10-13 whose builds held the
record, none of them the code as it stands, R and K were both
1,116,034, every block read ahead, and Z was 7.078 s, 7.128 s and
7.165 s; Y was 47.369 s in the first, whose build had no merkle trees
on the reading thread, and 52.536 s and 52.562 s in the two whose build
had them. On 2026-10-18, from a block server on another machine on the
same LAN, in a series of its own whose line counted blocks past
1,116,035 up to the shutdown, Y was 52.52 to 52.94 s in the runs of
three builds without the counts of signature operations and 56.70 and
57.00 s in the two runs of the build that added them, together with a
change that runs nothing on the reading thread; that thread's processor
time rose 3.9 s with them ([bench-ledger.md](bench-ledger.md), "Rungs
from a block server on the LAN, two changes held for their memory, and
dcrd v2.1.7", build B). In that series' runs of the afternoon, another
session, Y was 57.96 to 57.98 s in the three runs of a build without the
checks of a block's data and 63.03 and 63.06 s in the two runs of the
build that added them, whose syncs took 3.32 s less by the means, which
that session's spread does not resolve; with them that thread's
processor time rose 5.2 s and that of the thread that processes blocks
fell 5.3 s (the same section, build H).

After the assume-valid block the node also keeps threads for checking
scripts. dcrd starts goroutines for each batch of a block's inputs.
dcroxide, since `f60ae3a`, checks each transaction tree with 4 script
items or more of a block it connects on helper threads that live as long
as the process, the thread that processes blocks checking with them
([PARITY.md](PARITY.md), *Script checks of a connected block*). They
are named `scriptval-N`, are created as batches or the signature
pre-verification below want them, as many as the widest batch so far
less one, or as the pre-verification may hold if that is more, and never
more than one fewer than the logical CPUs the process may run on, and
are parked, using no processor time, while there is nothing to check.
Before the assume-valid block no script is checked and no signature
pre-verified, so a sync from genesis starts none until then, and a node
that has checked scripts keeps the ones it made until it exits. Count
them against a task limit (`TasksMax` under systemd, a cgroup's
`pids.max`, `RLIMIT_NPROC`). A helper the operating system refuses costs
speed only: the thread that processes blocks and the helpers there are
do its share, nothing is logged, and no creation is tried again before
the 1,024th batch after that one. No `DCROXIDE_` variable sets their
number; `DCROXIDE_PREVERIFY` (below) sets only how many of them may
pre-verify at once. In the two syncs of 2026-10-13 of `4700cf1` with
these threads added (above), on a node held to eight cores, 16 hardware
threads, 15 of them were there at the end, and peak resident memory,
read before the closing flush, was 2,998 and 2,908 MiB, inside the 2,832
to 3,128 MiB of the three runs of `4700cf1` without them.

During the initial chain sync the same helpers also check signatures
ahead of the thread that processes blocks, which dcrd does not do
([PARITY.md](PARITY.md), *Signature pre-verification ahead of the
block thread*). While the sync peer's connection is read ahead, its
reading thread hands each block it has read to them, unless the chain
will check none of its scripts, and the inputs that spend a
pay-to-pubkey-hash output, told by the shape of their signature scripts
(a signature of the `SigHashAll` type and a public key), are verified
into the signature cache, where the chain then finds them as it connects
the block. Once the initial chain sync is done, nothing more is handed
to them. By default at most two fewer helpers than the physical cores
the process may run on do this at once, plus one for every two logical
CPUs beyond those cores, counting at most one beyond each core, and at
least one from two cores. Where the cores are read, that is two fewer
than the cores without SMT or with one hardware thread of each core
allowed, and ten with two hardware threads to each of eight cores,
where the rule before 2026-10-22, two fewer than the cores alone, gave
six. Where the cores cannot be read, as on Windows and macOS, they are
taken to be half the logical CPUs, so that sixteen logical CPUs give
ten there, with or without SMT, where they gave six. The helpers do this
only while no block being connected wants them; the thread that
processes blocks takes a block back as it reaches it and checks whatever
was not reached itself. Set `DCROXIDE_PREVERIFY=off` (or a whole number
that is zero, such as `0`, `00` or `+0`) and restart the node to turn it
off, from
the same binary; the node then logs `Signature pre-verification disabled
by DCROXIDE_PREVERIFY` at startup. A positive whole number sets the most
helpers instead, never more than one fewer than the logical CPUs the
process may run on; the node logs the number in effect as `Signature
pre-verification on at most N helper threads by DCROXIDE_PREVERIFY`, or,
when it can start none, `Signature pre-verification not started:` and
the reason. Any other value is the warning `DCROXIDE_PREVERIFY=V is
neither off, 0 nor a whole number of helper threads; using the default`,
and the default stays. It does nothing with `DCROXIDE_READ_AHEAD=off`,
which has no reading thread, or with `--sigcachemaxsize=0`, which keeps
no entry; with `--assumevalid=0` it starts at the first block read
ahead. A cache much smaller than the default 100,000 entries keeps the
entries made for the blocks ahead for less long; how many of them are
evicted before their block is connected has not been measured. It was
measured in syncs on 2026-10-18, from a block server on another machine
on the same LAN, in a series of its own: the build that added it, on top
of other changes, one of them not kept, took 7.95 s less than the build
below it by the means of two runs each, 8.50 s less after the
assume-valid block, and the script threads' processor time 29.0 s less;
and one build of `88c46c3`'s code with it, run once with it on and once
with `DCROXIDE_PREVERIFY=off`, took 7.4 s less with it on, its connect
checks finding 60.5% of the signatures they looked up in the cache
([bench-ledger.md](bench-ledger.md), "Rungs from a block server on the
LAN, two changes held for their memory, and dcrd v2.1.7", build G and
the prototype pair). The default's count beyond the cores rests on one
comparison, on 2026-10-19 with the node held to eight cores and their
SMT siblings, in a build of `797a213`'s code that read the read-ahead's
depth from a variable, at sixteen frames: at most ten helpers, set with
`DCROXIDE_PREVERIFY=10`, checked 90.2% and 89.3% of the guessed inputs
ahead, against 65.5% to 66.2% at six, and the syncs took 5.02 s less by
the means of two runs and three, about ±2.6 s, for 29.83 s more node CPU
time ([bench-ledger.md](bench-ledger.md), "Where `797a213`'s block
thread waits, a deeper read-ahead and a rung of four changes"). No other
count was run, nor any machine without SMT or with another core count,
nor ten helpers on the code as committed. Where that processor time is
better spent on other work, a smaller `DCROXIDE_PREVERIFY` holds fewer.
A node that pre-verified also logs one line under `SRVR` as it shuts
down, after the read-ahead's:

```text
Signature pre-verification: B blocks with I inputs to guess for on at most W helpers; C inputs checked ahead of the block thread, V verified; K blocks cut short by the block thread or the shutdown; R refused for room
```

B blocks were handed to the helpers, with I inputs of the guessed shape
among them; W is the most helpers at once. C of those inputs were
checked before the thread that processes blocks took their block, and V
of them verified against the guessed script, which puts or keeps their
signatures in the cache; C less V are inputs whose spent script the
guess got wrong or whose signature does not verify. K blocks were taken
back by the thread that processes blocks, or let go at shutdown, with
inputs left unchecked: when K is close to B the helpers fell behind. R
blocks were refused because the queue held as many bytes as it may,
which is not expected.

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
flushes taking 107–110 s, 15% of it. In the nine syncs of 2026-10-12 on
a data directory as created, of the code from `b4a5d2d` to the
read-ahead build (above), a sync made 54 to 56 flushes taking
104–111 s: 15% of the longest sync and 21% of each of the two shortest,
so once more the flush time did not grow and the sync got shorter.
Those nine passed 39.6–40.3 GB to write calls, as the three of
2026-10-11 did (39.7–39.8 GB). Counts of write calls, which the ledger
records, are not comparable across `7c6ec9a`, the third of that day's
changes: it writes each block record with one positioned write where
there were a seek and four writes, so three fewer write calls and one
fewer seek for every block record, with the same bytes. Since
`a589c4a` the record of a block the reading thread read (above) is
built and checksummed on that thread, from the bytes the block arrived
in, and not at the commit, which still writes it with that one
positioned write. This guide used to describe a node fully stalled on
storage for
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
On 2026-10-13 one sync of `4700cf1` with the index off took 423.6 s,
against 504.2 s to 513.5 s in three with it on (the sync budget above
has that session's label). The index's commit hook has changed since
(`64359e7`). On 2026-10-16 `8fc9160`, which has that hook, took 351.3 s
with the index off in one run, against a median of 430.7 s over four
with it on (the sync budget above has that session). On 2026-10-17
`88c46c3` took 343.9 s and 344.0 s with the index off against a median
of 396.25 s over four with it on, so the index cost it 52.3 s, 13.2% of
its sync, and its data directory was 2.0 GiB smaller. On 2026-10-19 a
build of the code of `797a213` took 250.8 s and 249.6 s with the index
off against a mean of 271.68 s over four with it on, from a block server
on the LAN, so the index cost it 21.5 s, 7.9% of its sync; those runs
record no data directory's size.
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
[PARITY.md](PARITY.md): a storage read error answers "Could not query
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
more on disk (27.89 against 25.88 GiB). On 2026-10-12 the index's work
for a block was moved ahead of its wait for the database's writer, and
its key comparisons were made inline
([ADR-0011](adr/0011-exists-address-layout-3-and-the-flush-participant.md),
addendum of that date). With those two and a change to the ticket
database that was measured with them, one sync with the index on took
628.0 s where the run before them took 673.8 s. No sync ran with the
index off that day, so the 16% is the index's share on `b4a5d2d`. On
2026-10-13 `4700cf1`, which holds those changes, took 423.6 s with the
index off in one run, 80.6 s to 89.9 s less than each of its three
runs with it on, two of which had slow commit phases (the sync budget
above). On 2026-10-16 `8fc9160`, whose index hook is the changed one,
took 351.3 s with the index off in one run, 69.9 s to 82.7 s less than
each of its four clean runs with it on. On 2026-10-17 `88c46c3` took
52.3 s less with the index off, two runs against four, 13.2% of its
default sync (the sync budget above). On 2026-10-19, from the LAN
server, a build of the code of `797a213` took 21.5 s less, two runs
against four, 7.9% of its default sync, and dcrd v2.1.7 1,687.7 s less
in one run against two, 55.8% of its own (the sync budget above).

- **Memory**: the index's in-memory set holds up to about 3 million
  addresses (about 63 MB) after each flush while syncing, and up to about
  4 million (84 MB) just before one; a catch-up from genesis peaked at
  4.5 million (95 MB). Those figures are from before the change to
  commits of 2026-10-11. Since it, with the index pacing most commits
  of a sync, the set has held 4.5 million at the start of its fullest
  flush in every sync measured with the index on at the defaults, those
  of 2026-10-12 and 2026-10-13 included. It also takes in, at each
  block, every address the mempool has seen since the last block, so a
  very large mempool adds to that. The index's pages also fill the
  metadata page cache (`DCROXIDE_DB_CACHE`, below) up to its configured
  size. On m2's tail,
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
  What in it holds that memory has not been found. That is the code of
  2026-10-11, `b4a5d2d`. On 2026-10-12 seven syncs on a data directory
  as created, of that code and of five steps after it, peaked at
  3,204–3,299 MiB without the read-ahead, and the two with it (the
  build before its review's fixes) at 2,967 and 2,921 MiB. None ran
  with the index off. On 2026-10-13 `4700cf1` peaked at 2,149 MiB in
  one run with the index off against 2,832 to 3,128 MiB in three with
  it on, each read before the closing flush, and on 2026-10-16
  `8fc9160` at 2,162 MiB in one run with it off against 2,952 to
  3,339 MiB in four with it on. With the metadata commit on a thread of
  its own (since `02b802c`), up to `u_max` more keys, 1.5 million at the
  defaults, can arrive while a flush's commit is under way, before that
  flush's `finished` lets go of the keys it merged, so the set can hold
  up to 6.0 million (126 MB) then; how many it held in the syncs of
  2026-10-16 and 2026-10-17 was not read. On `88c46c3`, on 2026-10-17,
  the peak to the tip was 2,202 and 2,203 MiB in two runs with the index
  off against 3,464 to 3,710 MiB in four with it on, so the index adds
  about 1.2 to 1.5 GiB (1,261–1,508 MiB) there. The megabytes given
  above for the set count its keys alone, 21 bytes each. Each memtable
  partition now also keeps a Bloom filter of its keys
  ([ADR-0011](adr/0011-exists-address-layout-3-and-the-flush-participant.md),
  addendum of 2026-10-17), which adds at most 2 bytes a key and one
  64-byte block a partition: up to about 8 MB at 4 million keys, 9 MB at
  4.5 million and 12 MB at 6.0 million. None of the peaks above is of a
  build with the filters. They were first run in syncs on 2026-10-18,
  from a block server on another machine on the same LAN, where two runs
  of one build differed by up to 235 MiB in peak resident memory in the
  morning's rungs, and by more in the afternoon's, so what the filters
  add to it is not resolved ([bench-ledger.md](bench-ledger.md), "Rungs
  from a block server on the LAN, two changes held for their memory, and
  dcrd v2.1.7"). On 2026-10-19, from the same server, a build of the
  code of `797a213`, which has the filters, peaked at 2,456 to 2,470 MiB
  in four runs with the index on and at 2,269 and 2,270 MiB in two with
  it off, read with the node still syncing (the sync budget above).
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

Four settings tune the metadata store: how much it caches and how often
it commits. Three are measured and one is not; the numbers are in
[bench-ledger.md](bench-ledger.md) and the reasoning in
[ADR-0004](adr/0004-storage-backend.md). A fifth,
`DCROXIDE_DB_SYNC_COMMIT`, sets which thread makes its commits rather
than how often, and is described with the environment variables
below. Its default, the commit on a thread of its own, was measured on
m3 on 2026-10-16 on a build that is not the code of a commit, against
the same build without it, four runs each: 389.55 s against 429.45 s by
the medians, 9.3% less, at 27 s more process CPU time and about 256 MiB
more peak resident memory to the tip (the memory below; the ledger's
"`8fc9160`, a background commit and dcrd v2.1.7" has the runs). On
2026-10-17 `88c46c3` was measured against itself with the variable set,
four runs at the default against two: 396.25 s against 429.2 s by the
medians, 7.7% less and less in every pairing, at 32.3 s and 33.7 s more
process CPU time and 205.5 and 254.5 MiB more peak resident memory to
the tip, and both arms ended with the same UTXO set (the ledger's
"`88c46c3`, the background commit as committed, dcrd v2.1.7 and two
preloaded allocators"). On 2026-10-19 a build of the code of `797a213`,
whose `dbcommit` thread writes each flush's rows as well as its commit
and is kept for the life of the store, was measured against itself with
the variable set, from a block server on another machine on the same
LAN, four runs at the default against two: 271.68 s against 350.40 s by
the means, 78.7 s or 22.5% less, with the flushes in the foreground for
2.5 to 2.8 s of each run against 106.1 s and 106.5 s, and it peaked
lower at the default, at 2,456 to 2,470 MiB against 2,959 and 2,964 MiB,
for 893.7 to 902.9 s of process CPU time against 877.8 s and 874.6 s
(the ledger's "One commit thread for the life of the store, a sync that
checks every script, and dcrd v2.1.7"). Neither arm's end state was
recorded.

**Since 2026-10-11 a sync commits less often, and the overlay's default
ceiling is 300 MiB.** Until then every UTXO cache flush forced a durable
commit, about 120 of the 133 in a sync, and the overlay's own ceiling of
100 MiB hardly mattered. Now a flush the size limit trips shares the
next commit (the paragraph on unclean stops near the top has what that
risks). That commit comes when the overlay holds two thirds of its
ceiling or, with the exists-address index on, when the index has taken
about 1.5 million new keys since its last flush, which is what trips
most of them after the first few minutes of a sync; in the syncs of
2026-10-11 about one in ten was the two-minute rule's, which since
2026-10-19 counts from the last UTXO cache flush any durable commit
carried, so how often it comes due in a sync now has not been
counted ([PARITY.md](PARITY.md), *Periodic UTXO cache flush
interval*). On m3 on 2026-10-11 the code before the change
took 775.6 s with 133 flushes in one sync, a prototype of the change
took 724.6 s with 52 flushes at 300 MiB and 736.9 s with 63 at 200 MiB,
and the change as made took a median of 728.7 s over three syncs, with
54 flushes. It costs memory: peak resident memory was 3.0–3.2 GiB in
those three runs against 2.6 GiB before, and 2.1 GiB with the
exists-address index off, where the index-off sync of `c128a93` peaked
at 1.9 GiB. So nearly all of the extra appears to come with the index,
though the code before the change was not run with the index off; what
in it holds the memory has not been found. Since `02b802c` the commit of
most flushes runs on a thread of its own, and while it runs the layers
it captured stay in the overlay beside the new ones. On 2026-10-16 a
build with it peaked about 256 MiB higher to the tip than the same
build without it (medians 3,533 and 3,277 MiB, four runs each), and
its shutdown flush took it to 3.84 to 4.14 GiB by its flush log; the
build without it was not read there. On 2026-10-19 a build of the code
of `797a213`, whose `dbcommit` thread writes the rows as well and lives
as long as the store, peaked lower with the commit on that thread than
with `DCROXIDE_DB_SYNC_COMMIT=1` (above). `DCROXIDE_DB_OVERLAY=100`
should put the overlay's part of the cadence back to about one commit
per UTXO cache flush, and restores the old ceiling in the header sync,
where the larger one should also mean fewer commits; neither was run on
the new code. A catch-up of the exists-address index is paced by the
index itself and does not change. The paragraphs below describe
measurements made before this change, and where they say a UTXO cache
flush forces a commit, that was so then.

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
changes, where the flush time was the same and the sync shorter, 15%
with the sixth, which makes 54 flushes, and up to 21% in the shorter
syncs of 2026-10-12, whose 54 to 56 flushes took as long), where
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
overlay entry as dcrd does, at 72 bytes plus its key and value, while an
entry, since its key holds its first sixteen bytes inline, asks the
allocator for about 97 bytes beside its key and value (74 before, about
its count), so what the overlay holds runs about 10% above its count for
a mainnet sync's rows (about 260 counted bytes an entry) and about a
quarter above it for rows as small as a 25-byte key with no value, with
the allocator's own overhead on top. The 97 is a counting allocator's
figure over 200,000 entries; the excess has not been measured in a sync,
and the peak memory of builds A1 and A2 in the ledger's "Rungs from a
block server on the LAN, two changes held for their memory, and dcrd
v2.1.7" does not resolve it.
Before 2026-09-23 entries were counted at key and value bytes only, which
let the overlay hold 2–4× the configured figure. The 12.7%
measurement for `DCROXIDE_DB_OVERLAY=800` below was taken under that older
accounting, so the same setting now flushes a smaller overlay. The
re-measurements since, on m3, found no gain: the one above, and one run
on 2026-10-13 at 450 MiB together with a developer setting that is not
in the tree (the ledger has it). Unset, both keep the compiled
defaults.

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

**The filesystem under the data directory is part of the commit cost,
and on m3 what btrfs's copy-on-write, checksums and compression add has
been measured.** m3's data volume is btrfs with zstd compression over
an encrypted mapping. A data directory created with the
no-copy-on-write attribute (`chattr +C` on the empty directory), which
turns those three off for the files made in it, was run against one
created as usual three times, one sync each on a quiet machine
([bench-ledger.md](bench-ledger.md), "Shared commits for UTXO-cache
flushes, the filesystem's share and a delayed link" and "Eleven
changes, a background commit not kept and a pool gate"). `7d31abb`, the
code before the change to commits of 2026-10-11, took 736.8 s against
775.6 s that day, 5.0% less; a prototype of that change, run that day
with `DCROXIDE_DB_OVERLAY=300`, the ceiling the change as made has by
default, took 707.3 s against 724.6 s, 2.4% less; and the change as
made, `b4a5d2d`, took 714.1 s against 728.5 s on 2026-10-12, 2.0% less.
The flushes took 144.0 s against
177.8 s, 86.7 s against 104.8 s and 97.1 s against 107.4 s, and the
volume took 52.3, 40.4 and 41.6 GB where it took 91.6, 53.4 and
53.2 GB, for nearly the same bytes passed to write calls. In these
three pairs the attribute saved less where a sync made fewer commits:
38.8 s with 133 of them, and 17.3 s and 14.4 s with 52 to 55. This is a
measurement of one stack and not advice. The encrypted mapping was
under both directories, what ext4 or xfs would do with the same writes
was not measured, none of the code after `b4a5d2d` was run this way,
and a directory made this way gives up the filesystem's own checksums
of the node's files.

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
| metadata commit on the committing thread | `DCROXIDE_DB_SYNC_COMMIT` (unset, or not valid Unicode, = on a thread of its own; a positive whole number = on the committing thread, as dcrd; anything else warns and keeps the default) | — |
| exists-address memtable target (developer-only) | `DCROXIDE_EXISTSADDR_MEMTABLE_KEYS` (keys, default 2,000,000) | — |
| block download window | `DCROXIDE_BLOCK_WINDOW` (`dcrd`, or a whole number of blocks from 16 to 505; default this port's own window, at most 128 blocks and 3,145,728 bytes) | — |
| block read-ahead | `DCROXIDE_READ_AHEAD` (unset = on; `off` or `0` = off; anything else warns and stays on) | — |
| signature pre-verification | `DCROXIDE_PREVERIFY` (unset = on, on at most two helper threads fewer than the physical cores plus one for every two logical CPUs beyond them, at most one beyond each core; `off`, or a whole number that is zero, = off; a positive whole number = at most that many helpers, never more than one fewer than the logical CPUs; anything else warns and keeps the default) | — |

The chain itself lives under the home directory, not at it: `--datadir`
defaults to `<home>/data` with the network appended, so on Linux the
blocks are in `~/.dcroxide/data/mainnet` while `dcroxide.conf`,
`rpc.cert` and `rpc.key` sit in `~/.dcroxide` itself.

Those eleven are the only `DCROXIDE_*` variables read; only the first
two have dcrd counterparts, since the page cache, the overlay, the
flush log and the thread a commit runs on are properties of this
port's metadata store over redb, which dcrd does not use (dcrd
commits on the thread that holds its write lock, as
`DCROXIDE_DB_SYNC_COMMIT` does; [PARITY.md](PARITY.md), *Where a
cache flush's commit runs*), the
memtable is a property of this port's exists-address layout, the
download window is this port's own rule for requesting blocks
([PARITY.md](PARITY.md), *Block download window*), and the
read-ahead is a thread dcrd does not have (*Reading ahead of the block
handler*), and pre-verification is work dcrd does not do (*Signature
pre-verification ahead of the block thread*). Of the five
storage variables, `DCROXIDE_DB_CACHE` is the one to leave unset, the
next two are untuned instruments (see the storage tuning above),
`DCROXIDE_DB_SYNC_COMMIT` is the way back to dcrd's place for a
metadata commit (below), and `DCROXIDE_DB_FLUSHLOG` is diagnostic: it
appends one JSON object per
metadata flush (sequence, end instant, duration, entries, bytes), which
is how the 90–98% attribution above was measured, and also, for each of
the flush's three phases (block-file sync, insert loop, commit), its time
and, on Linux, the bytes the flushing thread read from storage and the bytes
it dirtied in that phase. `write_bytes` counts pages when they are dirtied,
not when they are written back, so writeback time shows in a phase's `ms`
and not in its `write_bytes`, and the block-file sync always reads about 0
there. Since 2026-10-16 each phase ends with the flushing thread's
processor time in it, four fields after those three. `utime_ms` and
`stime_ms` are the milliseconds it ran in user mode and in the kernel,
from `/proc/thread-self/stat`, which counts in clock ticks of 10 ms;
`on_cpu_ns` and `runq_wait_ns` are the nanoseconds it was on a
processor and the nanoseconds it was runnable but waiting for one, from
`/proc/thread-self/schedstat`. What a phase's `ms` holds beyond those
last two the thread spent asleep, waiting for storage or for a lock.
All four are `null` off Linux, and the last two on a kernel without
that file. The kernel brings those counters up to date at a scheduler
tick or a context switch, so a figure can be off by a tick at either
end of a phase, and a phase of a millisecond or two can show more
processor time than its `ms`: sums over a sync mean something, single
short phases do not. No field the lines had changed its name, place or
format. Since 2026-10-17 eight more keys follow `commit`, before
`participant`: `explicit`, whether the flush was asked for by a caller
that waits for it to be durable (`Database::flush` or the close) rather
than tripped by a commit or, since 2026-10-19, asked for by the chain's
periodic UTXO cache flush, which the line does not tell from a tripped
one, with `DCROXIDE_DB_SYNC_COMMIT` set or not, so the `explicit` lines
of a sync no longer count the two-minute rule's flushes as those of
earlier builds did; `bg`, whether its block files were synced and its
rows and commit written on the thread `dbcommit`; `fg_ms`, the part of
`elapsed_ms` the capturing thread spent holding the database's writer,
all of it unless `bg` and then the capture to the hand-off, which holds
the taking of what the block-file sync owes, the opening of the write
transaction and the exists-address index's seal, and, since
2026-10-19, not the sync itself;
`wait_ms`, the time spent since the flush before was captured, outside
`elapsed_ms`, waiting with the writer held for an earlier flush's commit
to end: the capturing thread's wait before its capture, and any other
thread's, such as a commit's at the write cache's ceiling, which counts
against the next capture whichever thread makes it; `snap`, whether the
commit held a read snapshot of the store, which a flush takes only for a
commit it hands to `dbcommit`, so in the daemon it is `bg` but on the
rare line of a flush whose thread the operating system refused (`snap`
true, `bg` false) or for which no snapshot could be had (`bg` true,
`snap` false); `layers` and `overlay`, what the flush pinned in the
write cache; and `mem`, the process's resident memory, its peak, its
anonymous part and its thread count at the capture (`capture`), the
hand-off (`handoff`), when the commit returned (`commit`) and twice at
the end of the flush before (`prev_finished`, once the index was told,
and `prev_end`), with `prev_finished_ms` and `prev_release_ms`, the
times from that flush's retirement to each. Since the rows moved
onto `dbcommit` on 2026-10-19, after the change of that day that
keeps the thread, the `handoff` reading is taken once the flush's
write transaction is open, before any row is written, on every
flush that commits, handed over or not. Before, it was taken once
the overlay's rows and the exists-address index's had been written
into that transaction, so the `mem.handoff` of earlier builds holds
what writing them had allocated by then, and neither it nor
`mem.commit` less `mem.handoff` compares across the change.
`overlay.handoff` reads the same at either point, since nothing
commits between them. The readings at the capture
and when the commit returned add `arena_maps`, `arena_bytes` and
`brk_bytes`, the count and span of the anonymous mappings that start on
the 64 MiB boundary where glibc's allocator places a thread arena's
heaps, and the program break: a heuristic for glibc, which says nothing
of what an allocator holds free, and meaningless under another. Every
reading is `null` off Linux. `elapsed_ms` on a `bg` line runs from the
capture to the retirement of what was captured, on `dbcommit`, and
`fg_ms` plus `wait_ms` is what the flush, with the waits counted against
it, kept every other writer out for, so sums of it by thread divide that
time only roughly. A flush that committed on its capturing thread frees
the layers it retired once that thread has released the writer, after
its own line's readings, so the next line's `prev_end` and
`prev_release_ms` do not hold those frees; after a `bg` line they do.
Each line's `participant` is what the exists-address index wrote
inside that flush -- its rows, reads, journaled keys, merges, base
rewrites and memtable size, with its own time, I/O and processor time
as a fourth phase -- or `null` when it had nothing to write. Since
2026-10-12 each line ends with two more fields. `thread` is the name of
the thread that ended the flush, or `null` for a thread without a
name: the thread that ran it, which held the database's writer for its
`elapsed_ms`, or on a `bg` line `dbcommit`, which never holds the
writer. Since 2026-10-19 `dbcommit` is one thread for the whole run,
started by the first `bg` flush and asleep between flushes until the
shutdown's close stops it, where before each `bg` flush made one that
ended with it. So `ps -L`, `top -H` and a sampler of the node's threads
list it from that flush on, busy or idle, so its presence says nothing
of a commit under way, and what `/proc` counts for it, processor time
and I/O, adds up its part of every `bg` flush so far. A `mem` reading
taken on another thread while it sleeps counts it, as those at the
capture and at the hand-off of every `bg` flush after the first do: one
thread more than before. The readings `dbcommit` takes itself, `commit`
on a `bg` line and `prev_finished` and `prev_end` on the line after one,
count as before, and so do those of the shutdown's own flush, made once
the thread has stopped. On a `bg` line the processor time and I/O of
`sync`, of `insert`, of the participant's phase and of `commit` are
`dbcommit`'s. Before the block-file sync moved onto `dbcommit` on
2026-10-19, `sync` on a `bg` line was the capturing thread's, which the
line does not name, and counted in its `fg_ms`, and before the rows
moved there `insert` and the participant's phase were too.
In a sync from an outbound peer, as in the syncs
measured on 2026-10-12, the lines read
`peer-outbound`, the thread that connects the sync peer's blocks
(`peer-inbound` when that peer connected to the node, by the code; not
seen in a run), `index`, the index thread, and `main` for the flush at
shutdown.
`writer_wait` is
`{"index":{"count":N,"ns":N},"other":{"count":N,"ns":N}}`: for the
thread named `index` and for every other thread together, how many
times one found the writer held and how many nanoseconds it then waited
for it. Both pairs are totals from the opening of the database to that
flush, not figures for that flush, and the file is started anew at each
start: the last line of a run has the totals up to its last flush, and
the difference of two lines has those of the stretch between them. A
thread that finds the writer free is neither timed nor counted, and a
wait is added when it ends. The thread that connects blocks is among
the others, so block processing waited for the writer at most the
seconds that `other.ns` of the last line gives when divided by 1e9; RPC
calls that write and the shutdown are counted with it. The lines whose
`thread` is `index` are the flushes the index thread ran. The sum of
their `elapsed_ms` is the most the thread that connects blocks can have
waited behind those flushes, and the rest of `other` was waited behind
the index thread's transactions for each block, or behind another
thread that is not the index thread. That holds only where every
flush committed where it was captured, as with
`DCROXIDE_DB_SYNC_COMMIT=1`. Otherwise the index thread's flushes
are the `index` lines and those of the `bg` lines it captured, which a
line does not tell from the others, each of which kept the thread
that connects blocks out for about its `fg_ms` plus `wait_ms`.
`dcroxide-bench`'s own
`--flushlog` writes lines of another shape, which carry neither field,
though their three phases carry the four processor-time fields. Leave
`DCROXIDE_DB_FLUSHLOG` unset in normal operation; it writes a line
inside each flush, and on a Linux kernel with all three counter files
(`io`, `stat` and `schedstat` under `/proc/thread-self`) it has each
flush read `/proc` 18 times for the phases where it read it 6 times
before 2026-10-16, or 24 where 8 when the index writes in the flush,
outside each phase's `ms` and inside the line's `elapsed_ms`, and the
memory readings add seven more, five of `/proc/self/status` and two of
`/proc/self/maps`: 25 in all, or 31. All seven are read with the writer
held for a flush that commits where it was captured, and three of them
for a `bg` flush. What those reads cost was not measured apart. Without
it a flush reads
nothing from `/proc`. `DCROXIDE_EXISTSADDR_MEMTABLE_KEYS` is
for measurements only: it sets how many keys the exists-address index
holds in memory before its flushes merge them into its sorted runs (the
hard bound is one and a half times it), trading the index's memory, 21
bytes a key and up to 2 more for its partition's Bloom filter, against
the pages its flushes write. It never changes an
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
`DCROXIDE_READ_AHEAD` is read once at startup too, and turns off the
read-ahead of blocks during the initial sync; the sync budget above
says what that is and when to turn it off. `off`, in any letter case,
or `0` turns it off and is logged at startup as `Read-ahead of blocks
disabled by DCROXIDE_READ_AHEAD`. Any other value, `on` and `1`
included, is the warning `DCROXIDE_READ_AHEAD=V is neither off nor 0;
using the default`, and the read-ahead stays on. Unset, it is on and
nothing is logged.
`DCROXIDE_DB_SYNC_COMMIT` is read once at startup and is the way back
to dcrd's place for a metadata commit. Unset, a flush that a commit
trips, or that the chain's periodic UTXO cache flush asks for, syncs its
block files, writes its rows and makes its commit on the thread
`dbcommit`, which the node keeps from the first such flush to the
shutdown, and nothing is logged.
A positive whole number puts every commit back on the thread that ran
the flush, under the database's writer, starts no `dbcommit` thread, and
is logged at startup as `Metadata write cache commits on the committing
thread by DCROXIDE_DB_SYNC_COMMIT`. Any other value, `0` included, is
the warning `DCROXIDE_DB_SYNC_COMMIT=V is not a positive whole number;
committing the metadata write cache on a thread of its own`, and the
default stays; a value that is not valid Unicode reads as unset, with
no warning. Set it where commits run back to back, which the flush
log shows as `wait_ms` on most lines: the commit then gains nothing on
a thread of its own and the next flush waits for it with the writer
held. A flush that `Database::flush` or the close asks for commits on
the thread that asked for it whatever the variable says, since it
acknowledges durability. The default was measured on m3 only, on one
NVMe drive under btrfs, where on 2026-10-19 it took a sync of a build of
the code of `797a213`, from a block server on the LAN, from 350.40 s
with the variable set to 271.68 s by the means, 22.5%, and peaked lower,
at 2,456 to 2,470 MiB against 2,959 and 2,964 MiB when the clock
stopped, for 893.7 to 902.9 s of process CPU time against 877.8 s and
874.6 s (the storage tuning above, which also has the measurements of
2026-10-16 and 2026-10-17); the form of 2026-08-16, on m1, lost 9.5%
where commits ran back to back. On slower storage, or with few spare
cores, measure it with the variable set before relying on the default.
`DCROXIDE_PREVERIFY` is read once at startup too, and turns off, or
sets the most helpers of, the signature pre-verification of the blocks
read ahead; the paragraph on the threads kept for checking scripts above
says what it does, what each value does and what the node logs.
A malformed or zero value in any of the tuning variables warns and
falls back to the default rather than refusing to start, since they are
hints; `DCROXIDE_READ_AHEAD` and `DCROXIDE_PREVERIFY` alone take `0`,
which turns each off.
Everything else is a command-line flag or a `dcroxide.conf` entry,
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
where dcrd accepts them are listed in [PARITY.md](PARITY.md).

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

**Three error lines when the peer is on a private address are dcrd's,
not a fault.** Syncing from a node on the same machine or LAN, with
`--connect` or `--addpeer` naming a loopback, RFC 1918, `100.64.0.0/10`
or other non-routable address, logs these at each connection:

```text
[ERR] SRVR: Marking address as attempted failed: address 127.0.0.1:19108 not found
[ERR] SRVR: Setting services for address failed: address 127.0.0.1:19108 not found
[ERR] SRVR: Marking address as good failed: address 127.0.0.1:19108 not found
```

dcrd logs the same three for the same peer, because its address manager
keeps only routable addresses, so the three updates it makes for an
outbound peer find nothing to update. The connection and the sync are
unaffected. The first line comes at every dial, retries included; the
second when the peer's version message arrives; the third once the
handshake completes. None is logged on simnet or regnet, for an inbound
peer, or for a peer with a public address. See QK-0028 in
[QUIRKS.md](QUIRKS.md).

## Status of what you are running

Per-package parity status is in [PARITY.md](PARITY.md), which also
records every deliberate divergence from dcrd and the known remaining
gaps. Bug-for-bug reproductions of dcrd behavior — the ones that look
like defects and are not — are catalogued in [QUIRKS.md](QUIRKS.md).

There is no per-RPC-method status ledger yet. It is planned alongside
the ecosystem-acceptance work (the `dcrdtest` harness, a `dcrctl`
sweep, dcrwallet integration), none of which has been run; the project
brief tracks that as unmet.
