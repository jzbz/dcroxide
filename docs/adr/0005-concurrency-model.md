# ADR-0005 — D2: Concurrency model

- **Status:** Accepted (decision D2) — ratified 2026-08-07 as shipped: the
  thread-per-peer fallback, not the tokio proposal; see the addenda
- **Date:** 2026-07-03 (proposed), 2026-07-26 (addendum: what shipped),
  2026-08-07 (ratified), 2026-08-13 (addendum: the storage levers closed),
  2026-10-10 (addendum: a later sync comparison; second addendum: the
  parity commit and the index off), 2026-10-11 (addendum: one more
  thread, for the indexes), 2026-10-12 (addendum: a thread dcrd does not
  have, reading ahead on the sync peer's connection), 2026-10-16
  (addendum: more work on the reading thread, and threads kept for the
  scripts of a connected block; second addendum: a short-lived thread
  for the metadata commit), 2026-10-17 (addendum: the reading thread
  counts signature operations; second addendum: the script pool's
  helpers pre-verify the signatures of blocks read ahead)

## Context

dcrd is goroutine-per-concern: per-peer read/write loops, a sync manager
event loop, RPC handlers, and worker pools for signature validation. Rust
offers async (tokio) or OS threads; consensus validation is CPU-bound while
p2p/RPC are I/O-bound with modest connection counts (default 125 peers max).

## Decision (proposed)

- **tokio** for all I/O surfaces: peer connections, DNS seeding, RPC
  (HTTPS + websocket), IPC. Peer protocol drivers as per-peer tasks with
  bounded channels mirroring dcrd's queue semantics (inv/relay queues, stall
  detection).
- **Dedicated thread pool (rayon or hand-rolled) for validation**: script
  checks, signature batches, PoW/merkle verification. Consensus code stays
  synchronous and runtime-free — no `async` in any consensus crate, which
  keeps it auditable, deterministic, and testable without a runtime.
- Chain state behind a single-writer model equivalent to dcrd's chain lock;
  notifications via bounded broadcast channels.

## Consequences

- The async boundary lives exactly at the netsync/rpcserver ↔ blockchain
  seam, same as dcrd's goroutine/chain-lock boundary — the parity audit maps
  cleanly.
- Thread-per-peer (closer to dcrd's structure) remains the documented
  fallback if tokio's complexity shows up in audits; the peer driver is
  written against traits for readability either way.
- Final ratification blocked on: the Phase 11 peer read/write loop prototype
  demonstrating stall handling and backpressure equivalent to dcrd's under
  the adversarial harness.

## Addendum, 2026-07-26 — the fallback shipped, not the proposal

The port has no async runtime. Neither `tokio` nor `rayon` appears in any
manifest in the workspace, and no crate contains an `async fn`. The
documented fallback above — thread-per-peer, closer to dcrd's structure — is
what was built: OS threads over `std::sync::mpsc` channels for every I/O
surface (listener, per-peer input and output loops, outbound dialer, RPC and
websocket handlers, the seeder and the IPC runtime). The validation pool is `std::thread::scope` in `dcroxide-blockchain`'s
`validate_items`, capped at the item count and running inline below 16
items, rather than rayon. Its width is **one worker per core**
(`std::thread::available_parallelism`), deliberately not dcrd's
`runtime.NumCPU()*3` (`internal/blockchain/scriptval.go` 120): the port
copied that count until 2026-08-14, when spawning OS threads at three per
core measured slower than one per core — the measurement is recorded on
`validate_items` itself. The core count is probed once per process, in a
`OnceLock`, because on Linux `available_parallelism` re-reads the cgroup quota
files on every call; the probe runs after the inline return for batches of
fewer than 16 items. A thread the OS refuses no longer aborts the node:
workers start through `Builder::spawn_scoped`, spawning stops at the first
refusal, and the calling thread drains what is left through the same
work-stealing index (`validate_items_survives_refused_worker_threads`). dcrd's
goroutines cannot fail to start, so this keeps dcrd's outcome rather than
changing it.

Two clauses of the proposal did hold and are load-bearing: no consensus crate
is async, and chain state sits behind a single writer. One did not — the
websocket notification path is unbounded rather than a bounded broadcast
channel. That is deliberate, because dcrd's is unbounded in the same two
places; `PARITY.md`'s known-gaps section carries the reasoning and the
rejected alternatives.

The thread model has one consequence the proposal did not anticipate. Rust
mutexes poison on panic and Go's do not, so dcrd's per-goroutine `recover`
has no equivalent here: one thread's panic disables every other consumer of
the locks it held, and the RPC layer's `catch_unwind` then kept the process
alive answering canned errors. `[profile.release]` therefore sets
`panic = "abort"`, which makes the surviving `catch_unwind` guards inert in
release builds and requires operators to run the node under a supervisor;
dev and test builds keep unwinding. The full reasoning, and the test that
fails if the setting is dropped, are in `PARITY.md`'s "Known remaining gaps".

## Addendum, 2026-08-07 — ratified as shipped

The model the previous addendum describes — OS threads over
`std::sync::mpsc`, runtime-free consensus crates, a single chain-state
writer — is the accepted decision for D2. Two developments since the
proposal retire both the ratification gate and the standing reason to
revisit the choice.

The gate is met. Ratification was blocked on a peer read/write loop
demonstrating stall handling and backpressure equivalent to dcrd's. That
machinery shipped and is pinned: the stall detector and the stall-carrying
peer loops in `dcroxide-node`'s `peerloop.rs` port dcrd's `stallHandler`,
and `tests/b4_stall.rs` exercises them over real loopback TCP — including
the handler-active accounting that keeps the detector from firing on
honest peers. Both networks have synced from genesis to tip through these
loops, and the node syncs against dcrd in both directions.

The performance question belongs to another layer. The one open
performance gap — initial block download, ~2.2x dcrd when ADR-0004's
amendment measured it and **1.29x** when re-measured daemon-against-daemon
on 2026-08-15 — is localized by that amendment in the storage engine's
commit shape, not in threading or validation: the profiled syncs spent
80.1% / 82.4% of wall time in progress stalls longer than 20 s while dcrd
stalled zero times in 754 windows. No concurrency model removes those
stalls. The IBD gap is to be closed in the storage layer, through
ADR-0004's levers, and is not
grounds for reopening this decision.

External corroboration, for the record. Cuprate — the from-scratch Rust
Monero node — took the other fork: tokio, with tower services at every
internal boundary. Its published record points the same way. The
0.1.0-preview release notes report a single-wallet workload tied with
monerod, with the architecture's measured wins confined to multi-client
RPC scaling; the large sync-speed gain arrived with the April 2026
storage rewrite (github.com/Cuprate/cuprate/pull/587), not with the
runtime; and its own documentation concedes the abstraction's costs — a
p2p core it calls verbose, and a generic database service layer deleted
in that same rewrite. An async re-architecture buys multi-client scaling,
a surface this node has not yet needed, and it would forfeit the
structural property the port depends on: OS threads over channels mirror
dcrd's goroutine-per-concern layout thread for goroutine, which is what
keeps the line-by-line parity audit tractable. Multi-client RPC/websocket
concurrency stays an honest open question — it is to be measured against
dcrd before wallet integrations land, not assumed — but its answer,
either way, arrives as targeted fixes behind the existing seams, not as a
runtime swap.

## Addendum, 2026-08-13 — the levers closed; the gap did not move

The 2026-08-07 performance paragraph closed on the IBD gap being "to be
closed in the storage layer, through ADR-0004's levers". That no longer
holds. All four levers are measured and closed. (a) *audit long-lived read
transactions*: dead, three probe arms within 0.0008% and in the direction
opposite to pinning. (b) *size the read cache*: inverted, an 8 GiB page
cache is 50% slower over a full replay. (c) *decouple flush cadence*: a real
11%, the only tuning gain measured anywhere. (d) *shrink the dominant
buckets*: one bucket, `spendjournalv3`, holding 1.536 GiB of measured slack
that the page-size remedy cannot reach (redb gates `set_page_size` behind
`cfg(any(fuzzing, test))`), that re-keying makes worse (six layouts built at
the bucket's real dimensions, every split larger than today's), and that a
denser row reaches only by inventing an encoding dcrd does not have — dcrd
stores the same bucket byte for byte. Tuning above the engine buys 11%
against what was a 2.2x gap, and is a larger share of the 1.29x the gap
measured on 2026-08-15.

Its attribution no longer rests on the stall statistic. A 2026-08-15
task-state decomposition measured the mechanism: the port drives 11.7x the
kernel-side storage work dcrd does, and its blocked threads park in btrfs
writeback and transaction-commit waits. That confirms the cost is storage
commit shape — and confirms it is not threading, since most of it is paid in
kernel threads rather than in either daemon's own. The matched `--addrindex` replay
appeared to bound the storage term from the other side, 863 s of 4,767 s in
flushes, 18% of wall time. That bound does not hold: a replay validates every
block where the daemon skips roughly 93% of validation under mainnet's
assume-valid anchor, so the replay's composition is not the sync's. Measured
on the daemon, storage is indeed the larger share, not the smaller: 34.6% of
block-sync wall time against the replay-derived 18%.

D2 is unaffected, and now for a measured reason rather than an assumed one:
the stalls are storage waits with nothing else runnable — 99.4% of dcroxide's
blocked samples have zero runnable threads — so they are not contention
between its own threads, and no scheduling policy reaches them. What remains
of the storage question is
ADR-0009's engine decision, which no longer has a usable bound in either
direction. The 1.22x that once argued it could not be sold on IBD rested on
the replay's 18%; measured on the daemon, dcroxide is fully stalled on storage
for **34.6%** of block-sync wall time against dcrd's 0.9%, and removing that
brings both to the same ~346 blk/s. That convergence is an upper bound on all
storage stall rather than a prize one change collects. Attributed 2026-08-16
with the flush observer, 90–98% of the stalled time is inside a metadata-flush
window, and the stall is 48% of wall once the sampler's own starvation is
corrected (34.6% was a count-weighting artifact). But no multiplier follows:
the counterfactual projects a rate faster than dcrd's, which means the model
over-credits it. Whether the 1.5x stop rule is cleared remains unsettled —
though the target is now specific, and it is the commit rather than storage
at large.

Also open is the *form* a rework would take: two or more of the port's
threads block simultaneously in 0.2% of samples, so the storage path is
serialized, and a synchronous fsync on the critical path is implicated as much
as the engine choice.

## Addendum, 2026-10-10 — a later sync comparison, on the same thread model

The 2026-08-07 and 2026-08-13 addenda argue from an initial-sync gap,
~2.2x and then 1.29x behind dcrd, and from a node fully stalled on storage
for 34.6% and then 48% of block-sync wall time. Those are the 2026-07 and
2026-08 figures, taken on m1 in [bench-ledger.md](../bench-ledger.md)
against dcrd 2.2.0-pre. They stand as measured. They are no longer the
most recent comparison of the two daemons, and "the one open performance
gap" is to be read with its date.

On 2026-10-09 and 2026-10-10 dcroxide `c128a93` and dcrd release v2.1.6
each synced mainnet from genesis to block 1,116,035 over loopback on the
ledger's m3, each from a block server run by the other: four runs per
direction, at their defaults apart from the flags that point each at its
server, the exists-address index on in both. The medians are 1,058.6 s
(1,054.3 blk/s) for dcroxide against 2,863.9 s (389.7 blk/s) for dcrd,
dcroxide **2.71x** as fast. The lead is 2.3x up to the assume-valid block,
1,026,597, and 4.4x over the 89,438 blocks after it, which both daemons
validate in full (461.0 against 104.0 blk/s). Every run ended on the
server's tip, so the node again synced against dcrd in both directions,
here v2.1.6. The rows are in [bench-ledger.md](../bench-ledger.md),
"Daemon against daemon, each from the other".

The binary measured is the model the addenda above describe. `c128a93` has
no `tokio` or `rayon` in any manifest and no `async fn` in any crate, chain
state sits behind a single writer, and the validation pool is
`validate_items` at one worker per core. That width is newer than the 1.29x
above: the ledger's row for it was measured on `b6d0c63`, before `c091b46`
took the pool from three workers per core to one on 2026-08-14, so the
pool's width is among the things that differ between the 1.29x and this
comparison, which does not separate it. The two changes the ledger names
in that commit, the height-first keys of ADR-0010 and the exists-address
layout 3 of ADR-0011, are storage layouts, and neither adds a thread:
layout 3 writes its rows inside the metadata flush's own write
transaction. D2 is unchanged, and the comparison gives no reason to
revisit it.

The stall was not measured again in the form the 2026-08-13 addendum
quotes. These runs sampled no task states, so the share of wall time with
nothing runnable (34.6%, then 48%), the 99.4% and the 11.7x have no new
counterpart. What the runs do record is dcroxide's flush log. In its four
cross-source runs the 133 metadata flushes of the timed sync took
159.8–170.5 s in all, 15.1–16.1% of wall time, with a median flush of
1.30–1.37 s and a longest of 2.44–2.97 s. On m1 on 2026-08-16 a sync made
130 flushes with a median of 26.9 s, and flush windows occupied 68% of
wall time.

None of this reaches back into the 2026-08 record. The comparison does not
re-measure the 1.29x row and is not a later point on its curve: the
machine, the dcrd version and the harness all differ, and dcrd `6f6cf21b`,
the parity target, was not run. Neither daemon was profiled and neither was
run with the index off, so the runs do not say where the difference comes
from, and they are one machine with fast storage, over loopback. The
2026-08 attribution stands as the record of m1.

Two questions the 2026-08-13 addendum leaves open were closed in 2026-08,
not by these runs, and are noted here because this ADR never recorded
them. ADR-0009's engine decision closed on 2026-08-17 with the engine
staying redb, and nothing above reopens it. Of the forms a rework could
take, moving the commit off the critical path was measured on 2026-08-16:
a committer thread per flush ran 9.5% slower than the synchronous commit
and was reverted (ledger, "Background commit (2026-08-16)"). A third
question stays open. Multi-client RPC/websocket concurrency, which the
2026-08-07 addendum sets aside to be measured, was not measured here: the
harness's once-a-second `getblockcount` poll is one client.

## Addendum, 2026-10-10 (second) — the parity commit, and the index off

Two things the addendum above lists as not run were run later that day, in
the same harness on m3 ([bench-ledger.md](../bench-ledger.md), "The parity
commit, the index off, two levers and a full replay"). dcrd `6f6cf21b`
synced in 2,909.8 s and 2,869.8 s, a mean 0.9% over v2.1.6's median, so the
2.71x above holds against the parity target, where it is 2.73x. With
`--noexistsaddrindex`, one run each, dcroxide took 880.8 s and dcrd v2.1.6
1,247.8 s, dcroxide 1.42x as fast: 1,438.3 s of the 1,805.3 s between the
daemons at their defaults (80%) is the difference in what that index costs
each. The other 367.0 s is a net, and dcroxide earns it after the
assume-valid block. With the index off dcrd is the faster up to that block,
618.5 s against 708.1 s, and dcroxide over the 89,438 fully validated
blocks after it, 517.9 against 142.1 blk/s. Those are the blocks whose
scripts are checked, the validation pool's work, and where the ledger has
the runs above, index on, at about five of the node's 16 threads busy for
dcroxide and under three for dcrd.

Neither daemon was profiled, so this places the remaining lead without
explaining it: nothing here says the pool is why dcroxide is faster after
that block, or what makes dcrd faster before it. The index-off figures are
one run each, on one machine, over loopback. In the three dcrd runs of
that session the dcroxide server read its block files from the drive as it
served them, which it had not before; whether that cost dcrd anything was
not measured. D2 is unchanged.

## Addendum, 2026-10-11 — one more thread: the indexes

The daemon gained one long-lived thread on 2026-10-11. Index
notifications, which the block-processing thread delivered inline, now
go through a bounded `std::sync::mpsc::sync_channel` of 128 entries to a
thread named "index" that runs the unchanged subscriber
([ADR-0011](0011-exists-address-layout-3-and-the-flush-participant.md),
addendum of the same date). It is the shape dcrd has, a channel and a
goroutine, and the shape this ADR ratified: an OS thread over a std
channel, no runtime, no pool. A full queue blocks the sender, so the
block-processing thread is paced by the index when the index is the
slower, as dcrd's is.

On m3 two default syncs with the thread took 759.1 s and 756.2 s where
one of the commit before it took 820.3 s, with node CPU time unchanged
([bench-ledger.md](../bench-ledger.md), "Five changes on the
block-processing thread"). Up to the assume-valid block an average of
1.15 and 1.17 of the node's 16 threads were busy where 1.06 were
before, so that stretch is still close to one thread. D2 is unchanged.

## Addendum, 2026-10-12 — a thread dcrd does not have: reading ahead on the sync peer's connection

The daemon gained a thread on 2026-10-12 that has no counterpart in
dcrd. During the initial chain sync, once the sync peer's connection has
had a block handled, a thread named "peer-reader" takes over that
connection's reads. It reads each frame, checks its checksum, decodes it
and, for a block, hashes its transactions, up to four frames ahead of
the connection's input thread, which goes on handling every message in
the order it arrived, with the code that handled it before (`PARITY.md`,
*Reading ahead of the block handler*, has the rule, what it leaves
unchanged and what can be observed of it). dcrd's `inHandler` reads a
message only when its listener has returned from the one before
(`peer/peer.go:1535-1598`), and the comment on its `OnBlock` says the
further receives are held back on purpose, so that a peer cannot queue
up bad blocks (`server.go:1365-1369`).

That is a departure from the ground the addenda above stand on, and it
is recorded as one. The 2026-08-07 addendum keeps OS threads over
channels because they mirror dcrd's goroutine-per-concern layout thread
for goroutine, which is what keeps the line-by-line parity audit
tractable. The 2026-10-11 addendum admitted the index thread as the
shape dcrd has. This thread mirrors nothing: dcrd has no goroutine ahead
of `inHandler`. What stands in for the mirror is tests. One runs 300
seeded streams over a real connection with and without the thread and
requires the same calls with the same contents in the same order and
the same end of the connection
(`the_handler_sees_the_same_calls_with_and_without_read_ahead`), and
others hold the queue to four frames, the stall detector and the peer's
counters to the moment a message is handled, the idle timer to the
moment the input thread began waiting, and the teardown to handling
nothing that is still queued. PARITY's row names them and lists what
they do not cover.

It is confined to one kind of connection because only there is the
reading in the way. During the initial chain sync the sync peer's input
thread is the thread that connects blocks, so the socket reads, the
checksums, the decoding and the hashing were done by the thread the sync
waits for. Every other connection, and every connection under
`DCROXIDE_READ_AHEAD=off`, is read by its input thread alone, as dcrd
reads. Once the sync is done the server answers no after every block,
so no connection is given the thread and one that has it stops being
read ahead. The thread is started behind the first block the connection
is kept for while it is the sync peer, and it stays until the
connection ends: once reading ahead is no longer wanted it reads each
frame only in turn, and it still hashes every block it reads. It is an
OS thread over std primitives: no runtime, no pool, and no thread per
block.

The queue between the two threads is a `std::sync::Mutex` with two
`Condvar`s over a `VecDeque` of at most four items, not the
`std::sync::mpsc` channel the other threads use. The reader may start a
frame early only behind a block. In every other case it has to wait
until the input thread is waiting with nothing queued, which is when
`inHandler` begins its read, and that same moment starts the idle
budget of the frame being read. A channel does not tell its sender that
the receiver is waiting on an empty queue. A lock that both sides take
does.

The two clauses the 2026-07-26 addendum calls load-bearing hold. No
consensus crate is async, and this change starts no thread and takes no
lock in one: `HashedBlock::new` in `dcroxide-blockchain` is plain
computation that the reader thread calls, and
`Chain::process_hashed_block` makes the checks of
`Chain::process_block` in the same order, reading the hashes where that
computes them. Chain state keeps its single writer: the reader thread
touches the socket, its queue and its counters and nothing else, and
every block of the connection is still processed by its input thread
under the chain's mutex.

On m3 on 2026-10-12, on a quiet machine with the node held to eight of
the machine's cores (16 threads), one binary synced mainnet to block
1,116,035 from a dcrd v2.1.6 server over loopback four times at the
defaults, in the order off, on, off, on with other runs between the
pairs: 597.6 s and 599.0 s with `DCROXIDE_READ_AHEAD=off`, and 494.6 s
and 490.8 s with the thread, 17.2% and 18.1% less. In the two runs with
it the reader thread spent 45.829 s and 45.886 s on checksums and
decoding and 47.209 s and 47.246 s on hashing, was parked with its
queue full for 382.350 s and 378.719 s, and the input thread waited
0.271 s and 0.273 s for a block: in those runs the thread that connects
blocks, not the reading, was the slower side. The queue never held more
than four frames. Peak resident memory was 2,967 and 2,921 MiB with the
thread against 3,273 and 3,256 MiB without, which is not explained.
Those four runs are of the build made before the review of 2026-10-12
and its fixes, which changed one condition of the idle budget and one
internal call of the hashing; the code as committed has not been run in
a sync. The binary also holds the commit before this one, which hands a
peer's block to the chain without copying it; the commit before that
took 612.4 s in one run that day. No sync was run of the hand-off
alone, and the 14.8 s and 13.4 s between that run and the two with the
setting off are not attributed.

Not measured: a sync over a delayed or a real link, where the round
trip and not the thread that connects blocks may set the pace and the
thread may gain nothing; fewer cores than those eight; the
exists-address index off; `--assumevalid=0`; the memory the queue can
hold, which is bounded at four frames and estimated, not measured, in
bytes; and macOS and Windows, where nothing of this change has been
run, neither a sync nor any of its tests, two of which
(`tests/read_ahead_join.rs`, `tests/read_ahead_sync.rs`) are
Linux-only.

What would undo it. At run time, `DCROXIDE_READ_AHEAD=off`: no reader
thread is started, and the same binary reads every connection as it did
before. In the code, a connection gets the thread only where an
implementation of `ServeHooks::read_ahead_wanted` answers yes, and the
trait's default is no (`hooks_that_do_not_ask_are_never_read_ahead`).
The daemon's one yes is in `ServerPeerHandler::handle_block`. Without
it no thread is ever started, and the reader, the setting and the
shutdown line can be taken out, leaving the input loop on its own
reads.

D2 as ratified does not cover a thread that dcrd has no goroutine for,
and this addendum does not claim that it does: it records what was
added and on what grounds. Whether those grounds, tests and four
loopback syncs on one machine in place of dcrd's shape, are enough to
keep the thread is the project owner's decision. Declining it is the
paragraph above, and nothing else in this ADR depends on the thread.

## Addendum, 2026-10-16 — more work on the reading thread, and threads kept for the scripts of a connected block

Commits of 2026-10-16 bear on this ADR in two places. None adds a
runtime, a dependency or an `async fn`, and chain state keeps its single
writer.

**The reading thread does more for each block.** The 2026-10-12 addendum
has the `peer-reader` thread read each frame, check its checksum, decode
it and, for a block, hash its transactions. Since `a589c4a` it also
serializes a block once, compares the serialization with the payload the
block arrived in, and lays that payload out in its own buffer as the
block's block-file record, with the record's CRC-32C and one more hash
of the header (`HashedBlock::keep_wire_bytes`,
`crates/dcroxide-blockchain/src/blockhashes.rs:310`). The input thread's
chain stores such a block as that record
(`Transaction::store_block_record`), so the thread that connects blocks
neither serializes nor checksums it. Since `44cf801` the reading thread
also builds the block's two transaction merkle trees from the hashes it
has taken and keeps their roots (`HashedBlock::new`, `:252`). The block
hash it takes is, since `54e8cad`, the one the sync manager and the
whole processing call use. The recorded choice stands, and in these
words: making a `HashedBlock` reaches no verdict, no merkle root is
compared with a header and no rule is applied off the input thread, and
a payload that does not compare equal to the serialization is dropped
without a verdict and its block stored as any other. Where the
2026-10-12 addendum says the thread "still hashes every block it reads",
it now hashes, builds the trees of and lays out every block it reads. It
is still one thread on one connection with at most four frames ahead;
each queued block now keeps the frame it was read in, which PARITY.md's
row *Reading ahead of the block handler* and SECURITY.md put in bytes,
as estimates. The work moved and was not removed: in the syncs of
2026-10-13, one or two runs a build, the build that added the record
took about 9 s of processor time off the thread that connects blocks,
outside its flushes, and added about 7 s to the reading thread, and the
one that added the trees, with the carried header hash, about 8 s and 5
s, while the reading thread, fed by a server on the same machine, still
waited over 320 s for the other. Over a link that leaves the reading
thread no time to spare, the move may gain nothing; that was not
measured.

**Threads kept for the scripts of a connected block.** The 2026-07-26
addendum records the validation pool as `std::thread::scope` in
`validate_items`, and the first addendum of 2026-10-10 records it as
`validate_items` at one worker per core. Both stand as the record of
those commits. Since `f60ae3a` the scripts of a block the chain connects
go, a transaction tree at a time, to helper threads that live as long as
the process (`crates/dcroxide-blockchain/src/scriptpool.rs`,
`Pool::global` at `:476`): the hand-rolled pool the proposal of
2026-07-03 named, still without rayon. It holds at most as many helpers
as the logical CPUs the process may run on, less one, so that with the
calling thread, which always checks too, a batch has at most one worker
per CPU, the width of 2026-08-14. Helpers are named `scriptval-N`, are
created as batches want them, park while there is nothing to check and
are never joined, the pool being a process-wide static. One mutex guards
the queue of open batches and a last-in-first-out stack of parked
helpers, and is never held across a check, a thread creation, an unpark
or a park; a helper leaves a batch through an atomic count that unparks
the calling thread when it reaches zero. A helper the OS refuses leaves
the pool narrower, the calling thread covers the work, and no creation
is tried again before the 1,024th batch after that one, so a refusal
still costs speed and not the node. The crate forbids unsafe code, so a
helper that outlives the call cannot borrow from the caller: a batch
owns what its checks read, holding the block, its transaction hashes and
the signature cache by reference count and a single copy of the previous
scripts it spends.

The scoped path keeps the rest (`validate_items`,
`crates/dcroxide-blockchain/src/validate.rs:5505`): a connected block's
tree of fewer than 4 script items, a tree whose previous scripts come to
more than 1 MiB, every tree where the process may run on one logical CPU
or in a build without `std`, the template check, the public
`check_block_scripts`, and a single transaction's check. A tree of 16
items or more is offered no fewer workers than before, so the lesson of
2026-08-14 holds; a tree of 4 to 15 items, which the calling thread
checked alone, now has a worker for each item up to one per CPU.

Three things are new to this ADR. A node that has checked scripts keeps
its helpers until it exits, parked and using no CPU when idle, and a
task limit counts them ([operating.md](../operating.md)). In an
unwinding build a helper catches the panic of a check, stops the batch
and keeps serving, and the calling thread raises the panic again; that
is the crate's first `catch_unwind` outside its tests, and like the
others the release profile's `panic = "abort"` makes it inert. And a
batch the pool runs names its failing input of lowest index on every
run, which dcrd's `txValidator` and the scoped workers do not promise;
PARITY.md's row *Script checks of a connected block* has the rule and
its exceptions. That no wake-up is lost and no interleaving deadlocks
rests on reading and on the tests, not on a model checker in the
repository. A verdict does not rest on it: `Ok` is returned only when an
always-on count shows that every item passed and the batch was not
stopped, and an error is always one a check of that batch returned, so a
fault in the pool can stall or stop the node and cannot accept a block.

This keeps dcrd's shape in what it does and departs from it in how long
the threads live. dcrd's `validateHandler` goroutines do the same work
and are started for each batch
(`internal/blockchain/scriptval.go:117-166`); the helpers here are the
same work kept alive between batches, which is the departure, and not a
thread without a dcrd counterpart in the sense of the 2026-10-12
addendum.

On m3 on 2026-10-13 two default syncs of `4700cf1` with the pool alone
took 491.3 s and 493.4 s, about 12 to 16 s less than that code,
depending on the measure, all of it after the assume-valid block; both
had 15 `scriptval-N` threads at the end, on a node held to 16 hardware
threads, and their peak resident memory, read before the closing flush,
was inside the range of `4700cf1`'s own runs
([bench-ledger.md](../bench-ledger.md), "Seven cumulative builds, the
validation pool, a background commit and dcrd"). The pool has not been
run with the other commits of 2026-10-16, so the code as it stands has
not been run in a sync, and its threshold of 4 items has not been tried
beside the reading thread's added work. D2 is unchanged.

> **Note, 2026-10-16, after the syncs of that day.** `8fc9160`, which
> holds the pool and the commits of 2026-10-16 before it as committed,
> took 421.2 s to 434.0 s in four default syncs on m3, a median of
> 430.7 s, with the threshold at 4 items
> ([bench-ledger.md](../bench-ledger.md), "`8fc9160`, a background
> commit and dcrd v2.1.7"). What the pool adds there was not measured
> apart, and the threshold was not varied.

> **Note, 2026-10-17, after the syncs of that day.** The code as it
> stands, `88c46c3`, which holds the pool and every commit after it,
> took 395.3 s to 397.8 s in four default syncs on m3, a median of
> 396.25 s, with the threshold at 4 items and the reading thread's
> added work ([bench-ledger.md](../bench-ledger.md),
> "`88c46c3`, the background commit as committed, dcrd v2.1.7 and two
> preloaded allocators"). What the pool adds there was not measured
> apart, and the threshold was not varied.

## Addendum, 2026-10-16 (second) — a short-lived thread for the metadata commit

In the daemon a flush of the metadata write cache that a commit's own
check trips now makes its redb commit on a thread of its own, named
`dbcommit` ([ADR-0009](0009-storage-shape.md), addendum of this date,
for what it means for durability and failure; PARITY.md's `database` row
and *Where a cache flush's commit runs*). dcrd commits on the goroutine
that holds its database write lock.

The thread is made with `std::thread::Builder` at the hand-off, with the
default stack, and ends when the commit, the retirement of what the
flush captured, the latch on a failure and the participant's `finished`
are done. At most one is alive: the next capture, `Database::flush`, the
close, and the registration or removal of a participant each wait for
it, with the writer held, before they go on. It takes neither the writer
semaphore nor the block store's lock; it takes the cache lock to retire
the captured layers and frees them after releasing it. There is no pool
and no channel, and no new dependency. If the operating system refuses
the thread, the flush commits on the thread that ran it, as it does for
`Database::flush`, the close and a flush that a participant which has
not opted in contributed to. A panic on it aborts a release build, as on
any thread; in a build that unwinds, the wait for it latches the store.

`DCROXIDE_DB_SYNC_COMMIT` set to a positive whole number puts every
commit back on the thread that ran the flush. The library's default is
that placement, so addblock, `dcroxide-bench` and the tests that do not
ask make no such thread.

D2 is unchanged: this is one more OS thread, made for each flush a
commit trips and ended with it, never more than one at a time.

## Addendum, 2026-10-17 — the reading thread counts signature operations

The `peer-reader` thread of the addenda of 2026-10-12 and 2026-10-16 now
also counts each block's signature operations, once for each answer the
treasury agenda can give, and keeps the two sums in the `HashedBlock`
(`BlockSigOps`). The input thread's contextual check, made as that very
block is accepted, compares the sum its agenda answer selects with the
limit, and counts the block itself, which gives the error and its text,
wherever that sum is over the limit; every block that arrives otherwise
is counted there as before. dcrd counts inside `checkBlockContext`
(PARITY.md's row *Reading ahead of the block handler*). The counts carry
no verdict: making a `HashedBlock` still reaches none, and no count is
compared with the limit off the input thread. Counting adds no lock, no
queue and no allocation that outlives a transaction to the thread, and a
`HashedBlock` is 16 bytes larger.

The work moved and was not removed, and the reading thread counts each
block twice.

The change moved lines that the first addendum of 2026-10-16 cites,
whose numbers stay as they were written: `HashedBlock::keep_wire_bytes`
is now at `crates/dcroxide-blockchain/src/blockhashes.rs:372` and
`HashedBlock::new` at `:312`, and the line of `validate_items`'s
documentation cited there is at
`crates/dcroxide-blockchain/src/validate.rs:5604`.

D2 is unchanged: no thread is added.

> **Note, 2026-10-18, after the syncs of that day.** The counts have
> been measured only together with the change that writes GCS filter
> bits a word at a time, which runs nothing on the reading thread, and
> the changes below them: on m3, from a dcrd v2.1.7 node on another
> machine on the same LAN, the build that added the two took 3.9 s more
> of the reading thread's time on a processor and 8.9 s less of the
> block thread's than the build below it
> ([bench-ledger.md](../bench-ledger.md), "Rungs from a block server on
> the LAN, two changes held for their memory, and dcrd v2.1.7", build
> B). Those builds were states of a worktree, not the tree of a commit,
> and the series is one of its own. A link that leaves the reading
> thread no time to spare was not tried.

## Addendum, 2026-10-17 (second) — the script pool's helpers pre-verify the signatures of blocks read ahead

While the sync peer's connection is read ahead, which it is until the
initial chain sync is done, the helpers of the script pool
(`scriptval-N`, first addendum of 2026-10-16) also check, while no batch
of a connected block wants them, the signatures of the blocks the
reading thread holds, so that the chain finds them in the signature
cache when it connects those blocks (PARITY.md, *Signature
pre-verification ahead of the block thread*). dcrd verifies a block's
signatures when it connects the block, or earlier only at mempool
acceptance.

No thread is added. The pool gains lanes
(`crates/dcroxide-blockchain/src/scriptpool.rs`, *Lanes*): a lane is a
queue of jobs, each a run of units a helper claims one at a time, with
the most helpers it may hold at once and the most bytes its queued jobs
may hold. A helper that scans the queue of batches and finds none that
wants it takes up the oldest job of a lane with room, and before each
unit compares a count of the batches queued so far, which every batch
bumps under the pool's mutex, with the value it read under the
acquisition in which it found no batch; once the count has moved it
leaves the job and scans again. So batches come first: the parked
helpers are woken for a batch as before, and a helper in a lane joins a
batch that still has a ticket after the unit it holds. The lanes' state
is guarded by the pool's one mutex, so the argument that no wake-up is
lost is the one the pool had: a helper is on the stack of parked helpers
only after a scan under the same acquisition found neither a batch nor a
lane job, and a lane's submitter pops parked helpers under it. Of a job
only two methods are called under the mutex, and they only read and
write its atomics (whether it has a unit left, and its withdrawal); a
lane's queue may allocate under the mutex, and a closed lane's last
helper notifies its closer under it. A lane is closed with its jobs
withdrawn, and the close waits on a condition variable of the pool until
no helper is inside one; a helper inside a unit finishes it first. In an
unwinding build a unit that panics withdraws its job and the helper goes
on serving; that is the pool's second `catch_unwind`, inert under the
release profile like the first. A lane holds no verdict: nothing waits
for its work, and the batches' verdict rule is not touched.

The one lane is the pre-verifier's
(`crates/dcroxide-blockchain/src/preverify.rs`), of at most two fewer
helpers than the physical cores the process may run on, at least one
from two cores, counted from `/proc/self/status` and each allowed CPU's
topology in `/sys` and taken as half the logical CPUs where those cannot
be read (`crates/dcroxide-node/src/preverify.rs`), so that one core is
left to the block thread and one to the reading, index and commit
threads; what a helper on the block thread's SMT sibling would cost that
thread was not measured. A unit is one input whose signature script has
the guessed shape, a `SigHashAll` signature and a public key: one hash
of its transaction's witness serialization and at most one signature
verification. The reading thread submits each block it has hashed while
reading ahead is wanted, taking the pool's mutex for it (never with the
read-ahead queue's), and the thread that processes blocks withdraws a
block as it takes it. `Preverifier::shutdown` runs right after block
processing stops. The helpers it creates are counted against the pool's
width, as a batch's are, and a refusal of a thread is handled as for a
batch.

`DCROXIDE_PREVERIFY=off` (or any whole number that is zero) leaves the
node as it was; a positive whole number sets the most helpers instead,
never more than the pool's width.

The change moved a line that the first addendum of 2026-10-16 cites,
whose number stays as it was written: `Pool::global` is now at
`crates/dcroxide-blockchain/src/scriptpool.rs:571`.

D2 is unchanged.

> **Note, 2026-10-18, after the syncs of that day.** Pre-verification
> was measured in syncs on m3, from a dcrd v2.1.7 node on another
> machine on the same LAN: the build that added it took 7.95 s less than
> the build below it by the means of two runs each, 8.50 s less after
> the assume-valid block, with 13.9 s less of the block thread's time on
> a processor and 29.0 s less of the script pool's threads'
> ([bench-ledger.md](../bench-ledger.md), "Rungs from a block server on
> the LAN, two changes held for their memory, and dcrd v2.1.7", build
> G). The build below it held a change that was not kept, those builds
> were states of a worktree and not the tree of a commit, and the series
> is one of its own.
