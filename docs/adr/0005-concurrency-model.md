# ADR-0005 — D2: Concurrency model

- **Status:** Accepted (decision D2) — ratified 2026-08-07 as shipped: the
  thread-per-peer fallback, not the tokio proposal; see the addenda
- **Date:** 2026-07-03 (proposed), 2026-07-26 (addendum: what shipped),
  2026-08-07 (ratified), 2026-08-13 (addendum: the storage levers closed),
  2026-10-10 (addendum: a later sync comparison; second addendum: the
  parity commit and the index off)

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
