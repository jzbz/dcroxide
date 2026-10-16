# ADR-0011 — Exists-address index layout 3 and the flush participant

- **Status:** Accepted 2026-10-09. The two database hooks (Decision,
  part 1) were approved by the project owner on 2026-10-09 and are
  checked against ADR-0009's guardrails below. Layout 3 (part 2) is
  implemented on them, with the recommended answer to each of the plan's
  decisions. On the benchmark host it passed every criterion that round
  could measure (speed, bytes written, flush count and the index digest
  at block 916,046) and tripped neither fallback test, so the fallback
  under Alternatives is not built. The plan's read and memory criteria
  were not judged by the method set for them. The end-state checks, the
  digest at the tip and a SIGKILL restart, ran separately on a
  development desktop and met their checks; the journal load's time
  there is inferred, not logged (Consequences).
- **Date:** 2026-10-09

## Context

In dcrd's layout, the exists-address index was the largest single cost
of an initial sync. With the index off, the node synced the 200,000
blocks from 916,000 to 1,116,035 **3.4x faster**: a median of 262
against 78 blocks/s, writing
21.8 GB instead of 151.6 GB ([operating.md](../operating.md), "The
exists-address index"). It serves two RPCs, `existsaddress` and
`existsaddresses`, and it is on by default, as in dcrd.

The cost is the layout, not the index. dcrd's layout (layout 2 here,
`EXISTS_ADDR_INDEX_VERSION` = 2 at
`crates/dcroxide-indexers/src/existsaddrindex.rs:33` before this change,
at commit 6c11a38) is one row per address ever seen: a 21-byte key,
`[type][hash160]`, and an empty value. Every connect probed the bucket
once per distinct address (`existsaddrindex.rs:504-509` at 6c11a38),
about 122 cold point reads per block, and put each new address as a row
through the overlay (`:511-514`). goleveldb
absorbs that cheaply: an LSM appends. redb is a copy-on-write B-tree, so a
flush pays one leaf, and its branch path, for nearly every new address,
scattered over a bucket of about 66 million rows. That is the shape
ADR-0010 removed from the seven per-block buckets, here in the bucket it
could not reach, because an address has no order to key it by.

What the index needs is to write its keys in large sorted batches, while
staying in the durability domain of its tip row. The tip row
(`idxtips/existsaddridx`) is written in the same transaction as the
connect, through the overlay, and reaches disk in the metadata flush that
carries the chain's rows. If the index's keys reached disk on any other
schedule, a power cut could keep a tip whose keys were lost, or keys
whose tip was lost. Three designs were judged. The one adopted keeps
every index row inside the existing metadata flush. It needs two things
the database did not offer: a way to write rows inside the flush's own
redb transaction, and a point in a commit at which to hand in-memory state
over atomically with the commit's rows.

## Decision

### 1. Two database hooks, in `dcroxide-database`

**A flush participant**
(`crates/dcroxide-database/src/participant.rs:64`). A participant owns one
key prefix, a bucket's four-byte id (`Bucket::raw_id`,
`crates/dcroxide-database/src/transaction.rs:1616`), and is registered
with `Database::set_flush_participant`
(`crates/dcroxide-database/src/lib.rs:1738`). The database drives it from
`flush_locked` (`lib.rs:662`), the one helper every flush goes through:

- **`wants_flush`** is asked by each commit's flush check, beside dcrd's
  `needsFlush`, and can trip a flush the overlay's thresholds would not
  (`lib.rs:674`).
- **`has_work`** is asked once per flush, after the block-file sync
  (`crates/dcroxide-database/src/dbcache.rs:749`). With work, the flush
  commits even an empty overlay.
- **`contribute`** writes the participant's rows inside the flush's
  existing write transaction, after the overlay's rows and before the
  commit (`dbcache.rs:820`, `:845`). The rows go through a `FlushWriter`
  that refuses any key outside the prefix (`participant.rs:324`).
- **`finished(committed)`** is called exactly once after each
  `contribute`, after the overlay layers are retired and, on failure,
  after the store has latched, still under the writer semaphore
  (`lib.rs:704`).

The database holds the participant by a **strong** reference
(`lib.rs:320`). The daemon drops its index handles before it closes the
database (`crates/dcroxide-node/src/bin/dcroxide.rs:367-391`), and the
close's flush must still journal what the index holds in memory for the
blocks whose tip rows that flush persists. `close` releases the
participant after that flush (`lib.rs:1674-1698`), so no flush that loses
the writer to the close can run it. `clear_flush_participant`
(`lib.rs:1802`) waits out any flush, and an index drop calls it before
deleting anything.

**No overlay row under the participant's prefix**, ever: a stale overlay
entry would shadow the participant's newer row for every reader.
Registration refuses a prefix the overlay holds a row under, and the
database's own buckets (`lib.rs:1738`). A commit that stages a row under
it is refused before anything is written, without latching
(`transaction.rs:1065`, `:1130`). A flush whose capture holds one fails
and latches as a backstop (`dbcache.rs:784`).

**`Transaction::on_commit`** (`transaction.rs:1049`) runs closures in
registration order once the commit's own flush has succeeded and before
its rows are published to the overlay (`transaction.rs:1201`, `:1225`,
`:1246`). At that point the writer semaphore is held, any flush this
commit triggered has completed, and no other transaction can see the
commit's rows. A rollback, a drop or a failed commit closes the
transaction and drops the closures unrun (`transaction.rs:1017`).

**Two raw reads**, `Transaction::try_first_after` and `try_scan_after`
(`transaction.rs:647`, `:663`), find the first row past a key under a
prefix. Unlike `Bucket::get`, a store read error comes back as an error
rather than as absence.

**The flush log counts participant-only flushes.** `FlushObservation`
gains `participant: Option<ParticipantStats>`, and a flush in which only
the participant wrote takes a sequence number and reaches the observer
(`dbcache.rs:896`).

Nothing here changes behaviour for a caller that registers no participant
and no hook, and no dcrd interface has these hooks.

### 2. Layout 3 for the exists-address index, in `dcroxide-indexers`

Built on the hooks, in `crates/dcroxide-indexers/src/existsaddr/` and
`existsaddrindex.rs`:

- **In memory**, a memtable of the keys not yet merged, in 256 partitions
  placed by a keyed hash: SipHash-2-4 of the key under a 128-bit key drawn
  from the system's randomness when the index is created and kept in the
  meta row. Placed by a key's own first hash160 byte, as the plan had it,
  whoever pays to addresses could crowd one partition, for about 256
  tries an address: one merge would then rewrite a base of any size
  whatever the page budget, hold several copies of it in memory, and
  leave the other partitions unmerged, so the journal every restart reads
  would grow without bound. A connect copies the mempool overlay, filters
  its candidates against the memtable without a store read, puts the tip
  row as today, and registers an `on_commit` hook that inserts the
  candidates and then removes the copied keys from the mempool overlay.
- **On disk**, rows in the `existsaddridx` bucket, all written by the
  participant inside the metadata flush: a meta row; journal rows holding
  the keys each flush made durable; and per partition a delta run and a
  base run, each as near-equal sorted chunks of at most 192 keys, one 4 KiB
  leaf each, keyed by their last key.
- **Each flush with keys to journal** merges the largest partitions into
  their runs within a page budget, journals the new keys of the partitions
  it did not merge (a merged partition's keys are in its runs in the same
  commit), garbage-collects the journal rows no longer needed, and writes
  the meta row. A flush with nothing new to journal writes nothing, so the
  close's flush after the node's own shutdown flush commits nothing.
- **A lookup** reads the mempool overlay, then the memtable, then the
  runs: the order keys move in, so a lookup never misses a key mid-move.
- **On restart**, the memtable is reloaded from the journal. A corrupt
  meta or journal row is an error naming `--dropexistsaddrindex`, never an
  empty index. The runs are not read at a restart, so a corrupt run row is
  found by the first lookup or merge that reads it. The lookup fails with
  the same remedy, which the RPC handlers answer as "Could not query
  address: ...". The merge fails its flush, which latches the store: the
  node commits no further blocks, and every write refused after that names
  the first failure, the index and its remedy, not only the storage.
- **The version is 3.** A layout-2 directory is refused at startup with
  the remedy: run once with `--noexistsaddrindex --dropexistsaddrindex`,
  then restart to rebuild the index from genesis. There is no migration.
  A build from before layout 3 checks no version: run with the index on
  over a layout-3 index, it adds layout-2 rows and moves the tip. Those
  rows sort before every layout-3 row, so a start reads the bucket's first
  row and refuses with the same remedy if it is one.

Where the code is:

| Piece | Code |
|---|---|
| Version, refusal | `crates/dcroxide-indexers/src/existsaddrindex.rs:47`, `:472` |
| Lookup order: overlay, memtable, runs | `existsaddrindex.rs:212`, `:250` |
| Connect: copy, filter, tip row, commit hook | `existsaddrindex.rs:630`, `:755` |
| Load, register, retire an earlier instance | `existsaddrindex.rs:498`, `:522` |
| Drops clear the participant first | `existsaddrindex.rs:853`, `:897` |
| The participant: merges, journal, GC, meta | `crates/dcroxide-indexers/src/existsaddr/store.rs:213`, `:324` |
| Only new keys make work | `existsaddr/store.rs:205` |
| Restart load, layout-2 rows refused | `existsaddr/store.rs:367` |
| Partition hash and key | `existsaddr/policy.rs:156`, `:189` |
| Memtable | `existsaddr/memtable.rs` |
| Chunk codec, probe, level rewrite | `existsaddr/runs.rs` |
| Journal rows | `existsaddr/journal.rs` |
| Meta row | `existsaddr/meta.rs` |
| Limits and merge choice | `existsaddr/policy.rs` |
| The latch names its first failure | `crates/dcroxide-database/src/lib.rs:187`, `:212` |

The details the plan left open or that differ from it:

- **A journal row is numbered by a u32 within its flush**, not a u16: a
  flush journals whatever the mempool hand-off brings, which has no bound
  of its own, and 65,536 rows of 192 keys would be a hard failure inside
  the chain's flush. The row is 4,057 bytes, still one leaf.
- **`m*` is at least one key.** Below `k0` = 129, which only a test
  policy sets, the formula's cap is under one key and every merge would
  rewrite a base; with the floor, small test limits run the delta path.
- **The first merge of a flush always runs**, whatever the budget, so a
  flush that has work for the merges always makes progress.
- **A second instance of the index on one database retires the first**:
  registration finds it, a flush journals what it holds, it is released,
  and the new instance loads again. The daemon makes one instance; tests
  make more.
- **Partitions are placed by a keyed hash**, not by the first hash160
  byte (above). The meta row gains the 16-byte key and is 3,093 bytes,
  layout 2; layout 1, the plan's 3,077-byte row, is refused, and no
  released build wrote it. `Policy::partition_key` fixes the key for an
  index a policy creates; only tests set it, and `Policy::tiny` does, so a
  test's paths repeat with its seed.
- **A flush journals only the partitions it does not merge**, after its
  merges, a partition at a time into sorted batches of at most 49,152
  keys (256 full rows). Neither a flush nor a restart holds a second copy
  of more than a batch and one partition.
- **A flush with nothing new to journal does not contribute.** The plan's
  `has_work` was also true while the memtable held more than `k0` keys,
  which made the close's flush, after the node's own shutdown flush, a
  second durable commit made only to merge: 17-24 merges and 0.4-0.9 s at
  the end of every measured run.
- **The memtable keeps its unjournaled keys as sorted runs** of falling
  length, each more than twice the next, instead of one sorted vector and
  a 64-key buffer. The buffer's fold merged the partition's whole vector
  every 64 inserts, quadratic in a partition's inserts; the runs copy each
  key O(log n) times however the inserts arrive.
- **A restart reads the journal twice in one snapshot**: once to count
  each partition's pending keys, then into vectors of exactly that size,
  so it holds about one copy of them, where gathering and splitting one
  vector held two.
- **The database's latch keeps its first cause** (`DbInner::mark_fatal`),
  and every refusal after it names that cause. A flush the participant
  fails, for a damaged run row, latches the store like a storage fault,
  and the refusals should send the operator to the index's remedy.

The tip row, its timing, the subscriber, catch-up and recovery are
unchanged. The keys are visible no later than the tip, since the hook runs
before the tip row is published.

## Checked against ADR-0009's guardrails

| ADR-0009 | What the hooks do |
|---|---|
| **Durability enforced at the wrapper boundary** (condition 2) | No new `begin_write` and no new commit. The participant writes inside the transaction `begin_durable_write` opened (`lib.rs:146`), and it is never handed a transaction or a durability setting of its own. `tests/durability_policy.rs` is unchanged and passes. |
| **Durable defaults**: a deferred-sync mode ships opt-in | Nothing is deferred. The index's rows reach disk in the commit that carries the chain's and its tip row, at `Durability::Immediate`. |
| **The fail-closed latch** (condition 1, gate C) | A `contribute` error or a failed commit goes through `flush_locked`'s `mark_fatal` before the writer semaphore is released, and `finished(false)` is called after the latch. No later write on the handle succeeds, so a participant never retries a flush the engine mishandled. The latch keeps the first failure's text, and each refusal repeats it. |
| **`crash.rs` as a gate** (condition 3): a kill between each durability domain's commit, a commit spanning the paired buckets, both desync directions | The hooks add **no durability domain**. The index's rows ride in the chain's commit, with no file or commit of their own, so there is no new boundary to kill between. The pairing is the index's rows with the chain's rows and its tip row. `tests/participant.rs` cuts power at every storage operation of a scripted run, under the same `PowerLossBackend` `tests/crash.rs` uses (now shared from `dcroxide-testutil`). It requires every surviving store to hold exactly the keys of the generations whose tip survived, checking both directions. Controls that put the participant one flush behind, or hand keys in before the commit, are caught. |
| **No multi-backend trait layer** | `FlushParticipant` is not a storage abstraction and has one implementation. It writes into the one store's table through a prefix-confined writer; it does not stand between the node and the engine. |
| **Big-endian range keys** | Layout 3's rows sort by raw bytes: big-endian journal numbers, a partition byte, and chunks keyed by their last 21-byte key. `FlushWriter::range` and `try_first_after` are raw-order range reads. |

**Snapshot consistency** is unchanged. A transaction takes its overlay
snapshot and its redb snapshot under one hold of the cache lock
(`Database::begin_seed`), and the only commit that can land between them
is a flush whose captured layers are still in the overlay snapshot. The
participant's rows in that commit belong to connects whose `on_commit`
hooks ran before the capture, and so to connects whose rows are in those
layers. A reader therefore never sees index rows for a connect its
overlay snapshot does not hold.

**The hook's placement was tested, not argued.** Running the hooks before
the commit's own flush fails seven tests, both power-cut sweeps among
them. Running them after the rows are published is caught by the test
that reads from inside a hook. Moving `contribute` into a second commit
fails the sweep at the cuts between the two. Each mutation was made in
the database itself and reverted; `tests/participant.rs` lists them.

## Consequences

- **Measured on the benchmark host, 2026-10-09** (m2 in
  [bench-ledger.md](../bench-ledger.md), "Exists-address index layout
  3"). Fifteen interleaved runs over the 200,000-block tail from 916,046
  to 1,116,035, all with ADR-0010's height-first keys: six of base
  (commit 6c11a38, the index in dcrd's layout), six of layout 3, and
  three of base with the index off. Layout 3 synced at a median of
  **482.1 blocks/s** (461.8–497.5) against base's 94.0 (87.1–108.0),
  **5.1x**, and against the index-off floor's 501.1 (497.2–503.1). Its
  median sits 3.8% below the floor's, inside that storage's run-to-run
  spread. The plan had modelled 200–240 blocks/s, against a base from
  before ADR-0010. The index's measured cost is in the counts, which
  barely move from run to run. Layout 3 wrote 15.5 GB against the
  floor's 12.6 GB (+2.9 GB, +23%) and base's 137.4 GB. It used 649 s of
  CPU time against 594 s (+9%) and 1,566 s. It made the floor's 31
  metadata flushes, where base made 58–59. Its bytes (15,493 MB),
  flush-log counters and commit writes were identical in all six runs,
  and its write calls differed by at most one. Block connect does no
  store reads.
- **The plan's criteria, judged on those runs.** Speed: at least 180
  blocks/s and twice base's median (188.1); 482.1 passes. Bytes: at most
  10 GB over the floor's; 2.9 GB passes. Flush count: within 2 of the
  floor's; equal. The index digest at 916,046: the layout-3 snapshot's
  index, rebuilt from genesis after the old one was dropped, holds the
  same 49,318,296 keys, with the same BLAKE-256, as the old one. Neither
  fallback test tripped (below). Two of the plan's criteria were **not
  judged** by the method set for them. Read syscalls were to be counted
  outside the flush windows, which that harness does not separate:
  whole-run, layout 3 made 1,051,325 against the floor's 456,877, a
  count that includes its merges' level reads inside the flushes and
  the journal load. Peak memory was to be compared at a small fixed
  cache or with the cache's occupancy subtracted. At the default 1 GiB
  cache, layout 3 peaked at 2,749–2,773 MiB against the floor's
  2,423–2,424 MiB.
- **The rebuild from genesis**, measured when that snapshot was derived:
  157 s to block 916,046 on four cores with no block source, in 34
  flushes, writing 3.12 GB, at a peak of 1,727 MiB resident. Before it,
  the old index was refused with the version message, and the drop
  removed its 49,318,296 rows in 68 s.
- **The end-state checks, on a development desktop.** These were
  deterministic checks only, and no timing from that host is a
  measurement. Base and layout 3, each synced to 1,116,035 from the same
  frozen chain, hold the same index: 67,960,843 keys with the same
  BLAKE-256 digest (`dcroxide-bench existsaddr-digest`).
  A layout-3 node killed with SIGKILL just after block 1,000,009
  restarted at 998,896, the chain's last durable flush, after the
  metadata store's unclean-shutdown repair. Its index caught up one
  block, to that tip, and no further. It then synced to 1,116,035 and
  reached the same digest. Through the restart and the re-sync, no
  lookup answered `false` for an address of a block at or below the
  chain tip it had read. While the chain ran ahead, 62 of 125 lookups
  returned dcrd's "index not synced" error after the 3 s wait of the
  readiness gate the port keeps from dcrd. At the tip, 22,010 sampled
  addresses answered as dcrd's did. The journal load logs no line of its
  own (`crates/dcroxide-indexers/src/existsaddrindex.rs:457`). The
  index's startup, from its "enabled" line to its catch-up line, took
  0.33 s and reloaded about 2.1 million keys, a count derived from the
  first flush's counters.
- **Measured on a development desktop**, before the last six details
  listed under the Decision's code table. Over the tail from 916,546 to
  1,116,035, deterministic byte counts: the index-on run wrote 11.23 GB to redb against 8.02 GB with the
  index off (+40%), and 133.3 GB for layout 2 in 59 flushes; the flush
  count equalled the index-off run's, 30 in the window. Each full flush
  wrote 7–73% more than the index-off run's, its flushes took 65.2 s in
  all against 42.8 s (+52%, of which `contribute` was 12.7 s; desktop
  timings, not deterministic), and the run took 381.5 s against 307.0 s.
- **The page budget bounds a flush only while the memtable stays at or
  below `k0_hard`.** Past it, the hard bound overrides the budget, and a
  flush merges whatever its inflow needs. Late in the desktop tail the
  memtable came back to `k0_hard` after every flush, and flushes wrote
  19,500–25,300 run pages, 1.6–2.1 times the budget, and 23,900–30,500 rows
  in all, past the modelled 26,000.
- **The index's rows overflow redb's write buffer.** The plan sized the
  budget so a flush would fit half the default 1 GiB cache; it does not.
  In 30 of the tail's 31 full flushes the participant's rows pushed the
  flush past it, and pages evicted mid-flush were written again: with a
  4 GiB cache the same tail wrote 10.10 GB, so 1.13 GB of the 3.21 GB the
  index adds is pages written twice. A larger default cache, or a merge
  budget that tracks the flush's dirty set, would avoid it; both are open,
  and the first costs every node memory.
- **The fallback test did not trip, by a margin not yet explained.**
  Every byte the index writes lands inside the chain's flush, under the
  writer semaphore, so "no added cost on the critical path" holds for
  block connect and not for the flushes. The desktop review, above,
  expected the test to trip. On the benchmark host, layout 3's flushes
  committed 10.03 GB against the floor's 7.99 GB (+26%), yet took 77.8 s
  per tail (median) against the floor's 105.5 s, 0.74x where the test
  allows 1.15x. The floor's commits read 14.7–20.4 GB from storage, and
  layout 3's read 1.8–3.6 GB. Base's commits, on the floor's own
  snapshot with the index on, read under 0.1 GB. Why the floor's read so
  much has not been established. Read the result as "index-on flushes
  were not slower there", not as "the index makes flushes cheaper". The
  merge tuning above stays open.
- **The measurement that decided it**: interleaved tail runs of base,
  the new layout and index-off, judged on deterministic bytes, CPU time
  and the flush logs, with wall time reported as median and range. The
  new layout had to reach a median of at least 180 blocks/s and twice
  base's, write at most 10 GB more than index-off, and keep the flush
  count within 2 of it. The index's digest had to equal base's. The
  results are above and in [bench-ledger.md](../bench-ledger.md).
- **An index bug can now stop the node's writes.** `contribute` runs
  inside the chain's flush. An error from it latches the whole store, and
  under `panic = "abort"` a panic in it ends the process, where today a
  failed index transaction fails only the index. A damaged run row does
  the same at the first merge that reads it. That is the price of one
  durability domain. The participant does in-memory merges and
  prefix-confined writes, with every row it reads validated, and its
  failure paths are tested; but its code is on the chain's durability
  path from now on, and review should treat it so.
- **Hooks and `contribute` run under the writer semaphore**, so their time
  is every committer's wait. The index's hook is a memory insert of
  O(log n) per key. Its `contribute` is bounded by the merge budget only
  below `k0_hard` (above). It took up to 0.57 s of a flush late in the
  desktop tail. On the benchmark host it took up to 0.95 s of a flush,
  and 10.7–14.7 s per tail.
- **Memory**, measured on the desktop tail: the memtable held up to about
  3 million keys (63 MB) after each flush and 3.8–4.0 million (84 MB) at
  the start of one; a catch-up from genesis peaked at 4.5 million (95 MB).
  A connect also hands the memtable everything the mempool overlay holds,
  with no bound of its own. A restart reading 3 million journaled keys
  holds about one copy of them. The index's pages also occupy redb's page
  cache up to its configured size: the node's peak resident memory was
  about 380 MB above the index-off run's at the default 1 GiB cache, and
  about 140 MB above it with a 256 MiB cache. On the benchmark host the
  memtable held at most 3,987,345 keys (84 MB) when a flush began. At the
  default cache the node peaked at 2,749–2,773 MiB, against 2,423–2,424
  MiB with the index off and 2,504–2,506 MiB for base.
- **Lookups** read up to two 4 KiB leaves for a key the memtable does not
  hold, against one today, so a large `existsaddresses` call costs about
  twice today's I/O.
- **Divergences from dcrd**, recorded in PARITY.md.
  dcrd's transient `false` for a mempool-only address during its connect
  is closed. A store read error during a lookup is an RPC error
  ("Could not query address: ...") where dcrd's ffldb answers `false`. The
  drop's "Deleted N keys" line counts rows, not addresses.
- **Development data directories with the index** must drop it once, or
  re-sync. Snapshots taken in layout 2 cannot be reused with the index on,
  nor can a layout-3 index built before the partition key (meta row
  layout 1), which is refused as corrupt with the same remedy.

## Alternatives

- **Sorted-run files beside the metadata store, merged by a background
  compactor.** The highest modelled ceiling, 215–250 blocks/s, but its
  edge over layout 3 lies inside the benchmark storage's ~7% run-to-run
  spread. It adds a second durability domain: run-file and directory
  fsyncs, manifest ordering, an orphan sweep, deferred deletion and
  Windows file semantics. It also needs a compactor with 1.3 GB merge
  bursts, and it is the most code. It was **kept as the fallback** in
  case layout 3's median landed below about 180 blocks/s, or its flushes
  ran more than 15% slower than the index-off floor's. Neither happened:
  482.1 blocks/s, and 0.74x the floor's flush time (Consequences). It is
  not built.
- **Batched durable commits of the index outside the flush.** The slowest,
  about 165 blocks/s modelled. Each batch holds the writer semaphore for
  35–85 s, stalling every commit in the process; the design adds about 90
  scattered durable commits per tail; and an unclean stop re-indexes up to
  a whole batch window.
- **Hand the keys to memory before the commit.** Rejected. The commit's
  own flush can then journal keys whose tip row it did not capture, and
  keys stay visible after a failed commit.
  `the_checker_catches_keys_handed_in_before_the_commit` shows the first:
  after a power cut, the store holds index rows for a block it never
  recorded.
- **Run the hook after the rows are published.** Rejected: a reader could
  see the tip of block *h* and miss one of its keys.
- **Register the participant weakly, or let the index own it.** Rejected:
  the close's flush would run after the index handles are gone and skip
  the memtable, losing the keys of blocks whose tip rows it persists.
- **Keep layout 2 and advise `--noexistsaddrindex`.** That advice stands
  for operators whose wallets do not use the two RPCs. It is no answer for
  those whose wallets do.

## Addendum, 2026-10-10 — the first syncs from genesis with the layout

Every sync measured above is a 200,000-block tail, and the figures from
genesis are index rebuilds over a chain already synced. On 2026-10-09
and 2026-10-10 commit c128a93, the commit that landed layout 3, and
dcrd release v2.1.6 each synced mainnet from genesis to block 1,116,035
on m3 ([bench-ledger.md](../bench-ledger.md), "Daemon against daemon,
each from the other"): over loopback, each from a block server run by
the other, four runs per direction, defaults otherwise, so with the
index on in both. m3 is the development desktop of the end-state checks
above, in the ledger's machine table since 2026-10-10. The statement
there that no timing from that host is a measurement holds for those
checks, and the desktop tail in the bullet after them carries its own
"desktop timings, not deterministic". Neither is to be set against the
runs here, which pinned the node to eight cores and each waited for a
quiet machine.

dcroxide took a median of 1,058.6 s (1,055.8–1,065.0), **1,054.3
blocks/s**, against dcrd's 2,863.9 s and 389.7 blocks/s: 2.71x as fast.
It passed 51.4 GB to write calls and used 1,821.3 s of CPU time,
against 286.3 GB and 5,566.6 s. Over m2's window, 916,000 to the tip,
it ran at 593.0 blocks/s (584.7–599.2). The 482.1 above is another
machine, on four cores and slower storage, in another session, so the
two are not a ratio. Every run made 133 metadata flushes during the
timed sync and one at shutdown. In the four runs from dcrd's server the
133 took 159.8–170.5 s, 15.1–16.1% of wall time, with a median flush of
1.30–1.37 s and a longest of 2.44–2.97 s. The participant's
`contribute` call took 18.5–19.1 s of that, under 2% of the wall time;
the commit of the rows it wrote is inside the commit phase
(101.7–112.7 s) and is not separated. The node peaked at
2,129–2,146 MiB resident at the default cache, against dcrd's
1,848–1,852 MiB. Like the rate, that is not to be set against m2's
figures above.

Apart from that `contribute` time, which is a floor on the index's
part of a flush and not the whole of it, none of it separates the index
from the rest of the node. Neither daemon ran with
`--noexistsaddrindex`, dcroxide was not run with the index in dcrd's
layout, and neither daemon was profiled. So the 2.71x compares two
daemons whole, and measures neither the layout nor either storage
engine. These runs have no floor and no base: none of the plan's
criteria is judged again, its read and memory criteria stay unjudged,
and the flush-time margin, the write-buffer overflow and the merge
tuning stay open. The ledger records no index digest and no lookup for
these runs, so the end-state checks above remain the evidence for the
index's contents. dcrd here is its release, not the parity commit
6f6cf21b, and m3 is one machine with fast storage, over loopback. The
decision, the hooks and the guardrail table are as accepted: a sync's
rate tests no durability property.

## Addendum, 2026-10-10 (second) — the same syncs with the index off

Later the same day the two binaries of the addendum above each synced
once more on m3 with `--noexistsaddrindex`, in the same harness
([bench-ledger.md](../bench-ledger.md), "The parity commit, the index
off, two levers and a full replay"). dcroxide took 880.8 s (1,267.0
blocks/s) against the 1,058.6 s median with the index on: layout 3
costs 177.8 s, 16.8% of the sync, where five default runs span 9.2 s.
On m2's tail the gap to the floor was 3.8%, inside that storage's
spread. Here it is 11% even over the 89,438 fully validated blocks
after the assume-valid block, 461.0 blocks/s against 517.9.

The index added 164.8 s of CPU time (+10%), 7.6 GB passed to write
calls (+17%) and no flush: 133 either way. At the default cache the
node peaked at 1,996 MiB without it against 2,129–2,148 MiB, and its
data directory was 2.01 GiB smaller. The 133 flushes took 115.5 s
without it against 159.8–170.5 s, so the index's part of them is
44.3–55.0 s, `contribute` being 18.5–19.1 s of that. With the index
on, the 133 flushes took 1.38–1.48x the floor's one run. The
fallback's test allows 1.15x, m2's tail measured 0.74x, and the
desktop tail above had +52%. The test is set on m2's tail and was not
run again: this is one floor run over a whole chain on another
machine, so the status line's "tripped neither fallback test" is not
judged again. More than two thirds of the 177.8 s is outside the
flushes and is not attributed.

dcrd v2.1.6 took 1,247.8 s against 2,863.9 s: at its defaults the
index in its own layout costs it 1,616.1 s, 56% of its sync. The
Context's "goleveldb absorbs that cheaply" was not a measurement. With
the index off dcroxide is 1.42x as fast, and 1,438.3 s of the
1,805.3 s between the two at their defaults (80%) is the difference in
what the index costs each.

Each floor is one run, and dcrd's is its release's: the parity commit
ran only with the index on (2,909.8 s and 2,869.8 s, a mean 0.9% over
the release's median). In dcrd's floor run the dcroxide server read its
block files from the drive as it served them; if that slowed dcrd, the
index costs it more than 56%. No base arm ran on m3, so layout 3 is still not
measured from genesis against dcrd's layout on redb, and none of the
plan's criteria is judged again; its read and memory criteria stay
unjudged. Neither daemon was profiled, and m2's flush-time margin, the
write-buffer overflow and the merge tuning stay open.

## Addendum, 2026-10-11 — the indexes on their own thread

Since 2026-10-11 the daemon no longer updates the indexes on the
block-processing thread. Each drained block event's notification goes
onto a 128-deep bounded queue served by one thread, as dcrd's subscriber
does with its channel and goroutine ([PARITY.md](../../PARITY.md), the
`internal/blockchain/indexers` row). Three statements above are no
longer exact for the daemon:

- **"The tip row, its timing, the subscriber, catch-up and recovery are
  unchanged."** The subscriber, catch-up and recovery are. The timing is
  not: a block's index update, its tip row included, is committed by the
  index thread after the block has connected, and the index can trail
  the chain by a little more than the queue's depth. The keys are still
  visible no later than the tip, since the hook still runs inside that
  commit before the tip row is published.
- **The copy of the mempool's addresses at connect** (the mempool race
  under Consequences). The copy is made when the connect is queued, on
  the thread that drained the event, and installed for the index thread's
  update; under inline delivery (in-process tests, catch-up, the vectors,
  `dcroxide-bench replay`) it is made at the connect as before. A mempool
  address is therefore persisted with the first block connected after it
  was seen and not with an earlier one still queued, which dcrd's
  goroutine would do.
- **"The daemon drops its index handles before it closes the
  database."** It first stops and joins the index thread, before its
  final chain flush, so the thread's last commit is inside the shutdown
  flushes; what is still queued is dropped, and the next start's
  catch-up indexes it.

The two database hooks and their contract are untouched. Commits still
serialize on the writer semaphore, the participant still contributes
inside the flush under it, and the hand-over still runs between the
commit's own flush and the publication of its tip row. What changed is
which thread a flush runs on: one tripped by an index commit now runs on
the index thread, with the block-processing thread free until it needs
the writer. On disk the index tip is still never ahead of the chain,
because a block's index commit follows its connect and a flush captures
a prefix of the commit order. A crash now leaves the index up to the
queue's depth plus two blocks behind (128 queued, one the index thread
has taken and not yet committed, one connected and not yet queued), or
more when one processing call connected several blocks, where it was at
most the blocks of one call, normally one; catch-up repairs any lag.
That bound is read from the code and was not tested. The daemon's
power-cut test (`crates/dcroxide-node/tests/existsaddr_powerloss.rs`:
four SIGKILLs of a mining simnet daemon under `tools/powerloss`) runs
the daemon, so it now exercises the queued path. The `PowerLossBackend`
sweeps do not: the index's (`existsaddr/tests.rs`) call the subscriber
directly, and the database's (`tests/participant.rs`) use a stand-in
participant with no index.

On m3 two default syncs took 759.1 s and 756.2 s with the thread where
one of the commit before it, without, took 820.3 s
([bench-ledger.md](../bench-ledger.md), "Five changes on the
block-processing thread"). Node CPU time did not fall (the work moved),
and peak resident memory rose from 2,146 MiB to 2,621 and 2,624 MiB,
which was not examined. How long the block-processing thread and the index thread
wait for each other at the writer was not measured, the fallback's
flush-time test was not run again, and none of the plan's criteria is
judged again.

## Addendum, 2026-10-11 (second) — the participant now paces most commits of a sync

Since the afternoon of 2026-10-11 a UTXO cache flush that only the
cache's size limit tripped no longer forces a metadata commit
([ADR-0004](0004-storage-backend.md), addendum of that date), and the
overlay's default ceiling is 300 MiB. A default sync on m3 now makes 54
flushes where it made 133 ([bench-ledger.md](../bench-ledger.md),
"Shared commits for UTXO-cache flushes, the filesystem's share and a
delayed link"). Nothing in the hooks or their contract changed, but what
trips a flush did. In one of the three syncs measured, the overlay's own
size tripped 11 of the 54, all within 141 s of the first flush; five
more, about 122 s apart, are presumably the UTXO cache's periodic flush;
and the other 38 journaled 1.1–1.25 million keys each with the overlay
well under its trigger, which is the participant's `wants_flush`.
`u_max` counts 1,500,000 keys new to the memtable, and about 1.2 million
of them are journaled, because the keys of the partitions a flush merges
go into their runs and not the journal. So the trigger this ADR added
for the index's catch-up now paces most durable commits of an initial
sync with the index on. With the index off, the overlay's size tripped
36 of 41.

In those three syncs the largest flush journaled 1,254,393 to 1,272,007
keys, against 858,923 in a sync of the code before; the memtable peaked
at 4.50 million keys against 3.99 million, which is `k0_hard` plus
`u_max`; the participant's own time was 15.0–15.1 s over 53 flushes
against 18.8 s over 129, and its merges about 2,520 against 3,387. Peak
resident memory with the index on rose from 2,635 MiB to 3,090–3,285 MiB
and was 2,138 MiB with it off, so the index now accounts for about
0.9–1.1 GiB of the peak (952–1,147 MiB), where at `c128a93` it was about
140 MiB. The code before this change was not run with the index off, so
how much of that came with this change was not measured. What holds it
was not established, and the memtable's extra half million keys do not
account for it. The merge budget and `u_max` were tuned at the old
cadence and were not re-tuned. A test now stops the node uncleanly after
a commit the index asked for and checks the reopened UTXO set and index
(`crates/dcroxide-node/tests/index_thread.rs`).

The line numbers cited in the text above are those of the commit this
ADR was accepted at. The change of 2026-10-11 moved the cited lines of
`dcroxide-database`'s `lib.rs` and `dbcache.rs` down by four to six and
those of `policy.rs` by three; the functions they name are unchanged.

## Addendum, 2026-10-12 — a queued connect is prepared before it takes the writer

Since 2026-10-12 the index does the part of a queued connect that needs
no transaction before the update's write transaction begins. A connect
that the daemon's index thread delivers comes with the copy of the
mempool overlay made when it was queued (the first addendum of
2026-10-11; `crates/dcroxide-node/src/indexes.rs:303`). For such a
connect the subscriber takes the index's mutex, has the index extract
the block's addresses, add the copied keys, hash each key to its
partition, filter the keys against the memtable, sort them and hash the
header (`Indexer::prepare_notification`, called at
`crates/dcroxide-indexers/src/subscriber.rs:294`), and only then begins
the write transaction (`:295`), which is where the writer semaphore is
claimed. dcrd does all of it inside the notification's `dbTx`
(`existsaddrindex.go:383-444`, `:451-456`), and until this change so
did the port. The bucket check, the tip row and the `on_commit` hook
stay in the transaction. Every other connect has no copy to bring
(catch-up, inline delivery, a direct call): it takes the overlay as it
stands once it has the writer and filters inside its transaction, as
before. A disconnect only moves the tip. What was prepared goes back to
the index through `Indexer::process_prepared_notification`
(`crates/dcroxide-indexers/src/common.rs:149`) and is used only for the
connect of the very block it was made for, the same allocation
(`existsaddrindex.rs:793`). Handed to any other notification it is
dropped whole, and the work is done inside the transaction.

Decision part 2's sentence on a connect ("copies the mempool overlay,
filters its candidates against the memtable without a store read, puts
the tip row as today, and registers an `on_commit` hook") still lists
what a connect does. What moved for a queued connect is its first
filter, which is now made under the index's mutex and without the
writer, and that filter is advisory. Nothing enters the memtable before
the commit hook, and the hook checks each key again under its
partition's write lock (`Memtable::insert_candidates`,
`existsaddr/memtable.rs:174`), which is what keeps a partition's
vectors disjoint. A transaction that fails, or one that never begins,
therefore leaves nothing in the index to undo, and the copied keys are
still in the overlay for the next connect. The two database hooks and
their contract are untouched: the hand-over still runs between the
commit's own flush and the publication of the tip row, the participant
still contributes inside the flush under the writer, and the lock order
is still the index's mutex and then the writer.

The filter made before the transaction is still good when the hook runs
because of where keys enter and leave the memtable (the comment on
`prepare_connect`, `existsaddrindex.rs:746`, carries the argument).
They enter it only in this index's commit hooks and in the load when
the index is opened. A hook exists only for a transaction that this
index's connect ran in, which needs the index's mutex, and it runs
under the writer; the subscriber holds the mutex from before the
prepare until the connect has returned, and the writer from its `begin`
until its own hook has run. They leave it only when a committed flush
clears the partitions it merged, whose keys are by then in the runs
that commit wrote, and when the index is reloaded or dropped, which
needs the mutex. So a key the filter left out as held is, at the hook,
still held or in a run, and a key it kept is inserted unless the hook
finds it held. A caller outside the subscriber could commit a connect
of its own between a prepare and its hook, and the hook's check skips
what that added.

One thing differs, and it depends on timing. When another thread's
commit flushes between the filter and the transaction, a key of a
partition that flush merged has been left out by the filter, as held. A
filter made inside the transaction finds the partition empty and hands
the key over again, a duplicate of its run's key for a later merge to
drop. So the memtable and the journal can hold one duplicate fewer than
before; the set of keys the index holds, and every answer, are the
same. A flush on another thread is the ordinary case and not a rare
interleaving: in the 628.0 s sync below, by the flush log's `thread`,
43 of the 56 flushes ran on the thread that connects blocks and 13 on
the index thread. How many keys the difference kept out of that sync's
journal was not counted.

The index's keys are compared inline since the same day. The memtable's
lookups, merges and per-partition sort, the journal's batch sort, the
union of runs in a merge and the order check on a decoded row use
`cmp_keys` (`crates/dcroxide-indexers/src/existsaddr/mod.rs:60`), which
reads a key as three big-endian words, the third overlapping the second
by three bytes, and compares them in place. That is the order of the
keys' bytes, which the array type's own comparison gave through a call
to the C library's `memcmp` at every step of a search or a merge. The
order is part of the on-disk format, and the format and every answer
are unchanged. The connect's sort of its candidates, the load's sort at
a restart and a lookup's search of a chunk still use the array type's
comparison, in the same order. So "Hooks and `contribute` run under the
writer semaphore" stands as written, with a cheaper comparison inside
both.

On m3 on 2026-10-12, on a quiet machine, the two changes were measured
together with a third that is not the index's, one lookup of each
ticket bucket per best-node write in the stake database, and not one at
a time ([bench-ledger.md](../bench-ledger.md), "Eleven changes, a
background commit not kept and a pool gate"). One
default sync to block 1,116,035 took 628.0 s on the tree of `6271436`,
which holds the three, where the run before it, on the tree of
`a83f9a1`, took 673.8 s: 45.8 s or 6.8% less, one run each. `a83f9a1`
had added a timer on the writer semaphore to the flush log
(`writer_wait`, [operating.md](../operating.md)), which answers what
the first addendum of 2026-10-11 left unmeasured, how long the two
threads wait for each other. From the opening of the database to its
last flush, the threads other than the index thread waited 74.9 s for
the writer in the 673.8 s sync, in 401,906 waits, and the index thread
0.02 s in 295. In the 628.0 s sync the others waited 30.7 s in 166,810
waits and the index thread 30.4 s in 97,538. The participant's
`contribute` took 12.3 s over 54 flushes where it had taken 15.2 s over
53, node CPU time was 1,393.8 s against 1,400.9 s, and peak resident
memory 3,224 MiB against 3,299 MiB.

Those figures do not separate the three changes. No sync ran with the
prepare alone, the comparison alone or the bucket lookups alone, so
what each is worth is not known, and neither is how the 44.3 s by which
the other threads' wait fell divides between them. `other` is every
thread but the one named `index`, the close and any RPC that writes
among them, so it bounds from above what the thread that connects
blocks waited. It is one run against one run on one machine, over
loopback. No sync of that day ran with the index off, so the index's
share of a sync (16% on 2026-10-11) and of its peak memory are not
known for the code as it stands; the fallback's flush-time test was not
run again, and none of the plan's criteria is judged again.

The tests are in `crates/dcroxide-indexers/src/existsaddr/tests.rs`. A
queued connect is prepared while another transaction holds the writer
(`a_queued_connect_is_prepared_before_the_subscriber_claims_the_writer`),
no other thread finds the index's mutex free between a prepare and its
connect (`the_index_lock_is_held_from_a_prepare_until_its_connect`), a
connect without a copy takes the overlay only once it has the writer
(`a_connect_with_no_copy_takes_the_overlay_once_it_has_the_writer`), a
prepared connect leaves the index as one inside its transaction does
(`a_prepared_connect_leaves_the_index_as_a_connect_inside_its_transaction_does`),
a flush placed between the prepare and the transaction of every
connect loses no key
(`a_flush_between_a_prepare_and_its_transaction_loses_no_key`), what
was prepared for one connect is dropped when it is handed to the
connect of another block or to a disconnect, as is a result that is not
this index's
(`what_was_prepared_for_one_connect_is_not_used_for_another_notification`),
an update that fails after the prepare, by a rollback, a failed commit
or a transaction that never begins, leaves the index as it was
(`an_update_that_fails_after_the_prepare_leaves_the_index_as_it_was`),
and a connect delivered again after its update rolled back is done
afresh inside its transaction
(`a_connect_delivered_again_after_its_update_rolled_back_starts_afresh`).
The first addendum of 2026-10-11 says the index's `PowerLossBackend`
sweeps call the subscriber directly and so do not exercise the queued
path.
They now run a second time with every connect delivered with its copy
and prepared before its transaction
(`a_power_cut_at_every_storage_operation_of_prepared_connects_keeps_index_and_tip_together`
and its random companion), from the test's own thread and not through
the daemon's queue. The comparison is held to the byte order by
`the_inline_key_comparison_is_the_byte_order` and
`every_place_that_compares_keys_keeps_the_byte_order`.

The line numbers cited above this addendum stay those of the commit
the ADR was accepted at, and the commits of 2026-10-12 moved more of
them. In `existsaddrindex.rs` the version refusal's `:472` is at
`:489`, the lookup's `:212` and `:250` at `:229` and `:267`, the load
and registration's `:498` and `:522` at `:515` and `:539`, the drops'
`:853` and `:897` at `:999` and `:1043`, and the journal load's `:457`
at `:474`. The connect row's `:630` and `:755` named one function that
is now several: the address extraction is at `:630`, the candidates and
their filter at `:697`, `prepare_connect` at `:746`, `connect_block` at
`:786`, and the hook at `:841`, registered at `:862`. In
`existsaddr/store.rs`, `:205`, `:213`, `:324` and `:367` are at `:211`,
`:219`, `:330` and `:373`. In `dcroxide-database`, the wait timer moved
the cited lines of `lib.rs` from `:320` on: `:320` is at `:359`,
`:662`, `:674` and `:704` at `:784`, `:796` and `:829`, `:1674-1698` at
`:1782-1806`, `:1738` at `:1846` and `:1802` at `:1910`; and those of
`dbcache.rs` by four more, nine in all (`:749`, `:784`, `:820`, `:845`
and `:896` are at `:758`, `:793`, `:829`, `:854` and `:905`). The cited
lines of `lib.rs` before `:320`, of `transaction.rs`, `participant.rs`
and `dcroxide.rs`, and of `policy.rs` since 2026-10-11, did not move.
The functions named are unchanged but for the connect, divided as
above.

## Addendum, 2026-10-16 — the commit hook trusts a partition that has not changed since the filter

The addendum of 2026-10-12 calls the filter made before the transaction
advisory: nothing enters the memtable before the commit hook, and the
hook checks each key again under its partition's write lock, which is
what keeps a partition's vectors disjoint. Since `64359e7` the hook
makes that second search only where something may have changed. Each
partition counts the changes to its vectors, its version. The only two
places that write the vectors, `Part::add_run` for an insert that adds a
run and `Part::replace` for a flush's fold, a flush's clear of a
partition it merged and a load, both under the partition's write lock,
move it, and nothing sets it back. `Memtable::filter`
(`existsaddr/memtable.rs:230`) reads a partition's version under the
same read lock as its search, before the search, and each key it keeps
carries that version. `Memtable::insert_candidates` (`:268`) takes a
partition's keys as one run, without a search, a sort or a pass for
repeats, when every one of them carries the partition's current version
and they strictly ascend. Any other group is searched key by key and
sorted, as before, and a debug build still searches on the first path,
as an assertion. An unmoved version means nothing entered or left the
partition since each key was found missing, so the search would have
removed nothing, and ascending keys are what the sort would have left.
Disjointness now rests on the version where it stands and on the search
where it has moved, and the filter is no longer advisory: where its
partition has not moved, it is what the hook inserts.

The argument of the addendum of 2026-10-12 for why the filter is still
good at the hook stands. Its last sentence reads the same with the
version in it: a caller outside the subscriber that commits a connect of
its own between a prepare and its hook moves the versions of the
partitions it inserts into, so the hook searches those and skips what
that connect added. On the daemon's index thread nothing comes between
the filter and the hook but a flush, which moves the versions of the
partitions it changes.

A version says something only of the memtable it was read from. So what
a connect prepared now names the store it was filtered against, and
`connect_block` uses it only on that store and for that very block
(`existsaddrindex.rs:820-821`). Handed to another instance of the index,
it is dropped whole and the work is done inside the transaction, as the
documentation of `Indexer::process_prepared_notification` already asked.
The daemon runs one instance, so only a direct call can meet this.

The run that goes in is the run the search would have made, so the
merges, the journal, the flush log's counters, the rows on disk and
every answer are unchanged. No on-disk format, policy constant or lock
order changes, and the two database hooks and their contract are
untouched. Two other commits of the same day touch the hooks'
surroundings without changing that contract. `85a5dc8` has a commit and
`Database::flush` free the overlay layers a flush retired once the
writer semaphore is released, on the thread that flushed, where they
were freed while it was held; `finished` is still called under the
writer. And `6376eeb` keeps a copy of the bucket index in memory,
updated as each commit publishes its rows; a participant's rows never
pass through a commit, so the refusal of a participant prefix inside the
bucket index, which registration already made, is now a condition of
that copy being right.

Measured only with `85a5dc8` and not one at a time, on m3 on 2026-10-13
([bench-ledger.md](../bench-ledger.md), "Seven cumulative builds, the
validation pool, a background commit and dcrd"), in a series of builds
on `4700cf1` that each added one change or group of changes to the build
before. Every build of it also held a developer variable for this
index's flush request that is not in the tree, so the code as committed
has not been run in a sync. The build that added the two took 466.7 s
against 481.7 s for the build before it, one run each. Those 15.0 s are
not the gain: the earlier run's flushes spent about 8 s longer in their
commit phase, for reasons the records do not give. With the commit
seconds taken out the step is 7.0 s, and by the node's clock less its
flush time 6.5 s, each good to 3.5 to 6 s either way, so one run's best
estimate and not an established figure. What holds beyond one run is the
wait the two act on. The flush log's total of the waits for the writer
by the threads other than the index thread, which bounds the wait of the
thread that connects blocks from above, less the flushes the index
thread ran, was 8.1 to 9.5 s in the eleven runs of earlier code that
session that committed on the flushing thread and changed no other
setting, and 1.6 to 1.7 s in all five runs of builds with the two. The
same session has the one run with the index off since the addendum of
2026-10-12: `4700cf1`, without this change, took 423.6 s with
`--noexistsaddrindex` against 504.2 to 513.5 s in three runs at the
defaults, two of which had slow commit phases, and peaked at 2,149 MiB
against 2,832 to 3,128 MiB, read before the closing flush. So the
index's share of a sync and of its peak is known for `4700cf1` from one
run, and not for the code as it stands. The fallback's flush-time test
was not run again, and none of the plan's criteria is judged again.

The tests are in `crates/dcroxide-indexers/src/existsaddr/memtable.rs`
(the first four) and `existsaddr/tests.rs`: a partition's version moves
with every change to its vectors and to no other partition's, and never
back
(`a_version_moves_with_every_change_to_its_partition_and_never_back`);
an insert searches only the partitions changed since its filter
(`an_insert_searches_only_the_partitions_changed_since_its_filter`);
threads that filter without the writer and insert with it held, with
flushes among them, leave no key twice
(`filters_that_race_inserts_leave_no_key_twice`); a memtable that trusts
its versions and one that searches for every key hold the same vectors
through random filters, inserts, flushes and loads
(`random_interleavings_leave_what_a_search_for_every_key_leaves`); two
indexes, one of each kind, hold the same tip row, keys, memtable and
rows through a script with another connect, a flush or a disconnect
between a prepare and its connect
(`a_hook_that_trusts_its_versions_leaves_what_one_that_searches_leaves`);
a scripted run ends at a digest pinned from `4700cf1`
(`a_scripted_run_writes_the_rows_it_wrote_when_the_hook_searched_for_every_key`);
a block's journal row holds the bytes it held
(`a_blocks_journal_row_holds_the_bytes_it_always_held`); on the
subscriber's path with no flush the hook searches for nothing
(`a_connect_through_the_subscriber_searches_the_memtable_once`); and
what one index prepared is not used by another
(`what_one_index_prepared_is_not_used_by_another`). They have run on
Linux only.

The changes of 2026-10-16 moved more of the lines cited above, whose
numbers stay as they were written. In `existsaddrindex.rs` the version
constant is now at `:48`, the version refusal at `:497`, the lookup's
two at `:237` and `:275`, the load and registration at `:523` and
`:547`, the drops at `:1031` and `:1075`, the journal load at `:482`,
the address extraction at `:638`, the candidates at `:705`,
`prepare_connect` at `:767`, `connect_block` at `:810`, and the hook at
`:870`, registered at `:892`; `Memtable::insert_candidates` is at
`existsaddr/memtable.rs:268`. In `dcroxide-database`'s `lib.rs`,
`begin_durable_write` is at `:158`, the latch's `:187` and `:212` at
`:199` and `:224`, the participant's field at `:404`, `flush_locked` at
`:875` with `wants_flush` asked at `:890` and `finished` called at
`:923`, `close` at `:1919-1944`, `set_flush_participant` at `:1983` and
`clear_flush_participant` at `:2051`. In `dbcache.rs`, `has_work` is
asked at `:916`, the prefix guard is at `:951`, `contribute` is called
at `:987`, the commit at `:1012` and the participant-only flush's count
at `:1073`. In `transaction.rs`, `raw_id` is at `:1817`, the prefix
check at `:1228` and its call in the commit at `:1293`, `on_commit` at
`:1212`, the commit's own flush at `:1371`, its hooks taken at `:1396`
and its rows published at `:1420`, the hooks dropped by a rollback at
`:1180`, and `try_first_after` and `try_scan_after` at `:696` and
`:712`. `participant.rs`'s key check is at `:325`. The cited lines of
`existsaddr/store.rs`, `policy.rs` and `mod.rs`, of `subscriber.rs`,
`common.rs`, `indexes.rs`, `participant.rs:64` and `dcroxide.rs` did not
move. The functions named are unchanged but for the hook's insert and
`connect_block`, as above.
