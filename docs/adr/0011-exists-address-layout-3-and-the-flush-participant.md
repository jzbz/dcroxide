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
