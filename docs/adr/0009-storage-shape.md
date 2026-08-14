# ADR-0009 — Storage rework: what the evidence supports, and what must be measured first

- **Status:** Proposed — **all four prerequisites measured as of 2026-08-13,
  and the three conditions this ADR set on an engine change are met. What
  remains is a decision, not a measurement, and ratifying or superseding
  this ADR is the project owner's call.**
- **Date:** 2026-08-10 (proposed), 2026-08-13 (prerequisites complete)

**Read this first.** The ADR below is a record of an investigation that
changed direction more than once, and the reasoning it superseded is kept
deliberately. The current position, in four lines:

- The metadata gap is the storage engine and nothing else. Both
  implementations store the *same payload*, so no encoding or
  data-difference explanation survives.
- Nothing above the engine shrinks the store. All four ADR-0004 levers are
  measured and closed, which satisfies that ADR's revisit gate.
- A candidate engine reaches goleveldb's density on dcroxide's own write
  pattern: 5.80 GiB against redb's 16.00 for byte-identical content, with
  faster reads. The rig that measured it reproduces a known baseline to
  0.008% and its oracle arm confirms the target is real.
- The blockers this ADR placed on adopting it are cleared. **That is not a
  recommendation to adopt it.** It is a pre-alpha node with unaddressed
  security and ecosystem-acceptance work; this ADR's own "do nothing,
  indefinitely" alternative argues deferral is cheap because the rework's
  difficulty does not track chain size. Whether 10 GiB of disk is worth a
  storage migration now is a priorities judgement, and it has not been made.

## Context

[ADR-0004](0004-storage-backend.md) chose `redb` and set a gate: revisit only
if sync time or metadata size becomes a release blocker *after* its four
levers have been measured and found insufficient. This ADR reports where that
stands and proposes the next step.

An earlier draft of this document proposed splitting the metadata store into
append-only files plus an LSM, on the strength of a "goleveldb carries 9%
overhead, redb carries 156%" comparison. Adversarial review found the
comparison invalid and the design wrong on its own premises. Both are
recorded below rather than quietly dropped, because the errors are
instructive and because the ADR's evidence base is the point of the file.

**That withdrawal was itself half wrong, and the half matters.** The design
was wrong for the reasons given, and stays withdrawn. The *comparison* was
withdrawn on the premise that dcrd must hold less payload — inferred from
its `utxodb` file being smaller than dcroxide's `utxosetv3` payload, on the
reasoning that no structural efficiency can put a file under the bytes it
stores. That reasoning is false: goleveldb's sstable blocks store only each
key's non-shared suffix, so with compression off dcrd's `utxodb` really does
hold 127,657,896 B of payload in a 119,405,557 B file, 0.935x. Measuring
both sides instead of deriving one (2026-08-11, prerequisite 2 below) shows
the payloads are the same to 54 bytes in 6.06 GB. The comparison is
reinstated, with bases named; the specific number "156%" is not, because it
was computed on the whole-file figure, which is the least reproducible
quantity in this whole investigation.

### What is measured

- **Lever (a), long-lived read transactions: closed.** Three probe arms
  differed by 0.0008%, in the direction opposite to pinning.
- **Levers (b) read cache and (c) flush cadence: no effect on fill.** Five
  full-chain arms, an eightfold page cache and an eightfold flush cadence;
  fill spanned 0.6450 to 0.6462, a spread of 0.0011. Lever (c) raises free
  pages. The *throughput* half of that sweep was voided by a 1.64x drift
  between two runs of the identical baseline.
- **Fill is the stable property.** 0.645 to 0.649 across every run, tree size
  and index configuration, converging on the real datadir's 0.6486 when
  composition matches.
- **Free pages are reused working space**, not recoverable garbage, and swing
  1.6% to 33.0% across the last ten flushes of a single run.
- **On-disk totals at the same height:** dcrd 6.15 GiB of metadata across two
  goleveldb databases; dcroxide 14.48 GiB in one `metadata.redb`, of which
  the live tree is 9.79 GiB and the payload 5.65 GiB.
- **Payload, both sides, matched composition (2026-08-11).** The same
  payload: dcrd 6,061,905,929 B against dcroxide 6,069,302,583 B, fifteen
  buckets equal to the byte, the difference accounted for to 54 bytes by a
  4-byte bucket-id prefix on 1,849,177 UTXO rows. Over each store's own
  payload, apparent length on disk: goleveldb **1.081x**, redb's live tree
  **1.738x**, redb's whole file 2.832x uncompacted and 2.132x compacted.
  (**Corrected 2026-08-12:** this line read "consumed on disk" and 2.566x
  for the uncompacted file, which is the retracted `st_blocks` figure. The
  compacted file is dense, so the two metrics agree at 2.132x.)

### What is not measured, and blocks the gate

- **Lever (d) is measured, and half closed.** `spendjournalv3` is one row per
  4096-byte page at a 2402 B mean, 1.74 GiB of the 2.33 GiB of predicted
  slack. The page-size remedy is unreachable (redb gates `set_page_size`
  behind `cfg(any(fuzzing, test))`). The row-encoding remedy lost its
  precedent on 2026-08-11: dcrd stores that bucket at exactly the same
  2,643,223,854 B over the same 1,100,392 rows, so a denser row is a
  divergence to invent rather than a dcrd behaviour to copy. What is **not**
  closed is the arithmetic — a row under ~2040 B still recovers ~1.74 GiB —
  nor a re-*keying* that splits the row while storing dcrd's exact bytes,
  which has never been tested. **ADR-0004's gate is therefore still not
  formally satisfied**, though what remains under it is narrow.
  **Superseded 2026-08-12.** The re-keying is now tested and refuted — six
  layouts built at the bucket's real dimensions, today's the smallest, every
  split costing 0.18–0.38 GiB — and the slack measures 1.536 GiB against the
  modelled 1.74, of which ~86% is B-tree leaf under-fill and ~14% the
  allocator's power-of-two rounding. The "1 row per page" premise was a model
  artifact; the bucket packs 1.55 rows per leaf node. All four levers are now
  measured and none is sufficient, so **ADR-0004's revisit gate is
  satisfied**. The only remedy left inside this engine is an encoding denser
  than the reference implementation's.
- ~~**dcrd's payload is unknown.**~~ **Measured, 2026-08-11.** The argument
  that stood here — that dcrd's whole `utxodb` being 0.108 GiB against
  dcroxide's 0.13 GiB `utxosetv3` payload proves denser dcrd encodings,
  since "negative overhead is impossible over identical bytes" — was wrong
  twice. It compared a *file* against a *payload*, and its premise is false:
  goleveldb elides shared key prefixes, so a file under its own payload is
  routine, not impossible. Measured payload against payload, the two stores
  hold the same bytes and dcrd's encodings are not denser. See
  prerequisite 2.
- **The 2026-07 dcrd baseline's index configuration was never recorded** and
  its datadir is gone; this project has already retracted one conclusion for
  exactly that failure mode. The 2026-08-11 pair fixes it going forward —
  composition recorded on both sides, datadir preserved and rowed in
  [bench-ledger.md](../bench-ledger.md) — but it does not recover the old
  one. That figure can be bounded (dcrd metadata is 4.09 GiB without the
  address index and 5.98 with it, so 6.045 GiB excludes any composition
  differing by a bucket of hundreds of MiB) but not identified: a file size
  is not a composition fingerprint. Retire the 2026-07 figure rather than
  back-filling a composition onto a datadir that no longer exists.
- **Commit cost is not established as the dominant term.** The 2.2x IBD gap
  is attributed to commit shape by a progress-stall statistic — which records
  that progress halted, not what halted it — and no profile exists. The
  ledger bounds it the other way: the full `--addrindex` replay spent 863 s
  of 4,767 s in flushes, 18%, and ran at 230.8 blk/s against the live sync's
  124. Roughly half of IBD wall time is outside the storage path on an
  identical engine. **An LSM cannot close 2.2x on its own**, and the
  replay-versus-sync gap is the larger unexplained term.

### The corrected structural figure

The defensible comparison excludes free pages from dcroxide's side, since
this ADR's own evidence calls them working space:

| | GiB | over payload |
|---|---:|---:|
| payload (76,302,003 rows) | 5.65 | — |
| live B-tree | 9.79 | **1.73x** |
| whole file, including free pages | 14.48 | 2.56x (not a structural figure) |

That 14.48 GiB is the 2026-07 live-synced store. The 2.832x in the table
above it is a *different* store — the matched-composition replay, 16.00 GiB
apparent — so the two whole-file multiples are not a discrepancy but they
are not comparable either, which is the point of quoting the live tree
instead.

So redb's *structural* overhead is about 73%, not 156%. The attributable
part is 0.69 GiB of engine overhead plus 3.44 GiB of slack.

Since 2026-08-11 that table has a counterpart on the other side, over the
*same* payload, disk measured as apparent length rather than consumed:

| | over its own payload |
|---|---:|
| dcrd, goleveldb, both stores | **1.081x** |
| dcroxide, redb live B-tree | **1.738x** (1.726x on dcrd's write schedule) |
| dcroxide, whole file, compacted | 2.132x |
| dcroxide, whole file, uncompacted | 2.832x |

Quote the first two, and quote the redb side as *apparent* length or live
tree — never `st_blocks`. redb extends with a bare `set_len` and never
punches a hole, so consumed bytes are a high-water mark that climbs toward
the claimed length as the node runs; two stores of byte-identical length have
already been measured 717 MB apart on that metric alone. The choice moves
only redb's side: goleveldb's 3,179 files consume 1.001x their apparent
length, rounding up to 4 KiB blocks, so the 2026-08-12 correction left its
column where it was. goleveldb's 1.081x is itself net of shared-key-prefix
elision, so it is not a pure packing figure to set against redb's 0.646
fill.

Two caveats travelled with these numbers. One is now measured:

- ~~The write schedules differed.~~ **Measured 2026-08-12.** Rebuilding the
  address index dcroxide-side in one catch-up pass — dcrd's schedule, via
  `dcroxide-bench indexcatchup` — moves the live tree −0.68% and fill +0.004,
  *in dcroxide's favour*. The schedule-matched structural figure is **1.726x**
  against the shipped path's 1.738x, so the schedule accounts for about 1.8%
  of the excess over goleveldb's 1.081x. The mechanism was right and the
  magnitude was not. Bounded rather than closed: only exists-address rows
  changed schedule, neither arm was compacted, and goleveldb's own schedule
  sensitivity — the premise of the objection — was never measured.
- **Equality of payload is equality of *summed* key and value lengths**, not
  a content diff. Fifteen buckets agreeing at byte resolution makes
  coincidence implausible, but a digest over each side's sorted stream is
  what would make it proof.

## Decision (proposed)

**All four prerequisites are measured as of 2026-08-13. The recommendation
is: take the redb 4.1.0 upgrade now, and propose fjall as a conditional
change that does not start until three named conditions are met.**

The size case is no longer arguable. On the identical engine-level journal,
dcroxide's 76,301,856 rows occupy **5.80 GiB under fjall against 16.00 GiB
under redb 2.6.3** — 1.026x payload against 2.831x, marginally denser than
goleveldb itself, with reads 3.5x faster and a bulk load 22x faster. Every
pre-registered size and speed threshold clears with room:

| gate | threshold, set before any arm ran | fjall | |
|---|---|---|---|
| A — size settled | ≤ 1.25x payload | 1.026x | ✓ |
| A — size peak | ≤ 1.60x payload | 1.519x | ✓ |
| B — point reads | ≤ 1.5x redb | 0.29x | ✓ |
| B — full scan | ≤ 1.5x redb | 0.12x | ✓ |
| B — load time | ≤ 1.15x redb | 0.04x | ✓ |
| D — constraints | pure Rust, no C toolchain | no LZ4, no bindgen | ✓ |
| **C — crash safety** | **zero failures AND no open upstream issue on the atomicity invariant** | **see below** | **✗** |

**Gate C is not met, and it is the gate ADR-0004 chose redb for.** The
mechanical half passes: three `kill -9`s per engine, each batch writing a
marker inside its own atomic unit, zero missing rows, zero wrong values,
zero rows leaked from an uncommitted batch. But gate C was deliberately
written wider than a kill test, and the wider half fails:

- **fjall #308 is open, filed against 3.1.8, and lands exactly on this
  project's hard requirement.** `WriteBatch::commit()` does not poison the
  database when a journal write fails; a later batch then commits after the
  unterminated record and returns `Ok`, and recovery truncates from the
  first bad record on reopen. That is `commit()` returning success for a
  batch that does not survive restart — the precise thing
  `process.rs:908-916` exists to prevent. A `kill -9` does not exercise it,
  because it needs a *write failure*, not process death.
- **fjall #311 is open**: no strict recovery mode, so mid-journal corruption
  is indistinguishable from a torn tail and presents as silent truncation
  rather than a loud failure.
- **The default is not durable.** `Database::batch()` hands back
  `PersistMode::Buffer`, which returns `Ok` with no fsync. The arms here
  used `SyncData` explicitly. redb gives durability unless asked otherwise;
  fjall gives speed unless asked otherwise, which inverts the polarity of
  ADR-0004's durable-defaults rule and leaves a standing footgun in every
  future code path that forgets it.

**So the three conditions before a fjall migration starts:**

1. ~~#308 fixed upstream, or proven unreachable by dcroxide's usage.~~
   **Checked 2026-08-13: it was reachable, and is now closed by a change.**

   The check found that dcroxide supplied all three conditions the bug
   needs. (i) fjall issues the unpoisoned write only for batches over its
   8 KiB journal buffer — `WriteBatch::commit` calls `write_batch` with a
   bare `?` (`src/batch/mod.rs:115`) where the `persist` two lines below
   poisons and even rewrites the error to `Error::Poisoned` — and
   dcroxide's flush batch, block index rows plus UTXO entries plus both
   state markers, is far over that. (ii) Nothing excludes a journal write
   failure; the `kill -9` suite cannot produce one, which is why the
   existing evidence never touched it. (iii) **dcroxide would issue a later
   commit after a failed one.** `DbCache::flush` returns at the `?` before
   clearing the dirty set, so the failed batch survives in the cache and
   the next flush retries it; `DbInner` carried one `AtomicBool`, `closed`,
   written only by `Database::close`; and a storage error reaches
   `SyncManager::on_block`, is logged, and sync continues. Worse for the
   interval case, `last_flush` is set *before* the commit, so a failed
   timed flush resets the timer and the next commit returns `Ok` without
   touching the engine.

   The fix is a fail-closed latch in `dcroxide-database`: a `fatal` flag
   set by every path that hands a durable commit to the engine, checked
   before any write. Once a durable write fails, no later write on that
   store can report success — which is the property the bug needs and now
   cannot have, whatever engine is underneath. Reads stay available
   deliberately: data that reached disk is still valid, and refusing it
   would turn a write fault into a total outage for no integrity gain.

   The regression test pins the consequence on every platform, and a
   second test — added 2026-08-13 — now proves the cause. It mounts a
   2 MiB `tmpfs` inside a user namespace (no root needed), fills it under
   a live database, and checks what comes back: a real `ENOSPC` arrives as
   an error rather than a panic, latches the store, and leaves reads
   working. Linux-only, since it needs unprivileged `CLONE_NEWUSER`; CI
   sets `DCROXIDE_REQUIRE_FAULT_INJECTION=1` so it fails rather than skips
   there, and it asserts the child process actually ran its assertions
   because a mistyped test filter would otherwise exit 0 having checked
   nothing.

   That test measured something worth recording: with the latch removed,
   the write after the failure still fails — with redb's own message,
   "Previous I/O error occurred. Please close and re-open the database".
   **redb poisons itself; fjall's `write_batch` path does not.** That
   asymmetry is the argument for the latch living in dcroxide rather than
   being left to the engine: on redb it is belt and braces, on fjall it is
   the only thing between a failed write and a commit that reports
   success.

   Two defects were found in passing and are **not** fixed here, because
   they are node policy rather than storage. **Both were fixed 2026-08-13
   in `51f3891`, after this was written:**
   - A storage failure is indistinguishable from a consensus rejection.
     It surfaces as a non-rule `ProcessBlockFailure`, gets logged, and sync
     continues, so a transient disk error makes a valid block look invalid
     and blames the peer. With the latch this becomes loud and permanent
     rather than silent, which is better but still wrong.
     **Fixed:** `Database::is_fatal` is public and threaded
     into `combine_process_block_result` (`sync.rs:166-168`), so a latched
     store reports a disk fault instead of a rule error attributed to the
     peer. Two tests pin both directions: a real rule violation stays the
     peer's, a storage failure does not become one.
   - `dcroxide.rs` logs a failed shutdown flush and exits `SUCCESS`, in the
     one place whose own comment says that failure wedges the node on next
     start.
     **Fixed:** `dcroxide.rs:1063` returns `ExitCode::FAILURE` there.

   What was deliberately not done: a fatal storage error still does not
   shut the node down. The store latches and the manager logs "Failed to
   process block" rather than blaming the peer, but the process keeps
   running, so a supervisor has the exit code and that line to key on and
   nothing else.
2. ~~Durability enforced at the wrapper boundary.~~ **Done, 2026-08-13.**
   Every write transaction in `dcroxide-database` now goes through one
   helper that sets `Durability::Immediate` explicitly, and a policy test
   scans the crate's own source and fails if any other call site opens a
   write transaction, or if the helper's level is weakened.

   redb already defaults to `Immediate`, so this changes no behaviour
   today — which is the reason to do it now rather than later. The property
   currently holds by luck, and fjall defaults the other way:
   `Database::batch()` hands back `PersistMode::Buffer`, whose `commit()`
   returns `Ok` having called no fsync. A port relying on an inherited
   default would have gone silently non-durable on the day it switched, in
   a commit that looked like a dependency bump. The seam now exists and is
   enforced, so that day is a compile-and-test problem rather than a silent
   one.

   Both assertions were checked by mutation: routing one call site around
   the helper fails the first test with the file and line, and weakening
   the level to `Durability::None` fails the second.
3. ~~`crash.rs` rebuilt into an actual gate first.~~ **Done, 2026-08-13.**
   The suite went from four tests that never wrote metadata to nine that
   reproduce `Chain::flush`'s pairing — block index rows, UTXO entries and
   both state markers in one transaction — and tear it: a torn commit
   spanning buckets, repeated tears at varying commit sizes, block data and
   metadata rolling back together across the two durability domains, durable
   metadata surviving the block-file rollback, and deletes being atomic with
   the puts beside them (the disconnect shape, which is how the spend
   journal shrinks). Desync is checked in **both** directions: a marker
   claiming more rows than survive is lost data, one claiming fewer is
   uncommitted data that leaked, and a suite checking only the first passes
   on an engine that keeps writes it never committed.

   Verified by breaking the store on purpose. Deleting the state-marker
   write from `DbCache::flush` fails four of the new tests and **passes all
   five of the old ones**, which is the concrete form of the complaint this
   item recorded.

**Take redb 4.1.0 now, independently.** Measured on the same journal, it
holds the identical content in 14.50 GiB against 2.6.3's 16.00 — 9.4%
smaller — and loads 21% faster. It does not touch the 1.738x structural
figure (its leaf layout is unchanged), so it is not an answer to the space
problem; it is a dependency bump that gives back 1.5 GiB and forecloses
nothing. Note it carries its own open issues (#1331, #1332, #1333: process
aborts and unopenable files on malformed input, with read-path checksum
verification only on master), which argue for the upgrade being routine
maintenance rather than a security improvement.

Everything below this line predates the 2026-08-13 measurement and is kept
because the reasoning is checkable.

**Do not start a rework yet. Run four measurements that the gate requires and
that would change the design, then decide.** Three are now done. The first
two narrowed the case — lever (d) is one bucket's row encoding, and the only
tuning gain measured anywhere is 11% — and the third widens it: with payload
identity established, no part of the storage gap has a domain-level
explanation left. The same 5.65 GiB occupies 6.10 GiB under goleveldb and
9.82 GiB in redb's live tree.

That is a real change of direction on the *size* question and no change at
all on the *speed* one, and the two must not be run together. A rework
justified on size would still be judged by this ADR's stop rule, which is
stated in IBD terms — and the ledger bounds what storage can buy there:
the matched `--addrindex` replay spent 863 s of 4,767 in flushes, so
eliminating the storage cost *entirely* moves 230.8 to 281.9 blk/s, 1.22x,
against a 1.5x stop rule. Whatever else is true, an engine swap cannot be
sold on IBD.

> **Caveat, 2026-08-14: that bound may not transfer to the daemon.** The 18%
> comes from a *replay*, which validates every block. The daemon syncs
> headers first, finds mainnet's assume-valid anchor, and skips connect
> validation for roughly 93% of the chain — so the same storage work is a
> share of a much smaller total, and storage is plausibly a *larger* fraction
> of daemon IBD than 18%, not a smaller one. That would cut against the
> conclusion this paragraph draws. It is a caveat and not a correction: the
> 2026-08-14 profiling attempt that raised it could not measure the daemon's
> composition reliably, and its own figure is withdrawn. What is established
> is that a replay is not a proxy for daemon IBD and that this bound was
> derived from one. See [bench-ledger.md](../bench-ledger.md).

1. **Lever (d) on `spendjournalv3`.** ~~Prerequisite~~ **Measured**, by
   `redbstat --buckets`: the bucket holds a 2402-byte mean row against a
   4096-byte page, takes one row per page, and accounts for 1.74 GiB of the
   2.33 GiB predicted slack — 75%, concentrated in one bucket, with every
   other bucket packing at 10 rows per page or better. The page-size remedy
   is unreachable, since redb gates `set_page_size` behind
   `cfg(any(fuzzing, test))`. What remains reachable is a denser row: under
   about 2040 bytes two would share a page. That is a change to what this
   port stores rather than how redb stores it, and it competes with the
   rework rather than being subsumed by it — a re-encoded spend journal is a
   far smaller change than a new storage engine for most of the same GiB.
   **Amended 2026-08-11:** that remedy no longer has dcrd behind it. dcrd
   stores the same bucket at the same 2,643,223,854 B over the same
   1,100,392 rows, so dcroxide is already using dcrd's encoding and a denser
   row means inventing one dcrd does not have — a deliberate divergence,
   which raises the parity cost without changing the 1.74 GiB arithmetic.
   dcrd needs none of it because goleveldb has no page round-up at all, so
   "no dcrd headroom" is the expected result and says nothing about what is
   recoverable here. The untested third option is a re-*keying* that splits
   the row across two entries while storing dcrd's exact bytes.
   **Measured 2026-08-12, and refuted.** Six layouts were built at the
   bucket's real dimensions: today's is the smallest, and every split costs
   0.18–0.38 GiB, raising slack as well as payload. Splitting only the 16.7%
   of rows that provably cannot share a leaf loses too. The slack is real —
   1.536 GiB measured, against the 1.74 GiB the model predicted — but ~86% of
   it is ordinary B-tree leaf under-fill and ~14% the allocator's
   power-of-two rounding, neither of which a key layout reaches. **Lever (d)
   is closed at this layer**, leaving only an encoding denser than dcrd's or
   a different engine.
2. **dcrd's payload, measured.** ~~Prerequisite~~ **Done, 2026-08-11**, and
   it reverses this ADR's withdrawal. Rather than a network sync, dcrd was
   fed the identical bytes: dcroxide exported `mainnet-full.corpus` in
   dcrd's `addblock` bootstrap format from its own datadir and dcrd imported
   that exact file, so the block data is the same on both sides by
   construction. Index composition was recorded — exists-address index on,
   transaction index off — and the datadir preserved. (`addblock` *enables*
   the index without *building* it; the daemon has to run once for catch-up,
   and a comparison taken before that step would have repeated the 2026-07
   error.) Result: the two store the same payload, fifteen buckets equal to
   the byte, 54 bytes of residual on 6.06 GB. So the encoding explanation is
   dead and the gap is the storage layer — 1.081x against 1.738x over each
   store's own payload. Full numbers in
   [ADR-0004's 2026-08-11 addendum](0004-storage-backend.md) and
   [bench-ledger.md](../bench-ledger.md).
3. **A repeatable throughput rig.** ~~Prerequisite~~ **Built**, as
   `dcroxide-bench sweep`: arms interleaved rather than blocked, the order
   rotated each repetition so no arm holds a fixed position, a fresh process
   and workdir per run, machine state captured per run, and a summary that
   reports **drift first** — the median of the sweep's first half against its
   second — before any arm comparison, with a warning when drift exceeds 10%.
   A validation run measured 0.93x drift and separated a 1.28x arm effect
   from it, which the previous rig could not have done. What remains is to
   re-run levers (b) and (c) through it at full scale.
4. **Candidate engine benchmark.** ~~Prerequisite~~ **Done, 2026-08-13.**
   Rather than loading `mainnet-full.corpus`, every arm was handed the
   *engine-level journal* — what dcroxide's storage engine was actually
   given, batch for batch, 102,686,859 records in 130 batches, captured by
   `replay --writelog`. Loading the sorted corpus instead would have decided
   the benchmark by itself: a sorted bulk load is an LSM's best case and a
   copy-on-write B-tree's worst.

   | engine | settled | over payload | reads (200k point) | full scan |
   |---|---:|---:|---:|---:|
   | **fjall 3.1.8** | 6,227,582,792 | **1.026x** | 29.80 µs | 11.2 s |
   | goleveldb, *oracle* | 6,421,155,136 | 1.058x | — | — |
   | redb 4.1.0 | 15,568,752,640 | 2.565x | — | — |
   | redb 2.6.3, incumbent | 17,182,003,200 | 2.831x | 104.26 µs | 93.4 s |

   Two controls make the numbers quotable. The **redb 2.6.3 arm reproduced
   the measured baseline** — live tree within 0.008%, fill within 0.0001 —
   which was the pre-registered abort condition on the rig. And the
   **goleveldb oracle landed at 1.058x, inside its pre-registered 1.05–1.12x
   band**, which establishes that dcrd's 1.081x is a property of the engine
   class rather than of dcrd's write schedule. That was the sleeper
   condition: had it failed, the answer was "stay on redb" regardless of
   what any candidate measured.

   Full detail, including the excluded candidates and a voided first
   goleveldb run, is in [bench-ledger.md](../bench-ledger.md).

**If those land in favour of a change, the shape to propose is a single
LSM metadata store, not a split.** dcrd achieves 6.10 GiB with *one*
general-purpose store holding block index, spend journal and hash-keyed
indexes together — over 6,061,905,929 B of payload measured to be the same
payload dcroxide holds, so the argument no longer rests on any assumption
about what the two store. The earlier draft's claim that a split "converges
with dcrd" was backwards. On ADR-0004's own bucket figures the append-only
half is worth roughly 0.26 GiB beyond what an LSM swap already gives — and
it costs the atomicity below.

## Why the earlier split design was withdrawn

Recorded because the errors are checkable and someone will propose it again.

- **The append-shaped classification was factually wrong.**
  `spendjournalv3` — 84% of the payload that half would hold — is keyed by
  block *hash* (`chaindb.rs:266`) and is *deleted* on disconnect
  (`db_remove_spend_journal_entry`). `ffldb-blockidx` is likewise keyed by
  hash. "Written once, in order, read by a monotone key" is false for the
  data it named.
- **It broke atomicity the chain depends on.** `process.rs:908-916` writes
  block index rows, UTXO entries and both state markers in one
  transaction, with a comment that a crash must never leave the flushed set
  ahead of or behind its recorded state. The split crossed exactly that
  boundary while claiming "consensus behaviour is untouched, since none of
  this crosses the `database/v3` contract" — atomicity *is* that contract.
- **The rebuild story was impossible.** "Rebuild the LSM side from the
  append-only side" cannot work: `existsaddridx` needs every output script
  and the transaction index needs every txid, both of which live only in the
  block bodies, and the spend journal stores *spent* outputs for rewind.
- **The acceptance criterion was satisfiable by moving bytes.** It measured
  `metadata.redb`, and the design moved `spendjournalv3` and the block index
  out of that file — passing with zero improvement in total density.

## Guardrails, when a rework does start

Each from a cost someone else already paid, and each survives the redesign.

- **No multi-backend trait layer.** Cuprate spent three years on
  `Env`/`Tx`/`Database` traits over heed and redb, documented the costs —
  leaked error types, unusable backend features, forced read copies — and
  deleted the layer in PR #587 when it blocked the optimization that
  eventually won. `database/v3` semantics are already the boundary.
- **Durable defaults.** Cuprate's Gen-1 `SyncMode::Fast` default corrupted a
  database on a crash (issue #412), after which the node silently restarted
  from height 0. Any deferred-sync mode ships opt-in with the risk
  documented.
- **`crash.rs` is a gate that must first be made adequate.** Its four tests
  exercise only `store_block`/`fetch_block`/`has_block`; none writes
  metadata. Before it can gate a storage change it needs tests that fail the
  new design when it is wrong: a kill between each durability domain's
  commit, a commit spanning the buckets `process.rs` pairs, and detection of
  each desync direction.
- **Big-endian range keys.** Cuprate's issues #179 and #348 broke LMDB range
  queries with native-endian keys; ffldb's layout is already correct.

## Consequences

- Deciding now is deferred by the cost of the four measurements — days, not
  months, and three of them are useful regardless of the outcome. Three are
  now done; the deferral cost is one measurement, the candidate engine
  benchmark.
- The throughput rig is the long pole and the one with value beyond this
  decision: without it, no storage change can be judged on the metric that
  motivates it.
- If the measurements do not support a rework, the honest outcome is that
  dcroxide carries a larger metadata store than dcrd and a slower IBD, both
  documented, on a node that is pre-alpha and not yet safe to operate. That
  is a defensible state to be in while ecosystem acceptance and the security
  gaps in SECURITY.md are unaddressed. **As of 2026-08-11 the size half is
  no longer a matter of differing designs**: it is the same payload costing
  1.081x under one engine and 1.738x under another, with nothing above the
  engine left to explain it. The speed half is unchanged and still
  unattributed.
- **Stop rule for the rework itself, if it starts:** if IBD does not improve
  by at least 1.5x on the repaired rig at the first milestone, abandon it and
  record why. A rewrite of `dcroxide-database`'s internals with no stop rule
  is how a project spends a year on a thing it cannot later justify.

## Alternatives

- **Start the rework now.** Rejected: the gate is unmet, the motivating
  comparison is withdrawn, no engine is benchmarked, and there is no rig to
  judge the result. **Three of those four grounds are now gone** — the
  comparison is reinstated and measured on both sides (2026-08-11), the rig
  exists (prerequisite 3), and lever (d) is closed by measurement
  (2026-08-12), which satisfies ADR-0004's gate. **Only one ground remains:
  no candidate engine has been benchmarked.** Prerequisite 4 now decides this
  ADR on its own, and it is the last thing standing between "rejected" and a
  real decision. Note what closing lever (d) did and did not establish: it
  showed the slack is not reachable from above the engine, which is a reason
  to look *at* the engine — not evidence that a different one would do
  better, which remains unmeasured.
- **More tuning.** Partly rejected — (a), (b), (c) are measured and do not
  move fill — but lever (d) on `spendjournalv3` is exactly the tuning that
  has *not* been tried, and it is prerequisite 1. Now measured: one bucket,
  1.74 GiB, page-size remedy unreachable, row-encoding remedy stripped of
  its dcrd precedent. A row re-keying remains untried. Add one more untried
  item found while measuring: `redb::Database::compact` is never called in
  production here, but its yield varies 20x between two stores of the same
  chain (0.12 GiB against 2.45 GiB consumed), it never repacks, and it is
  not an operator knob on that evidence.
- **Value compression.** Still rejected on ADR-0004's grounds for codec
  compression. The note that used to stand here — that dcrd's domain-level
  encodings look denser — is deleted: measured, they are not. What dcrd does
  have is *structural*, not domain: goleveldb elides shared key prefixes
  between adjacent sstable entries, which is why its `utxodb` file is 0.935x
  its own payload. That belongs with the engine question, not this one.
- **Do nothing, indefinitely.** Defensible. The chain grows a few percent a
  year and the rework's difficulty does not track chain size, so deferral is
  cheap. What it displaces matters more: the per-block state comparator, the
  ecosystem-acceptance milestones, and SECURITY.md's standing gaps are all
  unaddressed, and each is closer to making the node usable than a faster
  store is.
