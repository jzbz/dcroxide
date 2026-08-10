# ADR-0009 — Storage rework: what the evidence supports, and what must be measured first

- **Status:** Proposed
- **Date:** 2026-08-10

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

### What is not measured, and blocks the gate

- **Lever (d) is untested where it matters.** `existsaddridx` is capped near
  0.75 GiB *by arithmetic* and declined on the cost of the contiguous
  keyspace — not found ineffective. `spendjournalv3`'s page-size hypothesis
  has never been run, and it is the largest bucket (4.1 GiB of tree
  footprint, 2402 B mean row), which makes it the most plausible single
  source of the 3.44 GiB of slack this ADR would target. **ADR-0004's gate is
  therefore not satisfied.**
- **dcrd's payload is unknown.** Only its file sizes were measured. Deriving
  its overhead ratio from *dcroxide's* payload assumes both stores hold
  identical bytes, and one cross-check falsifies that: dcrd's entire
  `utxodb` is 0.108 GiB while dcroxide's `utxosetv3` payload alone is
  0.13 GiB. Negative overhead is impossible over identical bytes, so dcrd's
  domain-level compressed amount and script encodings are smaller *payload*,
  not smaller overhead. The "9% versus 156%" framing is withdrawn.
- **The dcrd baseline's index configuration was never recorded** and its
  datadir is gone. This project has already retracted one conclusion for
  exactly this failure mode.
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

So redb's *structural* overhead is about 73%, not 156%. The attributable
part is 0.69 GiB of engine overhead plus 3.44 GiB of slack.

## Decision (proposed)

**Do not start a rework yet. Run four measurements that the gate requires and
that would change the design, then decide.** Two are now done, and both
narrowed the case for a rework rather than strengthening it: lever (d) is one
bucket's row encoding, and the only tuning gain measured anywhere is 11%.

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
2. **dcrd's payload, measured.** Iterate its ffldb metadata and `utxodb`,
   sum key and value bytes per bucket, and record the run's index flags.
   Without this there is no legitimate density comparison, only file sizes.
3. **A repeatable throughput rig.** ~~Prerequisite~~ **Built**, as
   `dcroxide-bench sweep`: arms interleaved rather than blocked, the order
   rotated each repetition so no arm holds a fixed position, a fresh process
   and workdir per run, machine state captured per run, and a summary that
   reports **drift first** — the median of the sweep's first half against its
   second — before any arm comparison, with a warning when drift exceeds 10%.
   A validation run measured 0.93x drift and separated a 1.28x arm effect
   from it, which the previous rig could not have done. What remains is to
   re-run levers (b) and (c) through it at full scale.
4. **Candidate engine benchmark.** Load the exported `mainnet-full.corpus`
   into each candidate LSM with compression off; record on-disk bytes, wall
   time, and behaviour under `kill -9`. No engine is named in this ADR
   because none has been measured, and ADR-0004 chose redb partly for
   crash-safety — a pure-Rust LSM's record there is shorter than
   goleveldb's, and rocksdb reintroduces the C toolchain that ADR-0004's
   Consequences weighed and declined.

**If those land in favour of a change, the shape to propose is a single
LSM metadata store, not a split.** dcrd achieves 6.15 GiB with *one*
general-purpose store holding block index, spend journal and hash-keyed
indexes together. The earlier draft's claim that a split "converges with
dcrd" was backwards. On ADR-0004's own bucket figures the append-only half is
worth roughly 0.26 GiB beyond what an LSM swap already gives — and it costs
the atomicity below.

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
  months, and three of them are useful regardless of the outcome.
- The throughput rig is the long pole and the one with value beyond this
  decision: without it, no storage change can be judged on the metric that
  motivates it.
- If the measurements do not support a rework, the honest outcome is that
  dcroxide carries a larger metadata store than dcrd and a slower IBD, both
  documented, on a node that is pre-alpha and not yet safe to operate. That
  is a defensible state to be in while ecosystem acceptance and the security
  gaps in SECURITY.md are unaddressed.
- **Stop rule for the rework itself, if it starts:** if IBD does not improve
  by at least 1.5x on the repaired rig at the first milestone, abandon it and
  record why. A rewrite of `dcroxide-database`'s internals with no stop rule
  is how a project spends a year on a thing it cannot later justify.

## Alternatives

- **Start the rework now.** Rejected: the gate is unmet, the motivating
  comparison is withdrawn, no engine is benchmarked, and there is no rig to
  judge the result.
- **More tuning.** Partly rejected — (a), (b), (c) are measured and do not
  move fill — but lever (d) on `spendjournalv3` is exactly the tuning that
  has *not* been tried, and it is prerequisite 1.
- **Value compression.** Still rejected on ADR-0004's grounds for codec
  compression. Note the dcrd comparison above suggests dcrd's *domain-level*
  encodings are denser, which is a different question and belongs with
  prerequisite 2.
- **Do nothing, indefinitely.** Defensible. The chain grows a few percent a
  year and the rework's difficulty does not track chain size, so deferral is
  cheap. What it displaces matters more: the per-block state comparator, the
  ecosystem-acceptance milestones, and SECURITY.md's standing gaps are all
  unaddressed, and each is closer to making the node usable than a faster
  store is.
