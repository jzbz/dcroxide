# Architecture decision records

One file per decision, numbered. A decision is immutable once accepted:
correct a fact or append a dated addendum, but supersede with a new ADR rather
than rewriting what was decided. Use [template.md](template.md).

## Index

- [ADR-0001](0001-oracle-driven-differential-testing.md) — Oracle rig: Go shim over line-JSON, pinned to dcrd `release-v2.1.5` *(Accepted; addendum 2026-07-26 — re-pinned to master `452c1a6c`)*
- [ADR-0002](0002-vendor-blake256-from-dcr-rs.md) — Vendor BLAKE-256 from dcr-rs *(Accepted)*
- [ADR-0003](0003-slice-based-wire-decoding.md) — Slice-based wire decoding with consumed-length semantics *(Accepted; addendum 2026-07-26 — framing bounds per message type)*
- [ADR-0004](0004-storage-backend.md) — D1: dcrd's database semantics over `redb`, flat block files, fresh-sync C6 stance *(Accepted; amended 2026-07-26, - [ADR-0004](0004-storage-backend.md) — D1: dcrd's database semantics over `redb`, flat block files, fresh-sync C6 stance *(Accepted; amended 2026-07-26, then dated addenda through 2026-08-15 including one retraction and several corrections — the status block and the "Findings as of" section at the top carry the current state. Its revisit gate was **satisfied and closed 2026-08-17: the engine stays redb**. Now on redb 4.1.0, which changed the on-disk format.)* Now on redb 4.1.0, which changed the on-disk format.)*
- [ADR-0005](0005-concurrency-model.md) — D2: tokio for I/O, runtime-free consensus, validation pool *(Accepted; ratified 2026-08-07 as shipped — threads, not tokio; see the addenda)*
- [ADR-0006](0006-secp256k1-backend.md) — D3: libsecp bindings for ECDSA, `k256` for Schnorr-DCRv0 *(Proposed; addendum 2026-07-26 — the split held)*
- [ADR-0007](0007-json-emission-strategy.md) — D4: controlled serde emission + Go-float formatter + golden captures *(Proposed; serde not used — see the 2026-07-26 addendum)*
- [ADR-0008](0008-clippy-lint-policy.md) — Curated lint set: `iter_over_hash_type`/`allow_attributes`/`unreachable_pub` adopted, cast lints refused or deferred, with the measured fallout *(Accepted)*
- [ADR-0009](0009-storage-shape.md) — Storage rework: what the evidence supports, and the four measurements the ADR-0004 gate needed - [ADR-0009](0009-storage-shape.md) — Storage rework: what the evidence supports, and the four measurements the ADR-0004 gate needed *(**Closed 2026-08-17 — the engine stays redb**, decided by the project owner: the candidate won on size and on write shape and lost on crash safety, fjall #311 reproducing as a silently discarded set of acknowledged commits whose reopen still succeeds. All four ADR-0004 levers were measured as of 2026-08-13. An earlier split-by-access-shape draft was withdrawn under review, and a later partial withdrawal was itself corrected; both are recorded in it.)* An earlier split-by-access-shape draft was withdrawn under review, and a later partial withdrawal was itself corrected; both are recorded in it.)*

## Pending decisions (from the project brief, §9)

- **D1** — accepted as ADR-0004; the write-load gate it named is resolved,
  and as of 2026-08-13 so is the *revisit* gate: all four storage levers are
  measured and none is sufficient. - **D1** — accepted as ADR-0004; the write-load gate it named is resolved,
  and as of 2026-08-13 so is the *revisit* gate: all four storage levers are
  measured and none is sufficient. The follow-on question ADR-0009 carried —
  whether to change engine at all — was decided on 2026-08-17: the engine
  stays redb, the candidate having lost on crash safety.
- **D2** — accepted: ADR-0005 was ratified 2026-08-07 as shipped (threads
  over channels, not tokio); its final addendum records the evidence
- **D3–D4** — still Proposed as ADR-0006/0007. Each names the prototype that
  gates final ratification, and each carries a dated addendum recording what
  shipped: D4 diverged from its draft, D3 did not. Ratifying them, or
  superseding them, is the project owner's call.
- **D5** — Upstream tracking cadence. The port has followed dcrd master twice
  (`release-v2.1.5` → `452c1a6c` → `29f17894`, version 2.2.0-pre); the
  standing cadence is still undecided. The mechanical half is no longer
  manual: `tools/pinbump` resolves an upstream delta to the crates that
  port it through PARITY.md's table, so a bump starts from a review list.
  What remains undecided is how often to look, not how to look.
- **D6** — dcr-rs relationship (upstream vs. fork) — partially covered by ADR-0002
- **D7** — MSRV, platform tiers, release signing/reproducibility (MSRV
  currently 1.94 via workspace `rust-version`; formal ADR pending).  The
  ADR is a hard gate before any binary is published, and it must decide
  the pre-1.0 stale-binary question explicitly — a Cuprate-style expiry
  or a recorded refusal.  The threat model is Decred's, not Monero's: a
  consensus-divergent node cannot sustain a competing chain without
  ticket votes, so a stale pre-release self-isolates rather than
  splitting the network, and the concentrated harm is to its own
  operator — a voting wallet or VSP behind a wedged node bleeds missed
  votes.  The pinned 1.97.1 toolchain and `codegen-units = 1` already
  make reproducible-artifact verification attainable as a release gate.
