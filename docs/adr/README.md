# Architecture decision records

One file per decision, numbered. A decision is immutable once accepted:
correct a fact or append a dated addendum, but supersede with a new ADR rather
than rewriting what was decided. Use [template.md](template.md).

## Index

- [ADR-0001](0001-oracle-driven-differential-testing.md) — Oracle rig: Go shim over line-JSON, pinned to dcrd `release-v2.1.5` *(Accepted; addendum 2026-07-26 — re-pinned to master `452c1a6c`)*
- [ADR-0002](0002-vendor-blake256-from-dcr-rs.md) — Vendor BLAKE-256 from dcr-rs *(Accepted)*
- [ADR-0003](0003-slice-based-wire-decoding.md) — Slice-based wire decoding with consumed-length semantics *(Accepted; addendum 2026-07-26 — framing bounds per message type)*
- [ADR-0004](0004-storage-backend.md) — D1: dcrd's database semantics over `redb`, flat block files, fresh-sync C6 stance *(Accepted; amended 2026-07-26)*
- [ADR-0005](0005-concurrency-model.md) — D2: tokio for I/O, runtime-free consensus, validation pool *(Proposed; tokio not adopted — see the 2026-07-26 addendum)*
- [ADR-0006](0006-secp256k1-backend.md) — D3: libsecp bindings for ECDSA, `k256` for Schnorr-DCRv0 *(Proposed; addendum 2026-07-26 — the split held)*
- [ADR-0007](0007-json-emission-strategy.md) — D4: controlled serde emission + Go-float formatter + golden captures *(Proposed; serde not used — see the 2026-07-26 addendum)*

## Pending decisions (from the project brief, §9)

- **D1** — accepted as ADR-0004; the write-load gate it named is resolved
- **D2–D4** — still Proposed as ADR-0005…0007. Each names the prototype that
  gates final ratification, and each now carries a dated addendum recording
  what shipped: D2 and D4 diverged from their drafts, D3 did not. Ratifying
  them, or superseding them, is the project owner's call.
- **D5** — Upstream tracking cadence. The port has followed dcrd master twice
  (`release-v2.1.5` → `452c1a6c` → `29f17894`, version 2.2.0-pre); the
  standing cadence is still undecided
- **D6** — dcr-rs relationship (upstream vs. fork) — partially covered by ADR-0002
- **D7** — MSRV, platform tiers, release signing/reproducibility (MSRV
  currently 1.94 via workspace `rust-version`; formal ADR pending)
