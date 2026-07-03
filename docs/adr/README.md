# Architecture decision records

One file per decision, numbered, immutable once accepted (supersede with a new
ADR instead of editing). Use [template.md](template.md).

## Index

- [ADR-0001](0001-oracle-driven-differential-testing.md) — Oracle rig: Go shim over line-JSON, pinned to dcrd release-v2.1.5 module versions *(Accepted)*
- [ADR-0002](0002-vendor-blake256-from-dcr-rs.md) — Vendor BLAKE-256 from dcr-rs *(Accepted)*
- [ADR-0003](0003-slice-based-wire-decoding.md) — Slice-based wire decoding with consumed-length semantics *(Accepted)*
- [ADR-0004](0004-storage-backend.md) — D1: storage backend (`redb` proposed) & C6 stance *(Proposed)*
- [ADR-0005](0005-concurrency-model.md) — D2: tokio for I/O, runtime-free consensus, validation pool *(Proposed)*
- [ADR-0006](0006-secp256k1-backend.md) — D3: libsecp bindings for ECDSA, `k256` for Schnorr-DCRv0 *(Proposed)*
- [ADR-0007](0007-json-emission-strategy.md) — D4: controlled serde emission + Go-float formatter + golden captures *(Proposed)*

## Pending decisions (from the project brief, §9)

- **D1–D4** — drafted as ADR-0004…0007 (Proposed); each names the prototype
  that gates final ratification
- **D5** — Upstream tracking cadence once dcrd 2.2 lands
- **D6** — dcr-rs relationship (upstream vs. fork) — partially covered by ADR-0002
- **D7** — MSRV, platform tiers, release signing/reproducibility (MSRV
  currently 1.85 via workspace `rust-version`; formal ADR pending)
