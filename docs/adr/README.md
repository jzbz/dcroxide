# Architecture decision records

One file per decision, numbered, immutable once accepted (supersede with a new
ADR instead of editing). Use [template.md](template.md).

## Index

- [ADR-0001](0001-oracle-driven-differential-testing.md) — Oracle rig: Go shim over line-JSON, pinned to dcrd release-v2.1.5 module versions
- [ADR-0002](0002-vendor-blake256-from-dcr-rs.md) — Vendor BLAKE-256 from dcr-rs

## Pending decisions (from the project brief, §9)

- **D1** — Storage backend & C6 (datadir compatibility) stance
- **D2** — Concurrency model (tokio vs. thread-per-peer; validation pool)
- **D3** — secp256k1 backend split (bindings vs. `k256` vs. hybrid)
- **D4** — JSON emission strategy for RPC byte-parity
- **D5** — Upstream tracking cadence once dcrd 2.2 lands
- **D6** — dcr-rs relationship (upstream vs. fork) — partially covered by ADR-0002
- **D7** — MSRV, platform tiers, release signing/reproducibility
