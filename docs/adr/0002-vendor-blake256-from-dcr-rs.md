# ADR-0002 — Vendor BLAKE-256 from dcr-rs

- **Status:** Accepted
- **Date:** 2026-07-03

## Context

BLAKE-256 (14-round SHA-3-finalist BLAKE, not BLAKE2/BLAKE3) hashes nearly
everything in Decred: txids, pre-DCP0011 block hashes, sighashes, address
hashes, base58check checksums, merkle trees. No maintained Rust crate exists.
[dcr-rs](https://github.com/jzbz/dcr-rs) (ISC) carries a clean `no_std`
implementation pinned by known-answer vectors generated from dcrd's
`crypto/blake256`.

## Decision

Vendor `blake256.rs` from dcr-rs at commit `fd32c1a` into `dcroxide-crypto`,
with SPDX/attribution header and the dcr-rs copyright line added to the
repository `LICENSE`. Keep the KAT suite, and re-verify the vectors against
dcrd continuously via the `tools/oracle` differential test rather than
trusting the inherited fixtures (brief §6 Phase 1).

The broader D6 question (upstreaming to dcr-rs vs. hard fork of the whole
crate) stays open; this ADR covers only BLAKE-256, which we own from here on
(dcroxide is its natural long-term home — it is on the txid/merkle hot path
and will eventually want SIMD work that is out of scope for a signing-firmware
crate).

## Consequences

- We maintain the implementation ourselves: KAT + differential + fuzz
  coverage from day one, later optimization freedom.
- Divergence from dcr-rs upstream is possible; the vendored header records
  the source commit so diffs stay tractable.
- Remaining dcr-rs candidates (tx serialization, sighash, addresses, base58)
  get their own decision when their phase starts.
