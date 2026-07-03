# ADR-0003 — Slice-based wire decoding with consumed-length semantics

- **Status:** Accepted
- **Date:** 2026-07-03

## Context

dcrd decodes wire data from Go `io.Reader`s. A Rust port must pick an I/O
model before the first codec lands. P2P messages are length-prefixed by the
message framing, and stored blocks/transactions are length-known, so decoding
never actually requires pull-based streaming.

## Decision

`dcroxide-wire` decodes from byte slices via a `Cursor` (position-tracking
view). `from_bytes` constructors return `(value, consumed)`; like dcrd's
`Deserialize`/`FromBytes`, trailing bytes are not an error — framing is the
caller's job. Both `io.EOF` and `io.ErrUnexpectedEOF` collapse into a single
`WireError::UnexpectedEof` (dcrd distinguishes them internally but the
distinction is not part of any compatibility surface; revisit if peer-facing
error handling proves otherwise).

Error variants map 1:1 to the dcrd `wire.ErrorCode` kinds reachable from each
codec; message *text* parity is not chased unless it leaks into observable
behavior (tracked in `PARITY.md`).

Two invariants follow from dcrd's canonical-varint enforcement and are locked
in by fuzz targets and property tests for every codec:
`encode(decode(bytes)) == bytes[..consumed]`, and decode never panics.

The crates stay `no_std` + `alloc` so primitives remain usable by embedded
consumers; encoding appends to `Vec<u8>` and is infallible.

## Consequences

- Message framing (Phase 2 proper) will read whole payloads (bounded by
  `MaxMessagePayload`, 32 MiB) before decoding — same memory profile as
  dcrd, which also buffers full payloads.
- dcrd's in-memory-only quirks (e.g. `BlockHeader.Timestamp` being a
  `time.Time` that truncates to u32 on write) are represented by the wire
  domain instead (`timestamp: u32`); nothing representable diverges on the
  wire.
- Differential tests compare decoded/re-encoded bytes and hashes rather than
  in-memory structure, so this model difference is continuously verified as
  behavior-neutral.
