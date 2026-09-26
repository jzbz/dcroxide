# ADR-0003 — Slice-based wire decoding with consumed-length semantics

- **Status:** Accepted
- **Date:** 2026-07-03 (accepted), 2026-07-26 (addendum: the framing bound
  came out tighter than predicted)

## Context

dcrd decodes wire data from Go `io.Reader`s. A Rust port must pick an I/O
model before the first codec lands. P2P messages are length-prefixed by the
message framing, and stored blocks/transactions are length-known, so decoding
never actually requires pull-based streaming.

## Decision

`dcroxide-wire` decodes from byte slices via a `Cursor` (position-tracking
view). `from_bytes` constructors return `(value, consumed)`; like dcrd's
`Deserialize`/`FromBytes`, trailing bytes are not an error — framing is the
caller's job. `Cursor::take` distinguishes Go's two short-read errors the way
dcrd's readers over a byte reader do: `WireError::Eof` when a read finds no
bytes left (`io.EOF`, `shortRead`'s `n == 0` case) and
`WireError::UnexpectedEof` when it finds only part (`io.ErrUnexpectedEOF`).
Both have an empty kind name, so P2P ban decisions treat them alike.

Error variants map 1:1 to the dcrd `wire.ErrorCode` kinds reachable from each
codec. Their text is observable through `decoderawtransaction`,
`sendrawtransaction`, `getrawtransaction`, `submitblock` and
`sendrawmixmessage`, so every error the transaction, block header, block and
mixing message decoders return renders dcrd's text exactly. That covers the
io errors, and dcrd's `MessageError` `Func: Description` for coded errors
(`wire/error.go:266-270`), including the shared `ReadVarInt`,
`ReadVarBytes`, `readScript`, `ReadVarString` and `ReadAsciiVarString`
readers. Kinds whose description varies by check carry a `MessageText`
holding dcrd's `op` and format string verbatim. Kinds only the other P2P
codecs raise, the `ErrMsgInvalidForPVer` gate and `ReadMessage`'s framing
errors reach only logs, and print their kind name (`ErrWrongNetwork` aside,
which renders dcrd's `ReadMessage: message from other network [%v]`, the
magic printed by `CurrencyNet.String`, pinned against the oracle by
`crates/dcroxide-wire/tests/review_wrong_network_text.rs`).

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

## Addendum, 2026-07-26 — framing bounds by message type, not by the global cap

The first consequence above predicted framing bounded by `MaxMessagePayload`
(32 MiB). The shipped reader is tighter. `wire::read_message_header`
(`crates/dcroxide-wire/src/message.rs` 394) applies dcrd's checks in dcrd's
order — global cap, network magic, command form, known command, per-type
payload maximum — and `read_message` allocates the payload only after all of
them pass, so a peer cannot name 32 MiB in a 24-byte header for a message
type whose own maximum is smaller.

That order is not cosmetic: the port did bound the allocation by the global
cap alone for a while, and `read_message` now delegates to
`read_message_header` so the sequence stays single-sourced. `PARITY.md`'s
divergence table records the correction.

The rest of the model held as written. `from_bytes` still returns
`(value, consumed)`, Go's two EOF errors became distinct variants in the
2026-09 review, because RPC clients see their text, and `dcroxide-wire` is
still `no_std` outside of tests.
