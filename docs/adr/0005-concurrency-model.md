# ADR-0005 — D2: Concurrency model

- **Status:** Proposed (draft for decision D2) — the tokio choice was not
  taken; see the 2026-07-26 addendum
- **Date:** 2026-07-03 (proposed), 2026-07-26 (addendum: what shipped)

## Context

dcrd is goroutine-per-concern: per-peer read/write loops, a sync manager
event loop, RPC handlers, and worker pools for signature validation. Rust
offers async (tokio) or OS threads; consensus validation is CPU-bound while
p2p/RPC are I/O-bound with modest connection counts (default ~133 peers max).

## Decision (proposed)

- **tokio** for all I/O surfaces: peer connections, DNS seeding, RPC
  (HTTPS + websocket), IPC. Peer protocol drivers as per-peer tasks with
  bounded channels mirroring dcrd's queue semantics (inv/relay queues, stall
  detection).
- **Dedicated thread pool (rayon or hand-rolled) for validation**: script
  checks, signature batches, PoW/merkle verification. Consensus code stays
  synchronous and runtime-free — no `async` in any consensus crate, which
  keeps it auditable, deterministic, and testable without a runtime.
- Chain state behind a single-writer model equivalent to dcrd's chain lock;
  notifications via bounded broadcast channels.

## Consequences

- The async boundary lives exactly at the netsync/rpcserver ↔ blockchain
  seam, same as dcrd's goroutine/chain-lock boundary — the parity audit maps
  cleanly.
- Thread-per-peer (closer to dcrd's structure) remains the documented
  fallback if tokio's complexity shows up in audits; the peer driver is
  written against traits for readability either way.
- Final ratification blocked on: the Phase 11 peer read/write loop prototype
  demonstrating stall handling and backpressure equivalent to dcrd's under
  the adversarial harness.

## Addendum, 2026-07-26 — the fallback shipped, not the proposal

The port has no async runtime. Neither `tokio` nor `rayon` appears in any
manifest in the workspace, and no crate contains an `async fn`. The
documented fallback above — thread-per-peer, closer to dcrd's structure — is
what was built: OS threads over `std::sync::mpsc` channels for every I/O
surface (listener, per-peer input and output loops, outbound dialer, RPC and
websocket handlers, the seeder and the IPC runtime). The validation pool is
`std::thread::scope` in `dcroxide-blockchain`'s `validate_items`, sized like
dcrd's (`runtime.NumCPU()*3` capped at the item count, running inline below
16 items), rather than rayon.

Two clauses of the proposal did hold and are load-bearing: no consensus crate
is async, and chain state sits behind a single writer. One did not — the
websocket notification path is unbounded rather than a bounded broadcast
channel. That is deliberate, because dcrd's is unbounded in the same two
places; `PARITY.md`'s known-gaps section carries the reasoning and the
rejected alternatives.

The thread model has one consequence the proposal did not anticipate. Rust
mutexes poison on panic and Go's do not, so dcrd's per-goroutine `recover`
has no equivalent here: one thread's panic disables every other consumer of
the locks it held, and the RPC layer's `catch_unwind` then kept the process
alive answering canned errors. `[profile.release]` therefore sets
`panic = "abort"`, which makes the surviving `catch_unwind` guards inert in
release builds and requires operators to run the node under a supervisor;
dev and test builds keep unwinding. The full reasoning, and the test that
fails if the setting is dropped, are in `PARITY.md`'s "Known remaining gaps".
