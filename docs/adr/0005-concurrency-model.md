# ADR-0005 — D2: Concurrency model

- **Status:** Proposed (draft for decision D2)
- **Date:** 2026-07-03

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
