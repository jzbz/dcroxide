# dcroxide — Developer Brief & Project Plan

**A full Rust re-implementation of the Decred full-node daemon (`dcrd`), built as a drop-in replacement.**

Prepared for the implementing developer/team. Parity target: **dcrd master `29f17894`** (version `2.2.0-pre`) — moved up twice, from the `release-v2.1.5` tag this plan was originally written against and then from `452c1a6c`; see the status block below. Wire protocol version **12**, JSON-RPC API version **8.3.0**.

---

## 1. Project statement (the short version)

dcroxide is a from-scratch Rust implementation of the Decred full-node daemon. The goal is that an operator can stop `dcrd`, start `dcroxide` with the same command line and the same `dcrd.conf`, and nothing else in the ecosystem notices: peers speak to it identically, `dcrwallet`/Decrediton/`dcrctl` connect over the same TLS JSON-RPC and websocket API, miners get identical work, and — above all — it accepts and rejects exactly the same blocks and transactions as dcrd, byte for byte, on mainnet, testnet3, simnet, and regnet.

Scope is the complete daemon feature set of dcrd at the parity target:

- Full consensus validation: hybrid PoW/PoS, the ticket lottery, all deployed and defined consensus agendas (from `maxblocksize` through `headercommitments`, `treasury`, `autorevocations`, `changesubsidysplit`, `blake3pow`, `changesubsidysplitr2`, and `maxtreasuryspend`), BLAKE3 proof-of-work with the ASERT difficulty algorithm post-DCP0011, the decentralized treasury, sequence locks, and version-2 GCS filter header commitments.
- The complete P2P protocol at version 12, **including peer-to-peer StakeShuffle mixing message relay** (`mixpool` and all eight `MsgMix*` wire messages), batched v2 committed filters, and address management.
- Stake-aware mempool (tickets/votes/revocations/treasury transactions) with fee estimation.
- Mining infrastructure: background block-template generation, `getwork`, `notifywork`, template regeneration on new votes, and the simnet/regnet CPU miner (`generate`/`setgenerate`).
- The full JSON-RPC surface: 77 HTTP-reachable methods plus 17 websocket-only methods and the notification system, served over TLS with auto-generated certificates, matching dcrd's request/response JSON exactly.
- The transaction index and exists-address index.
- Operational compatibility: `dcrd.conf` parsing, all CLI flags, data-directory layout, log subsystem naming and rotation, the Decrediton pipe-based IPC lifecycle protocol, signal handling, and the auxiliary tools (`gencerts`, `addblock`, `promptsecret` equivalents).

Explicit non-goals: wallet functionality (that is `dcrwallet`), the mixing **client** state machine (`mixclient` — wallet-side; optional later library milestone), Decrediton/GUI work, and gRPC (dcrd has none; only dcrwallet does).

"Full test coverage" is defined concretely in §7: every dcrd test vector ported or regenerated, a fuzz target on every decoder and the script engine, property tests on all round-trip codecs, and a continuously running differential-testing rig that uses real dcrd as an oracle. dcrd carries ~134k lines of Go tests against ~168k lines of implementation; matching that discipline is part of the deliverable, not an afterthought.

---

## Status against this plan — 2026-07-26

*A signpost, not a second README. Per-package detail lives in
[PARITY.md](PARITY.md), deliberate bug-for-bug reproductions in
[QUIRKS.md](QUIRKS.md), operational caveats in [SECURITY.md](SECURITY.md).
Everything below this block is the original plan. Its text stands, with two
exceptions: the parity target is corrected wherever the plan names it, and
where the build diverged from the plan an "as built" note sits beside the
proposal rather than replacing it.*

**Phases 0–14 are complete; the project is inside Phase 15.** Every dcrd
package the plan names is accounted for in the parity ledger, and the daemon
assembles them end to end: config and CLI, the chain engine with full
consensus validation, mempool and fee estimation, mining and the CPU miner, the
P2P server with sync, relay, and StakeShuffle mixing message relay, the
JSON-RPC/websocket server, the tool commands, the pipe IPC lifecycle, and the
Windows service wrapper. The gate runs 729 tests across 234 suites, most of them
differential against dcrd or replaying sessions generated inside dcrd's own
packages. The parity target moved twice during the port, from
`release-v2.1.5` to upstream master `452c1a6c` and then to `29f17894`
(2.2.0-pre); the oracle rig was re-pinned for the first move and kept at
`452c1a6c` for the second, since nothing in that delta changes what the
exporters emit (see PARITY.md).

Work from earlier phases that is genuinely still outstanding. "Complete" above
means the implementation work of those phases is done; several of their written
exit criteria have not been demonstrated, and those are listed here too:

- **Phase 13 — `dcroxide-rpcclient` was never built.** The daemon's RPC surface
  is complete, but the typed Rust client the plan lists as its own deliverable
  is not started; the ledger's `rpcclient` row still reads "—".
- **Ecosystem acceptance has not been run.** The Phase 13/14 exit criteria name
  an unmodified `dcrctl` command sweep, `dcrwallet` in RPC mode, and Decrediton
  including the IPC lifecycle; M4's acceptance column adds the Go `dcrdtest`
  harness pointed at the dcroxide binary. Nothing in the repo records any of
  those being executed. The same applies to the Phase 8 per-block state
  comparator: the mainnet and testnet syncs validated to a matching tip, which
  is weaker than comparing chain state at every height.
- **Phase 0 — the CI gates are partly wired.** `.github/workflows/ci.yml` runs
  rustfmt and `clippy -D warnings`, `cargo test --workspace` on all three OSes
  with the oracle required (`DCROXIDE_REQUIRE_ORACLE=1`), a `cargo check` at
  the 1.94 MSRV, `cargo-deny` over licenses/advisories/sources, a
  60-second-per-target fuzz smoke — all of those on every push to `master`
  and every pull request — and a nightly
  10-minute-per-target run over the 11 fuzz targets. Not wired: coverage
  reporting (`cargo-llvm-cov`), `cargo-vet`, `cargo-mutants`, and any sanitizer
  coverage beyond the AddressSanitizer `cargo fuzz` builds in by default. No
  manual dependency audit or version freeze has been recorded either, which is
  a Phase 15 item.
- Three further ledger rows sit at "—" for reasons that are not debt:
  `crypto/rand` (the daemon seeds its CSPRNGs from `getrandom` rather than
  porting dcrd's package), `dcrutil` (its contents were distributed rather than
  given a crate — `hash160` into `dcroxide-txscript`'s `stdaddr` module,
  app-dir resolution into `dcroxide-node`, and amounts left as plain `i64`
  atoms with the coin conversion at the RPC edge), and `bech32` (nothing at the
  parity target uses it).

What Phase 15 has covered so far:

- **Validation.** testnet and mainnet both synced to the tip from genesis with
  full consensus validation. The first mainnet run validated 1,098,308 blocks
  in ~20.4 h over the public network, before the optimization campaign.
- **Performance campaign.** Storage-commit policy, the release build profile,
  script-engine allocation, parallel script validation, per-block hash
  memoization, a `SigCache` port, and a batch of smaller allocation fixes.
- **Interop and performance benchmark**, all four syncer/source directions,
  one machine, loopback, mainnet genesis to tip (~1,100,400 blocks), fresh
  datadir per run, both nodes `--norpc`, dcroxide 2.2.0-pre against dcrd
  2.2.0-pre+452c1a6c3 (go1.26.5):

  | syncer / source | from dcroxide      | from dcrd          |
  |---|---|---|
  | dcroxide        | 2.47 h — 124 blk/s | 2.51 h — 122 blk/s |
  | dcrd            | 1.11 h — 276 blk/s | 1.02 h — 299 blk/s |

  The syncer decides the time and the source barely matters: swapping the
  source moves the figure 1.6–8.8%, swapping the syncer moves it 2.2x.
  Interop was verified in both directions: dcrd accepts
  `/dcrwire:1.0.0/dcroxide:2.2.0/` and dcroxide accepts
  `/dcrwire:1.0.0/dcrd:2.2.0(pre)/`, each syncing to a matching tip.
- **IBD gap re-measured 2026-08-15: 1.29x, superseding the 2.2x above.** Both
  daemons syncing mainnet from one shared dcrd server, defaults, index
  composition verified on both sides: dcroxide 4,153 s (265.0 blk/s) against
  dcrd 3,220.5 s (341.7 blk/s). Both sides improved since 2026-07 — dcroxide
  124 → 265, dcrd 276 → 342 — and dcrd improving too indicates part of the
  original figure was its harness, which ran the two nodes syncing from each
  other on one machine. A bound rather than a point estimate: arms ~12 h
  apart, unmatched load average, n=1 each, all of which can only have cost
  dcroxide. **It reaches 1.29x at half dcrd's CPU** (0.76 cores against 1.50),
  so the open question is what the node blocks on, not what compute it lacks.
  The gap is still attributed to the storage engine's commit shape rather
  than validation — dcroxide spent 80.1% and 82.4% of wall time in progress
  stalls over 20 s, where dcrd stalled 0 times in 754 windows — and the
  attribution is still not established. Chain on disk at tip: dcrd 23.69 GiB,
  dcroxide 33.58 GiB — identical consensus block bytes, the difference is
  metadata.
- **Security-blocker campaign.** The release blockers, highs, and mediums from
  an audit of the ported surface: RPC authentication and admission, peer
  message-path bounds (stall deadlines, getdata, queue and write limits),
  OS-seeded CSPRNGs, secret-file modes, a datadir lock file, panic containment,
  and the `dbCache` overlay rewrite.
- **Release engineering, partial.** A `[profile.dist]` build profile
  (`inherits = "release"`, `strip = "debuginfo"`) and `panic = "abort"` in
  release builds. Reproducible builds, signed artifacts, OS packages, the
  external security review, and the public differential dashboard are not done.

Named open items, tracked and not fixed:

- The RPC `Server` uses one coarse mutex where dcrd has per-field locks, so a
  single long request — a multi-thousand-block `rescan` — stalls notification
  construction for every other client.
- The redb metadata tree packs at 64.86% page fill (0.645–0.649 across every
  run; the fill figure is the per-table `TableStats::fragmented_bytes` —
  `DatabaseStats::fragmented_bytes` charges the allocator's free pool against
  the tree and reads 43.8%). That is the best case for this data: a sorted
  copy-out rebuild packs *worse*, 58.29%, on a larger live tree, 10.92 GiB
  against 9.79. The 1.536 GiB of intra-page slack in `spendjournalv3` is real
  and unreachable inside this engine.
- The node is flush-bound under fast ingest (the 80% stall figure above).

**The node is still pre-alpha. Do not expose it to the internet and do not use
it with funds.**

---

## 2. Source material, scale, and honest sizing

| Item | Fact |
|---|---|
| Reference implementation | [decred/dcrd](https://github.com/decred/dcrd), Go, ISC license, in production since Feb 2016, ~7,300 commits |
| Parity target | Planned as the `release-v2.1.5` tag (Apr 2026), tracking upstream releases thereafter. It did move: the target is now master `29f17894` (2.2.0-pre), reached via `452c1a6c` |
| Implementation size | ~168,000 lines of non-test Go; ~134,000 lines of Go tests |
| Protocol facts | P2P wire protocol 12 (mixing added at v10, batched cfilters at v11); JSON-RPC API semver 8.3.0; mainnet ports 9108 (p2p) / 9109 (RPC) |
| RPC surface | 77 HTTP methods + 17 websocket methods, spec in `docs/json_rpc_api.mediawiki` |
| Starting point | [jzbz/dcr-rs](https://github.com/jzbz/dcr-rs), Rust, ISC — see §2.1 |
| License plan | dcroxide should be ISC to match dcrd and dcr-rs, with attribution preserved when porting code or test vectors |

Sizing reality check: this is a multi-engineer-year project. A rough planning assumption is that the Rust implementation lands in the same order of magnitude as dcrd's 168k LOC, plus an equal or larger test/tooling volume. The phase plan in §6 is ordered so that value is delivered and verifiable continuously (libraries → validating chain sync → relaying node → RPC-complete drop-in → hardened release), rather than a single big-bang port.

### 2.1 What dcr-rs gives us (and what it doesn't)

`dcr-rs` is a young (single-commit, unaudited) but well-constructed `no_std` crate of Decred *primitives*, grown out of hardware-wallet signing firmware. Its philosophy matches ours ("hand-roll nothing that touches curve math or standard KDFs") and its correctness story is oracle-based: BLAKE-256 known-answer vectors generated from dcrd itself, BIP32 chains from dcrd's `hdkeychain` tests, address vectors from dcrd's `stdaddr` tests, and a real mainnet transaction whose embedded signatures must verify against the recomputed sighash.

Directly reusable (fork/vendor, then extend under our workspace):

- **BLAKE-256** (14-round, the SHA-3-finalist BLAKE — *not* BLAKE2/BLAKE3). No maintained crate exists; dcr-rs vendors a KAT-pinned implementation. This is the single most load-bearing primitive in Decred (txids, block hashes pre-BLAKE3-PoW, sighashes, address hashes, base58 checksums, merkle trees).
- **Transaction wire format** — byte-exact `MsgTx` prefix‖witness serialization, txids.
- **The Decred signature hash** (not Bitcoin's BIP143) — already validated against a mainnet transaction.
- **Address encode/decode/classify** for P2PKH (ECDSA) and P2SH across all four networks, and base58 with the double-BLAKE-256 checksum.
- **HD keys** with Decred `dprv`/`dpub` version bytes (needed only for the optional `hdkeychain` library-parity milestone, not by the daemon itself).

Not covered by dcr-rs (i.e., ~95% of dcroxide): networking, RPC, consensus, staking, mixing, mempool, database, script *execution* (dcr-rs signs P2PKH only — it does not evaluate scripts), Schnorr/Ed25519 signature types, and address flavors beyond P2PKH/P2SH (stake-tagged addresses, P2PK, etc.). Treat dcr-rs as a Phase-1 accelerator and a model for the oracle-pinned testing style, not as an architectural foundation.

Action item for week 1: contact the dcr-rs author about upstreaming vs. forking; either way, vendor at a pinned commit with attribution and add our own vector regeneration scripts.

---

## 3. The compatibility contract — what "drop-in replacement" means, precisely

Every task in this project serves one of six compatibility surfaces. They are listed in priority order; C1 failures are ship-blockers of the highest severity (a consensus divergence can fork a money network).

**C1 — Consensus (absolute, bug-for-bug).** For every block and transaction ever seen or seeable on any Decred network, dcroxide's accept/reject verdict, resulting chain state (best tip, UTXO set, live-ticket set, treasury balance, agenda threshold states), and all consensus-derived values (subsidies, difficulty, lottery winners, sequence locks) must equal dcrd's exactly. Where dcrd's behavior deviates from written specification, **dcrd's behavior wins** and the deviation is recorded in [QUIRKS.md](QUIRKS.md) with a test pinning it.

**C2 — P2P wire protocol (version 12).** Message framing, per-network magic bytes, version negotiation and services, all message types including the eight mixing messages, inventory/relay semantics, protocol-version gating of features (mixing ≥10, batched cfilters ≥11), misbehavior/ban scoring, and connection policies — such that mixed fleets of dcrd and dcroxide nodes interoperate indefinitely and neither side bans the other.

**C3 — RPC API (JSON-RPC 8.3.0).** All 77 HTTP methods and 17 websocket methods, byte-compatible JSON encoding (field names, field order, presence/omission rules, number formatting — see the Go-float risk in §10), identical error codes/messages, identical help text (`help`), TLS with self-signed cert auto-generation, HTTP Basic auth with full and limited (`rpclimituser`) privilege tiers, and the websocket notification system (`notifyblocks`, `notifywork`, `notifynewtransactions`, `notifywinningtickets`, `notifytspend`, `loadtxfilter`/`rescan`, etc.). Acceptance oracle: `dcrctl`, `dcrwallet` (RPC mode), and Decrediton must work unmodified.

**C4 — CLI, config, lifecycle.** Every dcrd flag and `dcrd.conf` option with identical names, defaults, precedence (CLI > config file > defaults), and validation errors; identical default data-dir/log-dir resolution per OS and per network; exit codes; POSIX signals; the Windows service wrapper; and the pipe-based IPC protocol (`--piperx`/`--pipetx` lifecycle events) that Decrediton uses to supervise the daemon.

> **As built:** option names, defaults, precedence, validation messages, and the
> per-OS/per-network path *algorithm* are dcrd's, but the daemon runs under its
> own name. The application data directory is `~/.dcroxide`, the default config
> file is `dcroxide.conf`, and the two environment variables dcrd reads are
> renamed to match (`DCROXIDE_APPDATA`, `DCROXIDE_ALT_DNSNAMES`). An operator's
> existing `dcrd.conf` is still a valid input — the grammar and every option are
> unchanged — but it has to be named or pointed at explicitly rather than picked
> up in place.

**C5 — Operational artifacts.** `rpc.cert`/`rpc.key` generation compatible with what dcrwallet/dcrctl expect, log file naming/rotation, pprof-style profiling endpoints (`--profile`) with a documented Rust-appropriate equivalent where Go-runtime-specific outputs cannot be replicated, UPnP, proxy/Tor (SOCKS5, onion) support, and `--altdnsnames`.

> **As built:** certificate generation, log naming and rotation, the proxy/Tor
> dial path, and `--altdnsnames` are in. Three items are deliberate non-ports:
> the profiling flags (`--profile`/`--cpuprofile`/`--memprofile`) validate but
> serve nothing, `--upnp` parses but maps nothing, and the Windows service ships
> without the event-log half (log lines go to standard output under the SCM).
> Go's soft-memory-limit tuning has no Rust analog and is not reproduced.
> PARITY.md lists each with its reasoning.

**C6 — On-disk data directory.** dcrd stores blocks in flat `.fdb` files with goleveldb metadata (`ffldb`), plus a dedicated UTXO backend and index databases. Reading an existing dcrd datadir in place is a *stretch goal*; the default plan is fresh sync (plus an `addblock`-style bulk importer that can ingest dcrd's exported block files to accelerate it). Do not let C6 hold earlier milestones hostage.

> **Decided and built:** [ADR-0004](docs/adr/0004-storage-backend.md) (Accepted)
> settled this — dcrd's `database` interface semantics over `redb` for metadata
> plus dcrd-style flat block files, **fresh sync only**, `addblock`-format
> import as the migration path, and ffldb/goleveldb read-compat explicitly out
> of scope. A dcroxide datadir is therefore not a dcrd datadir and cannot be
> swapped either way — and since the 2026-08-13 bump to redb 4.1.0 the same
> stance holds inside the port: a dcroxide datadir written before that date is
> refused outright with a typed error, not misread, and has to be re-synced or
> re-imported. The block bytes are consensus data and identical, and so is the
> metadata payload — 54 B of residual difference on 6.06 GB across fifteen
> buckets — so the disk gap is entirely the engine's page layout: goleveldb
> holds that payload in 1.081x its size, redb's live B-tree in 1.738x at
> 64.86% page fill.

---

## 4. Engineering principles

1. **dcrd is the specification.** Written docs (DCPs, `docs/`) are secondary. When in doubt, read dcrd source at the pinned upstream commit and reproduce it — including quirks. Every intentional quirk reproduction gets an entry in `QUIRKS.md` and a pinning test.
2. **Oracle-driven development.** Every consensus-relevant module ships with (a) test vectors extracted from dcrd's own tests or generated by small Go shim programs we write against dcrd packages, and (b) where feasible, a differential fuzz target comparing dcroxide to dcrd live. The dcrd clone plus our `tools/oracle/` Go shims are first-class parts of this repo.
3. **No hand-rolled cryptography for standard algorithms.** secp256k1 arithmetic, SHA-2 family, RIPEMD-160, Ed25519 field math, and BLAKE3 come from audited/widely-used crates. We own only Decred-specific constructions: BLAKE-256 (vendored, KAT-pinned), EC-Schnorr-DCRv0 (composed on top of a vetted arithmetic backend), the sighash, and the mixing DC-net math (ported with vectors).
4. **Memory safety as a feature.** `#![forbid(unsafe_code)]` in all dcroxide crates; `unsafe` allowed only inside vetted third-party dependencies, tracked via `cargo-deny`/`cargo-vet`/`cargo-audit` in CI. This is a headline advantage of the project — protect it.
5. **Consensus code is boring code.** No cleverness in validation paths: explicit integer widths, checked arithmetic mirroring dcrd's `checkedmath`, no floating point anywhere near consensus, deterministic iteration orders, and exhaustive error enums mapped 1:1 to dcrd's error kinds (RPC and reject messages leak error identity — parity matters).
6. **DoS posture parity.** dcrd's limits (message sizes, orphan pools, ban scores, per-peer rate limits, mixpool limits, APBF sizing) are consensus-adjacent: divergence lets an attacker partition mixed networks. Port limits verbatim; test them.
7. **Pin, then track.** All parity claims reference one pinned upstream commit — `release-v2.1.5` when this plan was written, master `29f17894` now. A standing "upstream watch" task reviews every dcrd release/merged consensus PR and files parity issues. A `PARITY.md` ledger maps each dcrd package to its dcroxide crate and status.

---

## 5. Proposed workspace architecture

Cargo workspace mirroring dcrd's package graph so that parity auditing is mechanical. dcrd's module layout has proven boundaries — keep them unless Rust gives a strong reason not to.

| dcroxide crate | Mirrors dcrd | Contents |
|---|---|---|
| `dcroxide-chainhash` | `chaincfg/chainhash` | 32-byte hash type, hex/serde |
| `dcroxide-crypto` | `crypto/blake256`, `crypto/ripemd160`, `crypto/rand` | BLAKE-256 (vendored from dcr-rs), RIPEMD-160/SHA-2 re-exports, CSPRNG wrapper |
| `dcroxide-dcrec` | `dcrec`, `dcrec/secp256k1`, `dcrec/edwards` | Signature types 0/1/2: ECDSA-secp256k1, Ed25519, EC-Schnorr-DCRv0; DER/compact parsing with dcrd's exact acceptance rules |
| `dcroxide-wire` | `wire` | All P2P messages incl. `MsgMixPairReq/KeyExchange/Ciphertexts/SlotReserve/DCNet/FactoredPoly/Confirm/Secrets`, tx/block/header serialization, protocol constants |
| `dcroxide-chaincfg` | `chaincfg` | All four network params, agenda deployments, premine/genesis, seeders, address prefixes |
| `dcroxide-dcrutil` | `dcrutil` | Amounts, addresses (extend dcr-rs to all standard address kinds), app-dir resolution, block/tx convenience wrappers |
| `dcroxide-base58` / `dcroxide-bech32` | `base58` (separate repo dep in Go), `bech32` | Encodings with Decred checksums |
| `dcroxide-txscript` | `txscript` (+ `stdaddr`, `sign`) | Script engine, opcodes incl. stake opcodes, standardness, sighash (from dcr-rs), tokenizer |
| `dcroxide-stake` | `blockchain/stake` | Stake tx classification (SStx/SSGen/SSRtx/treasury), ticket lottery (`Hash256PRNG`), live-ticket state, treasury rules |
| `dcroxide-standalone` | `blockchain/standalone` | Pure functions: merkle roots, PoW checks (BLAKE-256 & BLAKE3 + ASERT), subsidy schedule incl. all split changes, inclusion proofs, tspend math |
| `dcroxide-gcs` | `gcs` | Version-2 Golomb-coded sets, SipHash-keyed, filter building/matching |
| `dcroxide-database` | `database` (+ `ffldb`) | Storage abstraction + chosen backend(s); optional ffldb-compat reader |
| `dcroxide-blockchain` | `internal/blockchain` | Chain engine: block index, chain view, threshold/agenda state, difficulty, treasury, sequence locks, header commitments, UTXO cache/backend, spend journal, reorg handling, notifications |
| `dcroxide-indexers` | `internal/blockchain/indexers` | txindex, existsaddrindex, index subscriber, legacy-index drop logic |
| `dcroxide-mempool` | `internal/mempool`, `internal/fees` | Stake-aware pool, orphan handling, policy, fee estimator |
| `dcroxide-mining` | `internal/mining` | Background template generator, priority/selection logic, CPU miner |
| `dcroxide-mixing` | `mixing`, `mixing/mixpool`, `mixing/utxoproof` | Mix message validation/pooling/relay, DC-net field math, UTXO ownership proofs, expiry; (`mixclient` optional, later) |
| `dcroxide-addrmgr` / `-connmgr` / `-peer` | `addrmgr`, `internal/connmgr`, `peer` | Address book, connection lifecycle/retry/ban, per-peer protocol driver |
| `dcroxide-netsync` | `internal/netsync` | Initial sync orchestration (headers-first, parallel block download), steady-state relay |
| `dcroxide-rpc` | `internal/rpcserver`, `rpc/jsonrpc/types`, `dcrjson` | JSON-RPC server, websocket layer, typed command/result structs, help text |
| `dcroxide-rpcclient` | `rpcclient` | Typed Rust client (needed by our own integration tests; also a deliverable) |
| `dcroxide-containers` | `container/apbf`, `container/lru` | Age-partitioned bloom filter (mix relay dedupe), LRU |
| `dcroxide-certgen` | `certgen` | Self-signed TLS cert generation compatible with the ecosystem's expectations |
| `dcroxide` (bin) | repo root, `cmd/*` | Daemon assembly: config/CLI, server orchestration, logging, signals, IPC, Windows service; plus `gencerts`/`addblock`/`promptsecret` equivalents |
| `tools/oracle` (Go) | n/a | Shim binaries linking real dcrd packages to emit vectors / act as differential oracles |

**As built:** the workspace holds 32 crates and follows this table closely. Three
proposed crates do not exist. `dcroxide-dcrutil` was never created — the
addresses this row proposed for it are in `dcroxide-txscript`'s `stdaddr`
module, which is where dcrd keeps them at the parity target too, along with
`hash160`; app-dir resolution is in `dcroxide-node`; and amounts stayed plain
`i64` atoms rather than becoming a type. `dcroxide-bech32` was never created
because nothing at the parity target uses it, and `dcroxide-rpcclient` is still
outstanding (see the status block). Four crates arrived that this table did not
anticipate:
`dcroxide-ratelimit` (dcrd 2.2's `internal/ratelimit` token bucket),
`dcroxide-winsvc` (the Windows service wrapper, split out of the binary),
`dcroxide-bench` (a block-replay harness for the performance work), and
`dcroxide-testutil`. Two groupings were split finer than sketched here:
`dcroxide-fees` is its own crate rather than part of `dcroxide-mempool`, and
`dcroxide-dcrjson` and `dcroxide-rpctypes` are their own crates rather than part
of `dcroxide-rpc`. `dcroxide-uint256` (Phase 1) belongs in this table and is
absent from it. The daemon crate is `dcroxide-node`; the binary it produces is
`dcroxide`.

---

## 6. Phase plan

Phases are ordered by dependency, sized S/M/L/XL (relative engineering effort, including tests), and grouped into the milestones of §11. Every phase's exit criteria are testable; nothing advances on "looks done."

### Phase 0 — Scaffolding, oracle rig, and CI *(S)*

- Cargo workspace, MSRV policy, rustfmt/clippy (deny warnings), `cargo-deny` + `cargo-audit` + (aspirationally) `cargo-vet` gates, coverage via `cargo-llvm-cov`, CI matrix for Linux/macOS/Windows.
- Vendor dcrd at `release-v2.1.5` as a submodule; build `tools/oracle/` harness: small Go programs that link dcrd packages and expose them over stdin/stdout JSON for vector generation and live differential testing.
- Fuzzing infrastructure (`cargo-fuzz`; optionally honggfuzz), corpus storage, and a nightly fuzz CI job from day one.
- Repo docs skeleton: `PARITY.md` ledger, `QUIRKS.md`, ADR (architecture decision record) directory.
- **Exit:** CI green on all platforms; a demo differential test (e.g., BLAKE-256 of random inputs vs. dcrd oracle) runs in CI.

### Phase 1 — Primitives & cryptography *(M)*

- Integrate/vendor dcr-rs: BLAKE-256, base58check, amounts, tx serialization, sighash; regenerate its KAT vectors from our own oracle rig to remove trust in inherited fixtures.
- `chainhash`; BLAKE3 (official `blake3` crate); RIPEMD-160/SHA-256 (RustCrypto); CSPRNG wrapper mirroring `crypto/rand` semantics.
- Signature type 0 (ECDSA-secp256k1): verify + RFC6979 low-S sign, DER *and* dcrd's exact lax-parsing acceptance behavior.
- Signature type 2 (EC-Schnorr-DCRv0): implement per dcrd `dcrec/secp256k1/schnorr` on the chosen arithmetic backend (§9 decision); port all dcrd vectors; differential-fuzz sign/verify against the oracle.
- Signature type 1 (Ed25519): wrap a vetted crate but **match dcrd's `dcrec/edwards` acceptance exactly** (canonicality/malleability edge cases) — differential fuzz mandatory before this ships.
- `uint256` (port of `math/uint256`: fixed 256-bit ops used by difficulty/work), with property tests against a bigint reference.
- **Exit:** all dcrd vectors for these packages pass; differential fuzzers for ECDSA/Schnorr/Ed25519 verify paths and BLAKE-256 run clean for an extended soak; zero `unsafe` in our code.

### Phase 2 — Wire protocol & core types *(M/L)*

- Every wire message at protocol 12, including all eight mix messages and batched cfilters; the 180-byte Decred header with its stake fields; tx prefix/witness serialization types; message framing, per-network magic, checksums, size limits.
- Round-trip property tests (decode∘encode = id; encode∘decode = id on valid corpora); port dcrd's `wire` tests wholesale; a fuzz target per message type (decoders are the classic remote attack surface).
- **Exit:** byte-identical encodings vs. oracle across dcrd's test corpus + 10⁷ random structured messages; fuzzers clean.

### Phase 3 — chaincfg *(S)*

- All four networks' parameters: genesis blocks, premine, seeders, ports, address/HD prefixes, stake parameters, subsidy schedule constants, and the complete agenda deployment set (`maxblocksize`, `sdiffalgorithm`, `lnsupport`, `lnfeatures`, `fixlnseqlocks`, `headercommitments`, `treasury`, `reverttreasurypolicy`, `explicitverupgrades`, `autorevocations`, `changesubsidysplit`, `blake3pow`, `changesubsidysplitr2`, `maxtreasuryspend`) with per-network deployment windows and choices.
- **Exit:** a generated dump of every param struct is byte-identical to an oracle dump; genesis hashes reproduce.

### Phase 4 — txscript *(XL — consensus-critical heart)*

- Tokenizer, full opcode set including Decred's stake opcodes and script version gating; the engine with all flag combinations dcrd uses (consensus vs. standardness); signature checking across all three signature types; `stdaddr`-equivalent standard-script classification for every address kind; script-building/sign helpers needed by RPC (`createrawsstx`, etc.).
- Port dcrd's entire txscript test corpus; add a **differential script fuzzer**: random scripts + random flags executed in both engines via the oracle, comparing verdict *and* error kind. This fuzzer runs continuously for the life of the project.
- **Exit:** corpus parity; differential fuzzer clean over a large soak (target: ≥10⁹ executions before Phase 8 ships); mainnet historical spot-check (Phase 8 will make it exhaustive).

### Phase 5 — Stake primitives *(L)*

- Stake transaction classification and rule checks (tickets/votes/revocations, treasury add/spend/base, vote bits, commitments); the ticket lottery: `Hash256PRNG` and deterministic winner selection; live/immature/expired ticket accounting; auto-revocation rules.
- **Exit:** lottery selections match the oracle for the full mainnet history sample set dcrd tests use, plus randomized differential tests; stake classification verdict parity fuzzer clean.

### Phase 6 — Standalone consensus functions *(M)*

- Merkle roots (regular, stake, and post-DCP0005 combined), header-commitment inclusion proofs, PoW checks for both hash functions, both difficulty algorithms (legacy EMA retarget and ASERT), the full subsidy schedule across all three split regimes (60/30/10 → 10/80/10 → 1/89/10), and treasury spend math.
- **Exit:** vector + property parity (e.g., subsidy summed over height ranges equals oracle; ASERT anchors reproduce mainnet difficulties).

### Phase 7 — Database & chain storage *(L)*

- Storage abstraction mirroring dcrd's `database` interface semantics (buckets, tx model); chosen backend per §9 decision D1; block-file storage; the dedicated UTXO backend + cache with dcrd's compressed script/amount encodings; spend journal; block index persistence.
- `addblock`-equivalent bulk importer/exporter (also our fast-sync path and our C6 mitigation).
- **Exit:** crash-consistency tests (kill -9 during writes, restart, verify), storage round-trip property tests, import of a multi-hundred-thousand-block file matches oracle tip state.

### Phase 8 — The chain engine *(XL — the core deliverable)*

- Full block acceptance pipeline: context-free checks, contextual checks, threshold/agenda state machine, difficulty, stake validation against the live ticket set, treasury account and expenditure policy, sequence locks, header commitments, connect/disconnect with spend journal, deep reorg handling, notifications, pruning hooks, invalidate/reconsider support.
- Port `blockchain/fullblocktests` and the `chaingen` block generator — dcrd's purpose-built consensus battery — in full. This is a project within the project; budget accordingly.
- **The flagship acceptance test:** full initial sync of mainnet and testnet3 with a per-block comparator against a synced dcrd (tip hash, `getblockchaininfo`-level state, UTXO-set stats, live-ticket set hash, treasury balance at every height). Any divergence is a stop-ship bug.
- **Exit:** fullblocktests parity; clean mainnet + testnet3 syncs with zero comparator divergence; reorg storm tests on simnet.

### Phase 9 — Filters & indexers *(M)*

- Version-2 GCS committed filters (build + match, SipHash parameters exactly as dcrd), validated against header commitments across the full chain; txindex and existsaddrindex incl. incremental build, catch-up, and drop logic for the removed legacy indexes.
- **Exit:** every mainnet block's cfilter v2 hash matches the header commitment and the oracle's `getcfilterv2`; index query parity on sampled history.

### Phase 10 — Mempool, fees, mining *(L)*

- Stake-aware mempool with dcrd's policy (standardness, expiry handling, orphan limits, per-type pools, vote/ticket interactions, treasury tx gating), RBF-absence semantics as dcrd defines them, and the fee estimator behind `estimatesmartfee`.
- Mining: background template generator with vote-triggered regeneration (`regentemplate`), `getwork` semantics for BLAKE3 PoW, `submitblock`, and the CPU miner for simnet/regnet.
- Differential mempool testing: replay identical tx streams into dcrd and dcroxide; compare accept/reject + error + resulting pool contents. Template comparison on simnet under scripted vote/ticket scenarios.
- **Exit:** mempool differential soak clean; mined simnet chains cross-validate (dcroxide mines, dcrd follows, and vice versa).

### Phase 11 — P2P stack & sync *(L)*

- `addrmgr` (persistence format decision-linked), `connmgr` (targets, retry/backoff, ban/whitelist, listeners, proxy/Tor, UPnP), `peer` (handshake, version gating, ping, inv/relay queues, stall/misbehavior handling), `netsync` (headers-first initial sync, parallel block download, steady-state), APBF + LRU containers for relay dedupe.
- Interop testing: long-running mixed dcrd/dcroxide simnet and testnet fleets; adversarial peer harness (malformed/slow/flooding peers) asserting ban behavior matches dcrd's.
- **Exit:** dcroxide syncs mainnet from real network peers; mixed fleets stable for multi-week soak; adversarial suite parity.

### Phase 12 — Mixing (mixpool) *(M/L)*

- `mixpool`: acceptance/validation of all eight message types (signatures, session/run linkage, pair-request UTXO ownership proofs via `utxoproof`, fee-rate and count limits), orphan handling, epoch/expiry rules keyed to chain state, inv-based relay with APBF dedupe, and the `getmixmessage`/`getmixpairrequests`/`sendrawmixmessage` RPCs.
- DC-net finite-field and vector math ported with dcrd's vectors (needed for validation paths even without the client).
- Acceptance oracle: an unmodified `dcrwallet` performing real StakeShuffle mixes through a dcroxide node on testnet3, and mixed-relay tests where messages originate behind dcrd and must complete via dcroxide relays (and vice versa).
- **Exit:** live wallet mixes succeed through dcroxide; relay/expiry/ban behavior differential-tested; malformed-mix-message fuzzers clean.
- Optional later add-on (separate milestone, not daemon parity): `mixclient` as a Rust library for wallet builders.

### Phase 13 — RPC server *(L)*

- Transport: HTTPS + websocket on one port, TLS via `certgen` equivalent, Basic auth with full/limited tiers, connection limits.
- All 77 HTTP methods + 17 websocket methods + notifications, `dcrjson`-equivalent typed command/result layer, and the complete `help` text corpus.
- JSON byte-parity harness: golden request/response captures from dcrd for every method (success + each documented error), replayed against dcroxide; canonical comparison plus raw-bytes comparison where feasible (see number-formatting risk, §10).
- **Exit:** golden-parity suite green; `dcrctl` full command sweep passes unmodified; `dcrwallet` runs against dcroxide in RPC mode through funding/staking/voting flows on simnet; Decrediton connects and operates.

### Phase 14 — Daemon assembly & operational parity *(M)*

- Config/CLI layer replicating dcrd's go-flags behavior (INI-style `dcrd.conf`, every option, precedence, validation messages), app-dir/log-dir resolution, subsystem loggers with dcrd's names and `--debuglevel` grammar, log rotation, signals, exit codes, pipe IPC lifecycle protocol for Decrediton, Windows service mode, profiling endpoints, `gencerts`/`addblock`/`promptsecret` tool equivalents.
- **Exit:** a config-compat test that runs dcrd's own `config_test`-derived cases; Decrediton launches, supervises, and cleanly stops dcroxide via IPC on all three OSes.

### Phase 15 — Hardening, performance, release *(L, then continuous)*

- Fuzz totals review and corpus minimization; differential fuzzers promoted to scheduled long-runs; `cargo-mutants`-style mutation testing on consensus crates; dependency audit freeze.
- Performance: criterion micro-benchmarks per crate plus macro benchmarks vs. dcrd (initial sync wall-clock, block validation latency at tip, mempool ingest throughput, RPC latency, memory ceiling vs. dcrd's ~2 GB guidance) with regression gates in CI. Parity is the floor; document wins.
- External security review of consensus, p2p, and RPC-auth code paths; publish threat model and `SECURITY.md`.
- Release engineering: reproducible builds, signed artifacts matching Decred's binary-verification culture, OS packages, upgrade/runbook docs, and a public "differential dashboard" node pair (dcrd + dcroxide) on mainnet.
- **Exit:** v1.0 criteria = all C1–C5 acceptance suites green at the pinned upstream commit, multi-week mainnet soak with zero divergence, review findings resolved.

---

## 7. Testing & verification strategy ("full test coverage," defined)

Coverage percentage alone is a vanity metric for consensus software; a line can be covered and still wrong. dcroxide's definition of full coverage is the conjunction of all seven layers below, with hard CI gates.

**Layer 1 — Ported vectors.** Every test vector in dcrd's ~134k lines of tests that exercises observable behavior gets ported or mechanically regenerated through `tools/oracle`. The `PARITY.md` ledger tracks per-package: vectors ported / regenerated / intentionally skipped (with justification).

**Layer 2 — Property-based tests** (`proptest`). Mandatory for every codec (round-trip laws), arithmetic type (`uint256` vs. bigint reference), and data structure with invariants (ticket accounting, UTXO cache vs. backend equivalence, APBF false-negative-freedom within window).

**Layer 3 — Fuzzing** (`cargo-fuzz`, nightly CI + long-run boxes). One target minimum per: wire message decoder, script engine, address/base58/bech32 parsing, GCS filters, mix message validation, JSON-RPC request parsing, config parsing, database record decoding. Crash-free is necessary but not the point —

**Layer 4 — Differential (oracle) testing** is the point. dcrd itself, driven through `tools/oracle` shims or as a live node, is the oracle for: script execution verdicts+errors, signature verification across all three types, sighash, lottery selection, difficulty/subsidy, mempool acceptance, block acceptance, cfilter contents, and RPC responses. Differential fuzzers (random input → both implementations → compare) run continuously; any divergence files a stop-ship bug with a minimized repro that becomes a permanent regression test.

**Layer 5 — Consensus battery.** Full port of `blockchain/fullblocktests` + `chaingen`, extended with Decred-agenda-specific scenario generators (vote outcomes flipping threshold states, treasury expenditure edges, auto-revocation boundaries, DCP0011 transition blocks).

**Layer 6 — Integration & ecosystem acceptance.**
- Historical: full mainnet + testnet3 syncs with the per-block state comparator (Phase 8).
- Harness: stand up nodes programmatically for multi-node tests; because dcroxide is CLI-compatible, pointing the existing Go harness ([decred/dcrtest](https://github.com/decred/dcrtest)'s dcrd harness) at the dcroxide binary is itself an acceptance test. Port dcrd's `internal/integration` suite.
- Simnet: scripted environments with dcrwallet voting wallets (per dcrd's simnet docs) covering staking, voting, treasury tspends, reorgs, and mixing end-to-end.
- Ecosystem sweep: unmodified `dcrctl` (all commands), `dcrwallet` (RPC mode incl. mixing), Decrediton (incl. IPC lifecycle) against dcroxide.
- Soak: long-running mixed dcrd/dcroxide fleets on testnet3 and mainnet with alerting on any relay/ban/state anomaly.

**Layer 7 — Performance & robustness.** Criterion benches with regression thresholds; macro benchmarks vs. dcrd on identical hardware; adversarial peer/RPC load tests; crash-consistency (power-cut simulation) on the storage layer; resource-ceiling tests against the published minimum specs (2 GB RAM class hardware).

**Gates:** consensus-tagged crates (`txscript`, `stake`, `standalone`, `blockchain`, `gcs`, `dcrec`, `wire`, `mixing` validation paths) require: 100% of ported vectors passing, differential fuzz soak sign-off, mutation-testing review, and two-reviewer sign-off on every PR. Workspace line coverage is reported and ratcheted (never decreases); a target ≥90% overall is expected to fall out naturally rather than be chased.

---

## 8. Dependency policy & candidate crates

Policy: prefer widely-deployed, actively-maintained, audited-where-possible crates; pin exact versions; `cargo-deny` license/advisory gates; vendor-and-pin anything Decred-specific. Every dependency addition is an ADR. Candidates (developer validates final picks in Phase 0–1):

| Need | Candidate | Notes / risks |
|---|---|---|
| Async runtime & net | `tokio` | Industry default; alternative thread-per-peer model is decision D2 |
| TLS | `rustls` + `rcgen` | `rcgen` replaces `certgen` for self-signed cert generation; verify dcrwallet/dcrctl accept the certs |
| WebSocket | `tokio-tungstenite` | dcrd uses gorilla/websocket; behavior parity on ping/close needed |
| HTTP | `hyper` (or `axum` thin layer) | RPC server is a small, auth-gated surface; avoid framework sprawl |
| JSON | `serde`/`serde_json` + custom emit layer | Byte-parity with Go's `encoding/json` (field order, omitempty, **float formatting**) will need a controlled serializer for responses — see risk R3 |
| secp256k1 | `secp256k1` (libsecp bindings) and/or `k256` | dcr-rs uses the bindings for ECDSA. EC-Schnorr-DCRv0 needs raw scalar/point ops → likely `k256` (pure Rust) for the custom scheme; decision D3. Daemon is verification-heavy, which eases constant-time pressure, but signing paths (miner, RFC6979 helpers) still exist |
| Ed25519 | `ed25519-dalek` (wrapped) | Must match dcrd `dcrec/edwards` acceptance exactly; expect to add compatibility shims after differential fuzzing |
| BLAKE3 | `blake3` | Official, SIMD-optimized — likely *faster* than dcrd's PoW hashing |
| BLAKE-256 | vendored (from dcr-rs) | No maintained crate exists; KAT-pinned against dcrd; consider optimizing later (it's on the hot path for txids/merkle) |
| SHA-2 / RIPEMD-160 / HMAC | RustCrypto (`sha2`, `ripemd`, `hmac`) | Standard, widely reviewed |
| SipHash (GCS) | `siphasher` | Match dcrd's keying/variant exactly |
| Storage | decision D1: `rocksdb` / `redb` / leveldb-compat (`rusty-leveldb` or C bindings) | goleveldb-format compat only matters if C6 in-place reuse is pursued |
| Config/CLI | `clap` + custom INI layer | jessevdk/go-flags semantics (INI file + flags, exact option names/precedence) will not fall out of any crate for free; budget a real compat layer with dcrd's `config_test` cases as spec |
| Logging | `tracing` (or `log`+custom) | Must reproduce dcrd subsystem names, `--debuglevel` grammar, file rotation |
| SOCKS/Tor, UPnP | `tokio-socks`, `igd`(-next) | Feature-flag UPnP; verify against dcrd's `--upnp`/`--proxy`/onion behavior |
| Test/QA | `proptest`, `criterion`, `cargo-fuzz`, `cargo-llvm-cov`, `cargo-mutants`, `cargo-deny`, `cargo-audit`, `cargo-vet` | CI from Phase 0 |

Not needed by the daemon (avoid scope creep): CBOR/airgap bits of dcr-rs, BIP39, gRPC.

**As built**, five rows landed elsewhere than the candidate column suggests.
There is no async runtime: `tokio` is not in the dependency graph and the daemon
is OS-threaded throughout. There is no HTTP or websocket framework either —
`hyper` and `tokio-tungstenite` were not adopted, and the RPC listener speaks
HTTP/1.1 and RFC 6455 directly over `rustls` (ring provider only, so nothing
pulls a C crypto library into a workspace that forbids `unsafe`). The RPC crates
declare no serde dependency at all: dcrd's `dcrjson` is reflection-driven, so
the port carries a runtime Go type model with `encoding/json` reimplemented over
it, Go float formatting and all (ADR-0007). `certgen` is a direct port of dcrd's
package rather than `rcgen`, with the divergences PARITY.md records (dcrd's
RSA4096 algorithm is omitted, among others). Storage went to `redb` per
ADR-0004. Of the policy half: `cargo-deny` gates licenses, advisories, and
sources in CI against `deny.toml`, but `cargo-vet` was never adopted, no manual
audit or version freeze of the dependency set has been recorded, and the
manifests carry caret ranges with a committed `Cargo.lock` rather than the exact
pins this policy asks for.

---

## 9. Decisions the developer must surface in the first two weeks

> **These were surfaced, and the record is in [docs/adr/](docs/adr/).** D1–D4
> were drafted as ADR-0004 through ADR-0007 in the first sprint; ADR-0001
> (the oracle rig), ADR-0002 (vendoring BLAKE-256), and ADR-0003 (slice-based
> wire decoding) cover early decisions this list did not anticipate. Where the
> outcome differs from the recommendation below, the difference is worth
> knowing:
>
> - **D1** — ratified as [ADR-0004](docs/adr/0004-storage-backend.md)
>   (Accepted): `redb` behind dcrd's database semantics, flat block files,
>   fresh sync only.
> - **D2** — [ADR-0005](docs/adr/0005-concurrency-model.md), *Accepted*
>   (ratified 2026-08-07). The recommendation was not taken: there is no
>   tokio in the dependency graph and the node is OS-threaded throughout,
>   which is the ADR's own documented fallback. Its addenda record what
>   shipped and the evidence behind ratification.
> - **D3** — [ADR-0006](docs/adr/0006-secp256k1-backend.md), still *Proposed*.
>   The split held: libsecp256k1 bindings for ECDSA, `k256` for
>   Schnorr-DCRv0, curve25519-dalek for Ed25519.
> - **D4** — [ADR-0007](docs/adr/0007-json-emission-strategy.md), still
>   *Proposed*. Both halves were built but neither in the proposed shape: the
>   emission layer uses no serde at all (a runtime Go type model with a
>   reimplementation of `encoding/json` over it), and the regression corpus is
>   dumped from inside dcrd's own packages rather than captured from a running
>   node.
> - **D5** (upstream tracking cadence) and **D7** (MSRV, platform tiers,
>   release signing and reproducibility) have no ADR. Facts on the ground:
>   the parity target did move to master `452c1a6c` and again to `29f17894`,
>   MSRV is pinned at 1.94
>   through the workspace `rust-version` with a CI job that `cargo check`s the
>   workspace at it, and CI tests on Linux, macOS, and Windows. Release signing
>   and reproducible builds are neither decided nor built.
> - **D6** is partially covered by
>   [ADR-0002](docs/adr/0002-vendor-blake256-from-dcr-rs.md): dcr-rs is
>   vendored at a pinned commit with attribution.
>
> The original list follows unchanged.

- **D1 — Storage backend & C6 stance.** Recommendation: modern embedded KV (`redb` or `rocksdb`) behind dcrd's database interface semantics, fresh-sync default, `addblock`-style import as the migration path; ffldb/goleveldb read-compat as a separately-scheduled stretch. Needs an ADR either way.
- **D2 — Concurrency model.** Recommendation: tokio async for p2p/RPC with validation on a dedicated rayon/thread pool; but a thread-per-peer design closer to dcrd's goroutine structure is defensible for auditability. ADR with a small prototype of the peer read/write loops.
- **D3 — secp256k1 backend split.** Bindings vs. pure-Rust vs. hybrid (bindings for ECDSA, `k256` for Schnorr-DCRv0). Constraint: identical verification acceptance across all inputs, proven by differential fuzz.
- **D4 — JSON emission strategy** for byte-parity (custom serializer vs. canonicalized comparison + documented deltas). Interacts with R3.
- **D5 — Upstream tracking cadence** once 2.2 lands upstream: parity branch policy, how consensus PRs are mirrored, who owns the watch.
- **D6 — dcr-rs relationship**: upstream contributions vs. hard fork into the workspace; either way pin + attribute.
- **D7 — MSRV, platform tier list** (match dcrd: Linux/macOS/Windows first-class), and release signing/reproducibility approach.

---

## 10. Top risks & mitigations

- **R1 — Consensus divergence (chain-split class).** The central risk. Mitigations are the whole of §7: oracle-driven development, fullblocktests port, full-history comparator syncs, continuous differential fuzzing, quirk ledger, mainnet differential dashboard before any production recommendation.
- **R2 — "Spec vs. dcrd" traps.** DCP documents and even dcrd docs can lag code. Rule: code at the pinned upstream commit is truth; every discovered mismatch gets a QUIRKS entry + pinning test.
- **R3 — Go JSON formatting.** Go's `encoding/json` float formatting (e.g., difficulty values), field ordering, and omitempty rules differ from serde defaults. Golden-capture suites per RPC method + a controlled response serializer; document any byte-level deltas proven irrelevant to real clients (dcrctl/dcrwallet/Decrediton are the arbiters).
- **R4 — Ed25519 & signature-parsing edge cases.** Historic verifier differences (canonicality, malleability, lax DER) are exactly where reimplementations fork chains. Differential fuzz all three signature types to high volume before the chain engine consumes them.
- **R5 — Lottery/PRNG exactness.** `Hash256PRNG` winner selection must match bit-for-bit at every height; a single off-by-one invalidates vote validation. Full-history winner comparison is part of the Phase 8 comparator.
- **R6 — DoS-behavior mismatch.** Divergent limits/ban logic lets attackers partition dcroxide from dcrd peers. Port limits verbatim; adversarial interop suite in Phase 11.
- **R7 — Moving upstream target.** 2.2 (and future consensus agendas) will land mid-project. Mitigation: D5 process, pinned-tag parity claims, agenda-aware design (threshold state machine is data-driven from chaincfg).
- **R8 — Team/bus factor & review scarcity.** Consensus-grade Rust reviewers are rare. Two-reviewer rule on consensus crates, early engagement with Decred developers (they are receptive to alternative implementations; the mixing and blockchain modules were designed for reuse), and the external review in Phase 15.
- **R9 — Underestimation.** dcrd is 168k LOC of battle-hardened Go with a decade of edge cases. The milestone structure below is designed so partial completion still yields shippable value (libraries → tools → archival node → full node), and progress is measured by acceptance suites, not vibes.

---

## 11. Milestones

| Milestone | Contents (phases) | Demo / acceptance |
|---|---|---|
| **M0 — Rig** | P0 | CI + oracle + fuzz infra live; differential demo test |
| **M1 — Decred-in-Rust libraries** | P1–P6 | Crate suite (crypto, wire, chaincfg, txscript, stake, standalone) with vector+differential parity — independently useful to the whole Rust/Decred ecosystem |
| **M2 — Validating archive node** | P7–P9 | dcroxide fully syncs & validates mainnet from a dcrd peer; per-block comparator zero-divergence; filters/indexes parity |
| **M3 — Full relay node** | P10–P12 | Participates in mainnet/testnet p2p incl. tx/block relay and mixing message relay; mixed-fleet soak; wallet mixes complete via dcroxide |
| **M4 — Drop-in daemon** | P13–P14 | `dcrctl`/`dcrwallet`/Decrediton sweeps pass unmodified; config/IPC/service parity on 3 OSes; the Go dcrdtest harness runs green against the dcroxide binary |
| **M5 — Hardened 1.0** | P15 | External review resolved; perf parity-or-better documented; multi-week mainnet differential soak clean; reproducible signed release |

**Where these stand:** the implementation behind M0–M4 is in the tree and M5 is
underway; the status block near the top records what Phase 15 has covered. The
demo/acceptance column is the honest measure and it is not fully satisfied —
M2's per-block comparator, M3's mixed-fleet soak and live wallet mixes, and all
four of M4's ecosystem sweeps have not been run. Read the acceptance column, not
the phase list, when judging readiness.

Sizing guidance (not a promise): M1 and M2 are each on the order of several engineer-months for a strong systems-Rust developer already fluent in Bitcoin-family internals; P4 and P8 dominate. Calendar estimates should be produced by the developer after Phase 0/1, when the oracle rig gives real porting-velocity data.

---

## 12. Working agreements — definition of done for every task

A task/PR is done when: (1) implementation matches the pinned dcrd tag with any quirk documented; (2) dcrd's corresponding tests are ported or regenerated and passing; (3) new parsers/state machines have fuzz + property targets wired into CI; (4) consensus-tagged code has differential coverage and two approving reviews; (5) `PARITY.md` and (if applicable) `QUIRKS.md`/ADRs are updated; (6) public items are documented (`#![deny(missing_docs)]` on library crates); (7) benchmarks exist for hot paths with thresholds recorded.

Suggested first sprint for the developer: Phase 0 rig + D1–D4 ADR drafts + vendor dcr-rs with regenerated vectors + the wire `MsgTx`/header codecs under differential fuzz. That sequence produces immediate, measurable parity signal and forces the big decisions while they're still cheap.

---

*Reference links: [decred/dcrd](https://github.com/decred/dcrd) · [jzbz/dcr-rs](https://github.com/jzbz/dcr-rs) · RPC spec: `docs/json_rpc_api.mediawiki` in the dcrd repo · Consensus change proposals (DCPs): [github.com/decred/dcps](https://github.com/decred/dcps) · Simnet guide: `docs/simnet_environment.mediawiki` · Integration harness: [decred/dcrtest](https://github.com/decred/dcrtest)*
