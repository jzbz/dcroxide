# dcroxide — Developer Brief & Project Plan

**A full Rust re-implementation of the Decred full-node daemon (`dcrd`), built as a drop-in replacement.**

Prepared for the implementing developer/team. Parity target: **dcrd `release-v2.1.5`** (latest release, April 2026; upstream master is `2.2.0-pre`). Wire protocol version **12**, JSON-RPC API version **8.3.0**.

---

## 1. Project statement (the short version)

dcroxide is a from-scratch Rust implementation of the Decred full-node daemon. The goal is that an operator can stop `dcrd`, start `dcroxide` with the same command line and the same `dcrd.conf`, and nothing else in the ecosystem notices: peers speak to it identically, `dcrwallet`/Decrediton/`dcrctl` connect over the same TLS JSON-RPC and websocket API, miners get identical work, and — above all — it accepts and rejects exactly the same blocks and transactions as dcrd, byte for byte, on mainnet, testnet3, simnet, and regnet.

Scope is the complete daemon feature set of dcrd v2.1.5:

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

## 2. Source material, scale, and honest sizing

| Item | Fact |
|---|---|
| Reference implementation | [decred/dcrd](https://github.com/decred/dcrd), Go, ISC license, in production since Feb 2016, ~7,300 commits |
| Parity target | `release-v2.1.5` tag (Apr 2026). Track upstream releases thereafter (master is 2.2.0-pre — expect a moving target) |
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

**C1 — Consensus (absolute, bug-for-bug).** For every block and transaction ever seen or seeable on any Decred network, dcroxide's accept/reject verdict, resulting chain state (best tip, UTXO set, live-ticket set, treasury balance, agenda threshold states), and all consensus-derived values (subsidies, difficulty, lottery winners, sequence locks) must equal dcrd's exactly. Where dcrd's behavior deviates from written specification, **dcrd's behavior wins** and the deviation is recorded in `docs/QUIRKS.md` with a test pinning it.

**C2 — P2P wire protocol (version 12).** Message framing, per-network magic bytes, version negotiation and services, all message types including the eight mixing messages, inventory/relay semantics, protocol-version gating of features (mixing ≥10, batched cfilters ≥11), misbehavior/ban scoring, and connection policies — such that mixed fleets of dcrd and dcroxide nodes interoperate indefinitely and neither side bans the other.

**C3 — RPC API (JSON-RPC 8.3.0).** All 77 HTTP methods and 17 websocket methods, byte-compatible JSON encoding (field names, field order, presence/omission rules, number formatting — see the Go-float risk in §10), identical error codes/messages, identical help text (`help`), TLS with self-signed cert auto-generation, HTTP Basic auth with full and limited (`rpclimituser`) privilege tiers, and the websocket notification system (`notifyblocks`, `notifywork`, `notifynewtransactions`, `notifywinningtickets`, `notifytspend`, `loadtxfilter`/`rescan`, etc.). Acceptance oracle: `dcrctl`, `dcrwallet` (RPC mode), and Decrediton must work unmodified.

**C4 — CLI, config, lifecycle.** Every dcrd flag and `dcrd.conf` option with identical names, defaults, precedence (CLI > config file > defaults), and validation errors; identical default data-dir/log-dir resolution per OS and per network; exit codes; POSIX signals; the Windows service wrapper; and the pipe-based IPC protocol (`--piperx`/`--pipetx` lifecycle events) that Decrediton uses to supervise the daemon.

**C5 — Operational artifacts.** `rpc.cert`/`rpc.key` generation compatible with what dcrwallet/dcrctl expect, log file naming/rotation, pprof-style profiling endpoints (`--profile`) with a documented Rust-appropriate equivalent where Go-runtime-specific outputs cannot be replicated, UPnP, proxy/Tor (SOCKS5, onion) support, and `--altdnsnames`.

**C6 — On-disk data directory (decision required, see §9).** dcrd stores blocks in flat `.fdb` files with goleveldb metadata (`ffldb`), plus a dedicated UTXO backend and index databases. Reading an existing dcrd datadir in place is a *stretch goal*; the default plan is fresh sync (plus an `addblock`-style bulk importer that can ingest dcrd's exported block files to accelerate it). Do not let C6 hold earlier milestones hostage.

---

## 4. Engineering principles

1. **dcrd is the specification.** Written docs (DCPs, `docs/`) are secondary. When in doubt, read dcrd source at the pinned tag and reproduce it — including quirks. Every intentional quirk reproduction gets an entry in `QUIRKS.md` and a pinning test.
2. **Oracle-driven development.** Every consensus-relevant module ships with (a) test vectors extracted from dcrd's own tests or generated by small Go shim programs we write against dcrd packages, and (b) where feasible, a differential fuzz target comparing dcroxide to dcrd live. The dcrd clone plus our `tools/oracle/` Go shims are first-class parts of this repo.
3. **No hand-rolled cryptography for standard algorithms.** secp256k1 arithmetic, SHA-2 family, RIPEMD-160, Ed25519 field math, and BLAKE3 come from audited/widely-used crates. We own only Decred-specific constructions: BLAKE-256 (vendored, KAT-pinned), EC-Schnorr-DCRv0 (composed on top of a vetted arithmetic backend), the sighash, and the mixing DC-net math (ported with vectors).
4. **Memory safety as a feature.** `#![forbid(unsafe_code)]` in all dcroxide crates; `unsafe` allowed only inside vetted third-party dependencies, tracked via `cargo-deny`/`cargo-vet`/`cargo-audit` in CI. This is a headline advantage of the project — protect it.
5. **Consensus code is boring code.** No cleverness in validation paths: explicit integer widths, checked arithmetic mirroring dcrd's `checkedmath`, no floating point anywhere near consensus, deterministic iteration orders, and exhaustive error enums mapped 1:1 to dcrd's error kinds (RPC and reject messages leak error identity — parity matters).
6. **DoS posture parity.** dcrd's limits (message sizes, orphan pools, ban scores, per-peer rate limits, mixpool limits, APBF sizing) are consensus-adjacent: divergence lets an attacker partition mixed networks. Port limits verbatim; test them.
7. **Pin, then track.** All parity claims reference the `release-v2.1.5` tag. A standing "upstream watch" task reviews every dcrd release/merged consensus PR and files parity issues. A `PARITY.md` ledger maps each dcrd package to its dcroxide crate and status.

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
- **Exit:** v1.0 criteria = all C1–C5 acceptance suites green at the pinned tag, multi-week mainnet soak with zero divergence, review findings resolved.

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

---

## 9. Decisions the developer must surface in the first two weeks

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
- **R2 — "Spec vs. dcrd" traps.** DCP documents and even dcrd docs can lag code. Rule: code at the pinned tag is truth; every discovered mismatch gets a QUIRKS entry + pinning test.
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

Sizing guidance (not a promise): M1 and M2 are each on the order of several engineer-months for a strong systems-Rust developer already fluent in Bitcoin-family internals; P4 and P8 dominate. Calendar estimates should be produced by the developer after Phase 0/1, when the oracle rig gives real porting-velocity data.

---

## 12. Working agreements — definition of done for every task

A task/PR is done when: (1) implementation matches the pinned dcrd tag with any quirk documented; (2) dcrd's corresponding tests are ported or regenerated and passing; (3) new parsers/state machines have fuzz + property targets wired into CI; (4) consensus-tagged code has differential coverage and two approving reviews; (5) `PARITY.md` and (if applicable) `QUIRKS.md`/ADRs are updated; (6) public items are documented (`#![deny(missing_docs)]` on library crates); (7) benchmarks exist for hot paths with thresholds recorded.

Suggested first sprint for the developer: Phase 0 rig + D1–D4 ADR drafts + vendor dcr-rs with regenerated vectors + the wire `MsgTx`/header codecs under differential fuzz. That sequence produces immediate, measurable parity signal and forces the big decisions while they're still cheap.

---

*Reference links: [decred/dcrd](https://github.com/decred/dcrd) · [jzbz/dcr-rs](https://github.com/jzbz/dcr-rs) · RPC spec: `docs/json_rpc_api.mediawiki` in the dcrd repo · Consensus change proposals (DCPs): [github.com/decred/dcps](https://github.com/decred/dcps) · Simnet guide: `docs/simnet_environment.mediawiki` · Integration harness: [decred/dcrtest](https://github.com/decred/dcrtest)*
