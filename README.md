# dcroxide

A from-scratch Rust implementation of the Decred full-node daemon, built as a
drop-in replacement for [dcrd](https://github.com/decred/dcrd).

Parity target: **dcrd master `382ff4dd`** (version 2.2.0-pre) — wire protocol
12, JSON-RPC API 8.3.0. dcrd's behavior at that commit is the specification; see
[QUIRKS.md](QUIRKS.md) for deliberate bug-for-bug reproductions and
[PARITY.md](PARITY.md) for per-package status. The full plan lives in
[dcroxide-project-brief.md](dcroxide-project-brief.md).

**Status: pre-alpha — the dcrd surface is ported end to end.** Every
dcrd package has a Rust counterpart and the threaded daemon assembles
them all: config, chain engine with full consensus validation, mempool,
mining and CPU miner, P2P server with sync, relay, and mixing, the
JSON-RPC/websocket server, the tool commands, the pipe IPC lifecycle,
and the Windows service wrapper. The deliberate non-ports are small
and documented in PARITY.md (Go GC tuning, the pprof servers, UPnP,
the Windows event log, and the wallet-side mixclient). The test suite
runs 2,536 tests across 444 suites on Linux, most differential against
dcrd itself or replaying sessions generated inside dcrd's own packages.

Since the surface completed, four rounds of work have landed on it. A
performance campaign: ffldb's metadata write cache, block scripts
validated on dcrd's worker pool, a ported `SigCache`, one transaction
hash per block, batched UTXO reads, and a layered dbCache overlay. A
security campaign closing the blockers an audit found in the RPC and
peer surfaces: authentication and admission control, bounded peer
message paths with stall deadlines and queue limits, OS-seeded
CSPRNGs, secret-file handling, and `panic = "abort"` in release
builds. And the rename onto dcroxide's own identity — data directory
`~/.dcroxide`, configuration file `dcroxide.conf`, `DCROXIDE_*`
environment variables. And a line-by-line review against dcrd covering
the whole surface, whose fixes reach consensus code rather than only
the RPC and peer edges: the EMA retarget divided the way Go's
`big.Int.Div` does, vote payment outputs counted in signed arithmetic,
the in-block fraud proof pass run at height 1, and the block index
flushed during header sync instead of accumulating a million entries.

It has synced testnet and mainnet to the tip from genesis, and syncs
against dcrd in both directions (the [bench
ledger](docs/bench-ledger.md), "Daemon against daemon, each from the
other"). A sync at the defaults validates in full only the blocks after
the built-in assume-valid block, as dcrd's does: up to that block both
skip connect validation, script checks included. On 2026-10-10 the
replay harness, `dcroxide-bench` below, drove every mainnet block up to
1,116,035 through the chain engine with full validation, at commit
`337779d`, which has the review fixes above, and did so again on
2026-10-11 on the code with the first five of the six changes the bench
ledger describes for that day. That replay does not exercise the fifth,
the indexes on a thread of their own: a replay updates the indexes
inline, on the thread that connects the blocks.
Together that says the consensus rules of the code that was replayed
accept every mainnet block that dcrd's accepted. No replay has been run
of later code: the sixth change and the eleven commits to the node's
code after it, which the bench ledger describes, have been run in syncs
only, each of which validated in full only the blocks after the
assume-valid block. One of the eleven changes how a `SigHashAll`
signature hash is computed while a block is connected, and the syncs
made with it put that to the 89,438 blocks after the assume-valid block
and to none before it. The eighteen commits to the node's code after the
eleven, several of which change code that applies the consensus rules,
among them where a connected block's scripts are checked, have been put
to blocks only in syncs: `8fc9160`, which holds them, was run in four on
2026-10-16. The commits after it, which port dcrd's changes since
`6f6cf21b`, some of them to the consensus rules, and move the metadata
commit to a thread of its own, were first put to blocks on 2026-10-17,
in syncs of `88c46c3` (Performance), each of which validated in full
only the blocks after the assume-valid block and ended with the UTXO set
that dcrd's syncs of that day ended with. The commits after `fdd7a83`
have been put to blocks only in builds made from a worktree, not from
their trees. All but one were in syncs of 2026-10-18 from a block server
on another machine on the same LAN, each of which validated in full only
the blocks after the assume-valid block and had dcrd's block at height
1,116,035, and in three syncs from the loopback server that ended with
that same UTXO set (the bench ledger, "Rungs from a block server on the
LAN, two changes held for their memory, and dcrd v2.1.7"). The one that
keeps the metadata commit thread for the life of the store, which
changes no consensus rule, was in none of those builds: it has been put
to blocks only in a build that also holds the two changes held that day
for their memory, in syncs of 2026-10-19 from the same two servers (the
bench ledger, "One commit thread for the life of the store, a sync that
checks every script, and dcrd v2.1.7").
That the rules reject what dcrd's reject rests on the test batteries
described below, not on a sync, and none of it says the node is safe to
operate. **Do not expose it to the internet and do not use it with
funds** — see [SECURITY.md](SECURITY.md) for what is known to be missing
and how to report a vulnerability, and
[docs/operating.md](docs/operating.md) for what running it deliberately
requires (a supervisor is mandatory, and a dcrd data directory will not
work). Currently implemented:

- `dcroxide-crypto` — BLAKE-256 (vendored from
  [dcr-rs](https://github.com/jzbz/dcr-rs), KAT-pinned, differential-tested
  against dcrd live), RIPEMD-160 (RustCrypto-backed, KAT-pinned), and —
  behind the non-default `rand` feature, so the rest stays `no_std` —
  dcrd's `crypto/rand` userspace CSPRNG, which the address and
  connection managers both draw from
- `dcroxide-chainhash` — the 32-byte hash type with dcrd's byte-reversed
  string encoding, including its short-string parsing quirk
- `dcroxide-wire` — message framing with dcrd's exact validation order and
  error identities, plus **all 41 P2P message types** at protocol version 12,
  including `addrv2` with its typed `NetAddressV2` (IPv4/IPv6/TorV3) and the
  eight StakeShuffle mixing messages; `MsgTx`, blocks, headers,
  filters, state, and mixing messages all under differential test, fuzzing,
  and round-trip property tests — including the first `QUIRKS.md` entry
  (write-only `reject`)
- `dcroxide-uint256` — fixed-precision 256-bit arithmetic (difficulty/work
  math) ported operation-for-operation from dcrd's `math/uint256`,
  differentially tested against it across every operation
- `dcroxide-dcrec` — all three Decred signature types with dcrd's exact
  acceptance rules and error identities: ECDSA-secp256k1 (type 0, over
  libsecp256k1), Ed25519 (type 1, over curve25519-dalek with dcrd's
  2017-agl verify semantics), and EC-Schnorr-DCRv0 (type 2, over k256 with
  dcrd's RFC6979 nonce variant); every signing path differentially verified
  byte-for-byte against dcrd
- `dcroxide-chaincfg` — all four networks' consensus parameters
  (mainnet/testnet3/simnet/regnet): genesis blocks reproducing dcrd's exact
  hashes and quirks, the full consensus-agenda deployment history, and the
  block-one premine ledgers; the complete parameter set is dumped
  field-by-field and compared byte-for-byte against dcrd's `chaincfg`
  through the oracle
- `dcroxide-txscript` — the version-0 Decred script engine ported from
  dcrd's `txscript`: tokenizer, `ScriptNum`, the full 256-opcode set
  (including the stake and treasury opcodes), the execution engine with all
  flag combinations and P2SH handling, strict-encoding checks, signature
  hashing, and signature checking across all three suites; dcrd's entire
  `script_tests.json`/`tx_valid`/`tx_invalid`/`sighash.json` corpora run
  green, backed by a live differential script fuzzer against dcrd. The
  `stdaddr`, `stdscript`, and `sign` modules add all seven version-0
  address kinds, standard-script classification, and transaction signing
  across every suite and script shape (P2PK/P2PKH, multisig, P2SH, stake
  and treasury outputs), all differentially matched against dcrd across
  every network
- `dcroxide-base58` — modified base58 and Decred base58check from
  decred/base58, vector- and differentially-tested
- `dcroxide-stake` — the stake transaction primitives from dcrd's
  `blockchain/stake`: ticket/vote/revocation/treasury format checks and
  classification with all 72 of dcrd's error kinds, commitment and vote
  extraction, the `Hash256PRNG` ticket lottery, vote/revocation reward
  math (including auto-revocation remainder distribution), and revocation
  construction; dcrd's own test vectors replay oracle-free and the whole
  surface is differentially matched against dcrd; the ticket-database
  state machinery also lives here and is described under
  `dcroxide-blockchain`, which drives it
- `dcroxide-standalone` — dcrd's `blockchain/standalone` consensus
  functions: merkle roots and inclusion proofs, compact-difficulty
  conversions and proof-of-work checks (including the BLAKE3 `PowHashV2`
  from DCP0011, added to `dcroxide-wire`), the ASERT difficulty
  algorithm replaying dcrd's reference vectors, the full subsidy
  schedule across all three split regimes (validated by dcrd's exact
  total-supply figures), treasury spend window math, and context-free
  transaction sanity checks — all additionally differentially matched
  against dcrd
- `dcroxide-database` — block and metadata storage with dcrd's
  `database` interface semantics (buckets, transactions, block storage
  APIs, all error kinds), backed by redb 4.3.0 per ADR-0004 with
  dcrd's ffldb key layout and flat-file block record format, except
  that blocks and the other per-block rows are keyed by height first
  (ADR-0010, chain database version 15), plus
  bulk block import/export in dcrd's `addblock` bootstrap format, plus
  ffldb's metadata write cache — layered snapshots over one durable
  flush per window — so a sync commits on dcrd's schedule rather than
  per block; pinned by the ported ffldb interface-test battery and a
  crash-consistency rig (fresh-sync stance: no in-place dcrd datadir
  reuse, and no in-place upgrade across a redb format change or a
  chain database version either — an older format is refused with a
  typed error naming it, and the chain must be re-synced or
  re-imported)
- `dcroxide-blockchain` — the chain engine from dcrd's
  `internal/blockchain`, ported complete.

  The serialization and consensus-math foundations: dcrd's UTXO
  serialization layer (VLQs, the domain-specific script and amount
  compression, UTXO entries, outpoint keys, and the set state), the
  legacy work and stake difficulty algorithms, the stake-version voting
  machinery, the agenda threshold state machine, the agenda-driven
  algorithm selectors, and the chain persistence formats.

  The validation layers: context-free transaction validation and block
  sanity, the DCP0003 sequence lock calculation, positional and
  contextual header validation, the full transaction input validation
  (tickets, votes, revocations, and treasury spends through the
  fee-computing `CheckTransactionInputs`), and the block sigop and
  stake amount accounting.

  The chain state: the in-memory block index and chain view (skip-list
  ancestors, chain tips, best-chain candidates, invalidation
  propagation, and block locators), plus the immutable ticket treap,
  the ticket database serialization formats, and the full ticket pool
  state machine (connect/disconnect with lottery winners and undo data)
  in `dcroxide-stake` — wired into validation through the header stake
  commitments, the ticket redeemer checks, and the full contextual
  block assembly (`checkBlockContext`).

  Block connection: the utxo viewpoint with block connect/disconnect
  and spend journaling, the fee-accounting
  `checkTransactionsAndConnect` loop, and the full `checkConnectBlock`
  battery (treasury payouts, both tree connects, sequence locks, the
  header commitment filter, and block script execution).

  Block intake: the headers-first processing layer
  (`maybeAcceptBlockHeader` over the real block index with
  assumed-valid tracking and old fork rejection), the stake node
  attachment layer (`fetchStakeNode` with the pruned-node regeneration
  walk and side chain replay), the reorganization engine
  (`connectBlock`/`disconnectBlock` with best state snapshots and
  `reorganizeChain` over dcrd-exact utxo cache semantics), the complete
  `ProcessBlock` intake path (duplicate/orphan/invalid handling,
  headers-first data linking, and best chain selection), and the manual
  chain manipulation surface
  (`InvalidateBlock`/`ReconsiderBlock`/`ForceHeadReorganization`).

  Persistence and the consumer surface: the ticket database persistence
  layer over redb (bucket row values byte-identical to dcrd's ffldb,
  with the two per-height buckets keyed by big-endian height where
  dcrd's keys are little-endian, ADR-0010),
  durable chain state (`createChainState`/`initChainState` with restart
  round trips over the reorganization ground truth), mining support
  (`CheckConnectBlockTemplate`, ticket exhaustion checks, and the chain
  query surface), the treasury account with the complete treasury spend
  checks (balances, vote tallies, and expenditure policies), and the
  RPC/netsync query surface (threshold state queries, vote counting,
  stake version walks, block locators, and the stake difficulty
  estimators).

  Pinned by dcrd's own test vectors, by synthetic-chain scenarios
  generated inside dcrd's internal package, and end to end by dcrd's
  own full block test battery (`fullblocktests`): 577 instances of
  fully signed blocks and invalid variants replayed through the real
  `ProcessBlock` with scripts on, matching every acceptance, rejection
  kind, and expected tip
- `dcroxide-mempool` — the transaction memory pool from dcrd's
  `internal/mempool`: the mempool error kinds, the relay policy layer
  (minimum relay fees, dust outputs, and the transaction, output
  script, and input standardness checks), and the `TxPool` itself with
  the full acceptance gauntlet, orphan processing, ticket staging,
  batch acceptance, pruning, and the vote, revocation, and treasury
  spend acceptance paths — pinned by dcrd's own policy verdicts and
  scripted pool sessions generated with dcrd's own test harness
- `dcroxide-fees` — the smart fee estimator from dcrd's
  `internal/fees`: decaying confirmation tracking over exponential
  fee rate buckets and the median fee estimation, replaying dcrd's
  floating point accounting bit for bit
- `dcroxide-mining` — block template mining support from dcrd's
  `internal/mining`: the transaction dependency graph and mining view
  with ancestor statistics tracking, the priority queue with Go's
  exact heap semantics, the priority calculation, the block template
  building blocks (coinbase and treasurybase construction, parent
  vote sorting, and the template roots), the full `NewBlockTemplate`
  assembly replayed byte for byte against dcrd's own harness, wired
  into the mempool's mining hooks, and the background template
  generator's regeneration state machine replayed against dcrd's own
  event handlers
- `dcroxide-gcs` — Golomb-coded set filters (versions 1 and 2) and the
  DCP0005 version 2 block committed filters for light clients, matched
  differentially against dcrd over random filters and structured blocks
  with real stake transactions
- `dcroxide-indexers` — the optional block chain indexes from dcrd's
  `internal/blockchain/indexers`: the transaction index with its
  block-ID compaction, the exists address index with the unconfirmed
  overlay (dcrd's address set in this port's own layout: a memtable, a
  journal and sorted runs, written inside the metadata flush), and the
  subscriber machinery with dependent relay,
  catch-up, recovery, and incremental drops, replayed against a real
  redb-backed database from a session scripted inside dcrd's own
  package
- `dcroxide-containers` — the container data structures from dcrd's
  `container` packages: the age-partitioned bloom filter used for
  P2P relay deduplication and the generic LRU map and set with
  optional time-based expiration, replayed bit for bit from sessions
  scripted inside dcrd's own packages with injected hash keys and a
  mock clock
- `dcroxide-addrmgr` — the peer address manager from dcrd's
  `addrmgr`: address keys and network groups with dcrd's exact
  formatting, RFC-range routability and reachability, the new/tried
  bucket machinery over BLAKE-256 derivations with viability
  tracking, dcrd-compatible `peers.json` persistence, and the HTTPS
  seeder and Tor SOCKS DNS resolution dcrd 2.2 moved into this
  package, pinned by grids and state transitions scripted inside
  dcrd's own package with the randomized paths covered under an
  injected RNG, plus scripted proxy exchanges and seeder parse
  batteries
- `dcroxide-dcrjson` — the JSON-RPC command infrastructure from
  dcrd's `dcrjson/v4` module: Go's reflection-driven registry,
  marshalling, parameter parsing, usage, and help generation made
  explicit over type descriptors, with Go `encoding/json` semantics
  (HTML escaping, float formatting, sorted map keys, exact decode
  error messages) and a `text/tabwriter` port reimplemented so every
  byte of JSON, error text, and help output matches, pinned by a
  scripted session generated inside dcrd's own package
- `dcroxide-rpctypes` — the chain server command, result, and
  notification definitions from dcrd's `rpc/jsonrpc/types` module:
  all 105 registered methods and every struct type as descriptors
  over the dcrjson base, including the custom five-shape Vin
  marshaling, pinned by usage text, zero-value marshals of every
  type, and curated populated round trips generated inside dcrd's
  own package
- `dcroxide-rpc` — RPC server components from dcrd's
  `internal/rpcserver`: the help subsystem (the English help
  description map, the per-method result types, and the caching
  help/usage provider) and the handlers' pure transform layer (the
  RPC error constructors, address/hash/difficulty helpers, getwork
  serialization, and the vin/vout/raw-transaction result builders),
  plus the command handler slices (the stateless, chain-query,
  stake-query, mempool/connection, tx/utxo lookup, peer/address,
  submission/control, fee-info/node-info, mining/network/mix, and
  treasury-vote, getwork, and help commands — all 77 dcrd
  handlers) plus the request dispatch core (parse, route, reply
  marshalling, and the limited-user gate), Basic auth over HMAC'd
  credentials, the single/batched request body processing, and the
  websocket client core (transaction filters, rescans, and the
  websocket command handlers), and the websocket notification
  builders over a Server scaffold
  with the chain, mempool, sync and
  connection managers, indexes, database, filterer, log manager, fee
  estimator, sanity checker, time source, CPU miner, mix pooler,
  profiler and address managers, block templater, and clock behind
  trait seams, pinned by the complete generated help text,
  fully marshalled transaction results, and per-handler
  request/response cases from sessions generated inside dcrd's own
  package
- `dcroxide-netsync` — the network chain synchronization manager
  from dcrd's `internal/netsync`: the sync manager as a synchronous
  decision core returning message/disconnect/timer actions, with
  header-first sync, block download scheduling, announcement
  tracking, and the rejected/recently-confirmed filters, pinned by a
  scripted 87-step session against a real dcrd sync manager, chain,
  peers, and pools, replayed over the real Rust chain engine; beside
  dcrd's block download window it holds the wider one the daemon uses
  by default, which dcrd does not have (PARITY.md, *Block download
  window*)
- `dcroxide-node` — the daemon itself from dcrd's package main, as OS
  threads over channels rather than goroutines: the full configuration
  layer (every option with dcrd's defaults, the go-flags command line,
  INI, and environment semantics with dcrd's exact error strings, and
  the generated help text byte for byte), the server dispatch wiring
  every ported handler over live TCP peers (handshake, sync, relay,
  addr exchange, bans, mixing, and getdata serving with absolute
  per-message read deadlines), the outbound connection driver with
  addrmgr-backed dialing, the SOCKS5/Tor dial path with stream
  isolation, the HTTPS seeder (proxy-routed when configured), the
  JSON-RPC/websocket server over TLS with the shutdown drain and
  request-read watchdog, the mempool/chain/index/fee-estimator
  glue, the background template generator and CPU miner, the pipe
  IPC lifecycle, and the tool binaries (gencerts, addblock,
  promptsecret) — the P2P and RPC decision cores replayed against
  dcrd's real handlers, the runtime pinned by end-to-end socket
  tests; one of its threads has no goroutine in dcrd, the one that
  reads the sync peer's connection ahead of the block handler during
  the initial sync (PARITY.md, *Reading ahead of the block handler*)
- `dcroxide-peer` — the peer-to-peer protocol decision core from
  dcrd's `peer` package: version negotiation with self-connection
  detection and dcrd's exact acceptance rules, local version
  construction including proxy address hiding, the push builders
  with duplicate filters, ping/pong state, known-inventory
  tracking, and the stall deadline table, pinned by negotiations
  against dcrd's own package over real piped connections byte for
  byte
- `dcroxide-certgen` — self-signed TLS certificate generation from
  dcrd's `certgen` over an exact DER writer for Go's certificate
  shape: Ed25519 pairs pin byte for byte and ECDSA pairs pin their
  to-be-signed bytes and keys, from a scripted session mirroring
  dcrd's template construction
- `dcroxide-ratelimit` — dcrd 2.2's `internal/ratelimit` token bucket:
  a bucket seeded with `burst` tokens refilling at a fixed rate,
  reproducing dcrd's `f64` operations in dcrd's order — including
  `time.Duration.Seconds()`'s whole-second/nanosecond split — so the
  token counts drift bit for bit with dcrd's, with Go's zero
  `time.Time` refill saturation carried by an explicit sentinel and
  Go's platform-defined `uint64(float64)` conversion pinned to the
  oracle platform; pinned by differential vectors including the cases
  where accumulated rounding error denies an event the documented
  average rate would allow
- `dcroxide-connmgr` — connection management from dcrd 2.2's
  `internal/connmgr`: the dynamic ban score over a bit-exact port of
  Go's portable `math.Exp`, and the rewritten connection manager as a
  synchronous state machine with injectable dialers and event-driven
  retries — inbound anti-flood admission over per-network-group token
  buckets with the S-curve drop probability, outbound group spreading,
  per-host permits, and the persistent retry policy with dcrd's
  backoff scaling (including the upstream shift overflow, which the
  wrapping port reproduces); pinned by the full decay domain and by a
  state-machine dump driving dcrd's real `ConnManager` under a stub
  dialer and a scripted CSPRNG. dcrd 2.2 relocated HTTPS seeding and
  Tor DNS resolution into `addrmgr`, and the port follows
- `dcroxide-mixing` — the StakeShuffle mixing support from dcrd's
  `mixing` package: message identity hashes and Schnorr signatures,
  session ID derivation and validation, the DC-net finite field and
  vector math, the per-run ChaCha20 PRNG, UTXO ownership proofs, and
  the mixpool itself with its acceptance rules, orphan handling,
  expiry, and misbehavior observer, replayed bit for bit from
  sessions scripted inside dcrd's own packages including a full
  honest 4-peer mix run and two observer strike rounds
- `dcroxide-winsvc` — dcrd's Windows service wrapper over the
  `windows-service` crate: SCM detection and the service body with
  dcrd's status transitions, and the `--service`
  install/remove/start/stop commands (the option registered only on
  Windows, exactly like dcrd); plus the console control handler that
  holds a console close, logoff or shutdown until the daemon has shut
  down, as Go's runtime does, and the adoption of inherited
  `--piperx`/`--pipetx` pipe handles (dcrd's `os.NewFile`)
- `dcroxide-testutil` — the differential-test harness every crate
  shares (no dcrd counterpart): the line-delimited JSON transport to
  `tools/oracle`, the toolchain gate (a missing Go toolchain skips the
  test, or fails it when `DCROXIDE_REQUIRE_ORACLE` is set), a
  deterministic SplitMix64 PRNG that prints its seed so a failure
  reproduces, and hex helpers; a dev-dependency only, never published
- `dcroxide-bench` — the block replay harness (no dcrd counterpart):
  `export` writes the main chain of a stopped data directory to a
  bootstrap-format corpus, and `replay` drives that corpus back
  through the live chain engine with full validation of every block,
  where a network sync skips connect validation up to the
  assume-valid block — reporting throughput at a fixed block
  interval, so an optimization is measured on the same blocks before
  and after
- `tools/oracle` — Go shim linking dcrd's own packages (pinned to the
  parity target, master `382ff4dd`: each dcrd module at that commit's
  pseudo-version or at a tag whose source is byte-identical to it, as the
  header of `tools/oracle/go.mod` records) as a test oracle over
  line-delimited JSON
- `tools/helpgen` — the go-flags help-vector generator over dcrd's
  verbatim config struct
- `tools/dcrdstat` — sums the payload dcrd actually stores, per ffldb
  bucket, so a density comparison against dcroxide rests on both sides'
  measured bytes rather than on file sizes alone
- `tools/pinbump` — given two dcrd commits, resolves the upstream files
  they touch to the dcroxide crates that port them, via PARITY.md's own
  table, so moving the parity pin starts from a review list rather than
  a whole-diff read
- `tools/dsample` — the per-thread scheduler-state sampler behind the
  bench ledger's stall measurements (Python)
- `tools/powerloss` — an `LD_PRELOAD` shim over the write path plus a
  replay driver, so crash consistency is tested the same way against
  any storage engine (C + Python)
- `tools/mixpoolgen` — the generator of `mixpool_vectors.txt`, run as a
  test inside a dcrd checkout's `mixing/mixpool` package through
  `go test -overlay` with the pool's clock frozen, writing nothing into
  the checkout (Go + sh)
- `tools/mempoolvectors` — the exporter of the mempool vector files, an
  overlay run inside dcrd's `internal/mempool` (Go, not a module)
- `tools/utxoviewgen` — recomputes `tests/utxoview_vectors.rs`'s utxo
  viewpoint states inside dcrd's own `internal/blockchain` package, from
  the base view and blocks the vector file holds (Go sources overlaid on
  a dcrd checkout by `run.sh`)
- `tools/chainopsgen` — regenerates the vector files of
  `tests/processblock_vectors.rs`, `tests/invalidate_vectors.rs` and
  `tests/reorg_vectors.rs` inside dcrd's own `internal/blockchain`
  package: it gives every input of the files' blocks the fraud proof of
  the output it spends and recomputes every expectation, from the seeds,
  blocks and operations the files hold (Go sources overlaid on a dcrd
  checkout by `run.sh`)
- `tools/disapprovalgen` — runs dcrd's disapproval scenarios inside
  dcrd's own `internal/blockchain` package and dumps the chains
  `tests/disapproval_vectors.rs` replays (Go sources overlaid on a dcrd
  checkout by `run.sh`)

## Performance

On 2026-10-17 `88c46c3`, the head of master when the syncs ran, synced
mainnet from genesis to block 1,116,035 in a median of **6.6 minutes**
over four runs at the defaults, where dcrd v2.1.7 took **49.1 and 48.8
minutes** in two runs of the same session: dcroxide was **7.43x and
7.39x as fast**. With the exists-address index, which both daemons
build by default, turned off in both, it was 3.83x, against one dcrd
run. A figure for four runs is their median, and for one or two each
run's value:

| daemon | setting | runs | wall time | rate | node CPU time | written by the node | peak memory to the tip |
|---|---|---:|---|---|---|---|---|
| dcroxide `88c46c3` | defaults | 4 | **396.25 s** (395.3–397.8 s) | 2,816.5 blk/s | 1,046.6 s | 39.7 GB | 3,496.5 MiB |
| dcrd v2.1.7 | defaults | 2 | **2,944.4 s, 2,926.4 s** | 379.0, 381.4 blk/s | 5,608.1 s, 5,614.0 s | 299.9 GB, 302.3 GB | 1,837 MiB, 1,835 MiB |
| dcroxide `88c46c3` | `--noexistsaddrindex` | 2 | 343.9 s, 344.0 s | 3,245.2, 3,244.3 blk/s | 871.8 s, 870.4 s | 32.2 GB, 32.1 GB | 2,202 MiB, 2,203 MiB |
| dcrd v2.1.7 | `--noexistsaddrindex` | 1 | 1,317.2 s | 847.3 blk/s | 2,757.7 s | 129.9 GB | 1,838 MiB |

At the defaults dcrd used 5.36x dcroxide's CPU time and passed 7.55x and
7.61x its bytes to write calls; dcroxide's peak memory was 1.90x and
1.91x dcrd's (dcrd keeps a soft limit of 1.80 GiB). The index costs
dcroxide 52.3 s, 13.2% of its sync, and dcrd 1,627.2 s and 1,609.2 s,
55.3% and 55.0%, so the difference in what it costs is 61.8% and 61.5%
of the gap between the daemons. Two later default runs took 391.1 s and
395.8 s. Every full sync of the session, dcrd's included (eighteen, the
ledger lists them), ended with the same block files and UTXO set
(`gettxoutsetinfo`: 1,850,903 outputs, serialized hash `eb7f88de…`); the
rest of the metadata store was not compared. In the quiet runs of
2026-10-09 to 2026-10-13 dcrd v2.1.6 took 2,848.8 to 2,920.3 s, under
other conditions; why dcrd ran slower here is not established.

**How it was measured.** The runs were on m3 in the [bench
ledger](docs/bench-ledger.md), a 16-core desktop with one encrypted NVMe
drive under btrfs, with transparent huge pages at `madvise` where
2026-10-16 ran at `always`, so figures from other sessions are not like
for like. The node synced over loopback from a dcrd v2.1.6 server pinned
to other cores, whose data stayed in the page cache. The runs went one
at a time, interleaved (the ledger has the order), each after a `sync`,
300 s idle and a quiet check (the first of the two later default runs
had the check alone); none was marked disturbed, and dcroxide's flush
log was on in all, at a cost not measured. The clock runs from the
node's start to the first once-a-second `getblockcount` poll at
1,116,035 and leaves out the harness's `gettxoutsetinfo` call after it:
2.8–4.0 s for dcroxide, a 1.7–2.7 s flush included, and 1.3–1.4 s for
dcrd. CPU time is the node process's, without the kernel threads that
encrypt and write back its bytes; "written" is bytes passed to write
calls, in GB of 10^9; peak memory is `VmHWM` when the clock stops, and
through that call and the shutdown the four default runs of dcroxide
reached 3,764–4,052 MiB.

**The background commit.** Since `02b802c` most metadata commits run on
a thread of their own ([PARITY.md](PARITY.md), *Where a cache flush's
commit runs*). Two runs with `DCROXIDE_DB_SYNC_COMMIT=1`, which puts
every commit back on the committing thread, took 430.4 s and 428.0 s:
the default is 32.95 s or 7.7% less by the medians, and every default
run was faster than both, for 32.3 s and 33.7 s more CPU time and 205.5
and 254.5 MiB more peak memory to the tip, on m3's storage only
([docs/operating.md](docs/operating.md) says when to set the variable).

Both daemons skip connect validation, script checks included, up to the
assume-valid block, 1,026,597, and validate in full after it, where the
lead grows most. Time to each height, interpolated between 10 s samples:

| block | dcroxide `88c46c3`, median of four | dcrd v2.1.7, each run | dcrd / dcroxide |
|---:|---:|---:|---:|
| 250,000 | 50.8 s | 211.1 s, 212.7 s | 4.16x, 4.19x |
| 500,000 | 105.1 s | 507.7 s, 512.1 s | 4.83x, 4.87x |
| 750,000 | 195.5 s | 1,101.4 s, 1,111.5 s | 5.63x, 5.69x |
| 1,000,000 | 301.0 s | 1,966.6 s, 1,946.6 s | 6.53x, 6.47x |
| 1,026,597 (assume-valid) | 314.6 s | 2,077.4 s, 2,057.1 s | 6.60x, 6.54x |
| 1,116,035 | 396.25 s | 2,944.4 s, 2,926.4 s | 7.43x, 7.39x |
| the 89,438 blocks after 1,026,597 | 81.6 s (1,096 blk/s) | 867.0 s, 869.3 s (103.2, 102.9 blk/s) | 10.62x, 10.65x |

What these figures do not cover:

- **A link with a round trip.** Every sync above was over loopback.
  dcroxide's download window, up to 128 blocks where dcrd keeps 16
  ([PARITY.md](PARITY.md), *Block download window*), has been run over a
  link with a longer round trip than a LAN's only in short runs on
  2026-10-12, through a relay that delays every chunk and on the public
  network (the ledger, "Eleven changes, a background commit not kept and
  a pool gate"), and in no whole sync. The only whole syncs over a real
  link, on 2026-10-18 and 2026-10-19, took their blocks from a node on
  another machine on the same LAN (the ledger, "Rungs from a block
  server on the LAN, two changes held for their memory, and dcrd v2.1.7"
  and "One commit thread for the life of the store, a sync that checks
  every script, and dcrd v2.1.7"), a series of its own.
- **The read-ahead's gain as committed.** Its one comparison with
  `DCROXIDE_READ_AHEAD=off`, on 2026-10-12, was of a build before its
  review's fixes ([PARITY.md](PARITY.md), *Reading ahead of the block
  handler*). Over loopback the block thread waited 0.84–0.86 s in all
  for the reader, which a round trip need not allow.
- **Other machines.** Every figure above is of m3 (the ledger has older
  runs on m2), and no sync has been timed on Windows or macOS.

The [bench ledger](docs/bench-ledger.md) has every run of 2026-10-17
("`88c46c3`, the background commit as committed, dcrd v2.1.7 and two
preloaded allocators"), the earlier measurements, and this section's
text until then ("README Performance text retired on 2026-10-17"). After
shutdown the data directory was a median of 27.93 GiB under dcroxide
against 24.16 and 24.18 GiB under dcrd, 17.88 GiB of it block files in
each ([ADR-0004](docs/adr/0004-storage-backend.md) and
[ADR-0009](docs/adr/0009-storage-shape.md) have the storage analysis).

## Layout

- `crates/` — the Cargo workspace: one crate per dcrd package (see
  PARITY.md), plus the shared test harness and the replay bench
- `tools/oracle/` — the dcrd differential-test oracle (Go)
- `tools/helpgen/` — the go-flags help-vector generator (Go)
- `tools/pinbump/` — the parity-pin bump review-list generator (Go)
- `tools/dcrdstat/` — dcrd payload measurement over ffldb + utxodb (Go)
- `tools/dsample/` — per-thread scheduler-state sampler (Python)
- `tools/powerloss/` — write-interception shim and replay driver for
  engine-independent crash-consistency testing (C + Python)
- `tools/mixpoolgen/` — the mixpool vector generator, an overlay test for
  dcrd's `mixing/mixpool` (Go + sh)
- `tools/mempoolvectors/` — the mempool vector exporter, an overlay for
  dcrd's `internal/mempool` (Go)
- `tools/utxoviewgen/` — the utxo viewpoint vector generator (Go, overlay
  sources)
- `tools/chainopsgen/` — the block processing, invalidation and
  reorganization vector generator (Go, overlay sources)
- `tools/disapprovalgen/` — the disapproval scenario vector generator
  (Go, overlay sources)
- `fuzz/` — `cargo-fuzz` targets (nightly toolchain)
- `docs/adr/` — architecture decision records

## Development

Rust 1.98.1 and a Go toolchain (for the oracle-backed differential
tests; without Go those tests skip). `DCROXIDE_REQUIRE_ORACLE=1` turns a
missing toolchain into a failure instead, so a run cannot silently pass
with the differential coverage skipped — CI sets it.

Every randomized differential prints the seed it drew
(`<label>: seed 0x…`). To replay a failure without editing the test, set
`DCROXIDE_TEST_SEED` to that value and run the failing test by name.
`DCROXIDE_REQUIRE_FAULT_INJECTION=1` does for the Linux fault-injection
tests (the database ENOSPC test, the `tools/powerloss` shim test and the
exists-address index's power-cut test, which runs the daemon under that
shim) what `DCROXIDE_REQUIRE_ORACLE` does for the oracle: a missing
prerequisite fails the test instead of skipping it. CI sets it too.

`rust-toolchain.toml` pins the toolchain builds actually use, so a commit
compiles with one rustc everywhere, and the workspace `rust-version` names
the same release, so there is no older floor to check separately. Commands
needing another toolchain say so explicitly (`cargo +nightly fuzz ...`).

```sh
cargo test --workspace          # unit + KAT + differential tests
DCROXIDE_REQUIRE_ORACLE=1 cargo test --workspace   # oracle mandatory
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo +nightly fuzz list                       # requires cargo-fuzz
cargo +nightly fuzz run wire_msgtx_decode
cargo build --profile dist      # release artifacts
```

`dist` inherits `release` and strips debug info. `release` itself sets
`panic = "abort"`; dev and test builds keep unwinding.

The workspace forbids `unsafe_code` and denies `missing_docs`
everywhere, with one audited exception: `dcroxide-winsvc` denies rather
than forbids unsafe code. The `windows-service` entry macro expands an
FFI shim into it, and it calls Windows directly for the console control
handler and for adopting inherited `--piperx`/`--pipetx` handles, which
std does not wrap. Each of those unsafe blocks is Windows-only, allowed
individually, and carries a `SAFETY` comment; the crate documentation
lists them.

## License

ISC. Portions derived from dcrd and dcr-rs, both ISC; see [LICENSE](LICENSE)
and per-file attribution headers.
