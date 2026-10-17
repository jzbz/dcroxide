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
runs 2,368 tests across 437 suites on Linux, most differential against
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
against dcrd in both directions (see [Performance](#performance)). A
sync at the defaults validates in full only the blocks after the
built-in assume-valid block, as dcrd's does: up to that block both skip
connect validation, script checks included. On 2026-10-10 the replay
harness, `dcroxide-bench` below, drove every mainnet block up to
1,116,035 through the chain engine with full validation, at commit
`337779d`, which has the review fixes above, and did so again on
2026-10-11 on the code with the first five of the six changes described under
Performance. That replay does not exercise the fifth, the indexes on a
thread of their own: a replay updates the indexes inline, on the thread
that connects the blocks.
Together that says the consensus rules of the code that was replayed
accept every mainnet block that dcrd's accepted. No replay has been run
of later code: the sixth change and the eleven commits to the node's
code after it, which Performance describes, have been run in syncs
only, each of which validated in full only the blocks after the
assume-valid block. One of the eleven changes how a `SigHashAll`
signature hash is computed while a block is connected, and the syncs
made with it put that to the 89,438 blocks after the assume-valid block
and to none before it. The eighteen commits to the node's code after the
eleven, several of which change code that applies the consensus rules,
among them where a connected block's scripts are checked, have been put
to blocks only in syncs, and only in builds that are not the code as it
stands, which has been run in none (Performance). That the rules reject
what dcrd's reject rests on the test batteries described below, not on a
sync, and none of it says the node is safe to operate. **Do not expose
it to the internet and do not use it with funds** — see
[SECURITY.md](SECURITY.md) for what is known to be missing and how to
report a vulnerability, and [docs/operating.md](docs/operating.md) for
what running it deliberately requires (a supervisor is mandatory, and a
dcrd data directory will not work). Currently implemented:

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

The figures here are of two kinds. The last complete comparison set out
on this page, with three runs of dcroxide, a run with the exists-address
index off and dcrd in the same session, is of dcroxide `b4a5d2d` on
2026-10-11: a median of 12.1 minutes against dcrd's 48.1, 3.96x. Eleven
commits that change the node's code followed it. Their steps were
measured on 2026-10-12 in one or two syncs each, dcrd was not run that
day, and the last step was measured in a build that is not the code as
committed. They come first. Eighteen more commits that change the
node's code have followed those eleven, and the code as it stands has
not been run in a sync. A session of the same kind was run on
2026-10-13 with `4700cf1`, the first of the eighteen, beside builds
that held the changes of the other seventeen in parts, none of the
builds run holding them all. The [bench ledger](docs/bench-ledger.md)
has that session, and this page sets out no figure from it. From *The
last complete comparison* on, every table, and every measurement of
dcroxide not dated 2026-10-12, is of `b4a5d2d` or of the code before
it. Every sync time on this page is from one machine, over loopback,
into a fresh data directory.

**Eleven commits to the node's code since `b4a5d2d`, measured a step at
a time on 2026-10-12.** Each run was a sync of mainnet from genesis to
block 1,116,035 from a dcrd v2.1.6 server, at the defaults but for the
one setting named below, on a quiet machine, with the machine, the
harness and the pinning of the comparison further down. Each ended on
the server's tip, and the harness marked none as disturbed. One run of
the code of each commit that was run:

| dcroxide | what it adds to the row above | wall time, one run | node CPU time |
|---|---|---:|---:|
| `b4a5d2d` | (the code of the complete comparison) | 12.1 min (728.5 s) | 1,458 s |
| `a83f9a1` | four small changes | 11.2 min (673.8 s) | 1,401 s |
| `6271436` | three on the exists-address index and the ticket database | 10.5 min (628.0 s) | 1,394 s |
| `3a367e5` | the `SigHashAll` prefix hash taken from the block's transaction hashes | 10.1 min (607.7 s) | 1,152 s |
| `540b203` | the block download window | 10.2 min (612.4 s) | 1,160 s |

The first three steps are 54.7 s (7.5%), 45.8 s (6.8%) and 20.3 s
(3.2%) less than the run before them. The window's run is 4.7 s (0.8%)
more than the one before it, and one run each does not settle whether
the window costs anything over loopback; what it is for is a link with
a round trip, under *What these figures do not say*. Every step is one
run against one run. For scale, the three runs of `b4a5d2d` on
2026-10-11 spanned 3.5 s.

The last two commits were measured in one binary, run four times in
the order off, on, off, on, with other runs between the two pairs.
With `DCROXIDE_READ_AHEAD=off`, which leaves the block hand-off of
`5cf9e04` and reads every connection as dcrd does, a sync took 597.6 s
and 599.0 s. With the read-ahead of `b4ceb1c` on, which is the default,
it took 494.6 s and 490.8 s, 8.2 minutes: 103.0 s and 108.2 s less,
17.2% and 18.1%. **That binary is the build made before the review of
the read-ahead and its fixes. Those four runs are of no commit.**
`b4ceb1c` as committed was run in syncs on 2026-10-13, inside `4700cf1`
and only with the read-ahead on (the [bench
ledger](docs/bench-ledger.md) has those runs), so its gain as committed
has not been measured. The hand-off was not measured alone: the 14.8 s
and 13.4 s between the window's run and the two with the read-ahead off
are not attributed.

What the eleven are, in the order they were made:

- **Four small changes, measured together: 673.8 s against 728.5 s.**
  - `7f99184` — the best state holds its missed tickets as a handle on
    the tip stake node's treap, where every connect walked that whole
    treap to fill a list that only the mining template reads.
  - `a65d647` — the keys of the UTXO view and of the UTXO cache are
    compared inline, where each key a search visited cost a call to the
    C library's `memcmp`, and a view is committed to the cache in one
    pass.
  - `7c6ec9a` — a block record is written with one positioned write,
    where it took a seek and four writes; dcrd makes the four
    (`database/ffldb/blockio.go:466-489`). The node made 5.86 million
    write calls in the sync with it and 9.15 million in the one before.
  - `a83f9a1` — the waits for the database's writer are timed and
    reported in the flush log. It is a measurement and changes no
    behaviour: in that sync the threads other than the index thread
    waited 74.9 s for the writer.
- **Three on the exists-address index and the ticket database, measured
  together: 628.0 s against 673.8 s**, with those threads' wait for the
  writer at 30.7 s.
  - `1d5d8a9` — the index computes a connected block's keys before it
    takes the database's writer (the address extraction, the partition
    hashes, a first filter against its memtable, the sort), where it
    computed them inside its write transaction, as dcrd does
    (`internal/blockchain/indexers/existsaddrindex.go:383-444`).
  - `4535d1e` — the index's 21-byte keys are compared inline, as the
    UTXO maps' keys are.
  - `6271436` — a best-node write of the ticket database looks each
    ticket bucket up once, where it looked one up for every ticket, as
    dcrd does (`blockchain/stake/internal/ticketdb/chainio.go:609`,
    `:625`).
- **`3a367e5`, a step past dcrd: 607.7 s against 628.0 s.** While a
  block is connected, a `SigHashAll` signature hash takes its prefix
  hash from the block's transaction hashes, which are already computed,
  where dcrd serializes and hashes the transaction's prefix again for
  every signature. dcrd carries the shortcut in its source and ships it
  switched off, with a warning that it has not been vetted
  (`txscript/opcode.go:27-32`); [PARITY.md](PARITY.md) records it under
  the accepted departures, with its tests. The 89,438 blocks validated
  in full took 121.6 s against 140.3 s, and the node's user CPU time
  was 1,058.0 s against 1,298.6 s.
- **`540b203`, the block download window: 612.4 s against 607.7 s over
  loopback.** During the initial sync the node keeps up to 128 blocks
  requested from its sync peer, within a byte budget, where dcrd keeps
  16 ([PARITY.md](PARITY.md), *Block download window*). Its
  measurements over a delayed link are below.
- **`5cf9e04`, not measured alone.** A block a peer delivers is handed
  to the chain as the allocation its message was decoded into, where
  the chain copied it once as it accepted it; dcrd copies nothing there
  (`internal/blockchain/process.go:571`).
- **`b4ceb1c`, the read-ahead: 494.6 s and 490.8 s against 597.6 s and
  599.0 s, in the build before its review's fixes.** During the initial
  sync a thread of its own reads the sync peer's connection up to four
  messages ahead of the thread that connects blocks, checks each
  checksum, decodes and, for a block, hashes its transactions. dcrd has
  no such thread and holds further reads back on purpose
  (`server.go:1365-1369`). Two of the eighteen later commits to the
  node's code give that thread more to do for each block: since
  `a589c4a` it lays the block out as its block-file record from the
  bytes it arrived in, and since `44cf801` it builds the block's two
  merkle trees. [PARITY.md](PARITY.md), *Reading ahead of the block
  handler*, has the rule and what a peer can see of it, and
  [SECURITY.md](SECURITY.md) what it gives a hostile sync peer.

**dcrd was not run on 2026-10-12, so there is no ratio for the code run
that day from one session.** dcrd's last run before it, on the evening
of 2026-10-11 on the same machine and in the same harness, took
2,883.9 s. Set against it across sessions, the 612.4 s of `540b203`,
the last commit whose code was run that day, is 4.71x, and the two runs
with the read-ahead on are 5.83x and 5.88x, of a build that is not the
committed code. Neither is a figure of the kind the 3.96x below is.
dcrd was run once more on 2026-10-13, in the session of `4700cf1`
above, and that run is in the ledger.

Not measured on 2026-10-12, for any of the eleven: a sync with the
exists-address index off, so what the index cost that code, and how
much of the lead it was, was not known that day (`4700cf1` was run once
with the index off on 2026-10-13, and dcrd was not); a second run of
any step but the last; the four changes of the first batch and the
three of the second one at a time; any other machine or filesystem;
and a whole sync over a delayed or a real link, where the round trip
and not the thread that connects blocks may set the pace. The tables of
the index's cost and of the time to each height below are of `b4a5d2d`
and were not redone. The
[bench ledger](docs/bench-ledger.md) has every run of the day, with
what else was measured then and is not in the repository.

**The last complete comparison set out here is of `b4a5d2d`, on
2026-10-11.** It synced mainnet from genesis to block 1,116,035 in a
median of 12.1 minutes over three runs that day. dcrd release v2.1.6
(go1.25.4) took 48.1 minutes in one run that evening, so
dcroxide was **3.96x as fast** in one session. dcrd's median over four
runs on 2026-10-09 and 2026-10-10, on the same machine and in the same
harness, is 47.7 minutes, and the tables below use it: against it the
figure is 3.93x, across sessions. When the two were first measured
together, at dcroxide `c128a93`, it was 17.6 minutes against 47.7,
**2.71x**. Much of the lead is the exists-address index,
which both daemons build by default: with it off dcroxide took 10.2
minutes in one run on 2026-10-11 and dcrd 20.8 on 2026-10-10, 2.04x
across sessions. In the tables below the syncing daemon took its
blocks from a server run by the other daemon; dcrd's one run of the
evening of 2026-10-11 took them from a dcrd server.

| syncer | source | runs | wall time, median (range) | mean rate | node CPU time | written by the node |
|---|---|---|---|---|---|---|
| dcroxide `b4a5d2d` | dcrd | three, 2026-10-11 | **12.1 min** (728.7 s; 725.9–729.4 s) | 1,532 blk/s | 1,462 s | 39.7 GB |
| dcroxide `c128a93` | dcrd | four, 2026-10-09 and 2026-10-10 | 17.6 min (1,058.6 s; 1,055.8–1,065.0 s) | 1,054 blk/s | 1,821 s | 51.4 GB |
| dcrd v2.1.6 | dcroxide | four, 2026-10-09 and 2026-10-10 | **47.7 min** (2,863.9 s; 2,848.8–2,894.8 s) | 390 blk/s | 5,567 s | 286.3 GB |

Each figure is the median of its runs. The rate is 1,116,035 blocks over
the wall time. CPU time is the node process's own, user plus system.
"Written" is the bytes the process passed to write calls, in GB of 10^9
bytes, not what reached the drive. So at `b4a5d2d` dcroxide took about
a quarter of dcrd's node CPU time and passed about a seventh of its
bytes to write calls. The three runs of `b4a5d2d` span 0.5% of their
median, and every sync timed on this page ended on the server's tip.
Interop holds in both directions: dcrd accepts
`/dcrwire:1.0.0/dcroxide:2.2.0(pre)/` and dcroxide accepts
`/dcrwire:1.0.0/dcrd:2.1.6/`.

**Six changes since `c128a93` account for the difference.** Five are on
the block-processing path: a wider table for the block-file checksum,
the BLAKE-256 rounds written out, the tickets each block purchased kept
in memory for the block that matures them, a block's transaction hashes
computed once as it is processed where four steps each computed them,
and the indexes on a thread of their own. On the morning of 2026-10-11
the code before them took 1,058.3 s in one run, where the median above
is 1,058.6 s, and one sync as each was added took 1,015.3 s, 912.8 s,
893.7 s, 820.3 s and, with all five, 759.1 s and 756.2 s. The sixth
changes when the node commits: during the initial sync a UTXO cache
flush that the cache's size limit trips no longer forces the metadata
store to disk, so several share one commit. That afternoon the code
before it took 775.6 s in one run, and the figures above are the code
with it. It trades a longer replay after a crash during the initial
sync, and more memory, for the time;
[docs/operating.md](docs/operating.md) has the trade and the [bench
ledger](docs/bench-ledger.md) every step.

**The commit dcroxide then tracked syncs like the release.** dcrd
master `6f6cf21b` (2.2.0-pre), then the parity target, built under
go1.26.2 with the flags of its release image, took 2,909.8 s and
2,869.8 s from a dcroxide server in two runs on 2026-10-10. One is
inside the release's range above and the other 0.5% over its slowest
run.

**Much of the lead is the exists-address index.** One run of each daemon
with `--noexistsaddrindex`, dcroxide's on 2026-10-11 and dcrd's on
2026-10-10, set against the medians above:

| | index on | index off | the index costs |
|---|---:|---:|---:|
| dcroxide `b4a5d2d` | 12.1 min (728.7 s) | 10.2 min (610.2 s) | 16% of its sync |
| dcrd v2.1.6 | 47.7 min (2,863.9 s) | 20.8 min (1,247.8 s) | 56% of its sync |
| dcrd / dcroxide | 3.93x | 2.04x | |

Of the 36 minutes between the two at their defaults, 70% is the
difference in what the index costs each. With it off dcroxide reached
the assume-valid block in 7.9 minutes, where dcrd took 10.3, and ran the
fully validated blocks after it in 2.3 minutes against 10.5. At
`c128a93` dcrd was the first to that block, 10.3 minutes against 11.8.

**The syncer decides the time, not the source.** At `c128a93` each
daemon was also run from a server of its own kind, back to back with a
cross-source run: dcroxide took 1,072.2 s from a dcroxide server against
1,061.1 s from dcrd's, and dcrd 2,872.8 s from a dcrd server against
2,894.8 s from dcroxide's. That is one run of each, and the source moved
either by about 1% or less, the size of the run-to-run spread. An
earlier pair of same-source runs, taken with more activity on the
machine, is in the ledger with the rest. Every sync of dcroxide on
2026-10-11 and 2026-10-12, and every run through the relay, took its
blocks from the dcrd server.

Both daemons ran at their defaults, apart from the flags that point them
at the block server and open RPC for the height poll, and
`--noexistsaddrindex` in the index-off pair. So the exists-address index
is on in every other run, and both carry the same assume-valid block,
1,026,597: up to it they skip connect validation, script checks
included, and they validate the 89,438 blocks after it in full. The
syncing node was pinned to eight cores (16 threads) of a 16-core desktop
with one NVMe drive, m3 in the [bench ledger](docs/bench-ledger.md), and
the serving node to four others, with its data read into the page cache
before each run. The clock runs from the syncing process's start to the
first once-a-second `getblockcount` poll that reports the target height.
In three of dcrd's runs of 2026-10-10, the two of `6f6cf21b` and the one
with the index off, the page cache did not keep the dcroxide server's
block files and it read them from the drive as it served them. Whether
that cost dcrd anything was not measured.

The lead grows along the chain, and most where full validation begins.
Time to reach each height, the median of each daemon's runs above,
interpolated between samples taken every 10 s:

| block | dcroxide `b4a5d2d` | dcrd v2.1.6 |
|---:|---:|---:|
| 250,000 | 1.5 min | 3.4 min |
| 500,000 | 3.2 min | 8.0 min |
| 750,000 | 6.0 min | 17.6 min |
| 1,000,000 | 9.2 min | 31.7 min |
| 1,026,597 (assume-valid) | 9.6 min | 33.4 min |
| 1,116,035 | 12.1 min | 47.7 min |

Up to the assume-valid block dcroxide led 3.5x with the index on. Over
the 89,438 blocks after it dcroxide ran at about 586 blk/s against
dcrd's 104, 5.6x. dcroxide's metadata flushes took 15% of its wall time,
and its peak resident memory was 3.16 GiB against dcrd's 1.81 GiB.
Those are of `b4a5d2d`. In the nine syncs of 2026-10-12 described at
the top of this section the flushes took 104.3–111.4 s whichever code
ran, so their share grew as the rest shrank: 21.3% of each of the two
runs with the read-ahead on.

What these figures do not say:

- **Where the rest of the difference comes from.** dcrd was not
  profiled, and dcroxide only on 2026-10-11, in one sync of the code
  before the six changes above (user-space time only). What dcrd's time
  goes on has not been taken apart.
- **It is loopback, and what a delayed link costs depends on the
  download window.** dcrd requests blocks through a window of 16 in
  flight, refilled once fewer than 10 remain. So did dcroxide through
  the runs of 2026-10-11, and so it does when started with
  `DCROXIDE_BLOCK_WINDOW=dcrd`. Through a relay that delays every
  chunk, at a 50 ms round trip dcroxide synced the early chain at
  260 blk/s and dcrd at 252, about 13 blocks per round trip each, where
  over loopback they pass those blocks at about 3,200 and 1,500 blk/s.
  Those are fixed-time runs of 2026-10-11 with dcroxide `7d31abb`, on a
  machine that was not quiet. At 13 blocks per round trip this chain
  would take about 72 minutes at 50 ms for a daemon that processes
  faster than that throughout, as dcroxide does over loopback; dcrd runs
  the blocks after the assume-valid block at about 104 blk/s, so by the
  same arithmetic it would take at least about 80. Both are worked out
  for dcrd's window and were not run.
  By default dcroxide now uses a window of its own, measured only in
  short runs. It keeps up to 128 blocks requested from its sync peer,
  and beyond the first 16 no more than 3,145,728 bytes of them by the
  sizes in their headers, and it halves both limits, down to dcrd's 16
  blocks, each time a sync peer leaves with more than 16 requested
  ([PARITY.md](PARITY.md), *Block download window*). On 2026-10-12, on
  m3, one binary was run through the same relay for 300 s per arm,
  header sync included, on a quiet machine with the node on four cores,
  once with `DCROXIDE_BLOCK_WINDOW=dcrd` and once at the default: at a
  50 ms round trip it reached block 68,031 under dcrd's rule and block
  532,079 under the default, and at 150 ms blocks 18,445 and 158,440.
  No arm logged a narrowed or widened window or a stalled peer. The
  relay delays and does not limit bandwidth. The same day five
  outbound-only starts of 300 s were made against the public main
  network, on a machine that was not quiet and with the peers and links
  the network offered: under dcrd's rule the node reached block 24,455
  180.7 s after its first block arrived and block 41,191 after 220.3 s,
  and under the default block 188,469 after 215.7 s and block 93,095
  after 161.8 s. A third start under the default fetched no block, its
  header sync being about 68% done when the 300 s ended. None logged a
  narrowing, a stalled peer or a ban. Over loopback, on a quiet
  machine, one sync to block 1,116,035 took 612.4 s with the window and
  607.7 s with the code before it (`3a367e5`), one run each that day:
  0.8% more, and one run each does not settle whether the window costs
  anything over loopback. Both are in the table of 2026-10-12 at the
  top of this section. Not measured: a whole sync over a delayed or a
  real link, and the two cases in which the wider window can cost sync
  peers. No sync was run over a link held to a set rate or with a
  reader made to stop for 20 s or more: the public-network starts ran
  over whatever links their peers had, at rates that were not recorded,
  and the longest flush of the loopback sync took 3.5 s. A real link
  adds loss and a bandwidth limit that the relay does not;
  [docs/operating.md](docs/operating.md) has the budget and the setting
  that puts dcrd's window back.
- **The read-ahead's gain was measured over loopback only, and not as
  committed.** dcrd reads one message from a connection, handles it
  and only then reads the next (`inHandler`,
  `peer/peer.go:1535-1598`). During the initial sync dcroxide now
  reads its sync peer's connection up to four messages ahead of the
  thread that connects blocks, on a thread of its own, and reads as
  dcrd does when started with `DCROXIDE_READ_AHEAD=off`
  ([PARITY.md](PARITY.md), *Reading ahead of the block handler*). The
  494.6 s and 490.8 s at the top of this section, against 597.6 s and
  599.0 s with it off, are of 2026-10-12 on m3, on a quiet machine
  with the node on eight cores, and of the build made before the
  review of the read-ahead and its fixes. The node's own line at
  shutdown put the checksum and decode work that left the block thread
  at 45.8 s and 45.9 s and the hashing at 47.2 s in both runs, 93 s of
  the 103.0 s and 108.2 s gained; the socket reads moved too and are
  not timed, and what the rest is was not established. The reader
  thread was parked on a full queue for 382.4 s and 378.7 s of those
  runs, and the block thread waited on an empty one for 0.27 s: over
  loopback the next block was nearly always there, which a link with a
  round trip need not give. Peak resident memory was 2,967 and
  2,921 MiB with it on against 3,273 and 3,256 MiB with it off, which
  is not explained. Not measured: the gain of the code as committed,
  which was run on 2026-10-13 only inside `4700cf1` and only with the
  read-ahead on, nor of the reader's added work since (`a589c4a`,
  `44cf801`), which has been run only in builds that are not the code
  as it stands; a sync with it over a delayed or a real link, where the
  round trip and not the thread that connects blocks may set the pace
  and reading ahead may gain nothing; a node on fewer than eight cores;
  and its gain with `--noexistsaddrindex`, under which it was run once,
  in `4700cf1` on 2026-10-13. It costs one more thread and one more
  descriptor on that connection and the memory of up to four decoded
  messages held there, each with the frame it was read in, which was
  not measured. By estimates from the sizes of the structures, since
  `a589c4a` those are about 220 kB for four main network blocks of mean
  size, and at worst, from a hostile sync peer, the connection holds
  about 62 MB, with about 1.3 MB more for a moment while one frame is
  compared with its block's serialization, or up to about 1.4 MB while
  one block's merkle trees are built, against about 12.5 MB without the
  read-ahead ([SECURITY.md](SECURITY.md), *Known gaps*).
  [docs/operating.md](docs/operating.md) has the setting and how to
  read the shutdown line.
- **It is one machine with fast storage.** On m2 in the ledger, a
  container on a ZFS
  mirror of QLC drives with the node on four cores, dcroxide with the
  same storage layout ran the 200,000 blocks after 916,000 at a median
  of 482 blk/s, where m3 ran them at about 593, both before the changes
  of 2026-10-11. No sync from genesis has been measured on m2 with that
  layout, and the eleven commits of 2026-10-12 have been run on m3
  only. One run that day, of `b4a5d2d`, was on a data directory
  without copy-on-write: 714.1 s, against 728.5 s on the directory as
  created. None of the eleven was run that way.

At block 1,116,035 the data directory is 27.90 GiB under dcroxide and
24.16 GiB under dcrd, 1.15x. Block files make up 17.88 GiB of each. The
rest is metadata: one 10.01 GiB `metadata.redb`, against about 6.28 GiB left
for dcrd's two leveldb stores. The exists-address index is about 2.0 GiB
of either: with it off the directories were 25.88 and 22.19 GiB. Neither
side compresses. A 2026-08-11
measurement found the two implementations storing the same payload for
the same chain, so the difference then was redb's page layout and not
extra data. The exists-address index has since moved to a layout of its
own ([ADR-0011](docs/adr/0011-exists-address-layout-3-and-the-flush-participant.md)),
and that payload comparison has not been repeated.
[PARITY.md](PARITY.md) records the divergence from dcrd's two-database
layout.

Earlier measurements are kept in the
[bench ledger](docs/bench-ledger.md), which records every figure per
machine, commit and corpus, with the storage analysis behind them in
[ADR-0004](docs/adr/0004-storage-backend.md) and
[ADR-0009](docs/adr/0009-storage-shape.md). The 2026-07 and 2026-08
figures there were taken against dcrd 2.2.0-pre on m1, before the
height-first block keys
([ADR-0010](docs/adr/0010-height-first-block-keys.md)) and the
exists-address layout, so they are not earlier points on the same curve
as the headline figures above. The 2026-10 rows on m2 measure those two
changes, on slower storage and four cores.

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
