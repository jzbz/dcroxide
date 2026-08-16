# dcroxide

A from-scratch Rust implementation of the Decred full-node daemon, built as a
drop-in replacement for [dcrd](https://github.com/decred/dcrd).

Parity target: **dcrd master `29f17894`** (version 2.2.0-pre) — wire protocol
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
runs 729 tests across 234 suites, most differential against dcrd
itself or replaying sessions generated inside dcrd's own packages.

Since the surface completed, three rounds of work have landed on it. A
performance campaign: ffldb's metadata write cache, block scripts
validated on dcrd's worker pool, a ported `SigCache`, one transaction
hash per block, batched UTXO reads, and a layered dbCache overlay. A
security campaign closing the blockers an audit found in the RPC and
peer surfaces: authentication and admission control, bounded peer
message paths with stall deadlines and queue limits, OS-seeded
CSPRNGs, secret-file handling, and `panic = "abort"` in release
builds. And the rename onto dcroxide's own identity — data directory
`~/.dcroxide`, configuration file `dcroxide.conf`, `DCROXIDE_*`
environment variables.

It has synced testnet and mainnet to the tip from genesis with full
consensus validation, and syncs against dcrd in both directions (see
[Performance](#performance)). That says the consensus rules agree with
dcrd's across the whole chain; it does not say the node is safe to
operate. **Do not expose it to the internet and do not use it with
funds** — see [SECURITY.md](SECURITY.md) for what is known to be
missing and how to report a vulnerability, and
[docs/operating.md](docs/operating.md) for what running it deliberately
requires (a supervisor is mandatory, and a dcrd data directory will not
work). Currently implemented:

- `dcroxide-crypto` — BLAKE-256 (vendored from
  [dcr-rs](https://github.com/jzbz/dcr-rs), KAT-pinned, differential-tested
  against dcrd live) and RIPEMD-160 (RustCrypto-backed, KAT-pinned)
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
  APIs, all error kinds), backed by redb 4.1.0 per ADR-0004 with
  dcrd's exact ffldb key layout and flat-file block record format, plus
  bulk block import/export in dcrd's `addblock` bootstrap format, plus
  ffldb's metadata write cache — layered snapshots over one durable
  flush per window — so a sync commits on dcrd's schedule rather than
  per block; pinned by the ported ffldb interface-test battery and a
  crash-consistency rig (fresh-sync stance: no in-place dcrd datadir
  reuse, and no in-place upgrade from a pre-2026-08-13 dcroxide datadir
  either — redb 4 refuses a 2.x file with a typed error naming the
  version, and the chain must be re-synced or re-imported)
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
  layer over redb (byte-identical bucket rows against dcrd's ffldb),
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
  own full block test battery (`fullblocktests`): 573 instances of
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
  overlay, and the subscriber machinery with dependent relay,
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
  peers, and pools, replayed over the real Rust chain engine
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
  tests
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
  Windows, exactly like dcrd)
- `dcroxide-testutil` — the differential-test harness every crate
  shares (no dcrd counterpart): the line-delimited JSON transport to
  `tools/oracle`, the toolchain gate (a missing Go toolchain skips the
  test, or fails it when `DCROXIDE_REQUIRE_ORACLE` is set), a
  deterministic SplitMix64 PRNG that prints its seed so a failure
  reproduces, and hex helpers; a dev-dependency only, never published
- `dcroxide-bench` — the block replay harness (no dcrd counterpart):
  `export` writes the main chain of a stopped data directory to a
  bootstrap-format corpus, and `replay` drives that corpus back
  through the live chain engine with full validation — a network sync
  without the network — reporting throughput at a fixed block
  interval, so an optimization is measured on the same blocks before
  and after
- `tools/oracle` — Go shim linking dcrd's own packages (pinned to the
  master `452c1a6c` module versions) as a test oracle over line-delimited JSON
- `tools/helpgen` — the go-flags help-vector generator over dcrd's
  verbatim config struct
- `tools/dcrdstat` — sums the payload dcrd actually stores, per ffldb
  bucket, so a density comparison against dcroxide rests on both sides'
  measured bytes rather than on file sizes alone
- `tools/pinbump` — given two dcrd commits, resolves the upstream files
  they touch to the dcroxide crates that port them, via PARITY.md's own
  table, so moving the parity pin starts from a review list rather than
  a whole-diff read

## Performance

Mainnet sync from genesis to the tip (~1,100,400 blocks) over
loopback, one machine, a fresh data directory per run, both nodes
`--norpc`: dcroxide 2.2.0-pre against dcrd 2.2.0-pre+452c1a6c3
(go1.26.5), in all four combinations.

| syncer / source | from dcroxide | from dcrd |
|---|---|---|
| dcroxide | 2.47 h — 124 blk/s | 2.51 h — 122 blk/s |
| dcrd | 1.11 h — 276 blk/s | 1.02 h — 299 blk/s |

The syncer decides the time and the source barely matters: swapping
the source moves the result 1.6-8.8%, swapping the syncer moves it
2.2x. Interop holds in both directions — dcrd accepts
`/dcrwire:1.0.0/dcroxide:2.2.0/` and dcroxide accepts
`/dcrwire:1.0.0/dcrd:2.2.0(pre)/`, each reaching a matching tip.

**That 2.2x is superseded. Re-measured on 2026-08-15, the gap is
1.29x** — both daemons syncing mainnet from one shared dcrd server,
defaults intact, index composition verified on both sides:

| arm | wall | rate | mean cores |
|---|---|---|---|
| dcrd | 3,220.5 s | 341.7 blk/s | 1.50 |
| dcroxide | 4,153 s | 265.0 blk/s | 0.76 |

Both sides improved — dcroxide 124 → 265 blk/s, dcrd 276 → 342 — and
dcrd improving too is the sign that part of the 2026-07 figure was its
harness, which had the two nodes syncing from each other on one
machine. Read 1.29x as a bound rather than a point estimate: the arms
ran ~12 h apart under unmatched load average (4.62 against 2.45), n=1
each, and the dcroxide binary predates the fan-out fix. Each of those
can only have cost dcroxide, not flattered it.

**dcroxide reaches that at roughly half dcrd's CPU** — 0.76 cores
against 1.50, on a 32-thread host. So the open question is not how much
compute is missing but what the node is blocked on. A load average of
4.62 at 0.76 cores is either another tenant or dcroxide's own threads
parked in D-state on redb writes, and this run does not separate them.

The gap was attributed to the storage engine's commit shape rather than
to validation: across its two 2026-07 runs dcroxide spent 80.1% and
82.4% of wall time in progress stalls over 20 seconds, where dcrd
stalled zero times in 754 windows. goleveldb's LSM commit is O(dirty)
with background compaction, while redb is a copy-on-write B-tree with
no background work, so commit cost tracks the size of the tree.

**That attribution was measured on 2026-08-15 and holds** — by a
mechanism the hypothesis had wrong. Sampling every thread's scheduler
state through both syncs, dcroxide's *own* threads are barely blocked
(0.38 tasks); what separates the daemons is kernel-side storage work,
**1.64 tasks against dcrd's 0.14**, mostly dm-crypt writeback. It is
the write shape rather than the volume: dcrd writes 1.16x more bytes at
1.74x the rate and blocks 30x less per GiB, because LSM compaction is
sequential and off the write path while a copy-on-write B-tree writes
synchronously, one fsync per commit. dcroxide's blocked threads park in
btrfs page-writeback, metadata-reservation and transaction-commit
waits, and it reads 99x more than dcrd during ingest. Most of the cost
lands outside the process, which is why profiling the port's own
threads never found it.

**The share is measured too, from the same samples: dcroxide is fully
stalled — zero runnable threads — for 34.6% of block-sync wall time,
against dcrd's 0.9%.** It tracks tree growth, which is the
copy-on-write prediction: 1.3% of wall time below block 300,000 and
**50.9% above block 900,000**, where the port spends half its time
completely stopped. Removing *all* of that stall would move dcroxide to
346.6 blk/s and dcrd to 346.9 — they converge, which bounds how much
storage can be worth here.

**The stall is the metadata commit.** Pairing that sampler with
dcroxide's own flush observer on 2026-08-16, **90–98% of the
fully-stalled time falls inside a flush window** on every weighting:
during a flush the process is stalled 40.9% of the time at 0.55 cores,
outside one 3.2% at 1.38. Two figures around it needed correcting
though. **34.6% was a count-weighting artifact** — the sampler is
starved during the very stalls it measures, and weighting each sample
by the time it represents puts both runs at **48–51%**. And the
counterfactual above **overshoots**: removing only the commit stall
projects 373.7 blk/s, faster than dcrd, which shows the model is too
generous rather than the prize enormous. A flush is not pure blocking
(median 26.9 s, occupying 59% of wall), and moving it to a background
thread relocates its CPU half rather than removing it.

Nor is it settled that the stall is *removable*: dcrd shows the work
can be overlapped, not that redb can overlap it. Two or more dcroxide
threads block at once in only 0.2% of samples, so its storage path is
serialized — implicating a synchronous fsync on the critical path as
much as the engine choice. Full figures, and the two weaknesses in the
method, in the [bench ledger](docs/bench-ledger.md).

At the tip the same chain cost 23.73 GiB under dcrd and 32.06 GiB
under dcroxide, measured 2026-07 under redb 2.6.3. The 2026-08-15 pair
above, under redb 4.1.0 with composition verified, puts it at 23.69 GiB
against 33.58 — dcrd flat across the year, dcroxide up 1.5 GiB, 1.42x.
Block bytes are consensus data and match to within a
mebibyte — 17.580 GiB against 17.579 GiB — so the whole 8.33 GiB
difference is metadata: dcrd's 6.045 GiB `blocks_ffldb/metadata`
leveldb plus a 0.108 GiB `utxodb`, against one 14.483 GiB
`metadata.redb`. Neither side compresses; dcrd opens its chain
databases with `opt.NoCompression`. The redb file holds 5.65 GiB of
payload over 76,302,003 rows, and the rest divides into 0.69 GiB of
per-pair overhead, 3.44 GiB of intra-page slack at 64.86% B-tree fill,
and 4.69 GiB of allocated-but-free pages. That last figure is reused
working space the allocator draws down, not a packing loss and not a
comparison metric: it has moved 4x at 250,000 blocks, 2.01x across five
matched cache/cadence arms with the live tree pinned, and 55% between
two runs of the same arm. The figure to quote is the live B-tree, which
reproduces at 9.79-9.82 GiB across runs of matching composition. All
four of ADR-0004's levers are measured and closed; what stays open is
the flush-bound ingest and the engine question in
[ADR-0009](docs/adr/0009-storage-shape.md).

Since 2026-08-11 the difference has a measured explanation rather than
an inferred one. Feeding dcrd the identical block bytes and recording
the index composition on both sides, the two implementations store the
**same payload** — 6,061,905,929 B against 6,069,302,583 B, fifteen
buckets equal to the byte, the remainder accounted for by a four-byte
bucket-id prefix dcroxide adds to each UTXO row. So none of the gap is
data dcroxide keeps and dcrd does not, and none of it is a denser dcrd
encoding. Over each store's own payload it is 1.081x under goleveldb
against 1.738x for redb's live B-tree (1.726x on dcrd's write
schedule). The full measurement record is in
[ADR-0004](docs/adr/0004-storage-backend.md); PARITY.md records the
divergence from dcrd's two-database layout. Measurements are recorded
per machine, commit, and corpus in
[docs/bench-ledger.md](docs/bench-ledger.md).

## Layout

- `crates/` — the Cargo workspace: one crate per dcrd package (see
  PARITY.md), plus the shared test harness and the replay bench
- `tools/oracle/` — the dcrd differential-test oracle (Go)
- `tools/helpgen/` — the go-flags help-vector generator (Go)
- `tools/pinbump/` — the parity-pin bump review-list generator (Go)
- `tools/dcrdstat/` — dcrd payload measurement over ffldb + utxodb (Go)
- `fuzz/` — `cargo-fuzz` targets (nightly toolchain)
- `docs/adr/` — architecture decision records

## Development

Rust ≥ 1.94 (MSRV) and a Go toolchain (for the oracle-backed differential
tests; without Go those tests skip). `DCROXIDE_REQUIRE_ORACLE=1` turns a
missing toolchain into a failure instead, so a run cannot silently pass
with the differential coverage skipped — CI sets it.

`rust-toolchain.toml` pins the toolchain builds actually use, so a commit
compiles with one rustc everywhere; the MSRV above is the older floor CI
checks separately. Commands needing another toolchain say so explicitly
(`cargo +nightly fuzz ...`).

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
everywhere (the one exception: `dcroxide-winsvc` denies rather than
forbids unsafe because the service-entry macro expands an FFI shim,
while writing none itself).

## License

ISC. Portions derived from dcrd and dcr-rs, both ISC; see [LICENSE](LICENSE)
and per-file attribution headers.
