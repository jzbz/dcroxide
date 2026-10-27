# dcroxide

A from-scratch Rust implementation of the Decred full-node daemon, built as a
drop-in replacement for [dcrd](https://github.com/decred/dcrd).

Parity target: **dcrd v2.2**, which upstream has not yet released: until it is
tagged, the pin follows dcrd master, now **`3360ae4d`** (version 2.2.0-pre) —
wire protocol 12, JSON-RPC API 8.3.0. dcrd's behavior at the pinned commit is
the specification; see [QUIRKS.md](docs/QUIRKS.md) for deliberate bug-for-bug
reproductions and [PARITY.md](docs/PARITY.md) for per-package status. The full
plan lives in [dcroxide-project-brief.md](docs/dcroxide-project-brief.md).

**Status: pre-alpha — the dcrd surface is ported end to end.** Every
dcrd package has a Rust counterpart and the threaded daemon assembles
them all: config, chain engine with full consensus validation, mempool,
mining and CPU miner, P2P server with sync, relay, and mixing, the
JSON-RPC/websocket server, the tool commands, the pipe IPC lifecycle,
and the Windows service wrapper. The deliberate non-ports are small
and documented in PARITY.md (Go GC tuning, the pprof servers, UPnP,
the Windows event log, and the wallet-side mixclient). The test suite
runs 2,682 tests across 453 suites on Linux, most differential against
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
only, each of which before 2026-10-19 validated in full only the blocks
after the assume-valid block. One of the eleven changes how a
`SigHashAll` signature hash is computed while a block is connected, and
the syncs made with it before then put that to the 89,438 blocks after
the assume-valid block and to none before it. The eighteen commits to
the node's code after the eleven, several of which change code that
applies the consensus rules, among them where a connected block's
scripts are checked, have been put to blocks only in syncs: `8fc9160`,
which holds them, was run in four on 2026-10-16. The commits after it,
which port dcrd's changes since `6f6cf21b`, some of them to the
consensus rules, and move the metadata commit to a thread of its own,
were first put to blocks on 2026-10-17, in syncs of `88c46c3` (the bench
ledger, "`88c46c3`, the background commit as committed, dcrd v2.1.7 and
two preloaded allocators"), each of which validated in full only the
blocks after the assume-valid block and ended with the UTXO set that
dcrd's syncs of that day ended with. The commits after `fdd7a83` were
put to blocks first in builds made from a worktree, not from their
trees. All but one were in syncs of 2026-10-18 from a block server on
another machine on the same LAN, each of which validated in full only
the blocks after the assume-valid block and had dcrd's block at height
1,116,035, and in three syncs from the loopback server that ended with
that same UTXO set (the bench ledger, "Rungs from a block server on the
LAN, two changes held for their memory, and dcrd v2.1.7"). The one that
keeps the metadata commit thread for the life of the store, which
changes no consensus rule, was in none of those builds: it has been put
to blocks only in a build that also holds the two changes held that day
for their memory, in syncs of 2026-10-19 from the same two servers (the
bench ledger, "One commit thread for the life of the store, a sync that
checks every script, and dcrd v2.1.7"). One of those syncs, from the
loopback server with `--assumevalid=0`, validated every block in full,
script checks included, and ended with that same UTXO set and the same
block files: a build whose code is that of `797a213` but for a doc
comment and a test's local name accepted every block of mainnet's chain
up to 1,116,035 with each one validated in full.
On the evening of 2026-10-19 a release build of the tree of `797a213`,
which holds every commit above, was put to blocks in six syncs from the
LAN server, each of which validated in full only the blocks after the
assume-valid block and had dcrd's block at height 1,116,035 (the bench
ledger, "Where `797a213`'s block thread waits, a deeper read-ahead and a
rung of four changes").
Of the commits after `797a213`, eighteen change the node's code beyond
tests and comments: one classifies a block's transactions once for every
step that reads their types, among them checks that apply the consensus
rules, and changes no rule; another allocates a block filter's list of
entries once, and changes no filter's bytes; a third moves a handed-over
metadata flush's block-file sync onto the commit thread, and reports a
failure of that sync to the next write, flush or close rather than to
the commit that tripped the flush; a fourth reads the scripts a block
filter commits to from the spend journal the block's connect built, not
from the UTXO view, and changes no filter's bytes either; a fifth reads
the sync peer's connection up to sixteen frames ahead of the block
handler, where it read four, and changes no verdict; a sixth lets more
of the script pool's helpers pre-verify signatures by default on a
machine with SMT or whose cores are not read, as on Windows and macOS,
ten where there were six on eight cores of two hardware threads each,
and changes no verdict either; a seventh writes the daemon's log file
and rotates it as dcrd does, and changes no verdict; the eighth takes a
block whose contextual merkle check fails, which dcrd leaves unmarked,
out of the best chain candidates with the blocks on it, still unmarked,
so that a reorganization falls back past it, and changes no block's
status, but a valid block that tied with such a block now connects where
dcrd returns the other block's `ErrBadMerkleRoot`; the ninth refuses a
block whose header names another size than the block's before it counts
the block's data as the header's, where dcrd, with the header
commitments agenda's state decided, refuses it after and marks the
header as failed, so that a copy of a valid block with the tail of a
merkle tree repeated no longer has the valid block refused when it
arrives, where dcrd refuses it (PARITY.md, *The header's size and a
proven data commitment*); the tenth adds again, without the fresh mark,
an output that a disconnect marked spent when the UTXO cache has no slot
for it, so that after a restart, or once a flush has evicted the entry,
a spend before the next flush leaves a tombstone and the flush deletes
the stored row, as on a node that kept the entry cached, where a
restarted dcrd keeps the row and accepts a later block spending it,
which the port then rejects (PARITY.md, *UTXO cache entry for an output
added again after a disconnect*); the eleventh closes the metadata
store's file when the block database closes, so that a clean shutdown
leaves it without redb's recovery flag, and changes no verdict; the
twelfth has the RPC listener's TLS handshake choose its key exchange,
P-521 now among them, and its cipher suite as Go's server does and log a
refused handshake as dcrd does, and changes no verdict; the thirteenth
logs the mempool's and the template generator's lines below info as dcrd
does, and changes no verdict; the fourteenth gives `startprofiler` and
`--profile` dcrd's address checks and refuses an address dcrd would
serve, the profile servers not being part of this port, and changes no
verdict; the fifteenth copies the committed filters a getcfilterv2 or
getcfsv2 request takes from the chain's recent window after releasing
the chain lock, where it copied them under it, as dcrd's
`LocateCFiltersV2` copies its filters after releasing its chain lock,
and changes no verdict; the sixteenth checks an RPC client
certificate's chain in one webpki search, held to each root's path
length constraint within it, where it searched all of the
intermediates sent and then up to 100 choices of them, each on its
own, and admits a chained certificate whose extended key usage
includes anyExtendedKeyUsage, as dcrd does, but now refuses, under a
path length constraint, a chain whose alternative issuers spend
webpki's budget of signature checks before Go's would be spent
(PARITY.md, the clientcert entry), and changes no verdict; the
seventeenth holds every certificate an RPC client presents to the
parse and unhandled critical extension checks of Go's `x509` that the
pool's certificates already met, so a leaf or intermediate dcrd
refuses for a critical subject alternative name or name constraints
extension of a form Go does not handle, or for a fault Go's parser
refuses as far as the port reads it, is refused, where it verified,
and changes no verdict; the eighteenth holds an RPC client's chain to
Go's certificate policy validation, so a chain dcrd refuses for its
policies, one with an intermediate whose non-critical policy constraints
require an explicit policy none of its certificates names, say, is
refused, where it verified, as is a certificate the client sends with a
length written in more octets than it needs where the port reads it, in
a policy extension, say, which Go's parser refuses and which the client
CA pool now skips as dcrd's does,
and changes no verdict. In syncs the first four were initially put to
blocks in a build made from a worktree that holds the four of them, R1
of that section: in four from the LAN server, each of which had dcrd's
block at height 1,116,035, and in one from the loopback server that
ended with that same UTXO set and the same block files. The fifth's
depth of sixteen frames was first put to blocks in the diagnostic
build of that section, `797a213`'s code with the depth read from a
variable, and not with the other four: in five syncs from the LAN
server, each of which had dcrd's block at height 1,116,035, two of
them with `DCROXIDE_PREVERIFY=10`, which on that node is the sixth's
default. A release build of `8bda92e`, which holds the first six, then
synced four times from the LAN server on 2026-10-22, each with dcrd's
block at that height (the bench ledger, "`8bda92e` in a directory
without copy-on-write, and block records on fresh pages"); one of
`b49145e`, whose node code is `8bda92e`'s, synced from the loopback
server on 2026-10-23, and the blocks and every other record both
stores keep for a block were equal at every height from genesis to
1,116,035 in the data directory it left and the one dcrd wrote for the
same chain (the ledger, "Per-block comparison with dcrd, genesis to
block 1,116,035"); and one of `58bd107`, which holds the first twelve,
synced mainnet once from the LAN server to block 1,126,076, as the
node of the Decrediton run the project brief records, outside the
bench harness, so not as a timing, and was not compared with dcrd at
its end. Each sync in the three sentences before this one validated in
full only the blocks after the assume-valid block. A release build of
`f37d763`, which holds all eighteen, synced on 2026-10-24 four times
from the LAN server, each with dcrd's block at height 1,116,035, and
three times from the loopback server, each ending with the UTXO set that
dcrd's syncs of 2026-10-17 ended with and the same block files; all but
one of the seven validated in full only the blocks after the
assume-valid block, and that one, with `--assumevalid=0`, validated
every block in full (the ledger, "`f37d763` against `797a213`, its end
state and a sync that checks every script").
That the rules reject what dcrd's reject, but for the valid block the
ninth accepts after such a copy, rests on the test batteries
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
- `dcroxide-tlscrypto` — the rustls crypto provider that is to replace
  `ring` (no dcrd counterpart; ADR-0015), built in steps beside it: so
  far the nine cipher suites' record protection over RustCrypto's
  `aes-gcm` and `chacha20poly1305`, with their transcript hashes, HMAC,
  HKDF and TLS 1.2 PRF, and the X25519, P-256, P-384 and P-521 key
  exchanges over `curve25519-dalek` and RustCrypto's curve crates, with
  Go's rules for a peer's share and ephemeral keys from the kernel,
  pinned by Wycheproof's vectors on hardware and portable backends, by
  in-memory handshakes against ring's suites and groups of the same
  names, both ways, and by Go's `crypto/ecdh` through the oracle; the
  node takes only its P-521 key exchange so far
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
- `dcroxide-sigdiff` — the signature differential soak (no dcrd
  counterpart): generators for named input classes of all three signature
  types, public key parsing and compact recovery, built with their own
  curve arithmetic rather than the code under test, a pipelined client for
  `tools/oracle`, and the `sigsoak` binary that runs the classes against
  dcrd's own code at recorded volume, replays any case from its seed and
  runs deliberately broken models to show the classes can fail, and emits
  the witness vectors `dcroxide-dcrec` keeps; development only, never
  published
- `dcroxide-bench` — the block replay harness (no dcrd counterpart):
  `export` writes the main chain of a stopped data directory to a
  bootstrap-format corpus, and `replay` drives that corpus back
  through the live chain engine with full validation of every block,
  where a network sync skips connect validation up to the
  assume-valid block — reporting throughput at a fixed block
  interval, so an optimization is measured on the same blocks before
  and after
- `tools/oracle` — Go shim linking dcrd's own packages (pinned to the
  parity pin, master `3360ae4d`: each dcrd module at that commit's
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
- `tools/profilergen` — the generator of `profiler_vectors.txt`, run as
  a test inside a dcrd checkout's package main through
  `go test -overlay`, so every row is what dcrd's own
  `profileServer.Start` returned, writing nothing into the checkout
  (Go + sh)

## Performance

On 2026-10-25 a build of `dfa77fe`, the head of master when the syncs
ran, synced mainnet from genesis to block 1,116,035 in a mean of **4.2
minutes** over four runs at the defaults, where dcrd v2.1.7 took **50.0
and 49.5 minutes** in two runs of the same session: dcroxide was
**11.87x as fast** by the means, 11.74x to 12.01x over the eight
pairings. With the exists-address index, which both daemons build by
default, turned off in both, it was 5.74x, against one dcrd run. Both
took their blocks from a dcrd node on another machine on the same LAN: a
series of its own, not comparable with the syncs over loopback that this
section gave until 2026-10-19 (below). A figure for four runs is their
mean, or their range where one is given, and for one or two each run's
value:

| daemon | setting | runs | wall time | rate | node CPU time | peak memory when the clock stops |
|---|---|---:|---|---|---|---|
| dcroxide | defaults | 4 | **251.58 s** (249.6–253.1 s) | 4,436.2 blk/s | 927.48 s | 2,462–2,496 MiB |
| dcrd v2.1.7 | defaults | 2 | **2,997.7 s, 2,972.5 s** | 372.3, 375.5 blk/s | 5,632.4 s, 5,569.9 s | 1,854 MiB, 1,855 MiB |
| dcroxide | `--noexistsaddrindex` | 2 | 230.5 s, 231.0 s | 4,841.8, 4,831.3 blk/s | 809.7 s, 814.4 s | 2,276 MiB, 2,281 MiB |
| dcrd v2.1.7 | `--noexistsaddrindex` | 1 | 1,325.3 s | 842.1 blk/s | 2,724.9 s | 1,850 MiB |

At the defaults dcrd used 6.0x dcroxide's CPU time, and dcroxide's peak
memory was 1.33x to 1.35x dcrd's (dcrd keeps a soft limit of 1.80 GiB).
The index costs dcroxide 20.8 s, 8.3% of its sync, and dcrd 1,659.8 s,
55.6% of its own.

**How it was measured.** The runs were on m3 in the [bench
ledger](docs/bench-ledger.md), a 16-core desktop with one encrypted NVMe
drive under btrfs and transparent huge pages at `always` (the kernel's
default there) on kernel 7.3.0, and took their blocks from a live dcrd
v2.1.7 node following the network, about 0.3 ms away. `dfa77fe` changes
nothing in the node's code after `f37d763`, and its build is byte for
byte the build of `f37d763` that the ledger's runs of 2026-10-24 used.
The runs went one at a time in one queue (the ledger has the order),
each after a `sync`, 300 s idle and a quiet check, the first after the
check alone; none was marked disturbed, and dcroxide's flush log was on
in all, at a cost not measured. The clock runs from the node's start to
the first once-a-second `getblockcount` poll at or past 1,116,035, which
came 37 to 2,111 blocks past it. CPU time is the node process's, without
the kernel threads that encrypt and write back its bytes, and peak
memory is `VmHWM`, both read when the clock stops, with the node still
syncing.

**The background commit.** Since `02b802c` most metadata commits run on
a thread of their own, and since 2026-10-19 that thread, `dbcommit`,
writes each flush's rows as well and is kept from the first flush handed
to it to the store's close ([PARITY.md](docs/PARITY.md), *Where a cache
flush's commit runs*); since `aa157d1` it also syncs a handed-over
flush's block files. On 2026-10-19, with transparent huge pages at
`madvise`, two runs of a build of the code of `797a213`, which comes
before `aa157d1`, with `DCROXIDE_DB_SYNC_COMMIT=1`, which puts every
commit back on the committing thread, took 350.2 s and 350.6 s against a
mean of 271.68 s over four at the default: the default was 78.7 s or
22.5% less by the means, and it peaked lower, 2,456–2,470 MiB against
2,959 and 2,964 MiB, for 893.7 to 902.9 s of CPU time against 877.8 s
and 874.6 s; on m3's storage only
([docs/operating.md](docs/operating.md) says when to set the variable).
No build that holds `aa157d1` has been run with the variable set.

Both daemons skip connect validation, script checks included, up to the
assume-valid block, 1,026,597, and validate in full after it, where the
lead grows most. Time to that block, interpolated between 10 s samples:

| stretch | dcroxide, mean of four | dcrd v2.1.7, each run | dcrd / dcroxide, by the means |
|---|---:|---:|---:|
| genesis to 1,026,597 (assume-valid) | 202.71 s | 2,117.1 s, 2,100.4 s | 10.4x |
| the 89,438 blocks after it | 48.86 s | 880.6 s, 872.1 s | 17.9x |

**The end state, and every block validated in full.** The node goes on
syncing from the live server after the clock stops, so the runs above
record no end state, only that its block at 1,116,035 was `8752fdc9…`.
On 2026-10-24 the same binary synced three times from a dcrd v2.1.6
server on the same machine, twice at the defaults and once with
`--assumevalid=0`, which validates every block in full, scripts
included, and each sync ended with the block files and the UTXO set of
every full sync from that server since 2026-10-17, dcrd's included
(`gettxoutsetinfo`: 1,850,903 outputs, serialized hash `eb7f88de…`); the
rest of the metadata store was not compared. The sync with
`--assumevalid=0`, from a server that read nothing from its drive, took
491.7 s, 237.2 s more to the assume-valid block than the default sync
whose server also read nothing from its drive (the other was marked
disturbed, and its server read 11.9 GB from its drive) and 0.5 s more
after it, with 4,702.1 s of CPU time against 915.6 s, 3,959.1 s of it on
the script pool's 15 threads, and peaked at 2,392 MiB. dcrd was not run
so.

What these figures do not cover:

- **A link with a longer round trip.** The LAN server was about 0.3 ms
  away, and dcroxide's download window, up to 128 blocks where dcrd
  keeps 16 ([PARITY.md](docs/PARITY.md), *Block download window*), has been
  run over a longer round trip only in short runs on 2026-10-12, through
  a relay and on the public network, and in no whole sync.
- **The syncs of 2026-10-19.** Until 2026-10-25 this section gave the
  syncs of a build of the code of `797a213` from the same LAN server,
  with transparent huge pages at `madvise` on an older kernel: a mean of
  271.68 s, 11.13x dcrd v2.1.7's 3,014.6 s and 3,033.4 s. The setting
  and the kernel may change either daemon's speed, by amounts not
  measured, so those figures are not to be set beside these.
- **The syncs over loopback.** Until 2026-10-19 this section gave
  `88c46c3`'s syncs of 2026-10-17 from a dcrd v2.1.6 server on the same
  machine, whose data stayed in the page cache: a median of 396.25 s,
  7.43x and 7.39x dcrd v2.1.7. The server, the link and the node's
  receive path differ, so none of those figures is to be set beside
  these: from the LAN server on 2026-10-18 `88c46c3` itself took 407.0
  to 407.9 s, against 391.1 to 397.8 s over loopback.
- **The read-ahead's gain as committed.** Its one comparison with
  `DCROXIDE_READ_AHEAD=off`, on 2026-10-12, was of a build before its
  review's fixes ([PARITY.md](docs/PARITY.md), *Reading ahead of the block
  handler*), and no run here turned it off.
- **Other machines.** Every figure above is of m3 (the ledger has older
  runs on m2), and no sync has been timed on Windows or macOS.

The [bench ledger](docs/bench-ledger.md) has every run of 2026-10-25
("`dfa77fe` against dcrd v2.1.7, with the exists-address index on and
off"), the end-state syncs of 2026-10-24 ("`f37d763` against `797a213`,
its end state and a sync that checks every script"), the runs of the
morning of 2026-10-19 ("One commit thread for the life of the store, a
sync that checks every script, and dcrd v2.1.7"), those of 2026-10-17
("`88c46c3`, the background commit as committed, dcrd v2.1.7 and two
preloaded allocators"), the earlier measurements, and this section's
text until 2026-10-17 ("README Performance text retired on 2026-10-17").
The LAN runs record no data directory's size; after the syncs of
2026-10-17 it was a median of 27.93 GiB under `88c46c3` against 24.16
and 24.18 GiB under dcrd, 17.88 GiB of it block files in each
([ADR-0004](docs/adr/0004-storage-backend.md) and
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
- `tools/profilergen/` — the profile server vector generator, an overlay
  test for dcrd's package main (Go + sh)
- `fuzz/` — `cargo-fuzz` targets (nightly toolchain)
- `docs/adr/` — architecture decision records

## Development

Rust 1.98.1 and a Go toolchain (for the oracle-backed differential
tests; without Go those tests skip). Go 1.26.2 is the reference: the
release dcrd's release image builds the parity pin with, and the one CI
runs (`GO_VERSION` in `.github/workflows/ci.yml`; ADR-0001's 2026-10-26
addendum on the reference Go). The oracle builds with Go 1.24 or later,
but where an answer comes from Go's standard library, an oracle built
with another release answers as that release does.
`DCROXIDE_REQUIRE_ORACLE=1` turns a missing toolchain into a failure
instead, so a run cannot silently pass with the differential coverage
skipped — CI sets it.

`DCROXIDE_ORACLE_BIN` can name a prebuilt oracle instead: the absolute
path of a `dcrd-oracle` built from this checkout's `tools/oracle` with
`go build -o`. Every test process then runs that binary rather than
building its own, and no Go toolchain is needed. The binary is taken as
found, so one built before a change to `tools/oracle` answers for the
old source. A name that is not an absolute path to a file skips the
oracle tests, or fails them under `DCROXIDE_REQUIRE_ORACLE`.

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
