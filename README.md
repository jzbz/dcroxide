# dcroxide

A from-scratch Rust implementation of the Decred full-node daemon, built as a
drop-in replacement for [dcrd](https://github.com/decred/dcrd).

Parity target: **dcrd `release-v2.1.5`** — wire protocol 12, JSON-RPC API
8.3.0. dcrd's behavior at that tag is the specification; see
[QUIRKS.md](QUIRKS.md) for deliberate bug-for-bug reproductions and
[PARITY.md](PARITY.md) for per-package status. The full plan lives in
[dcroxide-project-brief.md](dcroxide-project-brief.md).

**Status: pre-alpha — Phases 4 and 6 complete, plus the stake
transaction primitives from Phase 5 and the storage layer opening
Phase 7 (rig, primitives, wire, chaincfg, the full script engine
including addresses, classification, and signing, stake transaction
rules, the standalone consensus functions, and the block/metadata
database).** Nothing here is ready to validate, relay, or hold funds.
Currently implemented:

- `dcroxide-crypto` — BLAKE-256 (vendored from
  [dcr-rs](https://github.com/jzbz/dcr-rs), KAT-pinned, differential-tested
  against dcrd live) and RIPEMD-160 (RustCrypto-backed, KAT-pinned)
- `dcroxide-chainhash` — the 32-byte hash type with dcrd's byte-reversed
  string encoding, including its short-string parsing quirk
- `dcroxide-wire` — message framing with dcrd's exact validation order and
  error identities, plus **all 40 P2P message types** at protocol version 11,
  including the eight StakeShuffle mixing messages; `MsgTx`, blocks, headers,
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
  surface is differentially matched against dcrd (the ticket-database
  state machinery follows in the blockchain phase)
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
  APIs, all error kinds), backed by redb per ADR-0004 with dcrd's exact
  ffldb key layout and flat-file block record format, plus bulk block
  import/export in dcrd's `addblock` bootstrap format; pinned by the
  ported ffldb interface-test battery and a crash-consistency rig
  (fresh-sync stance: no in-place dcrd datadir reuse)
- `dcroxide-blockchain` — the beginnings of the chain engine: dcrd's
  UTXO serialization layer (VLQs, the domain-specific script and amount
  compression, UTXO entries, outpoint keys, and the set state) and the
  legacy work/stake difficulty algorithms, the stake-version voting
  machinery, the agenda threshold state machine, the agenda-driven algorithm selectors, the chain persistence formats, the context-free transaction validation and block sanity layers, the DCP0003 sequence lock calculation, the positional and contextual header validation layers, the full transaction input validation (tickets, votes, revocations, and treasury spends through the fee-computing CheckTransactionInputs), the block sigop and stake amount accounting, and the in-memory block index and chain view (skip-list ancestors, chain tips, best-chain candidates, invalidation propagation, and block locators), plus the immutable ticket treap, the ticket database serialization formats, and the full ticket pool state machine (connect/disconnect with lottery winners and undo data) in dcroxide-stake — now wired into validation through the completed header stake commitments, the ticket redeemer checks, and the full contextual block assembly (checkBlockContext) and the utxo viewpoint with block connect/disconnect and spend journaling, the fee-accounting checkTransactionsAndConnect loop, the full checkConnectBlock battery (treasury payouts, both tree connects, sequence locks, the header commitment filter, and block script execution), the headers-first processing layer (maybeAcceptBlockHeader over the real block index with assumed-valid tracking and old fork rejection), the stake node attachment layer (fetchStakeNode with the pruned-node regeneration walk and side chain replay), the reorganization engine (connectBlock/disconnectBlock with best state snapshots and reorganizeChain over dcrd-exact utxo cache semantics), the complete ProcessBlock intake path (duplicate/orphan/invalid handling, headers-first data linking, and best chain selection), the manual chain manipulation surface (InvalidateBlock/ReconsiderBlock/ForceHeadReorganization), the ticket database persistence layer over redb (byte-identical bucket rows against dcrd's ffldb), durable chain state (createChainState/initChainState with restart round trips over the reorganization ground truth), mining support (CheckConnectBlockTemplate, ticket exhaustion checks, and the chain query surface), the treasury account with the complete treasury spend checks (balances, vote tallies, and expenditure policies), and the RPC/netsync query surface (threshold state queries, vote counting, stake version walks, block locators, and the stake difficulty estimators), completing the internal/blockchain port — pinned by dcrd's own test vectors, by synthetic-chain
  scenarios generated inside dcrd's internal package, and end to end by
  dcrd's own full block test battery (`fullblocktests`): 573 instances of
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
- `dcroxide-mining` — the beginnings of block template mining support
  from dcrd's `internal/mining`: the transaction dependency graph and
  mining view with ancestor statistics tracking, the priority queue
  with Go's exact heap semantics, and the priority calculation, now
  wired into the mempool's mining hooks
- `dcroxide-gcs` — Golomb-coded set filters (versions 1 and 2) and the
  DCP0005 version 2 block committed filters for light clients, matched
  differentially against dcrd over random filters and structured blocks
  with real stake transactions
- `tools/oracle` — Go shim linking dcrd's own packages (pinned to the
  release-v2.1.5 module versions) as a test oracle over line-delimited JSON

## Layout

- `crates/` — the Cargo workspace (one crate per dcrd package, see PARITY.md)
- `tools/oracle/` — the dcrd differential-test oracle (Go)
- `fuzz/` — `cargo-fuzz` targets (nightly toolchain)
- `docs/adr/` — architecture decision records

## Development

Rust ≥ 1.85 (MSRV) and a Go toolchain (for the oracle-backed differential
tests; without Go those tests skip).

```sh
cargo test --workspace          # unit + KAT + differential tests
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo +nightly fuzz list                       # requires cargo-fuzz
cargo +nightly fuzz run wire_msgtx_decode
```

Consensus-tagged crates enforce `#![forbid(unsafe_code)]` (workspace-wide
lint) and `#![deny(missing_docs)]`.

## License

ISC. Portions derived from dcrd and dcr-rs, both ISC; see [LICENSE](LICENSE)
and per-file attribution headers.
