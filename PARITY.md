# Parity ledger

Maps each dcrd package to its dcroxide crate and tracks parity status against
the pinned tag **`release-v2.1.5`** (wire protocol 12, JSON-RPC 8.3.0).

Status legend:

- **—** not started
- **WIP** implementation in progress
- **vectors** dcrd test vectors ported or regenerated via `tools/oracle`
- **diff** live differential coverage against the dcrd oracle
- **parity** vectors + differential + fuzz sign-off complete

| dcrd package | dcroxide crate | Status | Notes |
|---|---|---|---|
| `crypto/blake256` | `dcroxide-crypto` | vectors + diff | Vendored from dcr-rs `fd32c1a`; KATs regenerated via oracle; live differential test + incremental-hashing fuzz target |
| `crypto/ripemd160` | `dcroxide-crypto` | — | RustCrypto re-export planned (Phase 1) |
| `crypto/rand` | `dcroxide-crypto` | — | Phase 1 |
| `chaincfg/chainhash` | `dcroxide-chainhash` | — | Phase 1 |
| `dcrec` (ECDSA/Ed25519/Schnorr) | `dcroxide-dcrec` | — | Phase 1; decision D3 pending |
| `math/uint256` | tbd | — | Phase 1 |
| `wire` | `dcroxide-wire` | — | Phase 2 |
| `chaincfg` | `dcroxide-chaincfg` | — | Phase 3 |
| `txscript` (+ `stdaddr`, `sign`) | `dcroxide-txscript` | — | Phase 4 |
| `blockchain/stake` | `dcroxide-stake` | — | Phase 5 |
| `blockchain/standalone` | `dcroxide-standalone` | — | Phase 6 |
| `gcs` | `dcroxide-gcs` | — | Phase 9 |
| `database` (+ `ffldb`) | `dcroxide-database` | — | Phase 7; decision D1 pending |
| `internal/blockchain` | `dcroxide-blockchain` | — | Phase 8 |
| `internal/blockchain/indexers` | `dcroxide-indexers` | — | Phase 9 |
| `internal/mempool`, `internal/fees` | `dcroxide-mempool` | — | Phase 10 |
| `internal/mining` | `dcroxide-mining` | — | Phase 10 |
| `mixing`, `mixing/mixpool`, `mixing/utxoproof` | `dcroxide-mixing` | — | Phase 12 |
| `addrmgr` / `internal/connmgr` / `peer` | `dcroxide-addrmgr` / `-connmgr` / `-peer` | — | Phase 11 |
| `internal/netsync` | `dcroxide-netsync` | — | Phase 11 |
| `internal/rpcserver`, `rpc/jsonrpc/types`, `dcrjson` | `dcroxide-rpc` | — | Phase 13 |
| `rpcclient` | `dcroxide-rpcclient` | — | Phase 13 |
| `container/apbf`, `container/lru` | `dcroxide-containers` | — | Phase 11 |
| `certgen` | `dcroxide-certgen` | — | Phase 13 |
| `base58`, `bech32` | `dcroxide-base58` / `dcroxide-bech32` | — | Phase 1–2 |
| `dcrutil` | `dcroxide-dcrutil` | — | Phase 1–2 |
| daemon (`config`, `server`, `cmd/*`) | `dcroxide` (bin) | — | Phase 14 |
