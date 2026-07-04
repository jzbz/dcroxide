# Parity ledger

Maps each dcrd package to its dcroxide crate and tracks parity status against
the pinned tag **`release-v2.1.5`** (wire protocol 11, JSON-RPC 8.3.0; the
project brief says protocol 12, but the source at the pinned tag says 11 and
source wins).

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
| `chaincfg/chainhash` | `dcroxide-chainhash` | vectors + diff | `hash_test.go` vectors ported (incl. short-string zero-pad quirk); parse/display differential + fuzz target. Not ported: Go-specific plumbing (`SetBytes` pointer API, marshalers) |
| `dcrec/secp256k1` + `ecdsa` (type 0) | `dcroxide-dcrec` | vectors + diff | dcrd's exact DER + pubkey acceptance (all 25 error kinds, incl. hybrid keys) over libsecp256k1 per ADR-0006; TestSignatureParsing/TestParsePubKey/TestSignatureSerialize ported; differential: parse verdict+kind+values, RFC6979 sign byte-equality, verify verdicts incl. high-S; 2 fuzz targets. Not ported: compact-sig recovery (`SignCompact`/`RecoverCompact`, needed by RPC `verifymessage`, Phase 13); `PrivKeyFromBytes` mod-N reduction (we reject out-of-range keys instead — not an observable surface) |
| `dcrec/secp256k1/schnorr` (type 2) | `dcroxide-dcrec` | vectors + diff | EC-Schnorr-DCRv0 on k256 per ADR-0006; dcrd's `NonceRFC6979` ported exactly (raw-key HMAC variant, extra-data/version/iteration semantics) and pinned by dcrd's own nonce vectors; TestSchnorrSignAndVerify ported (RFC6979 + explicit-nonce rows); differential: sign byte-equality, verify verdicts, parse verdict+kind; fuzz target. Unreachable-by-construction kinds (`ErrPrivateKeyIsZero`, `ErrPubKeyNotOnCurve`) not represented |
| `dcrec/edwards` (type 1) | `dcroxide-dcrec` | vectors + diff | Ed25519 on curve25519-dalek with dcrd's exact (2017-agl) acceptance implemented explicitly: sig-R parse accepts non-canonical encodings incl. x=0/sign-bit; pubkey parse rejects x=0/sign-bit (the `X >= P` quirk) and re-serializes canonically; raw verify checks only S's top 3 bits (full `s < L` at parse, the consensus path). RFC8032 TEST 1 KAT; differential: sign+pubkey byte-equality, edge-biased parse verdicts, raw-verify verdicts incl. s+L malleation; fuzz target. Not implemented: scalar-based keys (`PrivKeyFromScalar`/`SignFromScalar`, wallet-side legacy) and threshold signing |
| `math/uint256` | `dcroxide-uint256` | vectors + diff | Full API port (arithmetic incl. Knuth 4.3.1D division, u64 variants, bitwise/shifts, comparisons, BE/LE bytes, text in bases 2/8/10/16) with dcrd's wrap-around and panic-on-zero-divisor semantics; differential across all 22 ops with boundary-biased operands; u128-reference + algebraic property tests; fuzz target. Not ported: `big.Int` interop (Go-specific), `fmt.Formatter` (Rust fmt traits provided; `text` is the parity surface) |
| `wire` | `dcroxide-wire` | vectors + diff | Framing (24-byte header, BLAKE-256 checksum, dcrd's exact validation order + error kinds) and **all 40 message types** at protocol 11 (39 decodable; reject is write-only per QK-0001): version (optional-field semantics), addr/getaddr, inv/getdata/notfound, getblocks/getheaders/headers/block, ping/pong/mempool, miningstate/getminingstate, sendheaders/feefilter, deprecated cf family + cfilterv2 + batched cfiltersv2, initstate/getinitstate, write-only reject (QK-0001), and the eight StakeShuffle mixing messages (`MsgMixPairReq`/`KeyExchange`/`Ciphertexts`/`SlotReserve`/`FactoredPoly`/`DCNet`/`Confirm`/`Secrets`) + `MixVect`. Frame differential: every message type × structured rounds byte-identical across all 4 networks + mutation verdict/kind parity; 3 fuzz targets + proptest laws. Not ported: mixpool identity/signed-data hashes (`WriteHash`/`WriteSignedData` — Phase 12 mixing crate), `PowHashV2` (BLAKE3, with standalone crate). Note: `ProtocolVersion` is 11 at the pinned tag (the project brief says 12; source wins) |
| `chaincfg` | `dcroxide-chaincfg` | vectors + diff | All four networks' `Params` ported field-for-field: genesis blocks built from the wire types (reproducing testnet's `TxHash`-instead-of-`TxHashFull` merkle root and simnet's zero-instead-of-null-sentinel genesis input witness), canonical agenda vote definitions shared across per-network deployment schedules, block-one ledgers extracted mechanically from `subsidytables.go` (mainnet: 3,146 payouts / 1,680,000 DCR). Parity pinned two ways: dcrd's own serialized-genesis test vectors + genesis hashes, and a canonical full-params dump compared byte-for-byte against dcrd's `chaincfg/v3 v3.3.0` via the oracle across all networks (every field, every deployment/vote/choice string, serialized genesis, BLAKE-256 ledger commitment). dcrd's init-time deployment validation (`init.go`) ported as data sanity tests. Not ported: deprecated `Checkpoints` (no network sets it), trivial Go-interface getter methods (fields are public), `DNSSeed.String` |
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
