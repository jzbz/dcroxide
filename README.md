# dcroxide

A from-scratch Rust implementation of the Decred full-node daemon, built as a
drop-in replacement for [dcrd](https://github.com/decred/dcrd).

Parity target: **dcrd `release-v2.1.5`** — wire protocol 12, JSON-RPC API
8.3.0. dcrd's behavior at that tag is the specification; see
[QUIRKS.md](QUIRKS.md) for deliberate bug-for-bug reproductions and
[PARITY.md](PARITY.md) for per-package status. The full plan lives in
[dcroxide-project-brief.md](dcroxide-project-brief.md).

**Status: pre-alpha — Phase 0/1 (rig + primitives).** Nothing here is ready
to validate, relay, or hold funds. Currently implemented:

- `dcroxide-crypto` — BLAKE-256 (vendored from
  [dcr-rs](https://github.com/jzbz/dcr-rs), KAT-pinned, differential-tested
  against dcrd live)
- `dcroxide-chainhash` — the 32-byte hash type with dcrd's byte-reversed
  string encoding, including its short-string parsing quirk
- `dcroxide-wire` — message framing with dcrd's exact validation order and
  error identities, plus every non-mix P2P message at protocol version 11
  (the eight StakeShuffle mixing messages are next); `MsgTx`, blocks,
  headers, filters, and state messages all under differential test,
  fuzzing, and round-trip property tests — including the first `QUIRKS.md`
  entry (write-only `reject`)
- `dcroxide-uint256` — fixed-precision 256-bit arithmetic (difficulty/work
  math) ported operation-for-operation from dcrd's `math/uint256`,
  differentially tested against it across every operation
- `dcroxide-dcrec` — all three Decred signature types with dcrd's exact
  acceptance rules and error identities: ECDSA-secp256k1 (type 0, over
  libsecp256k1), Ed25519 (type 1, over curve25519-dalek with dcrd's
  2017-agl verify semantics), and EC-Schnorr-DCRv0 (type 2, over k256 with
  dcrd's RFC6979 nonce variant); every signing path differentially verified
  byte-for-byte against dcrd
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
