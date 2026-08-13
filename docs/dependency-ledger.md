# Consensus- and security-critical dependency ledger

[SECURITY.md](../SECURITY.md) states the gap this file starts to close:
*"Nobody has read the dependencies."* `cargo-deny` runs on every push and
gates the RustSec advisory database, a licence allow-list, yanked crates and
unknown sources — an automated check against problems someone else already
found, not a review.

This ledger does not claim a review has happened. It records **a decision
per dependency**, so the trust status of the load-bearing subset is explicit
rather than implied, and so a version bump of one of them is a decision
rather than a silent `Cargo.lock` change. The precedent is
[ADR-0002](adr/0002-vendor-blake256-from-dcr-rs.md): BLAKE-256 was vendored
into the tree precisely because it is consensus-critical.

Cuprate reached the same problem from the other side — pinning crypto and
storage crates to exact git revisions, maintaining frozen forks, and
eventually co-maintaining its curve library. Most of those rungs do not fit
a single-maintainer pre-alpha, and the sizes below are why: vendoring
`ring` would mean adopting 151k lines of C and assembly.

## Decision vocabulary

- **vendored** — the code is in this tree, pinned and attributed.
- **reviewed@V** — a human has read the parts this node depends on, at
  version V. Bumping past V requires a fresh look.
- **accepted** — used as-is on stated grounds, without a read. This is an
  honest status, not a placeholder: most entries below are here.
- **declined** — considered and not adopted.

The scope is the ~12 crates whose behaviour is observable in consensus, key
handling, or the network surface, out of 226 packages in the lock file.
Everything else is `accepted` by default and not listed.

## The set

| crate | version | role | decision | notes |
|---|---|---|---|---|
| `secp256k1` | 0.29.1 | ECDSA (signature type 0) | accepted | Bindings to the audited libsecp256k1 C library, per [ADR-0006](adr/0006-secp256k1-backend.md). dcrd's acceptance rules are not in this crate — DER parsing, low-S, error identities are all implemented in `dcroxide-dcrec` in front of it and differential-tested against dcrd. |
| `secp256k1-sys` | 0.10.1 | vendored libsecp256k1 | accepted | ~59k lines of vendored C. Declining to vendor further: this is the most widely deployed secp256k1 implementation in the ecosystem and re-vendoring it here would fork that scrutiny, not add to it. It is also the reason the no_std check gates only the Rust side (see the CI job comment). |
| `k256` | 0.13.4 | EC-Schnorr-DCRv0 group ops | accepted | Pure Rust. Used for raw scalar/point arithmetic no packaged signing API exposes. Its `precomputed-tables` feature is now behind `dcroxide-dcrec`'s `std`. |
| `curve25519-dalek` | 4.1.3 | Ed25519 (signature type 1) | accepted | ~33k lines. dcrd's exact (2017-agl) acceptance behaviour lives in `dcroxide-dcrec::edwards` on top of it, not in it. |
| `blake3` | 1.8.5 | DCP0011 v2 PoW hash | **reviewed@1.8.5, `pure`** | One call site: `dcroxide-wire/src/blockheader.rs`, hashing a 180-byte header. The default build compiles ~33k lines of C and SIMD assembly (SSE2/SSE4.1/AVX2/AVX512 — 24 object files) to accelerate long inputs. At 180 bytes that acceleration is worthless, so the `pure` feature is enabled: no C toolchain, no assembly, identical output (verified against the official BLAKE3 KATs for the empty string, `abc`, and a 180-byte input). |
| `redb` | 4.1.0 | chain metadata store | accepted, [ADR-0004](adr/0004-storage-backend.md) | ~30k lines of Rust. Chosen for crash-safety without a C toolchain; its commit shape is the tracked cost. Read closely in one respect — the free-page and transaction-tracker behaviour analysed in ADR-0004's 2026-08-07 addendum — but not reviewed as a whole. Bumped from 2.6.3 on 2026-08-13 (`7d2fe28`, and ADR-0004's addendum of that date): two majors, and the on-disk format changed with them. redb 4 reads only file format 3 and returns `UpgradeRequired` for a 2.x file, so a data directory written before that date is refused with a typed error rather than misread, and has to be re-synced. 2.6.3 remains in the lock file only as the pinned dev-dependency `redb2 = { package = "redb", version = "=2.6.3" }`, which writes a genuine v2 store for the refusal test; it is not linked into the daemon. |
| `ring` | 0.17.14 | TLS crypto (via rustls) | accepted | ~151k lines of C and assembly. Reachable only on the RPC/websocket surface, which requires credentials and is off entirely under `--norpc`. Vendoring is not viable at this size for this project. |
| `rustls` | 0.23.41 | RPC/websocket TLS | accepted | Same reachability as `ring`. |
| `getrandom` | 0.2.17 / 0.3.x | entropy | accepted | Two majors coexist: the 0.3 line is what dcroxide calls directly (nonces, the orphan-eviction draw, secret files); 0.2 arrives transitively through `p256`/`p384`/`p521`'s `rand_core` in `dcroxide-certgen`, which is production TLS key generation. Worth collapsing to one major when the certgen curve crates allow. |
| `sha2`, `hmac` | 0.10.9, 0.12.1 | RFC6979 nonces | accepted | RustCrypto, widely used; dcrd's exact RFC6979 variant is ported in `dcroxide-dcrec`, not taken from these. |
| `siphasher` | 1.0.3 | GCS filter hashing | accepted | Consensus-observable through `dcroxide-gcs`; the filter construction itself is ported and differential-tested. |
| `num-bigint` | 0.4.8 | difficulty math | accepted | Used by `dcroxide-blockchain`; the uint256 path that matters most is `dcroxide-uint256`, which is a port, not a dependency. |

## What is deliberately not here

`cargo-vet` is not wired up. It is the natural mechanical backing for this
ledger — audits committed to the repo, so bumping a critical crate requires
a recorded decision — and it should be adopted when there is more than one
maintainer to exchange audits with, or when the project imports another
organisation's audit set. For a single maintainer it would currently
restate this table in a format nobody else reads. Recorded as a decision
rather than an oversight.

Vendoring beyond ADR-0002 is declined for every crate above, on size:
`ring` is ~151k lines, `secp256k1-sys` ~59k, `curve25519-dalek` ~33k,
`redb` ~30k. ADR-0002's precedent applies to code small enough to own,
which BLAKE-256 was and none of these are.

## Maintaining this

Add a row when a dependency becomes consensus-observable or reaches key
material. Change a row's decision when someone actually reads the crate —
`reviewed@V` is a claim about a person having done that, and should not be
written otherwise.
