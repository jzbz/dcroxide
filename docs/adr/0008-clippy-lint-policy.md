# ADR-0008 — Curated lint set: what is adopted, deferred, and refused

- **Status:** Accepted
- **Date:** 2026-08-07

## Context

The workspace denies `unsafe_code`, denies `missing_docs`, and warns
`clippy::all` plus `clippy::arithmetic_side_effects`; CI escalates warnings
to errors. That is clippy's default groups and two additions. Cuprate — the
from-scratch Rust Monero node — instead curates roughly 280 lints at deny,
adopted through a documented cold/warm/hot process, and keeps the lints it
rejected as comments beside the ones it took so the reasoning survives.

The interesting question for a **port** is narrower than "which lints are
good": which lints catch the mistakes that Go-to-Rust transcription
actually makes. Two candidates look decisive on paper —
`iter_over_hash_type`, because Go deliberately randomizes map iteration and
transcribed code may depend on or mask that, and the cast lints, because
fixed-width conversion drift is the classic transcription bug.

Both were measured rather than assumed.

## Measured fallout

`cargo clippy --workspace --all-targets` with each lint at warn, on
1.97.1/Linux-x86_64, deduplicated by lint plus file, line and column. The
baseline is clean: the workspace emits zero warnings today, so every number
below is net new.

| lint | total | in `src/` |
|---|---:|---:|
| `clippy::cast_possible_truncation` | 968 | 541 |
| `clippy::cast_sign_loss` | 281 | 226 |
| `clippy::cast_possible_wrap` | 237 | 142 |
| `clippy::allow_attributes` | 104 | 93 |
| `unreachable_pub` | 59 | 43 |
| `clippy::iter_over_hash_type` | 34 | 33 |

Two mechanical facts, both verified rather than assumed. `unreachable_pub`
is a **rustc** lint: writing `clippy::unreachable_pub` names an unknown
lint and silently reports zero, so it belongs under
`[workspace.lints.rust]` and it also gates the MSRV and no_std jobs, where
different `cfg` changes which items are reachable. And a package cannot
combine `[lints] workspace = true` with a lint table of its own — cargo
rejects the manifest — so 31 of the 32 crates have no per-crate escalation
path through `Cargo.toml`; a crate-scoped ratchet has to be a
`#![deny(...)]` in `src/lib.rs`, which reaches the lib and its unit tests
but not `tests/*.rs`.

## Decision

### Refused: `cast_possible_truncation`

Not adopted at any level, and this refusal is the substantive decision
here.

`as` between integers is a truncating two's-complement conversion, and so
is Go's `uint32(x)`. When this port transcribes dcrd's `uint32(len(x))` or
an `int64`-to-`uint32` narrowing, `as` is not a shortcut for the correct
operator — it **is** the correct operator, the one whose behaviour matches
the specification. The alternatives are worse in a specific way:
`try_from().expect()` converts a silent, dcrd-faithful truncation into a
panic, and with `panic = "abort"` on the release profile (ADR-0005) that is
a remote-triggerable process abort where dcrd merely wraps.

The population confirms it is transcription rather than carelessness. The
dominant type pairs are `usize`→`u32`, `u64`→`u32`, `u64`→`usize` and
`i64`→`u32`; `dcroxide-blockchain/src/difficulty.rs` alone contributes
dozens from `params.work_diff_windows as usize`, where the field is `i64`
only because dcrd's is, and holds 4 or 20. A large share of the remainder
are `N`→`usize` conversions that cannot truncate on any 64-bit target, and
every CI target is 64-bit.

Denying this lint would mean annotating some 800 sites to assert what the
parity contract already asserts.

### Refused: converting hash containers to ordered ones for "determinism"

Recorded because the reflex is tempting and this codebase contains the
counterexample in both directions.

`TxPool::limit_num_orphans` evicted `orphans.values().next()` from a
`BTreeMap` — always the numerically smallest transaction hash. dcrd takes
the first entry of a `range` over a Go map, and its comment relies on that
being unpredictable. Against an ordered map it is not: grinding a large
hash is milliseconds, so an attacker's orphans were never evicted. Fixed by
drawing the index from a CSPRNG.

`SigCache` does the same thing correctly: it evicts
`valid_sigs.keys().next()` from a **`HashMap`**, where `RandomState` is
seeded per map, so the victim is arbitrary and untargetable — exactly
dcrd's property, and documented as such at the call site.

Converting that `HashMap` to a `BTreeMap` in the name of determinism would
manufacture the orphan bug. Ordered containers are the right default for
anything whose iteration is observable; they are the *wrong* choice where
the code needs an adversary-proof arbitrary pick. The distinction is the
rule, not the container.

### Adopted, sequenced

- **`iter_over_hash_type`** — cheap ratchet, not a bug-finder, and worth
  saying why. The consensus crates hold no hash containers at all:
  `dcroxide-blockchain` is 69 ordered containers to 0 hashed,
  `dcroxide-mining` 66 to 0, `dcroxide-mempool` 26 to 0, and `stake`,
  `chaincfg`, `chainhash`, `wire`, `uint256`, `dcrec`, `crypto`,
  `standalone`, `gcs` and `fees` hold neither. All 33 source hits are in
  P2P, RPC, mixing and node code — 18 in `dcroxide-mixing/src/mixpool.rs`,
  6 in `dcroxide-addrmgr/src/manager.rs`, the rest scattered. So the lint
  defends a property the consensus core already has by construction. Adopt
  it to keep it that way, triaging each site into *sort it* (where order
  escapes — `addrmgr` writes `peers.json` entry order, and picks which
  `StallReason` is reported) or `#[expect]` with a stated reason (where it
  provably cannot). Note the blind spot: it fires only on `for` loops, so
  the `keys().next()` calls discussed above are invisible to it in both
  the correct and the incorrect case.
- **`allow_attributes`** — 104 sites, all outer attributes, dominated by
  `too_many_arguments` (49), `arithmetic_side_effects` (14) and
  `missing_docs` (11). Migrating them to `#[expect]` makes a suppression
  fail once the underlying warning goes away, so a stale
  `arithmetic_side_effects` allow cannot rot silently. Verified that
  clippy-namespaced `#[expect]` is inert under plain `cargo check`, so the
  MSRV and no_std jobs are unaffected.
- **`unreachable_pub`** — 43 source sites, purely mechanical, hygiene
  rather than a porting hazard. `dcroxide-txscript/src/stack.rs` alone
  accounts for 18 methods on an already-`pub(crate)` type.

### Deferred

`cast_sign_loss` and `cast_possible_wrap`, 518 warnings between them. The
fix is `.cast_signed()` / `.cast_unsigned()`, stable since 1.87 and so
available under the 1.94 MSRV, and provably semantics-preserving even when
a truncating `as` follows. Sequence it crate by crate behind the
differential suites; `cargo clippy --fix` will not help, since only a
minority of hits carry a suggestion and every one is `MaybeIncorrect`. The
value is documented intent, not changed behaviour.

### Not expressible as a lint, and worth more than any of them

Rust's float-to-int `as` **saturates**; Go's `int64(f)` for an out-of-range
finite float is implementation-defined and yields `i64::MIN` on amd64. Both
`new_amount` implementations (`dcroxide-rpc/src/handlers.rs`,
`dcroxide-node/src/config.rs`) mirror dcrd's `dcrutil.NewAmount` including
its NaN/Inf-only guard, so `(scaled + 0.5) as i64` diverges from Go for
large finite inputs — Rust gives `i64::MAX` where dcrd gives `i64::MIN`.
Roughly 30 float-to-int sites deserve an audit; each is either range-checked
by its caller or a quirk to record. No lint in this set expresses it, and it
is currently buried under 968 truncation warnings — which is its own
argument against adopting that lint as a proxy for attention.

## Consequences

- The lint config gains a decision record. Refusals are kept here rather
  than as an absence, so the next person to propose `cast_possible_truncation`
  finds the measurement and the reasoning instead of re-deriving them.
- Adoption is staged, and each stage's fallout is enumerated above, so no
  stage is open-ended.
- `dcroxide-winsvc` does not inherit the workspace lints — it restates them
  by hand, because the `windows-service` entry macro expands an `unsafe`
  block and the crate cannot forbid `unsafe_code`. Every workspace lint
  addition must be mirrored there. Its `all = "warn"` also lacks
  `priority = -1`, which any specific clippy lint added alongside will
  require.
