# ADR-0008 — Curated lint set: what is adopted, deferred, and refused

- **Status:** Accepted
- **Date:** 2026-08-07

## Context

The workspace forbids `unsafe_code`, denies `missing_docs`, and warns
`clippy::all` plus `clippy::arithmetic_side_effects`; CI escalates warnings
to errors. That is clippy's default groups and two additions. Cuprate — the
from-scratch Rust Monero node — instead curates roughly 280 lints at deny,
adopted through a documented cold/warm/hot process, and keeps the lints it
rejected as comments beside the ones it took so the reasoning survives.

Since 2026-09-26 no crate allows `arithmetic_side_effects` crate-wide.
Until then `blockchain`, `wire`, `txscript`, `stake`, `standalone`,
`mempool`, `mining`, `uint256`, `chainhash`, `chaincfg`, `database`, `gcs`,
`fees` and `base58` (and `testutil`, and `dcroxide-node`'s `addblock` and
`promptsecret` binaries) did, so plain operators there were never linted.
Every operator those allows hid is now explicit in one of two ways. Where
dcrd's Go arithmetic wraps, the port calls `wrapping_*` at the width dcrd
computes in, so a `uint32` sum wraps at `u32` even where the port holds it
in an `i64`. Everywhere else the operator stays, under
`#[allow(clippy::arithmetic_side_effects, reason = "...")]` on the smallest
item that can carry it (a statement, block, match arm, loop or short
function), and the reason states the bound that keeps each site it covers
in range: a parameter's value on every network, a length checked above, a
loop's own limit. A bound on a value read from a header has to hold for
values no check has vetted, because fast-add skips some header checks for
assumed-valid ancestors.

Division, remainder and shifts have rules of their own, because turning
overflow checks off does not make them behave as Go's do. Rust's `/` and
`%` panic on `MIN / -1` and `MIN % -1` in every profile, release included,
where Go yields `MIN` and `0`. A signed `/` or `%` keeps its operator only
when its reason shows the divisor cannot be `-1` or the dividend cannot be
`MIN`; otherwise it is `wrapping_div` or `wrapping_rem`, which match Go
exactly. A zero divisor panics in both languages, and the lint also flags
`wrapping_div` by a divisor that is not a constant, so that allow says why
the divisor is nonzero or that dcrd panics the same way. Big-integer
division differs in rounding instead: `num-bigint`'s `/` truncates, dcrd's
`big.Int.Div` is Euclidean, and the two disagree for a negative dividend,
so a port of `Div` computes Euclidean division unless its reason shows
the dividend is non-negative: through `go_big_div`
(`dcroxide-blockchain/src/difficulty.rs`) inside `dcroxide-blockchain`,
where it is crate-private, and elsewhere through an equivalent correction,
as `dcroxide-stake`'s `calculate_ticket_return_amounts` makes over
`Uint256`. The lint does not flag shifts on primitive integers, so each
was checked by hand. Rust's `<<` and `>>` panic in dev builds on a count
at or past the operand's width and mask the count in release, as
`wrapping_shl` and `wrapping_shr` always do; Go yields zero, or the sign
fill for a signed `>>`. A shift keeps its operator when its count is
provably below the width, and computes Go's result explicitly where it is
not, as `checked_shl(..).unwrap_or(0)` does in `txscript`'s
`make_script_num`.

Release builds wrap on overflow (`overflow-checks = false`, pinned in
`[profile.release]` and asserted for `release` and `dist` by
`dcroxide-node/tests/panic_policy.rs`). Dev and test builds panic, so CI's
`test-wrapping` job runs the whole suite a second time with
`CARGO_PROFILE_DEV_OVERFLOW_CHECKS=false`.

Making every site explicit surfaced eleven places where the port's
arithmetic was not dcrd's. All eleven are fixed and pinned by tests, and
none changes what the node does with honest data on the built-in networks:
each needs corrupt stored rows, custom network parameters, a stake
difficulty fast-add never checked, a sum the mempool's own limits rule
out, a direct call into a public function, or a mining time offset beyond
292 years. Five other differences it found stay open, and PARITY.md
records them. Module-level allows remain in 38 modules this work did not
take up, and `tests/*.rs` keep their file-level allows. The 2026-09-26
addendum lists all of these.

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

`SigCache` had the same bug in a hashed container. It evicted
`valid_sigs.keys().next()` from a **`HashMap`**, on the assumption that
`RandomState` made the victim arbitrary. `RandomState` only randomizes which
key lands in which bucket; hashbrown iteration always starts at bucket zero.
The victim was therefore always the lowest occupied bucket, the front of the
table drained, and each new entry was evicted by the next add. It now draws
a uniform index into a key vector with a keyed hash
(`crates/dcroxide-txscript/src/sigcache.rs`). The rule: neither an ordered
nor a hashed container's iteration order is an adversary-proof arbitrary
pick. Draw one.

Converting a `HashMap` to a `BTreeMap` in the name of determinism does not
supply that draw; it only trades one predictable victim for another, and
the orphan pool shows how cheaply a sorted one is ground. Ordered containers
are the right default for anything whose iteration is observable; neither
kind is a substitute where the code needs an adversary-proof arbitrary
pick. The distinction is the rule, not the container.

### Adopted, sequenced

- **`iter_over_hash_type`** — cheap ratchet, not a bug-finder, and worth
  saying why. The consensus crates hold no hash containers at all:
  `dcroxide-blockchain` is 69 ordered containers to 0 hashed,
  `dcroxide-mining` 66 to 0, `dcroxide-mempool` 26 to 0; `stake`,
  `chaincfg`, `chainhash`, `wire`, `uint256`, `dcrec` and `crypto` hold
  neither kind, and `standalone`, `gcs` and `fees` hold only ordered ones. All 33 source hits are in
  P2P, RPC, mixing and node code — 18 in `dcroxide-mixing/src/mixpool.rs`,
  6 in `dcroxide-addrmgr/src/manager.rs`, the rest scattered. So the lint
  defends a property the consensus core already has by construction. Adopt
  it to keep it that way, triaging each site into *sort it* (where order
  escapes — `addrmgr` writes `peers.json` entry order, and picks which
  `StallReason` is reported) or `#[expect]` with a stated reason (where it
  provably cannot). Note the blind spot: it fires only on `for` loops, so
  the `.next()` picks discussed above were invisible to it, the
  `HashMap` one included.
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

## Addendum, 2026-09-25 — `dcroxide-winsvc` writes unsafe code of its own

The consequence above said `dcroxide-winsvc` denies rather than forbids
`unsafe_code` only because the `windows-service` entry macro expands an
unsafe block into it. It now also writes three unsafe blocks itself, the
workspace's one audited exception to the no-unsafe rule. Two Windows
behaviours dcrd gets from Go's runtime and `os` package have no safe std
equivalent. The first is a console control handler that holds a console
close, logoff or shutdown until the daemon has shut down
(`SetConsoleCtrlHandler`, in `console.rs`); Go's handler blocks the same
way. The second is adopting the inherited `--piperx`/`--pipetx` pipe handles
that `os.NewFile` adopts (`GetCurrentProcess` with `DuplicateHandle`, then
`OwnedHandle::from_raw_handle` on the duplicate, in `pipe.rs`). Both call
Windows through a direct `windows-sys` 0.61.2 dependency, the version the
lockfile already carried, which
[docs/dependency-ledger.md](../dependency-ledger.md) records.

The lint level stays `deny`, not `allow`. Each block carries its own
`#[allow(unsafe_code)]` on the one statement that needs it, with a
`// SAFETY:` comment stating the invariants, and the crate documentation
lists all three. Any further unsafe code in the crate fails the build until
it is reviewed and allowed the same way. Every block is Windows-only, so the
Linux lint job never compiles them. `cargo clippy --target
x86_64-pc-windows-msvc -p dcroxide-winsvc --all-targets -- -D warnings`
checks them from Linux, and CI's Windows test job builds and runs them. No
other crate gains unsafe code: `dcroxide-node` still forbids it, and calls
the two pieces through safe functions.

## Addendum, 2026-09-26 — the crate-level `arithmetic_side_effects` allows are gone

The refactor the Context once called open and deferred is done, and the
Context now states the policy it left. It went crate by crate, and through
`dcroxide-blockchain` and `txscript` module by module behind temporary
module allows marked `arith-lint: pending`, none of which remains. A grep of
`crates/*/src` counts what it added: 650 outer
`#[allow(clippy::arithmetic_side_effects, reason = "...")]` attributes (271
in `dcroxide-blockchain`, 80 in `txscript`, 62 in `wire`, 49 in `mining`,
and 35 or fewer in each other crate) and 141 `wrapping_*` calls (78 in
`dcroxide-blockchain`, 27 in `mining`, 10 in `standalone`, 9 in `stake`, 6
each in `database` and `fees`, 3 in `txscript` and 2 in `gcs`). `base58`,
`chainhash`, `chaincfg`, `mempool`, `testutil`, `uint256` and `wire` needed
no new `wrapping_*`: none of their operators reaches an edge where dcrd's
would wrap, and `uint256`'s modular limb arithmetic was already written
with `wrapping_*` and `overflowing_*`. The wrapping sites are the ones dcrd
computes at a fixed width over values a block, a stored row or a parameter
can drive: fee, subsidy, treasury and UTXO-set sums, vote and stake-version
tallies, `uint32` heights and counters, the block files' `uint32` write
offset, record length and file number (as in dcrd's ffldb), GCS filter
deltas, the script engine's byte-width small-integer and shift-count
arithmetic, and ASERT's shift count.

Where an allow can sit is narrower than the policy suggests. rustc rejects
a lint attribute on an assignment, a compound assignment or a block's tail
expression (E0658: attributes on expressions are unstable), and ignores one
on a `debug_assert!` statement, so those sites take the allow on a bare
block (`#[allow(...)] { x += 1; }`), a `let`, a loop, a match arm or the
enclosing function. An operator in an `if` condition puts the allow on the
whole `if`, whose reason must then bound every site inside it. Six
`#[cfg(test)]` modules carry one allow each for test arithmetic, and
`tests/*.rs` keep the file-level allows they had. CI's lint job runs on
Linux only and never compiles `cfg(windows)` arithmetic: the two sites in
`dcroxide-database`'s Windows `read_exact_at` loop show up only under
`cargo clippy --target x86_64-pc-windows-msvc`, and a change to
Windows-only arithmetic needs that run too.

The eleven divergences it fixed (the first bullet covers two), each pinned
by a test:

- `merge_difficulty` (three divisions) and `calc_next_stake_diff_v2` (two)
  divided big integers with truncation where dcrd's `big.Int.Div` is
  Euclidean. The results differ only for a negative dividend, which takes
  a negative stake difficulty or a candidate that wrapped past 2^63.
- `calc_ticket_return_amounts` subtracted 1 from an empty length in
  `usize` and panicked, where Go's `int` arithmetic gives an empty result.
- `calculate_treasury_balance` widened the coinbase maturity before
  subtracting 1. dcrd subtracts at `uint16`, so a maturity of zero looks
  65535 blocks back, where the port found no ancestor and read a zero
  balance.
- `deserialize_best_chain_state` checked and sliced the work sum in
  `usize` where dcrd uses `uint32`, which matters for records of 4 GiB or
  more.
- `read_deserialize_size_of_minimal_outputs` looped over a `u64` output
  count, where dcrd's `int(numOutputs)` turns negative at 2^63 and reads no
  outputs.
- The block-region read summed its file offset in `u64` where dcrd's
  ffldb wraps at `uint32`.
- The fee estimator's `fee / size * 1000` aborted on `i64::MIN / -1`, where
  Go wraps and leaves the transaction untracked.
- The stake node's height gates compared the `int64` parameters whole,
  where dcrd truncates them to `uint32` first.
- `median_adjusted_time` subtracted the mining time offset in seconds,
  where dcrd negates and scales it in `int64` nanoseconds, which wrap.
- The mining view summed ancestor signature operations in `i64`, where
  dcrd's sums are `uint32`.

Five differences it found stay open, and none is reachable with honest
data on the built-in networks. `gettxout` decodes a ticket's minimal
outputs, which dcrd's never touches; the treasury loader rejects
value-type flags that dcrd keeps; `GetStakeVersions` clamps its count in
`i64` where dcrd truncates to `int32`; the script tokenizer keeps `usize`
offsets where dcrd's are `int32`; and `is_treasury_vote_interval` returns
false for an interval of zero, where dcrd divides by it and panics.
PARITY.md records them: four under "Open: the port does not match dcrd
here", and the treasury value-type flags in the `internal/blockchain`
row's treasury-state clause.

Two kinds of allow are left. Module-level `#![allow]`s remain in 38
modules this work did not take up: eight in `dcroxide-node` (`addblock`,
`blockdb`, `config`, `flags`, `gostd`, `ipc`, `server`, `socks`), the rest
in `rpc`, `addrmgr`, `connmgr`, `netsync`, `mixing`, `certgen`, `dcrjson`,
`containers` and `indexers`, and three crypto modules: `crypto`'s
`blake256`, and `dcrec`'s `edwards` and secp256k1 `schnorr`. And 21 older
outer allows carry no reason, in `connmgr`, `dcrec` and `dcroxide-node`'s
`rpcrun.rs`. They are the next candidates, under the same rules.

The measured fallout above predates this and has not been re-measured. The
`clippy::allow_attributes` row (104, 93 in `src/`) and the bullet's
`arithmetic_side_effects` count (14) cover outer attributes only, so the
crate-level `#![allow]`s this removed never figured in them, while every
per-site attribute it added does. By the grep's count that row is now some
650 higher, and the `#[expect]` migration the bullet adopts, which would
catch an allow that outlives its site, covers that many more.
