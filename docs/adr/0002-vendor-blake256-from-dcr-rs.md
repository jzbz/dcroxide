# ADR-0002 — Vendor BLAKE-256 from dcr-rs

- **Status:** Accepted — decision D6 closed by the 2026-10-26 addendum
- **Date:** 2026-07-03 (accepted), 2026-10-26 (addendum: D6 closed, a
  one-time import owned here)

## Context

BLAKE-256 (14-round SHA-3-finalist BLAKE, not BLAKE2/BLAKE3) hashes nearly
everything in Decred: txids, pre-DCP0011 block hashes, sighashes, address
hashes, base58check checksums, merkle trees. No maintained Rust crate exists.
[dcr-rs](https://github.com/jzbz/dcr-rs) (ISC) carries a clean `no_std`
implementation pinned by known-answer vectors generated from dcrd's
`crypto/blake256`.

## Decision

Vendor `blake256.rs` from dcr-rs at commit `fd32c1a` into `dcroxide-crypto`,
with SPDX/attribution header and the dcr-rs copyright line added to the
repository `LICENSE`. Keep the KAT suite, and re-verify the vectors against
dcrd continuously via the `tools/oracle` differential test rather than
trusting the inherited fixtures (brief §6 Phase 1).

The broader D6 question (upstreaming to dcr-rs vs. hard fork of the whole
crate) stays open; this ADR covers only BLAKE-256, which we own from here on
(dcroxide is its natural long-term home — it is on the txid/merkle hot path
and will eventually want SIMD work that is out of scope for a signing-firmware
crate).

## Consequences

- We maintain the implementation ourselves: KAT + differential + fuzz
  coverage from day one, later optimization freedom.
- Divergence from dcr-rs upstream is possible; the vendored header records
  the source commit so diffs stay tractable.
- Remaining dcr-rs candidates (tx serialization, sighash, addresses, base58)
  get their own decision when their phase starts.

## Addendum, 2026-10-26 — D6 closed: a one-time import, owned here

The Decision above left the broader D6 question open, upstreaming to dcr-rs
or a hard fork of the whole crate, and the Consequences deferred the
remaining dcr-rs candidates, each to a decision of its own. On 2026-10-26
the project owner closed D6. `blake256.rs` is a one-time import from dcr-rs
at `fd32c1a`, and dcroxide owns it: neither repository tracks the other on
any schedule, in either direction, and dcroxide has no obligation to send
changes upstream. `6d024eb` already read this ADR that way, fixing a lint
in the file instead of allowing it because, in its message's words,
ADR-0002 "records that dcroxide owns it from that point on".

**The other candidates came from Decred's Go code.** They were ported within a
day of this ADR, each from the Go package its commit message names: `wire`'s
`MsgTx` and block header in `15a7ccb`, with vectors from wire v1.7.5;
`decred/base58` v1.0.6, the base58 package dcrd requires, and `stdaddr` in
`c3dc64a`; and `txscript/v4` v4.1.2, its signature hash included, in `7d69c6c`.
So the whole-crate half of D6 has no subject left. Each file names dcrd or
`decred/base58` as what it mirrors (`crates/dcroxide-base58/src/lib.rs:2-3`,
`crates/dcroxide-txscript/src/sighash.rs:2`,
`crates/dcroxide-txscript/src/stdaddr.rs:2`,
`crates/dcroxide-wire/src/msgtx.rs:2-3`), and no file under `crates/` but
`blake256.rs` mentions dcr-rs. That shows what is marked, not that nothing else
was copied: the code was not compared. Nothing records why dcr-rs's versions
were passed over, but, it is inferred, they could not have served unchanged:
dcr-rs at `fd32c1a`, as still at `66a2ec9`, encodes base58 with the `bs58`
crate (`src/hashing.rs:36,41` at `fd32c1a`), where `dcroxide-base58` reproduces
`decred/base58`'s quirks, and computes only the `SigHashAll` signature hash
(`src/sighash.rs:13`). The brief's week-1 action item, to contact the dcr-rs
author about upstreaming or forking (§2.1), is moot as well: dcr-rs, like
dcroxide, is the project owner's repository.

**Why no tracking.** The two copies have drifted apart since `fd32c1a`,
each for its own project. Here, `6d024eb` (2026-08-22) moved the block
loop to `as_chunks`, and `5590b07` (2026-10-11) wrote out the fourteen
rounds of `compress` for throughput and added
`counter_high_word_is_mixed_in`, whose two digests are dcrd's. In dcr-rs
the only commits to touch the file after `fd32c1a`, up to `66a2ec9`, are
`89932d4` (2026-07-29), which added a `Drop` that zeroizes `buf` and `h`,
declined here in `72c2e0f` for the reasons the file's header gives (lines
7-18), and `b65424b` (2026-08-25), which changed a comment. dcr-rs serves
signing firmware and runs secret scalars through the hasher; dcroxide
hashes no secrets and tunes for sync speed. Tracking would have meant a
recurring read of dcr-rs for one decline and one comment, and it would add
little to correctness here: this copy is compared with dcrd live on every
CI run, where `DCROXIDE_REQUIRE_ORACLE` makes a missing Go toolchain a
failure (`.github/workflows/ci.yml:14-15`), over the 17 KAT lengths and
5,000 random inputs of up to 4,096 bytes
(`crates/dcroxide-crypto/tests/oracle_differential.rs`), and the
high-counter test reaches the counter's high word, which those inputs
leave at zero. The Consequences' "diffs stay tractable" no longer holds
for `compress` or for the full-block loop of `update`: a dcr-rs change to
either would not apply here as a patch.

**One clause.** Outside `compress` and that loop, the code that computes a
digest is still byte-identical in the two copies, compared with dcr-rs at
`66a2ec9`, `finalize` and its padding included, and so is the `DCRD_KATS`
table. A digest bug there would be in both. A correctness fix that changes
a digest, found in either copy, is therefore checked against the other; if
the other needs it too, the fix there is that repository's own change. The
check is owed only when such a fix is found, so there is no "reviewed up
to" marker to go stale, the failure mode `72c2e0f`'s message says this
codebase keeps producing. dcr-rs at `66a2ec9` does not mention dcroxide,
so the half of the clause that starts there rests on this record alone.

**What it costs.** A change in either copy that leaves every digest alone
(a comment, a performance finding, hardening like the `Drop`) is not
looked for in the other. `b65424b` is one: its comment records that LLVM
elides the copy dcr-rs stages each full block through, the assembly being
identical with and without it on x86-64 and thumbv7em-none-eabihf at Rust
1.85. That bears on the comment at
`crates/dcroxide-crypto/src/blake256.rs:227-230`, from `6d024eb`, which
says `as_chunks` removes a copy that `chunks_exact` forced. A scratch
compile of the hasher in both forms at 1.98.1 for x86-64 (opt-level 3, one
codegen unit, no LTO) found no block copy in either; thumbv7em and the
release profile's thin LTO were not checked. Correcting that comment is
outside D6 and is not decided here. dcr-rs, for its part, keeps its looped
`compress` and lacks the high-counter test unless they are ported there as
dcr-rs work, which is not decided here either.

**Later imports.** The rule covers BLAKE-256 alone. Any later import from
dcr-rs needs a decision of its own, an addendum here or a new ADR, and
porting from dcrd stays the default, as for every other package. Of what
the brief lists dcr-rs as offering (§2.1), everything but HD keys is now in
the tree, BLAKE-256 from dcr-rs and the rest from Decred's Go code. The
brief wants HD keys only for the optional `hdkeychain` library-parity
milestone, not for the daemon, and dcroxide has no `hdkeychain` port.

**Attribution stays.** The import is credited in `LICENSE` (line 4), the
file's header (lines 1-5), `README.md` (lines 213-214 and 839) and
`PARITY.md`'s `crypto/blake256` row, which meets the brief's "either way
pin + attribute" (§9). Each stays for as long as code derived from dcr-rs
remains. No code, manifest or CI change follows from this addendum: dcr-rs
is in no manifest and not in `Cargo.lock`, and nothing in CI compares
against it.
