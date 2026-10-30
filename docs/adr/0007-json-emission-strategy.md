# ADR-0007 — D4: JSON emission strategy for RPC byte-parity

- **Status:** Accepted (decision D4) — ratified 2026-10-26 as shipped: Go
  `encoding/json` reimplemented over a runtime type model, not serde, and
  vectors dumped inside dcrd, not live captures; see the addenda
- **Date:** 2026-07-03 (proposed), 2026-07-26 (addendum: what shipped),
  2026-10-26 (ratified)

## Context

Compatibility surface C3 wants byte-compatible JSON-RPC responses. Go's
`encoding/json` differs from serde_json defaults in float formatting (Go uses
a shortest-round-trip algorithm with specific exponent thresholds; difficulty
and fee fields are floats), struct-order field emission, and `omitempty`
semantics. Real clients (dcrctl, dcrwallet, Decrediton) are the acceptance
arbiters (risk R3).

## Decision (proposed)

- Typed command/result structs (`dcrjson` equivalent) emitted through
  **serde with a custom serializer layer** that: (a) preserves dcrd's field
  order (serde emits in declaration order — declare in dcrd's order and lock
  with golden tests), (b) reproduces Go `omitempty` rules per field, and
  (c) formats floats via a Go-`strconv.AppendFloat('g')`-compatible
  formatter (vendored/ported, KAT-pinned against oracle-generated vectors —
  Go's shortest-float algorithm is well-specified and portable).
- Golden request/response captures from dcrd for every method (success +
  each documented error) are the regression suite: canonical JSON comparison
  always; raw-byte comparison wherever the golden bytes are deterministic.
- Any residual byte-level delta that cannot be reproduced must be proven
  irrelevant against all three real clients and documented in `QUIRKS.md`.

## Consequences

- A float-formatting module with its own oracle-generated KAT corpus joins
  the project (small, but consensus-adjacent for `getwork`/difficulty
  outputs — treat with vector rigor).
- Golden capture tooling becomes part of `tools/oracle` scope in Phase 13.
- Final ratification blocked on: a Phase 13 spike running the golden suite
  over the first ~10 methods.

## Addendum, 2026-07-26 — no serde, and the captures came from inside dcrd

Both halves of the proposal were built, but neither in the shape described.

**The emission layer does not go through serde.** `dcroxide-dcrjson`,
`dcroxide-rpctypes` and `dcroxide-rpc` declare no serde dependency at all.
dcrd's `dcrjson` is reflection-driven — one registry of command types feeds
parameter parsing, marshalling, and the generated help text — so the port
carries a runtime type model (`GoType`/`GoValue`) and `gojson.rs`
reimplements Go `encoding/json` over it. That module covers the three
behaviours the ADR named (field order from `json` tags in declaration order,
per-field `omitempty`, and Go's shortest-round-trip float formatting with its
exponent-form cutoff and `e-0X` cleanup) plus two it had not identified:
HTML-unsafe escaping of `<`, `>` and `&`, and bytewise map-key sorting. The
float formatter is therefore part of `gojson.rs` rather than a module of its
own, and its corpus is not oracle-generated: it has a dedicated test file for
the non-finite and shortest-digit paths
(`crates/dcroxide-dcrjson/tests/gojson_nonfinite.rs`) on top of the float
values the frozen vectors below carry.

**The regression suite is not golden captures from a running dcrd, and
`tools/oracle` grew no JSON commands.** Instead an in-package dump test
running inside dcrd's own `dcrjson` and `internal/rpcserver` packages freezes
the marshalled request and response bytes, the exact error codes and
messages, the one-line usage text and the full generated help output; the
Rust suites rebuild the same inputs and compare byte for byte
(`crates/dcroxide-dcrjson/tests/dcrjson_vectors.rs`,
`crates/dcroxide-rpc/tests/rpchandlers*_vectors.rs`,
`rpchelp_vectors.rs`). Comparing dcrd's own marshalled bytes is the property
the ADR wanted; taking them from inside the package reaches handler paths and
error cases that driving a live daemon over HTTP cannot.

The captures carry one staleness. They were frozen inside dcrd at
`release-v2.1.5`, and the dcrd 2.2 rpcserver delta was absorbed by editing the
affected rows in place and adding native cases rather than by recapturing the
suite at the `452c1a6c` parity target, so those rows are pinned by the port's
reading of dcrd rather than by dcrd's own bytes.

The `QUIRKS.md` escape hatch has not been used: it carries no JSON-emission
entry. Ratifying D4 remains the project owner's call.

## Addendum, 2026-10-26 — ratified as shipped

The design the 2026-07-26 addendum describes is the accepted decision for D4,
ratified by the project owner on 2026-10-26. The project brief framed D4 as a
custom serializer against canonicalized comparison with documented deltas
(`docs/dcroxide-project-brief.md:862`). The answer is a custom serializer,
compared on raw bytes:

- **No serde.** `dcroxide-dcrjson` depends only on `dcroxide-chainhash`,
  `dcroxide-rpctypes` only on `dcroxide-dcrjson`, and none of `dcroxide-rpc`'s
  dependencies pulls serde in (`cargo tree -p dcroxide-rpc -e normal`).
  serde_json reaches their test builds only through the `dcroxide-testutil`
  dev-dependency.
- **Go's `encoding/json`, reimplemented.**
  `crates/dcroxide-dcrjson/src/gojson.rs` encodes and decodes over the runtime
  type model (`GoType`/`GoValue`) as Go does (its header, :1-12): struct
  fields from their `json` tags in declaration order with `omitempty`, map
  keys sorted bytewise, `<`, `>`, `&` and U+2028/U+2029 escaped
  (`append_json_string`), and Go's decode error texts.
- **Go's float formatting, not a port of `strconv`.** The digits are Rust's
  own shortest digits (`split_shortest`, `shortest_digits`), with an exact
  halfway tie moved to the even final digit, the one Go keeps (`even_on_tie`,
  `gojson.rs:94-172`). The JSON form takes an exponent below 1e-6 and from
  1e21, with the `e-0X` cleanup. A non-finite value fails the marshal with
  Go's `UnsupportedValueError` in `try_encode`, which replies are marshalled
  through (`crates/dcroxide-rpc/src/dispatch.rs:518`); the infallible
  `encode` writes `null` instead.
- **Frozen vectors, replayed byte for byte.** 2,372 lines in 19 files, dumped
  at `release-v2.1.5` by in-package tests inside three of dcrd's packages:
  `dcrjson_vectors.txt` (217 lines, `dcrjson`), `rpctypes_vectors.txt` (472,
  `rpc/jsonrpc/types`), and 1,683 lines from `internal/rpcserver` in the
  fifteen `rpchandlers*_vectors.txt`, `rpchelp_vectors.txt` and
  `rpchelpers_vectors.txt`. `cargo test --workspace` replays them on
  `ubuntu-latest`, `ubuntu-24.04-arm`, `macos-latest` and `windows-latest`,
  and again with overflow checks off (the `test` and `test-wrapping` jobs of
  `.github/workflows/ci.yml`).

The gate is met in substance, not in its literal form. Ratification was blocked
on "a Phase 13 spike running the golden suite over the first ~10 methods", with
the capture tooling in `tools/oracle`. That tooling was never built, and
`tools/oracle` has no JSON command. What was built covers more. The handler
batteries name each of the 105 methods `rpc/jsonrpc/types` registers except
`authenticate` (a match by name, not a measure of coverage), and with help,
usage and the error ladders they are compared on raw bytes rather than
canonically. The three arbiters that risk R3 names have also run against the
build, with the dcrd 2.1.7 release binaries as the reference
(`docs/dcroxide-project-brief.md:65-105`). `dcrctl` 2.1.7 sent 2,731 calls over
all 77 chain-server commands to dcrd and to `b49145e`, and every reply that
differed followed dcrd master's source at the pin of the time, `382ff4dd`, came
from the unported profile server or the inventory trickle delay then missing,
or matched a second dcrd given the same role and history. Two `dcrwallet` 2.1.7
wallets in RPC mode transferred, bought tickets and voted on simnet with
`b49145e` as their node, and Decrediton 2.1.7 connected in remote-daemon mode
to `58bd107`. dcrd's own `TestRpcServer` and `TestTreasury`, from `3360ae4d`,
passed through the `dcrdtest` harness against `b49145e`, as against dcrd 2.1.7
and a dcrd built from that tree. Those runs were one-offs whose tooling is not
in the tree, and the sweep and the wallets took the 2.1.7 release, not a build
of the pin, as the reference. The sweep, the wallets and the harness have not
run on a build after `b49145e`, nor Decrediton on one after `58bd107`, and
Decrediton's IPC lifecycle, RPC authentication by TLS client certificate and
`dcrwallet`'s mixing were not run.

**Corrections to the 2026-07-26 addendum.**

- It places the dump inside `dcrjson` and `internal/rpcserver` and names
  three replays. The `rpctypes` battery was dumped inside
  `rpc/jsonrpc/types`, and `crates/dcroxide-rpctypes/tests/rpctypes_vectors.rs`
  and `crates/dcroxide-rpc/tests/rpchelpers_vectors.rs` replay files it left
  out.
- The float formatter it describes did not yet match Go on exact ties. From
  `c74549f` (2026-07-06), which added it, until `9b343c4` (2026-09-23), a
  value exactly halfway between two shortest candidates came out with Rust's
  choice, the one away from zero: a float request id of 2^49 + 0.25 echoed
  as `562949953421312.3` where dcrd gives `.2`, the digit
  `crates/dcroxide-dcrjson/tests/review_go_text_parity.rs:716-729` now pins.
  No frozen vector caught it. In a measurement made for this decision, with
  a program not kept in the tree, one million random float64 bit patterns
  held 500 exact ties, 268 of them with the other candidate farther from
  zero, where Rust's choice is not Go's; one million random float32 held
  4,004 ties; and one million amounts, atoms divided by 1e8, held none.
- "Its corpus is not oracle-generated" no longer holds in full. Since
  `9b343c4`, `review_go_text_parity.rs` carries 60 float64 and 30 float32
  ties and the two trigger values, generated by running the Go calls each
  table names under go1.26.5 (:1-11, :300-699, :716-729): not through
  `tools/oracle`, and with the generator not kept. The check against "3M
  Go-formatted float64/float32 values" that the `dcrjson` row of
  `docs/PARITY.md` has cited since `3aadcb7` (2026-09-25) has neither a
  generator nor a corpus in the tree.
- The dcrd 2.2 rpcserver delta it mentions was absorbed in three commits,
  `940d6e4` (2026-07-17), `e06812e` and `e362edf` (2026-07-18): nine
  existing rows edited, six of them for version and protocol constants and
  three for behaviour or text (`addnode`'s error mapping, a lower-cased
  "invalid" in `node disconnect`'s error, and `debuglevel`'s help), and
  native case 35 added. Only case 35 is recorded in its replay
  (`crates/dcroxide-rpc/tests/rpchandlers4_vectors.rs:450-452`). The
  `3360ae4d` delta is pinned by a review test, not by a vector (the
  `382ff4dd..3360ae4d` section of `docs/PARITY.md`).
- `452c1a6c` was the parity target when it was written. The pin is now
  master `3360ae4d` (ADR-0001's 2026-10-25 addendum); the replay headers
  name `release-v2.1.5`, where the rows were dumped.
- It points the escape hatch at the wrong ledger, as the Decision above does.
  `QUIRKS.md` records dcrd's own deviations from its documentation that the
  port reproduces on purpose (`docs/QUIRKS.md:3-7`), and said so when this ADR
  was proposed. A byte-level delta the port cannot reproduce is a divergence
  from dcrd: once proven irrelevant to all three clients, it is recorded in
  `docs/PARITY.md` with the port's other divergences. Neither ledger records
  one for the JSON encoder.

**The Go reference.** The texts the encoder and decoder follow are those of
the Go release dcrd's release image builds with (`contrib/docker/Dockerfile`,
golang 1.26.2 at `3360ae4d`), the one Go reference the project owner
approved on 2026-10-26 (ADR-0001's addendum of that date on the reference
Go); where Go 1.27 differs, `docs/PARITY.md` notes it as forward-looking.
The tie table was generated under go1.26.5. Run again for this decision
under go1.26.2, with a program not kept, all 90 rows and both trigger values
came out the same, and `strconv`, `internal/strconv`, `encoding/json` and
`fmt` are the same in the two releases' sources. Under Go 1.27.1, with
`jsonv2` on and off, every row matched too, so for these digits Go 1.27's
exposure is the scanner's syntax-error texts, not the formatting.

**Follow-up, pending: a kept float generator.** The Consequences above asked
for an oracle-generated float corpus. The digits are Go's `strconv`, not
dcrd's code, so a generator outside `tools/oracle` serves, and the tie bug
shows what the corpus's absence cost. A Go generator using only the standard
library is to be kept under `tools/` and run under the reference Go release,
writing a committed corpus of random float64 and float32 bit patterns with
Go's output for each. A test in `crates/dcroxide-dcrjson/tests` is to replay
it through `format_float_json`, `format_float_json32`, `format_float_g`,
`format_float_g32` and `format_float_f`, so that `cargo test --workspace`
checks it in CI with no Go toolchain. Its size is not fixed here: at the
rates above, about 10^4 random-bit values would very likely hold enough ties
to show a regression of the kind that was live from 2026-07-06 to 2026-09-23
(inference). Nothing gates it, and nothing of it is built. Until it lands,
the 3M-value check cannot be repeated from the tree.

**Vector provenance is ADR-0001's.** How the frozen vectors are kept current
is no longer a D4 question. ADR-0001's 2026-10-26 addendum on frozen
batteries sets one rule for every battery whose exporter was scratch code,
the 19 files above among them. Under it the 17 `internal/rpcserver` files
are due first, since `3360ae4d` changed `internal/rpcserver/rpcserver.go`;
their exporter is not yet rebuilt, and its regeneration will meet the nine
hand-edited rows and case 35 above. `dcrjson` is the same at
`release-v2.1.5` and `3360ae4d`, and `rpc/jsonrpc/types` differs only in a
copyright year and a doc comment's name in `chainsvrcmds.go`, its module
path and one added test case, so those two files still hold what dcrd's code
writes at the pin (inferred from the delta, not regenerated).

**One residual, not decided here.** Notification parameters are marshalled
by `make_params` (`crates/dcroxide-dcrjson/src/cmdparse.rs:96-109`) through
the infallible `encode`, which writes `null` for a non-finite float. dcrd's
`NewRequest` returns `json.Marshal`'s error instead
(`dcrjson/jsonrpc.go:98-100` at `3360ae4d`), and the notification is logged
as a failure and not sent. The floats notifications carry are amounts
converted to coins, which are finite, so the difference is not known to be
reachable (inference); `docs/PARITY.md`'s open gap on the RPC server's log
lines says the same of dcrd's notification marshal failures. Whether the
port fails as dcrd does or records a divergence is left open.

The Decision section above still describes serde and live captures. It reads
correctly only through the addenda, as ADR-0005's does.
