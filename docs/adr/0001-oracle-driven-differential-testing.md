# ADR-0001 — Oracle rig: Go shim over line-JSON, pinned to dcrd release-v2.1.5

- **Status:** Accepted
- **Date:** 2026-07-03 (accepted), 2026-07-26 (addendum: the pin moved with
  the parity target), 2026-08-20 through 2026-10-25 (addenda: the pin's
  later moves), 2026-10-26 (addendum: frozen batteries whose exporters were
  scratch code; second addendum: one reference Go, and CI on it), 2026-11-12
  (addendum: the pin at `46e9df48` and the reference Go at 1.27.3; second
  addendum: `tools/fullblockgen` in `go-tools`), 2026-11-14 (addendum: the
  2026-11-12 pending items, followed or recorded)

## Context

The project brief (§4, §7) makes dcrd the specification and requires
differential testing against it for every consensus-relevant module. We need a
mechanism for (a) regenerating test vectors from dcrd instead of trusting
inherited fixtures, and (b) live differential fuzzing/testing where dcroxide
and dcrd process identical inputs and results are compared.

Options considered: cgo/FFI linking of dcrd packages into the Rust test
binary (fragile, couples build systems), golden-file-only vectors (no live
differential capability), or a standalone Go subprocess speaking a simple
protocol (loose coupling, works on all three target OSes, trivially
extensible).

## Decision

`tools/oracle` is a standalone Go module producing one binary, `dcrd-oracle`,
that links real dcrd packages and serves requests over **stdin/stdout,
one JSON object per line** (`{"cmd": ..., ...}` → `{"result": ...}` or
`{"error": ...}`). New capabilities are added as new `cmd` values.

Every dcrd module dependency in `tools/oracle/go.mod` is pinned to the exact
version required by dcrd `release-v2.1.5`'s `go.mod` — the parity target.
Versions move only when the parity target moves.

Rust tests build the oracle on demand (`go build` into
`<target-dir>/<profile>/oracle/`, found from the test binary's own path) and
spawn it. Locally, a missing Go toolchain skips differential tests with a
notice; in CI, `DCROXIDE_REQUIRE_ORACLE=1` turns a missing toolchain into a
failure so differential coverage can never silently disappear.

## Consequences

- Differential tests require a Go toolchain (CI installs one; developers
  without Go still get the full non-differential suite).
- Process-per-oracle with line-delimited JSON is slow relative to FFI, but
  hashing/validation throughput is dominated by pipe round-trips only for
  tiny inputs; acceptable for test volumes, and batching commands can be
  added later if needed.
- The full dcrd source tree is *not* vendored as a submodule yet; the Go
  module proxy provides pinned, checksummed sources. A submodule checkout for
  source-reading/test-porting convenience can be added when Phase 1 porting
  begins in earnest.

## Addendum, 2026-07-26 — re-pinned to dcrd master `452c1a6c`

## Addendum, 2026-08-20 — the target moved again; the oracle pin did not

The parity target is now dcrd master `29f17894` (still 2.2.0-pre): `PARITY.md`
tracks against it, and `crates/dcroxide-testutil/src/lib.rs`'s
`DCRD_PARITY_COMMIT` refuses to run the interop harness against a daemon built
from any other commit. `tools/oracle/go.mod` did **not** move with it — every
module is still on its `452c1a6c` pseudo-version — so this is an exception to
the rule above rather than the rule working. The reason is recorded in
`PARITY.md`'s "Oracle pin" paragraph: nothing in the `452c1a6c..29f17894`
delta changes what any exporter emits, several vector sets are expensive to
reproduce, and one of them (mixpool) can only be regenerated with a clock
overlay. Move the module pins when a delta actually requires it, not on every
target bump. Every module dcrd replaces
with an in-tree directory whose source differs from its published release —
`stake`, `standalone`, `edwards`, `secp256k1`, `gcs`, `txscript`, `wire` — is
pinned to the pseudo-version at that commit, so the oracle links the code the
dcrd binary at `452c1a6c` links. The remaining pins (`chainhash`, `chaincfg`,
`blake256`, `dcrutil`, `uint256`, `base58`) are byte-identical to the in-tree
sources at that commit and stay on their release versions.

Nothing about the mechanism changed: one Go binary, line-delimited JSON on
stdin/stdout, built on demand into the cargo target directory, with
`DCROXIDE_REQUIRE_ORACLE=1` set in CI so a missing toolchain fails instead of
skipping. The dcrd source tree is still not vendored as a submodule.

## Addendum, 2026-09-23 — target and oracle pin both at `b9634e01`

The addendum above is history: the parity target has since moved to
`036b7090` and then to dcrd master `b9634e01` (still 2.2.0-pre), the pin
`README.md`, `PARITY.md` and `DCRD_PARITY_COMMIT` now name, and
`tools/oracle/go.mod` moved with it both times. Every module whose in-tree
source at the target differs from its published tag is on the `b9634e01`
pseudo-version (`chaincfg` and `blake256` joined that set after `452c1a6c`),
and the `go.mod` comment records how the split was re-derived at the new
commit rather than carried forward. So the exception the 2026-08-20 addendum
describes is closed, and versions again move when the parity target moves.
The interop harness had lagged instead: `DCRD_PARITY_COMMIT` and the dcrd
commit CI builds for it both still named `29f17894` until 2026-09-23, so CI
ran the interop tests against a daemon two pins behind and a dcrd built at
the real pin was refused. `the_dcrd_pin_matches_ci_and_the_oracle`
(`crates/dcroxide-testutil/src/lib.rs`) now fails if the harness pin, CI's
`DCRD_COMMIT` and the commit `tools/oracle/go.mod` names disagree.

## Addendum, 2026-10-02 — target, oracle and battery generator at `6f6cf21b`

The parity target moved to dcrd master `6f6cf21b` (still 2.2.0-pre), and
`tools/oracle/go.mod` moved with it. The split was re-derived at the new
commit rather than carried forward: no module was tagged after `b9634e01`,
and of the oracle's modules only `txscript` (a comment) and `wire` changed
between the two pins, both already on pseudo-versions, so the same modules
sit on the new pseudo-version and the same tags stay. `wire`'s change is a behaviour change the oracle now
links: `ReadOutPoint` refuses a negative outpoint tree, so the stake, txscript
and standalone differentials, whose generators drew trees from -1 to 1, now
draw them from 0 to 2.

The oracle is not the only Go module that links dcrd. `tools/fullblockgen`,
which dumps dcrd's full block battery from inside `blockchain/fullblocktests`,
had stayed at `036b7090` through the whole `b9634e01` move, because nothing
read its `go.mod`. It now links `6f6cf21b` under the oracle's rule, and
`the_dcrd_pin_matches_ci_and_the_oracle` checks both `go.mod` files against
the harness pin.

## Addendum, 2026-10-16 — target, oracle and battery generator at `382ff4dd`

The parity target moved to dcrd master `382ff4dd` (still 2.2.0-pre), and
`tools/oracle/go.mod` and `tools/fullblockgen/go.mod` moved with it. The split
was re-derived at the new commit rather than carried forward. Three of dcrd's
nested modules were tagged after `6f6cf21b`: `wire` v1.8.0, `blockchain/stake`
v5.0.3 and `mixing` v0.7.5. The oracle links the first two; neither changed
code between the pins, and at `382ff4dd` each directory is byte-identical to
its new tag, so both moved from the pseudo-version to the tag: the oracle now
pins nine modules by pseudo-version where it pinned eleven, and `fullblockgen`,
whose `wire` moved the same way, seven where it pinned eight. Every other
module sits on the new pseudo-version or keeps its tag. `fullblockgen` moved
without a regeneration, since `blockchain/fullblocktests` and the code it links
are the same at both pins.

The exporters behind the vector files this move regenerated or added are kept
in the tree, as `tools/fullblockgen` and `tools/helpgen` already were; earlier
moves left their other exporters as scratch code. The five are
`tools/mixpoolgen`, `tools/mempoolvectors`, `tools/utxoviewgen`,
`tools/chainopsgen` and `tools/disapprovalgen`, each an overlay that runs
inside a dcrd checkout's own package and writes its committed files back byte
for byte when run at the pin.

## Addendum, 2026-10-25 — pin, oracle and battery generator at `3360ae4d`, toward the unreleased v2.2

The parity target is now dcrd v2.2, which upstream has not yet released, so
the pin follows master until v2.2 is tagged, moving at upstream milestones
and on the owner's word. It moved to master `3360ae4d`, one commit past
`382ff4dd`, which changes only `internal/rpcserver` in dcrd's root module, and
`tools/oracle/go.mod` and `tools/fullblockgen/go.mod` moved with it, as
`the_dcrd_pin_matches_ci_and_the_oracle` requires. The split was checked again
rather than carried forward: no module was tagged after `382ff4dd` and no
linked module's directory changed, so every pseudo-pinned module moved to the
new commit, nine in the oracle and seven in `fullblockgen`, and each one's
files, as the module proxy serves them, are byte-identical at both commits. No
exporter was run again: none runs in `internal/rpcserver`, and no vector file
changed.

## Addendum, 2026-10-26 — frozen batteries whose exporters were scratch code

Most of the project's frozen batteries were dumped from inside dcrd's own
packages by exporters run in a dcrd checkout and never committed. When a pin
move's delta reached one, its rows were re-expected by hand, or the file was
dumped again by an exporter written for that move and not kept either
(`docs/PARITY.md`'s *Oracle pin* paragraph). A row re-expected by hand is
pinned by the port's reading of dcrd rather than by dcrd's own bytes. The
2026-10-16 addendum kept the exporters behind the files that move regenerated
and set no rule for the rest. On 2026-10-26 the project owner set one.

**The rule.** A frozen battery whose exporter is not in the tree comes due when
a pin move's delta changes the package it was dumped in, or the package dcrd
has since moved that package's source to, or when the reference Go release, the
one dcrd's release image builds with, moves to a release that changes texts the
battery pins. A battery that has come due is regenerated, not re-expected by
hand, and its exporter is first rebuilt as a kept tool under `tools/`. Before
the tool is run at the pin, it must reproduce the frozen file byte for byte at
the commit the file was dumped at: the file as its dump wrote it, taken from
the history before any hand edit. An adaptation needed to reproduce it is
recorded, as `docs/PARITY.md` records those the tools kept at `382ff4dd`
needed. The regeneration's diff is then reviewed as a pin move's delta is,
including the rows it replaces that were re-expected by hand. From then on the
tool follows the practice of the tools already kept: a move whose delta touches
its package runs it again. The rule names no exemption. The approved rule names
one trigger, a change dcrd makes to a package a battery came from; the other
two, a move of that source to another package and a move of the reference Go
that changes texts a battery pins, are this record's reading of it.

**Where it starts.** This record reads the rule as counting from the
`3360ae4d` move, the move the approval named when it put RPC first. A
battery whose package changed only in earlier moves, where the change was
absorbed by hand or found not to reach it, comes due at the next move that
changes that package again.

**Due now: the `internal/rpcserver` batteries.** The seventeen files dumped
in `internal/rpcserver` at `release-v2.1.5`, 1,683 lines under
`crates/dcroxide-rpc/tests/data/` (the fifteen `rpchandlers*_vectors.txt`,
`rpchelp_vectors.txt` and `rpchelpers_vectors.txt`), are due first:
`3360ae4d` changed `internal/rpcserver/rpcserver.go`, and that move was
absorbed with a review test and no vector change. Nothing is built yet.
dcrd's own handler test mocks (`testRPCChain` and `defaultMockRPCChain` in
`internal/rpcserver/rpcserverhandlers_test.go` at `3360ae4d`) are there for
an overlay shaped like `tools/mempoolvectors` to drive. That a tool reading
each file's case and mock rows and writing only the outputs, as
`tools/chainopsgen` does for its files, would cost less than rebuilding the
lost dump whole is an inference. The 2026-10-25 addendum's "none runs in
`internal/rpcserver`" holds of the kept exporters only: the scratch exporter
behind these files ran there. ADR-0007's 2026-10-26 addendum lists the hand
edits the regeneration will meet.

**The rest.** Every other battery an exporter dumped from dcrd is under the
rule as well. Only thirteen files are written by kept tools:
`fullblock_vectors.txt` (`tools/fullblockgen`), `help_vector.txt` and
`help_vector_140.txt` (`tools/helpgen`), `mixpool_vectors.txt`
(`tools/mixpoolgen`), `txpool_vectors.txt`, `txstake_vectors.txt` and
`review_agenda_vectors.txt` (`tools/mempoolvectors`), `utxoview_vectors.txt`
(`tools/utxoviewgen`), `processblock_vectors.txt`, `invalidate_vectors.txt`
and `reorg_vectors.txt` (`tools/chainopsgen`), `disapproval_vectors.txt`
(`tools/disapprovalgen`) and `profiler_vectors.txt` (`tools/profilergen`,
kept since 2026-10-23, after the 2026-10-16 addendum's list). The batteries
without a kept exporter include:

- `dcrjson_vectors.txt` (217 lines) and `rpctypes_vectors.txt` (472), dumped
  in `dcrjson` and `rpc/jsonrpc/types` at `release-v2.1.5`.
  `dcrjson_vectors.txt` carries Go's JSON syntax-error texts, as
  `rpchandlers13_vectors.txt` and `seed_tor_vectors.txt` do, so each also
  comes due if the reference Go moves to a release that words them
  differently, as `docs/PARITY.md` expects Go 1.27's default `jsonv2` to.
- `netsync_vectors.txt` (1,131), dumped in `internal/netsync` at
  `release-v2.1.5`; its replay records the fifteen rows re-expected by hand
  at `6f6cf21b`.
- `config_vectors.txt` (368) and `flags_vectors.txt` (238), dumped in dcrd's
  package `main` at `release-v2.1.5`. 41 rows of the first and 26 of the second
  were re-expected by hand in `e06812e` for dcrd 2.2's removal of the `ADXR`
  log subsystem, and one more of the first in `e362edf` for a reworded
  whitelist error; neither replay records them. `tools/helpgen` copies
  `config.go`'s config struct and defaults for the help vectors only, and
  writes neither file.
- `staketx_vectors.txt` (285), dumped in `blockchain/stake` at
  `release-v2.1.5` from `staketx_test.go`'s transactions.
- The ten `srv*_vectors.txt` under `crates/dcroxide-node/tests/data/` (292),
  dumped by in-package tests: eight driving dcrd's server at
  `release-v2.1.5` and `srvextaddr_vectors.txt` driving it at `036b7090`,
  and `srvtargetout_vectors.txt`, at `036b7090`, evaluating expressions
  copied out of `server.go` and `internal/connmgr/connmanager.go`.
  `srvadmit_vectors.rs` records the rows dropped when the pin lost dcrd's
  `disconnectPeer`.
- `seed_tor_vectors.txt` (48), dumped in `connmgr` at `release-v2.1.5`.
  dcrd 2.2 moved its seeder and Tor sources into `addrmgr`, which is the
  package that counts for it now; its replay records the one row edited for
  the move.
- `bgtmpl_vectors.txt` (39), dumped at `release-v2.1.5` by an in-package
  test of dcrd's background template generator, which lives in
  `internal/mining`.

`docs/PARITY.md`'s paragraph on the release image's Go said the JSON vectors
are regenerated when that image moves to Go 1.27 or later. Under this rule that
move first rebuilds the exporters of the batteries whose texts it changes, as
that paragraph now says, and none of those tools exists yet.

## Addendum, 2026-10-26 (second) — one reference Go, the release dcrd's release image builds with, and CI on it

Part of what dcrd does comes from its Go standard library rather than its own
code: the RPC listener's TLS choices, the client-certificate chain search, the
HTTP server's framing and error texts, the Go-JSON error texts, `%q` quoting
and float formatting. The repository named no single Go release for that part.
PARITY.md's bump check, in its paragraph on the release image's Go, tied the
Go-JSON texts to the release dcrd's `contrib/docker/Dockerfile` builds with,
the tables in `crates/dcroxide-dcrjson/tests/review_go_text_parity.rs` were
generated under go1.26.5, the TLS and certificate work cited Go 1.27, and CI
built the oracle and vetted the tool modules with Go 1.24 and built the interop
daemon with 1.25. On 2026-10-26 the project owner approved one reference, the
Go version dcrd's release builds use, 1.26 on that date. This record reads it
as the release dcrd's release image builds the parity pin with, to the patch:
golang 1.26.2 at `3360ae4d` as at `b9634e01`. The image is the one build recipe
in dcrd's repository that names a Go release. dcrd's published archives need
not follow it: the dcrd binary in the 2.1.7 linux-amd64 archive reports
go1.27.2, where release-v2.1.7's Dockerfile names golang 1.25.4. Where Go 1.27
behaves differently, the difference is recorded beside the behaviour as a
forward-looking note, and the port follows the reference. When the image moves
to another release, the reference and CI move with it in the same bump, so the
oracle's toolchain is part of the rig, pinned like its module versions.

The reading takes the release to the patch because patch releases move
behaviour the port reproduces. `buildChains` itself changed inside 1.26:
go1.26.0 charges a candidate one of its 100 signature checks only after
`alreadyInChain` and the missing-key check, and go1.26.2 charges it first, as
go1.25.14 and go1.27.1 do (`crypto/x509/verify.go`). From 1.26.2 to 1.26.9,
`encoding/json`, `strconv`, `internal/strconv` and `unicode` are unchanged, so
the go1.26.5 tables stand, and `crypto/x509` changes only in how `verify.go`
matches host names, which client-certificate verification does not ask for. But
`crypto/tls`, `net/http`, `net/textproto` and `net/url` change, one of them in
a text the port writes: from 1.26.4, the first later patch release checked,
textproto's `readMIMEHeader` quotes the line in its `malformed MIME header
initial line` and `malformed MIME header line` errors, which 1.26.2 writes as
it came (`net/textproto/reader.go:544`, `:556-564` in 1.26.2).

The port's replay of Go's chain search (`go_build_chains`) does not turn on the
choice between 1.26.2 and 1.27: `buildChains` and `isValid`
(`crypto/x509/verify.go`), `findPotentialParents` (`cert_pool.go`) and
`CheckSignatureFrom` (`x509.go`) are the same text in 1.26.2, 1.26.8, 1.26.9
and 1.27.1, compared function by function. What differs is around them. 1.27's
`ParseCertificate` gives an ML-DSA key a public key, where 1.26.2 knows no
ML-DSA algorithm and leaves the key nil (`parser.go:1010` in 1.26.2), so
`buildChains` passes such a candidate over (`verify.go:741`) where 1.27 checks
its signature and can build a chain through it, which neither 1.26.2 nor the
port can; under both releases the candidate costs one check. 1.27 reads a name
attribute of any ASN.1 type, where 1.26.2's `parseName` refuses a certificate
whose attribute value is not a string (`parseASN1String`, `parser.go:138`).
1.27 refuses an IPv4-mapped IPv6 address as a subject alternative name or an IP
name constraint (`parseSANExtension`, `parseNameConstraintsExtension`), which
1.26.2 accepts. And in the name constraint checks made on a built chain
(`checkChainConstraints`), 1.27 masks an IP constraint's host bits before it
sorts and searches (`constraints.go`) and parses an email name's domain more
strictly (`parseRFC2821Mailbox`, `verify.go`).

CI runs the reference everywhere. A workflow-level `GO_VERSION: "1.26.2"` in
`.github/workflows/ci.yml` feeds all four `actions/setup-go` steps: `test`
(Linux x86_64 and arm64, macOS, Windows) and `test-wrapping`, whose `cargo test
--workspace` builds the oracle, and `go-tools`, which vets and tests `pinbump`,
`helpgen`, `oracle` and `dcrdstat`, these three on 1.24 before; and
`dcrd-interop`, which builds dcrd at the pin, on 1.25 before. No job needs an
older Go. The four modules' `go` lines (1.24.0, `helpgen`'s 1.21) are floors
that 1.26.2 builds, and all four vet and test cleanly under go1.26.2 and
go1.26.9. The workspace suite passed against a go1.26.2 oracle on an x86_64
Linux desktop for this change; the interop job, against a daemon built with
1.26.2, is first run by CI. dcrd's root module's `go` line is 1.25.0, but its
`debug.go` sets `//go:debug default=go1.26` behind `//go:build go1.26`, so a
1.25 build has neither those settings nor Go 1.26's two added hybrid TLS key
exchanges: CI tested against a daemon built with a toolchain the release image
does not use. It is now built with the one it does, though still with `go
build`'s default flags rather than the image's (`CGO_ENABLED=0`, `-trimpath`,
`-tags safe,netgo,timetzdata`), which this decision leaves alone. The dcrd
binary's cache key names the Go release, so a binary built with another is not
reused. dcrd's own CI at the pin builds and tests on Go 1.26 and 1.27 and lints
on 1.26 (`.github/workflows/go.yml`), and its README asks for Go 1.26 or 1.27.
With the oracle on 1.26.2, the client-certificate tests compare the verifier
with Go's own `x509.Verify` (the oracle's `x509_verify_client`) as the
reference runs it. 1.26.2's search charges a candidate first, where go1.24.13
charges it after, so against a 1.24 oracle the comparisons that turn on that
order were skipped or checked against the older count (`GoVerdict`'s
`charges_first` in `crates/dcroxide-node/src/rpcrun.rs`). Locally the oracle
still builds with whatever `go` is on the path, and one built with another
release answers the standard library's part as that release does.

What is pending, each in a change of its own and gated on its review:

- **Behaviour the port took from a later Go.** Five cases are known.
  `MAX_HEADER_VALUES` (`crates/dcroxide-node/src/rpcrun.rs`) refuses a request
  head or a chunked trailer past 500 header values, Go 1.27's
  `DefaultMaxHeaderValueCount` (`api/go1.27.txt`, go.dev/issue/79936), where
  1.26.2's server reads both with `ReadMIMEHeader`, which counts no values
  (`net/http/request.go:1133`, `transfer.go:937`,
  `net/textproto/reader.go:508`). `parse_trailer_fields` quotes the line in the
  two texts above as 1.26.4 and later do, texts dcrd answers as `400 error
  reading JSON message: <err>` (`internal/rpcserver/rpcserver.go:5686` at the
  pin). And `go_public_key` gives an ML-DSA key a key, as 1.27 does; since the
  replay charges such a candidate either way, its verdicts are inferred not to
  change. The mux's redirect to a cleaned path sends the cleaned escaped path
  as it is, as 1.27's `urlFromEscaped` does, where 1.26.2 builds
  `url.URL{Path: ...}` from it and escapes it again (`net/http/server.go:2695`
  in 1.26.2): against a go1.26.2 server, 1,634 of the 3,836 rows of
  `crates/dcroxide-node/tests/data/muxroute.tsv`, all redirects, differ. And a
  head whose first field line begins with a space or tab and runs past the 80
  bytes textproto quotes gets the 431 that 1.27 maps textproto's "message too
  large" to, where 1.26.2 answers a bare 400. By the rule each is to follow
  1.26.2, with the later behaviour as its note; the code is unchanged as of
  this addendum. Whether the port's certificate reader and constraint checks
  follow 1.27 or 1.26.2 on the other points above is to be checked.
- **Citations of Go 1.27.** Docs and tests that name Go 1.27 as the source of a
  behaviour, or carry expected outputs "from a Go 1.27 run", are re-pointed to
  1.26.2 where the two agree, with 1.26.2's line numbers, and re-run under
  1.26.2 where they have not been compared. The change that records this
  addendum does so for `crates/dcroxide-node/src/rpctls.rs`, PARITY.md's TLS
  entries and the other docs and tests that name a Go release; still to do are
  the Go line citations under `crates/` that name none, most of them
  `rpcrun.rs`'s `net/http`, `net/textproto` and `net/url` citations, written
  against 1.27.1, and the doc comments on the behaviour above, which change
  with it. Compared and found the same: the four functions above,
  `parseBasicConstraintsExtension` and `policiesValid`, `pem.Decode`,
  `net/url`'s `parse` and `parseHost`, `netip.ParseAddrPort`, the chunked
  reader, the TLS server's classical group order, its TLS 1.3 group choice and,
  under dcrd's GODEBUG defaults, its cipher-suite order, and the runtime's
  `hchan`.
- **The oracle's GODEBUG defaults.** `tools/oracle/go.mod` says `go 1.24.0` and
  the oracle sets no `//go:debug`, so built with 1.26.2 it runs with Go 1.24's
  value of every setting changed in 1.25 and 1.26 (`tlssha1`, `tlssecpmlkem`,
  `urlstrictcolons`, `x509sha256skid` and `cryptocustomrand` among them,
  `internal/godebugs/table.go`), where dcrd at the pin runs with 1.26's. No
  setting that `ParseCertificate` or `Verify` reads changed after 1.24
  (`x509negativeserial` in 1.23; `verify.go` reads none), so the oracle's
  certificate answers are inferred to be unaffected; that was read from the
  sources, not run. Giving the oracle the settings of dcrd's `debug.go` follows
  from the rule and is pending.
- **`tools/fullblockgen`.** Its `go.mod` says `go 1.27.0`, newer than the
  reference, so `go-tools` still leaves it out. With dcrd's `go 1.25.0` in its
  place it vets cleanly under 1.26.2, in a scratch copy; the edit is pending.
- **The bump check.** Nothing mechanical ties `GO_VERSION` to the release the
  Dockerfile at the pin names. PARITY.md's bump check, which reads the
  Dockerfile, now names `GO_VERSION` as moving with it; a check that fails
  when the two differ is not built.

## Addendum, 2026-11-12 — pin and generators at `46e9df48`, reference Go 1.27.3

The pin moved to master `46e9df48`, five commits past `3360ae4d`, and
`tools/oracle/go.mod` and `tools/fullblockgen/go.mod` moved with it.
`46e9df48` moves dcrd's release image from golang 1.26.2 to golang 1.27.3, so
under the second 2026-10-26 addendum the reference Go is now go1.27.3, and
CI's `GO_VERSION` and the harness's `REFERENCE_GO` moved in the same change.
The move was decided on 2026-11-12, with the port's Go behaviour to follow
1.27.3: what it had already taken from Go 1.27 becomes the reference's, and
the rest is to be brought in line.

**Modules and generators.** No module was tagged in the delta. Of the in-tree
modules the two tools link, only `blockchain/stake`'s directory changed, in
`staketx_test.go` alone. Stake leaves its v5.0.3 tag for the pin's
pseudo-version, by the oracle header's rule, which compares every file; every
other module that moved is byte-identical, as the module proxy serves it, at
both commits. The delta changes `internal/blockchain`, so `tools/chainopsgen`,
`tools/disapprovalgen` and `tools/utxoviewgen` were run again at the pin, and
each wrote its files back byte for byte, two of them once adapted to the delta
(`docs/PARITY.md`'s *Oracle pin* paragraph). Under go1.27.3,
`tools/helpgen`, `tools/mempoolvectors`, `tools/mixpoolgen` and
`tools/profilergen` wrote theirs back unchanged as well; `tools/fullblockgen`,
whose file records the time of its run, was not run again.

**Batteries due and not built.** Under the 2026-10-26 addendum on frozen
batteries this move brings due every battery without a kept exporter that was
dumped in `internal/blockchain` or `blockchain/stake`, the two packages its
delta changes, and the move of the reference Go brings due those whose Go-JSON
texts 1.27.3 words differently. No exporter of any of them is rebuilt yet;
until one is, the port is held to its file as it stands. Due as of this
addendum:

- 29 files under `crates/dcroxide-blockchain/tests/data`, dumped in
  `internal/blockchain`: `agenda_vectors.txt`, `blockcontext_vectors.txt`,
  `blocksanity_vectors.txt`, `cfilterserve_vectors.txt`, `chainio_vectors.txt`,
  `compress_vectors.txt`, `connectblock_vectors.txt`,
  `contextual_vectors.txt`, `contextual2_vectors.txt`, `ctac_vectors.txt`,
  `difficulty_vectors.txt`, `liveticket_vectors.txt`, `lottery_vectors.txt`,
  `positional_vectors.txt`, `processheaders_vectors.txt`,
  `query_vectors.txt`, `seqlock_vectors.txt`, `sigops_vectors.txt`,
  `stakeinputs_vectors.txt`, `stakenode_vectors.txt`, `stakever_vectors.txt`,
  `template_vectors.txt`, `threshold_vectors.txt`, `ticketspend_vectors.txt`,
  `tpv_vectors.txt`, `treasury_vectors.txt`, `txinputs_vectors.txt`,
  `utxoio_vectors.txt` and `validate_vectors.txt`. The other six files there
  are written by kept tools.
- 3 files under `crates/dcroxide-stake/tests/data`, dumped in
  `blockchain/stake`: `stakedb_vectors.txt`, `staketx_vectors.txt` and
  `ticketnode_vectors.txt`. The rule goes by the package, and the delta's
  change there, a case `01eef9f7` adds to `staketx_test.go`, is to a test
  file, for which it names no exemption.
  `review_ticketnode_expiring.txt`, from a Go test placed in a copy of the
  same package, comes due as well if the review tables count as batteries,
  which is not settled.
- `dcrjson_vectors.txt`, `rpchandlers13_vectors.txt` and
  `seed_tor_vectors.txt`, whose Go-JSON syntax-error texts Go 1.27's default
  `jsonv2` words differently. The port keeps Go 1.26.2's texts until they are
  regenerated, an interim divergence `docs/PARITY.md` records.
- The seventeen `internal/rpcserver` files, due since the `3360ae4d` move.
  `rpchandlers13_vectors.txt`, in the group above, is one of them.

**The second 2026-10-26 addendum's pending items.**

- **Behaviour the port took from a later Go.** The five cases, the 500
  header-value cap, the quoted MIME header texts, ML-DSA keys in the chain
  search, the mux redirect's escaping and the 431 for a long leading-space
  line, are now the reference's behaviour, and the code was not changed back.
  Each holds in 1.27.3 as in 1.27.1, from which the port took it. Behaviour
  newer than 1.27.1 is pending: the count of `Trailer` values against the cap
  and a failed continuation-line read reported as an error (both 1.27.2;
  corrected 2026-11-14, see the addendum of that date), and in 1.27.3 the drop
  of chains through distrusted keys. So are Go 1.27's refusal of an
  IPv4-mapped IPv6 address as a subject alternative name or IP name
  constraint, the runes Unicode 17 makes printable for `strconv.IsPrint`, the
  cause Go gives for a key it cannot parse, ML-DSA keys, certificates and
  signatures, and the Go-JSON texts. `docs/PARITY.md` records them as interim
  divergences; all but the Go-JSON texts are to be followed in the changes
  that complete this move.
- **Citations of Go 1.27.** The item turns over: the citations written against
  1.26.2, and those written against 1.27.1, are now the ones to re-point, to
  1.27.3.
- **The oracle's GODEBUG defaults.** Stands.
- **`tools/fullblockgen`.** Its `go 1.27.0` is now within the reference;
  `go-tools` takes it in a change of its own.
- **The bump check.** Stands.

Soak records made before and after this move compare only with `sigsoak
compare --allow-pin-change`. The condition item 5 of ADR-0006's second
2026-10-26 addendum set for that flag, unchanged `dcrec/secp256k1` and
`dcrec/edwards` source, holds between the two pins; the oracle on the later
side is also built with go1.27.3. The nightly job compares no records itself.

## Addendum, 2026-11-12 (second) — `tools/fullblockgen` in `go-tools`

`go-tools` now vets and tests `tools/fullblockgen` with the other four
modules, which settles the `tools/fullblockgen` item that the first addendum
of this date carried over from the second 2026-10-26 addendum. Its `go.mod`
keeps `go 1.27.0`: since the move to 1.27.3 that line is within the
reference, so the drop to dcrd's `go 1.25.0` that the 2026-10-26 item
planned is not needed. Under go1.27.3 the module vets cleanly; it has no
tests of its own.

## Addendum, 2026-11-14 — the 2026-11-12 pending items, followed or recorded

The first 2026-11-12 addendum listed the Go behaviour newer than 1.27.1 that
the port did not yet have, with Go 1.27's other changes it had not taken, and
said that all but the Go-JSON texts were to be followed in the changes that
complete the move to go1.27.3. Those changes are made, and not every item was
followed: each that was not is recorded in `docs/PARITY.md` as a divergence,
for the reason given here. Item by item, with the change that settled each:

- **The count of `Trailer` values against the header value cap** (Go 1.27.2):
  followed in `b14db10`, "Count Trailer values against the header value cap".
- **A failed continuation-line read reported as an error.** This is Go
  1.27.2's change, not 1.27.3's as the 2026-11-12 addendum first said
  (corrected there). It needs no code: the port reads a request head whole
  before it parses a field line, and a trailer only once its closing blank
  line is buffered, as Go reads a trailer, so neither read fails inside a
  continuation line, and a head that ends inside one gets the answer Go gives.
  `2e72ad4`, "Record the Go 1.27.3 points that need no code", pins and records
  it. The trailer reader keeps a `break` in its continuation loop, which it
  cannot reach, where Go now returns the error (decided 2026-11-12).
- **The drop of chains through distrusted keys** (Go 1.27.3): followed for
  client certificates in `8fee0dc`, "Drop client-cert chains through Go's
  distrusted keys". Recorded for the HTTPS seeders (decided 2026-11-12): ureq
  3.5.1 has no hook for a verifier of the port's own, so following Go there
  would take a verifier on the proxied transport and a connector for ureq on
  the direct one, new code on the path a seeder MITM attacks.
- **IPv4-mapped IPv6 addresses refused as subject alternative names and IP
  name constraints** (Go 1.27): followed for client certificates in `33cdc97`,
  "Refuse the IP names and mailbox constraints Go 1.27.3 refuses", with Go's
  refusal of IP addresses and masks of other lengths and its rule for reading
  an rfc822Name constraint, which refuses one whose domain holds `@`. Recorded
  for the seeders, for the reason above (decided 2026-11-12), and for the
  `rpc.cert` leaf, which the port does not parse as `tls.X509KeyPair` does, so
  that a leaf naming such an address loads (decided 2026-11-12), a gap older
  than 1.27.
- **A mailbox whose domain holds `@` below a certificate with name constraints
  of any form.** Not on the 2026-11-12 list: Go 1.27 refuses such a chain,
  which came to light as the points that need no code were recorded. Followed
  for client certificates in `bc71504`, "Refuse client chains naming a mailbox
  whose domain holds @" (decided 2026-11-13), for the `@` alone, which is what
  1.27 newly refuses. Go's older refusal of other names it cannot read under
  any constraint, such as a DNS name with an empty label or a URI whose host
  is an IP address or empty, stays recorded, as does webpki's own evaluation
  of rfc822Name and URI constraints, which differs from Go's (decided
  2026-11-12). Recorded for the seeders, for the reason above (decided
  2026-11-14).
- **The runes Unicode 17 makes printable for `strconv.IsPrint`**: followed in
  `1cf0be4`, "Take Go 1.27.3's IsPrint tables".
- **The cause Go gives for a key it cannot parse**: followed for the RPC key
  in `8d6a2d7`, "Read an RPC key in Go 1.27's order and keep asn1's error
  texts", and `64f876f`, "Give Go 1.27.3's cause when an RPC key does not
  parse", and for gencerts' CA key in `efe8265`, "Load gencerts' CA key as
  Go's X509KeyPair does". Recorded: an RSA key keeps the port's words, also
  where Go refuses its values with a cause of its own, since the provider
  refuses an RSA `rpc.key` whatever its values (ADR-0015, T6; decided
  2026-11-12); and gencerts refuses RSA, P-224 and ML-DSA CA keys in words of
  its own, where Go issues with them (ML-DSA decided 2026-11-12).
- **ML-DSA keys, certificates and signatures**: followed in TLS 1.3 on the
  `ml-dsa` crate, as ADR-0015's addendum of 2026-11-13 records: `323d51f`,
  "Add the ml-dsa crate for the TLS provider", `2151955`, "Verify ML-DSA
  signatures in the TLS provider", and the changes "Load and serve an ML-DSA
  RPC key as Go 1.27.3 does" and "Take ML-DSA client certificates as Go 1.27.3
  does". Recorded in `docs/PARITY.md`'s ML-DSA entry: the seeders keep ring's
  verification set and gencerts refuses an ML-DSA CA key (both decided
  2026-11-12); some refusals come later than Go's, or in rustls's or webpki's
  words or alerts, since those libraries make them; the TLS 1.3
  CertificateRequest lists PKCS#1 v1.5's three schemes, which Go leaves out of
  TLS 1.3, and not ECDSA with P-521, which the provider lacks, and carries no
  `signature_algorithms_cert`, which rustls 0.23.46 does not write; and a
  handshake message over rustls's 64 KiB is refused, where Go reads a
  Certificate message of up to 256 KiB. The entry on `--authtype=clientcert`
  records that a chain through an ML-DSA key whose BIT STRING has unused bits,
  which Go right-aligns, does not verify, failing closed. No ML-DSA code is
  under the constant-time check (ADR-0015's addenda of 2026-11-13 and
  2026-11-14).
- **The Go-JSON texts**: not followed, as the 2026-11-12 addendum excepted
  them. The three batteries that pin them are regenerated by rebuilt
  exporters, not re-expected by hand (the 2026-10-26 addendum on frozen
  batteries), and until those exist the port keeps Go 1.26.2's texts, an
  interim divergence `docs/PARITY.md` records.

**Gaps the move brought to light.** Checking the ML-DSA changes against Go
showed TLS differences older than the move, each in how rustls reads a
ClientHello or which alert it sends. A hello with a non-empty
`renegotiation_info` completes the handshake in TLS 1.3 with any key, and in
TLS 1.2 with any key but ML-DSA, where Go refuses it. With any key but ML-DSA,
a TLS 1.2 hello with compressed point formats alone draws `illegal_parameter`,
where Go sends `missing_extension`, and a TLS 1.2 hello without
`signature_algorithms` is refused by rustls first, and in its words. With any
key, rustls's `protocol_version` alert goes out in a record of version 0x0303,
where Go's carries 0x0301; a TLS 1.3 client that offers none of the key's
schemes is refused after the ServerHello, where Go refuses it before; and
under `--authtype=clientcert` a TLS 1.2 client that sends no certificate gets
`certificate_required`, where Go sends `handshake_failure`, and a TLS 1.3
CertificateVerify under a scheme that does not fit the leaf's key gets
`decrypt_error`, where Go sends `illegal_parameter`. Closing the four in
rustls's reading of the ClientHello would take a check ahead of rustls for
every key, like the one the port now makes for an ML-DSA key; the others come
later in the handshake. All of them are recorded in `docs/PARITY.md` as open.

**The other pending items.**

- **Citations of Go 1.27**: settled. "Re-point Go citations to 1.27.3"
  re-pointed the Go standard library line citations outside the ADR bodies to
  go1.27.3, except those a release beside them dates, and the change that adds
  this addendum names go1.27.3 as the reference where comments and docs still
  named 1.26.2. ADR bodies keep the citations they were written with;
  ADR-0015's addendum of this date says which release its body's read in, and
  ADR-0007's that its tie check stands under go1.27.3.
- **The oracle's GODEBUG defaults** and **the bump check**: stand.
  **`tools/fullblockgen`**: settled by the second 2026-11-12 addendum.
